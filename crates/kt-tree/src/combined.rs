//! Reading a `CombinedTreeProof` (§12.3).
//!
//! Every other structure in this protocol can be decoded and then checked. This one cannot.
//! It carries three arrays — timestamps, prefix proofs, prefix roots — with nothing saying
//! which log entry each element belongs to, because they arrive "in the order that the
//! algorithm the user is executing would request them". Decoding gives you three lists of the
//! right shape and no idea what is in them.
//!
//! So reading one is a conversation between the proof and an algorithm. The algorithm knows
//! which log entry it wants to look at next; [`Reader`] hands over the element that must
//! belong to it and keeps count. That inversion is what makes the whole thing verifiable: if
//! the algorithm and the log disagree about which entries are involved, the reader runs out of
//! elements or finishes with some left over, and §12.3 requires exactly neither.
//!
//! # The rules
//!
//! §12.3 states five requirements, and all five are here rather than left to callers, because
//! each one is the kind that an implementation passes by accident until the day it does not:
//!
//! 1. **A timestamp appears only once.** "If a log entry's timestamp is referenced multiple
//!    times by algorithms in the same `CombinedTreeProof`, it is only added to the
//!    `timestamps` array the first time." So a second reference must reuse the first value,
//!    not consume another element.
//! 2. **Retained timestamps are omitted.** A user who advertised a tree size is expected to
//!    have kept the timestamps their previous view covered, and those are not on the wire.
//!    [`Retained`] is where they come from.
//! 3. **A proof without a timestamp must match what the user retained.** Omitting a timestamp
//!    also omits that entry's leaf from `inclusion`, so nothing else ties the proof to the
//!    tree: "Users MUST verify that any such proof in `prefix_proof` is consistent with their
//!    retained prefix tree root hash for the log entry."
//! 4. **Two proofs for one entry must agree.** Different algorithms sharing a proof may each
//!    get their own `PrefixProof` for the same entry; they must compute the same root.
//! 5. **The counts must be exact** — "no more and no less" — and the timestamps, retained ones
//!    included, must be monotonic left to right.
//!
//! Rule 5 is the one that turns the ordering from an assumption into a test. An algorithm
//! implemented against the wrong reading of §12.3 does not merely compute something wrong: it
//! finishes with elements unread, and [`Reader::finish`] says so.

use crate::{distinguished, ibst, ladder, prefix};
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use kt_crypto::suite::CipherSuite;
use kt_wire::proofs::{CombinedTreeProof, PrefixProof, PrefixSearchResult};
use kt_wire::structs::HashValue;

/// Why a `CombinedTreeProof` could not be read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// The proof ran out of elements the algorithm still needs.
    ///
    /// Either the log sent too few, or the algorithm being run is not the one the log
    /// answered — which is the same thing from the verifier's side.
    Exhausted {
        /// Which array: `"timestamps"`, `"prefix_proofs"`, or `"prefix_roots"`.
        array: &'static str,
        /// The log entry whose element was wanted.
        position: u64,
    },
    /// Elements were left over once the algorithm finished (§12.3, "no more and no less").
    Unconsumed {
        /// Which array.
        array: &'static str,
        /// How many elements the algorithm asked for.
        used: usize,
        /// How many the proof carried.
        supplied: usize,
    },
    /// Timestamps did not increase from left to right (§12.3).
    NonMonotonic {
        /// The log entry whose timestamp broke the order.
        position: u64,
        /// Its timestamp.
        timestamp: u64,
        /// The neighbouring entry it contradicts.
        other_position: u64,
        /// That entry's timestamp.
        other_timestamp: u64,
    },
    /// Two proofs for the same log entry computed different prefix tree roots (§12.3).
    ConflictingRoot {
        /// The log entry.
        position: u64,
        /// The root established earlier.
        first: HashValue,
        /// The root this proof computes.
        second: HashValue,
    },
    /// A proof arrived for an entry whose timestamp was omitted, and it does not agree with
    /// the root the user retained for that entry (§12.3).
    ///
    /// This is the case §12.3 singles out. With the timestamp omitted the entry's leaf is not
    /// in `inclusion` either, so the retained root is the only thing that can catch a log
    /// serving a proof from a tree it never published.
    RetainedRootMismatch {
        /// The log entry.
        position: u64,
        /// What the user retained.
        retained: HashValue,
        /// What the proof computes.
        computed: HashValue,
    },
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Exhausted { array, position } => write!(
                f,
                "the proof has no `{array}` element left for log entry {position}"
            ),
            Self::Unconsumed {
                array,
                used,
                supplied,
            } => write!(
                f,
                "the algorithm read {used} of the {supplied} `{array}` elements; §12.3 requires \
                 exactly as many as it asks for"
            ),
            Self::NonMonotonic {
                position,
                timestamp,
                other_position,
                other_timestamp,
            } => write!(
                f,
                "entry {position}'s timestamp {timestamp} contradicts entry \
                 {other_position}'s {other_timestamp}"
            ),
            Self::ConflictingRoot { position, .. } => write!(
                f,
                "two proofs for log entry {position} compute different prefix tree roots"
            ),
            Self::RetainedRootMismatch { position, .. } => write!(
                f,
                "the proof for log entry {position} does not match the prefix tree root the \
                 user retained for it"
            ),
        }
    }
}

impl core::error::Error for Error {}

type Result<T> = core::result::Result<T, Error>;

/// What a user already knows about the log, and therefore is not sent again (§12.3).
///
/// A user who advertises a previously observed tree size is expected to have kept the
/// timestamps and prefix tree roots their earlier view covered. Both are needed: the
/// timestamps because they are omitted from the wire, and the roots because a proof for an
/// entry whose timestamp was omitted has nothing else to be checked against.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Retained {
    /// Timestamps the user kept, by log entry.
    pub timestamps: BTreeMap<u64, u64>,
    /// Prefix tree roots the user kept, by log entry.
    pub prefix_roots: BTreeMap<u64, HashValue>,
}

impl Retained {
    /// A user who has seen nothing.
    #[must_use]
    pub fn none() -> Self {
        Self::default()
    }
}

/// Hands out a `CombinedTreeProof`'s elements in the order an algorithm asks for them (§12.3).
#[derive(Debug)]
pub struct Reader<'a> {
    proof: &'a CombinedTreeProof,
    retained: &'a Retained,
    timestamps_used: usize,
    proofs_used: usize,
    roots_used: usize,
    /// Timestamps established so far, retained ones included, for rules 1 and 5.
    timestamps: BTreeMap<u64, u64>,
    /// Prefix tree roots established so far, for rule 4.
    roots: BTreeMap<u64, HashValue>,
}

impl<'a> Reader<'a> {
    /// Starts reading `proof` on behalf of a user holding `retained`.
    #[must_use]
    pub fn new(proof: &'a CombinedTreeProof, retained: &'a Retained) -> Self {
        Self {
            proof,
            retained,
            timestamps_used: 0,
            proofs_used: 0,
            roots_used: 0,
            timestamps: retained.timestamps.clone(),
            roots: retained.prefix_roots.clone(),
        }
    }

    /// The timestamp of log entry `position`.
    ///
    /// Returns a retained or already-established value without consuming an element, which is
    /// §12.3's rule that an entry's timestamp appears only the first time it is referenced.
    ///
    /// # Errors
    ///
    /// [`Error::Exhausted`] if the proof has no timestamp left, or [`Error::NonMonotonic`] if
    /// the value contradicts one already established for an entry on either side.
    pub fn timestamp(&mut self, position: u64) -> Result<u64> {
        if let Some(known) = self.timestamps.get(&position) {
            return Ok(*known);
        }
        let timestamp =
            *self
                .proof
                .timestamps
                .get(self.timestamps_used)
                .ok_or(Error::Exhausted {
                    array: "timestamps",
                    position,
                })?;
        self.timestamps_used = self.timestamps_used.saturating_add(1);

        // §12.3: "any given timestamp is greater than or equal to all observed timestamps to
        // its left". Checked against both sides, because elements do not arrive in position
        // order and a later element can be to the left of an earlier one.
        for (other, value) in &self.timestamps {
            let ordered = if *other < position {
                *value <= timestamp
            } else {
                *value >= timestamp
            };
            if !ordered {
                return Err(Error::NonMonotonic {
                    position,
                    timestamp,
                    other_position: *other,
                    other_timestamp: *value,
                });
            }
        }
        self.timestamps.insert(position, timestamp);
        Ok(timestamp)
    }

    /// The next prefix tree search proof, which must be for log entry `position`.
    ///
    /// The caller evaluates it — only the caller knows what was searched for — and reports the
    /// root it computes through [`Reader::establish_root`], which is where §12.3's agreement
    /// rules are enforced.
    ///
    /// # Errors
    ///
    /// [`Error::Exhausted`] if the proof has no search proof left.
    pub fn prefix_proof(&mut self, position: u64) -> Result<&'a PrefixProof> {
        let proof = self
            .proof
            .prefix_proofs
            .get(self.proofs_used)
            .ok_or(Error::Exhausted {
                array: "prefix_proofs",
                position,
            })?;
        self.proofs_used = self.proofs_used.saturating_add(1);
        Ok(proof)
    }

    /// Records the prefix tree root a proof for `position` computed.
    ///
    /// # Errors
    ///
    /// [`Error::ConflictingRoot`] if another proof for the same entry computed a different
    /// root, or [`Error::RetainedRootMismatch`] if it disagrees with what the user retained.
    pub fn establish_root(&mut self, position: u64, root: HashValue) -> Result<()> {
        if let Some(retained) = self.retained.prefix_roots.get(&position) {
            if *retained != root {
                return Err(Error::RetainedRootMismatch {
                    position,
                    retained: *retained,
                    computed: root,
                });
            }
        }
        match self.roots.get(&position) {
            Some(first) if *first != root => Err(Error::ConflictingRoot {
                position,
                first: *first,
                second: root,
            }),
            _ => {
                self.roots.insert(position, root);
                Ok(())
            }
        }
    }

    /// The prefix tree root of an entry that has a timestamp but no search proof (§12.3).
    ///
    /// # Errors
    ///
    /// [`Error::Exhausted`] if the proof has no root left, plus anything
    /// [`Reader::establish_root`] reports.
    pub fn prefix_root(&mut self, position: u64) -> Result<HashValue> {
        let root = *self
            .proof
            .prefix_roots
            .get(self.roots_used)
            .ok_or(Error::Exhausted {
                array: "prefix_roots",
                position,
            })?;
        self.roots_used = self.roots_used.saturating_add(1);
        self.establish_root(position, root)?;
        Ok(root)
    }

    /// Whether this entry's timestamp came from the wire rather than from the user's own state.
    ///
    /// §12.3 ties `inclusion` to "all leaf nodes whose timestamp was provided in
    /// `timestamps`", so this is what decides which leaves the log tree proof covers.
    #[must_use]
    pub fn timestamp_was_supplied(&self, position: u64) -> bool {
        self.timestamps.contains_key(&position) && !self.retained.timestamps.contains_key(&position)
    }

    /// The entries still owed a prefix tree root, in left-to-right order (§12.3).
    ///
    /// "The elements of the `prefix_roots` field are, in left-to-right order, the prefix tree
    /// root hashes for any log entries whose timestamp was provided in `timestamps` but a search
    /// proof was not provided in `prefix_proofs`." Both halves matter: an entry the user
    /// retained is not owed one, because its timestamp was not provided, and an entry with a
    /// proof is not owed one either, because the proof computes its root.
    ///
    /// The reason the log has to send them at all is `inclusion`: it covers the leaves of every
    /// entry whose timestamp was provided, and a leaf is the hash of a timestamp *and* a prefix
    /// tree root. An entry with a timestamp and no root would leave a hole in the log tree
    /// computation.
    #[must_use]
    pub fn entries_owed_roots(&self) -> Vec<u64> {
        self.timestamps
            .keys()
            .copied()
            .filter(|position| {
                self.timestamp_was_supplied(*position) && !self.roots.contains_key(position)
            })
            .collect()
    }

    /// The prefix tree root established for `position`, if any.
    #[must_use]
    pub fn root_of(&self, position: u64) -> Option<HashValue> {
        self.roots.get(&position).copied()
    }

    /// Every timestamp established, in log entry order.
    #[must_use]
    pub fn timestamps(&self) -> Vec<(u64, u64)> {
        self.timestamps
            .iter()
            .map(|(position, value)| (*position, *value))
            .collect()
    }

    /// Finishes reading, requiring that nothing was left over (§12.3).
    ///
    /// # Errors
    ///
    /// [`Error::Unconsumed`] for whichever array still has elements in it. This is the check
    /// that makes the element ordering testable: an algorithm that asked for the wrong
    /// entries, in the wrong order, or the wrong number of them, ends here.
    pub fn finish(self) -> Result<()> {
        for (array, used, supplied) in [
            (
                "timestamps",
                self.timestamps_used,
                self.proof.timestamps.len(),
            ),
            (
                "prefix_proofs",
                self.proofs_used,
                self.proof.prefix_proofs.len(),
            ),
            (
                "prefix_roots",
                self.roots_used,
                self.proof.prefix_roots.len(),
            ),
        ] {
            if used != supplied {
                return Err(Error::Unconsumed {
                    array,
                    used,
                    supplied,
                });
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;
    use kt_wire::proofs::{InclusionProof, PrefixSearchResult};

    fn hash(byte: u8) -> HashValue {
        HashValue::from_bytes([byte; 32])
    }

    fn proof_at(depth: u8) -> PrefixProof {
        PrefixProof {
            results: vec![PrefixSearchResult::Inclusion { depth }],
            elements: Vec::new(),
        }
    }

    fn combined(timestamps: Vec<u64>, proofs: usize, roots: Vec<HashValue>) -> CombinedTreeProof {
        CombinedTreeProof {
            timestamps,
            prefix_proofs: (0..proofs).map(|i| proof_at(i as u8)).collect(),
            prefix_roots: roots,
            inclusion: InclusionProof::new(Vec::new()),
        }
    }

    /// The straightforward read: three entries, each with a timestamp and a proof.
    #[test]
    fn an_algorithm_that_asks_for_everything_finishes_clean() {
        let proof = combined(vec![10, 20, 30], 3, Vec::new());
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for (i, position) in [3_u64, 5, 6].into_iter().enumerate() {
            assert_eq!(reader.timestamp(position).unwrap(), (i as u64 + 1) * 10);
            let _ = reader.prefix_proof(position).unwrap();
            reader.establish_root(position, hash(i as u8)).unwrap();
        }
        reader.finish().unwrap();
    }

    /// Rule 1: a second reference to an entry reuses the first value rather than consuming
    /// another element. An implementation that consumed one would read every later timestamp
    /// off by one and still finish — until the counts stopped matching.
    #[test]
    fn a_repeated_reference_does_not_consume_another_timestamp() {
        let proof = combined(vec![10, 20], 0, Vec::new());
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        assert_eq!(reader.timestamp(1).unwrap(), 10);
        assert_eq!(reader.timestamp(1).unwrap(), 10, "same entry, same value");
        assert_eq!(reader.timestamp(2).unwrap(), 20);
        reader.finish().unwrap();
    }

    /// Rule 2: what the user retained is not on the wire.
    #[test]
    fn retained_timestamps_are_not_read_from_the_proof() {
        let proof = combined(vec![30], 0, Vec::new());
        let mut retained = Retained::none();
        retained.timestamps.insert(3, 10);
        let mut reader = Reader::new(&proof, &retained);

        assert_eq!(
            reader.timestamp(3).unwrap(),
            10,
            "from the user's own state"
        );
        assert!(!reader.timestamp_was_supplied(3));
        assert_eq!(reader.timestamp(6).unwrap(), 30);
        assert!(reader.timestamp_was_supplied(6));
        reader.finish().unwrap();
    }

    /// Rule 3, and the case §12.3 calls out: a proof for an entry whose timestamp was omitted
    /// has nothing tying it to the tree except the root the user kept, because omitting the
    /// timestamp also omits the entry's leaf from `inclusion`.
    #[test]
    fn a_proof_for_a_retained_entry_must_match_the_retained_root() {
        let proof = combined(Vec::new(), 1, Vec::new());
        let mut retained = Retained::none();
        retained.timestamps.insert(3, 10);
        retained.prefix_roots.insert(3, hash(0xaa));

        let mut reader = Reader::new(&proof, &retained);
        let _ = reader.prefix_proof(3).unwrap();
        assert_eq!(
            reader.establish_root(3, hash(0xbb)),
            Err(Error::RetainedRootMismatch {
                position: 3,
                retained: hash(0xaa),
                computed: hash(0xbb),
            })
        );

        // And the same proof against the root the user actually kept.
        let mut reader = Reader::new(&proof, &retained);
        let _ = reader.prefix_proof(3).unwrap();
        reader.establish_root(3, hash(0xaa)).unwrap();
        reader.finish().unwrap();
    }

    /// Rule 4: two algorithms may each get a proof from the same entry, and they must agree
    /// about its prefix tree.
    #[test]
    fn two_proofs_for_one_entry_must_compute_the_same_root() {
        let proof = combined(vec![10], 2, Vec::new());
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        reader.timestamp(1).unwrap();
        let _ = reader.prefix_proof(1).unwrap();
        reader.establish_root(1, hash(0xaa)).unwrap();
        let _ = reader.prefix_proof(1).unwrap();
        assert_eq!(
            reader.establish_root(1, hash(0xbb)),
            Err(Error::ConflictingRoot {
                position: 1,
                first: hash(0xaa),
                second: hash(0xbb),
            })
        );
    }

    /// Rule 5, the count half. Both directions are errors: too few elements and the algorithm
    /// cannot finish, too many and it finished without reading them.
    #[test]
    fn the_counts_must_come_out_exact() {
        let retained = Retained::none();

        let short = combined(vec![10], 0, Vec::new());
        let mut reader = Reader::new(&short, &retained);
        reader.timestamp(1).unwrap();
        assert_eq!(
            reader.timestamp(2),
            Err(Error::Exhausted {
                array: "timestamps",
                position: 2
            })
        );

        let long = combined(vec![10, 20, 30], 0, Vec::new());
        let mut reader = Reader::new(&long, &retained);
        reader.timestamp(1).unwrap();
        assert_eq!(
            reader.finish(),
            Err(Error::Unconsumed {
                array: "timestamps",
                used: 1,
                supplied: 3
            })
        );

        let extra_proofs = combined(Vec::new(), 2, Vec::new());
        let mut reader = Reader::new(&extra_proofs, &retained);
        let _ = reader.prefix_proof(1).unwrap();
        assert_eq!(
            reader.finish(),
            Err(Error::Unconsumed {
                array: "prefix_proofs",
                used: 1,
                supplied: 2
            })
        );

        let extra_roots = combined(Vec::new(), 0, vec![hash(1)]);
        let reader = Reader::new(&extra_roots, &retained);
        assert_eq!(
            reader.finish(),
            Err(Error::Unconsumed {
                array: "prefix_roots",
                used: 0,
                supplied: 1
            })
        );
    }

    /// Rule 5, the monotonicity half. Checked against entries on both sides, because the
    /// elements do not arrive in position order: an algorithm may read entry 6 before entry 3.
    #[test]
    fn timestamps_must_be_monotonic_in_position_order() {
        let retained = Retained::none();

        // Read left to right: 20 then 10 at a later entry.
        let backwards = combined(vec![20, 10], 0, Vec::new());
        let mut reader = Reader::new(&backwards, &retained);
        reader.timestamp(1).unwrap();
        assert_eq!(
            reader.timestamp(2),
            Err(Error::NonMonotonic {
                position: 2,
                timestamp: 10,
                other_position: 1,
                other_timestamp: 20,
            })
        );

        // Read right to left, which the monitoring algorithms do: entry 6 first, then a
        // *larger* timestamp at entry 3, which is to its left.
        let out_of_order = combined(vec![10, 20], 0, Vec::new());
        let mut reader = Reader::new(&out_of_order, &retained);
        reader.timestamp(6).unwrap();
        assert_eq!(
            reader.timestamp(3),
            Err(Error::NonMonotonic {
                position: 3,
                timestamp: 20,
                other_position: 6,
                other_timestamp: 10,
            })
        );
    }

    /// A retained timestamp participates in the ordering check too — §12.3 says "along with
    /// any retained timestamps".
    #[test]
    fn retained_timestamps_constrain_the_order() {
        let proof = combined(vec![5], 0, Vec::new());
        let mut retained = Retained::none();
        retained.timestamps.insert(3, 10);
        let mut reader = Reader::new(&proof, &retained);
        assert_eq!(
            reader.timestamp(6),
            Err(Error::NonMonotonic {
                position: 6,
                timestamp: 5,
                other_position: 3,
                other_timestamp: 10,
            })
        );
    }

    /// `prefix_roots` covers entries that got a timestamp but no proof, and the root it
    /// supplies is subject to the same agreement rules.
    #[test]
    fn prefix_roots_are_read_for_entries_without_a_proof() {
        let proof = combined(vec![10, 20], 1, vec![hash(0xcc)]);
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);

        reader.timestamp(1).unwrap();
        let _ = reader.prefix_proof(1).unwrap();
        reader.establish_root(1, hash(0xaa)).unwrap();

        reader.timestamp(2).unwrap();
        assert_eq!(reader.prefix_root(2).unwrap(), hash(0xcc));
        assert_eq!(reader.root_of(2), Some(hash(0xcc)));
        reader.finish().unwrap();
    }

    #[test]
    fn errors_describe_themselves() {
        use alloc::string::ToString;
        let errors = [
            Error::Exhausted {
                array: "timestamps",
                position: 1,
            },
            Error::Unconsumed {
                array: "prefix_proofs",
                used: 1,
                supplied: 2,
            },
            Error::NonMonotonic {
                position: 2,
                timestamp: 1,
                other_position: 1,
                other_timestamp: 2,
            },
            Error::ConflictingRoot {
                position: 1,
                first: hash(1),
                second: hash(2),
            },
            Error::RetainedRootMismatch {
                position: 1,
                retained: hash(1),
                computed: hash(2),
            },
        ];
        for error in &errors {
            assert!(!error.to_string().is_empty());
            assert!(core::error::Error::source(error).is_none());
        }
    }
}

/// What the ladders inspected so far have established, and where (§6.2).
///
/// §6.2 lets a log omit a lookup in two cases: an inclusion proof for a version already proven
/// included "for a log entry to the left", and a non-inclusion proof for one already proven
/// absent "for a log entry to the right". Both are sound because the prefix tree only grows: a
/// version present at some entry is present at every entry after it, and one absent at some
/// entry was absent at every entry before it.
///
/// The direction is the whole content of the rule, so this records where each result came from
/// rather than accumulating a flat set. §6.3 walks strictly left to right and would not notice
/// the difference; §7.2 is a binary search that moves both ways, and there it decides whether a
/// ladder has two lookups or none.
#[derive(Clone, Debug, Default)]
struct Established {
    /// `(position, versions proven included there, versions proven absent there)`.
    entries: Vec<(u64, Vec<u32>, Vec<u32>)>,
}

impl Established {
    /// The omission sets for a ladder at `position`: inclusions established to its left, and
    /// non-inclusions established to its right.
    fn sets_for(&self, position: u64) -> (Vec<u32>, Vec<u32>) {
        let mut left_inclusion = Vec::new();
        let mut right_non_inclusion = Vec::new();
        for (at, included, absent) in &self.entries {
            if *at < position {
                for version in included {
                    if !left_inclusion.contains(version) {
                        left_inclusion.push(*version);
                    }
                }
            }
            if *at > position {
                for version in absent {
                    if !right_non_inclusion.contains(version) {
                        right_non_inclusion.push(*version);
                    }
                }
            }
        }
        (left_inclusion, right_non_inclusion)
    }

    /// Records what an entry's ladder proved.
    fn record(&mut self, position: u64, versions: &[u32], results: &[PrefixSearchResult]) {
        let mut included = Vec::new();
        let mut absent = Vec::new();
        for (version, result) in versions.iter().zip(results.iter()) {
            if result.is_inclusion() {
                included.push(*version);
            } else {
                absent.push(*version);
            }
        }
        self.entries.push((position, included, absent));
    }
}

/// One version of a label as a search key, taken from a response's binary ladder (§13.1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LadderKey {
    /// The VRF output for this label-version pair (§11.7).
    pub vrf_output: HashValue,
    /// The commitment to the value at this version, where the response carried one.
    ///
    /// §13.1 omits it for versions that do not exist — nothing to commit to — and for the
    /// target version, whose commitment the user recomputes from `opening` and `value`. A
    /// caller that has recomputed the target's commitment should put it here.
    pub commitment: Option<HashValue>,
}

/// What a greatest-version search established (§6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Search {
    /// The log entry the search started from: the rightmost distinguished entry, or the root
    /// if the log has none.
    pub start: u64,
    /// Every entry inspected, left to right, with the prefix tree root its proof computed.
    pub inspected: Vec<(u64, HashValue)>,
    /// The terminal entry: "the leftmost log entry inspected that contains the greatest
    /// version of the label" (§6.3).
    pub terminal: u64,
}

impl Search {
    /// Whether §6.3 obliges the user to monitor the label.
    ///
    /// "If the Transparency Log is deployed in Contact Monitoring mode and the terminal log
    /// entry of the search is to the right of the rightmost distinguished log entry, the user
    /// MUST monitor the label." The start of the search *is* that entry when one exists, so
    /// this is a comparison against it — and it is a `must`, not advice: a value that entered
    /// the log after the last reference point has not been seen by anyone else yet.
    #[must_use]
    pub const fn monitoring_required(
        &self,
        contact_monitoring: bool,
        has_distinguished: bool,
    ) -> bool {
        contact_monitoring && has_distinguished && self.terminal > self.start
    }
}

/// Reads a timestamp for the distinguished walk, turning a refusal into "not available".
///
/// The walk's contract is `Option`: `None` means the caller does not have that entry. For a
/// §12.3 consumer "does not have it" and "the proof is exhausted" are the same situation, and
/// [`distinguished::Error::MissingTimestamp`] is the more precise report of it.
fn reader_timestamp(reader: &mut Reader<'_>, position: u64) -> Option<u64> {
    reader.timestamp(position).ok()
}

/// Runs §6.3's greatest-version search against a proof.
///
/// The caller has already consumed §12.3.1's timestamps — the search itself provides none,
/// because "the frontier log entry timestamps are either already provided as part of updating
/// the user's view of the tree, or are expected to have been retained by the user". So this
/// reads only prefix proofs, one per inspected entry, and every timestamp it needs must
/// already be in `reader`.
///
/// `claimed_greatest` is the version the log says is the greatest, `keys` maps each version in
/// the response's binary ladder to its search key, and `window` is the Reasonable Monitoring
/// Window that decides where the search starts.
///
/// # Errors
///
/// [`SearchError`] for a proof that does not establish what §6.3 requires, including the
/// reader's own refusals.
pub fn greatest_version_search(
    suite: CipherSuite,
    size: u64,
    window: u64,
    claimed_greatest: u32,
    keys: &BTreeMap<u32, LadderKey>,
    reader: &mut Reader<'_>,
) -> core::result::Result<Outcome, SearchError> {
    // §6.3 starts "at the rightmost distinguished log entry, or the root of the implicit
    // binary search tree if there are no distinguished log entries".
    //
    // Finding it reads timestamps *through the reader*, which is not an implementation detail:
    // in the ordinary case they were all supplied by the view update and this consumes
    // nothing, but where §4.2's list comes out empty (DRAFT-06) the log has to send the
    // frontier's timestamps somewhere, and this walk is the first thing that asks for them.
    // The order it asks in — the rightmost entry, then the root, then right children — is
    // therefore part of the wire order.
    let mut lookup = |position: u64| reader_timestamp(reader, position);
    let distinguished = distinguished::rightmost_from_frontier(size, window, &mut lookup)?;
    let start = match distinguished {
        Some(position) => position,
        None => ibst::root(size)?,
    };

    let last = size.saturating_sub(1);
    let mut inspected = Vec::new();
    let mut terminal = None;
    let mut established = Established::default();

    let mut current = start;
    loop {
        let rightmost = current == last;

        // Step 1's ladder, as long as it could possibly be. The proof may carry *fewer*
        // results, and that is not the log being stingy: §5's ladder stops as soon as it has
        // established where the greatest version at this entry sits relative to the target,
        // and at an entry to the left of the terminal one that happens early. The results are
        // a prefix of this sequence, because the sequence itself does not depend on the local
        // greatest version — only where it stops does.
        let (left_inclusion, right_non_inclusion) = established.sets_for(current);
        let versions = ladder::search_binary_ladder(
            claimed_greatest,
            claimed_greatest,
            &left_inclusion,
            &right_non_inclusion,
        )?;

        // §12.3.2 says the search needs no timestamps of its own, because the frontier's are
        // either in the view update or retained. Asking anyway is free — §12.3's rule that a
        // timestamp appears only on first reference makes a repeat a no-op — and it is
        // necessary in practice: when §4.2's list comes out empty (DRAFT-06) the view update
        // supplies nothing, and the log sends the frontier timestamps here instead.
        reader.timestamp(current)?;

        let proof = reader.prefix_proof(current)?;
        let used = versions
            .get(..proof.results.len())
            .ok_or(SearchError::LadderLength {
                position: current,
                expected: versions.len(),
                actual: proof.results.len(),
            })?;

        // Step 2, which is exactly §6.2's interpretation: does this entry's ladder place the
        // greatest version below, at, or above the target? Reusing that keeps one reading of
        // the stopping rules rather than two.
        let ordering = ladder::interpret_search_ladder(used, claimed_greatest, &proof.results)?;
        if ordering == core::cmp::Ordering::Greater {
            return Err(SearchError::VersionAboveGreatestExists {
                position: current,
                version: claimed_greatest,
            });
        }
        if rightmost && ordering != core::cmp::Ordering::Equal {
            // One exception, and it is not in §6.3: a label with no versions at all. The log
            // still has to answer, and the only answer available is a claim of version 0 whose
            // single lookup proves version 0 absent. §6.3 step 2 read literally rejects that —
            // it requires the rightmost entry to show every version at or below the target as
            // included, which nothing can do when the label has never existed. So the response
            // that means "no such label" is unverifiable as specified, and this reports it as
            // an outcome rather than treating the log as dishonest. Tracked as `DRAFT-08`.
            if claimed_greatest == 0 && ordering == core::cmp::Ordering::Less {
                let root = {
                    let mut entries = Vec::new();
                    for (version, result) in used.iter().zip(proof.results.iter()) {
                        let key = keys.get(version).ok_or(SearchError::MissingLadderKey {
                            position: current,
                            version: *version,
                        })?;
                        entries.push(if result.is_inclusion() {
                            prefix::SearchEntry::included(
                                key.vrf_output,
                                key.commitment.ok_or(SearchError::MissingCommitment {
                                    position: current,
                                    version: *version,
                                })?,
                            )
                        } else {
                            prefix::SearchEntry::absent(key.vrf_output)
                        });
                    }
                    prefix::evaluate(suite, &entries, proof)?
                };
                reader.establish_root(current, root)?;
                inspected.push((current, root));
                return Ok(Outcome::NoVersions { start, inspected });
            }
            return Err(SearchError::RightmostInconsistent {
                position: current,
                claimed: claimed_greatest,
            });
        }
        if ordering == core::cmp::Ordering::Equal && terminal.is_none() {
            terminal = Some(current);
        }

        let mut entries = Vec::new();
        for (version, result) in used.iter().zip(proof.results.iter()) {
            let key = keys.get(version).ok_or(SearchError::MissingLadderKey {
                position: current,
                version: *version,
            })?;
            entries.push(if result.is_inclusion() {
                prefix::SearchEntry::included(
                    key.vrf_output,
                    key.commitment.ok_or(SearchError::MissingCommitment {
                        position: current,
                        version: *version,
                    })?,
                )
            } else {
                prefix::SearchEntry::absent(key.vrf_output)
            });
        }
        established.record(current, used, &proof.results);

        let root = prefix::evaluate(suite, &entries, proof)?;
        reader.establish_root(current, root)?;
        inspected.push((current, root));

        // Step 3.
        if rightmost {
            break;
        }
        current = ibst::right(current, size)?;
    }

    let terminal = terminal.ok_or(SearchError::NoEntryHoldsTheGreatestVersion {
        claimed: claimed_greatest,
    })?;
    Ok(Outcome::Found(Search {
        start,
        inspected,
        terminal,
    }))
}

/// What a greatest-version search concluded (§6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The log's claim about the greatest version holds.
    Found(Search),
    /// The label has no versions at all.
    ///
    /// §6.3 has no branch for this, which is `DRAFT-08` in `docs/interop.md`: the log answers
    /// with a claim of version 0 and a proof that version 0 does not exist, and step 2 read
    /// literally rejects it. Reported as an outcome because the response is well formed and
    /// says something true — just not something §6.3 anticipates.
    NoVersions {
        /// Where the search started.
        start: u64,
        /// The entries inspected, with the prefix tree roots their proofs computed.
        inspected: Vec<(u64, HashValue)>,
    },
}

/// Why a greatest-version search failed (§6.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchError {
    /// An entry's proof carried a different number of results than its ladder calls for.
    LadderLength {
        /// The log entry.
        position: u64,
        /// How many lookups §6.2's ladder specifies for this entry.
        expected: usize,
        /// How many results the proof carried.
        actual: usize,
    },
    /// A version above the claimed greatest was proven to exist (§6.3 step 2).
    VersionAboveGreatestExists {
        /// The log entry.
        position: u64,
        /// The version that should not have been there.
        version: u32,
    },
    /// The rightmost entry's ladder does not place the greatest version at the claim
    /// (§6.3 step 2).
    ///
    /// This is the check that makes "greatest" mean something. Any entry can show that some
    /// version exists; only the rightmost one can show that nothing above it does.
    RightmostInconsistent {
        /// The log entry.
        position: u64,
        /// The version the log claimed was greatest.
        claimed: u32,
    },
    /// The response's binary ladder had no search key for a version the ladder looks up.
    MissingLadderKey {
        /// The log entry being inspected.
        position: u64,
        /// The version with no key.
        version: u32,
    },
    /// A lookup proved inclusion but the response carried no commitment for that version.
    MissingCommitment {
        /// The log entry.
        position: u64,
        /// The version.
        version: u32,
    },
    /// No inspected entry contained the claimed greatest version, so there is nothing the
    /// claim can be true of.
    NoEntryHoldsTheGreatestVersion {
        /// The version the log claimed was greatest.
        claimed: u32,
    },
    /// The proof could not be read as §12.3 requires.
    Proof(Error),
    /// A prefix tree proof did not evaluate.
    Prefix(prefix::Error),
    /// The search tree could not be navigated.
    Ibst(ibst::Error),
    /// A ladder could not be computed.
    Ladder(ladder::Error),
    /// The distinguished entries could not be determined.
    Distinguished(distinguished::Error),
}

impl From<Error> for SearchError {
    fn from(err: Error) -> Self {
        Self::Proof(err)
    }
}

impl From<prefix::Error> for SearchError {
    fn from(err: prefix::Error) -> Self {
        Self::Prefix(err)
    }
}

impl From<ibst::Error> for SearchError {
    fn from(err: ibst::Error) -> Self {
        Self::Ibst(err)
    }
}

impl From<ladder::Error> for SearchError {
    fn from(err: ladder::Error) -> Self {
        Self::Ladder(err)
    }
}

impl From<distinguished::Error> for SearchError {
    fn from(err: distinguished::Error) -> Self {
        Self::Distinguished(err)
    }
}

impl core::fmt::Display for SearchError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::LadderLength {
                position,
                expected,
                actual,
            } => write!(
                f,
                "log entry {position}'s ladder should have {expected} lookups, the proof has \
                 {actual}"
            ),
            Self::VersionAboveGreatestExists { position, version } => write!(
                f,
                "log entry {position} proves version {version} exists, above the claimed \
                 greatest"
            ),
            Self::RightmostInconsistent { position, claimed } => write!(
                f,
                "the rightmost log entry {position} does not show version {claimed} as the \
                 greatest that exists"
            ),
            Self::MissingLadderKey { position, version } => write!(
                f,
                "no search key for version {version}, looked up at log entry {position}"
            ),
            Self::MissingCommitment { position, version } => write!(
                f,
                "version {version} is included at log entry {position} but the response \
                 carried no commitment for it"
            ),
            Self::NoEntryHoldsTheGreatestVersion { claimed } => write!(
                f,
                "no inspected log entry contains version {claimed}, so it cannot be the \
                 greatest"
            ),
            Self::Proof(err) => write!(f, "reading the proof: {err}"),
            Self::Prefix(err) => write!(f, "evaluating a prefix tree proof: {err}"),
            Self::Ibst(err) => write!(f, "walking the search tree: {err}"),
            Self::Ladder(err) => write!(f, "computing a binary ladder: {err}"),
            Self::Distinguished(err) => write!(f, "finding the distinguished entries: {err}"),
        }
    }
}

impl core::error::Error for SearchError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Proof(err) => Some(err),
            Self::Prefix(err) => Some(err),
            Self::Ibst(err) => Some(err),
            Self::Ladder(err) => Some(err),
            Self::Distinguished(err) => Some(err),
            _ => None,
        }
    }
}

/// Whether a log entry has outlived the log's maximum lifetime (§7.1).
///
/// "Whether a log entry is expired is determined by subtracting the timestamp of the log entry
/// in question from the timestamp of the rightmost log entry and checking if the result is
/// greater than or equal to the defined duration." A `lifetime` of zero means the log defines
/// none, and nothing expires.
#[must_use]
pub const fn expired(lifetime: u64, timestamp: u64, rightmost: u64) -> bool {
    if lifetime == 0 {
        return false;
    }
    match rightmost.checked_sub(timestamp) {
        // Monotonic timestamps make this unreachable, and a wrapped subtraction would report a
        // fresh entry as expired, so treat it as not expired and let the ordering check that
        // §12.3 already performs be the thing that objects.
        None => false,
        Some(age) => age >= lifetime,
    }
}

/// What a fixed-version search concluded (§7.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FixedOutcome {
    /// The target version was found at the terminal entry.
    Found {
        /// The entry that triggered step 5, or the one step 6 identified.
        terminal: u64,
        /// Every entry inspected, with the prefix tree root its proof computed. Entries the
        /// search skipped as expired have no root, so they are absent.
        inspected: Vec<(u64, HashValue)>,
    },
    /// The target version does not exist (§7.2 steps 6.1 and 6.3).
    DoesNotExist,
    /// The target version existed but has expired (§7.2 steps 5.2 and 6.2).
    Expired,
}

/// Runs §7.2's fixed-version search against a proof.
///
/// A binary search rather than a walk: §7.2 starts at the root of the implicit binary search
/// tree and moves left or right according to what each entry's ladder says about the target,
/// which is why it needs a timestamp for every entry it touches — unlike §6.3, whose entries
/// are all on the frontier.
///
/// `lifetime` is the log's maximum lifetime (§7.1), zero if it defines none.
///
/// The rightmost entry's timestamp is read first, before the walk, and that ordering is forced
/// by the draft rather than chosen: §7.1 defines expiry by "subtracting the timestamp of the log
/// entry in question from the timestamp of the rightmost log entry", so no expiry question can
/// be answered until it is known. It is therefore the first element of a fixed-version search's
/// `timestamps` — unless the user retained it, in which case §12.3 omits it and this consumes
/// nothing.
///
/// # Errors
///
/// [`SearchError`] for a proof that does not establish what §7.2 requires. Note that "the
/// version does not exist" and "the version has expired" are outcomes rather than errors: the
/// log answered honestly, and the answer is no.
#[allow(
    clippy::too_many_arguments,
    reason = "§7.2's inputs: the tree, the log's two time parameters, the target, its keys, and \
              the proof. Bundling them would hide which of the draft's parameters is which"
)]
pub fn fixed_version_search(
    suite: CipherSuite,
    size: u64,
    lifetime: u64,
    window: u64,
    target: u32,
    keys: &BTreeMap<u32, LadderKey>,
    reader: &mut Reader<'_>,
) -> core::result::Result<FixedOutcome, SearchError> {
    let rightmost = reader.timestamp(size.saturating_sub(1))?;
    let mut inspected: Vec<(u64, HashValue)> = Vec::new();
    let mut established = Established::default();
    let mut met_expired = false;
    // The leftmost inspected entry whose ladder placed the greatest version at or above the
    // target. §7.2 defines two terminals — the entry that triggers step 5, and the one step 6
    // identifies — and this is both: step 5's entry has the target as its greatest, step 6's has
    // something above it, and in each case the leftmost such entry is the one that counts.
    let mut terminal: Option<u64> = None;
    // Unexpired distinguished entries met on the way down, for steps 5.2 and 6.2.
    let mut vouchers: Vec<u64> = Vec::new();

    // §6.1's bracketing timestamps for the current entry, maintained by the descent itself.
    // This is why a search can decide distinguishedness at all: §6.1 brackets a node by the
    // timestamps of the entries either side of it in the search tree, and those are exactly the
    // ancestors this walk has already visited. A verifier that tried to enumerate the
    // distinguished set instead would need timestamps for entries the search never touches, and
    // the proof does not carry them.
    let mut left = (0_u64, 0_u64);
    let mut right = (size.saturating_sub(1), rightmost);

    let mut current = ibst::root(size)?;
    loop {
        let timestamp = reader.timestamp(current)?;

        // Step 1. An expired entry gets no ladder at all — that is what lets the log prune old
        // prefix trees — so the search moves right on the timestamp alone.
        if expired(lifetime, timestamp, rightmost) {
            met_expired = true;
            match ibst::right(current, size) {
                Ok(child) => {
                    left = (current, timestamp);
                    current = child;
                    continue;
                }
                Err(_) => break,
            }
        }
        if distinguished::is_distinguished(window, left, right)? {
            vouchers.push(current);
        }

        // Step 2, with the same prefix reasoning as §6.3: the proof may answer fewer lookups
        // than the verifier's ladder, because the log stops as soon as it has placed the
        // greatest version at this entry relative to the target.
        let (left_inclusion, right_non_inclusion) = established.sets_for(current);
        let versions =
            ladder::search_binary_ladder(target, target, &left_inclusion, &right_non_inclusion)?;
        let proof = reader.prefix_proof(current)?;
        let used = versions
            .get(..proof.results.len())
            .ok_or(SearchError::LadderLength {
                position: current,
                expected: versions.len(),
                actual: proof.results.len(),
            })?;
        let ordering = ladder::interpret_search_ladder(used, target, &proof.results)?;

        let mut entries = Vec::new();
        for (version, result) in used.iter().zip(proof.results.iter()) {
            let key = keys.get(version).ok_or(SearchError::MissingLadderKey {
                position: current,
                version: *version,
            })?;
            entries.push(if result.is_inclusion() {
                prefix::SearchEntry::included(
                    key.vrf_output,
                    key.commitment.ok_or(SearchError::MissingCommitment {
                        position: current,
                        version: *version,
                    })?,
                )
            } else {
                prefix::SearchEntry::absent(key.vrf_output)
            });
        }
        established.record(current, used, &proof.results);
        let root = prefix::evaluate(suite, &entries, proof)?;
        reader.establish_root(current, root)?;
        inspected.push((current, root));

        if ordering != core::cmp::Ordering::Less
            && terminal.is_none_or(|previous| current < previous)
        {
            terminal = Some(current);
        }

        match ordering {
            // Step 3: the greatest version here is below the target, so it arrived later.
            core::cmp::Ordering::Less => match ibst::right(current, size) {
                Ok(child) => {
                    left = (current, timestamp);
                    current = child;
                }
                Err(_) => break,
            },
            // Step 4: the greatest version here is above the target, so the target was already
            // present earlier.
            core::cmp::Ordering::Greater => match ibst::left(current) {
                Ok(child) => {
                    right = (current, timestamp);
                    current = child;
                }
                Err(_) => break,
            },
            // Step 5: this entry has the target as its greatest version.
            core::cmp::Ordering::Equal => {
                // Step 5.1.
                if !met_expired {
                    return Ok(FixedOutcome::Found {
                        terminal: current,
                        inspected,
                    });
                }
                // Step 5.2: something on the way was expired, so this entry needs a voucher —
                // itself, or an unexpired distinguished entry to its left in its direct path.
                // Without one, nobody was ever obliged to look here.
                if vouchers.iter().any(|voucher| *voucher <= current) {
                    return Ok(FixedOutcome::Found {
                        terminal: current,
                        inspected,
                    });
                }
                return Ok(FixedOutcome::Expired);
            }
        }
    }

    // Step 6: the walk ran off the tree without an entry whose greatest version is the target.
    let Some(identified) = terminal else {
        // Step 6.1.
        return Ok(FixedOutcome::DoesNotExist);
    };
    // Step 6.2. Note the comparison is strict here where step 5.2's is not: the identified entry
    // does *not* have the target as its greatest version, so §7.2 says clients "MUST NOT accept
    // a proof where the identified log entry is itself the leftmost unexpired and distinguished
    // log entry" — the label owner would have had no reason to check this version there.
    if met_expired && !vouchers.iter().any(|voucher| *voucher < identified) {
        return Ok(FixedOutcome::Expired);
    }
    // Step 6.3: one more lookup, for the target version alone.
    let key = keys.get(&target).ok_or(SearchError::MissingLadderKey {
        position: identified,
        version: target,
    })?;
    let proof = reader.prefix_proof(identified)?;
    let result = proof.results.first().ok_or(SearchError::LadderLength {
        position: identified,
        expected: 1,
        actual: 0,
    })?;
    let entry = if result.is_inclusion() {
        prefix::SearchEntry::included(
            key.vrf_output,
            key.commitment.ok_or(SearchError::MissingCommitment {
                position: identified,
                version: target,
            })?,
        )
    } else {
        prefix::SearchEntry::absent(key.vrf_output)
    };
    let root = prefix::evaluate(suite, &[entry], proof)?;
    reader.establish_root(identified, root)?;
    if result.is_inclusion() {
        Ok(FixedOutcome::Found {
            terminal: identified,
            inspected,
        })
    } else {
        Ok(FixedOutcome::DoesNotExist)
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod search_tests {
    use super::*;
    use alloc::vec;
    use kt_wire::proofs::{InclusionProof, PrefixLeaf};

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    /// A search key for a version. Standing in for a VRF output, which is all the tree cares
    /// about — §11.7's evaluation is checked elsewhere.
    pub(super) fn key_for(version: u32) -> HashValue {
        let mut bytes = [0_u8; 32];
        bytes[0] = u8::try_from(version.wrapping_mul(37) % 256).unwrap_or(0);
        bytes[31] = u8::try_from(version % 256).unwrap_or(0);
        HashValue::from_bytes(bytes)
    }

    fn commitment_for(version: u32) -> HashValue {
        HashValue::from_bytes([u8::try_from(version % 256).unwrap_or(0) ^ 0xa5; 32])
    }

    pub(super) fn keys_through(greatest: u32) -> BTreeMap<u32, LadderKey> {
        // Every version the ladder could ask about, existing or not: the response carries a
        // step per version looked up, and commitments only for those that exist.
        let mut keys = BTreeMap::new();
        for version in 0..=greatest.saturating_add(16) {
            keys.insert(
                version,
                LadderKey {
                    vrf_output: key_for(version),
                    commitment: (version <= greatest).then(|| commitment_for(version)),
                },
            );
        }
        keys
    }

    /// The prefix tree of the log entry at `position`, where version `v` was added at entry
    /// `v` — so entry `position` holds versions `0..=position`.
    pub(super) fn tree_at(position: u64) -> prefix::PrefixTree {
        let mut tree = prefix::PrefixTree::new();
        for version in 0..=u32::try_from(position).unwrap() {
            tree.insert(PrefixLeaf {
                vrf_output: key_for(version),
                commitment: commitment_for(version),
            })
            .unwrap();
        }
        tree
    }

    /// Builds the proof a log would serve for a greatest-version search, by running the same
    /// walk §6.3 does and asking each entry's tree for exactly the ladder it would answer.
    ///
    /// The per-entry ladder is indexed on the greatest version *at that entry*, which is what
    /// makes the results a prefix of the verifier's ladder rather than a match for it.
    fn build_proof(size: u64, start: u64, claimed: u32, timestamps: &[u64]) -> CombinedTreeProof {
        let mut proofs = Vec::new();
        let mut left_inclusion: Vec<u32> = Vec::new();
        let mut current = start;
        loop {
            let local_greatest = u32::try_from(current).unwrap();
            let versions =
                ladder::search_binary_ladder(claimed, local_greatest, &left_inclusion, &[])
                    .unwrap();
            let tree = tree_at(current);
            let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
            let proof = tree.prove(SUITE, &searches).unwrap();
            for (version, result) in versions.iter().zip(proof.results.iter()) {
                if result.is_inclusion() && !left_inclusion.contains(version) {
                    left_inclusion.push(*version);
                }
            }
            proofs.push(proof);
            if current == size - 1 {
                break;
            }
            current = ibst::right(current, size).unwrap();
        }
        CombinedTreeProof {
            timestamps: timestamps.to_vec(),
            prefix_proofs: proofs,
            prefix_roots: Vec::new(),
            inclusion: InclusionProof::new(Vec::new()),
        }
    }

    /// Timestamps that make only the root distinguished, which is the ordinary case for a log
    /// whose entries are close together: the window is far wider than the log's whole span.
    fn clustered(size: u64) -> Vec<u64> {
        (0..size).map(|i| 1_700_000_000_000 + i).collect()
    }

    /// A whole search over a four-entry log: the walk, the per-entry ladders, the roots, and
    /// §12.3's exact consumption.
    #[test]
    fn an_honest_search_consumes_the_proof_exactly() {
        let size = 4_u64;
        let claimed = 3_u32;
        let window = 604_800_000;
        let stamps = clustered(size);
        // The frontier of a four-entry log is just its root, which is also its rightmost
        // entry, so the search inspects one entry.
        let frontier = ibst::frontier(size).unwrap();
        let timestamps: Vec<u64> = frontier.iter().map(|x| stamps[*x as usize]).collect();
        let proof = build_proof(size, ibst::root(size).unwrap(), claimed, &timestamps);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for position in &frontier {
            reader.timestamp(*position).unwrap();
        }
        let outcome = greatest_version_search(
            SUITE,
            size,
            window,
            claimed,
            &keys_through(claimed),
            &mut reader,
        )
        .unwrap();
        let Outcome::Found(search) = outcome else {
            panic!("expected a found outcome");
        };
        assert_eq!(search.terminal, size - 1);
        assert_eq!(search.inspected.len(), frontier.len());
        for (position, root) in &search.inspected {
            assert_eq!(*root, tree_at(*position).root(SUITE), "entry {position}");
        }
        reader.finish().unwrap();
    }

    /// A seven-entry log, where the walk crosses several frontier entries and the per-entry
    /// ladders shorten as it goes. This is the shape that catches a verifier expecting the
    /// ladders to match rather than to be prefixes.
    #[test]
    fn a_multi_entry_walk_reads_shortened_ladders() {
        let size = 7_u64;
        let claimed = 6_u32;
        let window = 604_800_000;
        let stamps = clustered(size);
        let frontier = ibst::frontier(size).unwrap();
        assert_eq!(
            frontier,
            vec![3, 5, 6],
            "the walk should cross three entries"
        );
        let timestamps: Vec<u64> = frontier.iter().map(|x| stamps[*x as usize]).collect();
        let proof = build_proof(size, 3, claimed, &timestamps);

        // The ladders really do shorten, which is the premise of the test.
        let lengths: Vec<usize> = proof
            .prefix_proofs
            .iter()
            .map(|p| p.results.len())
            .collect();
        assert_eq!(lengths, vec![5, 3, 2]);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for position in &frontier {
            reader.timestamp(*position).unwrap();
        }
        let outcome = greatest_version_search(
            SUITE,
            size,
            window,
            claimed,
            &keys_through(claimed),
            &mut reader,
        )
        .unwrap();
        let Outcome::Found(search) = outcome else {
            panic!("expected a found outcome");
        };
        assert_eq!(search.start, 3);
        assert_eq!(
            search.terminal, 6,
            "only the rightmost entry holds version 6"
        );
        reader.finish().unwrap();
    }

    /// A log claiming a version higher than its rightmost entry can show. §6.3 step 2's second
    /// half is the only thing that catches this, and it is the whole reason a search inspects
    /// the rightmost entry rather than stopping at the first one that has the version.
    #[test]
    fn a_claim_the_rightmost_entry_cannot_support_is_refused() {
        let size = 4_u64;
        let window = 604_800_000;
        let stamps = clustered(size);
        let frontier = ibst::frontier(size).unwrap();
        let timestamps: Vec<u64> = frontier.iter().map(|x| stamps[*x as usize]).collect();
        // The log builds proofs honestly for a greatest of 3, then claims 9.
        let proof = build_proof(size, ibst::root(size).unwrap(), 3, &timestamps);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for position in &frontier {
            reader.timestamp(*position).unwrap();
        }
        let refused =
            greatest_version_search(SUITE, size, window, 9, &keys_through(9), &mut reader);
        assert!(
            matches!(refused, Err(SearchError::LadderLength { .. }))
                || matches!(refused, Err(SearchError::RightmostInconsistent { .. }))
                || matches!(refused, Err(SearchError::Ladder(_))),
            "expected a refusal, got {refused:?}"
        );
    }

    /// A label with no versions: `DRAFT-08`. The log claims version 0 and proves it absent, and
    /// §6.3 step 2 read literally rejects the only answer available.
    #[test]
    fn a_label_with_no_versions_is_an_outcome_not_a_failure() {
        let size = 1_u64;
        let window = 604_800_000;
        let empty = prefix::PrefixTree::new();
        let versions = ladder::search_binary_ladder(0, 0, &[], &[]).unwrap();
        // The log truncates to the first lookup, as katie does: one non-inclusion is enough to
        // say the label has never existed.
        let searches = vec![key_for(versions[0])];
        let proof = empty.prove(SUITE, &searches).unwrap();
        let combined_proof = CombinedTreeProof {
            timestamps: vec![1_700_000_000_000],
            prefix_proofs: vec![proof],
            prefix_roots: Vec::new(),
            inclusion: InclusionProof::new(Vec::new()),
        };

        let retained = Retained::none();
        let mut reader = Reader::new(&combined_proof, &retained);
        reader.timestamp(0).unwrap();
        let outcome =
            greatest_version_search(SUITE, size, window, 0, &keys_through(0), &mut reader).unwrap();
        match outcome {
            Outcome::NoVersions { start, inspected } => {
                assert_eq!(start, 0);
                assert_eq!(inspected.len(), 1);
                assert_eq!(inspected[0].1, empty.root(SUITE));
            }
            Outcome::Found(_) => panic!("the label has no versions"),
        }
        reader.finish().unwrap();
    }

    /// §6.3's monitoring obligation: in contact monitoring, a terminal entry to the right of
    /// the rightmost distinguished entry means the value has not been published anywhere the
    /// rest of the world has looked yet.
    #[test]
    fn monitoring_is_required_when_the_terminal_entry_is_past_the_reference_point() {
        let search = Search {
            start: 3,
            inspected: vec![(3, HashValue::ZERO), (6, HashValue::ZERO)],
            terminal: 6,
        };
        assert!(search.monitoring_required(true, true));
        assert!(
            !search.monitoring_required(false, true),
            "only contact monitoring"
        );
        assert!(
            !search.monitoring_required(true, false),
            "no reference point to be past"
        );

        let settled = Search {
            start: 3,
            inspected: vec![(3, HashValue::ZERO)],
            terminal: 3,
        };
        assert!(
            !settled.monitoring_required(true, true),
            "the terminal entry is the start"
        );
    }

    /// A proof missing the search key for a version its ladder looks up. That means the
    /// response's binary ladder and the proof disagree about which versions are involved, which
    /// no amount of hashing will reconcile.
    #[test]
    fn a_missing_search_key_is_refused() {
        let size = 1_u64;
        let window = 604_800_000;
        let proof = build_proof(size, 0, 0, &[1_700_000_000_000]);
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        reader.timestamp(0).unwrap();
        assert!(matches!(
            greatest_version_search(SUITE, size, window, 0, &BTreeMap::new(), &mut reader),
            Err(SearchError::MissingLadderKey { .. })
        ));
    }

    /// And one where the key is there but the commitment is not, for a version the proof says
    /// exists. §13.1 omits commitments only for versions that do not exist and for the target,
    /// so this is a malformed response rather than an unlucky one.
    #[test]
    fn a_missing_commitment_is_refused() {
        let size = 1_u64;
        let window = 604_800_000;
        let proof = build_proof(size, 0, 0, &[1_700_000_000_000]);
        let mut keys = BTreeMap::new();
        keys.insert(
            0,
            LadderKey {
                vrf_output: key_for(0),
                commitment: None,
            },
        );
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        reader.timestamp(0).unwrap();
        assert!(matches!(
            greatest_version_search(SUITE, size, window, 0, &keys, &mut reader),
            Err(SearchError::MissingCommitment { .. })
        ));
    }

    #[test]
    fn search_errors_describe_themselves() {
        use alloc::string::ToString;
        let errors = [
            SearchError::LadderLength {
                position: 1,
                expected: 3,
                actual: 4,
            },
            SearchError::VersionAboveGreatestExists {
                position: 1,
                version: 9,
            },
            SearchError::RightmostInconsistent {
                position: 6,
                claimed: 3,
            },
            SearchError::MissingLadderKey {
                position: 1,
                version: 2,
            },
            SearchError::MissingCommitment {
                position: 1,
                version: 2,
            },
            SearchError::NoEntryHoldsTheGreatestVersion { claimed: 4 },
            SearchError::from(Error::Exhausted {
                array: "timestamps",
                position: 1,
            }),
            SearchError::from(prefix::Error::DepthOverflow { depth: 256 }),
            SearchError::from(ibst::Error::EmptyLog),
            SearchError::from(ladder::Error::UnrepresentableRung {
                rung: 1 << 32,
                greatest: u32::MAX,
            }),
            SearchError::from(distinguished::Error::MissingTimestamp { position: 1 }),
        ];
        for error in &errors {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
        assert!(core::error::Error::source(&errors[6]).is_some());
        assert!(core::error::Error::source(&errors[0]).is_none());
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod fixed_tests {
    use super::search_tests::{keys_through, tree_at};
    use super::*;
    use alloc::vec;
    use kt_wire::proofs::InclusionProof;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;
    const WINDOW: u64 = 604_800_000;

    /// Builds the proof a log serves for a fixed-version search, by running §7.2's own walk and
    /// answering each entry with exactly the ladder it would answer. `lifetime` and the
    /// timestamps decide which entries are skipped as expired.
    fn build_fixed(
        size: u64,
        target: u32,
        lifetime: u64,
        stamps: &[u64],
    ) -> (CombinedTreeProof, Vec<u64>) {
        let rightmost = stamps[(size - 1) as usize];
        let mut timestamps = vec![rightmost];
        let mut order = vec![size - 1];
        let mut proofs = Vec::new();
        let mut established = Established::default();
        let mut above: Vec<u64> = Vec::new();
        let mut current = ibst::root(size).unwrap();

        let identified = loop {
            if !order.contains(&current) {
                timestamps.push(stamps[current as usize]);
                order.push(current);
            }
            if expired(lifetime, stamps[current as usize], rightmost) {
                match ibst::right(current, size) {
                    Ok(child) => {
                        current = child;
                        continue;
                    }
                    Err(_) => break above.first().copied(),
                }
            }
            let local = u32::try_from(current).unwrap();
            let (left, right) = established.sets_for(current);
            let versions = ladder::search_binary_ladder(target, local, &left, &right).unwrap();
            let tree = tree_at(current);
            let searches: Vec<HashValue> = versions
                .iter()
                .map(|v| super::search_tests::key_for(*v))
                .collect();
            let proof = tree.prove(SUITE, &searches).unwrap();
            established.record(current, &versions, &proof.results);
            proofs.push(proof);

            match local.cmp(&target) {
                core::cmp::Ordering::Less => match ibst::right(current, size) {
                    Ok(child) => current = child,
                    Err(_) => break above.first().copied(),
                },
                core::cmp::Ordering::Greater => {
                    above.push(current);
                    match ibst::left(current) {
                        Ok(child) => current = child,
                        Err(_) => break above.first().copied(),
                    }
                }
                core::cmp::Ordering::Equal => break None,
            }
        };

        // Step 6.3's extra lookup, where the walk ended without finding the target as greatest.
        if let Some(position) = identified {
            let tree = tree_at(position);
            let key = super::search_tests::key_for(target);
            proofs.push(tree.prove(SUITE, &[key]).unwrap());
        }

        // §12.3: an entry with a timestamp but no proof is owed a prefix root, left to right.
        let mut owed: Vec<u64> = order
            .iter()
            .copied()
            .filter(|position| {
                !established.entries.iter().any(|(at, _, _)| at == position)
                    && Some(*position) != identified
            })
            .collect();
        owed.sort_unstable();
        let prefix_roots = owed
            .iter()
            .map(|position| tree_at(*position).root(SUITE))
            .collect();

        (
            CombinedTreeProof {
                timestamps,
                prefix_proofs: proofs,
                prefix_roots,
                inclusion: InclusionProof::new(Vec::new()),
            },
            order,
        )
    }

    fn clustered(size: u64) -> Vec<u64> {
        (0..size).map(|i| 1_700_000_000_000 + i).collect()
    }

    /// The main path: a binary search that moves left and then right to land on the entry where
    /// the target became the greatest version.
    #[test]
    fn a_fixed_version_search_finds_its_entry_and_consumes_exactly() {
        let size = 7_u64;
        let target = 2_u32;
        let stamps = clustered(size);
        let (proof, _) = build_fixed(size, target, 0, &stamps);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        let outcome = fixed_version_search(
            SUITE,
            size,
            0,
            WINDOW,
            target,
            &keys_through(6),
            &mut reader,
        )
        .unwrap();
        match outcome {
            FixedOutcome::Found { terminal, .. } => assert_eq!(terminal, u64::from(target)),
            other => panic!("expected to find version {target}, got {other:?}"),
        }
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// A version the log never had. §7.2 step 6.1: no inspected entry ever showed a greatest
    /// above the target, so there is nowhere it could have been.
    #[test]
    fn a_version_above_everything_does_not_exist() {
        let size = 7_u64;
        let stamps = clustered(size);
        let (proof, _) = build_fixed(size, 99, 0, &stamps);
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        let outcome =
            fixed_version_search(SUITE, size, 0, WINDOW, 99, &keys_through(99), &mut reader)
                .unwrap();
        assert_eq!(outcome, FixedOutcome::DoesNotExist);
    }

    /// §7.1 and §7.2 step 1: an expired entry is skipped without a ladder at all, which is what
    /// lets a log prune old prefix trees. The search still has to reach a conclusion.
    #[test]
    fn an_expired_entry_is_skipped_without_a_ladder() {
        let size = 7_u64;
        let target = 6_u32;
        // Entries a day apart, with a two-day lifetime: everything but the last three is
        // expired. §7.1 requires the lifetime to exceed the monitoring window, so the window
        // here is an hour.
        let day = 86_400_000_u64;
        let stamps: Vec<u64> = (0..size).map(|i| 1_700_000_000_000 + i * day).collect();
        let lifetime = 2 * day;
        let window = 3_600_000;
        let (proof, _) = build_fixed(size, target, lifetime, &stamps);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        let outcome = fixed_version_search(
            SUITE,
            size,
            lifetime,
            window,
            target,
            &keys_through(6),
            &mut reader,
        )
        .unwrap();
        // The root of a seven-entry log is entry 3, four days behind the rightmost, so the
        // search starts on an expired entry and moves right on the timestamp alone.
        assert!(expired(lifetime, stamps[3], stamps[6]));
        match outcome {
            FixedOutcome::Found { terminal, .. } => assert_eq!(terminal, 6),
            other => panic!("expected to find version {target}, got {other:?}"),
        }
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// §7.1's boundary, which is "greater than or equal to" rather than "greater than": an entry
    /// exactly one lifetime behind the rightmost is expired.
    #[test]
    fn expiry_is_inclusive_at_the_boundary() {
        assert!(expired(10, 90, 100), "exactly one lifetime behind");
        assert!(!expired(10, 91, 100), "one millisecond inside");
        assert!(
            !expired(0, 0, u64::MAX),
            "a lifetime of zero means no expiry"
        );
        // Non-monotonic timestamps would wrap the subtraction; a fresh entry must not be
        // reported as expired because of it.
        assert!(!expired(10, 200, 100));
    }

    #[test]
    fn fixed_outcomes_are_distinguishable() {
        let found = FixedOutcome::Found {
            terminal: 3,
            inspected: vec![(3, HashValue::ZERO)],
        };
        assert_ne!(found, FixedOutcome::DoesNotExist);
        assert_ne!(FixedOutcome::DoesNotExist, FixedOutcome::Expired);
    }
}
