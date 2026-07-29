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
use alloc::vec;
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

    /// Whether every element has been read.
    ///
    /// Needed by exactly one algorithm. §8.3's second algorithm says at step 4 that "the only stop
    /// condition" from a user's perspective "is having consumed all of the Transparency Log's
    /// response" — so there, running out of proof is a legitimate outcome rather than an error. It
    /// is the one place in the protocol where the element count decides when the algorithm stops,
    /// instead of the algorithm deciding what the element count should be.
    #[must_use]
    pub fn is_exhausted(&self) -> bool {
        self.timestamps_used >= self.proof.timestamps.len()
            && self.proofs_used >= self.proof.prefix_proofs.len()
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

    pub(super) fn commitment_for(version: u32) -> HashValue {
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

/// One entry of a user's monitoring map: a log entry, and the version proven to exist there.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct MapEntry {
    /// The log entry the user is tracking.
    pub position: u64,
    /// The greatest version of the label proven to exist at that entry.
    pub version: u32,
}

/// What contact monitoring did to a user's map (§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Monitored {
    /// The map to carry forward: every pair moved up to the entry that vouched for it, with the
    /// ones a distinguished entry has now covered dropped entirely.
    ///
    /// §8.2's last step is what makes monitoring terminate: "remove all mappings where the
    /// position corresponds to a distinguished log entry". A version that has been proven
    /// correct at a reference point everybody else checks needs no further watching.
    pub map: Vec<MapEntry>,
    /// The entries inspected, with the prefix tree root each proof computed.
    pub inspected: Vec<(u64, HashValue)>,
}

/// Runs §8.2's contact monitoring algorithm against a proof.
///
/// `map` is the user's monitoring state — the pairs a search left behind — and `window` the
/// Reasonable Monitoring Window. The map is processed "from rightmost to leftmost log entry",
/// which is the opposite direction from every other algorithm here and the reason §12.3's
/// monotonicity rule has to look both ways: a timestamp read later can belong to an entry
/// further left.
///
/// # Errors
///
/// [`MonitorError`] where the proof does not establish what §8.2 requires.
pub fn contact_monitor(
    suite: CipherSuite,
    size: u64,
    window: u64,
    map: &[MapEntry],
    keys: &BTreeMap<u32, LadderKey>,
    reader: &mut Reader<'_>,
) -> core::result::Result<Monitored, MonitorError> {
    let mut pairs: Vec<MapEntry> = map.to_vec();
    // Rightmost to leftmost, as §8.2 says. Sorting rather than trusting the caller: the order
    // decides which element of the proof belongs to which map entry, so it is part of the
    // protocol rather than a convenience.
    pairs.sort_unstable_by_key(|pair| core::cmp::Reverse(pair.position));

    let mut inspected: Vec<(u64, HashValue)> = Vec::new();
    // Ladders already provided in this response, by the entry they came from, for step 3.1.
    let mut provided: BTreeMap<u64, u32> = BTreeMap::new();
    let mut updated: Vec<MapEntry> = Vec::new();
    // Which entries are known distinguished, and which known not: the descent in step 2 learns
    // this as it goes, and §6.1's ancestor-closure means a non-distinguished entry settles every
    // entry below it too.
    let mut distinguished_at: BTreeMap<u64, bool> = BTreeMap::new();

    for pair in pairs {
        // §12.3.4: "the timestamp of each log entry on the path from the root to the parent of
        // the log entry in the user's monitoring map, stopping if a non-distinguished log entry
        // is established". That descent is what tells the verifier which entries are
        // distinguished, so it has to happen before step 1 can be answered.
        descend_for_distinguished(size, window, pair.position, reader, &mut distinguished_at)?;

        // Step 1: a distinguished entry needs no monitoring, and stays in the map for the final
        // sweep to remove.
        if distinguished_at
            .get(&pair.position)
            .copied()
            .unwrap_or(false)
        {
            updated.push(pair);
            continue;
        }

        // Step 2.
        let list = entries_to_inspect(size, pair.position, &distinguished_at)?;

        // Step 3.
        let mut moved = None;
        let mut superseded = false;
        for entry in list {
            // Step 3.1: a ladder for this entry may already have been provided for another map
            // entry. Whether that is a saving or an error depends on which version it targeted.
            if let Some(target) = provided.get(&entry).copied() {
                if target > pair.version {
                    // Step 3.1.1: a greater version at the same entry subsumes this one — proving
                    // the greater version exists there proves every lesser version does.
                    superseded = true;
                    break;
                }
                // Step 3.1.2: a ladder for an equal or lesser version tells the user nothing new,
                // so the log has sent something it should not have.
                return Err(MonitorError::RedundantLadder {
                    position: entry,
                    provided: target,
                    wanted: pair.version,
                });
            }

            // Step 3.2: every lookup a monitoring ladder specifies must be present and must show
            // inclusion. A monitoring ladder makes no claim about what does *not* exist — it only
            // re-proves what the user already knows, at a new position.
            let versions = ladder::monitoring_binary_ladder(pair.version, &[]);
            let proof = reader.prefix_proof(entry)?;
            if proof.results.len() != versions.len() {
                return Err(MonitorError::LadderLength {
                    position: entry,
                    expected: versions.len(),
                    actual: proof.results.len(),
                });
            }
            let mut entries = Vec::new();
            for (version, result) in versions.iter().zip(proof.results.iter()) {
                if !result.is_inclusion() {
                    return Err(MonitorError::VersionMissing {
                        position: entry,
                        version: *version,
                    });
                }
                let key = keys.get(version).ok_or(MonitorError::MissingLadderKey {
                    position: entry,
                    version: *version,
                })?;
                entries.push(prefix::SearchEntry::included(
                    key.vrf_output,
                    key.commitment.ok_or(MonitorError::MissingCommitment {
                        position: entry,
                        version: *version,
                    })?,
                ));
            }
            let root = prefix::evaluate(suite, &entries, proof)?;
            reader.establish_root(entry, root)?;
            inspected.push((entry, root));
            provided.insert(entry, pair.version);

            // Step 3.3: the pair moves up to the entry that just vouched for it.
            moved = Some(entry);
        }

        if superseded {
            // The lesser pair leaves the map entirely.
            continue;
        }
        updated.push(MapEntry {
            position: moved.unwrap_or(pair.position),
            version: pair.version,
        });
    }

    // §8.2's final step: drop everything a distinguished entry now covers. What remains sits on
    // the frontier, which is where the next round of monitoring will pick it up.
    updated.retain(|pair| {
        !distinguished_at
            .get(&pair.position)
            .copied()
            .unwrap_or(false)
    });
    updated.sort_unstable();
    Ok(Monitored {
        map: updated,
        inspected,
    })
}

/// Reads timestamps down the path to `position`'s parent, recording what is distinguished.
///
/// §12.3.4 stops "if a non-distinguished log entry is established", and that early stop is sound
/// for the same reason §6.1's set is ancestor-closed: the recursion reaches a node only through
/// distinguished ancestors, so once one link is broken nothing below it can be distinguished
/// either. The verifier therefore needs no timestamps past that point, and the log sends none.
fn descend_for_distinguished(
    size: u64,
    window: u64,
    position: u64,
    reader: &mut Reader<'_>,
    known: &mut BTreeMap<u64, bool>,
) -> core::result::Result<(), MonitorError> {
    let last = size.saturating_sub(1);
    let rightmost = reader.timestamp(last)?;

    // The descent: root, then each node down to the map entry. §12.3.4 supplies a timestamp for
    // each entry "on the path from the root to the parent", which is why the map entry's own
    // timestamp is never read here — its distinguishedness follows from its parent's brackets.
    let mut chain = ibst::direct_path(position, size)?;
    chain.reverse();
    chain.push(position);

    // §6.1 brackets a node by the timestamps either side of it, and which side a step updates
    // depends on which way it goes: descending to a right child raises the left bracket to the
    // parent's timestamp, descending to a left child lowers the right bracket to it. Getting this
    // wrong is not a rounding error — it decides whether an entry counts as distinguished, and it
    // only shows up for map entries that are left descendants.
    let mut left = (0_u64, 0_u64);
    let mut right = (last, rightmost);

    for (index, entry) in chain.iter().enumerate() {
        if let Some(false) = known.get(entry) {
            // Already settled as non-distinguished, and so is everything below it.
            for rest in chain.get(index..).unwrap_or_default() {
                known.insert(*rest, false);
            }
            return Ok(());
        }
        let is = distinguished::is_distinguished(window, left, right)?;
        known.insert(*entry, is);
        if !is {
            // Ancestor-closure: nothing below a non-distinguished entry can be distinguished, so
            // the log sends no more timestamps and the verifier needs none.
            for rest in chain.get(index..).unwrap_or_default() {
                known.insert(*rest, false);
            }
            return Ok(());
        }
        let Some(next) = chain.get(index.saturating_add(1)).copied() else {
            break;
        };
        let timestamp = reader.timestamp(*entry)?;
        if next < *entry {
            right = (*entry, timestamp);
        } else {
            left = (*entry, timestamp);
        }
    }
    Ok(())
}

/// §8.2 step 2's ordered list of log entries to inspect.
fn entries_to_inspect(
    size: u64,
    position: u64,
    known: &BTreeMap<u64, bool>,
) -> core::result::Result<Vec<u64>, MonitorError> {
    // 2.1: the entry's direct path.
    let mut list = ibst::direct_path(position, size)?;
    // 2.2: nothing to the left of the entry. Monitoring moves *up* the tree as new intermediate
    // nodes are established, and an ancestor to the left was established before the version
    // being monitored existed, so it can say nothing about it.
    list.retain(|entry| *entry > position);
    list.sort_unstable();
    // 2.3: terminate just after the first distinguished entry. Past that point monitoring is
    // finished — a distinguished entry is a reference point the whole deployment checks.
    if let Some(index) = list
        .iter()
        .position(|entry| known.get(entry).copied().unwrap_or(false))
    {
        list.truncate(index.saturating_add(1));
    }
    Ok(list)
}

/// Why contact monitoring rejected a proof (§8.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MonitorError {
    /// A ladder was provided twice for the same entry, for a version that teaches nothing new
    /// (§8.2 step 3.1.2).
    RedundantLadder {
        /// The log entry.
        position: u64,
        /// The version the earlier ladder targeted.
        provided: u32,
        /// The version this map entry wanted.
        wanted: u32,
    },
    /// An entry's proof carried a different number of results than its monitoring ladder calls
    /// for (§8.2 step 3.2, "all expected lookups are present").
    LadderLength {
        /// The log entry.
        position: u64,
        /// How many lookups the ladder specifies.
        expected: usize,
        /// How many the proof carried.
        actual: usize,
    },
    /// A version the user already knows exists was not proven present (§8.2 step 3.2).
    ///
    /// This is monitoring's whole point: the log has dropped or moved something it had already
    /// committed to.
    VersionMissing {
        /// The log entry.
        position: u64,
        /// The version that should have been there.
        version: u32,
    },
    /// No search key was available for a version the ladder looks up.
    MissingLadderKey {
        /// The log entry.
        position: u64,
        /// The version.
        version: u32,
    },
    /// No commitment was available for a version the ladder proves present.
    MissingCommitment {
        /// The log entry.
        position: u64,
        /// The version.
        version: u32,
    },
    /// The proof could not be read as §12.3 requires.
    Proof(Error),
    /// A prefix tree proof did not evaluate.
    Prefix(prefix::Error),
    /// The search tree could not be navigated.
    Ibst(ibst::Error),
    /// The distinguished entries could not be determined.
    Distinguished(distinguished::Error),
}

impl From<Error> for MonitorError {
    fn from(err: Error) -> Self {
        Self::Proof(err)
    }
}

impl From<prefix::Error> for MonitorError {
    fn from(err: prefix::Error) -> Self {
        Self::Prefix(err)
    }
}

impl From<ibst::Error> for MonitorError {
    fn from(err: ibst::Error) -> Self {
        Self::Ibst(err)
    }
}

impl From<distinguished::Error> for MonitorError {
    fn from(err: distinguished::Error) -> Self {
        Self::Distinguished(err)
    }
}

impl core::fmt::Display for MonitorError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::RedundantLadder {
                position,
                provided,
                wanted,
            } => write!(
                f,
                "log entry {position} already carried a ladder for version {provided}, which \
                 teaches nothing about version {wanted}"
            ),
            Self::LadderLength {
                position,
                expected,
                actual,
            } => write!(
                f,
                "log entry {position}'s monitoring ladder should have {expected} lookups, the \
                 proof has {actual}"
            ),
            Self::VersionMissing { position, version } => write!(
                f,
                "log entry {position} does not contain version {version}, which the user has \
                 already been shown"
            ),
            Self::MissingLadderKey { position, version } => write!(
                f,
                "no search key for version {version}, looked up at log entry {position}"
            ),
            Self::MissingCommitment { position, version } => write!(
                f,
                "no commitment for version {version}, proven present at log entry {position}"
            ),
            Self::Proof(err) => write!(f, "reading the proof: {err}"),
            Self::Prefix(err) => write!(f, "evaluating a prefix tree proof: {err}"),
            Self::Ibst(err) => write!(f, "walking the search tree: {err}"),
            Self::Distinguished(err) => write!(f, "finding the distinguished entries: {err}"),
        }
    }
}

impl core::error::Error for MonitorError {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Proof(err) => Some(err),
            Self::Prefix(err) => Some(err),
            Self::Ibst(err) => Some(err),
            Self::Distinguished(err) => Some(err),
            _ => None,
        }
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
mod monitor_tests {
    use super::search_tests::{key_for, tree_at};
    use super::*;
    use alloc::vec;
    use kt_wire::proofs::InclusionProof;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    /// The versions a monitoring client holds: for a log where version `v` was added at entry
    /// `v`, every version up to `greatest`, with the commitment it kept from its search.
    fn known(greatest: u32) -> BTreeMap<u32, LadderKey> {
        let mut keys = BTreeMap::new();
        for version in 0..=greatest {
            keys.insert(
                version,
                LadderKey {
                    vrf_output: key_for(version),
                    commitment: Some(super::search_tests::commitment_for(version)),
                },
            );
        }
        keys
    }

    /// Builds the proof a log serves for §8.2 over `map`, in §12.3.4's order: per map entry from
    /// rightmost to leftmost, the timestamps down the path to its parent, then a monitoring
    /// ladder proof from each entry in step 2's list.
    fn build_monitor(
        size: u64,
        window: u64,
        map: &[MapEntry],
        stamps: &[u64],
    ) -> CombinedTreeProof {
        let last = size - 1;
        let mut timestamps: Vec<u64> = vec![stamps[last as usize]];
        let mut seen: Vec<u64> = vec![last];
        let mut proofs = Vec::new();
        let mut proved: Vec<u64> = Vec::new();
        let mut known_distinguished: BTreeMap<u64, bool> = BTreeMap::new();

        let mut pairs = map.to_vec();
        pairs.sort_unstable_by_key(|pair| core::cmp::Reverse(pair.position));
        for pair in &pairs {
            // The descent: root to the parent, stopping at the first non-distinguished entry.
            let mut chain = ibst::direct_path(pair.position, size).unwrap();
            chain.reverse();
            chain.push(pair.position);
            let mut left = (0_u64, 0_u64);
            let mut right = (last, stamps[last as usize]);
            let mut settled = false;
            for (index, entry) in chain.iter().enumerate() {
                let is = distinguished::is_distinguished(window, left, right).unwrap();
                known_distinguished.insert(*entry, is);
                if !is {
                    for rest in &chain[index..] {
                        known_distinguished.insert(*rest, false);
                    }
                    break;
                }
                let Some(next) = chain.get(index + 1).copied() else {
                    // The map entry itself is distinguished, so §8.2 step 1 leaves it alone.
                    settled = true;
                    break;
                };
                if !seen.contains(entry) {
                    timestamps.push(stamps[*entry as usize]);
                    seen.push(*entry);
                }
                if next < *entry {
                    right = (*entry, stamps[*entry as usize]);
                } else {
                    left = (*entry, stamps[*entry as usize]);
                }
            }
            if settled {
                continue;
            }

            for entry in entries_to_inspect(size, pair.position, &known_distinguished).unwrap() {
                let versions = ladder::monitoring_binary_ladder(pair.version, &[]);
                let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
                proofs.push(tree_at(entry).prove(SUITE, &searches).unwrap());
                proved.push(entry);
            }
        }

        // §12.3: an entry with a timestamp but no proof is owed a prefix root, left to right.
        // The log tree's leaves need both halves, so this is not optional padding.
        let mut owed: Vec<u64> = seen
            .iter()
            .copied()
            .filter(|entry| !proved.contains(entry))
            .collect();
        owed.sort_unstable();
        let prefix_roots = owed
            .iter()
            .map(|entry| tree_at(*entry).root(SUITE))
            .collect();

        CombinedTreeProof {
            timestamps,
            prefix_proofs: proofs,
            prefix_roots,
            inclusion: InclusionProof::new(Vec::new()),
        }
    }

    /// Entries a millisecond apart, so a week-long window leaves only the root distinguished.
    fn clustered(size: u64) -> Vec<u64> {
        (0..size).map(|i| 1_700_000_000_000 + i).collect()
    }

    /// The ordinary case: a version tracked at a non-distinguished entry is re-proven further up
    /// the tree, and the map moves with it.
    #[test]
    fn monitoring_moves_the_map_up_the_tree() {
        let size = 7_u64;
        let window = 604_800_000;
        let stamps = clustered(size);
        // Entry 2 has an ancestor to its right (entry 3) *and* is not itself distinguished, which
        // is the shape §8.2 does work for. Two nearby shapes do nothing at all: an entry on the
        // frontier has no ancestors to its right, and a left descendant like entry 1 keeps a left
        // bracket of zero and so is always distinguished. That is why the recorded
        // `contact-one-version` case carries no prefix proofs.
        let map = vec![MapEntry {
            position: 2,
            version: 2,
        }];
        let proof = build_monitor(size, window, &map, &stamps);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        let monitored = contact_monitor(SUITE, size, window, &map, &known(2), &mut reader).unwrap();

        // The pair ends up above where it started, which is the whole mechanic: monitoring
        // follows a version upward as new intermediate nodes are built over it.
        assert!(!monitored.inspected.is_empty());
        assert!(
            monitored.map.iter().all(|pair| pair.position >= 2),
            "the map moved up, not down: {:?}",
            monitored.map
        );
        for (position, root) in &monitored.inspected {
            assert_eq!(*root, tree_at(*position).root(SUITE), "entry {position}");
        }
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// What monitoring exists to catch. A log that drops or moves a version the user has already
    /// been shown fails here, and nowhere else would notice.
    #[test]
    fn a_version_the_user_already_has_must_still_be_there() {
        let size = 7_u64;
        let window = 604_800_000;
        let stamps = clustered(size);
        let map = vec![MapEntry {
            position: 2,
            version: 2,
        }];
        let honest = build_monitor(size, window, &map, &stamps);

        // Re-prove the inspected entry against a tree that never had version 1, which is what a
        // log rolling a value back would produce.
        let mut tampered = honest.clone();
        let versions = ladder::monitoring_binary_ladder(2, &[]);
        let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
        tampered.prefix_proofs = vec![tree_at(1).prove(SUITE, &searches).unwrap()];

        let retained = Retained::none();
        let mut reader = Reader::new(&tampered, &retained);
        let refused = contact_monitor(SUITE, size, window, &map, &known(2), &mut reader);
        assert!(
            matches!(refused, Err(MonitorError::VersionMissing { .. })),
            "expected a missing version, got {refused:?}"
        );
    }

    /// §8.2 step 1 and the final sweep: a pair already at a distinguished entry is not monitored,
    /// and then leaves the map. That is what makes monitoring terminate rather than grow.
    #[test]
    fn a_distinguished_entry_leaves_the_map() {
        let size = 7_u64;
        let window = 604_800_000;
        let stamps = clustered(size);
        // Entry 3 is the root of a seven-entry log, and with a week-long window it is the only
        // distinguished entry.
        let map = vec![MapEntry {
            position: 3,
            version: 3,
        }];
        let proof = build_monitor(size, window, &map, &stamps);
        assert!(
            proof.prefix_proofs.is_empty(),
            "a distinguished entry needs no ladder at all"
        );

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        let monitored = contact_monitor(SUITE, size, window, &map, &known(3), &mut reader).unwrap();
        assert!(
            monitored.map.is_empty(),
            "the pair should have been dropped: {:?}",
            monitored.map
        );
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// §8.2 step 2's list, checked directly: the direct path, with everything left of the entry
    /// removed and the tail cut just after the first distinguished entry.
    #[test]
    fn the_list_to_inspect_is_the_path_rightward() {
        let size = 7_u64;
        let mut known_distinguished = BTreeMap::new();

        // Nothing distinguished: the whole path to the right survives.
        let list = entries_to_inspect(size, 5, &known_distinguished).unwrap();
        assert!(list.iter().all(|entry| *entry > 5), "{list:?}");
        assert!(list.windows(2).all(|pair| pair[0] < pair[1]), "ascending");

        // With an entry distinguished, the list stops just after it.
        if let Some(first) = list.first().copied() {
            known_distinguished.insert(first, true);
            let truncated = entries_to_inspect(size, 5, &known_distinguished).unwrap();
            assert_eq!(truncated, vec![first]);
        }
    }

    #[test]
    fn monitor_errors_describe_themselves() {
        use alloc::string::ToString;
        let errors = [
            MonitorError::RedundantLadder {
                position: 3,
                provided: 2,
                wanted: 2,
            },
            MonitorError::LadderLength {
                position: 3,
                expected: 2,
                actual: 1,
            },
            MonitorError::VersionMissing {
                position: 3,
                version: 2,
            },
            MonitorError::MissingLadderKey {
                position: 3,
                version: 2,
            },
            MonitorError::MissingCommitment {
                position: 3,
                version: 2,
            },
            MonitorError::from(Error::Exhausted {
                array: "prefix_proofs",
                position: 3,
            }),
            MonitorError::from(prefix::Error::DepthOverflow { depth: 256 }),
            MonitorError::from(ibst::Error::EmptyLog),
            MonitorError::from(distinguished::Error::MissingTimestamp { position: 1 }),
        ];
        for error in &errors {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
        assert!(core::error::Error::source(&errors[5]).is_some());
        assert!(core::error::Error::source(&errors[0]).is_none());
    }
}

/// What owner initialization established (§8.3's first algorithm).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Initialized {
    /// The entries inspected, left to right, with the prefix tree root each proof computed.
    pub inspected: Vec<(u64, HashValue)>,
    /// The greatest version the owner should now consider itself to hold, if the label existed at
    /// the starting position.
    pub greatest: Option<u32>,
}

/// Runs §8.3's first algorithm: a label owner initializing state at a distinguished entry.
///
/// An owner is in a different position from a searcher or a contact. A searcher asks about one
/// version; an owner is claiming the label, and has to establish what the log thinks the *whole
/// history* looks like as of the entry it is starting from. So the response carries a greatest
/// version per inspected entry rather than one ladder, and this checks that those versions
/// descend as the entries go back in time — a label's version count can only grow, so seeing it
/// grow backwards means the log is lying about one of them.
///
/// `start` is the requested starting position, which §13.3 requires to be unexpired and
/// distinguished. `greatest_versions` is the response's list, which may be *shorter* than the
/// list of entries inspected: §13.3 says it ends "at the first log entry where the label doesn't
/// exist", and entries past that are searched for version zero instead.
///
/// The ladders here are full: §8.3 step 5 says "without omitting redundant lookups", unlike §6.3
/// and §7.2. An owner is establishing history rather than locating one version, so there is
/// nothing for a later ladder to lean on.
///
/// # Errors
///
/// [`InitError`] where the proof does not establish what §8.3 requires.
pub fn owner_init(
    suite: CipherSuite,
    size: u64,
    lifetime: u64,
    start: u64,
    greatest_versions: &[u32],
    keys: &BTreeMap<u32, LadderKey>,
    reader: &mut Reader<'_>,
) -> core::result::Result<Initialized, InitError> {
    let last = size.saturating_sub(1);
    let rightmost = reader.timestamp(last)?;

    // §12.3.5: "the timestamp of each log entry on the path from the root to the user's requested
    // starting position". The timestamps are what let both sides check that the start is
    // unexpired and distinguished, which is the precondition the whole operation rests on.
    let mut chain = ibst::direct_path(start, size)?;
    chain.reverse();
    for entry in &chain {
        reader.timestamp(*entry)?;
    }
    let start_timestamp = reader.timestamp(start)?;
    if expired(lifetime, start_timestamp, rightmost) {
        return Err(InitError::StartExpired {
            start,
            timestamp: start_timestamp,
            rightmost,
        });
    }

    // Step 1: the starting position, then the entries on its direct path and to its left, ending
    // just before the first expired one. Left, because an owner is looking *backwards* through
    // the history it is adopting — the opposite direction from contact monitoring, which follows
    // its versions forward.
    let mut list = vec![start];
    let mut path = ibst::direct_path(start, size)?;
    path.retain(|entry| *entry < start);
    path.sort_unstable_by_key(|entry| core::cmp::Reverse(*entry));
    for entry in path {
        let timestamp = reader.timestamp(entry)?;
        if expired(lifetime, timestamp, rightmost) {
            break;
        }
        list.push(entry);
    }

    // Step 2's check: the greatest version cannot grow as the entries go back in time.
    for pair in greatest_versions.windows(2) {
        if let [earlier, later] = pair {
            if later > earlier {
                return Err(InitError::VersionsNotDescending {
                    earlier: *earlier,
                    later: *later,
                });
            }
        }
    }
    if greatest_versions.len() > list.len() {
        return Err(InitError::TooManyVersions {
            supplied: greatest_versions.len(),
            inspected: list.len(),
        });
    }

    // Step 5: one full ladder per inspected entry, targeting that entry's greatest version — or
    // zero where the label did not exist there, which is what a list shorter than the entries
    // means.
    let mut inspected = Vec::new();
    for (index, entry) in list.iter().enumerate() {
        let target = greatest_versions.get(index).copied().unwrap_or(0);
        let versions = ladder::search_binary_ladder(target, target, &[], &[])?;
        let proof = reader.prefix_proof(*entry)?;
        let used = versions
            .get(..proof.results.len())
            .ok_or(InitError::LadderLength {
                position: *entry,
                expected: versions.len(),
                actual: proof.results.len(),
            })?;

        let ordering = ladder::interpret_search_ladder(used, target, &proof.results)?;
        let exists = greatest_versions.get(index).is_some();
        // A ladder for an entry where the label exists must place the greatest version *at* the
        // claim. Where it does not exist, version zero must be absent — that is what "no value is
        // provided" in step 2 has to mean for the proof to say anything.
        let expected = if exists {
            core::cmp::Ordering::Equal
        } else {
            core::cmp::Ordering::Less
        };
        if ordering != expected {
            return Err(InitError::LadderInconsistent {
                position: *entry,
                claimed: target,
                exists,
            });
        }

        let mut entries = Vec::new();
        for (version, result) in used.iter().zip(proof.results.iter()) {
            let key = keys.get(version).ok_or(InitError::MissingLadderKey {
                position: *entry,
                version: *version,
            })?;
            entries.push(if result.is_inclusion() {
                prefix::SearchEntry::included(
                    key.vrf_output,
                    key.commitment.ok_or(InitError::MissingCommitment {
                        position: *entry,
                        version: *version,
                    })?,
                )
            } else {
                prefix::SearchEntry::absent(key.vrf_output)
            });
        }
        let root = prefix::evaluate(suite, &entries, proof)?;
        reader.establish_root(*entry, root)?;
        inspected.push((*entry, root));
    }

    Ok(Initialized {
        inspected,
        greatest: greatest_versions.first().copied(),
    })
}

/// Why owner initialization rejected a proof (§8.3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InitError {
    /// The requested starting position is expired, which §13.3 forbids.
    StartExpired {
        /// The position asked for.
        start: u64,
        /// Its timestamp.
        timestamp: u64,
        /// The rightmost entry's timestamp, which expiry is relative to.
        rightmost: u64,
    },
    /// The greatest versions do not descend (§8.3 step 2, §13.3 step 1).
    ///
    /// A label's version count only grows, so a later entry in this list — which goes backwards
    /// through the log — cannot hold a greater version than an earlier one.
    VersionsNotDescending {
        /// The version at the earlier position in the list.
        earlier: u32,
        /// The greater version that followed it.
        later: u32,
    },
    /// More greatest versions were supplied than there are entries to inspect (§13.3 step 1).
    TooManyVersions {
        /// How many the response carried.
        supplied: usize,
        /// How many entries §8.3 step 1 computes.
        inspected: usize,
    },
    /// An entry's proof carried more results than its ladder specifies.
    LadderLength {
        /// The log entry.
        position: u64,
        /// How many lookups the ladder specifies.
        expected: usize,
        /// How many the proof carried.
        actual: usize,
    },
    /// An entry's ladder does not place the greatest version where the response claims.
    LadderInconsistent {
        /// The log entry.
        position: u64,
        /// The version claimed greatest there, or zero where the label was claimed absent.
        claimed: u32,
        /// Whether the response claimed the label existed at this entry.
        exists: bool,
    },
    /// No search key was available for a version the ladder looks up.
    MissingLadderKey {
        /// The log entry.
        position: u64,
        /// The version.
        version: u32,
    },
    /// No commitment was available for a version the ladder proves present.
    MissingCommitment {
        /// The log entry.
        position: u64,
        /// The version.
        version: u32,
    },
    /// The proof could not be read as §12.3 requires.
    Proof(Error),
    /// A prefix tree proof did not evaluate.
    Prefix(prefix::Error),
    /// The search tree could not be navigated.
    Ibst(ibst::Error),
    /// A ladder could not be computed.
    Ladder(ladder::Error),
    /// Distinguishedness could not be decided from the timestamps available.
    Distinguished(distinguished::Error),
}

impl From<distinguished::Error> for InitError {
    fn from(err: distinguished::Error) -> Self {
        Self::Distinguished(err)
    }
}

impl From<Error> for InitError {
    fn from(err: Error) -> Self {
        Self::Proof(err)
    }
}

impl From<prefix::Error> for InitError {
    fn from(err: prefix::Error) -> Self {
        Self::Prefix(err)
    }
}

impl From<ibst::Error> for InitError {
    fn from(err: ibst::Error) -> Self {
        Self::Ibst(err)
    }
}

impl From<ladder::Error> for InitError {
    fn from(err: ladder::Error) -> Self {
        Self::Ladder(err)
    }
}

impl core::fmt::Display for InitError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StartExpired {
                start,
                timestamp,
                rightmost,
            } => write!(
                f,
                "the requested starting entry {start} is expired: its timestamp {timestamp} \
                 against a rightmost of {rightmost}"
            ),
            Self::VersionsNotDescending { earlier, later } => write!(
                f,
                "the greatest versions do not descend: {later} follows {earlier}, but a label's \
                 version count only grows"
            ),
            Self::TooManyVersions {
                supplied,
                inspected,
            } => write!(
                f,
                "the response carried {supplied} greatest versions for {inspected} inspected \
                 entries"
            ),
            Self::LadderLength {
                position,
                expected,
                actual,
            } => write!(
                f,
                "log entry {position}'s ladder should have at most {expected} lookups, the proof \
                 has {actual}"
            ),
            Self::LadderInconsistent {
                position,
                claimed,
                exists,
            } => {
                if *exists {
                    write!(
                        f,
                        "log entry {position}'s ladder does not show version {claimed} as the \
                         greatest that exists"
                    )
                } else {
                    write!(
                        f,
                        "log entry {position} is claimed not to hold the label, but its ladder \
                         does not show version 0 absent"
                    )
                }
            }
            Self::MissingLadderKey { position, version } => write!(
                f,
                "no search key for version {version}, looked up at log entry {position}"
            ),
            Self::MissingCommitment { position, version } => write!(
                f,
                "no commitment for version {version}, proven present at log entry {position}"
            ),
            Self::Proof(err) => write!(f, "reading the proof: {err}"),
            Self::Prefix(err) => write!(f, "evaluating a prefix tree proof: {err}"),
            Self::Ibst(err) => write!(f, "walking the search tree: {err}"),
            Self::Ladder(err) => write!(f, "computing a binary ladder: {err}"),
            Self::Distinguished(err) => write!(f, "deciding distinguishedness: {err}"),
        }
    }
}

impl core::error::Error for InitError {
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

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod init_tests {
    use super::search_tests::{commitment_for, key_for, tree_at};
    use super::*;
    use kt_wire::proofs::InclusionProof;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    fn keys_upto(greatest: u32) -> BTreeMap<u32, LadderKey> {
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

    fn stamps(size: u64) -> Vec<u64> {
        (0..size).map(|i| 1_700_000_000_000 + i).collect()
    }

    /// The list §8.3 step 1 computes, and the proof a log would serve for it.
    fn build_init(
        size: u64,
        start: u64,
        lifetime: u64,
        stamps: &[u64],
    ) -> (CombinedTreeProof, Vec<u32>) {
        let last = size - 1;
        let rightmost = stamps[last as usize];
        let mut timestamps: Vec<u64> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        let push = |entry: u64, timestamps: &mut Vec<u64>, seen: &mut Vec<u64>| {
            if !seen.contains(&entry) {
                timestamps.push(stamps[entry as usize]);
                seen.push(entry);
            }
        };

        // The view update supplies the frontier's timestamps first.
        for entry in ibst::frontier(size).unwrap() {
            push(entry, &mut timestamps, &mut seen);
        }
        // §12.3.5: the path from the root to the starting position.
        let mut chain = ibst::direct_path(start, size).unwrap();
        chain.reverse();
        for entry in &chain {
            push(*entry, &mut timestamps, &mut seen);
        }
        push(start, &mut timestamps, &mut seen);

        // Step 1's list, and the timestamps the walk reads deciding where it ends.
        let mut list = vec![start];
        let mut path = ibst::direct_path(start, size).unwrap();
        path.retain(|entry| *entry < start);
        path.sort_unstable_by_key(|entry| core::cmp::Reverse(*entry));
        for entry in path {
            push(entry, &mut timestamps, &mut seen);
            if expired(lifetime, stamps[entry as usize], rightmost) {
                break;
            }
            list.push(entry);
        }

        // In this log version `v` was added at entry `v`, so the greatest version at an entry is
        // its own index — which descends as the list goes back in time, as step 2 requires.
        let greatest_versions: Vec<u32> = list
            .iter()
            .map(|entry| u32::try_from(*entry).unwrap())
            .collect();

        let mut proofs = Vec::new();
        for (index, entry) in list.iter().enumerate() {
            let target = greatest_versions[index];
            let versions = ladder::search_binary_ladder(target, target, &[], &[]).unwrap();
            let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
            proofs.push(tree_at(*entry).prove(SUITE, &searches).unwrap());
        }

        let mut owed: Vec<u64> = seen
            .iter()
            .copied()
            .filter(|entry| !list.contains(entry))
            .collect();
        owed.sort_unstable();
        let prefix_roots = owed
            .iter()
            .map(|entry| tree_at(*entry).root(SUITE))
            .collect();

        (
            CombinedTreeProof {
                timestamps,
                prefix_proofs: proofs,
                prefix_roots,
                inclusion: InclusionProof::new(Vec::new()),
            },
            greatest_versions,
        )
    }

    /// An owner adopting the history at entry 5 of a seven-entry log. Step 1's list is the start
    /// plus its ancestors to the *left* — backwards through the history being adopted, which is
    /// the opposite direction from contact monitoring.
    #[test]
    fn an_owner_initializes_and_consumes_the_proof_exactly() {
        let size = 7_u64;
        let start = 5_u64;
        let clock = stamps(size);
        let (proof, versions) = build_init(size, start, 0, &clock);
        assert!(versions.len() > 1, "the list should reach past the start");
        assert!(
            versions.windows(2).all(|pair| pair[0] >= pair[1]),
            "descending: {versions:?}"
        );

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        let initialized =
            owner_init(SUITE, size, 0, start, &versions, &keys_upto(6), &mut reader).unwrap();
        assert_eq!(initialized.greatest, Some(5));
        assert_eq!(initialized.inspected.len(), versions.len());
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// Step 2's ordering check. A version count only grows, so a list going backwards through the
    /// log cannot rise — a log claiming otherwise is lying about one of the two entries.
    #[test]
    fn greatest_versions_must_descend() {
        let size = 7_u64;
        let start = 5_u64;
        let clock = stamps(size);
        let (proof, _) = build_init(size, start, 0, &clock);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        assert_eq!(
            owner_init(SUITE, size, 0, start, &[3, 5], &keys_upto(6), &mut reader),
            Err(InitError::VersionsNotDescending {
                earlier: 3,
                later: 5
            })
        );
    }

    /// §13.3 step 1: no more versions than there are entries to inspect.
    #[test]
    fn more_versions_than_entries_is_refused() {
        let size = 7_u64;
        let start = 5_u64;
        let clock = stamps(size);
        let (proof, _) = build_init(size, start, 0, &clock);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        let refused = owner_init(
            SUITE,
            size,
            0,
            start,
            &[5, 4, 3, 2, 1, 0],
            &keys_upto(6),
            &mut reader,
        );
        assert!(
            matches!(refused, Err(InitError::TooManyVersions { .. })),
            "expected too many versions, got {refused:?}"
        );
    }

    /// §13.3 requires the starting position to be unexpired, and it is the one precondition a
    /// client can check for itself rather than taking on trust.
    #[test]
    fn an_expired_starting_position_is_refused() {
        let size = 7_u64;
        let start = 5_u64;
        let day = 86_400_000_u64;
        let clock: Vec<u64> = (0..size).map(|i| 1_700_000_000_000 + i * day).collect();
        let lifetime = day; // entry 5 is a day behind entry 6, so exactly at the boundary
        let (proof, versions) = build_init(size, start, lifetime, &clock);

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        assert!(matches!(
            owner_init(
                SUITE,
                size,
                lifetime,
                start,
                &versions,
                &keys_upto(6),
                &mut reader
            ),
            Err(InitError::StartExpired { .. })
        ));
    }

    #[test]
    fn init_errors_describe_themselves() {
        use alloc::string::ToString;
        let errors = [
            InitError::StartExpired {
                start: 5,
                timestamp: 1,
                rightmost: 9,
            },
            InitError::VersionsNotDescending {
                earlier: 1,
                later: 2,
            },
            InitError::TooManyVersions {
                supplied: 3,
                inspected: 2,
            },
            InitError::LadderLength {
                position: 5,
                expected: 2,
                actual: 3,
            },
            InitError::LadderInconsistent {
                position: 5,
                claimed: 3,
                exists: true,
            },
            InitError::LadderInconsistent {
                position: 5,
                claimed: 0,
                exists: false,
            },
            InitError::MissingLadderKey {
                position: 5,
                version: 1,
            },
            InitError::MissingCommitment {
                position: 5,
                version: 1,
            },
            InitError::from(Error::Exhausted {
                array: "timestamps",
                position: 5,
            }),
            InitError::from(prefix::Error::DepthOverflow { depth: 256 }),
            InitError::from(ibst::Error::EmptyLog),
            InitError::from(ladder::Error::UnrepresentableRung {
                rung: 1 << 32,
                greatest: u32::MAX,
            }),
        ];
        for error in &errors {
            assert!(!error.to_string().is_empty(), "{error:?}");
        }
        assert!(core::error::Error::source(&errors[8]).is_some());
        assert!(core::error::Error::source(&errors[0]).is_none());
    }
}

/// What owner monitoring established (§8.3's second algorithm).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OwnerMonitored {
    /// The distinguished entries whose ladders were checked, in the order the walk reached them.
    pub checked: Vec<(u64, HashValue)>,
    /// The rightmost entry the walk got to before the proof ran out.
    ///
    /// §8.3 expects users to "repeatedly query the Transparency Log until they detect that the
    /// above algorithm has either hit an unresolvable error or successfully reached the rightmost
    /// distinguished log entry", so this is what the next request starts from.
    pub reached: Option<u64>,
}

/// Runs §8.3's second algorithm: an owner checking the recent distinguished entries.
///
/// This is the only algorithm in the protocol whose stopping point is decided by the *proof*
/// rather than by the algorithm. Step 4 says the user's "only stop condition is having consumed
/// all of the Transparency Log's response" — the log is allowed to truncate, because §8.3 tells it
/// to limit how many entries it covers per response, and the user simply asks again. So exhaustion
/// is a legitimate outcome here, and only at step 4: running out anywhere else means the log sent
/// a proof that does not match its own shape.
///
/// One consequence worth knowing: §12.3's exact-count rule cannot police this algorithm's reading
/// the way it polices the others. Where a search either consumes everything or reveals a
/// misreading, an owner monitor consumes until empty by construction. What still catches a
/// misreading is the ladders themselves — an element attributed to the wrong entry evaluates to a
/// prefix tree root that entry never had.
///
/// `start` is the rightmost distinguished entry the owner has already verified. `expected` gives
/// the greatest version the owner believes existed as of a given log entry — *not* one global
/// version. §8.3 step 5 says the ladder targets "the greatest version of the label expected to
/// exist at this point according to the label owner's local state", and an owner has that state
/// because it created the versions itself: it knows which entry each one went into. Using the
/// global greatest everywhere gives ladders of the wrong length at every entry before the last,
/// since §5's series depends on its target.
///
/// # Errors
///
/// [`InitError`], shared with owner initialization: the two algorithms check the same things about
/// a ladder, and distinguishing their errors would be a distinction without a difference.
pub fn owner_monitor(
    suite: CipherSuite,
    size: u64,
    window: u64,
    start: u64,
    expected: &impl Fn(u64) -> u32,
    keys: &BTreeMap<u32, LadderKey>,
    reader: &mut Reader<'_>,
) -> core::result::Result<OwnerMonitored, InitError> {
    let last = size.saturating_sub(1);
    let rightmost = reader.timestamp(last)?;
    let mut checked = Vec::new();
    let mut reached = None;
    let root = ibst::root(size)?;
    owner_monitor_at(
        suite,
        size,
        window,
        start,
        expected,
        keys,
        reader,
        root,
        (0, 0),
        (last, rightmost),
        &mut checked,
        &mut reached,
    )?;
    Ok(OwnerMonitored { checked, reached })
}

/// §8.3's second algorithm at one log entry, recursing as its steps direct.
#[allow(
    clippy::too_many_arguments,
    reason = "the recursion's own state: the tree, the log's parameters, the owner's position, \
              the §6.1 brackets, and the two accumulators. Bundling them would obscure which \
              parameter each numbered step reads"
)]
fn owner_monitor_at(
    suite: CipherSuite,
    size: u64,
    window: u64,
    start: u64,
    expected: &impl Fn(u64) -> u32,
    keys: &BTreeMap<u32, LadderKey>,
    reader: &mut Reader<'_>,
    current: u64,
    left: (u64, u64),
    right: (u64, u64),
    checked: &mut Vec<(u64, HashValue)>,
    reached: &mut Option<u64>,
) -> core::result::Result<(), InitError> {
    // Step 1. Only distinguished entries are checked here — §8.3 says as much, and points out that
    // this is why an owner runs §8.2 alongside: between two reference points, only contact
    // monitoring notices anything.
    if !distinguished::is_distinguished(window, left, right)? {
        return Ok(());
    }

    // Step 2: entries at or before what the owner has already verified need no further checking,
    // but the walk still has to get past them to reach the ones that do.
    if current <= start {
        if let Ok(child) = ibst::right(current, size) {
            let timestamp = reader.timestamp(current)?;
            owner_monitor_at(
                suite,
                size,
                window,
                start,
                expected,
                keys,
                reader,
                child,
                (current, timestamp),
                right,
                checked,
                reached,
            )?;
        }
        return Ok(());
    }

    // Step 3: the left subtree first, so the walk covers the older distinguished entries before
    // the newer ones — which is what lets the log truncate at step 4 and the user resume.
    if !ibst::is_leaf(current) {
        let child = ibst::left(current)?;
        let timestamp = reader.timestamp(current)?;
        owner_monitor_at(
            suite,
            size,
            window,
            start,
            expected,
            keys,
            reader,
            child,
            left,
            (current, timestamp),
            checked,
            reached,
        )?;
    }

    // Step 4: the stop condition. For a user it is exhaustion, and nothing else.
    if reader.is_exhausted() {
        return Ok(());
    }

    // Step 5. The entry's own timestamp comes first, and §12.3.6 does not say so: it lists "the
    // timestamp for each log entry that causes the algorithm to recurse" and, separately, a proof
    // for each entry reaching step 5. But an entry with a proof and no timestamp cannot be placed
    // in the log tree at all — §11.8's leaf is the hash of a timestamp *and* a prefix tree root,
    // and §12.3 ties `inclusion` to "all leaf nodes whose timestamp was provided". Compare
    // §12.3.3, which lists both for every entry a fixed-version search touches. Measured against
    // the peer: it sends them, in this position. Recorded as `DRAFT-10`.
    reader.timestamp(current)?;

    // A full ladder for the version the owner expects to be greatest *here*.
    let greatest = expected(current);
    let versions = ladder::search_binary_ladder(greatest, greatest, &[], &[])?;
    let proof = reader.prefix_proof(current)?;
    let used = versions
        .get(..proof.results.len())
        .ok_or(InitError::LadderLength {
            position: current,
            expected: versions.len(),
            actual: proof.results.len(),
        })?;
    let ordering = ladder::interpret_search_ladder(used, greatest, &proof.results)?;
    if ordering != core::cmp::Ordering::Equal {
        return Err(InitError::LadderInconsistent {
            position: current,
            claimed: greatest,
            exists: true,
        });
    }
    let mut entries = Vec::new();
    for (version, result) in used.iter().zip(proof.results.iter()) {
        let key = keys.get(version).ok_or(InitError::MissingLadderKey {
            position: current,
            version: *version,
        })?;
        entries.push(if result.is_inclusion() {
            prefix::SearchEntry::included(
                key.vrf_output,
                key.commitment.ok_or(InitError::MissingCommitment {
                    position: current,
                    version: *version,
                })?,
            )
        } else {
            prefix::SearchEntry::absent(key.vrf_output)
        });
    }
    let root = prefix::evaluate(suite, &entries, proof)?;
    reader.establish_root(current, root)?;
    checked.push((current, root));
    *reached = Some(current);

    // Step 6.
    if let Ok(child) = ibst::right(current, size) {
        let timestamp = reader.timestamp(current)?;
        owner_monitor_at(
            suite,
            size,
            window,
            start,
            expected,
            keys,
            reader,
            child,
            (current, timestamp),
            right,
            checked,
            reached,
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod owner_monitor_tests {
    use super::search_tests::{commitment_for, key_for, tree_at};
    use super::*;
    use kt_wire::proofs::InclusionProof;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    /// Everything an owner holds after initialization: its own versions, and every version a
    /// search ladder for any of them reaches — including ones that never existed, which is why
    /// those have no commitment.
    fn owner_keys(greatest: u32) -> BTreeMap<u32, LadderKey> {
        let mut keys = BTreeMap::new();
        for version in 0..=greatest {
            for rung in ladder::search_binary_ladder(version, version, &[], &[]).unwrap() {
                keys.entry(rung).or_insert(LadderKey {
                    vrf_output: key_for(rung),
                    commitment: (rung <= greatest).then(|| commitment_for(rung)),
                });
            }
        }
        keys
    }

    /// Entries far enough apart that a small window makes most of them distinguished, which is the
    /// only shape where §8.3's walk reaches step 5 at all.
    fn spaced(size: u64) -> Vec<u64> {
        (0..size).map(|i| 1_700_000_000_000 + i * 100).collect()
    }

    /// Builds the proof for §8.3's walk, in §12.3.6's order plus the step-5 timestamps §12.3.6
    /// omits (see `DRAFT-10`). `limit` caps how many ladders the log includes, which is the
    /// truncation §8.3 permits.
    fn build_walk(
        size: u64,
        window: u64,
        start: u64,
        expected: &impl Fn(u64) -> u32,
        stamps: &[u64],
        limit: usize,
    ) -> CombinedTreeProof {
        let last = size - 1;
        let mut timestamps: Vec<u64> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        let mut proofs = Vec::new();
        let mut proved: Vec<u64> = Vec::new();

        // The view update first, as every operation does.
        for entry in ibst::frontier(size).unwrap() {
            if !seen.contains(&entry) {
                timestamps.push(stamps[entry as usize]);
                seen.push(entry);
            }
        }

        #[allow(
            clippy::too_many_arguments,
            reason = "the walk's own state, mirroring the library recursion it builds proofs for"
        )]
        fn walk(
            size: u64,
            window: u64,
            start: u64,
            expected: &impl Fn(u64) -> u32,
            stamps: &[u64],
            limit: usize,
            current: u64,
            left: (u64, u64),
            right: (u64, u64),
            timestamps: &mut Vec<u64>,
            seen: &mut Vec<u64>,
            proofs: &mut Vec<kt_wire::proofs::PrefixProof>,
            proved: &mut Vec<u64>,
        ) {
            if !distinguished::is_distinguished(window, left, right).unwrap() {
                return;
            }
            let push = |entry: u64, timestamps: &mut Vec<u64>, seen: &mut Vec<u64>| {
                if !seen.contains(&entry) {
                    timestamps.push(stamps[entry as usize]);
                    seen.push(entry);
                }
            };
            if current <= start {
                if let Ok(child) = ibst::right(current, size) {
                    push(current, timestamps, seen);
                    walk(
                        size,
                        window,
                        start,
                        expected,
                        stamps,
                        limit,
                        child,
                        (current, stamps[current as usize]),
                        right,
                        timestamps,
                        seen,
                        proofs,
                        proved,
                    );
                }
                return;
            }
            if !ibst::is_leaf(current) {
                let child = ibst::left(current).unwrap();
                push(current, timestamps, seen);
                walk(
                    size,
                    window,
                    start,
                    expected,
                    stamps,
                    limit,
                    child,
                    left,
                    (current, stamps[current as usize]),
                    timestamps,
                    seen,
                    proofs,
                    proved,
                );
            }
            if proofs.len() >= limit {
                // The log has sent as much as it intends to; §8.3 lets it stop here.
                return;
            }
            push(current, timestamps, seen);
            let target = expected(current);
            let versions = ladder::search_binary_ladder(target, target, &[], &[]).unwrap();
            let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
            proofs.push(tree_at(current).prove(SUITE, &searches).unwrap());
            proved.push(current);
            if let Ok(child) = ibst::right(current, size) {
                push(current, timestamps, seen);
                walk(
                    size,
                    window,
                    start,
                    expected,
                    stamps,
                    limit,
                    child,
                    (current, stamps[current as usize]),
                    right,
                    timestamps,
                    seen,
                    proofs,
                    proved,
                );
            }
        }

        walk(
            size,
            window,
            start,
            expected,
            stamps,
            limit,
            ibst::root(size).unwrap(),
            (0, 0),
            (last, stamps[last as usize]),
            &mut timestamps,
            &mut seen,
            &mut proofs,
            &mut proved,
        );

        let mut owed: Vec<u64> = seen
            .iter()
            .copied()
            .filter(|entry| !proved.contains(entry))
            .collect();
        owed.sort_unstable();
        let prefix_roots = owed
            .iter()
            .map(|entry| tree_at(*entry).root(SUITE))
            .collect();

        CombinedTreeProof {
            timestamps,
            prefix_proofs: proofs,
            prefix_roots,
            inclusion: InclusionProof::new(Vec::new()),
        }
    }

    /// The whole walk, checking a ladder at every distinguished entry past the owner's start.
    #[test]
    fn an_owner_walks_the_distinguished_entries() {
        let size = 7_u64;
        let window = 50_u64;
        let start = 1_u64;
        let stamps = spaced(size);
        let expected = |entry: u64| u32::try_from(entry).unwrap_or(6).min(6);
        let proof = build_walk(size, window, start, &expected, &stamps, usize::MAX);
        assert!(
            proof.prefix_proofs.len() > 1,
            "the walk should reach several entries"
        );

        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        let monitored = owner_monitor(
            SUITE,
            size,
            window,
            start,
            &expected,
            &owner_keys(6),
            &mut reader,
        )
        .unwrap();
        assert_eq!(monitored.checked.len(), proof.prefix_proofs.len());
        for (position, root) in &monitored.checked {
            assert_eq!(*root, tree_at(*position).root(SUITE), "entry {position}");
        }
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// §8.3 lets the log truncate: "the Transparency Log SHOULD limit the number of distinguished
    /// log entries that it provides binary ladders for in a single response", and step 4 makes
    /// exhaustion the user's stop condition. So a short proof is a valid answer, not an error —
    /// the user just asks again from where it got to.
    #[test]
    fn a_truncated_response_is_an_answer_not_an_error() {
        let size = 7_u64;
        let window = 50_u64;
        let start = 1_u64;
        let stamps = spaced(size);
        let expected = |entry: u64| u32::try_from(entry).unwrap_or(6).min(6);
        let full = build_walk(size, window, start, &expected, &stamps, usize::MAX);
        let short = build_walk(size, window, start, &expected, &stamps, 2);
        assert!(short.prefix_proofs.len() < full.prefix_proofs.len());

        let retained = Retained::none();
        let mut reader = Reader::new(&short, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        let monitored = owner_monitor(
            SUITE,
            size,
            window,
            start,
            &expected,
            &owner_keys(6),
            &mut reader,
        )
        .unwrap();
        assert_eq!(monitored.checked.len(), 2);
        assert!(monitored.reached.is_some(), "the walk got somewhere");
        for position in reader.entries_owed_roots() {
            reader.prefix_root(position).unwrap();
        }
        reader.finish().unwrap();
    }

    /// A ladder that does not place the expected version as the greatest. For an owner this is the
    /// alarm: someone else has created a version of a label the owner controls.
    #[test]
    fn a_ladder_inconsistent_with_the_owners_state_is_refused() {
        let size = 7_u64;
        let window = 50_u64;
        let start = 1_u64;
        let stamps = spaced(size);
        let honest = |entry: u64| u32::try_from(entry).unwrap_or(6).min(6);
        let proof = build_walk(size, window, start, &honest, &stamps, usize::MAX);

        // The owner believes version 0 is the greatest everywhere, so every ladder the log built
        // for a later version now disagrees with its state.
        let stale = |_: u64| 0_u32;
        let retained = Retained::none();
        let mut reader = Reader::new(&proof, &retained);
        for entry in ibst::frontier(size).unwrap() {
            reader.timestamp(entry).unwrap();
        }
        let refused = owner_monitor(
            SUITE,
            size,
            window,
            start,
            &stale,
            &owner_keys(6),
            &mut reader,
        );
        // Which refusal depends on how far the two states have diverged: a ladder for a much
        // smaller version is *shorter*, so the mismatch surfaces as a length disagreement before
        // the interpretation is even reached. Both are the same finding — the log's ladders do not
        // describe the history the owner believes in — so the test accepts either.
        assert!(
            matches!(
                refused,
                Err(InitError::LadderInconsistent { .. })
                    | Err(InitError::LadderLength { .. })
                    | Err(InitError::Ladder(_))
            ),
            "expected a refusal, got {refused:?}"
        );
    }

    #[test]
    fn the_distinguished_error_is_reported() {
        use alloc::string::ToString;
        let wrapped = InitError::from(distinguished::Error::NonMonotonic { left: 1, right: 2 });
        assert!(!wrapped.to_string().is_empty());
        assert!(core::error::Error::source(&wrapped).is_some());
    }
}
