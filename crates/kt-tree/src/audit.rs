//! Checking one log entry as a third-party auditor (§15.2).
//!
//! An auditor's whole job is to refuse to sign. It holds no tree — just the timestamp
//! and prefix tree root of the last entry it accepted — and for each new entry it is
//! handed an [`AuditorUpdate`] describing what changed. If every check below passes, the
//! entry follows from the state the auditor already had, and it may sign an
//! `AuditorTreeHead` covering it (§11.3). If any fails, it must not, and its state must
//! not move: a log that can get one bad entry signed can get any number, because every
//! later signature is computed against the state this one left behind.
//!
//! # What is checked here
//!
//! Steps 1 through 7 of §15.2: the structural checks, the eligibility check, and both
//! roots — the new prefix tree root via [`prefix::evaluate_before_after`], and the log
//! tree root the `AuditorTreeHead` signature would cover via [`log::Retained::append`].
//!
//! # Step 5, and why the auditor has to remember things
//!
//! Step 5 is the one check that is not about the update in front of the auditor. A removed
//! leaf must have "been published in at least one distinguished log entry before removal",
//! which is a statement about the log's past. A leaf inserted at position `p` is in the
//! prefix tree of every entry from `p` until it is removed, so it has been published in a
//! distinguished entry exactly when some distinguished entry at or after `p` exists — and
//! "before removal" means strictly left of the entry doing the removing, which is
//! [`distinguished::previous_rightmost`].
//!
//! So the auditor carries two more things: the timestamps along its log tree frontier,
//! without which it cannot decide which entries are distinguished at all, and the positions
//! of recently inserted VRF outputs. "Recently" is what makes this bounded: §6.1's
//! distinguished entries are stable, so once a leaf's insertion position is covered by one,
//! it is covered forever and can be forgotten. [`AuditorState::inserted`] therefore holds
//! only insertions the rightmost distinguished entry has not yet reached.
//!
//! # What is not checked here
//!
//! **Step 8's signature.** Producing the `AuditorTreeHead` is the caller's business: this
//! computes the size and root it would cover and hands them back, because whether to sign
//! also depends on [`Accepted::root_determined`], which is not a property of the bytes in
//! front of the verifier.

use crate::{distinguished, ibst, log, prefix};
use alloc::vec::Vec;
use kt_crypto::suite::CipherSuite;
use kt_wire::audit::AuditorUpdate;
use kt_wire::proofs::{PrefixLeaf, PrefixSearchResultType};
use kt_wire::structs::{HashValue, LogEntry};

/// Why an auditor rejected an update (§15.2).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// Step 1: the new entry's timestamp is older than the one the auditor holds.
    TimestampRegression {
        /// The timestamp the update carries.
        update: u64,
        /// The timestamp of the last entry the auditor accepted.
        previous: u64,
    },
    /// Step 2: a list is not in ascending `vrf_output` order, or repeats one.
    ///
    /// The two are one error because the ordering is strict: a repeat inside a list shows
    /// up as a pair that does not ascend.
    NotAscending {
        /// `"added"` or `"removed"`.
        list: &'static str,
        /// The index whose predecessor does not compare less than it.
        index: usize,
    },
    /// Steps 3 and 4: the proof does not answer every key the update names.
    ResultCount {
        /// `added.len() + removed.len()`.
        expected: usize,
        /// What the proof carries.
        actual: usize,
    },
    /// Step 3: an added leaf was already in the tree, and is not a replacement.
    AddedAlreadyPresent {
        /// Its index in `added`.
        index: usize,
    },
    /// Step 4: a removed leaf was not in the tree.
    RemovedNotPresent {
        /// Its index in `removed`.
        index: usize,
    },
    /// Step 6: the previous root the update implies is not the one the auditor holds.
    ///
    /// This is the check that makes an auditor's signature mean anything. Everything else
    /// says the update is well formed; this says it starts where the last one ended.
    PrefixRootMismatch {
        /// What the auditor holds.
        expected: HashValue,
        /// What the update's proof reconstructs.
        actual: HashValue,
    },
    /// Steps 6 and 7: the proof could not be evaluated at all.
    Prefix(prefix::Error),
    /// Step 5: a removed leaf was never published in a distinguished log entry, so it is
    /// not eligible for removal.
    ///
    /// The point of the rule is that a label owner who inspects every distinguished entry
    /// cannot have a value inserted and removed behind their back: it has to sit in a
    /// distinguished entry, where they will see it, before the log may take it away.
    NotEligibleForRemoval {
        /// Its index in `removed`.
        index: usize,
        /// The log entry that inserted it.
        inserted_at: u64,
        /// The rightmost distinguished entry left of the new one, if any.
        distinguished_through: Option<u64>,
    },
    /// Step 5: the auditor cannot decide eligibility, because a timestamp it needs is not
    /// in the state it retained.
    MissingHistory(distinguished::Error),
    /// Step 7: the new log entry could not be appended to the auditor's view.
    Log(log::Error),
}

impl From<distinguished::Error> for Error {
    fn from(err: distinguished::Error) -> Self {
        Self::MissingHistory(err)
    }
}

impl From<log::Error> for Error {
    fn from(err: log::Error) -> Self {
        Self::Log(err)
    }
}

impl From<prefix::Error> for Error {
    fn from(err: prefix::Error) -> Self {
        Self::Prefix(err)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::TimestampRegression { update, previous } => write!(
                f,
                "the update's timestamp {update} is before the previous entry's {previous}"
            ),
            Self::NotAscending { list, index } => {
                write!(f, "`{list}` does not ascend by vrf_output at index {index}")
            }
            Self::ResultCount { expected, actual } => write!(
                f,
                "the proof answers {actual} keys but the update names {expected}"
            ),
            Self::AddedAlreadyPresent { index } => write!(
                f,
                "added[{index}] is already in the tree and is not also being removed"
            ),
            Self::RemovedNotPresent { index } => {
                write!(f, "removed[{index}] is not in the tree")
            }
            Self::PrefixRootMismatch { .. } => {
                write!(
                    f,
                    "the update does not start from the auditor's prefix tree root"
                )
            }
            Self::NotEligibleForRemoval {
                index,
                inserted_at,
                distinguished_through,
            } => match distinguished_through {
                Some(through) => write!(
                    f,
                    "removed[{index}] was inserted at entry {inserted_at}, after the last \
                     distinguished entry {through}, so it was never published in one"
                ),
                None => write!(
                    f,
                    "removed[{index}] was inserted at entry {inserted_at} and there is no \
                     distinguished entry before this one at all"
                ),
            },
            Self::MissingHistory(err) => write!(f, "deciding removal eligibility: {err}"),
            Self::Prefix(err) => write!(f, "evaluating the proof: {err}"),
            Self::Log(err) => write!(f, "appending the log entry: {err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Prefix(err) => Some(err),
            Self::Log(err) => Some(err),
            Self::MissingHistory(err) => Some(err),
            _ => None,
        }
    }
}

type Result<T> = core::result::Result<T, Error>;

/// A VRF output whose insertion no distinguished log entry has covered yet.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Inserted {
    /// The log entry that inserted it.
    pub position: u64,
    /// The prefix tree search key inserted.
    pub vrf_output: HashValue,
}

/// What an auditor carries between updates.
///
/// Small on purpose: an auditor that kept more would be a mirror, and the point of the role
/// is that it can check the log without storing it. `log` is its whole view of the log tree
/// — the full subtree heads, `popcount(size)` hashes, so under 64 for any log that can
/// exist. `timestamps` is one per head, and `inserted` shrinks every time a new
/// distinguished entry appears.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditorState {
    /// Timestamp of the last entry accepted.
    pub timestamp: u64,
    /// Prefix tree root of the last entry accepted.
    pub prefix_root: HashValue,
    /// The log tree as of the last entry accepted. `size` zero means no entries yet.
    pub log: log::Retained,
    /// Timestamps of the entries along the log tree frontier, in the order
    /// [`ibst::frontier`] gives — which is the order `log.full_subtrees` is in, so the two
    /// stay aligned.
    pub timestamps: Vec<u64>,
    /// Insertions not yet covered by a distinguished log entry, sorted by `vrf_output`.
    pub inserted: Vec<Inserted>,
}

impl AuditorState {
    /// The state of an auditor that has accepted nothing.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            timestamp: 0,
            prefix_root: HashValue::ZERO,
            log: log::Retained {
                size: 0,
                full_subtrees: Vec::new(),
            },
            timestamps: Vec::new(),
            inserted: Vec::new(),
        }
    }

    /// The timestamp of log entry `position`, if this state retained it.
    ///
    /// An auditor keeps only the frontier's, which is what §6.1's walks need.
    #[must_use]
    pub fn timestamp_of(&self, position: u64) -> Option<u64> {
        let frontier = ibst::frontier(self.log.size).ok()?;
        frontier
            .iter()
            .position(|entry| *entry == position)
            .and_then(|index| self.timestamps.get(index))
            .copied()
    }
}

/// The state an accepted update moves the auditor to.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The new state, to be carried into the next update.
    pub state: AuditorState,
    /// The log tree root over the new entry (§15.2 step 7). An `AuditorTreeHead` for
    /// `state.log.size` is signed over this value (§11.3).
    pub log_root: HashValue,
    /// Whether the new prefix root followed from the proof, or was reached by assuming
    /// no §3.3 collapse was needed. See [`prefix::Mutation::assumed_no_collapse`].
    ///
    /// An auditor must not sign when this is false: the signature would cover a root the
    /// log's users cannot reproduce from their own proofs, which is worse than no
    /// signature at all. It is not an error here because the update may be perfectly
    /// honest — the draft simply gives the auditor no way to tell.
    pub root_determined: bool,
}

/// Runs §15.2's checks over one update.
///
/// `previous` is the state from the last accepted update, or `None` for the first entry an
/// auditor ever sees, where there is no timestamp to be after, no root to match, and — since
/// nothing has been published yet — nothing eligible for removal.
///
/// `window` is the log's Reasonable Monitoring Window, which step 5 needs: it is what
/// decides which entries are distinguished (§6.1).
///
/// # Errors
///
/// [`Error`], one variant per §15.2 step. Nothing is mutated: the caller advances its
/// state from [`Accepted`] only on success.
pub fn verify_update(
    suite: CipherSuite,
    window: u64,
    update: &AuditorUpdate,
    previous: Option<&AuditorState>,
) -> Result<Accepted> {
    // Step 1. Equal is allowed: two entries may share a millisecond.
    if let Some(state) = previous {
        if update.timestamp < state.timestamp {
            return Err(Error::TimestampRegression {
                update: update.timestamp,
                previous: state.timestamp,
            });
        }
    }

    // Step 2. Strictly ascending by vrf_output, which rules out a repeat within a list
    // as a side effect. A repeat *across* the lists is not just allowed but meaningful:
    // it is how a label's value is replaced.
    ascending("added", &update.added)?;
    ascending("removed", &update.removed)?;

    // Steps 3 and 4 read results positionally, so the count has to be right first.
    let expected = update.added.len().saturating_add(update.removed.len());
    if update.proof.results.len() != expected {
        return Err(Error::ResultCount {
            expected,
            actual: update.proof.results.len(),
        });
    }

    // Step 3. An added key must have been absent — unless it is also being removed, in
    // which case the update is a replacement and the key was present by definition.
    for (index, leaf) in update.added.iter().enumerate() {
        let included = update
            .proof
            .results
            .get(index)
            .is_some_and(|result| result.result_type() == PrefixSearchResultType::Inclusion);
        let replacement = update
            .removed
            .iter()
            .any(|other| other.vrf_output == leaf.vrf_output);
        if included && !replacement {
            return Err(Error::AddedAlreadyPresent { index });
        }
    }

    // Step 4. A removed key must have been present.
    for index in 0..update.removed.len() {
        let position = update.added.len().saturating_add(index);
        let included = update
            .proof
            .results
            .get(position)
            .is_some_and(|result| result.result_type() == PrefixSearchResultType::Inclusion);
        if !included {
            return Err(Error::RemovedNotPresent { index });
        }
    }

    // Step 5. A leaf inserted at position `p` is in the prefix tree of every entry from
    // `p` onwards, so it has been published in a distinguished entry exactly when one
    // exists at or after `p` — and "before removal" restricts that to entries strictly
    // left of the one doing the removing, which is what `previous_rightmost` gives once the
    // new entry is counted. Leaves the auditor is no longer tracking are eligible by
    // construction: `inserted` only drops an insertion once a distinguished entry has
    // covered it, and §6.1's distinguished entries never stop being distinguished.
    let new_size = previous.map_or(0, |state| state.log.size).saturating_add(1);
    let position = new_size.saturating_sub(1);
    if !update.removed.is_empty() {
        let timestamp = |wanted: u64| {
            if wanted == position {
                return Some(update.timestamp);
            }
            previous.and_then(|state| state.timestamp_of(wanted))
        };
        let through =
            distinguished::previous_rightmost_from_frontier(new_size, window, &timestamp)?;
        for (index, leaf) in update.removed.iter().enumerate() {
            let tracked = previous.and_then(|state| {
                state
                    .inserted
                    .iter()
                    .find(|entry| entry.vrf_output == leaf.vrf_output)
            });
            let Some(entry) = tracked else {
                continue;
            };
            if through.is_none_or(|covered| entry.position > covered) {
                return Err(Error::NotEligibleForRemoval {
                    index,
                    inserted_at: entry.position,
                    distinguished_through: through,
                });
            }
        }
    }

    // Steps 6 and 7.
    let mutation =
        prefix::evaluate_before_after(suite, &update.added, &update.removed, &update.proof)?;
    if let Some(state) = previous {
        if mutation.before != state.prefix_root {
            return Err(Error::PrefixRootMismatch {
                expected: state.prefix_root,
                actual: mutation.before,
            });
        }
    }

    // Step 7's second half: the log gains one entry committing to the timestamp and the
    // new prefix root (§11.8), and its root is what an `AuditorTreeHead` for the new size
    // would be signed over (§11.3). The auditor holds no leaves, so this is done by
    // carrying the full subtree heads forward.
    let entry = LogEntry {
        timestamp: update.timestamp,
        prefix_tree: mutation.after,
    };
    let leaf = log::leaf_value(suite, &entry)?;
    let mut view = previous.map_or_else(
        || log::Retained {
            size: 0,
            full_subtrees: Vec::new(),
        },
        |state| state.log.clone(),
    );
    view.append(suite, leaf)?;
    let log_root = view.root(suite)?;

    // The new frontier's timestamps. Every frontier entry but the new one was on the old
    // frontier too — a frontier node only ever leaves by being absorbed into a larger
    // subtree — so the auditor already has them.
    let mut timestamps = Vec::new();
    for entry in ibst::frontier(view.size).map_err(distinguished::Error::from)? {
        let value = if entry == position {
            update.timestamp
        } else {
            previous
                .and_then(|state| state.timestamp_of(entry))
                .ok_or(distinguished::Error::MissingTimestamp { position: entry })?
        };
        timestamps.push(value);
    }

    // And the insertions still worth tracking. Anything the rightmost distinguished entry
    // has reached is covered for good, so it is dropped here rather than carried forever.
    let covered = {
        let timestamp = |wanted: u64| {
            timestamps
                .get(
                    ibst::frontier(view.size)
                        .ok()?
                        .iter()
                        .position(|entry| *entry == wanted)?,
                )
                .copied()
        };
        distinguished::rightmost_from_frontier(view.size, window, &timestamp)?
    };
    let mut inserted: Vec<Inserted> = previous
        .map(|state| state.inserted.clone())
        .unwrap_or_default();
    for leaf in &update.added {
        inserted.push(Inserted {
            position,
            vrf_output: leaf.vrf_output,
        });
    }
    inserted.retain(|entry| covered.is_none_or(|through| entry.position > through));
    inserted.sort_unstable_by(|a, b| a.vrf_output.as_bytes().cmp(b.vrf_output.as_bytes()));
    inserted.dedup_by(|a, b| a.vrf_output == b.vrf_output);

    Ok(Accepted {
        state: AuditorState {
            timestamp: update.timestamp,
            prefix_root: mutation.after,
            log: view,
            timestamps,
            inserted,
        },
        log_root,
        root_determined: mutation.determined(),
    })
}

/// Step 2's ordering check.
fn ascending(list: &'static str, leaves: &[PrefixLeaf]) -> Result<()> {
    for index in 1..leaves.len() {
        let (Some(previous), Some(current)) =
            (leaves.get(index.wrapping_sub(1)), leaves.get(index))
        else {
            continue;
        };
        if previous.vrf_output.as_bytes() >= current.vrf_output.as_bytes() {
            return Err(Error::NotAscending { list, index });
        }
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
mod tests {
    use super::*;
    use crate::prefix::PrefixTree;
    use alloc::vec;
    use alloc::vec::Vec;
    use kt_wire::proofs::PrefixProof;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    /// An auditor that has accepted one entry, at `timestamp`, over `prefix_root`. Its log
    /// tree holds that one entry, which is what makes the step 7 append meaningful.
    fn state(timestamp: u64, prefix_root: HashValue) -> AuditorState {
        let mut log = crate::log::Retained {
            size: 0,
            full_subtrees: Vec::new(),
        };
        let leaf = crate::log::leaf_value(
            SUITE,
            &LogEntry {
                timestamp,
                prefix_tree: prefix_root,
            },
        )
        .unwrap();
        log.append(SUITE, leaf).unwrap();
        AuditorState {
            timestamp,
            prefix_root,
            log,
            timestamps: vec![timestamp],
            inserted: Vec::new(),
        }
    }

    /// A window long enough that only the log's very first entries are distinguished,
    /// which is the realistic case: the fixtures' timestamps are a minute apart and a real
    /// window is a week.
    const WINDOW: u64 = 604_800_000;

    fn leaf(first: u8, tag: u8, commitment: u8) -> PrefixLeaf {
        let mut key = [0_u8; 32];
        key[0] = first;
        key[31] = tag;
        PrefixLeaf {
            vrf_output: HashValue::from_bytes(key),
            commitment: HashValue::from_bytes([commitment; 32]),
        }
    }

    /// Builds the tree, then the update that adds `added` and removes `removed` from it.
    fn update_for(
        existing: &[PrefixLeaf],
        added: &[PrefixLeaf],
        removed: &[PrefixLeaf],
    ) -> (HashValue, AuditorUpdate) {
        let mut tree = PrefixTree::new();
        tree.extend(existing.iter().copied()).unwrap();
        let keys: Vec<HashValue> = added
            .iter()
            .chain(removed.iter())
            .map(|l| l.vrf_output)
            .collect();
        let proof = tree.prove(SUITE, &keys).unwrap();
        (
            tree.root(SUITE),
            AuditorUpdate {
                timestamp: 1_700_000_000_000,
                added: added.to_vec(),
                removed: removed.to_vec(),
                proof,
            },
        )
    }

    #[test]
    fn an_honest_update_advances_the_auditor() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let added = [leaf(0x40, 3, 0xc3)];
        let (root, update) = update_for(&existing, &added, &[]);
        let previous = state(1_600_000_000_000, root);

        let accepted = verify_update(SUITE, WINDOW, &update, Some(&previous)).unwrap();
        assert!(accepted.root_determined);
        assert_eq!(accepted.state.timestamp, update.timestamp);

        // And the new state is the tree the log would have built.
        let mut after = PrefixTree::new();
        after
            .extend(existing.iter().chain(added.iter()).copied())
            .unwrap();
        assert_eq!(accepted.state.prefix_root, after.root(SUITE));
    }

    #[test]
    fn the_first_update_has_nothing_to_match() {
        let added = [leaf(0x00, 1, 0xa1)];
        let (_, update) = update_for(&[], &added, &[]);
        let accepted = verify_update(SUITE, WINDOW, &update, None).unwrap();
        assert_eq!(accepted.state.timestamp, update.timestamp);
    }

    #[test]
    fn a_timestamp_may_repeat_but_not_regress() {
        let (root, update) = update_for(&[leaf(0x80, 2, 0xb2)], &[leaf(0x00, 1, 0xa1)], &[]);

        let same = state(update.timestamp, root);
        assert!(
            verify_update(SUITE, WINDOW, &update, Some(&same)).is_ok(),
            "equal is allowed"
        );

        let later = state(update.timestamp + 1, root);
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&later)),
            Err(Error::TimestampRegression {
                update: update.timestamp,
                previous: update.timestamp + 1,
            })
        );
    }

    #[test]
    fn lists_must_ascend_and_may_not_repeat() {
        let existing = [leaf(0x80, 2, 0xb2)];
        let low = leaf(0x00, 1, 0xa1);
        let high = leaf(0x40, 3, 0xc3);

        let (root, mut update) = update_for(&existing, &[low, high], &[]);
        let state = state(0, root);
        assert!(verify_update(SUITE, WINDOW, &update, Some(&state)).is_ok());

        update.added = vec![high, low];
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::NotAscending {
                list: "added",
                index: 1
            })
        );

        update.added = vec![low, low];
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::NotAscending {
                list: "added",
                index: 1
            }),
            "a repeat inside one list is a pair that does not ascend"
        );
    }

    #[test]
    fn removals_must_ascend_too() {
        let existing = [
            leaf(0x00, 1, 0xa1),
            leaf(0x40, 3, 0xc3),
            leaf(0x80, 2, 0xb2),
        ];
        let (root, mut update) = update_for(&existing, &[], &[existing[0], existing[1]]);
        let state = state(0, root);
        assert!(verify_update(SUITE, WINDOW, &update, Some(&state)).is_ok());

        update.removed = vec![existing[1], existing[0]];
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::NotAscending {
                list: "removed",
                index: 1
            })
        );
    }

    #[test]
    fn the_proof_must_answer_every_key() {
        let (root, mut update) = update_for(&[leaf(0x80, 2, 0xb2)], &[leaf(0x00, 1, 0xa1)], &[]);
        let state = state(0, root);
        update.proof = PrefixProof {
            results: Vec::new(),
            elements: update.proof.elements.clone(),
        };
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::ResultCount {
                expected: 1,
                actual: 0
            })
        );
    }

    /// Step 3: a log cannot use `added` to overwrite a leaf it is not also removing.
    /// Without this the update would silently change a committed value, and step 4's
    /// "was it published in a distinguished entry" check would never see it.
    #[test]
    fn adding_a_leaf_that_is_already_there_is_rejected() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let mut overwrite = existing[0];
        overwrite.commitment = HashValue::from_bytes([0xff; 32]);

        let (root, update) = update_for(&existing, &[overwrite], &[]);
        let state = state(0, root);
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::AddedAlreadyPresent { index: 0 })
        );
    }

    /// The same bytes, with the key also in `removed`, is the replacement §15.2 allows.
    #[test]
    fn the_same_key_in_both_lists_is_a_replacement() {
        let existing = [
            leaf(0x00, 1, 0xa1),
            leaf(0x40, 3, 0xc3),
            leaf(0x80, 2, 0xb2),
        ];
        let mut replacement = existing[0];
        replacement.commitment = HashValue::from_bytes([0xff; 32]);

        let (root, update) = update_for(&existing, &[replacement], &[existing[0]]);
        let state = state(0, root);
        let accepted = verify_update(SUITE, WINDOW, &update, Some(&state)).unwrap();
        assert!(accepted.root_determined, "the slot never empties");

        let mut after = PrefixTree::new();
        after
            .extend([replacement, existing[1], existing[2]])
            .unwrap();
        assert_eq!(accepted.state.prefix_root, after.root(SUITE));
    }

    /// Step 4: removing something that was never there.
    #[test]
    fn removing_an_absent_leaf_is_rejected() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let absent = leaf(0x40, 9, 0xe5);
        let (root, update) = update_for(&existing, &[], &[absent]);
        let state = state(0, root);
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::RemovedNotPresent { index: 0 })
        );
    }

    /// Step 6, and the only check that ties the update to the auditor's own history.
    #[test]
    fn an_update_from_a_different_tree_is_rejected() {
        let (root, update) = update_for(&[leaf(0x80, 2, 0xb2)], &[leaf(0x00, 1, 0xa1)], &[]);
        let elsewhere = HashValue::from_bytes([0x5a; 32]);
        let state = state(0, elsewhere);
        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&state)),
            Err(Error::PrefixRootMismatch {
                expected: elsewhere,
                actual: root
            })
        );
    }

    /// The removal shape the draft cannot express: everything structural passes, the
    /// root comes out, and `root_determined` is false — which is the only thing standing
    /// between an auditor and a signature over a root nobody can reproduce.
    #[test]
    fn a_removal_beside_an_uncovered_sibling_is_not_signable() {
        let existing = [
            leaf(0x00, 1, 0xa1),
            leaf(0x40, 2, 0xb2),
            leaf(0x80, 3, 0xc3),
        ];
        let (root, update) = update_for(&existing, &[], &[existing[0]]);
        let state = state(0, root);

        let accepted = verify_update(SUITE, WINDOW, &update, Some(&state)).unwrap();
        assert!(!accepted.root_determined);

        let mut after = PrefixTree::new();
        after.extend(existing[1..].iter().copied()).unwrap();
        assert_ne!(
            accepted.state.prefix_root,
            after.root(SUITE),
            "and the root it would have signed is not the tree's"
        );
    }

    /// Step 5's accept. A leaf whose insertion a distinguished entry has already covered may
    /// be removed: the label owner has had the chance to see it.
    #[test]
    fn a_leaf_a_distinguished_entry_covered_may_be_removed() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let target = existing[0];
        let (root, update) = update_for(&existing, &[], &[target]);

        // The auditor holds one entry, at position 0, which inserted both leaves. A window
        // this size makes entry 0 distinguished — its brackets are §6.1's initial 0 and the
        // rightmost timestamp — so the insertion is covered.
        let mut previous = state(1_600_000_000_000, root);
        previous.inserted = vec![
            Inserted {
                position: 0,
                vrf_output: existing[0].vrf_output,
            },
            Inserted {
                position: 0,
                vrf_output: existing[1].vrf_output,
            },
        ];

        let accepted = verify_update(SUITE, WINDOW, &update, Some(&previous)).unwrap();
        assert_eq!(accepted.state.timestamp, update.timestamp);
    }

    /// Step 5's refusal, which is the whole point of the rule: a value inserted and removed
    /// without ever sitting in a distinguished entry would never have been visible to the
    /// label owner who is supposed to be watching for it.
    #[test]
    fn a_leaf_no_distinguished_entry_covered_may_not_be_removed() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let target = existing[0];
        let (root, update) = update_for(&existing, &[], &[target]);

        // Same state, except the auditor recorded the insertion as happening at entry 1 —
        // to the right of every distinguished entry, since a one-entry log's only
        // distinguished entry is 0.
        let mut previous = state(1_600_000_000_000, root);
        previous.inserted = vec![Inserted {
            position: 1,
            vrf_output: target.vrf_output,
        }];

        assert_eq!(
            verify_update(SUITE, WINDOW, &update, Some(&previous)),
            Err(Error::NotEligibleForRemoval {
                index: 0,
                inserted_at: 1,
                distinguished_through: Some(0),
            })
        );
    }

    /// A window no gap can reach means no entry is distinguished, so nothing is removable at
    /// all. The auditor has to refuse rather than fall through to "no record, therefore
    /// fine".
    #[test]
    fn nothing_is_removable_when_no_entry_is_distinguished() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let target = existing[0];
        let (root, update) = update_for(&existing, &[], &[target]);

        let mut previous = state(1_600_000_000_000, root);
        previous.inserted = vec![Inserted {
            position: 0,
            vrf_output: target.vrf_output,
        }];

        assert_eq!(
            verify_update(SUITE, u64::MAX, &update, Some(&previous)),
            Err(Error::NotEligibleForRemoval {
                index: 0,
                inserted_at: 0,
                distinguished_through: None,
            })
        );
    }

    /// A leaf the auditor is no longer tracking is eligible. That is not a gap: `inserted`
    /// only drops an insertion once a distinguished entry has covered it, and §6.1's
    /// distinguished entries never stop being distinguished, so "not tracked" means
    /// "covered long ago".
    #[test]
    fn an_untracked_leaf_is_eligible() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let (root, update) = update_for(&existing, &[], &[existing[0]]);
        let previous = state(1_600_000_000_000, root);
        assert!(previous.inserted.is_empty());
        assert!(verify_update(SUITE, WINDOW, &update, Some(&previous)).is_ok());
    }

    /// And the bookkeeping is bounded: an insertion the rightmost distinguished entry has
    /// reached is dropped rather than carried forever, because it can never become
    /// ineligible again.
    #[test]
    fn covered_insertions_are_forgotten() {
        let added = [leaf(0x40, 3, 0xc3)];
        let (root, update) = update_for(&[leaf(0x00, 1, 0xa1)], &added, &[]);
        let mut previous = state(1_600_000_000_000, root);
        previous.inserted = vec![Inserted {
            position: 0,
            vrf_output: leaf(0x00, 1, 0xa1).vrf_output,
        }];

        // With a realistic window both entries of the new two-entry log are distinguished,
        // so both insertions are covered and neither needs tracking.
        let accepted = verify_update(SUITE, WINDOW, &update, Some(&previous)).unwrap();
        assert!(
            accepted.state.inserted.is_empty(),
            "still tracking {:?}",
            accepted.state.inserted
        );

        // With a window nothing reaches, nothing is covered, so both are retained — the old
        // one and the one this update added.
        let accepted = verify_update(SUITE, u64::MAX, &update, Some(&previous)).unwrap();
        assert_eq!(accepted.state.inserted.len(), 2);
        assert!(
            accepted
                .state
                .inserted
                .iter()
                .any(|entry| entry.vrf_output == added[0].vrf_output && entry.position == 1)
        );
    }

    /// A chain of accepted updates, checked against the log tree an implementation that
    /// held every leaf would have built. This is the whole of step 7: an auditor signs a
    /// root it computed from `popcount(size)` hashes, and if that drifts from the real tree
    /// by one entry every later signature is wrong too.
    #[test]
    fn a_chain_of_updates_tracks_the_real_log_tree() {
        let pool: Vec<PrefixLeaf> = (0..8).map(|i| leaf(i * 0x20, i + 1, 0xa0 + i)).collect();

        let mut auditor: Option<AuditorState> = None;
        let mut tree = PrefixTree::new();
        let mut leaves: Vec<HashValue> = Vec::new();

        for (step, added) in pool.iter().enumerate() {
            // The log's side: search the current tree, then add the leaf to it.
            let proof = tree.prove(SUITE, &[added.vrf_output]).unwrap();
            let update = AuditorUpdate {
                timestamp: 1_700_000_000_000 + step as u64 * 1_000,
                added: vec![*added],
                removed: Vec::new(),
                proof,
            };
            tree.insert(*added).unwrap();

            let accepted = verify_update(SUITE, WINDOW, &update, auditor.as_ref()).unwrap();
            assert_eq!(accepted.state.prefix_root, tree.root(SUITE), "step {step}");
            assert!(accepted.root_determined);

            // And the log tree, built the other way: every leaf, hashed from scratch.
            leaves.push(
                crate::log::leaf_value(
                    SUITE,
                    &LogEntry {
                        timestamp: update.timestamp,
                        prefix_tree: accepted.state.prefix_root,
                    },
                )
                .unwrap(),
            );
            assert_eq!(
                accepted.log_root,
                crate::log::root(SUITE, &leaves).unwrap(),
                "step {step}"
            );
            assert_eq!(accepted.state.log.size, leaves.len() as u64);

            auditor = Some(accepted.state);
        }
    }

    /// `AuditorState::empty` is what an auditor starts from, and it must be the same thing
    /// as passing `None`: a first entry has no predecessor either way.
    #[test]
    fn an_empty_state_and_no_state_agree() {
        let added = leaf(0x00, 1, 0xa1);
        let (_, update) = update_for(&[], &[added], &[]);

        let from_none = verify_update(SUITE, WINDOW, &update, None).unwrap();
        let empty = AuditorState::empty();
        let from_empty = verify_update(SUITE, WINDOW, &update, Some(&empty)).unwrap();
        assert_eq!(from_none, from_empty);
    }

    /// A state whose log view is malformed cannot be advanced. Step 7 is the only place
    /// this can surface, and it must be an error rather than a wrong root.
    #[test]
    fn a_malformed_log_view_is_refused() {
        let existing = [leaf(0x00, 1, 0xa1), leaf(0x80, 2, 0xb2)];
        let (root, update) = update_for(&existing, &[leaf(0x40, 3, 0xc3)], &[]);
        let mut broken = state(1_600_000_000_000, root);
        // Size 3 calls for two heads, not one.
        broken.log = crate::log::Retained {
            size: 3,
            full_subtrees: vec![HashValue::ZERO],
        };
        assert!(matches!(
            verify_update(SUITE, WINDOW, &update, Some(&broken)),
            Err(Error::Log(crate::log::Error::RetainedShape { .. }))
        ));
    }

    #[test]
    fn errors_describe_themselves() {
        use alloc::string::ToString;
        let rendered = [
            Error::TimestampRegression {
                update: 1,
                previous: 2,
            }
            .to_string(),
            Error::NotAscending {
                list: "added",
                index: 1,
            }
            .to_string(),
            Error::ResultCount {
                expected: 2,
                actual: 1,
            }
            .to_string(),
            Error::AddedAlreadyPresent { index: 0 }.to_string(),
            Error::RemovedNotPresent { index: 0 }.to_string(),
            Error::PrefixRootMismatch {
                expected: HashValue::ZERO,
                actual: HashValue::ZERO,
            }
            .to_string(),
            Error::from(prefix::Error::DepthOverflow { depth: 256 }).to_string(),
        ];
        for message in &rendered {
            assert!(!message.is_empty());
        }
        assert!(
            core::error::Error::source(&Error::from(prefix::Error::DepthOverflow { depth: 256 }))
                .is_some()
        );
        assert!(core::error::Error::source(&Error::RemovedNotPresent { index: 0 }).is_none());
        for message in [
            Error::NotEligibleForRemoval {
                index: 0,
                inserted_at: 4,
                distinguished_through: Some(2),
            },
            Error::NotEligibleForRemoval {
                index: 1,
                inserted_at: 0,
                distinguished_through: None,
            },
        ] {
            assert!(!message.to_string().is_empty());
            assert!(core::error::Error::source(&message).is_none());
        }
        let history = Error::from(crate::distinguished::Error::MissingTimestamp { position: 3 });
        assert!(!history.to_string().is_empty());
        assert!(core::error::Error::source(&history).is_some());
        let log_error = Error::from(crate::log::Error::InvalidSize { size: 0 });
        assert!(!log_error.to_string().is_empty());
        assert!(core::error::Error::source(&log_error).is_some());
    }
}
