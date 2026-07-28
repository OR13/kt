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
//! Steps 1 through 4 of §15.2, which are structural, plus steps 6 and 7's prefix tree
//! half via [`prefix::evaluate_before_after`].
//!
//! # What is not
//!
//! **Step 5** — that each removed leaf "was published in at least one distinguished log
//! entry before removal" — needs history this function does not have: which VRF outputs
//! were inserted since the last distinguished entry, which the auditor accumulates
//! across updates. It is a policy check over auditor state rather than a check on the
//! update, so it belongs to whatever owns that state.
//!
//! **Step 7's log tree half** — appending a `LogEntry` for the new timestamp and prefix
//! root, and computing the log root that the `AuditorTreeHead` signature covers — needs
//! an incremental append over the log tree frontier, which `crate::log` does not do yet:
//! it proves and verifies against a tree it is given, rather than growing one.
//!
//! Both are gaps in this implementation, not in the draft. [`Accepted`] therefore reports
//! what it did establish rather than a bare "valid".

use crate::prefix;
use kt_crypto::suite::CipherSuite;
use kt_wire::audit::AuditorUpdate;
use kt_wire::proofs::{PrefixLeaf, PrefixSearchResultType};
use kt_wire::structs::HashValue;

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
            Self::Prefix(err) => write!(f, "evaluating the proof: {err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Prefix(err) => Some(err),
            _ => None,
        }
    }
}

type Result<T> = core::result::Result<T, Error>;

/// What an auditor carries between updates.
///
/// Deliberately tiny: an auditor that kept more would be a mirror, and the point of the
/// role is that it can check the log without storing it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditorState {
    /// Timestamp of the last entry accepted.
    pub timestamp: u64,
    /// Prefix tree root of the last entry accepted.
    pub prefix_root: HashValue,
}

/// The state an accepted update moves the auditor to.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Accepted {
    /// The new state, to be carried into the next update.
    pub state: AuditorState,
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
/// `previous` is the state from the last accepted update, or `None` for the first entry
/// an auditor ever sees, where there is no timestamp to be after and no root to match.
///
/// # Errors
///
/// [`Error`], one variant per §15.2 step. Nothing is mutated: the caller advances its
/// state from [`Accepted`] only on success.
pub fn verify_update(
    suite: CipherSuite,
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

    Ok(Accepted {
        state: AuditorState {
            timestamp: update.timestamp,
            prefix_root: mutation.after,
        },
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
        let previous = AuditorState {
            timestamp: 1_600_000_000_000,
            prefix_root: root,
        };

        let accepted = verify_update(SUITE, &update, Some(&previous)).unwrap();
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
        let accepted = verify_update(SUITE, &update, None).unwrap();
        assert_eq!(accepted.state.timestamp, update.timestamp);
    }

    #[test]
    fn a_timestamp_may_repeat_but_not_regress() {
        let (root, update) = update_for(&[leaf(0x80, 2, 0xb2)], &[leaf(0x00, 1, 0xa1)], &[]);

        let same = AuditorState {
            timestamp: update.timestamp,
            prefix_root: root,
        };
        assert!(
            verify_update(SUITE, &update, Some(&same)).is_ok(),
            "equal is allowed"
        );

        let later = AuditorState {
            timestamp: update.timestamp + 1,
            prefix_root: root,
        };
        assert_eq!(
            verify_update(SUITE, &update, Some(&later)),
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
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };
        assert!(verify_update(SUITE, &update, Some(&state)).is_ok());

        update.added = vec![high, low];
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
            Err(Error::NotAscending {
                list: "added",
                index: 1
            })
        );

        update.added = vec![low, low];
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
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
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };
        assert!(verify_update(SUITE, &update, Some(&state)).is_ok());

        update.removed = vec![existing[1], existing[0]];
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
            Err(Error::NotAscending {
                list: "removed",
                index: 1
            })
        );
    }

    #[test]
    fn the_proof_must_answer_every_key() {
        let (root, mut update) = update_for(&[leaf(0x80, 2, 0xb2)], &[leaf(0x00, 1, 0xa1)], &[]);
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };
        update.proof = PrefixProof {
            results: Vec::new(),
            elements: update.proof.elements.clone(),
        };
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
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
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
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
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };
        let accepted = verify_update(SUITE, &update, Some(&state)).unwrap();
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
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
            Err(Error::RemovedNotPresent { index: 0 })
        );
    }

    /// Step 6, and the only check that ties the update to the auditor's own history.
    #[test]
    fn an_update_from_a_different_tree_is_rejected() {
        let (root, update) = update_for(&[leaf(0x80, 2, 0xb2)], &[leaf(0x00, 1, 0xa1)], &[]);
        let elsewhere = HashValue::from_bytes([0x5a; 32]);
        let state = AuditorState {
            timestamp: 0,
            prefix_root: elsewhere,
        };
        assert_eq!(
            verify_update(SUITE, &update, Some(&state)),
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
        let state = AuditorState {
            timestamp: 0,
            prefix_root: root,
        };

        let accepted = verify_update(SUITE, &update, Some(&state)).unwrap();
        assert!(!accepted.root_determined);

        let mut after = PrefixTree::new();
        after.extend(existing[1..].iter().copied()).unwrap();
        assert_ne!(
            accepted.state.prefix_root,
            after.root(SUITE),
            "and the root it would have signed is not the tree's"
        );
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
    }
}
