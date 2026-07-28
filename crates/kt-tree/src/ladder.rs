//! Binary ladder construction
//! (`draft-ietf-keytrans-protocol-05` §5, Appendix B).
//!
//! A binary ladder is a series of lookups in one log entry's prefix tree, each
//! producing an inclusion or non-inclusion proof, that together bound the
//! greatest version of a label as of that entry (§5). The base ladder pins the
//! bound exactly: versions `0, 1, 3, 7, …` until one is absent, then a binary
//! search between the last present version and the first absent one. §5's worked
//! example, for a label whose greatest version is 6, is inclusion for 0, 1, 3,
//! non-inclusion for 7, then inclusion for 5 and 6.
//!
//! The three variants in Appendix B differ only in where they stop and what they
//! leave out:
//!
//! | Function | Used by | Shape |
//! |---|---|---|
//! | [`base_binary_ladder`] | the definition in §5 | the full ladder for a known greatest version |
//! | [`search_binary_ladder`] | greatest- and fixed-version search (§6.2, §7) | truncated as soon as the target is bracketed |
//! | [`monitoring_binary_ladder`] | monitoring (§8.1) | only the versions at or below the monitored one |
//!
//! Both truncating variants also drop lookups whose answer is already known from
//! a proof given for a log entry to the left or right, which is what makes a
//! `CombinedTreeProof` as small as it is (§12.3).
//!
//! # Versions are `uint32`, ladders are not
//!
//! Appendix B is Python, so its ladder for `n = 2^32 - 1` happily contains
//! `2^33 - 1`. On the wire a version is a `uint32` (§11.7 `VrfInput`), so that
//! rung cannot be looked up: there is no way to prove that `2^32 - 1` is the
//! greatest version of a label, because doing so requires a non-inclusion proof
//! for a version that does not fit the field. [`base_binary_ladder`] and
//! [`search_binary_ladder`] report [`Error::UnrepresentableRung`] rather than
//! truncating silently; [`monitoring_binary_ladder`] cannot hit it, since it
//! keeps only rungs at or below the monitored version.
//!
//! The Go peer `katie` computes its whole ladder in `uint32`, which does not
//! survive the top half of the version range. Its binary search takes the
//! midpoint as `(lower + upper) / 2`, and once that sum exceeds `u32::MAX` it
//! wraps: the midpoint lands below the lower bound, the interval never closes,
//! and the loop appends rungs until it is killed. The first affected greatest
//! version is `2^31 - 1`, where the upper bound becomes `2^32 - 1`. (At
//! `u32::MAX` even the first phase spins, since `1 << 32` is 0 in Go and the rung
//! wraps to `u32::MAX`, which never exceeds `u32::MAX`.) Verified at pin
//! `00da5254`: `2^31 - 2` returns a 62-rung ladder, `2^31 - 1` is OOM-killed.
//!
//! So `interop/vectors/binary-ladder.json` stops at `2^31 - 2`, and everything
//! above it — including the one genuinely impossible case above — is pinned by the
//! tests in this module instead. Computing the rungs in `u64` is what avoids the
//! problem here; it is not a difference of interpretation, and both peer bugs are
//! worth an upstream report.

use alloc::vec::Vec;
use core::fmt;

use kt_wire::proofs::PrefixSearchResult;

/// A ladder that cannot be expressed with `uint32` versions.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The ladder needs a rung above `u32::MAX`, so it cannot be looked up.
    ///
    /// Only reachable when the greatest version is `u32::MAX`: establishing that
    /// bound requires a non-inclusion proof for version `2^32`, which the
    /// `uint32` version field cannot express.
    UnrepresentableRung {
        /// The rung the ladder called for.
        rung: u64,
        /// The greatest version the ladder was built for.
        greatest: u32,
    },
    /// A ladder's results do not correspond to its lookups (§6.2).
    ///
    /// Either there are more results than rungs, or a result that should have ended
    /// the ladder was followed by more. A log that sends either is answering
    /// different lookups than the ones the user asked for.
    LadderShape {
        /// How many rungs the ladder has, or where it should have ended.
        rungs: usize,
        /// How many results arrived.
        results: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnrepresentableRung { rung, greatest } => write!(
                f,
                "binary ladder for greatest version {greatest} needs version {rung}, \
                 which does not fit the uint32 version field"
            ),
            Self::LadderShape { rungs, results } => write!(
                f,
                "a ladder of {rungs} lookups cannot be answered by {results} results"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// A specialized [`Result`] for ladder construction.
pub type Result<T> = core::result::Result<T, Error>;

/// The versions that establish `greatest` as the greatest version of a label
/// (Appendix B `base_binary_ladder`).
///
/// # Errors
///
/// [`Error::UnrepresentableRung`] if `greatest` is `u32::MAX`; see the module
/// documentation.
pub fn base_binary_ladder(greatest: u32) -> Result<Vec<u32>> {
    let mut out = Vec::new();
    for rung in base_ladder_rungs(greatest) {
        out.push(narrow(rung, greatest)?);
    }
    Ok(out)
}

/// The versions looked up in a *search* binary ladder (Appendix B
/// `search_binary_ladder`).
///
/// `target` is the version being searched for and `greatest` is the greatest
/// version of the label that exists in the prefix tree being queried. The ladder
/// stops at the first lookup whose outcome settles whether `greatest` is at least
/// `target`: an inclusion proof for a version above `target`, or a non-inclusion
/// proof for a version at or below it (§6.2).
///
/// `left_inclusion` holds versions already shown to be included by a log entry to
/// the left, `right_non_inclusion` versions already shown to be absent by an entry
/// to the right. Those lookups are dropped, since the answer is already known —
/// but they still count for termination, because whether the ladder ends does not
/// depend on whether the proof happened to be sent.
///
/// # Errors
///
/// [`Error::UnrepresentableRung`] if `target` and `greatest` are both `u32::MAX`:
/// with nothing to distinguish them, the ladder runs to the end of the base
/// ladder, whose last rungs do not fit a `uint32`.
pub fn search_binary_ladder(
    target: u32,
    greatest: u32,
    left_inclusion: &[u32],
    right_non_inclusion: &[u32],
) -> Result<Vec<u32>> {
    let target_wide = u64::from(target);
    let greatest_wide = u64::from(greatest);
    // Appendix B's `would_end`: an inclusion proof for a version greater than the
    // target, or a non-inclusion proof for a version at or below it.
    let would_end = |rung: u64| {
        (rung <= greatest_wide && rung > target_wide)
            || (rung > greatest_wide && rung <= target_wide)
    };

    let mut out = Vec::new();
    for rung in base_ladder_rungs(greatest) {
        let version = narrow(rung, greatest)?;
        if !left_inclusion.contains(&version) && !right_non_inclusion.contains(&version) {
            out.push(version);
        }
        if would_end(rung) {
            break;
        }
    }
    Ok(out)
}

/// The versions looked up in a *monitoring* binary ladder (Appendix B
/// `monitoring_binary_ladder`).
///
/// Monitoring a label at version `target` means re-establishing that version
/// `target` is still what the log says it is, so only the rungs at or below
/// `target` are looked up — the ladder proves inclusion and never non-inclusion
/// (§8.1). `left_inclusion` drops lookups already proven by an entry to the left.
///
/// Infallible: every rung it keeps is at most `target`, so the `uint32` limit in
/// the module documentation cannot bite.
#[must_use]
pub fn monitoring_binary_ladder(target: u32, left_inclusion: &[u32]) -> Vec<u32> {
    let target_wide = u64::from(target);
    base_ladder_rungs(target)
        .into_iter()
        // A rung above u32::MAX is necessarily above `target` and would be
        // dropped by the filter below in any case.
        .filter(|rung| *rung <= target_wide)
        .filter_map(|rung| u32::try_from(rung).ok())
        .filter(|version| !left_inclusion.contains(version))
        .collect()
}

/// Appendix B's `base_binary_ladder`, computed in `u64` so that the rungs above
/// `u32::MAX` are representable and can be reported rather than wrapped.
///
/// Both phases are bounded: the first emits at most 34 rungs, since `2^33 - 1`
/// exceeds every `u32`, and the second halves an interval of at most `2^33`.
fn base_ladder_rungs(greatest: u32) -> Vec<u64> {
    let greatest = u64::from(greatest);
    let mut out = Vec::new();

    // §5 step 1: consecutive powers of two minus one, until one exceeds the
    // greatest version. `lower` starts at 0 because rung 0 can never exceed
    // `greatest`, so the loop always runs at least twice and `lower` is always
    // the rung before `upper`.
    let mut lower = 0_u64;
    let mut upper = 0_u64;
    for exponent in 0..=33_u32 {
        let rung = (1_u64 << exponent).saturating_sub(1);
        out.push(rung);
        if rung > greatest {
            upper = rung;
            break;
        }
        lower = rung;
    }

    // §5 step 2: binary search between the established bounds. Both are below
    // 2^34, so the sum cannot saturate.
    while lower.saturating_add(1) < upper {
        let rung = lower.saturating_add(upper) >> 1_u32;
        out.push(rung);
        if rung <= greatest {
            lower = rung;
        } else {
            upper = rung;
        }
    }

    out
}

/// Narrows a rung to the `uint32` version field.
fn narrow(rung: u64, greatest: u32) -> Result<u32> {
    u32::try_from(rung).map_err(|_| Error::UnrepresentableRung { rung, greatest })
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;

    /// §5's worked example: "if the greatest version of a label that existed in a
    /// particular log entry was version 6, that would be established by the
    /// following: inclusion proofs for versions 0, 1, 3, a non-inclusion proof
    /// for version 7, then followed by inclusion proofs for versions 5 and 6."
    #[test]
    fn base_ladder_matches_the_worked_example() {
        assert_eq!(base_binary_ladder(6).unwrap(), vec![0, 1, 3, 7, 5, 6]);
    }

    #[test]
    fn base_ladder_small_cases() {
        assert_eq!(base_binary_ladder(0).unwrap(), vec![0, 1]);
        assert_eq!(base_binary_ladder(1).unwrap(), vec![0, 1, 3, 2]);
        assert_eq!(base_binary_ladder(2).unwrap(), vec![0, 1, 3, 2]);
        assert_eq!(base_binary_ladder(3).unwrap(), vec![0, 1, 3, 7, 5, 4]);
        assert_eq!(
            base_binary_ladder(7).unwrap(),
            vec![0, 1, 3, 7, 15, 11, 9, 8]
        );
    }

    /// A base ladder determines its greatest version uniquely: the largest rung
    /// present is `n`, the smallest absent rung is `n+1`, and no other value of
    /// `n` produces the same sequence. That is the property §5 relies on when it
    /// says the log "would be unable to prove a different greatest version".
    #[test]
    fn base_ladder_pins_the_greatest_version() {
        for greatest in 0_u32..=2_000 {
            let ladder = base_binary_ladder(greatest).unwrap();
            let included: Vec<u32> = ladder.iter().copied().filter(|v| *v <= greatest).collect();
            let absent: Vec<u32> = ladder.iter().copied().filter(|v| *v > greatest).collect();
            assert_eq!(
                *included.iter().max().unwrap(),
                greatest,
                "greatest {greatest}"
            );
            assert_eq!(
                *absent.iter().min().unwrap(),
                greatest + 1,
                "greatest {greatest}"
            );
            // No duplicated lookups: a repeated rung would be wasted bytes.
            let mut sorted = ladder.clone();
            sorted.sort_unstable();
            let len = sorted.len();
            sorted.dedup();
            assert_eq!(
                sorted.len(),
                len,
                "greatest {greatest}: duplicate rung in {ladder:?}"
            );
            // Logarithmic, as §5 intends: powers-of-two phase plus a binary search.
            assert!(
                ladder.len() <= 2 * 32,
                "greatest {greatest}: ladder too long"
            );
        }
    }

    /// §6.2's ladder stops once the target is bracketed. Worked through by hand:
    /// searching for version 5 in an entry whose greatest version is 100, the
    /// inclusion proof for 7 already shows the greatest version exceeds 5.
    #[test]
    fn search_ladder_stops_once_the_target_is_settled() {
        assert_eq!(
            search_binary_ladder(5, 100, &[], &[]).unwrap(),
            vec![0, 1, 3, 7]
        );
        // The mirror image: greatest version 5, target 100. The *non*-inclusion
        // proof for 7 settles it, and the ladder is the same one.
        assert_eq!(
            search_binary_ladder(100, 5, &[], &[]).unwrap(),
            vec![0, 1, 3, 7]
        );
    }

    /// When the target is exactly the greatest version there is nothing to
    /// settle early, so the search ladder is the whole base ladder.
    #[test]
    fn search_ladder_with_target_equal_to_greatest_is_the_base_ladder() {
        for version in [0_u32, 1, 6, 7, 100, 1_000, 65_535] {
            assert_eq!(
                search_binary_ladder(version, version, &[], &[]).unwrap(),
                base_binary_ladder(version).unwrap(),
                "version {version}"
            );
        }
    }

    /// Deduplication drops the lookup but not the stopping point: `7` is still
    /// what ends the ladder even when it is not sent.
    #[test]
    fn search_ladder_drops_known_lookups_without_changing_where_it_ends() {
        let full = search_binary_ladder(5, 100, &[], &[]).unwrap();
        assert_eq!(full, vec![0, 1, 3, 7]);

        assert_eq!(
            search_binary_ladder(5, 100, &[1], &[]).unwrap(),
            vec![0, 3, 7]
        );
        assert_eq!(
            search_binary_ladder(5, 100, &[7], &[]).unwrap(),
            vec![0, 1, 3]
        );
        assert_eq!(
            search_binary_ladder(5, 100, &[], &[3]).unwrap(),
            vec![0, 1, 7]
        );
        assert_eq!(
            search_binary_ladder(5, 100, &[0, 1, 3, 7], &[]).unwrap(),
            Vec::<u32>::new()
        );
    }

    /// §8.1: a monitoring ladder only ever asks for inclusion, so every rung is
    /// at or below the monitored version.
    #[test]
    fn monitoring_ladder_keeps_only_versions_up_to_the_target() {
        assert_eq!(monitoring_binary_ladder(0, &[]), vec![0]);
        assert_eq!(monitoring_binary_ladder(6, &[]), vec![0, 1, 3, 5, 6]);
        assert_eq!(monitoring_binary_ladder(7, &[]), vec![0, 1, 3, 7]);
        for target in 0_u32..=500 {
            let ladder = monitoring_binary_ladder(target, &[]);
            assert!(ladder.iter().all(|v| *v <= target), "target {target}");
            assert_eq!(*ladder.iter().max().unwrap(), target, "target {target}");
        }
    }

    #[test]
    fn monitoring_ladder_drops_known_lookups() {
        assert_eq!(monitoring_binary_ladder(6, &[1, 5]), vec![0, 3, 6]);
        assert_eq!(
            monitoring_binary_ladder(6, &[0, 1, 3, 5, 6]),
            Vec::<u32>::new()
        );
    }

    /// The `uint32` edge from the module documentation. `u32::MAX - 1` is fine;
    /// `u32::MAX` is not expressible and says so instead of wrapping, truncating,
    /// or looping.
    #[test]
    fn greatest_version_of_u32_max_is_not_representable() {
        let ladder = base_binary_ladder(u32::MAX - 1).unwrap();
        assert_eq!(*ladder.iter().max().unwrap(), u32::MAX);

        assert_eq!(
            base_binary_ladder(u32::MAX),
            Err(Error::UnrepresentableRung {
                rung: (1 << 33) - 1,
                greatest: u32::MAX
            })
        );
        assert_eq!(
            search_binary_ladder(u32::MAX, u32::MAX, &[], &[]),
            Err(Error::UnrepresentableRung {
                rung: (1 << 33) - 1,
                greatest: u32::MAX
            })
        );

        // A search ladder with anything to distinguish target from greatest
        // terminates inside the representable range.
        assert!(search_binary_ladder(0, u32::MAX, &[], &[]).is_ok());
        assert!(search_binary_ladder(u32::MAX, 0, &[], &[]).is_ok());
        assert!(search_binary_ladder(u32::MAX - 1, u32::MAX, &[], &[]).is_ok());

        // And monitoring is defined at the top of the range.
        let monitoring = monitoring_binary_ladder(u32::MAX, &[]);
        assert_eq!(*monitoring.iter().max().unwrap(), u32::MAX);
        assert_eq!(monitoring.len(), 33, "0, 1, 3, … 2^32-1");
    }

    /// The Go peer builds its search ladder from the base ladder of the *target*
    /// version, where draft-05's Appendix B builds it from the base ladder of the
    /// *greatest* version. The outputs are nonetheless identical, which is why
    /// the katie-generated vectors are a valid oracle for this code.
    ///
    /// Why: the two base ladders agree rung by rung until the first rung whose
    /// comparison differs, i.e. the first rung with `min(t,n) < rung <= max(t,n)`.
    /// That condition is exactly Appendix B's `would_end`, and both variants
    /// include the rung that ends the ladder — so they cannot diverge before
    /// stopping. Checked here over a grid rather than argued only in prose.
    #[test]
    fn matches_a_target_indexed_search_ladder() {
        /// The peer's shape: iterate the base ladder of the target instead.
        fn target_indexed(target: u32, greatest: u32) -> Vec<u32> {
            let mut out = Vec::new();
            for rung in base_ladder_rungs(target) {
                let Ok(version) = u32::try_from(rung) else {
                    break;
                };
                out.push(version);
                let ends = (rung <= u64::from(greatest) && rung > u64::from(target))
                    || (rung > u64::from(greatest) && rung <= u64::from(target));
                if ends {
                    break;
                }
            }
            out
        }

        for target in 0_u32..=120 {
            for greatest in 0_u32..=120 {
                assert_eq!(
                    search_binary_ladder(target, greatest, &[], &[]).unwrap(),
                    target_indexed(target, greatest),
                    "target {target}, greatest {greatest}"
                );
            }
        }
        for (target, greatest) in [
            (0_u32, u32::MAX - 1),
            (u32::MAX - 1, 0),
            (1_000_000, 3),
            (3, 1_000_000),
            (u32::MAX - 1, u32::MAX - 1),
        ] {
            assert_eq!(
                search_binary_ladder(target, greatest, &[], &[]).unwrap(),
                target_indexed(target, greatest),
                "target {target}, greatest {greatest}"
            );
        }
    }
}

#[cfg(test)]
mod error_tests {
    use super::*;
    use alloc::string::ToString as _;

    /// The one error a ladder can produce says which rung it wanted and for which
    /// greatest version, because both are needed to see why it is unrepresentable.
    #[test]
    fn the_unrepresentable_rung_renders_both_numbers() {
        use core::error::Error as _;

        let err = Error::UnrepresentableRung {
            rung: (1 << 33) - 1,
            greatest: u32::MAX,
        };
        let rendered = err.to_string();
        assert!(rendered.contains("8589934591"), "{rendered}");
        assert!(rendered.contains("4294967295"), "{rendered}");
        assert!(rendered.contains("uint32"), "{rendered}");
        assert!(err.source().is_none());
    }
}

/// What a search binary ladder's outcomes say about the greatest version
/// (§6.2).
///
/// A searching user does not need the greatest version of a label, only whether it is
/// less than, equal to, or greater than the version they are looking for — that is
/// enough to steer the implicit binary search tree. §6.2 gets it from two stopping
/// rules on the ladder's outcomes:
///
/// - an *inclusion* proof for a version **above** the target means the greatest
///   version is above it;
/// - a *non-inclusion* proof for a version **at or below** the target means the
///   greatest version is below it;
/// - a ladder that runs to the end without either means the greatest version is
///   exactly the target.
///
/// The middle case is the one worth reading twice: the ladder deliberately continues
/// past an inclusion proof for a version *equal* to the target, because "this version
/// exists" does not yet distinguish "it is the greatest" from "there are more".
///
/// `results` are the outcomes in the order the ladder asked for them; only whether
/// each was an inclusion matters here, so a caller passes the results of a
/// [`PrefixProof`](kt_wire::proofs::PrefixProof) straight through.
///
/// # Errors
///
/// [`Error::LadderShape`] if there are more results than rungs, or if a result that
/// should have ended the ladder is not the last one. Both mean the log sent a ladder
/// that does not correspond to the lookups it claims to answer, and reading past that
/// point would be reading a proof of something else.
pub fn interpret_search_ladder(
    ladder: &[u32],
    target: u32,
    results: &[PrefixSearchResult],
) -> Result<core::cmp::Ordering> {
    use core::cmp::Ordering;

    if results.len() > ladder.len() {
        return Err(Error::LadderShape {
            rungs: ladder.len(),
            results: results.len(),
        });
    }

    for (index, version) in ladder.iter().enumerate() {
        let Some(result) = results.get(index) else {
            // The ladder has rungs the proof does not answer, and no stopping rule
            // fired, so the response is short rather than merely truncated early.
            return Err(Error::LadderShape {
                rungs: ladder.len(),
                results: results.len(),
            });
        };

        let ends = if result.is_inclusion() {
            *version > target
        } else {
            *version <= target
        };
        if ends {
            // A stopping rule fired, so this must be where the ladder ended.
            if results.len() != index.saturating_add(1) {
                return Err(Error::LadderShape {
                    rungs: index.saturating_add(1),
                    results: results.len(),
                });
            }
            return Ok(if result.is_inclusion() {
                Ordering::Greater
            } else {
                Ordering::Less
            });
        }
    }

    Ok(Ordering::Equal)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod interpretation_tests {
    use super::*;
    use core::cmp::Ordering;

    /// The outcomes an honest log would produce for a ladder, given the greatest
    /// version that really exists: a version is included exactly when it is at or
    /// below it.
    fn honest_results(ladder: &[u32], greatest: u32, target: u32) -> Vec<PrefixSearchResult> {
        let mut out = Vec::new();
        for version in ladder {
            let included = *version <= greatest;
            out.push(if included {
                PrefixSearchResult::Inclusion { depth: 0 }
            } else {
                PrefixSearchResult::NonInclusionParent { depth: 0 }
            });
            // §6.2's stopping rules, applied by the log when it builds the response.
            let ends = if included {
                *version > target
            } else {
                *version <= target
            };
            if ends {
                break;
            }
        }
        out
    }

    /// The whole point: for every target and every greatest version, the
    /// interpretation recovers the comparison the searcher needs. This is the
    /// property §6.2 exists to provide, checked over a grid rather than argued.
    #[test]
    fn interpretation_recovers_the_comparison() {
        for target in 0_u32..=60 {
            for greatest in 0_u32..=60 {
                let ladder = search_binary_ladder(target, greatest, &[], &[]).unwrap();
                let results = honest_results(&ladder, greatest, target);
                assert_eq!(
                    interpret_search_ladder(&ladder, target, &results).unwrap(),
                    greatest.cmp(&target),
                    "target {target}, greatest {greatest}, ladder {ladder:?}"
                );
            }
        }
    }

    /// §6.2: the ladder continues past an inclusion proof for a version *equal* to
    /// the target, because existing is not the same as being the greatest. If it
    /// stopped there, `Equal` and `Greater` would be indistinguishable.
    #[test]
    fn an_inclusion_at_the_target_does_not_end_the_ladder() {
        let ladder = search_binary_ladder(6, 6, &[], &[]).unwrap();
        assert_eq!(ladder, alloc::vec![0, 1, 3, 7, 5, 6]);

        // The stopping rules do not fire on the rung equal to the target, so an
        // honest log answers every rung rather than stopping at version 6.
        let equal = honest_results(&ladder, 6, 6);
        assert_eq!(
            equal.len(),
            ladder.len(),
            "an inclusion at the target must not end the ladder"
        );

        // Greatest 6 and greatest 7 share the ladder's early rungs and are told apart
        // only by what comes after the inclusion of 6.
        let equal = honest_results(&ladder, 6, 6);
        assert_eq!(
            interpret_search_ladder(&ladder, 6, &equal).unwrap(),
            Ordering::Equal
        );

        let seven = search_binary_ladder(6, 7, &[], &[]).unwrap();
        let greater = honest_results(&seven, 7, 6);
        assert_eq!(
            interpret_search_ladder(&seven, 6, &greater).unwrap(),
            Ordering::Greater
        );
    }

    /// A log that keeps going after a stopping rule has fired is answering different
    /// lookups than the ones it claims to, so the shape is rejected rather than the
    /// extra results ignored.
    #[test]
    fn results_past_a_stopping_rule_are_rejected() {
        let ladder = search_binary_ladder(5, 100, &[], &[]).unwrap();
        let mut results = honest_results(&ladder, 100, 5);
        assert_eq!(
            interpret_search_ladder(&ladder, 5, &results).unwrap(),
            Ordering::Greater
        );

        // One more result than the rule allows.
        results.push(PrefixSearchResult::Inclusion { depth: 0 });
        assert!(matches!(
            interpret_search_ladder(&ladder, 5, &results),
            Err(Error::LadderShape { .. })
        ));
    }

    #[test]
    fn a_short_or_over_long_response_is_rejected() {
        let ladder = search_binary_ladder(6, 6, &[], &[]).unwrap();

        // Fewer results than the ladder needs, with no stopping rule reached.
        let short = honest_results(&ladder, 6, 6);
        assert!(matches!(
            interpret_search_ladder(&ladder, 6, &short[..short.len() - 1]),
            Err(Error::LadderShape { .. })
        ));

        // More results than there are rungs.
        let mut long = short.clone();
        long.push(PrefixSearchResult::Inclusion { depth: 0 });
        assert!(matches!(
            interpret_search_ladder(&ladder, 6, &long),
            Err(Error::LadderShape {
                rungs: _,
                results: _
            })
        ));
    }

    /// A log that lies about one outcome changes the verdict, which is why the
    /// outcomes have to come from a verified `PrefixProof` rather than be taken on
    /// trust: this function reads a proof, it does not check one.
    #[test]
    fn flipping_an_outcome_changes_the_verdict() {
        let ladder = search_binary_ladder(6, 6, &[], &[]).unwrap();
        let honest = honest_results(&ladder, 6, 6);
        assert_eq!(
            interpret_search_ladder(&ladder, 6, &honest).unwrap(),
            Ordering::Equal
        );

        // Claim the first rung is absent: version 0 is at or below the target, so the
        // rule says the greatest version is below it.
        let mut lying = honest;
        lying.truncate(1);
        lying[0] = PrefixSearchResult::NonInclusionParent { depth: 0 };
        assert_eq!(
            interpret_search_ladder(&ladder, 6, &lying).unwrap(),
            Ordering::Less
        );
    }
}
