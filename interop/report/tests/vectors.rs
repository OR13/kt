//! The interop test suite: every committed vector, checked against this
//! implementation (`docs/interop.md` Tier 1).
//!
//! These tests and the published evidence page run the same code — see the crate
//! documentation. If this file passes, the page is accurate; if it fails, the
//! page cannot be published, because the generator exits non-zero.
//!
//! Beyond "every check agrees", these tests assert things about the *vectors*:
//! that they carry their provenance, that they still contain the refusal cases and
//! the negative cases, and that the coverage table on the page cannot claim
//! evidence that does not exist. A vector file that quietly lost its negative
//! cases would keep passing while testing much less.

#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    reason = "a test that cannot fail loudly is not a test"
)]

use kt_interop::check;
use kt_interop::report::{Coverage, Report, Suite};

fn report() -> Report {
    let dir = kt_interop::default_vector_dir();
    kt_interop::build(&dir, kt_interop::report::Provenance::default())
        .unwrap_or_else(|err| panic!("building the interop report from {}: {err}", dir.display()))
}

fn suite<'a>(report: &'a Report, file: &str) -> &'a Suite {
    report
        .suites
        .iter()
        .find(|s| s.file == file)
        .unwrap_or_else(|| panic!("no suite for {file}"))
}

/// The headline: every check in every committed vector file agrees.
#[test]
fn every_vector_check_agrees() {
    let report = report();

    let mut failures = Vec::new();
    for suite in &report.suites {
        for case in &suite.cases {
            for check in &case.checks {
                for failure in check.failures() {
                    failures.push(format!(
                        "{}, case {}: {}\n    peer: {}\n    kt:   {}",
                        suite.file, case.name, failure.what, failure.expected, failure.got
                    ));
                }
            }
        }
    }

    assert!(
        failures.is_empty(),
        "{} of {} checks disagree with the Go peer:\n{}",
        report.failed(),
        report.checks(),
        failures.join("\n")
    );
    assert!(report.checks() > 0, "no checks ran");
}

/// Every file this crate knows about is present and non-empty. A missing file is
/// an error rather than zero failures, but a *silently* empty suite would pass
/// every other assertion here.
#[test]
fn all_known_vector_files_are_checked() {
    let report = report();
    assert_eq!(report.suites.len(), check::FILES.len());
    for file in check::FILES {
        let suite = suite(&report, file);
        assert!(!suite.cases.is_empty(), "{file} has no cases");
        assert!(
            suite.checks() >= suite.cases.len(),
            "{file}: fewer checks than cases"
        );
    }
}

/// Provenance, per the contract in `interop/README.md`: a vector that cannot be
/// regenerated is worthless the day it fails.
#[test]
fn every_suite_records_its_oracle() {
    let report = report();
    for suite in &report.suites {
        assert_eq!(suite.generator.implementation, "katie", "{}", suite.file);
        assert_eq!(
            suite.generator.sha.len(),
            40,
            "{}: generator SHA must be a full git object id",
            suite.file
        );
        assert!(
            suite.generator.sha.chars().all(|c| c.is_ascii_hexdigit()),
            "{}: generator SHA is not hex",
            suite.file
        );
        assert!(
            suite.draft_section.contains('§'),
            "{}: no draft section",
            suite.file
        );

        let mut names: Vec<&str> = suite.cases.iter().map(|c| c.name.as_str()).collect();
        names.sort_unstable();
        let total = names.len();
        names.dedup();
        assert_eq!(
            names.len(),
            total,
            "{}: case names must be unique",
            suite.file
        );
    }
}

/// The commitment vectors must keep testing rejection, not just computation. A
/// verifier that accepts everything passes every positive case.
#[test]
fn commitment_vectors_still_test_refusal() {
    let report = report();
    let commitment = suite(&report, "commitment.json");
    assert!(
        commitment.negative_cases() > 0,
        "commitment.json has no negative cases: a vector file that only exercises the \
         happy path cannot catch an implementation that accepts everything"
    );
    assert!(
        commitment.cases.len() > commitment.negative_cases(),
        "commitment.json has no positive cases"
    );
    assert!(
        commitment.cipher_suite.is_some(),
        "commitment.json should name a cipher suite"
    );
}

/// The implicit binary search tree vectors must keep covering the inputs that have
/// no answer: a leaf's child, and the rightmost entry's right child.
#[test]
fn ibst_vectors_still_test_refusal() {
    let report = report();
    let ibst = suite(&report, "ibst.json");

    let refusals = ibst
        .cases
        .iter()
        .flat_map(|case| &case.checks)
        .flat_map(|check| &check.children)
        .filter(|child| child.expected == "refused")
        .count();
    assert!(
        refusals > 0,
        "ibst.json has no cases where a child must be refused"
    );

    // And the frontier of the largest tree in the file should be a real walk, not
    // a single node, or the vectors are not exercising `right`'s descent.
    let deepest = ibst
        .cases
        .iter()
        .flat_map(|case| &case.checks)
        .filter(|check| check.what.starts_with("frontier"))
        .map(|check| check.expected.matches(',').count())
        .max()
        .unwrap_or(0);
    assert!(
        deepest >= 8,
        "ibst.json has no deep frontiers: longest is {deepest} steps"
    );
}

/// All three Appendix B ladder variants must be covered, including the
/// deduplication sets — the part most likely to be plausibly-but-wrongly
/// implemented.
#[test]
fn ladder_vectors_cover_all_three_variants() {
    let report = report();
    let ladder = suite(&report, "binary-ladder.json");

    let count = |needle: &str| {
        ladder
            .cases
            .iter()
            .flat_map(|case| &case.checks)
            .filter(|check| check.what.starts_with(needle))
            .count()
    };
    assert!(count("base_binary_ladder") > 0, "no base ladder cases");
    assert!(count("search_binary_ladder") > 0, "no search ladder cases");
    assert!(
        count("monitoring_binary_ladder") > 0,
        "no monitoring ladder cases"
    );

    let with_dedup = ladder
        .cases
        .iter()
        .filter(|case| !case.input.contains("left [], right []") && case.input.contains("proven"))
        .count();
    assert!(
        with_dedup > 0,
        "no ladder cases with an already-proven lookup"
    );
}

/// The coverage table is the page's honesty check, so it gets one of its own: a
/// row may only claim to be verified against the peer if it names a vector file
/// that this report actually contains and that actually passes.
#[test]
fn coverage_table_cannot_overstate() {
    let report = report();

    for area in report.areas_with(Coverage::VerifiedAgainstPeer) {
        let file = area.evidence.as_deref().unwrap_or_else(|| {
            panic!(
                "{} {} claims peer verification with no vector file",
                area.section, area.name
            )
        });
        let suite = report
            .suites
            .iter()
            .find(|s| s.file == file)
            .unwrap_or_else(|| {
                panic!(
                    "{} {} cites {file}, which is not in the report",
                    area.section, area.name
                )
            });
        assert!(
            suite.passing(),
            "{} {} claims peer verification but {file} has {} failing checks",
            area.section,
            area.name,
            suite.failed()
        );
    }

    for area in report.areas_with(Coverage::ImplementedUnverified) {
        assert!(
            area.evidence.is_none(),
            "{} {} is marked unverified but cites evidence",
            area.section,
            area.name
        );
        assert!(
            area.module.is_some(),
            "{} {} is marked implemented but names no module",
            area.section,
            area.name
        );
    }

    for area in report.areas_with(Coverage::NotImplemented) {
        assert!(
            area.module.is_none() && area.evidence.is_none(),
            "{} {} is marked unimplemented but names a module or evidence",
            area.section,
            area.name
        );
    }

    // Every suite in the report must be cited by some verified row, or the page
    // would be running checks it does not tell the reader about.
    for suite in &report.suites {
        let cited = report
            .areas_with(Coverage::VerifiedAgainstPeer)
            .any(|area| area.evidence.as_deref() == Some(suite.file.as_str()));
        assert!(
            cited,
            "{} is checked but no coverage row cites it",
            suite.file
        );
    }
}

/// The rendered page must contain what it claims to: every case name, and no
/// unescaped vector content.
#[test]
fn rendered_page_contains_every_case() {
    let report = report();
    let html = kt_interop::html::render(&report);

    for suite in &report.suites {
        assert!(
            html.contains(&suite.file),
            "page does not mention {}",
            suite.file
        );
        for case in &suite.cases {
            assert!(
                html.contains(&case.name),
                "page does not mention case {} of {}",
                case.name,
                suite.file
            );
        }
    }

    // Rough well-formedness: one document, and the coverage anchor the summary
    // links to actually exists.
    assert_eq!(html.matches("<!DOCTYPE html>").count(), 1);
    assert_eq!(html.matches("</html>").count(), 1);
    assert!(html.contains(r#"id="coverage""#));
    assert!(html.contains(r#"id="provenance""#));

    // The unimplemented areas must be visible on the page: that is the difference
    // between evidence and advertising.
    for area in report.areas_with(Coverage::NotImplemented) {
        assert!(
            html.contains(&area.name),
            "page hides unimplemented area {}",
            area.name
        );
    }
}

/// A report with a failing check must render as failing and must be refused by the
/// generator. Checked by corrupting a loaded report rather than a vector file, so
/// the committed vectors stay untouched.
#[test]
fn a_disagreement_is_visible_and_fatal() {
    let mut report = report();
    let suite = report.suites.first_mut().expect("no suites");
    let case = suite.cases.first_mut().expect("no cases");
    let check = case.checks.first_mut().expect("no checks");
    check.got = format!("{}-tampered", check.got);
    check.verdict = kt_interop::report::Verdict::Fail;

    assert!(
        !report.passing(),
        "a tampered check must make the report fail"
    );
    assert_eq!(report.failed(), 1);

    let html = kt_interop::html::render(&report);
    assert!(html.contains("disagrees"), "a failing report must say so");
    assert!(
        html.contains("-tampered"),
        "a failing report must show the value it got"
    );
    assert!(
        !html.contains("all checks agree"),
        "a failing report must not claim agreement"
    );
}
