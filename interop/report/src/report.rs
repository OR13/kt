//! The result model: what was checked, what was expected, what happened.
//!
//! Serialized as `report.json` alongside the published page, so the evidence is
//! machine-readable and not only a rendering. Every check carries both the
//! expected and the observed value, including on success — a report that only
//! shows values when they disagree is asking to be taken on trust.

use serde::Serialize;

/// The outcome of one comparison.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// The observed value equalled the expected one.
    Pass,
    /// It did not.
    Fail,
}

impl Verdict {
    /// `Pass` if `condition` holds.
    #[must_use]
    pub const fn of(condition: bool) -> Self {
        if condition { Self::Pass } else { Self::Fail }
    }

    /// Whether this is a failure.
    #[must_use]
    pub const fn failed(self) -> bool {
        matches!(self, Self::Fail)
    }
}

/// One comparison: what was computed, what the peer said, and whether they agree.
#[derive(Clone, Debug, Serialize)]
pub struct Check {
    /// What was compared, with the draft section it comes from.
    pub what: String,
    /// The peer's value.
    pub expected: String,
    /// This implementation's value.
    pub got: String,
    /// Whether they match.
    pub verdict: Verdict,
    /// Sub-comparisons, for checks that cover a table of values — the per-node
    /// children of an implicit binary search tree, for instance. Present in full
    /// here even where the rendered page summarizes them.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub children: Vec<Check>,
}

impl Check {
    /// A check comparing two already-rendered values.
    #[must_use]
    pub fn new(
        what: impl Into<String>,
        expected: impl Into<String>,
        got: impl Into<String>,
    ) -> Self {
        let expected = expected.into();
        let got = got.into();
        let verdict = Verdict::of(expected == got);
        Self {
            what: what.into(),
            expected,
            got,
            verdict,
            children: Vec::new(),
        }
    }

    /// A check whose verdict is the conjunction of its children's.
    #[must_use]
    pub fn group(what: impl Into<String>, children: Vec<Self>) -> Self {
        let failures = children.iter().filter(|c| c.verdict.failed()).count();
        let total = children.len();
        let expected = format!("{total} sub-checks match");
        let got = if failures == 0 {
            format!("{total} sub-checks match")
        } else {
            format!("{failures} of {total} sub-checks disagree")
        };
        let verdict = Verdict::of(failures == 0);
        Self {
            what: what.into(),
            expected,
            got,
            verdict,
            children,
        }
    }

    /// Every failing check at or below this one, flattened.
    pub fn failures(&self) -> impl Iterator<Item = &Self> {
        let own = core::iter::once(self).filter(|c| c.verdict.failed() && c.children.is_empty());
        let nested = self.children.iter().filter(|c| c.verdict.failed());
        own.chain(nested)
    }
}

/// One case from a vector file.
#[derive(Clone, Debug, Serialize)]
pub struct Case {
    /// The case name from the vector file.
    pub name: String,
    /// Whether the case asserts a refusal rather than a value.
    pub negative: bool,
    /// A one-line rendering of the inputs.
    pub input: String,
    /// Every comparison made for this case.
    pub checks: Vec<Check>,
}

impl Case {
    /// The overall verdict: a case passes only if every check does.
    #[must_use]
    pub fn verdict(&self) -> Verdict {
        Verdict::of(!self.checks.iter().any(|c| c.verdict.failed()))
    }
}

/// One vector file's worth of results.
#[derive(Clone, Debug, Serialize)]
pub struct Suite {
    /// The primitive, e.g. `commitment`.
    pub primitive: String,
    /// A human-readable name for the page.
    pub title: String,
    /// The draft sections these vectors come from.
    pub draft_section: String,
    /// The vector file name.
    pub file: String,
    /// What produced the expected values.
    pub generator: Generator,
    /// The cipher suite, where the primitive depends on one.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cipher_suite: Option<String>,
    /// The cases.
    pub cases: Vec<Case>,
}

impl Suite {
    /// Number of checks, counting nested ones.
    #[must_use]
    pub fn checks(&self) -> usize {
        self.cases
            .iter()
            .map(|case| case.checks.iter().map(count_checks).sum::<usize>())
            .sum()
    }

    /// Number of failing checks, counting nested ones.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.cases
            .iter()
            .map(|case| case.checks.iter().map(count_failed).sum::<usize>())
            .sum()
    }

    /// Number of cases that assert a refusal.
    #[must_use]
    pub fn negative_cases(&self) -> usize {
        self.cases.iter().filter(|c| c.negative).count()
    }

    /// Whether every check in the suite passed.
    #[must_use]
    pub fn passing(&self) -> bool {
        self.failed() == 0
    }
}

fn count_checks(check: &Check) -> usize {
    if check.children.is_empty() {
        1
    } else {
        check.children.iter().map(count_checks).sum()
    }
}

fn count_failed(check: &Check) -> usize {
    if check.children.is_empty() {
        usize::from(check.verdict.failed())
    } else {
        check.children.iter().map(count_failed).sum()
    }
}

/// Which implementation produced a suite's expected values.
#[derive(Clone, Debug, Serialize)]
pub struct Generator {
    /// The implementation name.
    pub implementation: String,
    /// Its full commit id.
    pub sha: String,
}

/// How well covered one area of the protocol is.
///
/// [`Coverage::OutOfScope`] exists so the table can distinguish "we have not got to
/// this" from "we have decided not to do this". Listing a deliberate exclusion as a
/// gap invites someone to file it as a bug.
///
/// This table is the reason the page can be read as evidence rather than as a
/// claim: it lists the areas that are *not* covered next to the ones that are. A
/// row only moves up when a committed vector or a live test asserts it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Coverage {
    /// Implemented, and a committed vector asserts agreement with a Go peer.
    VerifiedAgainstPeer,
    /// Implemented and unit-tested against the draft, but no peer has confirmed
    /// the bytes.
    ImplementedUnverified,
    /// Not implemented.
    NotImplemented,
    /// Deliberately not implemented, with a reason.
    OutOfScope,
}

impl Coverage {
    /// A short label for the page.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::VerifiedAgainstPeer => "verified against peer",
            Self::ImplementedUnverified => "implemented, unverified",
            Self::NotImplemented => "not implemented",
            Self::OutOfScope => "out of scope",
        }
    }
}

/// One row of the coverage table.
#[derive(Clone, Debug, Serialize)]
pub struct Area {
    /// The draft sections involved.
    pub section: String,
    /// What the area is.
    pub name: String,
    /// Where it lives in this workspace, if it exists yet.
    pub module: Option<String>,
    /// How well covered it is.
    pub coverage: Coverage,
    /// The vector files that assert it, if any.
    ///
    /// A list rather than one file because an area can be covered in two different
    /// senses, and the difference matters: a file of values proves the two
    /// implementations *compute* the same thing, while `tampered.json` proves they
    /// *refuse* the same things. An area with only the first cannot catch a verifier
    /// that accepts everything.
    pub evidence: Vec<String>,
}

impl Area {
    /// Whether some file attests that this area rejects what the peer rejects.
    #[must_use]
    pub fn has_refusal_evidence(&self) -> bool {
        self.evidence.iter().any(|file| file == "tampered.json")
    }
}

/// Where the report was produced, so a reader can reproduce it.
#[derive(Clone, Debug, Default, Serialize)]
pub struct Provenance {
    /// UTC timestamp, RFC 3339.
    pub generated_at: String,
    /// The commit of this repository that was tested.
    pub commit: Option<String>,
    /// A link to that commit.
    pub commit_url: Option<String>,
    /// A link to the CI run that produced the page.
    pub run_url: Option<String>,
    /// The Rust toolchain used.
    pub rustc: Option<String>,
    /// The Go toolchain that generated the vectors, where known.
    pub go: Option<String>,
}

/// The whole report.
#[derive(Clone, Debug, Serialize)]
pub struct Report {
    /// The draft revision this implementation targets.
    pub draft: String,
    /// Where and when the report was produced.
    pub provenance: Provenance,
    /// One entry per vector file.
    pub suites: Vec<Suite>,
    /// The coverage table, verified areas included.
    pub coverage: Vec<Area>,
}

impl Report {
    /// Total number of checks across all suites.
    #[must_use]
    pub fn checks(&self) -> usize {
        self.suites.iter().map(Suite::checks).sum()
    }

    /// Total number of failing checks across all suites.
    #[must_use]
    pub fn failed(&self) -> usize {
        self.suites.iter().map(Suite::failed).sum()
    }

    /// Total number of cases across all suites.
    #[must_use]
    pub fn cases(&self) -> usize {
        self.suites.iter().map(|s| s.cases.len()).sum()
    }

    /// Whether every check passed.
    #[must_use]
    pub fn passing(&self) -> bool {
        self.failed() == 0
    }

    /// Areas with the given coverage.
    pub fn areas_with(&self, coverage: Coverage) -> impl Iterator<Item = &Area> {
        self.coverage.iter().filter(move |a| a.coverage == coverage)
    }
}

/// The coverage table.
///
/// Hand-maintained, and deliberately so: it is a statement about what this
/// implementation claims, and it should take a human decision to change. A test
/// asserts that every `VerifiedAgainstPeer` row names a vector file that the
/// report actually contains and that passes, so the table cannot overstate.
#[must_use]
pub fn coverage_table() -> Vec<Area> {
    let verified = |section: &str, name: &str, module: &str, files: &[&str]| Area {
        section: section.to_owned(),
        name: name.to_owned(),
        module: Some(module.to_owned()),
        coverage: Coverage::VerifiedAgainstPeer,
        evidence: files.iter().map(|file| (*file).to_owned()).collect(),
    };
    let todo = |section: &str, name: &str| Area {
        section: section.to_owned(),
        name: name.to_owned(),
        module: None,
        coverage: Coverage::NotImplemented,
        evidence: Vec::new(),
    };

    vec![
        verified(
            "§2.1",
            "Presentation-language codec",
            "kt-wire::codec",
            &["commitment.json"],
        ),
        verified(
            "§11.5",
            "UpdateValue",
            "kt-wire::structs",
            &["commitment.json"],
        ),
        verified(
            "§11.6",
            "CommitmentValue",
            "kt-wire::structs",
            &["commitment.json"],
        ),
        verified(
            "§11.6",
            "Commitment, HMAC(Kc, CommitmentValue)",
            "kt-crypto::commitment",
            &["commitment.json", "tampered.json"],
        ),
        verified(
            "§4.1, App. A",
            "Implicit binary search tree",
            "kt-tree::ibst",
            &["ibst.json"],
        ),
        verified(
            "§5, App. B",
            "Binary ladders",
            "kt-tree::ladder",
            &["binary-ladder.json"],
        ),
        verified(
            "§11.7",
            "VRF: ECVRF-EDWARDS25519-SHA512-TAI",
            "kt-crypto::vrf",
            &["vrf.json", "tampered.json"],
        ),
        verified(
            "§3.2, §11.8, §12.1",
            "Log tree: root, batch inclusion and consistency proofs",
            "kt-tree::log",
            &["log-tree.json", "log-math.json", "tampered.json"],
        ),
        verified(
            "§6.2",
            "Search ladder interpretation: is the greatest version below, at, or above",
            "kt-tree::ladder",
            &["ladder-interpretation.json"],
        ),
        verified(
            "§11.5, §13.1–§13.5",
            "Request structures and response building blocks",
            "kt-wire::requests",
            &["requests.json"],
        ),
        verified(
            "§4.2",
            "Updating a view of the tree: which entries must be checked",
            "kt-tree::ibst",
            &["update-view.json"],
        ),
        verified(
            "§11.2, §11.4",
            "Configuration, TreeHead, and FullTreeHead verification",
            "kt-crypto::signature",
            &["tree-head.json"],
        ),
        verified(
            "§11.4",
            "FullTreeHead wire encoding, whose shape the deployment mode decides",
            "kt-wire::heads",
            &["tree-head.json"],
        ),
        verified(
            "§11.3",
            "AuditorTreeHead verification",
            "kt-crypto::signature",
            &["tree-head.json"],
        ),
        verified(
            "§3.3, §11.9, §12.2",
            "Prefix tree: root, membership and non-membership proofs",
            "kt-tree::prefix",
            &["prefix-tree.json", "tampered.json"],
        ),
        Area {
            section: "§11.1, §17.1".to_owned(),
            name: "Cipher suite registry".to_owned(),
            module: Some("kt-crypto::suite".to_owned()),
            coverage: Coverage::ImplementedUnverified,
            evidence: Vec::new(),
        },
        Area {
            section: "§11.1".to_owned(),
            name: "Cipher suite hash function".to_owned(),
            module: Some("kt-crypto::hash".to_owned()),
            coverage: Coverage::ImplementedUnverified,
            evidence: Vec::new(),
        },
        Area {
            section: "§11.2".to_owned(),
            name: "DeploymentMode".to_owned(),
            module: Some("kt-wire::structs".to_owned()),
            coverage: Coverage::ImplementedUnverified,
            evidence: Vec::new(),
        },
        // Not a gap: the Ed25519 suite is the target, and both Go peers support it.
        Area {
            section: "§11.7, §17.1".to_owned(),
            name: "VRF: ECVRF-P256-SHA256-TAI (KT_128_SHA256_P256)".to_owned(),
            module: None,
            coverage: Coverage::OutOfScope,
            evidence: Vec::new(),
        },
        todo("§3.4, §12.3", "Combined tree and CombinedTreeProof"),
        todo("§6, §7, §13.1", "Greatest-version and fixed-version search"),
        todo("§8, §13.2–§13.4", "Contact and owner monitoring"),
        todo("§9, §13.5", "Updating a label"),
        todo(
            "§13.6",
            "Requesting distinguished heads, and fork detection (§10.2)",
        ),
        todo("§14", "Credentials"),
        verified(
            "§15.2",
            "AuditorUpdate, and the auditor's checks on one log entry",
            "kt-wire::audit, kt-tree::audit",
            &["auditor-update.json"],
        ),
        verified(
            "§6.1",
            "Distinguished log entries: which entries every user checks against",
            "kt-tree::distinguished",
            &["distinguished.json"],
        ),
        Area {
            section: "§10.1".to_owned(),
            name: "Walking recent distinguished heads".to_owned(),
            module: Some("kt-tree::distinguished".to_owned()),
            // The peer exposes no walk to compare against — its client asks only for the
            // rightmost distinguished entry — so this is covered by Rust tests against the
            // §6.1 set and nothing more. Saying "verified" would overstate it.
            coverage: Coverage::ImplementedUnverified,
            evidence: Vec::new(),
        },
        verified(
            "§3.2, §11.8",
            "Growing the log tree one leaf at a time, from retained subtree heads",
            "kt-tree::log",
            &["log-append.json", "auditor-update.json"],
        ),
        verified(
            "§15.2, §3.3",
            "Prefix tree root before and after an audited update",
            "kt-tree::prefix",
            &["prefix-mutation.json", "auditor-update.json"],
        ),
        todo(
            "§15.2 step 5",
            "Removal eligibility: that a removed leaf was published in a distinguished \
             log entry first",
        ),
        todo("live wire", "HTTP interop against a running Go peer"),
    ]
}
