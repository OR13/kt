//! Emits proofs *from* this implementation for the Go peer to verify.
//!
//! ```sh
//! cargo run -p kt-interop --bin kt-interop-emit -- --out interop/vectors/from-kt.json
//! cd interop/go && go run ./cmd/verify -in ../vectors/from-kt.json
//! ```
//!
//! Everything else in `interop/` runs Go → Rust: the peer produces a value and we
//! recompute it. That direction cannot catch two things. First, being
//! self-consistently wrong: an implementation that both builds and checks proofs
//! the same wrong way agrees with itself forever. Second, and worse for a client,
//! **over-acceptance** — verifying something the peer would reject. Neither shows
//! up in a comparison of values we recompute.
//!
//! So this binary writes proofs that *we* built, together with what should happen
//! to them, and `interop/go/cmd/verify` runs them through katie's verifiers:
//!
//! - honest proofs, which katie must accept and evaluate to the root we claim;
//! - tampered proofs, which katie must reject — and which our own verifier is
//!   asserted to reject here, before they are written out. A case where both
//!   implementations accept a corrupted proof would be the interesting bug, and it
//!   is the one this file exists to look for.
//!
//! The output is committed and regenerated in CI, so a change in what we emit is a
//! visible diff like every other vector file.

use std::fs;
use std::path::PathBuf;
use std::process::ExitCode;

use kt_crypto::suite::CipherSuite;
use kt_tree::{ibst, ladder, log, prefix};
use kt_wire::audit::AuditorUpdate;
use kt_wire::codec;
use kt_wire::proofs::{CombinedTreeProof, PrefixLeaf};
use kt_wire::structs::{HashValue, LogEntry};
use serde::Serialize;

const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

/// The file `interop/go/cmd/verify` reads.
#[derive(Serialize)]
struct File {
    primitive: &'static str,
    draft: &'static str,
    generator: Generator,
    notes: &'static str,
    cases: Vec<Case>,
}

#[derive(Serialize)]
struct Generator {
    r#impl: &'static str,
    version: &'static str,
}

/// What the peer must do with one proof.
#[derive(Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
enum Case {
    /// A log tree batch proof (§12.1).
    LogTree {
        name: String,
        expect: &'static str,
        /// Number of entries in the log.
        size: u64,
        /// Leaf indices being proven.
        entries: Vec<u64>,
        /// Their values, hex.
        values: Vec<String>,
        /// The size the verifier retained, if any.
        #[serde(skip_serializing_if = "Option::is_none")]
        retained_size: Option<u64>,
        /// The retained full subtree heads, hex.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        retained: Vec<String>,
        /// The proof's elements, hex.
        elements: Vec<String>,
        /// The root the proof should evaluate to, hex.
        root: String,
    },
    /// A prefix tree mutation replayed as a §15.2 auditor would.
    PrefixMutation {
        name: String,
        expect: &'static str,
        /// Leaves the update adds.
        added: Vec<Leaf>,
        /// Leaves the update removes.
        removed: Vec<Leaf>,
        /// The wire-encoded batch `PrefixProof`, hex.
        proof: String,
        /// The root before the update, hex.
        before: String,
        /// The root after it, hex.
        after: String,
    },
    /// A `CombinedTreeProof` for one of the peer's own algorithms to consume (§12.3).
    CombinedSearch {
        name: String,
        expect: &'static str,
        /// Which algorithm the peer should run: `greatest-version`, `fixed-version`, or
        /// `contact-monitor`.
        operation: &'static str,
        /// The log's size.
        size: u64,
        /// The target version: the claimed greatest for a greatest-version search, the requested
        /// one for a fixed-version search, unused for monitoring.
        greatest: u32,
        /// The monitoring map, for `contact-monitor`.
        #[serde(skip_serializing_if = "Vec::is_empty")]
        map: Vec<MapEntryOut>,
        /// Every log entry's timestamp, by position.
        timestamps: Vec<u64>,
        /// The versions the peer needs search keys for.
        versions: Vec<VersionKey>,
        /// The wire-encoded `CombinedTreeProof`, hex.
        proof: String,
    },
    /// A `CombinedTreeProof` for §9.1, which the peer reads with its own `Monitor.Update`.
    ///
    /// Separate from [`Case::CombinedSearch`] because §9.1 is checked against three things rather
    /// than one: the tree, the response's claims, and the *owner's own state*. That state has no
    /// counterpart in a search, and passing it as optional fields on a search case would suggest a
    /// search could have one.
    OwnerUpdate {
        name: String,
        expect: &'static str,
        /// The log's size.
        size: u64,
        /// The log entry the new versions were inserted into.
        position: u64,
        /// How many new versions were created there.
        ///
        /// Named `new_versions` on the wire because a search case's `versions` is a list of search
        /// keys, and one JSON name cannot be both a count and a list.
        #[serde(rename = "new_versions")]
        versions: usize,
        /// The owner's state before the update.
        owner: OwnerOut,
        /// Every log entry's timestamp, by position.
        timestamps: Vec<u64>,
        /// The search keys the peer needs for the lookups §9.1 makes.
        keys: Vec<VersionKey>,
        /// The wire-encoded `CombinedTreeProof`, hex.
        proof: String,
    },
    /// An `AuditorUpdate` for the peer's decoder (§15.2).
    AuditorUpdate {
        name: String,
        expect: &'static str,
        /// The encoded update, hex.
        encoding: String,
    },
    /// A prefix tree batch proof (§12.2).
    PrefixTree {
        name: String,
        expect: &'static str,
        /// The searches: key and, for inclusion, the commitment expected.
        searches: Vec<Search>,
        /// The wire-encoded `PrefixProof`, hex.
        proof: String,
        /// The root the proof should verify against, hex.
        root: String,
    },
}

/// One entry of a monitoring map, for the peer's contact monitoring state.
#[derive(Clone, Serialize)]
struct MapEntryOut {
    position: u64,
    version: u32,
}

/// A label owner's state, in the peer's representation.
///
/// `version_at_starting` is `-1` where the label did not exist at the reference point, which is how
/// the peer spells "no version" — it keeps the field an integer and lets the count arithmetic work
/// out. This side models it as an absent version; the conversion happens here rather than in the
/// library, so that the peer's encoding does not leak into a type the protocol defines otherwise.
#[derive(Clone, Serialize)]
struct OwnerOut {
    starting: u64,
    version_at_starting: i64,
    upcoming: Vec<u64>,
}

/// A version's search key and commitment, as the peer's proof handle wants them.
#[derive(Clone, Serialize)]
struct VersionKey {
    version: u32,
    vrf_output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
}

#[derive(Serialize)]
struct Leaf {
    vrf_output: String,
    commitment: String,
}

#[derive(Serialize)]
struct Search {
    vrf_output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    commitment: Option<String>,
}

const ACCEPT: &str = "accept";
const REJECT: &str = "reject";

fn main() -> ExitCode {
    let mut out = PathBuf::from("interop/vectors/from-kt.json");
    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--out" => match args.next() {
                Some(value) => out = PathBuf::from(value),
                None => {
                    eprintln!("kt-interop-emit: --out needs a value");
                    return ExitCode::from(2);
                }
            },
            "-h" | "--help" => {
                println!("usage: kt-interop-emit [--out <file>]");
                return ExitCode::SUCCESS;
            }
            other => {
                eprintln!("kt-interop-emit: unknown argument {other}");
                return ExitCode::from(2);
            }
        }
    }

    let cases = match build_cases() {
        Ok(cases) => cases,
        Err(message) => {
            eprintln!("kt-interop-emit: {message}");
            return ExitCode::FAILURE;
        }
    };

    let file = File {
        primitive: "from-kt",
        draft: kt_interop::DRAFT,
        generator: Generator {
            r#impl: "kt",
            version: env!("CARGO_PKG_VERSION"),
        },
        notes: "Proofs built by the Rust implementation for the Go peer to verify. \
                `expect` is `accept` when the peer must accept the proof and evaluate it to \
                `root`, and `reject` when it must not: either its verifier errors, or it \
                arrives at a different root. Every `reject` case is also rejected by this \
                implementation's own verifier before being written here, so a case the peer \
                accepts is a disagreement about what is valid rather than a broken fixture.",
        cases,
    };

    let json = match serde_json::to_string_pretty(&file) {
        Ok(json) => json,
        Err(err) => {
            eprintln!("kt-interop-emit: serializing: {err}");
            return ExitCode::FAILURE;
        }
    };
    if let Some(parent) = out.parent() {
        if let Err(err) = fs::create_dir_all(parent) {
            eprintln!("kt-interop-emit: creating {}: {err}", parent.display());
            return ExitCode::FAILURE;
        }
    }
    if let Err(err) = fs::write(&out, json + "\n") {
        eprintln!("kt-interop-emit: writing {}: {err}", out.display());
        return ExitCode::FAILURE;
    }

    let accepts = file.cases.iter().filter(|c| expect_of(c) == ACCEPT).count();
    println!(
        "wrote {} ({} cases: {} to accept, {} to reject)",
        out.display(),
        file.cases.len(),
        accepts,
        file.cases.len().saturating_sub(accepts)
    );
    ExitCode::SUCCESS
}

const fn expect_of(case: &Case) -> &'static str {
    match case {
        Case::LogTree { expect, .. }
        | Case::PrefixTree { expect, .. }
        | Case::PrefixMutation { expect, .. }
        | Case::CombinedSearch { expect, .. }
        | Case::OwnerUpdate { expect, .. }
        | Case::AuditorUpdate { expect, .. } => expect,
    }
}

fn build_cases() -> Result<Vec<Case>, String> {
    let mut cases = log_cases()?;
    cases.extend(prefix_cases()?);
    cases.extend(mutation_cases()?);
    cases.extend(search_cases()?);
    cases.extend(owner_update_cases()?);
    Ok(cases)
}

/// §6.3 proofs built by this implementation for the peer's own algorithm to consume.
///
/// Every other §6–§8 check runs one way: the peer serves a response and this side replays it. That
/// cannot catch over-acceptance — a proof this side would accept and the peer would not — and
/// over-acceptance is the direction that matters for a verifier. It is also the direction that
/// found the one real bug in this implementation's history: §12.1's balanced-subtree rule, which
/// self-consistent proofs passed and the peer rejected.
///
/// So this builds `CombinedTreeProof`s from a log constructed here, and the Go side feeds them to
/// katie's `GreatestVersionSearch` through its own `ReceivedProofHandle`. The peer's `Finish` is its
/// version of §12.3's exact-count rule, so a proof with an element too many or too few fails there
/// rather than being quietly tolerated.
///
/// No signing is involved: the tree-head signature is a separate step in a client, and the
/// algorithm layer checks a proof without it. That keeps this side a verifier rather than obliging
/// it to become a log.
fn search_cases() -> Result<Vec<Case>, String> {
    // A log where version `v` was added at entry `v`, timestamps a millisecond apart so that with a
    // week-long window only the root is distinguished and §6.3 starts there.
    const SIZE: u64 = 7;
    const GREATEST: u32 = 6;
    let timestamps: Vec<u64> = (0..SIZE)
        .map(|i| 1_700_000_000_000_u64.saturating_add(i))
        .collect();

    let key_for = |version: u32| {
        let mut bytes = [0_u8; HashValue::SIZE];
        bytes[0] = u8::try_from(version.wrapping_mul(37) % 256).unwrap_or(0);
        bytes[HashValue::SIZE - 1] = u8::try_from(version % 256).unwrap_or(0);
        HashValue::from_bytes(bytes)
    };
    let commitment_for = |version: u32| {
        HashValue::from_bytes([u8::try_from(version % 256).unwrap_or(0) ^ 0xa5; HashValue::SIZE])
    };
    let tree_at = |position: u64| -> Result<prefix::PrefixTree, String> {
        let mut tree = prefix::PrefixTree::new();
        for version in 0..=u32::try_from(position).unwrap_or(0) {
            tree.insert(PrefixLeaf {
                vrf_output: key_for(version),
                commitment: commitment_for(version),
            })
            .map_err(|err| format!("building the tree at {position}: {err}"))?;
        }
        Ok(tree)
    };

    // §6.3's walk: from the rightmost distinguished entry along the frontier, one ladder per entry,
    // each indexed on the greatest version present *there* — which is what makes the results a
    // prefix of the verifier's ladder rather than a match for it.
    let frontier = ibst::frontier(SIZE).map_err(|err| format!("frontier: {err}"))?;
    let start = ibst::root(SIZE).map_err(|err| format!("root: {err}"))?;
    let mut proofs = Vec::new();
    let mut roots = Vec::new();
    let mut left_inclusion: Vec<u32> = Vec::new();
    let mut current = start;
    loop {
        let local = u32::try_from(current).unwrap_or(0);
        let versions = ladder::search_binary_ladder(GREATEST, local, &left_inclusion, &[])
            .map_err(|err| format!("ladder at {current}: {err}"))?;
        let tree = tree_at(current)?;
        let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
        let proof = tree
            .prove(SUITE, &searches)
            .map_err(|err| format!("proving at {current}: {err}"))?;
        for (version, result) in versions.iter().zip(proof.results.iter()) {
            if result.is_inclusion() && !left_inclusion.contains(version) {
                left_inclusion.push(*version);
            }
        }
        proofs.push(proof);
        roots.push((current, tree.root(SUITE)));
        if current == SIZE - 1 {
            break;
        }
        current = ibst::right(current, SIZE).map_err(|err| format!("right of {current}: {err}"))?;
    }

    let stamp_at = |position: u64| -> Result<u64, String> {
        usize::try_from(position)
            .ok()
            .and_then(|index| timestamps.get(index))
            .copied()
            .ok_or_else(|| format!("no timestamp for entry {position}"))
    };

    // The log tree, so the proof carries a real inclusion proof for the leaves it names.
    let mut leaves = Vec::new();
    for position in 0..SIZE {
        let entry = LogEntry {
            timestamp: stamp_at(position)?,
            prefix_tree: tree_at(position)?.root(SUITE),
        };
        leaves
            .push(log::leaf_value(SUITE, &entry).map_err(|err| format!("leaf {position}: {err}"))?);
    }
    let mut inspected: Vec<u64> = frontier.clone();
    inspected.sort_unstable();
    let inclusion =
        log::prove(SUITE, &leaves, &inspected, None).map_err(|err| format!("log proof: {err}"))?;

    let combined = CombinedTreeProof {
        // §12.3.1: a first-time user gets the frontier's timestamps.
        timestamps: frontier
            .iter()
            .map(|position| stamp_at(*position))
            .collect::<Result<Vec<u64>, String>>()?,
        prefix_proofs: proofs,
        // Every frontier entry gets a proof here, so nothing is owed a root.
        prefix_roots: Vec::new(),
        inclusion,
    };

    let mut versions: Vec<VersionKey> = Vec::new();
    for version in 0..=GREATEST.saturating_add(1) {
        versions.push(VersionKey {
            version,
            vrf_output: hex::encode(key_for(version).as_bytes()),
            commitment: (version <= GREATEST)
                .then(|| hex::encode(commitment_for(version).as_bytes())),
        });
    }

    let encoded = |proof: &CombinedTreeProof| -> Result<String, String> {
        codec::encode(proof)
            .map(hex::encode)
            .map_err(|err| format!("encoding: {err}"))
    };

    let mut cases = vec![Case::CombinedSearch {
        name: "combined-greatest-version-search".to_owned(),
        expect: ACCEPT,
        operation: "greatest-version",
        map: Vec::new(),
        size: SIZE,
        greatest: GREATEST,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&combined)?,
    }];

    // And the negatives, which are the point of the exercise: each is a proof this side builds
    // deliberately wrong, and the peer must refuse it. A verifier that accepts these accepts more
    // than the protocol allows, which no amount of recomputing values would reveal.
    let mut extra_timestamp = combined.clone();
    extra_timestamp.timestamps.push(1_700_000_000_099);
    cases.push(Case::CombinedSearch {
        name: "combined-search-extra-timestamp".to_owned(),
        expect: REJECT,
        operation: "greatest-version",
        map: Vec::new(),
        size: SIZE,
        greatest: GREATEST,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&extra_timestamp)?,
    });

    let mut missing_proof = combined.clone();
    missing_proof.prefix_proofs.pop();
    cases.push(Case::CombinedSearch {
        name: "combined-search-missing-prefix-proof".to_owned(),
        expect: REJECT,
        operation: "greatest-version",
        map: Vec::new(),
        size: SIZE,
        greatest: GREATEST,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&missing_proof)?,
    });

    let mut reordered = combined.clone();
    reordered.prefix_proofs.reverse();
    cases.push(Case::CombinedSearch {
        name: "combined-search-proofs-out-of-order".to_owned(),
        expect: REJECT,
        operation: "greatest-version",
        map: Vec::new(),
        size: SIZE,
        greatest: GREATEST,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&reordered)?,
    });

    let mut backwards = combined.clone();
    backwards.timestamps.reverse();
    cases.push(Case::CombinedSearch {
        name: "combined-search-timestamps-backwards".to_owned(),
        expect: REJECT,
        operation: "greatest-version",
        map: Vec::new(),
        size: SIZE,
        greatest: GREATEST,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&backwards)?,
    });

    // §7.2 over the same log: a binary search from the root rather than a walk along the frontier,
    // so the proof it needs is a different shape and the peer's own FixedVersionSearch is a
    // different reader of it.
    let target = 2_u32;
    let mut fixed_proofs = Vec::new();
    let mut fixed_timestamps: Vec<u64> = Vec::new();
    let mut seen: Vec<u64> = Vec::new();
    let record =
        |position: u64, timestamps: &mut Vec<u64>, seen: &mut Vec<u64>| -> Result<(), String> {
            if !seen.contains(&position) {
                timestamps.push(stamp_at(position)?);
                seen.push(position);
            }
            Ok(())
        };
    // §12.3.1's view update comes first for a first-time user: the frontier's timestamps, in
    // frontier order. Only then does §7.2 start asking — and its first question, §7.1's rightmost
    // timestamp, is already answered, which is why nothing extra appears for it here.
    for position in &frontier {
        record(*position, &mut fixed_timestamps, &mut seen)?;
    }
    let mut established: Vec<(u64, Vec<u32>, Vec<u32>)> = Vec::new();
    let mut current = ibst::root(SIZE).map_err(|err| format!("root: {err}"))?;
    loop {
        record(current, &mut fixed_timestamps, &mut seen)?;
        let local = u32::try_from(current).unwrap_or(0);
        let (mut left_inclusion, mut right_non_inclusion) = (Vec::new(), Vec::new());
        for (at, included, absent) in &established {
            if *at < current {
                left_inclusion.extend(included.iter().copied());
            }
            if *at > current {
                right_non_inclusion.extend(absent.iter().copied());
            }
        }
        left_inclusion.sort_unstable();
        left_inclusion.dedup();
        right_non_inclusion.sort_unstable();
        right_non_inclusion.dedup();
        let versions =
            ladder::search_binary_ladder(target, local, &left_inclusion, &right_non_inclusion)
                .map_err(|err| format!("ladder at {current}: {err}"))?;
        let tree = tree_at(current)?;
        let searches: Vec<HashValue> = versions.iter().map(|v| key_for(*v)).collect();
        let proof = tree
            .prove(SUITE, &searches)
            .map_err(|err| format!("proving at {current}: {err}"))?;
        let (mut included, mut absent) = (Vec::new(), Vec::new());
        for (version, result) in versions.iter().zip(proof.results.iter()) {
            if result.is_inclusion() {
                included.push(*version);
            } else {
                absent.push(*version);
            }
        }
        established.push((current, included, absent));
        fixed_proofs.push(proof);
        match local.cmp(&target) {
            core::cmp::Ordering::Less => match ibst::right(current, SIZE) {
                Ok(child) => current = child,
                Err(_) => break,
            },
            core::cmp::Ordering::Greater => match ibst::left(current) {
                Ok(child) => current = child,
                Err(_) => break,
            },
            core::cmp::Ordering::Equal => break,
        }
    }
    // Everything with a timestamp but no proof is owed a prefix root, left to right.
    let mut owed: Vec<u64> = seen
        .iter()
        .copied()
        .filter(|position| !established.iter().any(|(at, _, _)| at == position))
        .collect();
    owed.sort_unstable();
    let mut fixed_roots = Vec::new();
    for position in &owed {
        fixed_roots.push(tree_at(*position)?.root(SUITE));
    }
    let mut fixed_inspected: Vec<u64> = seen.clone();
    fixed_inspected.sort_unstable();
    let fixed = CombinedTreeProof {
        timestamps: fixed_timestamps,
        prefix_proofs: fixed_proofs,
        prefix_roots: fixed_roots,
        inclusion: log::prove(SUITE, &leaves, &fixed_inspected, None)
            .map_err(|err| format!("log proof: {err}"))?,
    };
    cases.push(Case::CombinedSearch {
        name: "combined-fixed-version-search".to_owned(),
        expect: ACCEPT,
        operation: "fixed-version",
        map: Vec::new(),
        size: SIZE,
        greatest: target,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&fixed)?,
    });

    let mut fixed_short = fixed.clone();
    fixed_short.timestamps.pop();
    cases.push(Case::CombinedSearch {
        name: "combined-fixed-version-missing-timestamp".to_owned(),
        expect: REJECT,
        operation: "fixed-version",
        map: Vec::new(),
        size: SIZE,
        greatest: target,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&fixed_short)?,
    });

    // §8.2 over the same log, for a map entry that has an ancestor to its right and is not itself
    // distinguished — the only shape where contact monitoring inspects anything.
    let monitored_position = 2_u64;
    let monitored_version = 2_u32;
    let mut monitor_timestamps: Vec<u64> = Vec::new();
    let mut monitor_seen: Vec<u64> = Vec::new();
    for position in &frontier {
        record(*position, &mut monitor_timestamps, &mut monitor_seen)?;
    }
    // The descent §12.3.4 provides: the path from the root to the map entry's parent, which is what
    // tells the verifier which entries are distinguished.
    record(SIZE - 1, &mut monitor_timestamps, &mut monitor_seen)?;
    let mut chain =
        ibst::direct_path(monitored_position, SIZE).map_err(|err| format!("direct path: {err}"))?;
    chain.reverse();
    for position in &chain {
        record(*position, &mut monitor_timestamps, &mut monitor_seen)?;
    }
    // Step 2's list: the direct path to the right, cut after the first distinguished entry — which
    // with a week-long window is the root.
    let inspect: Vec<u64> = chain
        .iter()
        .copied()
        .filter(|position| *position > monitored_position)
        .collect();
    let mut monitor_proofs = Vec::new();
    let mut proved: Vec<u64> = Vec::new();
    for position in inspect.iter().take(1) {
        let ladder = ladder::monitoring_binary_ladder(monitored_version, &[]);
        let searches: Vec<HashValue> = ladder.iter().map(|v| key_for(*v)).collect();
        monitor_proofs.push(
            tree_at(*position)?
                .prove(SUITE, &searches)
                .map_err(|err| format!("proving at {position}: {err}"))?,
        );
        proved.push(*position);
    }
    let mut monitor_owed: Vec<u64> = monitor_seen
        .iter()
        .copied()
        .filter(|position| !proved.contains(position))
        .collect();
    monitor_owed.sort_unstable();
    let mut monitor_roots = Vec::new();
    for position in &monitor_owed {
        monitor_roots.push(tree_at(*position)?.root(SUITE));
    }
    let mut monitor_inspected: Vec<u64> = monitor_seen.clone();
    monitor_inspected.sort_unstable();
    let monitor = CombinedTreeProof {
        timestamps: monitor_timestamps,
        prefix_proofs: monitor_proofs,
        prefix_roots: monitor_roots,
        inclusion: log::prove(SUITE, &leaves, &monitor_inspected, None)
            .map_err(|err| format!("log proof: {err}"))?,
    };
    let map = vec![MapEntryOut {
        position: monitored_position,
        version: monitored_version,
    }];
    cases.push(Case::CombinedSearch {
        name: "combined-contact-monitor".to_owned(),
        expect: ACCEPT,
        operation: "contact-monitor",
        map: map.clone(),
        size: SIZE,
        greatest: monitored_version,
        timestamps: timestamps.clone(),
        versions: versions.clone(),
        proof: encoded(&monitor)?,
    });

    // A monitoring ladder with a lookup that shows non-inclusion is the failure monitoring exists
    // to catch: a version the user has already been shown is no longer there.
    let mut rolled_back = monitor.clone();
    let ladder = ladder::monitoring_binary_ladder(monitored_version, &[]);
    let searches: Vec<HashValue> = ladder.iter().map(|v| key_for(*v)).collect();
    rolled_back.prefix_proofs = vec![
        tree_at(0)?
            .prove(SUITE, &searches)
            .map_err(|err| format!("proving the rollback: {err}"))?,
    ];
    cases.push(Case::CombinedSearch {
        name: "combined-contact-monitor-rolled-back".to_owned(),
        expect: REJECT,
        operation: "contact-monitor",
        map,
        size: SIZE,
        greatest: monitored_version,
        timestamps,
        versions,
        proof: encoded(&rolled_back)?,
    });

    Ok(cases)
}

/// §15.2 updates for the peer to replay, plus the encodings for its decoder.
///
/// Only the shapes the two implementations agree on are here. The peer does not treat
/// §11.9's all-zero copath element as an empty subtree, and it refuses a replacement
/// outright — those two divergences are pinned in the other direction, by
/// `interop/vectors/prefix-mutation.json`, where the peer's own tree supplies the root it
/// should have reached. Sending them here as expected failures would restate that finding
/// while making this file's `reject` cases mean two different things.
fn mutation_cases() -> Result<Vec<Case>, String> {
    let leaf = |first: u8, tag: u8, commitment: u8| PrefixLeaf {
        vrf_output: {
            let mut key = [0_u8; HashValue::SIZE];
            key[0] = first;
            key[HashValue::SIZE - 1] = tag;
            HashValue::from_bytes(key)
        },
        commitment: HashValue::from_bytes([commitment; HashValue::SIZE]),
    };
    let hex_leaves = |leaves: &[PrefixLeaf]| {
        leaves
            .iter()
            .map(|l| Leaf {
                vrf_output: hex::encode(l.vrf_output.as_bytes()),
                commitment: hex::encode(l.commitment.as_bytes()),
            })
            .collect::<Vec<_>>()
    };

    let a = leaf(0x00, 1, 0xa1);
    let b = leaf(0x40, 2, 0xb2);
    let c = leaf(0x80, 3, 0xc3);
    let d = leaf(0xc0, 4, 0xd4);

    /// One update: the tree it applies to, and what it changes.
    struct Spec {
        name: &'static str,
        existing: Vec<PrefixLeaf>,
        added: Vec<PrefixLeaf>,
        removed: Vec<PrefixLeaf>,
    }
    let spec = |name, existing, added, removed| Spec {
        name,
        existing,
        added,
        removed,
    };

    let specs = [
        spec("add-one-leaf", vec![a, c], vec![b], vec![]),
        spec("add-two-leaves", vec![a], vec![b, c], vec![]),
        spec("remove-the-only-leaf", vec![a], vec![], vec![a]),
        // A removal whose emptied slot an addition refills, so no §3.3 collapse is in
        // question and both implementations reach the root the tree actually takes.
        spec(
            "remove-refilled-by-an-add",
            vec![a, b, c, d],
            vec![leaf(0x20, 5, 0xe5)],
            vec![a],
        ),
    ];

    let mut cases = Vec::new();
    for Spec {
        name,
        existing,
        added,
        removed,
    } in specs
    {
        let mut tree = prefix::PrefixTree::new();
        tree.extend(existing.iter().copied())
            .map_err(|err| format!("{name}: building the tree: {err}"))?;

        let keys: Vec<HashValue> = added
            .iter()
            .chain(removed.iter())
            .map(|l| l.vrf_output)
            .collect();
        let proof = tree
            .prove(SUITE, &keys)
            .map_err(|err| format!("{name}: proving: {err}"))?;
        let mutation = prefix::evaluate_before_after(SUITE, &added, &removed, &proof)
            .map_err(|err| format!("{name}: evaluating: {err}"))?;
        if !mutation.determined() {
            return Err(format!(
                "{name}: the root is not determined by the proof, so the peer's agreement \
                 would not mean anything"
            ));
        }
        let encoded =
            codec::encode(&proof).map_err(|err| format!("{name}: encoding the proof: {err}"))?;

        cases.push(Case::PrefixMutation {
            name: format!("mutation-{name}"),
            expect: ACCEPT,
            added: hex_leaves(&added),
            removed: hex_leaves(&removed),
            proof: hex::encode(&encoded),
            before: hex::encode(mutation.before.as_bytes()),
            after: hex::encode(mutation.after.as_bytes()),
        });

        let update = AuditorUpdate {
            timestamp: 1_700_000_000_000,
            added: added.clone(),
            removed: removed.clone(),
            proof,
        };
        let bytes =
            codec::encode(&update).map_err(|err| format!("{name}: encoding the update: {err}"))?;
        cases.push(Case::AuditorUpdate {
            name: format!("auditor-update-{name}"),
            expect: ACCEPT,
            encoding: hex::encode(&bytes),
        });
    }

    Ok(cases)
}

/// Deterministic log entries, matching the shape the Go generator uses so the two
/// directions talk about comparable trees.
fn log_leaves(size: u64) -> Result<Vec<HashValue>, String> {
    let mut out = Vec::new();
    for i in 0..size {
        let mut prefix_tree = [0_u8; HashValue::SIZE];
        for (j, byte) in prefix_tree.iter_mut().enumerate() {
            *byte = u8::try_from(i % 256).unwrap_or(0) ^ u8::try_from(j % 256).unwrap_or(0);
        }
        let entry = LogEntry {
            timestamp: 1_700_000_000_000_u64.saturating_add(i.saturating_mul(1_000)),
            prefix_tree: HashValue::from_bytes(prefix_tree),
        };
        out.push(log::leaf_value(SUITE, &entry).map_err(|err| format!("leaf {i}: {err}"))?);
    }
    Ok(out)
}

fn hex_all(values: &[HashValue]) -> Vec<String> {
    values
        .iter()
        .map(|value| hex::encode(value.as_bytes()))
        .collect()
}

fn log_cases() -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();

    for size in [1_u64, 2, 3, 4, 5, 7, 8, 11, 16, 17, 33, 50] {
        let leaves = log_leaves(size)?;
        let root = log::root(SUITE, &leaves).map_err(|err| format!("size {size}: {err}"))?;

        // Inclusion proofs for the ends and the middle, plus one batch.
        let mut requests: Vec<(Vec<u64>, Option<u64>)> = Vec::new();
        for index in [0, size / 2, size.saturating_sub(1)] {
            requests.push((vec![index], None));
        }
        if size >= 4 {
            let mut batch = vec![0, size / 2, size.saturating_sub(1)];
            batch.sort_unstable();
            batch.dedup();
            requests.push((batch, None));
        }
        // Consistency proofs, and the §12.1 overlap: a leaf inside the retained
        // subtree, which makes a retained head recomputable.
        for old in [1, size / 2, size.saturating_sub(1)] {
            if old == 0 || old > size {
                continue;
            }
            requests.push((Vec::new(), Some(old)));
            if old >= 2 {
                requests.push((vec![old / 2], Some(old)));
            }
        }

        for (leaves_asked, retained_size) in requests {
            let retained = match retained_size {
                None => None,
                Some(old) => Some(
                    log::Retained::from_leaves(SUITE, old, &leaves)
                        .map_err(|err| format!("size {size}, retained {old}: {err}"))?,
                ),
            };
            let proof = log::prove(SUITE, &leaves, &leaves_asked, retained.as_ref())
                .map_err(|err| format!("size {size}: {err}"))?;

            let claimed: Vec<log::Leaf> = leaves_asked
                .iter()
                .map(|index| {
                    let value = usize::try_from(*index)
                        .ok()
                        .and_then(|i| leaves.get(i))
                        .copied()
                        .unwrap_or(HashValue::ZERO);
                    (*index, value)
                })
                .collect();

            // Our own verifier must accept what we just built, or there is no
            // point asking the peer.
            let ours = log::evaluate(SUITE, size, &claimed, retained.as_ref(), &proof)
                .map_err(|err| format!("size {size}: our verifier rejected our proof: {err}"))?;
            if ours != root {
                return Err(format!(
                    "size {size}: our proof does not reach our own root"
                ));
            }

            let label = format!(
                "log-size-{size}-leaves-{}-retained-{}",
                if leaves_asked.is_empty() {
                    "none".to_owned()
                } else {
                    leaves_asked
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join("-")
                },
                retained_size.map_or_else(|| "none".to_owned(), |s| s.to_string())
            );

            cases.push(Case::LogTree {
                name: label.clone(),
                expect: ACCEPT,
                size,
                entries: leaves_asked.clone(),
                values: hex_all(&claimed.iter().map(|(_, v)| *v).collect::<Vec<_>>()),
                retained_size,
                retained: retained
                    .as_ref()
                    .map(|r| hex_all(&r.full_subtrees))
                    .unwrap_or_default(),
                elements: hex_all(&proof.elements),
                root: hex::encode(root.as_bytes()),
            });

            // One tampered variant per honest case shape, on the first element.
            if let Some(first) = proof.elements.first() {
                let mut broken = proof.clone();
                let mut bytes = *first.as_bytes();
                bytes[0] ^= 0x01;
                if let Some(slot) = broken.elements.first_mut() {
                    *slot = HashValue::from_bytes(bytes);
                }
                // Our verifier must not reach the honest root with this.
                let ours = log::evaluate(SUITE, size, &claimed, retained.as_ref(), &broken);
                if ours == Ok(root) {
                    return Err(format!("{label}: tampering changed nothing"));
                }
                cases.push(Case::LogTree {
                    name: format!("{label}-tampered-element"),
                    expect: REJECT,
                    size,
                    entries: leaves_asked.clone(),
                    values: hex_all(&claimed.iter().map(|(_, v)| *v).collect::<Vec<_>>()),
                    retained_size,
                    retained: retained
                        .as_ref()
                        .map(|r| hex_all(&r.full_subtrees))
                        .unwrap_or_default(),
                    elements: hex_all(&broken.elements),
                    root: hex::encode(root.as_bytes()),
                });
            }
        }
    }

    Ok(cases)
}

fn prefix_cases() -> Result<Vec<Case>, String> {
    let mut cases = Vec::new();

    for (name, count) in [("small", 5_u32), ("medium", 40), ("wide", 200)] {
        let mut tree = prefix::PrefixTree::new();
        let mut leaves = Vec::new();
        for i in 0..count {
            let mut key = [0_u8; HashValue::SIZE];
            key[0] = u8::try_from(i % 256).unwrap_or(0);
            key[1] = u8::try_from((i / 256) % 256).unwrap_or(0);
            key[2] = u8::try_from(i % 11).unwrap_or(0);
            let leaf = PrefixLeaf {
                vrf_output: HashValue::from_bytes(key),
                commitment: HashValue::from_bytes(
                    [u8::try_from(i % 251).unwrap_or(0); HashValue::SIZE],
                ),
            };
            tree.insert(leaf)
                .map_err(|err| format!("{name}: inserting {i}: {err}"))?;
            leaves.push(leaf);
        }
        let root = tree.root(SUITE);

        // A batch mixing inclusion with both flavours of non-inclusion.
        let mut searches: Vec<HashValue> = Vec::new();
        let mut expected: Vec<Search> = Vec::new();
        for leaf in leaves.iter().take(3) {
            searches.push(leaf.vrf_output);
            expected.push(Search {
                vrf_output: hex::encode(leaf.vrf_output.as_bytes()),
                commitment: Some(hex::encode(leaf.commitment.as_bytes())),
            });
        }
        for tag in [0xfe_u8, 0xfd] {
            let mut key = [0_u8; HashValue::SIZE];
            key[0] = tag;
            key[31] = tag;
            let absent = HashValue::from_bytes(key);
            searches.push(absent);
            expected.push(Search {
                vrf_output: hex::encode(absent.as_bytes()),
                commitment: None,
            });
        }

        let proof = tree
            .prove(SUITE, &searches)
            .map_err(|err| format!("{name}: proving: {err}"))?;
        let entries: Vec<prefix::SearchEntry> = searches
            .iter()
            .zip(expected.iter())
            .map(|(key, search)| match &search.commitment {
                Some(_) => {
                    let commitment = leaves
                        .iter()
                        .find(|leaf| leaf.vrf_output == *key)
                        .map_or(HashValue::ZERO, |leaf| leaf.commitment);
                    prefix::SearchEntry::included(*key, commitment)
                }
                None => prefix::SearchEntry::absent(*key),
            })
            .collect();
        prefix::verify(SUITE, &entries, &proof, root)
            .map_err(|err| format!("{name}: our verifier rejected our proof: {err}"))?;

        let wire = codec::encode(&proof).map_err(|err| format!("{name}: encoding: {err}"))?;
        cases.push(Case::PrefixTree {
            name: format!("prefix-{name}-mixed"),
            expect: ACCEPT,
            searches: expected,
            proof: hex::encode(&wire),
            root: hex::encode(root.as_bytes()),
        });

        // Tampered: one copath element flipped. The peer must not reach our root.
        if !proof.elements.is_empty() {
            let mut broken = proof.clone();
            if let Some(first) = broken.elements.first_mut() {
                let mut bytes = *first.as_bytes();
                bytes[0] ^= 0x01;
                *first = HashValue::from_bytes(bytes);
            }
            if prefix::verify(SUITE, &entries, &broken, root).is_ok() {
                return Err(format!("{name}: tampering changed nothing"));
            }
            let wire = codec::encode(&broken).map_err(|err| format!("{name}: encoding: {err}"))?;
            cases.push(Case::PrefixTree {
                name: format!("prefix-{name}-tampered-element"),
                expect: REJECT,
                searches: searches
                    .iter()
                    .zip(entries.iter())
                    .map(|(key, entry)| Search {
                        vrf_output: hex::encode(key.as_bytes()),
                        commitment: entry.commitment.map(|value| hex::encode(value.as_bytes())),
                    })
                    .collect(),
                proof: hex::encode(&wire),
                root: hex::encode(root.as_bytes()),
            });
        }

        // Tampered: a search claimed to be included that is not. A verifier that
        // accepts this is the over-acceptance failure this direction exists for.
        let mut key = [0_u8; HashValue::SIZE];
        key[0] = 0xfc;
        let absent = HashValue::from_bytes(key);
        let absent_proof = tree
            .prove(SUITE, &[absent])
            .map_err(|err| format!("{name}: proving: {err}"))?;
        let mut forged = absent_proof.clone();
        if let Some(slot) = forged.results.first_mut() {
            *slot = kt_wire::proofs::PrefixSearchResult::Inclusion {
                depth: slot.depth(),
            };
        }
        let claimed = [prefix::SearchEntry::included(absent, HashValue::ZERO)];
        if prefix::verify(SUITE, &claimed, &forged, root).is_ok() {
            return Err(format!(
                "{name}: forged inclusion was accepted by our own verifier"
            ));
        }
        let wire = codec::encode(&forged).map_err(|err| format!("{name}: encoding: {err}"))?;
        cases.push(Case::PrefixTree {
            name: format!("prefix-{name}-forged-inclusion"),
            expect: REJECT,
            searches: vec![Search {
                vrf_output: hex::encode(absent.as_bytes()),
                commitment: Some(hex::encode(HashValue::ZERO.as_bytes())),
            }],
            proof: hex::encode(&wire),
            root: hex::encode(root.as_bytes()),
        });
    }

    Ok(cases)
}

/// §9.1 proofs built by this implementation for the peer's own `Monitor.Update` to consume.
///
/// This is the only direction §9.1 can be checked in. The forward direction needs katie to *serve*
/// an update, and it cannot: `tree.Update` fails for every request because its own code path leaves
/// the owner state uninitialized before checking it (`KT-04`). The consumer half is sound, and it
/// takes the owner state from the caller — so a proof this side builds can be fed to the peer's
/// reading of the same algorithm, which is the direction that catches over-acceptance anyway.
///
/// The log model is the same as the search cases': version `v` was added at entry `v`, up to a cap.
/// The cap is what makes an honest step 2.2 possible — a label that gains a version in every entry
/// has nothing for the previous tree's frontier to confirm, since the owner's previous greatest
/// version was never the greatest anywhere except where it was created.
fn owner_update_cases() -> Result<Vec<Case>, String> {
    const SIZE: u64 = 7;
    let timestamps: Vec<u64> = (0..SIZE)
        .map(|i| 1_700_000_000_000_u64.saturating_add(i))
        .collect();
    let window = 604_800_000_u64;

    let key_for = |version: u32| {
        let mut bytes = [0_u8; HashValue::SIZE];
        bytes[0] = u8::try_from(version.wrapping_mul(37) % 256).unwrap_or(0);
        bytes[HashValue::SIZE - 1] = u8::try_from(version % 256).unwrap_or(0);
        HashValue::from_bytes(bytes)
    };
    let commitment_for = |version: u32| {
        HashValue::from_bytes([u8::try_from(version % 256).unwrap_or(0) ^ 0xa5; HashValue::SIZE])
    };
    // The prefix tree at `position` for a label that gained version `v` in entry `v` until it
    // stopped at `cap`, then gained one more in the last entry.
    let tree_at = |position: u64, cap: u64| -> Result<prefix::PrefixTree, String> {
        let greatest = if position == SIZE - 1 {
            cap.saturating_add(1)
        } else {
            position.min(cap)
        };
        let mut tree = prefix::PrefixTree::new();
        for version in 0..=u32::try_from(greatest).unwrap_or(0) {
            tree.insert(PrefixLeaf {
                vrf_output: key_for(version),
                commitment: commitment_for(version),
            })
            .map_err(|err| format!("building the tree at {position}: {err}"))?;
        }
        Ok(tree)
    };
    let greatest_at = |position: u64, cap: u64| -> u32 {
        let greatest = if position == SIZE - 1 {
            cap.saturating_add(1)
        } else {
            position.min(cap)
        };
        u32::try_from(greatest).unwrap_or(0)
    };
    let stamp_at = |position: u64| -> Result<u64, String> {
        usize::try_from(position)
            .ok()
            .and_then(|index| timestamps.get(index))
            .copied()
            .ok_or_else(|| format!("no timestamp for entry {position}"))
    };

    // §6.1's descent, over the timestamps directly: which entries a verifier reads on the way to
    // `target`, and the first one it finds not distinguished.
    let descend = |target: u64| -> Result<(Vec<u64>, Option<u64>), String> {
        let last = SIZE - 1;
        let mut reads = vec![last];
        let mut current = ibst::root(SIZE).map_err(|err| format!("root: {err}"))?;
        let mut left = (0_u64, 0_u64);
        let mut right = (last, stamp_at(last)?);
        loop {
            let gap = right.1.saturating_sub(left.1);
            if gap < window {
                return Ok((reads, Some(current)));
            }
            if current == target {
                return Ok((reads, None));
            }
            reads.push(current);
            let timestamp = stamp_at(current)?;
            if current < target {
                let next = ibst::right(current, SIZE)
                    .map_err(|err| format!("right of {current}: {err}"))?;
                left = (current, timestamp);
                current = next;
            } else {
                let next =
                    ibst::left(current).map_err(|err| format!("left of {current}: {err}"))?;
                right = (current, timestamp);
                current = next;
            }
        }
    };

    // One honest §9.1 proof, built by walking the algorithm's own steps.
    let build = |cap: u64,
                 position: u64,
                 owner_starting: u64,
                 owner_greatest: u32,
                 owner_upcoming: &[u64]|
     -> Result<CombinedTreeProof, String> {
        let mut stamps: Vec<u64> = Vec::new();
        let mut seen: Vec<u64> = Vec::new();
        let mut proofs = Vec::new();
        let mut proved: Vec<u64> = Vec::new();
        let mut established: Vec<(u64, Vec<u32>, Vec<u32>)> = Vec::new();
        let sets_for =
            |established: &[(u64, Vec<u32>, Vec<u32>)], position: u64| -> (Vec<u32>, Vec<u32>) {
                let (mut left, mut right) = (Vec::new(), Vec::new());
                for (at, included, absent) in established {
                    if *at < position {
                        for version in included {
                            if !left.contains(version) {
                                left.push(*version);
                            }
                        }
                    }
                    if *at > position {
                        for version in absent {
                            if !right.contains(version) {
                                right.push(*version);
                            }
                        }
                    }
                }
                (left, right)
            };
        let record =
            |position: u64, stamps: &mut Vec<u64>, seen: &mut Vec<u64>| -> Result<(), String> {
                if !seen.contains(&position) {
                    stamps.push(stamp_at(position)?);
                    seen.push(position);
                }
                Ok(())
            };

        // §12.3.1's view update: a first-time owner gets the whole frontier.
        for entry in ibst::frontier(SIZE).map_err(|err| format!("frontier: {err}"))? {
            record(entry, &mut stamps, &mut seen)?;
        }

        let last_update = owner_upcoming.last().copied().unwrap_or(owner_starting);
        let rightmost = position.saturating_sub(1);

        // Phase one: steps 1 and 2 over the previous tree.
        let (reads, first) = descend(rightmost)?;
        for entry in reads {
            record(entry, &mut stamps, &mut seen)?;
        }
        if let Some(first) = first {
            let mut current = first;
            while current > rightmost {
                current = ibst::left(current).map_err(|err| format!("left of {current}: {err}"))?;
            }
            // Step 2.2's omissions, seeded as if the skipped entries had been inspected.
            let ladder = ladder::search_binary_ladder(owner_greatest, owner_greatest, &[], &[])
                .map_err(|err| format!("seed ladder: {err}"))?;
            let assume = |established: &mut Vec<(u64, Vec<u32>, Vec<u32>)>,
                          at: u64,
                          bound: u32,
                          versions: &[u32]| {
                let (mut included, mut absent) = (Vec::new(), Vec::new());
                for version in versions {
                    if *version <= bound {
                        included.push(*version);
                    } else {
                        absent.push(*version);
                    }
                }
                established.push((at, included, absent));
            };
            let previous_root = ibst::root(position).map_err(|err| format!("root: {err}"))?;
            if current != previous_root {
                let parent = ibst::direct_path(current, position)
                    .map_err(|err| format!("direct path: {err}"))?
                    .first()
                    .copied()
                    .ok_or_else(|| format!("entry {current} has no parent"))?;
                assume(&mut established, parent, greatest_at(parent, cap), &ladder);
            }
            assume(&mut established, current, owner_greatest, &ladder);

            loop {
                if current > last_update {
                    let (left_inclusion, right_non_inclusion) = sets_for(&established, current);
                    let versions = ladder::search_binary_ladder(
                        owner_greatest,
                        greatest_at(current, cap),
                        &left_inclusion,
                        &right_non_inclusion,
                    )
                    .map_err(|err| format!("ladder at {current}: {err}"))?;
                    let searches: Vec<HashValue> =
                        versions.iter().map(|version| key_for(*version)).collect();
                    let proof = tree_at(current, cap)?
                        .prove(SUITE, &searches)
                        .map_err(|err| format!("proving at {current}: {err}"))?;
                    let (mut included, mut absent) = (Vec::new(), Vec::new());
                    for (version, result) in versions.iter().zip(proof.results.iter()) {
                        if result.is_inclusion() {
                            included.push(*version);
                        } else {
                            absent.push(*version);
                        }
                    }
                    established.push((current, included, absent));
                    record(current, &mut stamps, &mut seen)?;
                    proofs.push(proof);
                    proved.push(current);
                }
                if current == rightmost {
                    break;
                }
                current = ibst::right(current, position)
                    .map_err(|err| format!("right of {current}: {err}"))?;
            }
        }

        // Phase two: step 3 or step 4 at the entry holding the new versions.
        let (reads, first) = descend(position)?;
        for entry in reads {
            record(entry, &mut stamps, &mut seen)?;
        }
        let end_ver = greatest_at(position, cap);
        if first.is_some() {
            let (left_inclusion, right_non_inclusion) = sets_for(&established, position);
            let versions = ladder::search_binary_ladder(
                end_ver,
                greatest_at(position, cap),
                &left_inclusion,
                &right_non_inclusion,
            )
            .map_err(|err| format!("ladder at {position}: {err}"))?;
            let searches: Vec<HashValue> =
                versions.iter().map(|version| key_for(*version)).collect();
            let proof = tree_at(position, cap)?
                .prove(SUITE, &searches)
                .map_err(|err| format!("proving at {position}: {err}"))?;
            record(position, &mut stamps, &mut seen)?;
            proofs.push(proof);
            proved.push(position);
        }

        // The new versions a ladder for the new greatest version would not look up.
        let covered = ladder::search_binary_ladder(end_ver, end_ver, &[], &[])
            .map_err(|err| format!("covered ladder: {err}"))?;
        let additional: Vec<u32> = (owner_greatest.saturating_add(1)..=end_ver)
            .filter(|version| !covered.contains(version))
            .collect();
        if !additional.is_empty() {
            let searches: Vec<HashValue> =
                additional.iter().map(|version| key_for(*version)).collect();
            record(position, &mut stamps, &mut seen)?;
            proofs.push(
                tree_at(position, cap)?
                    .prove(SUITE, &searches)
                    .map_err(|err| format!("proving at {position}: {err}"))?,
            );
            proved.push(position);
        }

        // §12.3.2: a prefix root for every entry with a timestamp and no proof, ascending.
        let mut owed: Vec<u64> = seen
            .iter()
            .copied()
            .filter(|entry| !proved.contains(entry))
            .collect();
        owed.sort_unstable();
        let mut prefix_roots = Vec::new();
        for entry in &owed {
            prefix_roots.push(tree_at(*entry, cap)?.root(SUITE));
        }

        let mut leaves = Vec::new();
        for entry in 0..SIZE {
            let log_entry = LogEntry {
                timestamp: stamp_at(entry)?,
                prefix_tree: tree_at(entry, cap)?.root(SUITE),
            };
            leaves.push(
                log::leaf_value(SUITE, &log_entry).map_err(|err| format!("leaf {entry}: {err}"))?,
            );
        }
        let mut inspected = seen.clone();
        inspected.sort_unstable();
        let inclusion = log::prove(SUITE, &leaves, &inspected, None)
            .map_err(|err| format!("log proof: {err}"))?;

        Ok(CombinedTreeProof {
            timestamps: stamps,
            prefix_proofs: proofs,
            prefix_roots,
            inclusion,
        })
    };

    let encoded = |proof: &CombinedTreeProof| -> Result<String, String> {
        codec::encode(proof)
            .map(hex::encode)
            .map_err(|err| format!("encoding: {err}"))
    };
    let keys_through = |greatest: u32| -> Vec<VersionKey> {
        (0..=greatest.saturating_add(4))
            .map(|version| VersionKey {
                version,
                vrf_output: hex::encode(key_for(version).as_bytes()),
                commitment: (version <= greatest)
                    .then(|| hex::encode(commitment_for(version).as_bytes())),
            })
            .collect()
    };

    // The owner's last version went into the previous tree's rightmost entry, so step 2.1 skips it
    // and phase one reads nothing. This is the common case for an owner updating a label it updates
    // often.
    let skipped = build(5, 6, 3, 5, &[4, 5])?;
    let mut cases = vec![Case::OwnerUpdate {
        name: "owner-update-previous-frontier-skipped".to_owned(),
        expect: ACCEPT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 3,
            upcoming: vec![4, 5],
        },
        timestamps: timestamps.clone(),
        keys: keys_through(6),
        proof: encoded(&skipped)?,
    }];

    // The label stopped gaining versions at entry 3, so the previous tree's frontier has something
    // to confirm and step 2.2 sends a real ladder. This is the case that exercises the phase §9.1
    // exists for.
    let inspected = build(3, 6, 3, 3, &[])?;
    cases.push(Case::OwnerUpdate {
        name: "owner-update-previous-frontier-inspected".to_owned(),
        expect: ACCEPT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 3,
            upcoming: Vec::new(),
        },
        timestamps: timestamps.clone(),
        keys: keys_through(4),
        proof: encoded(&inspected)?,
    });

    // The negatives. Each is a proof this side builds deliberately wrong; the peer must refuse it.
    let mut extra = inspected.clone();
    extra.timestamps.push(1_700_000_000_099);
    cases.push(Case::OwnerUpdate {
        name: "owner-update-extra-timestamp".to_owned(),
        expect: REJECT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 3,
            upcoming: Vec::new(),
        },
        timestamps: timestamps.clone(),
        keys: keys_through(4),
        proof: encoded(&extra)?,
    });

    let mut short = inspected.clone();
    short.prefix_proofs.pop();
    cases.push(Case::OwnerUpdate {
        name: "owner-update-missing-prefix-proof".to_owned(),
        expect: REJECT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 3,
            upcoming: Vec::new(),
        },
        timestamps: timestamps.clone(),
        keys: keys_through(4),
        proof: encoded(&short)?,
    });

    let mut swapped = inspected.clone();
    swapped.prefix_proofs.reverse();
    cases.push(Case::OwnerUpdate {
        name: "owner-update-proofs-out-of-order".to_owned(),
        expect: REJECT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 3,
            upcoming: Vec::new(),
        },
        timestamps: timestamps.clone(),
        keys: keys_through(4),
        proof: encoded(&swapped)?,
    });

    // §13.5 step 1, checked on the peer: an honest proof presented with an owner state that has
    // already passed the claimed position. Nothing about the bytes is wrong, and the peer must
    // still refuse — a new version cannot appear to the left of one the owner already holds.
    cases.push(Case::OwnerUpdate {
        name: "owner-update-position-not-advancing".to_owned(),
        expect: REJECT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 3,
            upcoming: vec![4, 5, 6],
        },
        timestamps: timestamps.clone(),
        keys: keys_through(6),
        proof: encoded(&skipped)?,
    });

    // A label with exactly one version before the update, which makes every ladder in the proof as
    // short as it can be: the seeding ladder for version 0 is two rungs, and step 2.2's is one.
    // Short ladders are where an off-by-one in the omission bookkeeping shows up, because there is
    // no slack left in the sequence.
    let fresh = build(0, 6, 3, 0, &[])?;
    cases.push(Case::OwnerUpdate {
        name: "owner-update-shortest-possible-ladders".to_owned(),
        expect: ACCEPT,
        size: SIZE,
        position: 6,
        versions: 1,
        owner: OwnerOut {
            starting: 3,
            version_at_starting: 0,
            upcoming: Vec::new(),
        },
        timestamps: timestamps.clone(),
        keys: keys_through(1),
        proof: encoded(&fresh)?,
    });

    Ok(cases)
}
