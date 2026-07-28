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
use kt_tree::{log, prefix};
use kt_wire::codec;
use kt_wire::proofs::PrefixLeaf;
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
        Case::LogTree { expect, .. } | Case::PrefixTree { expect, .. } => expect,
    }
}

fn build_cases() -> Result<Vec<Case>, String> {
    let mut cases = log_cases()?;
    cases.extend(prefix_cases()?);
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
            let ours = log::verify(SUITE, size, &claimed, retained.as_ref(), &proof)
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
                let ours = log::verify(SUITE, size, &claimed, retained.as_ref(), &broken);
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
