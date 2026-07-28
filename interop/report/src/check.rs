//! Running the committed vectors against this implementation.
//!
//! One code path produces both the `#[test]` verdicts and the published page, so
//! the page cannot claim something the test suite does not enforce. Nothing here
//! panics or asserts: a disagreement becomes a [`Check`] with `Verdict::Fail`,
//! carrying both values, and it is the caller's job to fail the build over it.

use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use kt_crypto::commitment::{self, Commitment};
use kt_crypto::suite::CipherSuite;
use kt_crypto::vrf;
use kt_tree::{ibst, ladder, log, prefix};
use kt_wire::codec::Decoder;
use kt_wire::proofs::{InclusionProof, PrefixLeaf, PrefixProof};
use kt_wire::structs::{
    CommitmentValue, DeploymentMode, HashValue, LogEntry, UpdateSuffix, UpdateValue, VrfInput,
};

use crate::report::{Case, Check, Generator, Suite};
use crate::vectors::{
    CommitmentExpect, CommitmentInput, IbstExpect, IbstInput, LadderExpect, LadderInput,
    LogTreeExpect, LogTreeInput, PrefixTreeExpect, PrefixTreeInput, VectorFile, VrfCaseInput,
    VrfExpect,
};

/// The vector files this crate knows how to check, in dependency order.
pub const FILES: [&str; 6] = [
    "commitment.json",
    "ibst.json",
    "binary-ladder.json",
    "vrf.json",
    "log-tree.json",
    "prefix-tree.json",
];

/// Something wrong with a vector file itself, as opposed to a disagreement.
///
/// These are all "the file is not the file we contracted for" — unreadable,
/// unparseable, a hex string that is not hex, a cipher suite outside the
/// registry. None of them are interop results, so they are errors rather than
/// failing checks.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// The file could not be read.
    Read {
        /// The path attempted.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file did not match the format contract in `interop/README.md`.
    Parse {
        /// The path attempted.
        path: PathBuf,
        /// The underlying error.
        source: serde_json::Error,
    },
    /// A field that must be lowercase hex was not.
    Hex {
        /// Which file.
        file: String,
        /// Which case.
        case: String,
        /// Which field.
        field: String,
    },
    /// The file named a cipher suite that is not in §17.1.
    CipherSuite {
        /// Which file.
        file: String,
        /// The offending value.
        value: u16,
    },
    /// A computation the vector implies could not be carried out at all — a tree
    /// that will not build from the entries it lists, for instance. Distinct from
    /// a disagreement: the file is not describing something this code can attempt.
    Computation {
        /// Which file.
        file: String,
        /// Which case.
        case: String,
        /// What went wrong.
        detail: String,
    },
    /// A `commitment.json` case was missing a field its kind requires.
    MissingField {
        /// Which file.
        file: String,
        /// Which case.
        case: String,
        /// Which field.
        field: String,
    },
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Read { path, source } => write!(f, "reading {}: {source}", path.display()),
            Self::Parse { path, source } => write!(f, "parsing {}: {source}", path.display()),
            Self::Hex { file, case, field } => {
                write!(f, "{file}, case {case}: {field} is not lowercase hex")
            }
            Self::CipherSuite { file, value } => {
                write!(
                    f,
                    "{file}: cipher suite 0x{value:04x} is not in the §17.1 registry"
                )
            }
            Self::Computation { file, case, detail } => {
                write!(f, "{file}, case {case}: {detail}")
            }
            Self::MissingField { file, case, field } => {
                write!(f, "{file}, case {case}: missing required field {field}")
            }
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Read { source, .. } => Some(source),
            Self::Parse { source, .. } => Some(source),
            _ => None,
        }
    }
}

/// Checks every committed vector file in `dir`.
///
/// # Errors
///
/// [`Error`] if a file is missing or does not match the format contract. A
/// *disagreement* is not an error: it is a failing [`Check`] in the returned
/// suites.
pub fn run(dir: &Path) -> Result<Vec<Suite>, Error> {
    Ok(vec![
        commitment_suite(dir)?,
        ibst_suite(dir)?,
        ladder_suite(dir)?,
        vrf_suite(dir)?,
        log_tree_suite(dir)?,
        prefix_tree_suite(dir)?,
    ])
}

fn load<I, E>(dir: &Path, name: &str) -> Result<VectorFile<I, E>, Error>
where
    I: serde::de::DeserializeOwned,
    E: serde::de::DeserializeOwned,
{
    let path = dir.join(name);
    let raw = fs::read_to_string(&path).map_err(|source| Error::Read {
        path: path.clone(),
        source,
    })?;
    serde_json::from_str(&raw).map_err(|source| Error::Parse { path, source })
}

fn unhex(file: &str, case: &str, field: &str, value: &str) -> Result<Vec<u8>, Error> {
    hex::decode(value).map_err(|_| Error::Hex {
        file: file.to_owned(),
        case: case.to_owned(),
        field: field.to_owned(),
    })
}

/// §11.6, and with it the §2.1 codec and the §11.5/§11.6 structs.
fn commitment_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "commitment.json";
    let file: VectorFile<CommitmentInput, CommitmentExpect> = load(dir, FILE)?;

    let code = file.cipher_suite.unwrap_or_default();
    let suite = CipherSuite::from_code(code).map_err(|_| Error::CipherSuite {
        file: FILE.to_owned(),
        value: code,
    })?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let opening = unhex(FILE, name, "opening", &case.input.opening)?;
        let label = unhex(FILE, name, "label", &case.input.label)?;
        let value = unhex(FILE, name, "update.value", &case.input.update.value)?;
        let (suffix, mode) = match &case.input.update.signature {
            None => (UpdateSuffix::Empty, DeploymentMode::ContactMonitoring),
            Some(sig) => (
                UpdateSuffix::ThirdPartyManagement {
                    signature: unhex(FILE, name, "update.signature", sig)?,
                },
                DeploymentMode::ThirdPartyManagement,
            ),
        };
        let commitment_value = CommitmentValue {
            opening,
            label,
            version: case.input.version,
            update: UpdateValue { value, suffix },
        };

        let input = format!(
            "label {} bytes, version {}, value {} bytes",
            commitment_value.label.len(),
            commitment_value.version,
            commitment_value.update.value.len()
        );

        let mut checks = Vec::new();
        if case.expect.error {
            // A negative case: the vector says this opening must not verify
            // against the commitment it carries.
            let raw = case
                .input
                .commitment
                .as_deref()
                .ok_or_else(|| Error::MissingField {
                    file: FILE.to_owned(),
                    case: name.to_owned(),
                    field: "input.commitment".to_owned(),
                })?;
            let bytes = unhex(FILE, name, "input.commitment", raw)?;
            let got = match Commitment::from_slice(&bytes) {
                Err(err) => format!("unusable commitment: {err}"),
                Ok(target) => match commitment::verify(suite, &commitment_value, &target) {
                    Err(kt_crypto::Error::CommitmentMismatch) => "rejected".to_owned(),
                    Err(err) => format!("rejected with the wrong error: {err}"),
                    Ok(()) => "accepted".to_owned(),
                },
            };
            checks.push(Check::new(
                "verify() rejects this opening (§11.6)",
                "rejected",
                got,
            ));
        } else {
            let expected_encoding =
                case.expect
                    .commitment_value
                    .as_deref()
                    .ok_or_else(|| Error::MissingField {
                        file: FILE.to_owned(),
                        case: name.to_owned(),
                        field: "expect.commitment_value".to_owned(),
                    })?;
            let expected_commitment =
                case.expect
                    .commitment
                    .as_deref()
                    .ok_or_else(|| Error::MissingField {
                        file: FILE.to_owned(),
                        case: name.to_owned(),
                        field: "expect.commitment".to_owned(),
                    })?;

            match commitment::encode_commitment_value(suite, &commitment_value) {
                Ok(encoded) => {
                    checks.push(Check::new(
                        "CommitmentValue encoding (§2.1, §11.5, §11.6)",
                        expected_encoding,
                        hex::encode(&encoded),
                    ));
                    // The same bytes must decode back to the same struct: the
                    // vector pins the encoder, this pins the decoder against it
                    // on bytes the peer produced.
                    let mut dec = Decoder::new(&encoded);
                    let round_trip =
                        match CommitmentValue::decode_with_nc(&mut dec, suite.nc(), mode) {
                            Err(err) => format!("decode failed: {err}"),
                            Ok(decoded) => match dec.finish() {
                                Err(err) => format!("trailing bytes: {err}"),
                                Ok(()) if decoded == commitment_value => "round-trips".to_owned(),
                                Ok(()) => "decoded to a different value".to_owned(),
                            },
                        };
                    checks.push(Check::new(
                        "decode(encode(CommitmentValue)) is the identity",
                        "round-trips",
                        round_trip,
                    ));
                }
                Err(err) => {
                    checks.push(Check::new(
                        "CommitmentValue encoding (§2.1, §11.5, §11.6)",
                        expected_encoding,
                        format!("encoding failed: {err}"),
                    ));
                }
            }

            match commitment::commit(suite, &commitment_value) {
                Ok(got) => {
                    checks.push(Check::new(
                        "commitment = HMAC(Kc, CommitmentValue) (§11.6)",
                        expected_commitment,
                        hex::encode(got.as_bytes()),
                    ));
                }
                Err(err) => {
                    checks.push(Check::new(
                        "commitment = HMAC(Kc, CommitmentValue) (§11.6)",
                        expected_commitment,
                        format!("failed: {err}"),
                    ));
                }
            }

            // And the verification path must agree with the computation path.
            let bytes = unhex(FILE, name, "expect.commitment", expected_commitment)?;
            let accepted = match Commitment::from_slice(&bytes) {
                Err(err) => format!("unusable commitment: {err}"),
                Ok(target) => match commitment::verify(suite, &commitment_value, &target) {
                    Ok(()) => "accepted".to_owned(),
                    Err(err) => format!("rejected: {err}"),
                },
            };
            checks.push(Check::new(
                "verify() accepts the peer's commitment (§11.6)",
                "accepted",
                accepted,
            ));
        }

        cases.push(Case {
            name: name.to_owned(),
            negative: case.expect.error,
            input,
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Commitment".to_owned(),
        draft_section: section_of(&file.draft),
        file: FILE.to_owned(),
        generator: Generator {
            implementation: file.generator.implementation,
            sha: file.generator.sha,
        },
        cipher_suite: Some(format!("0x{:04x} {}", suite.code(), suite.name())),
        cases,
    })
}

/// §4.1 and Appendix A.
fn ibst_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "ibst.json";
    let file: VectorFile<IbstInput, IbstExpect> = load(dir, FILE)?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let size = case.input.size;
        let mut checks = vec![
            Check::new(
                "root(size) (§4.1)",
                case.expect.root.to_string(),
                render_result(ibst::root(size), |v| v.to_string()),
            ),
            Check::new(
                "frontier(size) (§4.1)",
                render_list(&case.expect.frontier),
                render_result(ibst::frontier(size), |f| render_list(&f)),
            ),
        ];

        let mut children = Vec::new();
        for node in &case.expect.nodes {
            let index = node.index;
            children.push(Check::new(
                format!("left({index})"),
                node.left
                    .map_or_else(|| "refused".to_owned(), |v| v.to_string()),
                render_refusal(ibst::left(index)),
            ));
            children.push(Check::new(
                format!("right({index}, {size})"),
                node.right
                    .map_or_else(|| "refused".to_owned(), |v| v.to_string()),
                render_refusal(ibst::right(index, size)),
            ));
        }
        checks.push(Check::group(
            "children of each node (§4.1, App. A)",
            children,
        ));

        cases.push(Case {
            name: case.name.clone(),
            negative: false,
            input: format!("log of {size} entries"),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Implicit binary search tree".to_owned(),
        draft_section: section_of(&file.draft),
        file: FILE.to_owned(),
        generator: Generator {
            implementation: file.generator.implementation,
            sha: file.generator.sha,
        },
        cipher_suite: None,
        cases,
    })
}

/// §5 and Appendix B.
fn ladder_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "binary-ladder.json";
    let file: VectorFile<LadderInput, LadderExpect> = load(dir, FILE)?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let expected = render_list(&case.expect.versions);
        let (what, input, got) = match &case.input {
            LadderInput::Base { greatest } => (
                "base_binary_ladder(greatest) (§5, App. B)",
                format!("greatest version {greatest}"),
                render_result(ladder::base_binary_ladder(*greatest), |v| render_list(&v)),
            ),
            LadderInput::Search {
                target,
                greatest,
                left_inclusion,
                right_non_inclusion,
            } => (
                "search_binary_ladder(target, greatest) (§6.2, App. B)",
                format!(
                    "target {target}, greatest {greatest}, already proven left {}, right {}",
                    render_list(left_inclusion),
                    render_list(right_non_inclusion)
                ),
                render_result(
                    ladder::search_binary_ladder(
                        *target,
                        *greatest,
                        left_inclusion,
                        right_non_inclusion,
                    ),
                    |v| render_list(&v),
                ),
            ),
            LadderInput::Monitoring {
                target,
                left_inclusion,
            } => (
                "monitoring_binary_ladder(target) (§8.1, App. B)",
                format!(
                    "target {target}, already proven left {}",
                    render_list(left_inclusion)
                ),
                render_list(&ladder::monitoring_binary_ladder(*target, left_inclusion)),
            ),
        };

        cases.push(Case {
            name: case.name.clone(),
            negative: false,
            input,
            checks: vec![Check::new(what, expected, got)],
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Binary ladders".to_owned(),
        draft_section: section_of(&file.draft),
        file: FILE.to_owned(),
        generator: Generator {
            implementation: file.generator.implementation,
            sha: file.generator.sha,
        },
        cipher_suite: None,
        cases,
    })
}

/// `"draft-ietf-keytrans-protocol-05 §11.6"` becomes `"§11.6"`.
fn section_of(draft: &str) -> String {
    draft
        .split_once(' ')
        .map_or_else(|| draft.to_owned(), |(_, rest)| rest.to_owned())
}

fn render_list<T: std::fmt::Display>(items: &[T]) -> String {
    let mut out = String::from("[");
    for (i, item) in items.iter().enumerate() {
        if i > 0 {
            out.push_str(", ");
        }
        let _ = write!(out, "{item}");
    }
    out.push(']');
    out
}

/// Renders a fallible computation whose failure is itself a disagreement.
fn render_result<T, E: std::fmt::Display>(
    result: Result<T, E>,
    show: impl FnOnce(T) -> String,
) -> String {
    match result {
        Ok(value) => show(value),
        Err(err) => format!("refused: {err}"),
    }
}

/// Renders a computation the vector may expect to be refused, so that a refusal
/// is a value to compare rather than an absence.
fn render_refusal<E>(result: Result<u64, E>) -> String {
    match result {
        Ok(value) => value.to_string(),
        Err(_) => "refused".to_owned(),
    }
}

/// §3.2, §11.8, and §12.1: the log tree.
fn log_tree_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "log-tree.json";
    let file: VectorFile<LogTreeInput, LogTreeExpect> = load(dir, FILE)?;
    let suite = CipherSuite::Kt128Sha256Ed25519;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let mut checks = Vec::new();

        // The leaf values: Hash(LogEntry) for each entry (§11.8).
        let mut leaves = Vec::new();
        let mut leaf_checks = Vec::new();
        for (i, entry) in case.input.entries.iter().enumerate() {
            let prefix_tree = hash_field(FILE, name, "entries[].prefix_tree", &entry.prefix_tree)?;
            let value = log::leaf_value(
                suite,
                &LogEntry {
                    timestamp: entry.timestamp,
                    prefix_tree,
                },
            )
            .map_err(|err| Error::Computation {
                file: FILE.to_owned(),
                case: name.to_owned(),
                detail: alloc_string(&err),
            })?;
            leaves.push(value);
            let expected = case.expect.leaf_values.get(i).cloned().unwrap_or_default();
            leaf_checks.push(Check::new(
                format!("Hash(LogEntry) for entry {i}"),
                expected,
                hex::encode(value.as_bytes()),
            ));
        }
        checks.push(Check::group("leaf values (§11.8)", leaf_checks));

        // The root, and the full subtree heads a verifier retains (§3.2, §4.2).
        checks.push(Check::new(
            "root of the log tree (§3.2, §11.8)",
            case.expect.root.clone(),
            render_result(log::root(suite, &leaves), |value| {
                hex::encode(value.as_bytes())
            }),
        ));

        let size = leaves.len() as u64;
        checks.push(Check::new(
            "full subtree heads (§4.2)",
            render_list(&case.expect.full_subtrees),
            render_result(
                log::Retained::from_leaves(suite, size, &leaves),
                |retained| {
                    render_list(
                        &retained
                            .full_subtrees
                            .iter()
                            .map(|value| hex::encode(value.as_bytes()))
                            .collect::<Vec<_>>(),
                    )
                },
            ),
        ));

        // Each batch proof: the same elements, the same wire bytes, and a
        // verification that lands on the peer's root.
        let mut proof_checks = Vec::new();
        for (i, request) in case.input.requests.iter().enumerate() {
            let Some(expected) = case.expect.proofs.get(i) else {
                proof_checks.push(Check::new(
                    format!("request {i}"),
                    "a proof",
                    "no proof in the vector",
                ));
                continue;
            };
            let retained = match request.retained_size {
                None => None,
                Some(retained_size) => Some(
                    log::Retained::from_leaves(suite, retained_size, &leaves).map_err(|err| {
                        Error::Computation {
                            file: FILE.to_owned(),
                            case: name.to_owned(),
                            detail: alloc_string(&err),
                        }
                    })?,
                ),
            };

            let label = describe_request(request);
            let built = log::prove(suite, &leaves, &request.proven_leaves, retained.as_ref());
            proof_checks.push(Check::new(
                format!("{label}: proof elements"),
                render_list(&expected.elements),
                render_result(built.as_ref().map(|proof| &proof.elements), |elements| {
                    render_list(
                        &elements
                            .iter()
                            .map(|v| hex::encode(v.as_bytes()))
                            .collect::<Vec<_>>(),
                    )
                }),
            ));
            proof_checks.push(Check::new(
                format!("{label}: wire encoding (§12.1)"),
                expected.proof.clone(),
                match built.as_ref().map(kt_wire::codec::encode) {
                    Ok(Ok(bytes)) => hex::encode(bytes),
                    Ok(Err(err)) => format!("encoding failed: {err}"),
                    Err(err) => format!("proving failed: {err}"),
                },
            ));

            // Decode the peer's own proof bytes and verify them: this is the
            // direction that matters for a client, since it is the peer's bytes a
            // client would receive.
            let peer_bytes = unhex(FILE, name, "expect.proofs[].proof", &expected.proof)?;
            let claimed: Vec<log::Leaf> = request
                .proven_leaves
                .iter()
                .filter_map(|index| {
                    usize::try_from(*index)
                        .ok()
                        .and_then(|i| leaves.get(i))
                        .map(|v| (*index, *v))
                })
                .collect();
            let verified = match kt_wire::codec::decode::<InclusionProof>(&peer_bytes) {
                Err(err) => format!("decoding the peer's proof failed: {err}"),
                Ok(proof) => render_result(
                    log::evaluate(suite, size, &claimed, retained.as_ref(), &proof),
                    |root| hex::encode(root.as_bytes()),
                ),
            };
            proof_checks.push(Check::new(
                format!("{label}: verifying the peer's proof reaches the peer's root"),
                case.expect.root.clone(),
                verified,
            ));
        }
        checks.push(Check::group("batch proofs (§12.1)", proof_checks));

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: format!(
                "log of {} entries, {} proof requests",
                case.input.entries.len(),
                case.input.requests.len()
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Log tree".to_owned(),
        draft_section: section_of(&file.draft),
        file: FILE.to_owned(),
        generator: Generator {
            implementation: file.generator.implementation,
            sha: file.generator.sha,
        },
        cipher_suite: None,
        cases,
    })
}

/// §3.3, §11.9, and §12.2: the prefix tree.
fn prefix_tree_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "prefix-tree.json";
    let file: VectorFile<PrefixTreeInput, PrefixTreeExpect> = load(dir, FILE)?;
    let suite = CipherSuite::Kt128Sha256Ed25519;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();

        // Build the tree from the same entries, in the same order.
        let mut tree = prefix::PrefixTree::new();
        for entry in &case.input.entries {
            let leaf = PrefixLeaf {
                vrf_output: hash_field(FILE, name, "entries[].vrf_output", &entry.vrf_output)?,
                commitment: hash_field(FILE, name, "entries[].commitment", &entry.commitment)?,
            };
            tree.insert(leaf).map_err(|err| Error::Computation {
                file: FILE.to_owned(),
                case: name.to_owned(),
                detail: alloc_string(&err),
            })?;
        }

        let mut searches = Vec::new();
        for key in &case.input.searches {
            searches.push(hash_field(FILE, name, "searches[]", key)?);
        }

        let mut checks = vec![Check::new(
            "root of the prefix tree (§3.3, §11.9)",
            case.expect.root.clone(),
            hex::encode(tree.root(suite).as_bytes()),
        )];

        // The proof we build for the same batch must match the peer's, both as
        // results and as bytes.
        let built = tree.prove(suite, &searches);
        checks.push(Check::new(
            "search results (§12.2)",
            render_prefix_results(&case.expect.results),
            match &built {
                Err(err) => format!("proving failed: {err}"),
                Ok(proof) => render_results(&proof.results),
            },
        ));
        checks.push(Check::new(
            "copath elements (§12.2)",
            render_list(&case.expect.elements),
            match &built {
                Err(err) => format!("proving failed: {err}"),
                Ok(proof) => render_list(
                    &proof
                        .elements
                        .iter()
                        .map(|v| hex::encode(v.as_bytes()))
                        .collect::<Vec<_>>(),
                ),
            },
        ));
        checks.push(Check::new(
            "wire encoding (§12.2)",
            case.expect.proof.clone(),
            match built.as_ref().map(kt_wire::codec::encode) {
                Ok(Ok(bytes)) => hex::encode(bytes),
                Ok(Err(err)) => format!("encoding failed: {err}"),
                Err(err) => format!("proving failed: {err}"),
            },
        ));

        // And the peer's own proof bytes must verify against the peer's root.
        let peer_bytes = unhex(FILE, name, "expect.proof", &case.expect.proof)?;
        let entries: Vec<prefix::SearchEntry> = searches
            .iter()
            .zip(case.expect.results.iter())
            .map(|(key, result)| {
                if result.result_type == 1 {
                    // An inclusion result needs the commitment the leaf holds; it
                    // is the one the peer recorded for this search.
                    let commitment = case
                        .input
                        .entries
                        .iter()
                        .find(|entry| entry.vrf_output == hex::encode(key.as_bytes()))
                        .and_then(|entry| {
                            HashValue::from_slice(&hex::decode(&entry.commitment).ok()?).ok()
                        });
                    match commitment {
                        Some(value) => prefix::SearchEntry::included(*key, value),
                        None => prefix::SearchEntry::absent(*key),
                    }
                } else {
                    prefix::SearchEntry::absent(*key)
                }
            })
            .collect();
        let root = hash_field(FILE, name, "expect.root", &case.expect.root)?;
        let verified = match kt_wire::codec::decode::<PrefixProof>(&peer_bytes) {
            Err(err) => format!("decoding the peer's proof failed: {err}"),
            Ok(proof) => match prefix::verify(suite, &entries, &proof, root) {
                Ok(()) => "accepted".to_owned(),
                Err(err) => format!("rejected: {err}"),
            },
        };
        checks.push(Check::new(
            "verifying the peer's proof against the peer's root",
            "accepted",
            verified,
        ));

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: format!(
                "{} entries, {} searches",
                case.input.entries.len(),
                case.input.searches.len()
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Prefix tree".to_owned(),
        draft_section: section_of(&file.draft),
        file: FILE.to_owned(),
        generator: Generator {
            implementation: file.generator.implementation,
            sha: file.generator.sha,
        },
        cipher_suite: None,
        cases,
    })
}

/// A short label for a batch proof request.
fn describe_request(request: &crate::vectors::LogProofRequest) -> String {
    let leaves = if request.proven_leaves.is_empty() {
        "no leaves".to_owned()
    } else {
        format!("leaves {}", render_list(&request.proven_leaves))
    };
    match request.retained_size {
        None => leaves,
        Some(size) => format!("{leaves}, retained {size}"),
    }
}

fn render_results(results: &[kt_wire::proofs::PrefixSearchResult]) -> String {
    let rendered: Vec<String> = results
        .iter()
        .map(|result| {
            let mut out = format!("{}@{}", result.result_type().as_u8(), result.depth());
            if let kt_wire::proofs::PrefixSearchResult::NonInclusionLeaf { leaf, .. } = result {
                out.push_str(&format!(
                    "({}…)",
                    hex::encode(&leaf.vrf_output.as_bytes()[..4])
                ));
            }
            out
        })
        .collect();
    render_list(&rendered)
}

fn render_prefix_results(results: &[crate::vectors::PrefixResultExpect]) -> String {
    let rendered: Vec<String> = results
        .iter()
        .map(|result| {
            let mut out = format!("{}@{}", result.result_type, result.depth);
            if let Some(leaf) = &result.leaf {
                out.push_str(&format!("({}…)", &leaf.vrf_output[..8]));
            }
            out
        })
        .collect();
    render_list(&rendered)
}

/// Decodes a hex field that must be a `HashValue`.
fn hash_field(file: &str, case: &str, field: &str, value: &str) -> Result<HashValue, Error> {
    let bytes = unhex(file, case, field, value)?;
    HashValue::from_slice(&bytes).map_err(|_| Error::Hex {
        file: file.to_owned(),
        case: case.to_owned(),
        field: field.to_owned(),
    })
}

fn alloc_string(err: &impl core::fmt::Display) -> String {
    format!("{err}")
}

/// §11.7: the VRF, and the KT wrapping around RFC 9381's ECVRF.
fn vrf_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "vrf.json";
    let file: VectorFile<VrfCaseInput, VrfExpect> = load(dir, FILE)?;

    let code = file.cipher_suite.unwrap_or_default();
    let suite = CipherSuite::from_code(code).map_err(|_| Error::CipherSuite {
        file: FILE.to_owned(),
        value: code,
    })?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let seed: [u8; vrf::SECRET_KEY_SIZE] =
            unhex(FILE, name, "private_key", &case.input.private_key)?
                .try_into()
                .map_err(|_| Error::Hex {
                    file: FILE.to_owned(),
                    case: name.to_owned(),
                    field: "private_key".to_owned(),
                })?;
        let secret = vrf::SecretKey::from_seed(seed);
        let label = unhex(FILE, name, "label", &case.input.label)?;
        let input = VrfInput::new(label, case.input.version);

        let mut checks = vec![Check::new(
            "public key derived from the seed (RFC 8032 §5.1.5)",
            case.input.public_key.clone(),
            hex::encode(secret.public_key().as_bytes()),
        )];

        if case.expect.error {
            // A negative case: the proof it carries is for a different
            // label-version pair and must not verify for this one.
            let raw = case
                .input
                .proof
                .as_deref()
                .ok_or_else(|| Error::MissingField {
                    file: FILE.to_owned(),
                    case: name.to_owned(),
                    field: "input.proof".to_owned(),
                })?;
            let bytes = unhex(FILE, name, "input.proof", raw)?;
            let got = match vrf::Proof::from_slice(&bytes) {
                Err(err) => format!("unusable proof: {err}"),
                Ok(proof) => match secret.public_key().verify(suite, &input, &proof) {
                    Err(_) => "rejected".to_owned(),
                    Ok(_) => "accepted".to_owned(),
                },
            };
            checks.push(Check::new(
                "verify() rejects a proof for another label-version pair (§11.7)",
                "rejected",
                got,
            ));
        } else {
            let expected_input =
                case.expect
                    .vrf_input
                    .as_deref()
                    .ok_or_else(|| Error::MissingField {
                        file: FILE.to_owned(),
                        case: name.to_owned(),
                        field: "expect.vrf_input".to_owned(),
                    })?;
            let expected_output =
                case.expect
                    .output
                    .as_deref()
                    .ok_or_else(|| Error::MissingField {
                        file: FILE.to_owned(),
                        case: name.to_owned(),
                        field: "expect.output".to_owned(),
                    })?;
            let expected_proof =
                case.expect
                    .proof
                    .as_deref()
                    .ok_or_else(|| Error::MissingField {
                        file: FILE.to_owned(),
                        case: name.to_owned(),
                        field: "expect.proof".to_owned(),
                    })?;

            // alpha_string is the encoded VrfInput. RFC 9381 says nothing about
            // this; §11.7 does, and it is where two conforming ECVRF
            // implementations can still disagree.
            checks.push(Check::new(
                "VrfInput encoding is alpha_string (§2.1, §11.7)",
                expected_input,
                render_result(kt_wire::codec::encode(&input), hex::encode),
            ));

            let produced = secret.evaluate(suite, &input);
            checks.push(Check::new(
                "VRF proof, VRF.Np = 80 bytes (§11.7, RFC 9381 §5.1)",
                expected_proof,
                match &produced {
                    Ok((_, proof)) => hex::encode(proof.as_bytes()),
                    Err(err) => format!("failed: {err}"),
                },
            ));
            checks.push(Check::new(
                "VRF output, truncated to VRF.Nh = 32 bytes (§17.1)",
                expected_output,
                match &produced {
                    Ok((output, _)) => hex::encode(output.as_bytes()),
                    Err(err) => format!("failed: {err}"),
                },
            ));

            // And the peer's own proof must verify and yield the peer's output —
            // the direction a client actually runs.
            let bytes = unhex(FILE, name, "expect.proof", expected_proof)?;
            let public = vrf::PublicKey::from_slice(&unhex(
                FILE,
                name,
                "public_key",
                &case.input.public_key,
            )?);
            let verified = match (public, vrf::Proof::from_slice(&bytes)) {
                (Err(err), _) => format!("unusable public key: {err}"),
                (_, Err(err)) => format!("unusable proof: {err}"),
                (Ok(public), Ok(proof)) => {
                    render_result(public.verify(suite, &input, &proof), |output| {
                        hex::encode(output.as_bytes())
                    })
                }
            };
            checks.push(Check::new(
                "verifying the peer's proof yields the peer's search key (§11.7)",
                expected_output,
                verified,
            ));
        }

        cases.push(Case {
            name: name.to_owned(),
            negative: case.expect.error,
            input: format!(
                "label {} bytes, version {}",
                case.input.label.len() / 2,
                case.input.version
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "VRF".to_owned(),
        draft_section: section_of(&file.draft),
        file: FILE.to_owned(),
        generator: Generator {
            implementation: file.generator.implementation,
            sha: file.generator.sha,
        },
        cipher_suite: Some(format!("0x{:04x} {}", suite.code(), suite.name())),
        cases,
    })
}
