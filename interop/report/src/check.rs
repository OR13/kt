//! Running the committed vectors against this implementation.
//!
//! One code path produces both the `#[test]` verdicts and the published page, so
//! the page cannot claim something the test suite does not enforce. Nothing here
//! panics or asserts: a disagreement becomes a [`Check`] with `Verdict::Fail`,
//! carrying both values, and it is the caller's job to fail the build over it.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use kt_crypto::commitment::{self, Commitment};
use kt_crypto::suite::CipherSuite;
use kt_crypto::{signature, vrf};
use kt_tree::{audit, ibst, ladder, log, prefix};
use kt_wire::audit::AuditorUpdate;
use kt_wire::codec::Decoder;
use kt_wire::heads::{
    AuditorConfig, AuditorTreeHead, AuditorTreeHeadTBS, Configuration, FullTreeHead, TreeHead,
    TreeHeadTBS,
};
use kt_wire::proofs::{InclusionProof, PrefixLeaf, PrefixProof};
use kt_wire::requests::{
    BinaryLadderStep, ContactMonitorRequest, LabelValue, MonitorMapEntry, OwnerInitRequest,
    OwnerMonitorRequest, SearchRequest, UpdateInfo, UpdateRequest, UpdateTBS,
};
use kt_wire::structs::{
    CommitmentValue, DeploymentMode, HashValue, LogEntry, UpdateSuffix, UpdateValue, VrfInput,
};

use crate::report::{Case, Check, Generator, Suite};
use crate::vectors::{
    AppendExpect, AppendInput, AuditorExpect, AuditorInput, CommitmentExpect, CommitmentInput,
    DistinguishedExpect, DistinguishedInput, HeadExpect, HeadInput, IbstExpect, IbstInput,
    InterpretationExpect, InterpretationInput, LadderExpect, LadderInput, LogMathExpect,
    LogMathInput, LogTreeExpect, LogTreeInput, MutationExpect, MutationInput, PrefixTreeExpect,
    PrefixTreeInput, RequestExpect, RequestInput, TamperedExpect, TamperedInput, UpdateViewExpect,
    UpdateViewInput, VectorFile, VrfCaseInput, VrfExpect,
};

/// The vector files this crate knows how to check, in dependency order.
pub const FILES: [&str; 16] = [
    "commitment.json",
    "ibst.json",
    "binary-ladder.json",
    "ladder-interpretation.json",
    "update-view.json",
    "distinguished.json",
    "vrf.json",
    "log-math.json",
    "log-tree.json",
    "log-append.json",
    "prefix-tree.json",
    "prefix-mutation.json",
    "auditor-update.json",
    "tree-head.json",
    "requests.json",
    "tampered.json",
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
        interpretation_suite(dir)?,
        update_view_suite(dir)?,
        distinguished_suite(dir)?,
        vrf_suite(dir)?,
        log_math_suite(dir)?,
        log_tree_suite(dir)?,
        append_suite(dir)?,
        prefix_tree_suite(dir)?,
        mutation_suite(dir)?,
        auditor_suite(dir)?,
        head_suite(dir)?,
        request_suite(dir)?,
        tampered_suite(dir)?,
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

/// §6.1: which log entries are distinguished.
fn distinguished_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "distinguished.json";
    let file: VectorFile<DistinguishedInput, DistinguishedExpect> = load(dir, FILE)?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let timestamps = case.input.timestamps.clone();
        let at = move |position: u64| {
            usize::try_from(position)
                .ok()
                .and_then(|index| timestamps.get(index))
                .copied()
        };
        let window = case.input.window;
        let size = case.input.size;

        // The peer reaches both answers by walking the frontier. This side runs §6.1's
        // recursion and takes the greatest element of the set it produces, so agreement is
        // evidence about the shortcut rather than about two copies of the same code.
        let render = |value: Result<Option<u64>, kt_tree::distinguished::Error>| match value {
            Ok(None) => "none".to_owned(),
            Ok(Some(position)) => position.to_string(),
            Err(err) => format!("failed: {err}"),
        };
        let checks = vec![
            Check::new(
                "rightmost distinguished log entry (§6.1)",
                case.expect
                    .rightmost
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                render(kt_tree::distinguished::rightmost(size, window, &at)),
            ),
            Check::new(
                "rightmost distinguished entry left of the last one (§6.1)",
                case.expect
                    .previous_rightmost
                    .map_or_else(|| "none".to_owned(), |value| value.to_string()),
                render(kt_tree::distinguished::previous_rightmost(
                    size, window, &at,
                )),
            ),
        ];

        // The full set has no counterpart to compare against — the peer never computes one —
        // so it goes in the description, where it is the thing a reader wants anyway.
        let enumerated = kt_tree::distinguished::enumerate(size, window, &at);
        let summary = match &enumerated {
            Err(err) => format!("enumerating failed: {err}"),
            Ok(set) if set.is_empty() => "no distinguished entries".to_owned(),
            Ok(set) => format!(
                "{} distinguished: {}",
                set.len(),
                render_list(&set.iter().take(8).map(u64::to_string).collect::<Vec<_>>())
            ),
        };

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: format!(
                "size {size}, window {window} · {summary} · peer read {} timestamps",
                case.expect.requested.len()
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Distinguished log entries".to_owned(),
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

/// §3.2 and §11.8: growing the log tree one leaf at a time.
fn append_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "log-append.json";
    let file: VectorFile<AppendInput, AppendExpect> = load(dir, FILE)?;
    let suite = CipherSuite::Kt128Sha256Ed25519;

    // One view carried across the whole sweep, appended to case by case — which is the
    // property under test. Re-deriving it per case would check the shape and miss the
    // thing an auditor actually does.
    let mut view = log::Retained {
        size: 0,
        full_subtrees: Vec::new(),
    };
    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let entry = case
            .input
            .entries
            .first()
            .ok_or_else(|| Error::Computation {
                file: FILE.to_owned(),
                case: name.to_owned(),
                detail: "input.entries is empty".to_owned(),
            })?;
        let leaf = log::leaf_value(
            suite,
            &kt_wire::structs::LogEntry {
                timestamp: entry.timestamp,
                prefix_tree: hash_field(FILE, name, "entries[].prefix_tree", &entry.prefix_tree)?,
            },
        )
        .map_err(|err| Error::Computation {
            file: FILE.to_owned(),
            case: name.to_owned(),
            detail: alloc_string(&err),
        })?;
        let appended = view.append(suite, leaf);

        let mut checks = vec![Check::new(
            "full subtree heads after the append (§3.2)",
            render_list(&case.expect.full_subtrees),
            match &appended {
                Err(err) => format!("appending failed: {err}"),
                Ok(()) => render_list(
                    &view
                        .full_subtrees
                        .iter()
                        .map(|value| hex::encode(value.as_bytes()))
                        .collect::<Vec<_>>(),
                ),
            },
        )];
        checks.push(Check::new(
            "root folded from those heads (§11.8)",
            case.expect.root.clone(),
            match view.root(suite) {
                Ok(root) => hex::encode(root.as_bytes()),
                Err(err) => format!("rooting failed: {err}"),
            },
        ));

        // And the same root the other way, from every leaf, which is the check that makes
        // the incremental path worth having: the two computations meet only at §11.8's
        // hashContent rule.
        let mut leaves = Vec::new();
        for value in &case.input.leaves {
            leaves.push(hash_field(FILE, name, "leaves[]", value)?);
        }
        checks.push(Check::new(
            "the same root computed from every leaf instead (§3.2)",
            case.expect.root.clone(),
            match log::root(suite, &leaves) {
                Ok(root) => hex::encode(root.as_bytes()),
                Err(err) => format!("rooting failed: {err}"),
            },
        ));

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: format!(
                "{} leaves, {} heads",
                case.input.size,
                case.expect.full_subtrees.len()
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Log tree, grown one leaf at a time".to_owned(),
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

/// §15.2: the prefix tree mutation an auditor replays from a proof.
fn mutation_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "prefix-mutation.json";
    let file: VectorFile<MutationInput, MutationExpect> = load(dir, FILE)?;
    let suite = CipherSuite::Kt128Sha256Ed25519;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let leaves = |field: &str, entries: &[crate::vectors::PrefixEntryInput]| {
            entries
                .iter()
                .map(|entry| {
                    Ok(PrefixLeaf {
                        vrf_output: hash_field(FILE, name, field, &entry.vrf_output)?,
                        commitment: hash_field(FILE, name, field, &entry.commitment)?,
                    })
                })
                .collect::<Result<Vec<_>, Error>>()
        };
        let entries = leaves("entries[]", &case.input.entries)?;
        let added = leaves("add[]", &case.input.add)?;
        let removed = leaves("remove[]", &case.input.remove)?;

        let mut tree = prefix::PrefixTree::new();
        for leaf in &entries {
            tree.insert(*leaf).map_err(|err| Error::Computation {
                file: FILE.to_owned(),
                case: name.to_owned(),
                detail: alloc_string(&err),
            })?;
        }

        // The batch an auditor is sent covers the additions first, then the removals.
        let keys: Vec<HashValue> = added
            .iter()
            .chain(removed.iter())
            .map(|leaf| leaf.vrf_output)
            .collect();
        let built = tree.prove(suite, &keys);
        let mut checks = vec![Check::new(
            "batch proof for the update's keys (§12.2)",
            case.expect.proof.clone(),
            match built.as_ref().map(kt_wire::codec::encode) {
                Ok(Ok(bytes)) => hex::encode(bytes),
                Ok(Err(err)) => format!("encoding failed: {err}"),
                Err(err) => format!("proving failed: {err}"),
            },
        )];

        // Everything below replays the *peer's* proof bytes, which is the direction that
        // matters: an auditor is handed those, not its own.
        let peer_bytes = unhex(FILE, name, "expect.proof", &case.expect.proof)?;
        let replayed = kt_wire::codec::decode::<PrefixProof>(&peer_bytes)
            .map_err(|err| format!("decoding the peer's proof failed: {err}"))
            .and_then(|proof| {
                prefix::evaluate_before_after(suite, &added, &removed, &proof)
                    .map_err(|err| format!("refused: {err}"))
            });

        checks.push(Check::new(
            "root before the update (§15.2 step 6)",
            case.expect.before.clone(),
            match &replayed {
                Ok(mutation) => hex::encode(mutation.before.as_bytes()),
                Err(detail) => detail.clone(),
            },
        ));

        // Which root to expect depends on whether the proof determines one. Where a
        // removal empties a slot beside an uncovered sibling it does not, and the value
        // to agree with the peer on is the one both reach by assuming no collapse. Where
        // it does, the value to reach is the root the peer's own tree took — a stronger
        // oracle than its verifier, and in two of these cases they differ.
        let (what, expected) = if case.input.sibling_uncovered {
            let peer = case.expect.peer_after.clone().unwrap_or_default();
            let label = if peer == case.expect.after {
                "root after the update, assuming no collapse (§15.2 step 7) — \
                 the assumption holds here, but the proof does not say so"
            } else {
                "root after the update, assuming no collapse (§15.2 step 7) — \
                 the assumption is wrong here and the tree's root is unreachable"
            };
            (label.to_owned(), peer)
        } else {
            let mut label = "root after the update (§15.2 step 7)".to_owned();
            match (&case.expect.peer_error, &case.expect.peer_after) {
                (Some(err), _) => {
                    label.push_str(&format!(" — the peer declines this update: {err}"))
                }
                (None, Some(peer)) if *peer != case.expect.after => label.push_str(&format!(
                    " — the peer's verifier returns {}…, which its own tree does not have",
                    &peer[..12.min(peer.len())]
                )),
                _ => {}
            }
            (label, case.expect.after.clone())
        };
        checks.push(Check::new(
            what,
            expected,
            match &replayed {
                Ok(mutation) => hex::encode(mutation.after.as_bytes()),
                Err(detail) => detail.clone(),
            },
        ));

        // And the part no vector can supply: whether that root followed from the proof.
        checks.push(Check::new(
            "whether the proof determines the root it produced (§15.2)",
            if case.input.sibling_uncovered {
                "assumed"
            } else {
                "determined"
            },
            match &replayed {
                Ok(mutation) if mutation.determined() => "determined",
                Ok(_) => "assumed",
                Err(_) => "no root",
            },
        ));

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: format!(
                "{} entries, +{} −{}",
                entries.len(),
                added.len(),
                removed.len()
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Prefix tree mutation".to_owned(),
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

/// §15.2: the third-party auditor's decision on one log entry.
fn auditor_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "auditor-update.json";
    let file: VectorFile<AuditorInput, AuditorExpect> = load(dir, FILE)?;
    let suite = CipherSuite::Kt128Sha256Ed25519;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();

        // The update is read from the peer's own bytes: an auditor is handed these, and
        // decoding them is the first thing that can go wrong.
        let bytes = unhex(FILE, name, "expect.encoding", &case.expect.encoding)?;
        let decoded = kt_wire::codec::decode::<AuditorUpdate>(&bytes);

        let mut checks = vec![Check::new(
            "AuditorUpdate wire encoding (§15.2)",
            case.expect.encoding.clone(),
            match decoded.as_ref().map(kt_wire::codec::encode) {
                Ok(Ok(reencoded)) => hex::encode(reencoded),
                Ok(Err(err)) => format!("re-encoding failed: {err}"),
                Err(err) => format!("decoding failed: {err}"),
            },
        )];

        // Then the verdict. Normalized to accepted/rejected: two implementations of eight
        // prose steps have no reason to word a refusal alike, and requiring them to would
        // make the check about English rather than about the protocol.
        let previous = (!case.input.first_entry)
            .then(|| {
                // The auditor's state as the peer's own auditor left it after priming:
                // its log tree heads, the frontier timestamps that decide which entries are
                // distinguished, and the step 5 record of insertions no distinguished entry
                // has covered yet. Resuming from the peer's bookkeeping rather than
                // reconstructing it is what makes the step 5 checks mean anything.
                let prefix_root =
                    hash_field(FILE, name, "input.prefix_root", &case.input.prefix_root)?;
                let mut full_subtrees = Vec::new();
                for head in &case.input.log_full_subtrees {
                    full_subtrees.push(hash_field(FILE, name, "input.log_full_subtrees[]", head)?);
                }
                let mut inserted = Vec::new();
                for entry in &case.input.inserted {
                    inserted.push(audit::Inserted {
                        position: entry.position,
                        vrf_output: hash_field(
                            FILE,
                            name,
                            "input.inserted[].vrf_output",
                            &entry.vrf_output,
                        )?,
                    });
                }

                Ok::<_, Error>(audit::AuditorState {
                    timestamp: case.input.previous_timestamp,
                    prefix_root,
                    log: log::Retained {
                        size: case.input.log_size,
                        full_subtrees,
                    },
                    timestamps: case.input.frontier_timestamps.clone(),
                    inserted,
                })
            })
            .transpose()?;
        let outcome = decoded
            .as_ref()
            .map_err(|err| format!("decoding failed: {err}"))
            .and_then(|update| {
                audit::verify_update(suite, case.input.window, update, previous.as_ref())
                    .map_err(|err| format!("rejected: {err}"))
            });
        let mut what = "the auditor's verdict (§15.2 steps 1–7)".to_owned();
        if let Some(detail) = &case.expect.peer_detail {
            what.push_str(&format!(" — the peer's reason: {detail}"));
        }
        checks.push(Check::new(
            what,
            case.expect.verdict.clone(),
            match &outcome {
                Ok(_) => "accepted",
                Err(_) => "rejected",
            },
        ));

        // Step 7's second half, for the updates the peer accepted: the log tree root the
        // auditor would sign. The peer computes it by folding the full subtree heads its
        // own state carries, which is the same job done by different code — and unlike the
        // prefix root, there is nothing ambiguous about it.
        if let (Some(size), Some(root)) = (case.expect.tree_size, case.expect.log_root.as_ref()) {
            checks.push(Check::new(
                "log tree root over the new entry (§15.2 step 7, §11.3)",
                format!("size {size}, root {root}"),
                match &outcome {
                    Ok(accepted) => format!(
                        "size {}, root {}",
                        accepted.state.log.size,
                        hex::encode(accepted.log_root.as_bytes())
                    ),
                    Err(detail) => detail.clone(),
                },
            ));
        }

        // Our own reason, and whether the new root followed from the proof, go in the
        // case's description rather than into checks of their own. Neither has anything in
        // the vector to compare against — the peer's wording is its own, and §15.2 has no
        // step for determinacy — and a check whose two sides are the same value by
        // construction cannot fail, which on a page of evidence is worse than absent.
        let mut description = format!(
            "{} entries, +{} −{}",
            case.input.entries.len(),
            case.input.added.len(),
            case.input.removed.len()
        );
        match &outcome {
            Err(detail) => description.push_str(&format!(" · {detail}")),
            Ok(accepted) if !accepted.root_determined => description.push_str(
                " · accepted, but the new root was assumed: a removal emptied a slot beside \
                 a sibling the proof does not identify",
            ),
            Ok(_) => {}
        }

        cases.push(Case {
            name: name.to_owned(),
            negative: case.expect.verdict != "accepted",
            input: description,
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Third-party auditor".to_owned(),
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

/// The must-reject suite: proofs the peer says are invalid.
///
/// Every other suite asks "do you compute the same value?", which a verifier that
/// accepts everything passes. This one asks "do you say no?", and the peer has
/// already confirmed that it does.
fn tampered_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "tampered.json";
    let file: VectorFile<TamperedInput, TamperedExpect> = load(dir, FILE)?;

    let code = file.cipher_suite.unwrap_or_default();
    let suite = CipherSuite::from_code(code).map_err(|_| Error::CipherSuite {
        file: FILE.to_owned(),
        value: code,
    })?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        if !case.expect.error {
            return Err(Error::MissingField {
                file: FILE.to_owned(),
                case: name.to_owned(),
                field: "expect.error must be true in this file".to_owned(),
            });
        }

        let (what, got) = match &case.input {
            TamperedInput::LogTree {
                size,
                entries,
                values,
                retained_size,
                retained,
                elements,
                root,
            } => {
                let mut leaves = Vec::new();
                for (index, value) in entries.iter().zip(values.iter()) {
                    leaves.push((*index, hash_field(FILE, name, "values[]", value)?));
                }
                let retained_view = match retained_size {
                    None => None,
                    Some(retained_size) => {
                        let mut heads = Vec::new();
                        for head in retained {
                            heads.push(hash_field(FILE, name, "retained[]", head)?);
                        }
                        Some(log::Retained {
                            size: *retained_size,
                            full_subtrees: heads,
                        })
                    }
                };
                let mut proof_elements = Vec::new();
                for element in elements {
                    proof_elements.push(hash_field(FILE, name, "elements[]", element)?);
                }
                let proof = InclusionProof::new(proof_elements);
                let root = hash_field(FILE, name, "root", root)?;

                let got = match log::verify(
                    suite,
                    *size,
                    &leaves,
                    retained_view.as_ref(),
                    &proof,
                    root,
                ) {
                    Err(err) => format!("rejected: {err}"),
                    Ok(()) => "accepted".to_owned(),
                };
                ("log::verify rejects it (§12.1)", got)
            }
            TamperedInput::PrefixTree {
                searches,
                proof,
                root,
            } => {
                let mut entries = Vec::new();
                for search in searches {
                    let key = hash_field(FILE, name, "searches[].vrf_output", &search.vrf_output)?;
                    entries.push(match &search.commitment {
                        Some(commitment) => prefix::SearchEntry::included(
                            key,
                            hash_field(FILE, name, "searches[].commitment", commitment)?,
                        ),
                        None => prefix::SearchEntry::absent(key),
                    });
                }
                let bytes = unhex(FILE, name, "proof", proof)?;
                let root = hash_field(FILE, name, "root", root)?;
                let got = match kt_wire::codec::decode::<PrefixProof>(&bytes) {
                    // A proof that will not even decode is rejected, which is the
                    // outcome the case calls for.
                    Err(err) => format!("rejected while decoding: {err}"),
                    Ok(proof) => match prefix::verify(suite, &entries, &proof, root) {
                        Err(err) => format!("rejected: {err}"),
                        Ok(()) => "accepted".to_owned(),
                    },
                };
                ("prefix::verify rejects it (§12.2)", got)
            }
            TamperedInput::Vrf {
                public_key,
                label,
                version,
                proof,
            } => {
                let key = unhex(FILE, name, "public_key", public_key)?;
                let bytes = unhex(FILE, name, "proof", proof)?;
                let input = VrfInput::new(unhex(FILE, name, "label", label)?, *version);
                let got = match (
                    vrf::PublicKey::from_slice(&key),
                    vrf::Proof::from_slice(&bytes),
                ) {
                    (Err(err), _) => format!("rejected with the key: {err}"),
                    (_, Err(err)) => format!("rejected with the proof: {err}"),
                    (Ok(public), Ok(proof)) => match public.verify(suite, &input, &proof) {
                        Err(err) => format!("rejected: {err}"),
                        Ok(_) => "accepted".to_owned(),
                    },
                };
                ("vrf verify rejects it (§11.7)", got)
            }
            TamperedInput::TreeHead {
                mode,
                signature_public_key,
                vrf_public_key,
                max_ahead,
                max_behind,
                reasonable_monitoring_window,
                tree_size,
                root,
                signature,
            } => {
                let mode = DeploymentMode::from_u8(*mode).map_err(|_| Error::Computation {
                    file: FILE.to_owned(),
                    case: name.to_owned(),
                    detail: format!("unknown deployment mode {mode}"),
                })?;
                let config = Configuration {
                    cipher_suite: suite.code(),
                    mode,
                    signature_public_key: unhex(
                        FILE,
                        name,
                        "signature_public_key",
                        signature_public_key,
                    )?,
                    vrf_public_key: unhex(FILE, name, "vrf_public_key", vrf_public_key)?,
                    leaf_public_key: None,
                    auditor: None,
                    max_ahead: *max_ahead,
                    max_behind: *max_behind,
                    reasonable_monitoring_window: *reasonable_monitoring_window,
                    maximum_lifetime: None,
                };
                let head = TreeHead {
                    tree_size: *tree_size,
                    signature: unhex(FILE, name, "signature", signature)?,
                };
                let root = hash_field(FILE, name, "root", root)?;
                let got = match signature::verify_tree_head(&config, &head, root) {
                    Err(err) => format!("rejected: {err}"),
                    Ok(()) => "accepted".to_owned(),
                };
                ("signature::verify_tree_head rejects it (§11.2)", got)
            }
            TamperedInput::Commitment {
                opening,
                label,
                version,
                update,
                commitment,
            } => {
                let value = CommitmentValue {
                    opening: unhex(FILE, name, "opening", opening)?,
                    label: unhex(FILE, name, "label", label)?,
                    version: *version,
                    update: UpdateValue::new(unhex(FILE, name, "update.value", &update.value)?),
                };
                let bytes = unhex(FILE, name, "commitment", commitment)?;
                let got = match Commitment::from_slice(&bytes) {
                    Err(err) => format!("rejected with the commitment: {err}"),
                    Ok(target) => match commitment::verify(suite, &value, &target) {
                        Err(err) => format!("rejected: {err}"),
                        Ok(()) => "accepted".to_owned(),
                    },
                };
                ("commitment::verify rejects it (§11.6)", got)
            }
        };

        // The comparison is deliberately on the prefix "rejected", not on the exact
        // message: which error a verifier reports is its own business, and pinning
        // the text here would make the vector untestable across implementations —
        // the same reason the format contract forbids error strings.
        let verdict = if got.starts_with("rejected") {
            "rejected".to_owned()
        } else {
            got.clone()
        };
        cases.push(Case {
            name: name.to_owned(),
            negative: true,
            input: case.expect.tamper.clone(),
            checks: vec![Check::new(what, "rejected", verdict)],
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Must reject".to_owned(),
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

/// §11.2, §11.3, §11.4: the configuration and the signatures over it.
fn head_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "tree-head.json";
    let file: VectorFile<HeadInput, HeadExpect> = load(dir, FILE)?;

    let code = file.cipher_suite.unwrap_or_default();
    let suite = CipherSuite::from_code(code).map_err(|_| Error::CipherSuite {
        file: FILE.to_owned(),
        value: code,
    })?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let mode = DeploymentMode::from_u8(case.input.mode).map_err(|_| Error::Computation {
            file: FILE.to_owned(),
            case: name.to_owned(),
            detail: format!("unknown deployment mode {}", case.input.mode),
        })?;

        let config = Configuration {
            cipher_suite: code,
            mode,
            signature_public_key: unhex(
                FILE,
                name,
                "signature_public_key",
                &case.input.signature_public_key,
            )?,
            vrf_public_key: unhex(FILE, name, "vrf_public_key", &case.input.vrf_public_key)?,
            leaf_public_key: match &case.input.leaf_public_key {
                None => None,
                Some(key) => Some(unhex(FILE, name, "leaf_public_key", key)?),
            },
            auditor: match &case.input.auditor_public_key {
                None => None,
                Some(key) => Some(AuditorConfig {
                    max_auditor_lag: case.input.max_auditor_lag.unwrap_or_default(),
                    auditor_start_pos: case.input.auditor_start_pos.unwrap_or_default(),
                    auditor_public_key: unhex(FILE, name, "auditor_public_key", key)?,
                }),
            },
            max_ahead: case.input.max_ahead,
            max_behind: case.input.max_behind,
            reasonable_monitoring_window: case.input.reasonable_monitoring_window,
            maximum_lifetime: None,
        };
        let root = hash_field(FILE, name, "root", &case.input.root)?;

        // The configuration's encoding, which every signature depends on. This is
        // the check that pins §11.2's grouped-case ambiguity: under contact
        // monitoring the two readings differ by a length-prefixed key, so a
        // mismatch here is not a detail.
        let mut checks = vec![Check::new(
            "Configuration encoding (§11.2)",
            case.expect.configuration.clone(),
            render_result(kt_wire::codec::encode(&config), hex::encode),
        )];

        // And the peer's own bytes must decode back to the same configuration.
        let peer_config = unhex(
            FILE,
            name,
            "expect.configuration",
            &case.expect.configuration,
        )?;
        checks.push(Check::new(
            "decoding the peer's Configuration gives the same value",
            "round-trips",
            match kt_wire::codec::decode::<Configuration>(&peer_config) {
                Err(err) => format!("decode failed: {err}"),
                Ok(decoded) if decoded == config => "round-trips".to_owned(),
                Ok(_) => "decoded to a different configuration".to_owned(),
            },
        ));

        let tbs = TreeHeadTBS {
            config: config.clone(),
            tree_size: case.input.tree_size,
            root,
        };
        checks.push(Check::new(
            "TreeHeadTBS encoding — the bytes signed (§11.2)",
            case.expect.tree_head_tbs.clone(),
            render_result(kt_wire::codec::encode(&tbs), hex::encode),
        ));

        let head = TreeHead {
            tree_size: case.input.tree_size,
            signature: unhex(FILE, name, "expect.signature", &case.expect.signature)?,
        };
        checks.push(Check::new(
            "TreeHead encoding (§11.2)",
            case.expect.tree_head.clone(),
            render_result(kt_wire::codec::encode(&head), hex::encode),
        ));

        // The signature itself: the peer signed, we verify.
        checks.push(Check::new(
            "the peer's tree head signature verifies (§11.2)",
            "accepted",
            match signature::verify_tree_head(&config, &head, root) {
                Ok(()) => "accepted".to_owned(),
                Err(err) => format!("rejected: {err}"),
            },
        ));

        // §11.4's FullTreeHead, decoded from the peer's bytes and re-encoded. Both shapes
        // are here because the interesting one is not `updated` but the pair: `same` is a
        // single octet, `updated` continues, and under thirdPartyAuditing it continues
        // further still. Nothing in the bytes says which — the mode does — so a decoder
        // that takes the mode from the wrong place stays silent until it reads the next
        // structure out of the middle of this one.
        for (label, expected) in [
            ("same", &case.expect.full_tree_head_same),
            ("updated", &case.expect.full_tree_head_updated),
        ] {
            let bytes = unhex(FILE, name, "expect.full_tree_head", expected)?;
            let mut dec = Decoder::new(&bytes);
            let parsed = FullTreeHead::decode_with_mode(&mut dec, mode);
            checks.push(Check::new(
                format!("FullTreeHead `{label}` round-trips through the mode (§11.4)"),
                expected.clone(),
                match &parsed {
                    Err(err) => format!("decode failed: {err}"),
                    Ok(head) => render_result(kt_wire::codec::encode(head), hex::encode),
                },
            ));

            // And what the mode decided, stated rather than implied by a byte count: the
            // §11.2 reading recorded here puts leaf_public_key only in one mode, and this
            // is the other field the same select governs.
            let carries_auditor = matches!(
                &parsed,
                Ok(FullTreeHead::Updated {
                    auditor_tree_head: Some(_),
                    ..
                })
            );
            let expected_auditor =
                label == "updated" && mode == kt_wire::structs::DeploymentMode::ThirdPartyAuditing;
            checks.push(Check::new(
                format!("`{label}` carries an auditor head only under thirdPartyAuditing (§11.4)"),
                expected_auditor.to_string(),
                carries_auditor.to_string(),
            ));
        }

        // The auditor's head, where the mode has one (§11.3).
        if let (Some(expected_tbs), Some(expected_head), Some(timestamp)) = (
            case.expect.auditor_tree_head_tbs.as_deref(),
            case.expect.auditor_tree_head.as_deref(),
            case.input.auditor_timestamp,
        ) {
            let auditor_tbs = AuditorTreeHeadTBS {
                config: config.clone(),
                timestamp,
                tree_size: case.input.tree_size,
                root,
            };
            checks.push(Check::new(
                "AuditorTreeHeadTBS encoding (§11.3)",
                expected_tbs,
                render_result(kt_wire::codec::encode(&auditor_tbs), hex::encode),
            ));

            let bytes = unhex(FILE, name, "expect.auditor_tree_head", expected_head)?;
            let parsed = kt_wire::codec::decode::<AuditorTreeHead>(&bytes);
            checks.push(Check::new(
                "the auditor's signature verifies (§11.3)",
                "accepted",
                match &parsed {
                    Err(err) => format!("decode failed: {err}"),
                    Ok(auditor) => match signature::verify_auditor_tree_head(
                        &config,
                        auditor,
                        case.input.tree_size,
                        root,
                    ) {
                        Ok(()) => "accepted".to_owned(),
                        Err(err) => format!("rejected: {err}"),
                    },
                },
            ));

            // And the whole FullTreeHead, which is what a client actually receives.
            if let Ok(auditor) = parsed {
                let full = FullTreeHead::Updated {
                    tree_head: head.clone(),
                    auditor_tree_head: Some(auditor),
                };
                let verified = signature::verify_full_tree_head(
                    &config,
                    &full,
                    signature::Advertised::default(),
                    |size| (size == case.input.tree_size).then_some(root),
                );
                checks.push(Check::new(
                    "FullTreeHead verification accepts the peer's heads (§11.4)",
                    "accepted",
                    match verified {
                        Ok(Some(_)) => "accepted".to_owned(),
                        Ok(None) => "accepted but returned no head".to_owned(),
                        Err(err) => format!("rejected: {err}"),
                    },
                ));
            }
        } else {
            // In the other modes a FullTreeHead carries no auditor head.
            let full = FullTreeHead::Updated {
                tree_head: head.clone(),
                auditor_tree_head: None,
            };
            let verified = signature::verify_full_tree_head(
                &config,
                &full,
                signature::Advertised::default(),
                |size| (size == case.input.tree_size).then_some(root),
            );
            checks.push(Check::new(
                "FullTreeHead verification accepts the peer's head (§11.4)",
                "accepted",
                match verified {
                    Ok(Some(_)) => "accepted".to_owned(),
                    Ok(None) => "accepted but returned no head".to_owned(),
                    Err(err) => format!("rejected: {err}"),
                },
            ));
        }

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: format!("{mode:?}, tree size {}", case.input.tree_size),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Tree head signatures".to_owned(),
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

/// §4.2: the entries a user needs in order to advance their view.
fn update_view_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "update-view.json";
    let file: VectorFile<UpdateViewInput, UpdateViewExpect> = load(dir, FILE)?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let size = case.input.size;
        let advertised = case.input.advertised;

        let mut checks = vec![Check::new(
            "update_view(size, advertised) (§4.2)",
            render_list(&case.expect.entries),
            render_result(ibst::update_view(size, advertised), |entries| {
                render_list(&entries)
            }),
        )];

        if let Some(expected) = &case.expect.frontier {
            checks.push(Check::new(
                "frontier(size) (§4.1)",
                render_list(expected),
                render_result(ibst::frontier(size), |f| render_list(&f)),
            ));
        }

        // The peer agreeing about the cases that yield nothing is what makes the
        // §4.2 gap a property of the procedure rather than of either implementation.
        if let Some(expected) = case.expect.right_edge_unchecked {
            checks.push(Check::new(
                "whether the rightmost entry is left unchecked (§4.2)",
                expected.to_string(),
                render_result(
                    ibst::leaves_right_edge_unchecked(size, advertised),
                    |flag| flag.to_string(),
                ),
            ));
        }

        cases.push(Case {
            name: case.name.clone(),
            negative: false,
            input: match advertised {
                None => format!("log of {size} entries, no previous view"),
                Some(previous) => format!("log of {size} entries, advertised {previous}"),
            },
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Updating a view".to_owned(),
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

/// §11.5 and §13.1–§13.5: the request structures and the response building blocks.
///
/// Each case is one structure's encoding, and each also decodes back — the round trip
/// is where a presence octet read in the wrong place shows up, since a wrong reading
/// usually still produces *some* value.
fn request_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "requests.json";
    let file: VectorFile<RequestInput, RequestExpect> = load(dir, FILE)?;

    let code = file.cipher_suite.unwrap_or_default();
    let suite = CipherSuite::from_code(code).map_err(|_| Error::CipherSuite {
        file: FILE.to_owned(),
        value: code,
    })?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let name = case.name.as_str();
        let expected = case.expect.encoding.clone();

        // Every arm produces the encoding plus a round-trip verdict, so that a
        // decoder which merely happens to produce *a* value is not mistaken for one
        // that reads the same fields.
        let (what, encoded, round_trip) = match &case.input {
            RequestInput::SearchRequest {
                last,
                label,
                version,
            } => {
                let request = SearchRequest {
                    last: *last,
                    label: unhex(FILE, name, "label", label)?,
                    version: *version,
                };
                let encoded = kt_wire::codec::encode(&request);
                let round_trip = round_trips::<SearchRequest>(&expected, &request, FILE, name)?;
                ("SearchRequest (§13.1)", encoded, round_trip)
            }
            RequestInput::BinaryLadderStep { proof, commitment } => {
                let step = BinaryLadderStep {
                    proof: unhex(FILE, name, "proof", proof)?,
                    commitment: match commitment {
                        None => None,
                        Some(value) => Some(hash_field(FILE, name, "commitment", value)?),
                    },
                };
                let encoded = kt_wire::codec::encode(&step);
                // Decoding needs VRF.Np from the suite, which the bytes do not carry.
                let bytes = unhex(FILE, name, "expect.encoding", &expected)?;
                let mut dec = Decoder::new(&bytes);
                let proof_size = step.proof.len();
                let round_trip =
                    match BinaryLadderStep::decode_with_proof_size(&mut dec, proof_size) {
                        Err(err) => format!("decode failed: {err}"),
                        Ok(back) => match dec.finish() {
                            Err(err) => format!("trailing bytes: {err}"),
                            Ok(()) if back == step => "round-trips".to_owned(),
                            Ok(()) => "decoded to a different value".to_owned(),
                        },
                    };
                ("BinaryLadderStep (§13.1)", encoded, round_trip)
            }
            RequestInput::MonitorMapEntry { position, version } => {
                let entry = MonitorMapEntry {
                    position: *position,
                    version: *version,
                };
                let encoded = kt_wire::codec::encode(&entry);
                let round_trip = round_trips::<MonitorMapEntry>(&expected, &entry, FILE, name)?;
                ("MonitorMapEntry (§13.2)", encoded, round_trip)
            }
            RequestInput::ContactMonitorRequest {
                last,
                label,
                entries,
            } => {
                let request = ContactMonitorRequest {
                    last: *last,
                    label: unhex(FILE, name, "label", label)?,
                    entries: entries
                        .iter()
                        .map(|e| MonitorMapEntry {
                            position: e.position,
                            version: e.version,
                        })
                        .collect(),
                };
                let encoded = kt_wire::codec::encode(&request);
                let round_trip =
                    round_trips::<ContactMonitorRequest>(&expected, &request, FILE, name)?;
                ("ContactMonitorRequest (§13.2)", encoded, round_trip)
            }
            RequestInput::OwnerInitRequest { last, label, start } => {
                let request = OwnerInitRequest {
                    last: *last,
                    label: unhex(FILE, name, "label", label)?,
                    start: *start,
                };
                let encoded = kt_wire::codec::encode(&request);
                let round_trip = round_trips::<OwnerInitRequest>(&expected, &request, FILE, name)?;
                ("OwnerInitRequest (§13.3)", encoded, round_trip)
            }
            RequestInput::OwnerMonitorRequest {
                last,
                label,
                entries,
                start,
                greatest_version,
            } => {
                let request = OwnerMonitorRequest {
                    last: *last,
                    label: unhex(FILE, name, "label", label)?,
                    entries: entries
                        .iter()
                        .map(|e| MonitorMapEntry {
                            position: e.position,
                            version: e.version,
                        })
                        .collect(),
                    start: *start,
                    greatest_version: *greatest_version,
                };
                let encoded = kt_wire::codec::encode(&request);
                let round_trip =
                    round_trips::<OwnerMonitorRequest>(&expected, &request, FILE, name)?;
                ("OwnerMonitorRequest (§13.4)", encoded, round_trip)
            }
            RequestInput::LabelValue { value } => {
                let label_value = LabelValue::new(unhex(FILE, name, "value", value)?);
                let encoded = kt_wire::codec::encode(&label_value);
                let round_trip = round_trips::<LabelValue>(&expected, &label_value, FILE, name)?;
                ("LabelValue (§13.5)", encoded, round_trip)
            }
            RequestInput::UpdateInfo { opening, mode } => {
                let mode = DeploymentMode::from_u8(*mode).map_err(|_| Error::Computation {
                    file: FILE.to_owned(),
                    case: name.to_owned(),
                    detail: format!("unknown deployment mode {mode}"),
                })?;
                let info = UpdateInfo {
                    opening: unhex(FILE, name, "opening", opening)?,
                    suffix: UpdateSuffix::Empty,
                };
                let encoded = kt_wire::codec::encode(&info);
                // Needs both Nc and the mode; neither is in the bytes.
                let bytes = unhex(FILE, name, "expect.encoding", &expected)?;
                let mut dec = Decoder::new(&bytes);
                let round_trip = match UpdateInfo::decode_with(&mut dec, suite.nc(), mode) {
                    Err(err) => format!("decode failed: {err}"),
                    Ok(back) => match dec.finish() {
                        Err(err) => format!("trailing bytes: {err}"),
                        Ok(()) if back == info => "round-trips".to_owned(),
                        Ok(()) => "decoded to a different value".to_owned(),
                    },
                };
                ("UpdateInfo (§13.5)", encoded, round_trip)
            }
            RequestInput::UpdateRequest {
                last,
                label,
                greatest_version,
                values,
            } => {
                let mut label_values = Vec::new();
                for value in values {
                    label_values.push(LabelValue::new(unhex(FILE, name, "values[]", value)?));
                }
                let request = UpdateRequest {
                    last: *last,
                    label: unhex(FILE, name, "label", label)?,
                    greatest_version: *greatest_version,
                    values: label_values,
                };
                let encoded = kt_wire::codec::encode(&request);
                let round_trip = round_trips::<UpdateRequest>(&expected, &request, FILE, name)?;
                ("UpdateRequest (§13.5)", encoded, round_trip)
            }
            RequestInput::UpdateTbs {
                configuration,
                label,
                version,
                value,
            } => {
                // The configuration comes from the peer's own bytes: this case is
                // about what UpdateTBS puts around it, not about the config itself.
                let config_bytes = unhex(FILE, name, "configuration", configuration)?;
                let config =
                    kt_wire::codec::decode::<Configuration>(&config_bytes).map_err(|err| {
                        Error::Computation {
                            file: FILE.to_owned(),
                            case: name.to_owned(),
                            detail: format!("decoding the configuration: {err}"),
                        }
                    })?;
                let tbs = UpdateTBS {
                    config,
                    label: unhex(FILE, name, "label", label)?,
                    version: *version,
                    value: unhex(FILE, name, "value", value)?,
                };
                let encoded = kt_wire::codec::encode(&tbs);
                let round_trip = round_trips::<UpdateTBS>(&expected, &tbs, FILE, name)?;
                ("UpdateTBS (§11.5)", encoded, round_trip)
            }
        };

        cases.push(Case {
            name: name.to_owned(),
            negative: false,
            input: what.to_owned(),
            checks: vec![
                Check::new(
                    format!("{what} encoding"),
                    expected,
                    render_result(encoded, hex::encode),
                ),
                Check::new(format!("{what} decodes back"), "round-trips", round_trip),
            ],
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Requests and building blocks".to_owned(),
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

/// Decodes the peer's bytes and checks the result equals what we built.
///
/// Encoding agreement alone is weaker than it looks: a decoder that reads the fields
/// in the wrong order still produces a value, and only a comparison catches it.
fn round_trips<T>(expected_hex: &str, original: &T, file: &str, case: &str) -> Result<String, Error>
where
    T: kt_wire::codec::Decode + PartialEq,
{
    let bytes = unhex(file, case, "expect.encoding", expected_hex)?;
    Ok(match kt_wire::codec::decode::<T>(&bytes) {
        Err(err) => format!("decode failed: {err}"),
        Ok(back) if back == *original => "round-trips".to_owned(),
        Ok(_) => "decoded to a different value".to_owned(),
    })
}

/// §6.2: what a search ladder's outcomes say about the greatest version.
fn interpretation_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "ladder-interpretation.json";
    let file: VectorFile<InterpretationInput, InterpretationExpect> = load(dir, FILE)?;

    let mut cases = Vec::new();
    for case in &file.cases {
        let results: Vec<kt_wire::proofs::PrefixSearchResult> = case
            .input
            .results
            .iter()
            .map(|included| {
                if *included {
                    kt_wire::proofs::PrefixSearchResult::Inclusion { depth: 0 }
                } else {
                    kt_wire::proofs::PrefixSearchResult::NonInclusionParent { depth: 0 }
                }
            })
            .collect();

        let mut checks = vec![Check::new(
            "the ladder itself (§6.2)",
            render_list(&case.input.ladder),
            render_result(
                ladder::search_binary_ladder(case.input.target, case.input.greatest, &[], &[]),
                |versions| render_list(&versions),
            ),
        )];

        // The verdict, rendered as the peer's -1/0/1 so the comparison is direct.
        let verdict = match ladder::interpret_search_ladder(
            &case.input.ladder,
            case.input.target,
            &results,
        ) {
            Err(err) => format!("refused: {err}"),
            Ok(core::cmp::Ordering::Less) => "-1".to_owned(),
            Ok(core::cmp::Ordering::Equal) => "0".to_owned(),
            Ok(core::cmp::Ordering::Greater) => "1".to_owned(),
        };
        checks.push(Check::new(
            "interpret_search_ladder: is the greatest version below, at, or above the target (§6.2)",
            case.expect.verdict.to_string(),
            verdict,
        ));

        cases.push(Case {
            name: case.name.clone(),
            negative: false,
            input: format!(
                "target {}, greatest {}",
                case.input.target, case.input.greatest
            ),
            checks,
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Search ladder interpretation".to_owned(),
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

/// §3.2, §4.2, §12.1 in the peer's flat node addressing.
///
/// `log-tree.json` pins the proof bytes; this pins the decomposition behind them. Two
/// implementations can agree on every proof we happen to generate while taking the
/// tree apart differently, and only comparing the node indices rules that out.
///
/// The file holds well over a thousand cases, which is the right number for CI and the
/// wrong number for a page a person reads. So they are grouped by tree size: one
/// rendered case per size, with every individual comparison as a sub-check. Nothing is
/// dropped — `report.json` carries them all — but the page does not gain a thousand
/// rows whose interest is collective rather than individual. The same treatment the
/// implicit binary search tree's per-node checks already get.
fn log_math_suite(dir: &Path) -> Result<Suite, Error> {
    const FILE: &str = "log-math.json";
    let file: VectorFile<LogMathInput, LogMathExpect> = load(dir, FILE)?;
    let suite = CipherSuite::Kt128Sha256Ed25519;

    // Group by tree size, preserving the order the cases appear in.
    let mut sizes: Vec<u64> = Vec::new();
    let mut grouped: BTreeMap<u64, Vec<Check>> = BTreeMap::new();

    for case in &file.cases {
        let expected = render_list(&case.expect.indices);
        let (size, what, got) = match &case.input {
            LogMathInput::FullSubtrees { size } => (
                *size,
                "full subtree heads, as node indices (§4.2)".to_owned(),
                render_result(log::full_subtree_indices(*size), |indices| {
                    render_list(&indices)
                }),
            ),
            LogMathInput::BatchCopath {
                size,
                leaves,
                retained_size,
            } => {
                // Only which nodes the walk emits matters here, not their values, so
                // any leaf values will do.
                let values: Vec<HashValue> = (0..*size)
                    .map(|i| {
                        HashValue::from_bytes([u8::try_from(i % 256).unwrap_or(0); HashValue::SIZE])
                    })
                    .collect();
                let retained = match retained_size {
                    None => None,
                    Some(previous) => Some(
                        log::Retained::from_leaves(suite, *previous, &values).map_err(|err| {
                            Error::Computation {
                                file: FILE.to_owned(),
                                case: case.name.clone(),
                                detail: alloc_display(&err),
                            }
                        })?,
                    ),
                };
                let label = match retained_size {
                    None => format!("leaves {}", render_list(leaves)),
                    Some(previous) => {
                        format!("leaves {}, retained {previous}", render_list(leaves))
                    }
                };
                (
                    *size,
                    format!("batch proof nodes for {label} (§12.1)"),
                    render_result(
                        log::proof_node_indices(*size, leaves, retained.as_ref()),
                        |indices| render_list(&indices),
                    ),
                )
            }
        };

        if !grouped.contains_key(&size) {
            sizes.push(size);
        }
        grouped
            .entry(size)
            .or_default()
            .push(Check::new(what, expected, got));
    }

    let mut cases = Vec::new();
    for size in sizes {
        let checks = grouped.remove(&size).unwrap_or_default();
        let count = checks.len();
        cases.push(Case {
            name: format!("size-{size}"),
            negative: false,
            input: format!("log of {size} entries, {count} decompositions"),
            checks: vec![Check::group(
                format!("node indices for a log of {size} entries (§3.2, §4.2, §12.1)"),
                checks,
            )],
        });
    }

    Ok(Suite {
        primitive: file.primitive,
        title: "Log tree structure".to_owned(),
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

fn alloc_display(err: &impl core::fmt::Display) -> String {
    format!("{err}")
}
