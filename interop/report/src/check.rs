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
use kt_tree::{ibst, ladder};
use kt_wire::codec::Decoder;
use kt_wire::structs::{CommitmentValue, DeploymentMode, UpdateSuffix, UpdateValue};

use crate::report::{Case, Check, Generator, Suite};
use crate::vectors::{
    CommitmentExpect, CommitmentInput, IbstExpect, IbstInput, LadderExpect, LadderInput, VectorFile,
};

/// The vector files this crate knows how to check, in dependency order.
pub const FILES: [&str; 3] = ["commitment.json", "ibst.json", "binary-ladder.json"];

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
