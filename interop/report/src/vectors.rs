//! The on-disk vector format (`interop/README.md`).
//!
//! These types are the file contract, not a convenience: `deny_unknown_fields`
//! everywhere means that if the Go generator starts emitting a field this crate
//! does not know about, loading fails loudly instead of silently checking less
//! than the file describes.

use serde::Deserialize;

/// A vector file, generic over the shape of its cases so all three files can
/// share the envelope.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VectorFile<I, E> {
    /// The primitive under test, matching the file name.
    pub primitive: String,
    /// The draft revision and section the vectors are taken from.
    pub draft: String,
    /// Which implementation produced the expected values, and at which commit.
    pub generator: Generator,
    /// The IANA `CipherSuite` value, absent for suite-independent primitives.
    #[serde(default)]
    pub cipher_suite: Option<u16>,
    /// Free-text provenance notes from the generator.
    #[serde(default)]
    pub notes: String,
    /// The cases themselves.
    pub cases: Vec<Case<I, E>>,
}

/// Where a file's expected values came from.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generator {
    /// The implementation name, e.g. `katie`.
    #[serde(rename = "impl")]
    pub implementation: String,
    /// The full git object id of that implementation's commit.
    pub sha: String,
}

/// One named case.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case<I, E> {
    /// Stable identifier, unique within the file.
    pub name: String,
    /// What to compute.
    pub input: I,
    /// What the peer computed.
    pub expect: E,
}

/// `commitment.json` input (§11.6).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentInput {
    /// `opaque opening[Nc]`, hex.
    pub opening: String,
    /// `opaque label<0..2^8-1>`, hex.
    pub label: String,
    /// `uint32 version`.
    pub version: u32,
    /// The `UpdateValue` being committed to.
    pub update: UpdateInput,
    /// On negative cases, the commitment that must *not* verify.
    #[serde(default)]
    pub commitment: Option<String>,
}

/// `UpdateValue` fields (§11.5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateInput {
    /// `opaque value<0..2^32-1>`, hex.
    pub value: String,
    /// The Service Operator signature, under `thirdPartyManagement` only.
    #[serde(default)]
    pub signature: Option<String>,
}

/// `commitment.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitmentExpect {
    /// The commitment, hex.
    #[serde(default)]
    pub commitment: Option<String>,
    /// The serialized `CommitmentValue` that gets HMAC'd, hex.
    #[serde(default)]
    pub commitment_value: Option<String>,
    /// Set on cases that must be rejected.
    #[serde(default)]
    pub error: bool,
}

/// `ibst.json` input (§4.1).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IbstInput {
    /// The number of entries in the log.
    pub size: u64,
}

/// `ibst.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IbstExpect {
    /// The root of the search over a log of this size.
    pub root: u64,
    /// The root, then repeated right children to the last entry.
    pub frontier: Vec<u64>,
    /// Per-node children.
    pub nodes: Vec<NodeExpect>,
}

/// One node's children. `None` means the input has no answer and must be
/// refused: `left` for a leaf, `right` for the rightmost entry of the log.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeExpect {
    /// The node's index.
    pub index: u64,
    /// Its left child, or `None` if it is a leaf.
    pub left: Option<u64>,
    /// Its right child, or `None` if its right subtree is empty.
    pub right: Option<u64>,
}

/// `binary-ladder.json` input (§5), tagged by variant.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "lowercase", deny_unknown_fields)]
pub enum LadderInput {
    /// The full ladder that pins a greatest version (§5).
    Base {
        /// The greatest version of the label that exists.
        greatest: u32,
    },
    /// A search ladder for a target version (§6.2).
    Search {
        /// The version being searched for.
        target: u32,
        /// The greatest version of the label that exists.
        greatest: u32,
        /// Versions already proven included by an entry to the left.
        left_inclusion: Vec<u32>,
        /// Versions already proven absent by an entry to the right.
        right_non_inclusion: Vec<u32>,
    },
    /// A monitoring ladder for a monitored version (§8.1).
    Monitoring {
        /// The version being monitored.
        target: u32,
        /// Versions already proven included by an entry to the left.
        left_inclusion: Vec<u32>,
    },
}

/// `binary-ladder.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LadderExpect {
    /// The versions looked up, in order.
    pub versions: Vec<u32>,
}
