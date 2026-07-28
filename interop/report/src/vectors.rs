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

/// `log-tree.json` input (§3.2, §11.8, §12.1).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogTreeInput {
    /// The log's entries, in order.
    pub entries: Vec<LogEntryInput>,
    /// The batch proofs to ask for, paired positionally with
    /// [`LogTreeExpect::proofs`].
    pub requests: Vec<LogProofRequest>,
}

/// One `LogEntry` (§11.8).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogEntryInput {
    /// Milliseconds since the Unix epoch.
    pub timestamp: u64,
    /// The prefix tree root as of this entry, hex.
    pub prefix_tree: String,
}

/// One batch proof request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogProofRequest {
    /// Leaf indices to prove included.
    pub proven_leaves: Vec<u64>,
    /// A smaller tree the verifier already observed, if any.
    #[serde(default)]
    pub retained_size: Option<u64>,
}

/// `log-tree.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogTreeExpect {
    /// `Hash(LogEntry)` for each entry, hex.
    pub leaf_values: Vec<String>,
    /// The tree root, hex.
    pub root: String,
    /// Full subtree heads for this size, left to right, hex.
    pub full_subtrees: Vec<String>,
    /// The proofs, paired positionally with the requests.
    pub proofs: Vec<LogProofExpect>,
}

/// One proof the peer produced.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogProofExpect {
    /// The wire-encoded `InclusionProof`, hex.
    pub proof: String,
    /// Its elements, hex.
    pub elements: Vec<String>,
}

/// `prefix-tree.json` input (§3.3, §11.9, §12.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixTreeInput {
    /// Entries to insert, in order.
    pub entries: Vec<PrefixEntryInput>,
    /// Search keys to look up as one batch, hex.
    pub searches: Vec<String>,
}

/// One prefix tree entry.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixEntryInput {
    /// The search key, hex.
    pub vrf_output: String,
    /// The commitment, hex.
    pub commitment: String,
}

/// `prefix-tree.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixTreeExpect {
    /// The tree root, hex.
    pub root: String,
    /// The wire-encoded `PrefixProof`, hex.
    pub proof: String,
    /// One result per search.
    pub results: Vec<PrefixResultExpect>,
    /// Copath values, hex.
    pub elements: Vec<String>,
    /// Commitments the peer found, in request order, hex.
    pub commitments: Vec<String>,
}

/// One `PrefixSearchResult` (§12.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PrefixResultExpect {
    /// 1 = inclusion, 2 = nonInclusionLeaf, 3 = nonInclusionParent.
    pub result_type: u8,
    /// Bits consumed to reach the terminal node.
    pub depth: u8,
    /// The leaf found instead, for `nonInclusionLeaf`.
    #[serde(default)]
    pub leaf: Option<PrefixEntryInput>,
}

/// `vrf.json` input (§11.7).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrfCaseInput {
    /// The VRF secret key seed, hex.
    pub private_key: String,
    /// The matching public key, hex.
    pub public_key: String,
    /// The label, hex.
    pub label: String,
    /// The version.
    pub version: u32,
    /// On negative cases, a proof that must not verify for this pair.
    #[serde(default)]
    pub proof: Option<String>,
}

/// `vrf.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VrfExpect {
    /// The encoded `VrfInput` that is `alpha_string`, hex.
    #[serde(default)]
    pub vrf_input: Option<String>,
    /// The 32-byte output, i.e. the search key, hex.
    #[serde(default)]
    pub output: Option<String>,
    /// The 80-byte proof, hex.
    #[serde(default)]
    pub proof: Option<String>,
    /// Set on cases that must be rejected.
    #[serde(default)]
    pub error: bool,
}

/// `tampered.json` input: what to check, and with which primitive.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum TamperedInput {
    /// A log tree batch proof that must not reach `root` (§12.1).
    LogTree {
        /// The log size.
        size: u64,
        /// Leaf indices claimed proven.
        entries: Vec<u64>,
        /// Their claimed values, hex.
        values: Vec<String>,
        /// A retained view's size, if the case uses one.
        #[serde(default)]
        retained_size: Option<u64>,
        /// The retained full subtree heads, hex.
        #[serde(default)]
        retained: Vec<String>,
        /// The proof's elements, hex.
        elements: Vec<String>,
        /// The root it must not reach, hex.
        root: String,
    },
    /// A prefix tree proof that must not verify (§12.2).
    PrefixTree {
        /// The searches, in request order.
        searches: Vec<TamperedSearch>,
        /// The wire-encoded `PrefixProof`, hex.
        proof: String,
        /// The root it must not verify against, hex.
        root: String,
    },
    /// A VRF proof that must not verify (§11.7).
    Vrf {
        /// The public key to check against, hex.
        public_key: String,
        /// The label, hex.
        label: String,
        /// The version.
        version: u32,
        /// The proof, hex.
        proof: String,
    },
    /// A commitment opening that must not verify (§11.6).
    Commitment {
        /// The opening, hex.
        opening: String,
        /// The label, hex.
        label: String,
        /// The version.
        version: u32,
        /// The update being opened to.
        update: UpdateInput,
        /// The commitment it must not open, hex.
        commitment: String,
    },
}

/// One search in a tampered prefix-tree case.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TamperedSearch {
    /// The search key, hex.
    pub vrf_output: String,
    /// The commitment expected, for inclusion results, hex.
    #[serde(default)]
    pub commitment: Option<String>,
}

/// `tampered.json` expectations: always a rejection, plus what was corrupted.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TamperedExpect {
    /// Always true; the field exists so the format matches every other file's
    /// negative cases.
    pub error: bool,
    /// A description of the corruption, for the report.
    pub tamper: String,
}
