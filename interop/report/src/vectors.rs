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

/// `prefix-mutation.json` input (§15.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationInput {
    /// Entries the tree holds before the update, in insertion order.
    pub entries: Vec<PrefixEntryInput>,
    /// Leaves the update adds.
    pub add: Vec<PrefixEntryInput>,
    /// Leaves the update removes.
    pub remove: Vec<PrefixEntryInput>,
    /// Set where a removal empties a slot whose sibling is a bare copath hash, so
    /// §3.3's collapse rests on a node type the proof does not reveal.
    #[serde(default)]
    pub sibling_uncovered: bool,
}

/// `prefix-mutation.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MutationExpect {
    /// Root of the peer's own tree before the update, hex.
    pub before: String,
    /// Root of the peer's own tree after the update, hex.
    pub after: String,
    /// The wire-encoded batch `PrefixProof`, hex.
    pub proof: String,
    /// One result per key, additions then removals.
    pub results: Vec<PrefixResultExpect>,
    /// Copath values, hex.
    pub elements: Vec<String>,
    /// What the peer's own verifier reconstructs for the "before" root, hex; absent
    /// where it declined the update.
    #[serde(default)]
    pub peer_before: Option<String>,
    /// What the peer's own verifier reconstructs for the "after" root, hex; absent
    /// where it declined the update.
    #[serde(default)]
    pub peer_after: Option<String>,
    /// Why the peer declined, where it did.
    #[serde(default)]
    pub peer_error: Option<String>,
}

/// `distinguished.json` input (§6.1).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistinguishedInput {
    /// The tree size.
    pub size: u64,
    /// The Reasonable Monitoring Window.
    pub window: u64,
    /// Timestamp per log entry, indexed by position.
    pub timestamps: Vec<u64>,
}

/// `distinguished.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DistinguishedExpect {
    /// The rightmost distinguished entry, absent where there is none.
    #[serde(default)]
    pub rightmost: Option<u64>,
    /// The rightmost distinguished entry left of the log's last entry.
    #[serde(default)]
    pub previous_rightmost: Option<u64>,
    /// Every position the peer asked a timestamp for, deduplicated and sorted.
    pub requested: Vec<u64>,
    /// Positions the peer asked about while finding `rightmost`, in order.
    pub requested_rightmost: Vec<u64>,
    /// Positions the peer asked about while finding `previous_rightmost`, in order.
    pub requested_previous: Vec<u64>,
}

/// `log-append.json` input (§3.2, §11.8).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendInput {
    /// The tree size after the append.
    pub size: u64,
    /// The entry appended, as a one-element list.
    pub entries: Vec<LogEntryInput>,
    /// Every leaf value in the resulting tree, hex.
    pub leaves: Vec<String>,
}

/// `log-append.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AppendExpect {
    /// Full subtree heads, left to right, hex.
    pub full_subtrees: Vec<String>,
    /// The root they fold to, hex.
    pub root: String,
}

/// `auditor-update.json` input (§15.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditorInput {
    /// Entries the previous log entry's prefix tree holds.
    pub entries: Vec<PrefixEntryInput>,
    /// The Reasonable Monitoring Window, which §15.2 step 5 needs (§6.1).
    pub window: u64,
    /// Timestamp of the previous log entry.
    pub previous_timestamp: u64,
    /// What the peer's auditor was still tracking for step 5 after priming: insertions no
    /// distinguished log entry has covered yet.
    pub inserted: Vec<InsertedInput>,
    /// The peer auditor's log tree size before this update.
    pub log_size: u64,
    /// Its retained full subtree heads, hex.
    pub log_full_subtrees: Vec<String>,
    /// Its retained frontier timestamps, in frontier order.
    pub frontier_timestamps: Vec<u64>,
    /// Timestamp the update carries.
    pub timestamp: u64,
    /// Leaves the update adds.
    pub added: Vec<PrefixEntryInput>,
    /// Leaves the update removes.
    pub removed: Vec<PrefixEntryInput>,
    /// The prefix tree root the auditor holds, hex.
    pub prefix_root: String,
    /// Set where the update is the first the auditor has ever seen, so there is no
    /// previous state to check against.
    #[serde(default)]
    pub first_entry: bool,
}

/// One recorded insertion (§15.2 step 5).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InsertedInput {
    /// The log entry that inserted it.
    pub position: u64,
    /// The search key inserted, hex.
    pub vrf_output: String,
}

/// `auditor-update.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AuditorExpect {
    /// The wire-encoded `AuditorUpdate`, hex.
    pub encoding: String,
    /// `"accepted"` or `"rejected"`.
    pub verdict: String,
    /// How the peer worded its refusal, where it refused.
    #[serde(default)]
    pub peer_detail: Option<String>,
    /// The log tree size after the update, where it was accepted.
    #[serde(default)]
    pub tree_size: Option<u64>,
    /// The log tree root over the new entry, hex, where the update was accepted. This is
    /// what an `AuditorTreeHead` for `tree_size` is signed over (§11.3).
    #[serde(default)]
    pub log_root: Option<String>,
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
    /// A tree head signature that must not verify (§11.2).
    TreeHead {
        /// The `DeploymentMode` registry value.
        mode: u8,
        /// The key the configuration names, hex.
        signature_public_key: String,
        /// The VRF public key, hex.
        vrf_public_key: String,
        /// How far ahead a head may be.
        max_ahead: u64,
        /// How far behind.
        max_behind: u64,
        /// The Reasonable Monitoring Window.
        reasonable_monitoring_window: u64,
        /// The tree size claimed.
        tree_size: u64,
        /// The root, hex.
        root: String,
        /// The signature that must not verify, hex.
        signature: String,
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

/// `tree-head.json` input (§11.2, §11.3).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadInput {
    /// The `DeploymentMode` registry value.
    pub mode: u8,
    /// The key that verifies tree head signatures, hex.
    pub signature_public_key: String,
    /// The VRF public key, hex.
    pub vrf_public_key: String,
    /// The Service Operator's key, under `thirdPartyManagement`, hex.
    #[serde(default)]
    pub leaf_public_key: Option<String>,
    /// The auditor's permitted lag, under `thirdPartyAuditing`.
    #[serde(default)]
    pub max_auditor_lag: Option<u64>,
    /// The auditor's start position.
    #[serde(default)]
    pub auditor_start_pos: Option<u64>,
    /// The auditor's key, hex.
    #[serde(default)]
    pub auditor_public_key: Option<String>,
    /// When the auditor signed.
    #[serde(default)]
    pub auditor_timestamp: Option<u64>,
    /// How far ahead a head may be.
    pub max_ahead: u64,
    /// How far behind.
    pub max_behind: u64,
    /// The Reasonable Monitoring Window.
    pub reasonable_monitoring_window: u64,
    /// The tree size being signed.
    pub tree_size: u64,
    /// The log tree root at that size, hex.
    pub root: String,
}

/// `tree-head.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HeadExpect {
    /// The encoded `Configuration`, hex.
    pub configuration: String,
    /// The encoded `TreeHeadTBS` — what the signature covers, hex.
    pub tree_head_tbs: String,
    /// The encoded `TreeHead`, hex.
    pub tree_head: String,
    /// The signature alone, hex.
    pub signature: String,
    /// The encoded `AuditorTreeHeadTBS`, under `thirdPartyAuditing`, hex.
    #[serde(default)]
    pub auditor_tree_head_tbs: Option<String>,
    /// The encoded `AuditorTreeHead`, hex.
    #[serde(default)]
    pub auditor_tree_head: Option<String>,
    /// A `FullTreeHead` of type `same`, hex.
    pub full_tree_head_same: String,
    /// A `FullTreeHead` of type `updated`, hex — carrying an `AuditorTreeHead` only where
    /// the deployment mode calls for one.
    pub full_tree_head_updated: String,
}

/// `update-view.json` input (§4.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateViewInput {
    /// The log's current size.
    pub size: u64,
    /// The size the user last observed, absent if they have none.
    #[serde(default)]
    pub advertised: Option<u64>,
}

/// `update-view.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UpdateViewExpect {
    /// The entry indices whose timestamps must be provided, in check order.
    pub entries: Vec<u64>,
    /// The frontier, on the no-previous-view cases.
    #[serde(default)]
    pub frontier: Option<Vec<u64>>,
    /// Whether the procedure leaves the rightmost entry unchecked.
    #[serde(default)]
    pub right_edge_unchecked: Option<bool>,
}

/// `requests.json` input: which §13 structure, and its fields.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum RequestInput {
    /// §13.1 `SearchRequest`.
    SearchRequest {
        /// The tree size last observed.
        #[serde(default)]
        last: Option<u64>,
        /// The label, hex.
        label: String,
        /// The exact version wanted, absent for the greatest.
        #[serde(default)]
        version: Option<u32>,
    },
    /// §13.1 `BinaryLadderStep`.
    BinaryLadderStep {
        /// The VRF proof, hex.
        proof: String,
        /// The commitment, absent when the version does not exist, hex.
        #[serde(default)]
        commitment: Option<String>,
    },
    /// §13.2 `MonitorMapEntry`.
    MonitorMapEntry {
        /// The log entry position.
        position: u64,
        /// The version at that position.
        version: u32,
    },
    /// §13.2 `ContactMonitorRequest`.
    ContactMonitorRequest {
        /// The tree size last observed.
        #[serde(default)]
        last: Option<u64>,
        /// The label, hex.
        label: String,
        /// The monitoring state.
        entries: Vec<MonitorEntryInput>,
    },
    /// §13.3 `OwnerInitRequest`.
    OwnerInitRequest {
        /// The tree size last observed.
        #[serde(default)]
        last: Option<u64>,
        /// The label, hex.
        label: String,
        /// The distinguished entry to start from.
        start: u64,
    },
    /// §13.4 `OwnerMonitorRequest`.
    OwnerMonitorRequest {
        /// The tree size last observed.
        #[serde(default)]
        last: Option<u64>,
        /// The label, hex.
        label: String,
        /// The monitoring state.
        entries: Vec<MonitorEntryInput>,
        /// The rightmost distinguished entry.
        start: u64,
        /// The greatest version known.
        #[serde(default)]
        greatest_version: Option<u32>,
    },
    /// §13.5 `LabelValue`.
    LabelValue {
        /// The value, hex.
        value: String,
    },
    /// §13.5 `UpdateInfo`.
    UpdateInfo {
        /// The commitment opening, hex.
        opening: String,
        /// The `DeploymentMode` registry value.
        mode: u8,
    },
    /// §13.5 `UpdateRequest`.
    UpdateRequest {
        /// The tree size last observed.
        #[serde(default)]
        last: Option<u64>,
        /// The label, hex.
        label: String,
        /// The greatest version known.
        #[serde(default)]
        greatest_version: Option<u32>,
        /// The values to publish, hex.
        values: Vec<String>,
    },
    /// §11.5 `UpdateTBS`.
    UpdateTbs {
        /// The encoded `Configuration` this TBS begins with, hex.
        configuration: String,
        /// The label, hex.
        label: String,
        /// The version.
        version: u32,
        /// The value, hex.
        value: String,
    },
}

/// One `MonitorMapEntry` in a request.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MonitorEntryInput {
    /// The log entry position.
    pub position: u64,
    /// The version at that position.
    pub version: u32,
}

/// `requests.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RequestExpect {
    /// The encoded structure, hex.
    pub encoding: String,
}

/// `ladder-interpretation.json` input (§6.2).
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpretationInput {
    /// The version being searched for.
    pub target: u32,
    /// The greatest version that exists in the log entry.
    pub greatest: u32,
    /// The ladder's versions, in order.
    pub ladder: Vec<u32>,
    /// Whether each lookup was an inclusion, in ladder order.
    pub results: Vec<bool>,
}

/// `ladder-interpretation.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InterpretationExpect {
    /// -1 if the greatest version is below the target, 0 if equal, 1 if above.
    pub verdict: i8,
}

/// `log-math.json` input: log tree structure in the peer's flat node indices.
#[derive(Debug, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum LogMathInput {
    /// The heads a verifier retains for a tree of this size (§4.2).
    FullSubtrees {
        /// The tree size.
        size: u64,
    },
    /// The nodes a batch proof carries, in order (§12.1).
    BatchCopath {
        /// The tree size.
        size: u64,
        /// The leaves being proven.
        leaves: Vec<u64>,
        /// A retained view's size, if any.
        #[serde(default)]
        retained_size: Option<u64>,
    },
}

/// `log-math.json` expectations.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogMathExpect {
    /// Flat node indices, in order.
    pub indices: Vec<u64>,
}
