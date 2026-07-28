//! Prefix tree over VRF outputs
//! (`draft-ietf-keytrans-protocol-05` §3.3, §11.9, §12.2).
//!
//! A prefix tree maps search keys — VRF outputs for label-version pairs (§11.7) —
//! to commitments. A parent represents a bit-prefix shared by everything beneath
//! it: its left subtree holds the keys that continue with `0`, its right subtree
//! the keys that continue with `1`, and the root represents the empty prefix
//! (§3.3). Searching means walking the bits of the key from the most significant
//! bit of the first byte, and it ends in one of three places, which is what §12.2
//! encodes as [`PrefixSearchResultType`].
//!
//! # Hashing (§11.9)
//!
//! ```pseudocode
//! leaf.value   = Hash(0x02 || vrf_output || commitment)
//! parent.value = Hash(0x03 || leftChild.value || rightChild.value)
//! ```
//!
//! "If one of the children does not exist, an all-zero byte string of length
//! `Hash.Nh` is used instead" — [`HashValue::ZERO`]. An empty tree therefore has
//! an all-zero root, which is the value a log's first entry commits to before
//! anything is inserted.
//!
//! # Two things §12.2 leaves implicit
//!
//! Both are resolved here the way the Go peer resolves them, and both are pinned
//! by `interop/vectors/prefix-tree.json` so the choice is checked rather than
//! assumed. They are worth an upstream question:
//!
//! 1. **What `depth` counts for `nonInclusionParent`.** §12.2 says the terminal
//!    node is "a parent node that lacks the desired child" and that `depth` is
//!    "the depth of the terminal node". Read literally those give different
//!    numbers, one apart: the parent sits one level above the child slot the
//!    search wanted. This implementation uses the number of bits consumed to reach
//!    the *missing child slot*, which is what the peer does and what makes `depth`
//!    mean the same thing for all three result types.
//! 2. **Whether a missing child consumes a proof element.** §12.2 says `elements`
//!    holds "the fewest node values that can be hashed together with the provided
//!    leaves to produce the root", and also that an all-zero string is "listed
//!    instead" for a node that does not exist. Those pull in opposite directions
//!    for the child slot that terminates a `nonInclusionParent` search. Here that
//!    slot consumes *no* element — the result type already says it is empty, so
//!    listing it would not be the fewest — while a copath sibling that happens not
//!    to exist does consume one, listed as all-zero.

use alloc::boxed::Box;
use alloc::vec::Vec;
use core::fmt;

use kt_crypto::hash;
use kt_crypto::suite::CipherSuite;
use kt_wire::proofs::{PrefixLeaf, PrefixProof, PrefixSearchResult};
use kt_wire::structs::HashValue;

/// The number of bits in a search key, and so the deepest a tree can be.
pub const KEY_BITS: usize = HashValue::SIZE * 8;

/// Something wrong with a prefix tree operation or proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The same search key was inserted twice.
    ///
    /// Each label-version pair has one VRF output, so a repeat means the caller
    /// has confused two entries.
    DuplicateKey {
        /// The key that was already present.
        key: HashValue,
    },
    /// The same search key was searched for twice in one batch.
    ///
    /// The peer rejects this too: it would make the mapping from results back to
    /// requests ambiguous.
    DuplicateSearch {
        /// The repeated key.
        key: HashValue,
    },
    /// The number of results did not match the number of searches.
    ResultCount {
        /// How many searches were requested.
        expected: usize,
        /// How many results the proof carried.
        actual: usize,
    },
    /// A result's depth or type contradicted the shape of the proof.
    ///
    /// Raised when the skeleton says the search should have ended somewhere else:
    /// a depth deeper than the tree the proof describes, an `inclusion` result at
    /// a node holding a different key, or a `nonInclusion` result at a node
    /// holding the key that was asked for.
    Malformed {
        /// Which search, by position in the request.
        index: usize,
    },
    /// An `inclusion` result was checked without the commitment it must open to.
    MissingCommitment {
        /// Which search, by position in the request.
        index: usize,
    },
    /// A `nonInclusionLeaf` result carried a leaf that cannot be where it claims.
    ///
    /// Either it holds the key that was searched for — which would be inclusion —
    /// or it does not share the prefix that the search walked to reach it. Neither
    /// can happen for a leaf really found by that search, so accepting them would
    /// be accepting a proof about a tree that cannot exist.
    ImpossibleLeaf {
        /// Which search, by position in the request.
        index: usize,
    },
    /// The proof had a different number of copath elements than the walk needed.
    ProofShape {
        /// How many elements the walk consumed.
        expected: usize,
        /// How many the proof carried.
        actual: usize,
    },
    /// The proof evaluated to a different root than the one supplied.
    RootMismatch,
    /// A terminal node sits deeper than §12.2's `uint8 depth` can express.
    ///
    /// Reachable only when two search keys agree on their first 255 bits, which puts
    /// their leaves at depth 256. For VRF outputs that is a `2^-255` coincidence, and
    /// a log cannot grind for it either, since it has to produce a valid VRF proof
    /// for whatever label-version pair it uses. So this is a limit of the wire
    /// format rather than a practical one — but saturating the field instead would
    /// emit a proof whose `depth` disagrees with the tree it describes, and no
    /// verifier could catch that except by failing on the root.
    DepthOverflow {
        /// The depth the terminal node actually sits at.
        depth: usize,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::DuplicateKey { .. } => f.write_str("search key is already in the tree"),
            Self::DuplicateSearch { .. } => {
                f.write_str("the same search key appears twice in one batch")
            }
            Self::ResultCount { expected, actual } => {
                write!(f, "proof has {actual} results for {expected} searches")
            }
            Self::Malformed { index } => {
                write!(
                    f,
                    "search {index}: result type or depth contradicts the proof"
                )
            }
            Self::MissingCommitment { index } => {
                write!(
                    f,
                    "search {index}: an inclusion result needs the expected commitment"
                )
            }
            Self::ImpossibleLeaf { index } => {
                write!(
                    f,
                    "search {index}: the leaf provided cannot be where the proof puts it"
                )
            }
            Self::ProofShape { expected, actual } => {
                write!(f, "proof needs {expected} copath elements, got {actual}")
            }
            Self::RootMismatch => f.write_str("proof does not evaluate to the expected root"),
            Self::DepthOverflow { depth } => write!(
                f,
                "terminal node is at depth {depth}, which the uint8 depth field of §12.2 \
                 cannot express"
            ),
        }
    }
}

impl core::error::Error for Error {}

/// A specialized [`Result`] for prefix tree operations.
pub type Result<T> = core::result::Result<T, Error>;

/// Bit `index` of a search key, most significant bit of the first byte first
/// (§3.3: "the first bit of a search key").
///
/// Out-of-range indices read as `false`; the callers here never exceed
/// [`KEY_BITS`], and a panic in a verifier is not an option.
#[must_use]
pub fn bit(key: &HashValue, index: usize) -> bool {
    let Some(byte) = key.as_bytes().get(index / 8) else {
        return false;
    };
    let shift = 7_u32.saturating_sub(u32::try_from(index % 8).unwrap_or(7));
    (byte >> shift) & 1 == 1
}

/// A node of a prefix tree.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Node {
    /// A key-value mapping.
    Leaf(PrefixLeaf),
    /// A shared prefix, with either child possibly absent.
    Parent {
        /// Keys continuing with a `0` bit.
        left: Option<Box<Node>>,
        /// Keys continuing with a `1` bit.
        right: Option<Box<Node>>,
    },
}

impl Node {
    fn value(&self, suite: CipherSuite) -> HashValue {
        match self {
            Self::Leaf(leaf) => leaf_value(suite, leaf),
            Self::Parent { left, right } => parent_value(
                suite,
                child_value(suite, left.as_deref()),
                child_value(suite, right.as_deref()),
            ),
        }
    }
}

fn child_value(suite: CipherSuite, child: Option<&Node>) -> HashValue {
    child.map_or(HashValue::ZERO, |node| node.value(suite))
}

/// The value of a prefix tree leaf (§11.9).
#[must_use]
pub fn leaf_value(suite: CipherSuite, leaf: &PrefixLeaf) -> HashValue {
    hash::hash(
        suite,
        &[
            &[0x02],
            leaf.vrf_output.as_bytes(),
            leaf.commitment.as_bytes(),
        ],
    )
}

/// The value of a prefix tree parent from its children's values (§11.9).
///
/// Pass [`HashValue::ZERO`] for a child that does not exist.
#[must_use]
pub fn parent_value(suite: CipherSuite, left: HashValue, right: HashValue) -> HashValue {
    hash::hash(suite, &[&[0x03], left.as_bytes(), right.as_bytes()])
}

/// A prefix tree, as the Transparency Log holds it.
///
/// Built by inserting leaves; a verifier never needs one of these, only
/// [`evaluate`] and [`verify`].
#[derive(Clone, Debug, Default)]
pub struct PrefixTree {
    root: Option<Node>,
}

impl PrefixTree {
    /// An empty tree, whose root value is [`HashValue::ZERO`].
    #[must_use]
    pub const fn new() -> Self {
        Self { root: None }
    }

    /// Whether the tree holds no entries.
    #[must_use]
    pub const fn is_empty(&self) -> bool {
        self.root.is_none()
    }

    /// The tree's root value (§11.9), or [`HashValue::ZERO`] if it is empty.
    #[must_use]
    pub fn root(&self, suite: CipherSuite) -> HashValue {
        child_value(suite, self.root.as_ref())
    }

    /// Inserts a leaf, adding intermediate parents as §3.3 describes.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateKey`] if the search key is already present.
    pub fn insert(&mut self, leaf: PrefixLeaf) -> Result<()> {
        insert_into(&mut self.root, leaf, 0)
    }

    /// Inserts many leaves.
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateKey`] on the first repeated search key.
    pub fn extend(&mut self, leaves: impl IntoIterator<Item = PrefixLeaf>) -> Result<()> {
        for leaf in leaves {
            self.insert(leaf)?;
        }
        Ok(())
    }

    /// Searches for `key` and reports where the search ended (§12.2).
    ///
    /// # Errors
    ///
    /// [`Error::DepthOverflow`] if the terminal node is deeper than §12.2's `uint8
    /// depth` can express, which takes two keys agreeing on 255 bits.
    pub fn search(&self, key: &HashValue) -> Result<PrefixSearchResult> {
        let mut slot = self.root.as_ref();
        let mut depth = 0_usize;
        loop {
            let truncated = || u8::try_from(depth).map_err(|_| Error::DepthOverflow { depth });
            match slot {
                // The child the search wanted is absent: the terminal is this
                // empty slot, at the depth reached to get here.
                None => {
                    return Ok(PrefixSearchResult::NonInclusionParent {
                        depth: truncated()?,
                    });
                }
                Some(Node::Leaf(leaf)) => {
                    return if leaf.vrf_output == *key {
                        Ok(PrefixSearchResult::Inclusion {
                            depth: truncated()?,
                        })
                    } else {
                        Ok(PrefixSearchResult::NonInclusionLeaf {
                            leaf: *leaf,
                            depth: truncated()?,
                        })
                    };
                }
                Some(Node::Parent { left, right }) => {
                    slot = if bit(key, depth) {
                        right.as_deref()
                    } else {
                        left.as_deref()
                    };
                    depth = depth.saturating_add(1);
                }
            }
        }
    }

    /// Builds a batch proof for `keys`, in the order given (§12.2).
    ///
    /// # Errors
    ///
    /// [`Error::DuplicateSearch`] if a key appears twice.
    pub fn prove(&self, suite: CipherSuite, keys: &[HashValue]) -> Result<PrefixProof> {
        for (i, key) in keys.iter().enumerate() {
            if keys
                .iter()
                .skip(i.saturating_add(1))
                .any(|other| other == key)
            {
                return Err(Error::DuplicateSearch { key: *key });
            }
        }

        let mut results = Vec::new();
        for key in keys {
            results.push(self.search(key)?);
        }
        let mut elements = Vec::new();
        if !keys.is_empty() {
            let active: Vec<&HashValue> = keys.iter().collect();
            collect_copath(suite, self.root.as_ref(), 0, &active, &mut elements);
        }
        Ok(PrefixProof { results, elements })
    }
}

/// Inserts `leaf` into `slot`, which covers keys sharing the first `depth` bits.
fn insert_into(slot: &mut Option<Node>, leaf: PrefixLeaf, depth: usize) -> Result<()> {
    match slot.take() {
        // §3.3: "If the search terminates at a parent without a left or right
        // child, a new leaf is simply added as the parent's missing child."
        None => {
            *slot = Some(Node::Leaf(leaf));
            Ok(())
        }
        Some(Node::Leaf(existing)) => {
            if existing.vrf_output == leaf.vrf_output {
                *slot = Some(Node::Leaf(existing));
                return Err(Error::DuplicateKey {
                    key: existing.vrf_output,
                });
            }
            // §3.3: add intermediate nodes "until we reach the first bit that
            // differs between the new search key and the existing search key".
            *slot = Some(split_leaves(existing, leaf, depth));
            Ok(())
        }
        Some(Node::Parent {
            mut left,
            mut right,
        }) => {
            let child = if bit(&leaf.vrf_output, depth) {
                &mut right
            } else {
                &mut left
            };
            let mut owned = child.take().map(|boxed| *boxed);
            let result = insert_into(&mut owned, leaf, depth.saturating_add(1));
            *child = owned.map(Box::new);
            *slot = Some(Node::Parent { left, right });
            result
        }
    }
}

/// Builds the chain of parents that separates two leaves whose keys first differ
/// at or after `depth`.
fn split_leaves(existing: PrefixLeaf, inserted: PrefixLeaf, depth: usize) -> Node {
    // Recursion is bounded by KEY_BITS: two distinct 32-byte keys differ within
    // 256 bits, and equal keys were rejected before this point.
    if depth >= KEY_BITS {
        // Unreachable for distinct keys. Keeping the existing leaf is the choice
        // that cannot lose data.
        return Node::Leaf(existing);
    }
    let existing_bit = bit(&existing.vrf_output, depth);
    let inserted_bit = bit(&inserted.vrf_output, depth);
    if existing_bit == inserted_bit {
        let child = Box::new(split_leaves(existing, inserted, depth.saturating_add(1)));
        if existing_bit {
            Node::Parent {
                left: None,
                right: Some(child),
            }
        } else {
            Node::Parent {
                left: Some(child),
                right: None,
            }
        }
    } else if inserted_bit {
        Node::Parent {
            left: Some(Box::new(Node::Leaf(existing))),
            right: Some(Box::new(Node::Leaf(inserted))),
        }
    } else {
        Node::Parent {
            left: Some(Box::new(Node::Leaf(inserted))),
            right: Some(Box::new(Node::Leaf(existing))),
        }
    }
}

/// Walks the skeleton of the searches in `active`, appending each copath value in
/// left-to-right order (§12.2).
///
/// A slot with no active search is a copath node and contributes its value, or
/// [`HashValue::ZERO`] if it does not exist. A slot where the search terminates —
/// an absent child or a leaf — contributes nothing: the result type already says
/// what it is.
fn collect_copath(
    suite: CipherSuite,
    slot: Option<&Node>,
    depth: usize,
    active: &[&HashValue],
    out: &mut Vec<HashValue>,
) {
    match slot {
        None | Some(Node::Leaf(_)) => {}
        Some(Node::Parent { left, right }) => {
            let mut going_left = Vec::new();
            let mut going_right = Vec::new();
            for key in active {
                if bit(key, depth) {
                    going_right.push(*key);
                } else {
                    going_left.push(*key);
                }
            }
            let next = depth.saturating_add(1);
            for (child, keys) in [(left, &going_left), (right, &going_right)] {
                if keys.is_empty() {
                    out.push(child_value(suite, child.as_deref()));
                } else {
                    collect_copath(suite, child.as_deref(), next, keys, out);
                }
            }
        }
    }
}

/// What a verifier is looking up: a search key, and the commitment it expects if
/// the key is present.
///
/// `commitment` is only needed for a search the verifier expects to be included:
/// the leaf's value depends on it, so a verifier that does not know it cannot
/// check an inclusion result.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SearchEntry {
    /// The search key: a VRF output.
    pub vrf_output: HashValue,
    /// The commitment the leaf must hold, for inclusion results.
    pub commitment: Option<HashValue>,
}

impl SearchEntry {
    /// A lookup expected to be included, opening to `commitment`.
    #[must_use]
    pub const fn included(vrf_output: HashValue, commitment: HashValue) -> Self {
        Self {
            vrf_output,
            commitment: Some(commitment),
        }
    }

    /// A lookup with no expected commitment, for non-inclusion.
    #[must_use]
    pub const fn absent(vrf_output: HashValue) -> Self {
        Self {
            vrf_output,
            commitment: None,
        }
    }
}

/// The verifier's partial reconstruction of the tree.
#[derive(Clone, Debug)]
enum Skeleton {
    /// A copath node whose value comes from the proof's `elements`.
    Unknown(Option<HashValue>),
    /// A child slot the proof says is absent: value [`HashValue::ZERO`].
    Empty,
    /// A leaf, either the one searched for or the one found instead.
    Leaf(PrefixLeaf),
    /// A parent whose children are reconstructed in turn.
    Parent(Box<Skeleton>, Box<Skeleton>),
}

impl Skeleton {
    fn value(&self, suite: CipherSuite) -> HashValue {
        match self {
            Self::Unknown(value) => value.unwrap_or(HashValue::ZERO),
            Self::Empty => HashValue::ZERO,
            Self::Leaf(leaf) => leaf_value(suite, leaf),
            Self::Parent(left, right) => parent_value(suite, left.value(suite), right.value(suite)),
        }
    }
}

/// Recomputes the root that `proof` implies for `entries` (§12.2).
///
/// # Errors
///
/// Any [`Error`] except [`Error::RootMismatch`]; see [`verify`] for that.
pub fn evaluate(
    suite: CipherSuite,
    entries: &[SearchEntry],
    proof: &PrefixProof,
) -> Result<HashValue> {
    if entries.len() != proof.results.len() {
        return Err(Error::ResultCount {
            expected: entries.len(),
            actual: proof.results.len(),
        });
    }
    for (i, entry) in entries.iter().enumerate() {
        let repeated = entries
            .iter()
            .skip(i.saturating_add(1))
            .any(|other| other.vrf_output == entry.vrf_output);
        if repeated {
            return Err(Error::DuplicateSearch {
                key: entry.vrf_output,
            });
        }
    }

    // The skeleton starts as one unknown node — for an empty batch that is the
    // root itself, and the proof must then say what it is.
    let mut root = Skeleton::Unknown(None);
    for (index, (entry, result)) in entries.iter().zip(proof.results.iter()).enumerate() {
        add_to_skeleton(&mut root, entry, result, index)?;
    }

    let mut supplied = proof.elements.iter().copied();
    let consumed = fill_copath(&mut root, &mut supplied);
    if consumed != proof.elements.len() {
        return Err(Error::ProofShape {
            expected: consumed,
            actual: proof.elements.len(),
        });
    }

    Ok(root.value(suite))
}

/// Checks that `proof` proves `entries` against `root` (§12.2).
///
/// # Errors
///
/// [`Error::RootMismatch`] if the proof evaluates to a different root, plus
/// anything [`evaluate`] reports.
pub fn verify(
    suite: CipherSuite,
    entries: &[SearchEntry],
    proof: &PrefixProof,
    root: HashValue,
) -> Result<()> {
    let computed = evaluate(suite, entries, proof)?;
    if computed == root {
        Ok(())
    } else {
        Err(Error::RootMismatch)
    }
}

/// Grafts one search's terminal node into the skeleton, validating the result
/// against what the skeleton already says.
fn add_to_skeleton(
    root: &mut Skeleton,
    entry: &SearchEntry,
    result: &PrefixSearchResult,
    index: usize,
) -> Result<()> {
    let target = usize::from(result.depth());
    let mut node = root;
    let mut depth = 0_usize;

    loop {
        match node {
            // A slot another search already showed to be empty. Only a
            // non-inclusion result ending exactly here is consistent with that.
            Skeleton::Empty => {
                if target != depth || result.is_inclusion() {
                    return Err(Error::Malformed { index });
                }
                return Ok(());
            }
            // A leaf another search already placed. The two searches must agree
            // about whether this is the key being looked for.
            Skeleton::Leaf(leaf) => {
                let same_key = leaf.vrf_output == entry.vrf_output;
                if target != depth || result.is_inclusion() != same_key {
                    return Err(Error::Malformed { index });
                }
                return Ok(());
            }
            Skeleton::Parent(left, right) => {
                node = if bit(&entry.vrf_output, depth) {
                    right
                } else {
                    left
                };
                depth = depth.saturating_add(1);
            }
            Skeleton::Unknown(_) => {
                if depth > target {
                    // The search claims to have ended above a node that another
                    // search proved to be a parent.
                    return Err(Error::Malformed { index });
                }
                if depth == target {
                    *node = terminal(entry, result, depth, index)?;
                    return Ok(());
                }
                *node = Skeleton::Parent(
                    Box::new(Skeleton::Unknown(None)),
                    Box::new(Skeleton::Unknown(None)),
                );
            }
        }
    }
}

/// The skeleton node a search result terminates on.
fn terminal(
    entry: &SearchEntry,
    result: &PrefixSearchResult,
    depth: usize,
    index: usize,
) -> Result<Skeleton> {
    match result {
        PrefixSearchResult::Inclusion { .. } => {
            let commitment = entry.commitment.ok_or(Error::MissingCommitment { index })?;
            Ok(Skeleton::Leaf(PrefixLeaf {
                vrf_output: entry.vrf_output,
                commitment,
            }))
        }
        PrefixSearchResult::NonInclusionLeaf { leaf, .. } => {
            // A leaf really reached by this search shares the bits the search
            // walked and holds a different key. Rejecting anything else costs
            // nothing and removes a class of proofs about impossible trees.
            if leaf.vrf_output == entry.vrf_output {
                return Err(Error::ImpossibleLeaf { index });
            }
            let shares_prefix =
                (0..depth).all(|i| bit(&leaf.vrf_output, i) == bit(&entry.vrf_output, i));
            if !shares_prefix {
                return Err(Error::ImpossibleLeaf { index });
            }
            Ok(Skeleton::Leaf(*leaf))
        }
        PrefixSearchResult::NonInclusionParent { .. } => Ok(Skeleton::Empty),
    }
}

/// Fills every unknown node with the next element, left to right, and reports how
/// many were consumed (§12.2).
fn fill_copath(node: &mut Skeleton, supplied: &mut impl Iterator<Item = HashValue>) -> usize {
    match node {
        Skeleton::Empty | Skeleton::Leaf(_) => 0,
        Skeleton::Unknown(value) => {
            *value = supplied.next();
            1
        }
        Skeleton::Parent(left, right) => {
            let used = fill_copath(left, supplied);
            used.saturating_add(fill_copath(right, supplied))
        }
    }
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::panic,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;

    pub(super) const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    /// A key whose first five bits are `bits`, the rest zero — so the §3.3 figures
    /// can be written out directly.
    fn key(bits: [u8; 5]) -> HashValue {
        let mut bytes = [0_u8; 32];
        for (i, b) in bits.iter().enumerate() {
            if *b == 1 {
                bytes[0] |= 1 << (7 - i);
            }
        }
        // Keep the keys distinct beyond the first five bits.
        bytes[31] = bits
            .iter()
            .enumerate()
            .fold(0, |acc, (i, b)| acc | (b << i));
        HashValue::from_bytes(bytes)
    }

    fn leaf(bits: [u8; 5], commitment: u8) -> PrefixLeaf {
        PrefixLeaf {
            vrf_output: key(bits),
            commitment: HashValue::from_bytes([commitment; 32]),
        }
    }

    /// The tree from §3.3's first figure: 00010, 00101, 10001, 10111, 11011.
    pub(super) fn figure_tree() -> (PrefixTree, Vec<PrefixLeaf>) {
        let leaves = vec![
            leaf([0, 0, 0, 1, 0], 0xa1),
            leaf([0, 0, 1, 0, 1], 0xb2),
            leaf([1, 0, 0, 0, 1], 0xc3),
            leaf([1, 0, 1, 1, 1], 0xd4),
            leaf([1, 1, 0, 1, 1], 0xe5),
        ];
        let mut tree = PrefixTree::new();
        tree.extend(leaves.iter().copied()).unwrap();
        (tree, leaves)
    }

    #[test]
    fn bits_are_read_most_significant_first() {
        let value = HashValue::from_bytes({
            let mut bytes = [0_u8; 32];
            bytes[0] = 0b1000_0001;
            bytes[1] = 0b0100_0000;
            bytes
        });
        assert!(bit(&value, 0), "bit 0 is the top bit of byte 0");
        assert!(!bit(&value, 1));
        assert!(bit(&value, 7), "bit 7 is the bottom bit of byte 0");
        assert!(bit(&value, 9), "bit 9 is the second bit of byte 1");
        assert!(
            !bit(&value, KEY_BITS),
            "out of range reads as false, not a panic"
        );
    }

    /// §11.9's rules, spelled out so a wrong prefix byte or a wrong stand-in shows
    /// up here rather than as an interop mismatch.
    #[test]
    fn hashing_follows_the_rule() {
        let entry = leaf([0, 0, 0, 1, 0], 0x11);
        assert_eq!(
            leaf_value(SUITE, &entry),
            hash::hash(
                SUITE,
                &[
                    &[0x02],
                    entry.vrf_output.as_bytes(),
                    entry.commitment.as_bytes()
                ]
            )
        );

        let left = HashValue::from_bytes([0x22; 32]);
        let right = HashValue::from_bytes([0x33; 32]);
        assert_eq!(
            parent_value(SUITE, left, right),
            hash::hash(SUITE, &[&[0x03], left.as_bytes(), right.as_bytes()])
        );

        // A missing child is the all-zero string, not an omission.
        let mut tree = PrefixTree::new();
        tree.insert(leaf([0, 0, 0, 0, 0], 0x44)).unwrap();
        tree.insert(leaf([0, 0, 0, 0, 1], 0x55)).unwrap();
        let root = tree.root(SUITE);
        // Both keys start with four zero bits, so the root's right child is absent
        // through four levels.
        let mut expected = parent_value(
            SUITE,
            leaf_value(SUITE, &leaf([0, 0, 0, 0, 0], 0x44)),
            leaf_value(SUITE, &leaf([0, 0, 0, 0, 1], 0x55)),
        );
        for _ in 0..4 {
            expected = parent_value(SUITE, expected, HashValue::ZERO);
        }
        assert_eq!(root, expected);
    }

    /// An empty tree hashes to the stand-in value (§11.9).
    #[test]
    fn empty_tree_root_is_zero() {
        let tree = PrefixTree::new();
        assert!(tree.is_empty());
        assert_eq!(tree.root(SUITE), HashValue::ZERO);
    }

    /// A one-entry tree's root is the leaf: the leaf *is* the root (§3.3).
    #[test]
    fn single_entry_root_is_the_leaf() {
        let mut tree = PrefixTree::new();
        let only = leaf([1, 0, 1, 0, 1], 0x66);
        tree.insert(only).unwrap();
        assert_eq!(tree.root(SUITE), leaf_value(SUITE, &only));
    }

    /// Insertion order must not change the tree: the structure is determined by
    /// the keys, per §3.3.
    #[test]
    fn insertion_order_does_not_matter() {
        let (tree, leaves) = figure_tree();
        let expected = tree.root(SUITE);

        let mut reversed = PrefixTree::new();
        reversed.extend(leaves.iter().rev().copied()).unwrap();
        assert_eq!(reversed.root(SUITE), expected);

        let mut shuffled = PrefixTree::new();
        for i in [2_usize, 0, 4, 1, 3] {
            shuffled.insert(leaves[i]).unwrap();
        }
        assert_eq!(shuffled.root(SUITE), expected);
    }

    #[test]
    fn duplicate_insertion_is_rejected_and_leaves_the_tree_alone() {
        let (mut tree, leaves) = figure_tree();
        let before = tree.root(SUITE);
        let mut repeat = leaves[1];
        repeat.commitment = HashValue::from_bytes([0xff; 32]);
        assert_eq!(
            tree.insert(repeat),
            Err(Error::DuplicateKey {
                key: leaves[1].vrf_output
            })
        );
        assert_eq!(
            tree.root(SUITE),
            before,
            "a rejected insert must not mutate the tree"
        );
    }

    /// §3.3's search outcomes, one of each, with the depths the terminal sits at.
    #[test]
    fn search_reports_the_three_terminals() {
        let (tree, leaves) = figure_tree();

        // Present: 00101 is a leaf. Its siblings 00010 shares two bits, so the
        // leaf sits at depth 3.
        assert_eq!(
            tree.search(&leaves[1].vrf_output).unwrap(),
            PrefixSearchResult::Inclusion { depth: 3 }
        );

        // Absent, ending at another key's leaf: 00011 shares its first three bits
        // with 00010, and that is where 00010's leaf sits — the tree only branches
        // as deep as it needs to, so the search runs out of tree at depth 3 rather
        // than walking all five bits.
        let searched = key([0, 0, 0, 1, 1]);
        match tree.search(&searched).unwrap() {
            PrefixSearchResult::NonInclusionLeaf { leaf: found, depth } => {
                assert_eq!(found.vrf_output, leaves[0].vrf_output);
                assert_eq!(depth, 3);
            }
            other => panic!("expected a non-inclusion leaf, got {other:?}"),
        }

        // Absent, ending at a missing child: 01000 leaves the tree after one bit,
        // because nothing else begins 01.
        assert_eq!(
            tree.search(&key([0, 1, 0, 0, 0])).unwrap(),
            PrefixSearchResult::NonInclusionParent { depth: 2 }
        );
    }

    /// Every key in the tree proves included, one at a time.
    #[test]
    fn inclusion_proofs_verify() {
        let (tree, leaves) = figure_tree();
        let root = tree.root(SUITE);

        for entry in &leaves {
            let proof = tree.prove(SUITE, &[entry.vrf_output]).unwrap();
            assert_eq!(proof.results.len(), 1);
            assert!(proof.results[0].is_inclusion());
            let lookup = [SearchEntry::included(entry.vrf_output, entry.commitment)];
            verify(SUITE, &lookup, &proof, root).unwrap();
        }
    }

    /// And every key in the tree proves included in one batch.
    #[test]
    fn batch_inclusion_proof_verifies() {
        let (tree, leaves) = figure_tree();
        let root = tree.root(SUITE);

        let keys: Vec<HashValue> = leaves.iter().map(|l| l.vrf_output).collect();
        let proof = tree.prove(SUITE, &keys).unwrap();
        let lookups: Vec<SearchEntry> = leaves
            .iter()
            .map(|l| SearchEntry::included(l.vrf_output, l.commitment))
            .collect();
        verify(SUITE, &lookups, &proof, root).unwrap();

        // Proving every key still needs the *absent* siblings. Nothing in the
        // results tells the verifier that the right child of the depth-1 parent
        // does not exist — no search terminates there — so §12.2's "an all-zero
        // byte string is listed instead" applies and it is carried as an element.
        // The missing child that *terminates* a search is the opposite case: the
        // result type says it is empty, so it costs nothing. Both readings live in
        // the same proof.
        assert_eq!(proof.elements.len(), 1);
        assert!(
            proof.elements[0].is_zero(),
            "an absent sibling is listed as all-zero"
        );
    }

    /// Both flavours of non-inclusion, and a batch mixing all three.
    #[test]
    fn non_inclusion_proofs_verify() {
        let (tree, leaves) = figure_tree();
        let root = tree.root(SUITE);

        for absent in [
            key([0, 0, 0, 1, 1]),
            key([0, 1, 0, 0, 0]),
            key([1, 1, 1, 1, 1]),
        ] {
            let proof = tree.prove(SUITE, &[absent]).unwrap();
            assert!(!proof.results[0].is_inclusion());
            verify(SUITE, &[SearchEntry::absent(absent)], &proof, root).unwrap();
        }

        let mixed = [
            leaves[0].vrf_output,
            key([0, 1, 0, 0, 0]),
            key([0, 0, 0, 1, 1]),
        ];
        let proof = tree.prove(SUITE, &mixed).unwrap();
        let lookups = [
            SearchEntry::included(leaves[0].vrf_output, leaves[0].commitment),
            SearchEntry::absent(mixed[1]),
            SearchEntry::absent(mixed[2]),
        ];
        verify(SUITE, &lookups, &proof, root).unwrap();
    }

    /// An empty tree can still answer a search: everything is absent, the proof is
    /// empty, and the root is the stand-in value.
    #[test]
    fn empty_tree_proves_non_inclusion() {
        let tree = PrefixTree::new();
        let absent = key([1, 0, 1, 0, 1]);
        let proof = tree.prove(SUITE, &[absent]).unwrap();
        assert_eq!(
            proof.results,
            vec![PrefixSearchResult::NonInclusionParent { depth: 0 }]
        );
        assert!(proof.elements.is_empty());
        verify(
            SUITE,
            &[SearchEntry::absent(absent)],
            &proof,
            HashValue::ZERO,
        )
        .unwrap();
    }

    /// A larger tree, to exercise deep paths and batches that fan out.
    #[test]
    fn many_entries_verify_in_batches() {
        let mut tree = PrefixTree::new();
        let mut leaves = Vec::new();
        for i in 0_u16..200 {
            // Spread the keys across the first two bytes so the tree branches
            // early and deeply.
            let mut bytes = [0_u8; 32];
            bytes[0] = u8::try_from(i % 256).unwrap();
            bytes[1] = u8::try_from(i / 256).unwrap();
            bytes[2] = u8::try_from(i % 7).unwrap();
            let entry = PrefixLeaf {
                vrf_output: HashValue::from_bytes(bytes),
                commitment: HashValue::from_bytes([u8::try_from(i % 251).unwrap(); 32]),
            };
            tree.insert(entry).unwrap();
            leaves.push(entry);
        }
        let root = tree.root(SUITE);

        for chunk in leaves.chunks(7) {
            let keys: Vec<HashValue> = chunk.iter().map(|l| l.vrf_output).collect();
            let proof = tree.prove(SUITE, &keys).unwrap();
            let lookups: Vec<SearchEntry> = chunk
                .iter()
                .map(|l| SearchEntry::included(l.vrf_output, l.commitment))
                .collect();
            verify(SUITE, &lookups, &proof, root).unwrap();
        }
    }

    /// Tampering with any copath element must change the computed root.
    #[test]
    fn tampering_with_an_element_is_caught() {
        let (tree, leaves) = figure_tree();
        let root = tree.root(SUITE);
        let proof = tree.prove(SUITE, &[leaves[2].vrf_output]).unwrap();
        let lookup = [SearchEntry::included(
            leaves[2].vrf_output,
            leaves[2].commitment,
        )];
        assert!(!proof.elements.is_empty());

        for i in 0..proof.elements.len() {
            let mut broken = proof.clone();
            let mut bytes = *broken.elements[i].as_bytes();
            bytes[0] ^= 0x01;
            broken.elements[i] = HashValue::from_bytes(bytes);
            assert_eq!(
                verify(SUITE, &lookup, &broken, root),
                Err(Error::RootMismatch),
                "{i}"
            );
        }
    }

    /// Claiming inclusion of a key that is absent must not verify, and neither
    /// must claiming a different commitment for a key that is present.
    #[test]
    fn lying_about_the_result_is_caught() {
        let (tree, leaves) = figure_tree();
        let root = tree.root(SUITE);

        // The right commitment is required for an inclusion result.
        let proof = tree.prove(SUITE, &[leaves[3].vrf_output]).unwrap();
        let wrong = [SearchEntry::included(leaves[3].vrf_output, HashValue::ZERO)];
        assert_eq!(
            verify(SUITE, &wrong, &proof, root),
            Err(Error::RootMismatch)
        );

        // An inclusion result with no commitment cannot be checked at all.
        let missing = [SearchEntry::absent(leaves[3].vrf_output)];
        assert_eq!(
            verify(SUITE, &missing, &proof, root),
            Err(Error::MissingCommitment { index: 0 })
        );

        // Rewriting a non-inclusion result as inclusion contradicts the skeleton.
        let absent = key([0, 1, 0, 0, 0]);
        let mut forged = tree.prove(SUITE, &[absent]).unwrap();
        forged.results[0] = PrefixSearchResult::Inclusion { depth: 2 };
        let lookup = [SearchEntry::included(absent, HashValue::ZERO)];
        // The forged proof describes a tree with a leaf where the real tree has
        // nothing, so it cannot reach the real root.
        assert_eq!(
            verify(SUITE, &lookup, &forged, root),
            Err(Error::RootMismatch)
        );
    }

    /// A `nonInclusionLeaf` result has to carry a leaf that could really be where
    /// the search would have found it.
    #[test]
    fn impossible_leaves_are_rejected() {
        let (tree, leaves) = figure_tree();
        let root = tree.root(SUITE);
        let searched = key([0, 0, 0, 1, 1]);
        let proof = tree.prove(SUITE, &[searched]).unwrap();

        // The searched key itself is not a valid non-inclusion witness.
        let mut same = proof.clone();
        same.results[0] = PrefixSearchResult::NonInclusionLeaf {
            leaf: PrefixLeaf {
                vrf_output: searched,
                commitment: HashValue::ZERO,
            },
            depth: 4,
        };
        assert_eq!(
            verify(SUITE, &[SearchEntry::absent(searched)], &same, root),
            Err(Error::ImpossibleLeaf { index: 0 })
        );

        // Nor is a leaf from a different part of the tree: it does not share the
        // prefix the search walked.
        let mut elsewhere = proof.clone();
        elsewhere.results[0] = PrefixSearchResult::NonInclusionLeaf {
            leaf: leaves[4],
            depth: 4,
        };
        assert_eq!(
            verify(SUITE, &[SearchEntry::absent(searched)], &elsewhere, root),
            Err(Error::ImpossibleLeaf { index: 0 })
        );
    }

    /// Contradictory depths, mismatched counts, and wrong element counts are
    /// shape errors rather than surprising roots.
    #[test]
    fn malformed_proofs_are_rejected() {
        let (tree, leaves) = figure_tree();
        let keys = [leaves[0].vrf_output, leaves[1].vrf_output];
        let proof = tree.prove(SUITE, &keys).unwrap();
        let lookups: Vec<SearchEntry> = keys
            .iter()
            .zip(leaves.iter())
            .map(|(k, l)| SearchEntry::included(*k, l.commitment))
            .collect();

        let mut short = proof.clone();
        short.results.pop();
        assert_eq!(
            evaluate(SUITE, &lookups, &short),
            Err(Error::ResultCount {
                expected: 2,
                actual: 1
            })
        );

        let mut wrong_depth = proof.clone();
        wrong_depth.results[1] = PrefixSearchResult::Inclusion { depth: 0 };
        assert_eq!(
            evaluate(SUITE, &lookups, &wrong_depth),
            Err(Error::Malformed { index: 1 })
        );

        let mut extra = proof.clone();
        extra.elements.push(HashValue::ZERO);
        let needed = proof.elements.len();
        assert_eq!(
            evaluate(SUITE, &lookups, &extra),
            Err(Error::ProofShape {
                expected: needed,
                actual: needed + 1
            })
        );

        let repeated = [lookups[0], lookups[0]];
        assert_eq!(
            evaluate(SUITE, &repeated, &proof),
            Err(Error::DuplicateSearch { key: keys[0] })
        );
        assert_eq!(
            tree.prove(SUITE, &[keys[0], keys[0]]),
            Err(Error::DuplicateSearch { key: keys[0] })
        );
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::indexing_slicing,
    clippy::arithmetic_side_effects,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod error_tests {
    use super::tests::{SUITE, figure_tree};
    use super::*;
    use alloc::string::ToString as _;

    /// Every variant renders, and the ones that identify a search say which one — a
    /// batch proof can hold 255 lookups, so "malformed proof" without an index is not
    /// an error message a caller can act on.
    #[test]
    fn every_error_renders_its_detail() {
        use core::error::Error as _;

        let key = HashValue::from_bytes([1; 32]);
        let cases: [(Error, &[&str]); 8] = [
            (Error::DuplicateKey { key }, &["already"]),
            (Error::DuplicateSearch { key }, &["twice"]),
            (
                Error::ResultCount {
                    expected: 3,
                    actual: 2,
                },
                &["3", "2"],
            ),
            (Error::Malformed { index: 4 }, &["4"]),
            (Error::MissingCommitment { index: 1 }, &["1", "commitment"]),
            (Error::ImpossibleLeaf { index: 2 }, &["2"]),
            (
                Error::ProofShape {
                    expected: 5,
                    actual: 6,
                },
                &["5", "6"],
            ),
            (Error::RootMismatch, &["root"]),
        ];
        for (error, needles) in cases {
            let rendered = error.to_string();
            for needle in needles {
                assert!(rendered.contains(needle), "{rendered:?} omits {needle:?}");
            }
            assert!(error.source().is_none());
        }
    }

    /// A batch that searches nothing: the root is a single unknown node, so the proof
    /// has to supply it and the evaluation is just that value.
    #[test]
    fn an_empty_batch_evaluates_to_the_supplied_root() {
        let root = HashValue::from_bytes([0x99; 32]);
        let proof = PrefixProof {
            results: Vec::new(),
            elements: alloc::vec![root],
        };
        assert_eq!(evaluate(SUITE, &[], &proof).unwrap(), root);

        // And with nothing supplied, the shape is wrong rather than silently zero.
        let empty = PrefixProof::default();
        assert_eq!(
            evaluate(SUITE, &[], &empty),
            Err(Error::ProofShape {
                expected: 1,
                actual: 0
            })
        );
    }

    /// A search whose result claims to end deeper than another search proved the tree
    /// branches: the two contradict each other and the second one in is rejected.
    #[test]
    fn contradictory_depths_are_rejected() {
        let (tree, leaves) = figure_tree();
        let keys = [leaves[0].vrf_output, leaves[1].vrf_output];
        let proof = tree.prove(SUITE, &keys).unwrap();

        let mut forged = proof.clone();
        // Claim the first search ended at the root, where the second proved a parent.
        forged.results[0] = PrefixSearchResult::NonInclusionParent { depth: 0 };
        let lookups = [
            SearchEntry::included(keys[0], leaves[0].commitment),
            SearchEntry::included(keys[1], leaves[1].commitment),
        ];
        assert!(matches!(
            evaluate(SUITE, &lookups, &forged),
            Err(Error::Malformed { .. }) | Err(Error::ProofShape { .. })
        ));
    }

    /// `SearchEntry`'s two constructors, and the accessors on a search result that the
    /// verifier reads but the tests had not.
    #[test]
    fn search_entry_and_result_accessors() {
        let key = HashValue::from_bytes([2; 32]);
        let commitment = HashValue::from_bytes([3; 32]);
        assert_eq!(
            SearchEntry::included(key, commitment).commitment,
            Some(commitment)
        );
        assert_eq!(SearchEntry::absent(key).commitment, None);

        let inclusion = PrefixSearchResult::Inclusion { depth: 3 };
        assert!(inclusion.is_inclusion());
        assert_eq!(inclusion.depth(), 3);

        let parent = PrefixSearchResult::NonInclusionParent { depth: 9 };
        assert!(!parent.is_inclusion());
        assert_eq!(parent.depth(), 9);
    }

    /// Keys that agree for all 256 bits are the same key, so the tree refuses the
    /// second one rather than growing a 256-deep spine to separate them.
    #[test]
    fn keys_differing_only_by_commitment_are_duplicates() {
        let mut tree = PrefixTree::new();
        let key = HashValue::from_bytes([0x5a; 32]);
        tree.insert(PrefixLeaf {
            vrf_output: key,
            commitment: HashValue::ZERO,
        })
        .unwrap();
        assert_eq!(
            tree.insert(PrefixLeaf {
                vrf_output: key,
                commitment: HashValue::from_bytes([1; 32])
            }),
            Err(Error::DuplicateKey { key })
        );
    }

    /// Builds a two-entry tree whose keys first differ at bit `index`, so their
    /// leaves sit at depth `index + 1`.
    fn pair_differing_at(index: usize) -> (PrefixTree, PrefixLeaf, PrefixLeaf) {
        let mut second = [0_u8; 32];
        second[index / 8] |= 1 << (7 - (index % 8));
        let a = PrefixLeaf {
            vrf_output: HashValue::from_bytes([0_u8; 32]),
            commitment: HashValue::from_bytes([7; 32]),
        };
        let b = PrefixLeaf {
            vrf_output: HashValue::from_bytes(second),
            commitment: HashValue::from_bytes([8; 32]),
        };
        let mut tree = PrefixTree::new();
        tree.insert(a).unwrap();
        tree.insert(b).unwrap();
        (tree, a, b)
    }

    /// The deepest tree §12.2 can describe: keys differing at bit 254 put their
    /// leaves at depth 255, which is exactly `u8::MAX`.
    #[test]
    fn the_deepest_expressible_tree_verifies() {
        let (tree, a, _) = pair_differing_at(254);
        let root = tree.root(SUITE);
        let proof = tree.prove(SUITE, &[a.vrf_output]).unwrap();
        assert_eq!(proof.results[0].depth(), 255);
        assert_eq!(
            proof.elements.len(),
            255,
            "254 absent siblings plus the sibling leaf"
        );
        verify(
            SUITE,
            &[SearchEntry::included(a.vrf_output, a.commitment)],
            &proof,
            root,
        )
        .unwrap();
    }

    /// One bit deeper is not expressible, and saying so is better than emitting a
    /// proof whose `depth` field disagrees with the tree it describes.
    ///
    /// Two keys agreeing on 255 bits is a `2^-255` coincidence for VRF outputs, and a
    /// log cannot grind for it — it has to produce a valid VRF proof for whatever
    /// label-version pair it uses. So this is a limit of the wire format, not a
    /// practical one; it is worth an upstream note rather than a fix.
    #[test]
    fn a_tree_deeper_than_the_depth_field_is_refused() {
        let (tree, a, _) = pair_differing_at(255);
        assert_eq!(
            tree.search(&a.vrf_output),
            Err(Error::DepthOverflow { depth: 256 })
        );
        assert_eq!(
            tree.prove(SUITE, &[a.vrf_output]),
            Err(Error::DepthOverflow { depth: 256 })
        );
        // The tree itself is still well formed; only the proof cannot be expressed.
        assert_ne!(tree.root(SUITE), HashValue::ZERO);
    }

    /// `bit` past the end of a key reads false rather than panicking, which is what
    /// keeps a hostile depth field from taking the process down.
    #[test]
    fn bits_past_the_key_are_false() {
        let key = HashValue::from_bytes([0xff; 32]);
        assert!(bit(&key, KEY_BITS - 1));
        assert!(!bit(&key, KEY_BITS));
        assert!(!bit(&key, usize::MAX));
    }
}
