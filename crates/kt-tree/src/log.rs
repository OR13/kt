//! Append-only log tree
//! (`draft-ietf-keytrans-protocol-05` §3.2, §11.8, §12.1).
//!
//! The log tree stores entries in the order they were added, as a *left-balanced*
//! binary tree: for every parent, either the parent is balanced — its size is a
//! power of two and its subtrees are equal — or its left subtree is the largest
//! balanced tree that fits in it (§3.2). For `n` leaves that structure is unique,
//! and every parent has both children.
//!
//! This module works in terms of leaf *ranges* rather than node indices. The
//! draft defines the tree by that recursive splitting rule, so a subtree is
//! exactly a half-open range of leaves, and [`split`] is the rule itself. A flat
//! node-index scheme would be an equally valid encoding of the same tree, but it
//! would put arithmetic between the code and the definition it implements.
//!
//! # Hashing (§11.8)
//!
//! A leaf's value is the hash of its [`LogEntry`]. A parent's value is
//!
//! ```pseudocode
//! parent.value = Hash(hashContent(parent.leftChild) ||
//!                     hashContent(parent.rightChild))
//!
//! hashContent(node):
//!   if node.type == leafNode:    return 0x00 || node.value
//!   else if node.type == parentNode: return 0x01 || node.value
//! ```
//!
//! Note where the prefix byte goes: it describes the *child* being hashed into a
//! parent, not the node whose value is being computed. A subtree of one leaf
//! contributes `0x00`, anything larger contributes `0x01`.
//!
//! # Proofs (§12.1)
//!
//! One structure covers both inclusion and consistency: given the leaves being
//! proven and the subtree heads the verifier retained from an earlier view,
//! [`prove`] emits the fewest subtree head values that let the verifier finish
//! computing the root, left to right. [`verify`] walks the same recursion and
//! recomputes it.
//!
//! §12.1 flags one edge case as a `MUST`, and it is the reason [`verify`] does not
//! simply trust retained values: if inclusion is proven for leaves that sit inside
//! a subtree whose head the verifier retained, that head becomes recomputable, and
//! a verifier that used the retained value instead of checking it against the
//! recomputation would accept proofs it should reject. Here, a retained head is
//! used only where nothing inside it was proven; where something was, the head is
//! recomputed and compared, and a mismatch is
//! [`Error::RetainedMismatch`].

use alloc::vec::Vec;
use core::fmt;

use kt_crypto::hash;
use kt_crypto::suite::CipherSuite;
use kt_wire::codec;
use kt_wire::proofs::InclusionProof;
use kt_wire::structs::{HashValue, LogEntry};

/// The largest tree size this module accepts.
///
/// `2^63` keeps every range arithmetic well inside `u64` and is far beyond any
/// real log; the Go peer uses the same bound. Sizes above it are rejected rather
/// than risking a wrap in the middle of a proof.
pub const MAX_TREE_SIZE: u64 = 1 << 63;

/// Something wrong with a log tree query or proof.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// The tree size was zero or above [`MAX_TREE_SIZE`].
    InvalidSize {
        /// The size supplied.
        size: u64,
    },
    /// A leaf index was not below the tree size.
    LeafOutOfRange {
        /// The index supplied.
        index: u64,
        /// The tree size.
        size: u64,
    },
    /// Leaf indices were not sorted, or a leaf was listed twice.
    ///
    /// The proof's element order is defined by a left-to-right walk, so prover
    /// and verifier have to agree on the order of the leaves too.
    LeavesNotSorted,
    /// A retained view's size exceeded the current tree size.
    RetainedTooLarge {
        /// The retained size.
        retained: u64,
        /// The current size.
        size: u64,
    },
    /// A retained view supplied the wrong number of full subtree heads.
    RetainedShape {
        /// How many heads the retained size calls for.
        expected: usize,
        /// How many were supplied.
        actual: usize,
    },
    /// A retained subtree head did not match the value recomputed from the proof
    /// (§12.1).
    ///
    /// The case the draft calls out: proving inclusion for leaves inside a
    /// retained subtree makes its head recomputable, and the recomputation is
    /// what must be believed.
    RetainedMismatch {
        /// First leaf of the subtree whose head disagreed.
        start: u64,
        /// Number of leaves in it.
        len: u64,
    },
    /// The proof had a different number of elements than the walk called for.
    ProofShape {
        /// How many elements the walk consumed or needed.
        expected: usize,
        /// How many the proof carried.
        actual: usize,
    },
    /// A leaf value was needed but not supplied.
    MissingLeaf {
        /// The index whose value was missing.
        index: u64,
    },
    /// A structure could not be encoded for hashing.
    Wire(codec::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidSize { size } => {
                write!(f, "tree size {size} is not in 1..=2^63")
            }
            Self::LeafOutOfRange { index, size } => {
                write!(
                    f,
                    "leaf {index} is beyond the right edge of a log of {size} entries"
                )
            }
            Self::LeavesNotSorted => f.write_str("leaf indices must be sorted and distinct"),
            Self::RetainedTooLarge { retained, size } => {
                write!(
                    f,
                    "retained view of {retained} entries is larger than the log's {size}"
                )
            }
            Self::RetainedShape { expected, actual } => {
                write!(
                    f,
                    "retained view needs {expected} full subtree heads, got {actual}"
                )
            }
            Self::RetainedMismatch { start, len } => {
                write!(
                    f,
                    "recomputed head of the subtree at {start}..{} does not match the retained \
                     value",
                    start.saturating_add(*len)
                )
            }
            Self::ProofShape { expected, actual } => {
                write!(f, "proof needs {expected} elements, got {actual}")
            }
            Self::MissingLeaf { index } => write!(f, "no value supplied for leaf {index}"),
            Self::Wire(err) => write!(f, "encoding: {err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Wire(err) => Some(err),
            _ => None,
        }
    }
}

impl From<codec::Error> for Error {
    fn from(err: codec::Error) -> Self {
        Self::Wire(err)
    }
}

/// A specialized [`Result`] for log tree operations.
pub type Result<T> = core::result::Result<T, Error>;

/// The number of leaves in the left subtree of a tree with `len` leaves (§3.2).
///
/// The largest power of two below `len`: for a balanced tree that is half of it,
/// and otherwise it is the largest balanced subtree that fits, which is what
/// "left-balanced" means. `len` must be at least 2; a single leaf has no children.
#[must_use]
pub const fn split(len: u64) -> u64 {
    match len {
        0 | 1 => 0,
        // 1 << floor(log2(len - 1)): for len = 8 that is 4, for len = 5 it is 4,
        // for len = 2 it is 1.
        _ => {
            let below = len.saturating_sub(1);
            let exponent = u64::BITS
                .saturating_sub(1)
                .saturating_sub(below.leading_zeros());
            1_u64 << exponent
        }
    }
}

/// The value of a log tree leaf: the hash of its [`LogEntry`] (§11.8).
///
/// # Errors
///
/// [`Error::Wire`] if the entry cannot be encoded, which for a fixed-size
/// structure cannot actually happen.
pub fn leaf_value(suite: CipherSuite, entry: &LogEntry) -> Result<HashValue> {
    let encoded = codec::encode(entry)?;
    Ok(hash::hash(suite, &[&encoded]))
}

/// The value of a parent from its two children's values (§11.8).
///
/// `left_is_leaf` and `right_is_leaf` select each child's `hashContent` prefix:
/// `0x00` for a leaf, `0x01` for a parent.
#[must_use]
pub fn parent_value(
    suite: CipherSuite,
    left: (HashValue, bool),
    right: (HashValue, bool),
) -> HashValue {
    let (left_value, left_is_leaf) = left;
    let (right_value, right_is_leaf) = right;
    hash::hash(
        suite,
        &[
            &[content_prefix(left_is_leaf)],
            left_value.as_bytes(),
            &[content_prefix(right_is_leaf)],
            right_value.as_bytes(),
        ],
    )
}

/// `hashContent`'s prefix byte (§11.8).
const fn content_prefix(is_leaf: bool) -> u8 {
    if is_leaf { 0x00 } else { 0x01 }
}

/// The root value of a log tree whose leaves have the given values.
///
/// # Errors
///
/// [`Error::InvalidSize`] if `leaves` is empty or longer than [`MAX_TREE_SIZE`].
pub fn root(suite: CipherSuite, leaves: &[HashValue]) -> Result<HashValue> {
    let size = as_u64(leaves.len());
    check_size(size)?;
    subtree_value(suite, leaves, 0, size)
}

/// The value of the subtree covering `start..start+len` of `leaves`.
fn subtree_value(
    suite: CipherSuite,
    leaves: &[HashValue],
    start: u64,
    len: u64,
) -> Result<HashValue> {
    if len == 1 {
        return leaf_at(leaves, start);
    }
    let left_len = split(len);
    let right_len = len.saturating_sub(left_len);
    let left = subtree_value(suite, leaves, start, left_len)?;
    let right = subtree_value(suite, leaves, start.saturating_add(left_len), right_len)?;
    Ok(parent_value(
        suite,
        (left, left_len == 1),
        (right, right_len == 1),
    ))
}

/// The full subtrees of a log of `size` entries, left to right (§4.2).
///
/// The balanced subtrees that are as large as possible — those without another
/// balanced subtree as a parent. They fall out of the binary representation of
/// `size`: a log of 5 entries has full subtrees covering `0..4` and `4..5`, which
/// is what a verifier retains between queries.
///
/// # Errors
///
/// [`Error::InvalidSize`] if `size` is zero or above [`MAX_TREE_SIZE`].
pub fn full_subtrees(size: u64) -> Result<Vec<(u64, u64)>> {
    check_size(size)?;
    let mut out = Vec::new();
    let mut start = 0_u64;
    let mut remaining = size;
    while remaining > 0 {
        // The largest power of two that fits in what is left.
        let exponent = u64::BITS
            .saturating_sub(1)
            .saturating_sub(remaining.leading_zeros());
        let len = 1_u64 << exponent;
        out.push((start, len));
        start = start.saturating_add(len);
        remaining = remaining.saturating_sub(len);
    }
    Ok(out)
}

/// A verifier's retained view of an earlier version of the log (§4.2).
///
/// `size` is the tree size that was observed and `full_subtrees` the head values
/// of that tree's full subtrees, in left-to-right order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Retained {
    /// The tree size that was observed.
    pub size: u64,
    /// Head values of that size's full subtrees, left to right.
    pub full_subtrees: Vec<HashValue>,
}

impl Retained {
    /// Builds a retained view from a full list of leaf values.
    ///
    /// # Errors
    ///
    /// [`Error::InvalidSize`] if `size` is out of range, or
    /// [`Error::LeafOutOfRange`] if `leaves` is shorter than `size`.
    pub fn from_leaves(suite: CipherSuite, size: u64, leaves: &[HashValue]) -> Result<Self> {
        check_size(size)?;
        if as_u64(leaves.len()) < size {
            return Err(Error::LeafOutOfRange {
                index: size.saturating_sub(1),
                size: as_u64(leaves.len()),
            });
        }
        let mut values = Vec::new();
        for (start, len) in full_subtrees(size)? {
            values.push(subtree_value(suite, leaves, start, len)?);
        }
        Ok(Self {
            size,
            full_subtrees: values,
        })
    }

    /// The ranges its heads cover, paired with their values.
    ///
    /// # Errors
    ///
    /// [`Error::RetainedShape`] if the number of values does not match the number
    /// of full subtrees the size implies.
    pub fn ranges(&self) -> Result<Vec<((u64, u64), HashValue)>> {
        let ranges = full_subtrees(self.size)?;
        if ranges.len() != self.full_subtrees.len() {
            return Err(Error::RetainedShape {
                expected: ranges.len(),
                actual: self.full_subtrees.len(),
            });
        }
        Ok(ranges
            .into_iter()
            .zip(self.full_subtrees.iter().copied())
            .collect())
    }
}

/// A leaf being proven: its index and its value.
pub type Leaf = (u64, HashValue);

/// Builds the batch inclusion and consistency proof for `leaves` (§12.1).
///
/// `all_leaves` is every leaf value in the log — the prover has the whole tree.
/// `leaves` are the indices being proven, sorted and distinct, and `retained` is
/// the verifier's earlier view if it advertised one.
///
/// # Errors
///
/// [`Error::InvalidSize`], [`Error::LeafOutOfRange`], [`Error::LeavesNotSorted`],
/// or [`Error::RetainedTooLarge`] if the request is inconsistent.
pub fn prove(
    suite: CipherSuite,
    all_leaves: &[HashValue],
    leaves: &[u64],
    retained: Option<&Retained>,
) -> Result<InclusionProof> {
    let size = as_u64(all_leaves.len());
    let plan = Plan::new(size, leaves, retained)?;

    let mut elements = Vec::new();
    plan.walk(0, size, &mut |start, len| {
        // A node the verifier cannot derive: hand over its head value.
        elements.push(subtree_value(suite, all_leaves, start, len)?);
        Ok(())
    })?;
    Ok(InclusionProof::new(elements))
}

/// Verifies a batch proof and returns the root it implies (§12.1).
///
/// `leaves` pairs each proven index with the value being claimed for it, sorted
/// by index. `retained` is the verifier's earlier view, whose heads are checked
/// rather than trusted wherever the proof lets them be recomputed.
///
/// # Errors
///
/// Any [`Error`]; in particular [`Error::ProofShape`] if the proof has the wrong
/// number of elements for what was asked, and [`Error::RetainedMismatch`] for the
/// §12.1 edge case.
pub fn verify(
    suite: CipherSuite,
    size: u64,
    leaves: &[Leaf],
    retained: Option<&Retained>,
    proof: &InclusionProof,
) -> Result<HashValue> {
    let indices: Vec<u64> = leaves.iter().map(|(index, _)| *index).collect();
    let plan = Plan::new(size, &indices, retained)?;

    // Count what the walk needs before consuming, so a proof of the wrong length
    // is reported as a shape error rather than as a missing element halfway
    // through the recursion.
    let mut needed = 0_usize;
    plan.walk(0, size, &mut |_, _| {
        needed = needed.saturating_add(1);
        Ok(())
    })?;
    if needed != proof.elements.len() {
        return Err(Error::ProofShape {
            expected: needed,
            actual: proof.elements.len(),
        });
    }

    let mut supplied = proof.elements.iter().copied();
    let (value, _) = evaluate(suite, &plan, leaves, 0, size, &mut supplied)?;
    Ok(value)
}

/// Which leaves are proven and which subtrees the verifier retained.
///
/// Prover and verifier share this so that the walk order, and therefore the
/// meaning of each proof element, is identical on both sides.
struct Plan {
    leaves: Vec<u64>,
    retained: Vec<((u64, u64), HashValue)>,
}

impl Plan {
    fn new(size: u64, leaves: &[u64], retained: Option<&Retained>) -> Result<Self> {
        check_size(size)?;
        for pair in leaves.windows(2) {
            let (Some(first), Some(second)) = (pair.first(), pair.get(1)) else {
                continue;
            };
            if first >= second {
                return Err(Error::LeavesNotSorted);
            }
        }
        for index in leaves {
            if *index >= size {
                return Err(Error::LeafOutOfRange {
                    index: *index,
                    size,
                });
            }
        }

        let retained = match retained {
            None => Vec::new(),
            Some(view) => {
                if view.size > size {
                    return Err(Error::RetainedTooLarge {
                        retained: view.size,
                        size,
                    });
                }
                view.ranges()?
            }
        };

        Ok(Self {
            leaves: leaves.to_vec(),
            retained,
        })
    }

    /// Whether any proven leaf lies in `start..start+len`.
    fn covers_proven_leaf(&self, start: u64, len: u64) -> bool {
        let end = start.saturating_add(len);
        self.leaves
            .iter()
            .any(|index| *index >= start && *index < end)
    }

    /// The retained head for exactly this range, if there is one.
    fn retained_head(&self, start: u64, len: u64) -> Option<HashValue> {
        self.retained
            .iter()
            .find(|((s, l), _)| *s == start && *l == len)
            .map(|(_, value)| *value)
    }

    /// Whether the verifier already knows something *strictly* inside this range.
    ///
    /// Either a proven leaf, or a retained subtree smaller than this node. The
    /// retained subtrees of a given size are disjoint and none contains another,
    /// so a range that is itself retained has no other retained range inside it.
    fn knows_interior(&self, start: u64, len: u64) -> bool {
        if self.covers_proven_leaf(start, len) {
            return true;
        }
        let end = start.saturating_add(len);
        self.retained.iter().any(|((s, l), _)| {
            let inside = *s >= start && s.saturating_add(*l) <= end;
            inside && !(*s == start && *l == len)
        })
    }

    /// What to do with the node covering `start..start+len`.
    ///
    /// [`prove`] and [`verify`] both drive off this one function, which is what
    /// keeps them in step: the prover emits a value wherever this says
    /// [`Step::Supplied`], and the verifier consumes one there. Splitting the
    /// decision from the two walks is deliberate — the first version of this
    /// module had the logic written twice and the two copies disagreed about
    /// retained subtrees.
    fn step(&self, start: u64, len: u64) -> Step {
        if !self.knows_interior(start, len) {
            // Nothing inside is known, so this node is either one the verifier
            // retained whole, or one it has to be given.
            if let Some(value) = self.retained_head(start, len) {
                return Step::Retained(value);
            }
            // §12.1 is specific about what a proof may contain: "the minimum set
            // of head values from *balanced* subtrees". In a left-balanced tree a
            // subtree is balanced exactly when its leaf count is a power of two,
            // so a node that is not — the right subtree of a seven-leaf log, say,
            // or the root of any log whose size is not a power of two — cannot be
            // handed over as one value. It is decomposed into the balanced
            // subtrees it is made of, which is the same decomposition as §4.2's
            // full subtrees.
            if len.is_power_of_two() {
                return Step::Supplied;
            }
            return Step::Descend { check: None };
        }
        if len == 1 {
            // The only thing that can be known inside a single leaf is the leaf.
            return Step::ProvenLeaf;
        }
        // Something inside is known, so the node gets recomputed from its
        // children. If its head was also retained, §12.1 says the recomputation
        // is what must be believed, and the retained value must agree with it.
        Step::Descend {
            check: self.retained_head(start, len),
        }
    }

    /// Walks the tree in left-to-right order, calling `emit` for each node whose
    /// value the verifier cannot derive from what it already has.
    fn walk(
        &self,
        start: u64,
        len: u64,
        emit: &mut impl FnMut(u64, u64) -> Result<()>,
    ) -> Result<()> {
        if len == 0 {
            return Ok(());
        }
        match self.step(start, len) {
            Step::Retained(_) | Step::ProvenLeaf => Ok(()),
            Step::Supplied => emit(start, len),
            Step::Descend { .. } => {
                let left_len = split(len);
                self.walk(start, left_len, emit)?;
                self.walk(
                    start.saturating_add(left_len),
                    len.saturating_sub(left_len),
                    emit,
                )
            }
        }
    }
}

/// What the walk does at one node.
enum Step {
    /// The verifier holds this value already: a retained head with nothing proven
    /// inside it.
    Retained(HashValue),
    /// The prover supplies this value; the verifier consumes one proof element.
    Supplied,
    /// A leaf whose value came with the request.
    ProvenLeaf,
    /// Recompute from the children. `check` is a retained head for the same range
    /// that the recomputation must agree with (§12.1).
    Descend {
        /// The retained value to check against, if this range was also retained.
        check: Option<HashValue>,
    },
}

/// Recomputes the value of `start..start+len`, consuming proof elements in walk
/// order. Returns the value and whether the node is a single leaf.
fn evaluate(
    suite: CipherSuite,
    plan: &Plan,
    leaves: &[Leaf],
    start: u64,
    len: u64,
    supplied: &mut impl Iterator<Item = HashValue>,
) -> Result<(HashValue, bool)> {
    match plan.step(start, len) {
        Step::Retained(value) => Ok((value, len == 1)),
        // The count check in `verify` runs first, so the iterator cannot be short
        // here; the error keeps the promise that nothing panics regardless.
        Step::Supplied => {
            let value = supplied.next().ok_or(Error::ProofShape {
                expected: 0,
                actual: 0,
            })?;
            Ok((value, len == 1))
        }
        Step::ProvenLeaf => {
            let value = leaves
                .iter()
                .find(|(index, _)| *index == start)
                .map(|(_, value)| *value)
                .ok_or(Error::MissingLeaf { index: start })?;
            Ok((value, true))
        }
        Step::Descend { check } => {
            let left_len = split(len);
            let right_len = len.saturating_sub(left_len);
            let left = evaluate(suite, plan, leaves, start, left_len, supplied)?;
            let right = evaluate(
                suite,
                plan,
                leaves,
                start.saturating_add(left_len),
                right_len,
                supplied,
            )?;
            let value = parent_value(suite, left, right);

            // §12.1: the recomputation is authoritative; a retained head for the
            // same range must agree with it.
            if let Some(head) = check {
                if head != value {
                    return Err(Error::RetainedMismatch { start, len });
                }
            }

            Ok((value, false))
        }
    }
}

fn leaf_at(leaves: &[HashValue], index: u64) -> Result<HashValue> {
    let position = usize::try_from(index).map_err(|_| Error::LeafOutOfRange {
        index,
        size: as_u64(leaves.len()),
    })?;
    leaves.get(position).copied().ok_or(Error::LeafOutOfRange {
        index,
        size: as_u64(leaves.len()),
    })
}

const fn check_size(size: u64) -> Result<()> {
    if size == 0 || size > MAX_TREE_SIZE {
        return Err(Error::InvalidSize { size });
    }
    Ok(())
}

fn as_u64(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod tests {
    use super::*;
    use alloc::vec;

    const SUITE: CipherSuite = CipherSuite::Kt128Sha256Ed25519;

    fn leaves(n: u64) -> Vec<HashValue> {
        (0..n)
            .map(|i| {
                leaf_value(
                    SUITE,
                    &LogEntry {
                        timestamp: 1_700_000_000_000 + i,
                        prefix_tree: HashValue::from_bytes([u8::try_from(i % 256).unwrap(); 32]),
                    },
                )
                .unwrap()
            })
            .collect()
    }

    /// §3.2's rule, read off the figures: a five-leaf tree splits 4/1, not 3/2.
    #[test]
    fn split_follows_the_left_balanced_rule() {
        assert_eq!(split(2), 1);
        assert_eq!(split(3), 2);
        assert_eq!(split(4), 2);
        assert_eq!(split(5), 4);
        assert_eq!(split(6), 4);
        assert_eq!(split(7), 4);
        assert_eq!(split(8), 4);
        assert_eq!(split(9), 8);
        assert_eq!(split(u64::MAX), 1 << 63);
        // Every split is a power of two, is at least half, and leaves a
        // non-empty right subtree.
        for len in 2_u64..=4_096 {
            let k = split(len);
            assert!(k.is_power_of_two(), "split({len}) = {k}");
            assert!(k < len, "split({len}) = {k}");
            assert!(
                k * 2 >= len,
                "split({len}) = {k} is not the largest that fits"
            );
        }
    }

    /// §4.2's full subtrees, and §3.2's worked five-leaf tree.
    #[test]
    fn full_subtrees_follow_the_binary_representation() {
        assert_eq!(full_subtrees(1).unwrap(), vec![(0, 1)]);
        assert_eq!(full_subtrees(4).unwrap(), vec![(0, 4)]);
        assert_eq!(full_subtrees(5).unwrap(), vec![(0, 4), (4, 1)]);
        assert_eq!(full_subtrees(7).unwrap(), vec![(0, 4), (4, 2), (6, 1)]);
        assert_eq!(full_subtrees(11).unwrap(), vec![(0, 8), (8, 2), (10, 1)]);
        assert_eq!(full_subtrees(0), Err(Error::InvalidSize { size: 0 }));
        // The ranges tile 0..size exactly, in order.
        for size in 1_u64..=500 {
            let subtrees = full_subtrees(size).unwrap();
            let mut next = 0;
            for (start, len) in &subtrees {
                assert_eq!(*start, next, "size {size}");
                assert!(len.is_power_of_two());
                next += len;
            }
            assert_eq!(next, size);
            assert_eq!(subtrees.len(), usize::try_from(size.count_ones()).unwrap());
        }
    }

    /// A one-leaf log's root is the leaf value itself: there is no parent to hash.
    #[test]
    fn single_leaf_root_is_the_leaf() {
        let values = leaves(1);
        assert_eq!(root(SUITE, &values).unwrap(), values[0]);
    }

    /// §11.8 by hand for two and three leaves, including the `hashContent` prefix
    /// bytes, so a mistake in where `0x00` and `0x01` go shows up here.
    #[test]
    fn small_roots_match_the_hashing_rule() {
        let values = leaves(3);

        let two = parent_value(SUITE, (values[0], true), (values[1], true));
        assert_eq!(root(SUITE, &values[..2]).unwrap(), two);
        assert_eq!(
            two,
            hash::hash(
                SUITE,
                &[&[0x00], values[0].as_bytes(), &[0x00], values[1].as_bytes()]
            )
        );

        // Three leaves split 2/1: a parent on the left, a leaf on the right.
        let three = parent_value(SUITE, (two, false), (values[2], true));
        assert_eq!(root(SUITE, &values).unwrap(), three);
        assert_eq!(
            three,
            hash::hash(
                SUITE,
                &[&[0x01], two.as_bytes(), &[0x00], values[2].as_bytes()]
            )
        );
    }

    /// Rolling the full subtree heads up from the right must give the same root as
    /// the recursive split — the peer computes it the second way, so a divergence
    /// between the two formulations would be an interop bug waiting to happen.
    #[test]
    fn root_equals_a_right_fold_of_full_subtrees() {
        for size in 1_u64..=200 {
            let values = leaves(size);
            let subtrees = full_subtrees(size).unwrap();

            let mut iter = subtrees.iter().rev();
            let (start, len) = *iter.next().unwrap();
            let mut acc = (subtree_value(SUITE, &values, start, len).unwrap(), len == 1);
            for (start, len) in iter {
                let head = subtree_value(SUITE, &values, *start, *len).unwrap();
                acc = (parent_value(SUITE, (head, *len == 1), acc), false);
            }

            assert_eq!(root(SUITE, &values).unwrap(), acc.0, "size {size}");
        }
    }

    /// Appending a leaf must not change any existing leaf's contribution: the
    /// root of the first `k` leaves is stable as the log grows.
    #[test]
    fn growth_preserves_prefixes() {
        let values = leaves(40);
        for size in 1_usize..=40 {
            let prefix_root = root(SUITE, &values[..size]).unwrap();
            let retained = Retained::from_leaves(SUITE, as_u64(size), &values).unwrap();
            let mut iter = retained.full_subtrees.iter().rev();
            let ranges = full_subtrees(as_u64(size)).unwrap();
            let mut acc = {
                let (_, len) = ranges[ranges.len() - 1];
                (*iter.next().unwrap(), len == 1)
            };
            for (i, value) in iter.enumerate() {
                let (_, len) = ranges[ranges.len() - 2 - i];
                acc = (parent_value(SUITE, (*value, len == 1), acc), false);
            }
            assert_eq!(prefix_root, acc.0, "size {size}");
        }
    }

    /// The §3.2 figure: proving leaf 2 in a five-leaf log takes three values —
    /// the head of `0..2`, leaf 3, and leaf 4.
    #[test]
    fn inclusion_proof_matches_the_figure() {
        let values = leaves(5);
        let proof = prove(SUITE, &values, &[2], None).unwrap();
        assert_eq!(proof.elements.len(), 3);
        assert_eq!(
            proof.elements[0],
            subtree_value(SUITE, &values, 0, 2).unwrap()
        );
        assert_eq!(proof.elements[1], values[3]);
        assert_eq!(proof.elements[2], values[4]);

        let got = verify(SUITE, 5, &[(2, values[2])], None, &proof).unwrap();
        assert_eq!(got, root(SUITE, &values).unwrap());
    }

    /// Every single-leaf inclusion proof in every tree up to 64 leaves.
    #[test]
    fn inclusion_proofs_verify_everywhere() {
        for size in 1_u64..=64 {
            let values = leaves(size);
            let expected = root(SUITE, &values).unwrap();
            for index in 0..size {
                let proof = prove(SUITE, &values, &[index], None).unwrap();
                let got = verify(
                    SUITE,
                    size,
                    &[(index, values[index as usize])],
                    None,
                    &proof,
                )
                .unwrap();
                assert_eq!(got, expected, "size {size}, leaf {index}");
            }
        }
    }

    /// Batches: every pair, and the whole tree at once. Proving everything needs
    /// no proof elements at all.
    #[test]
    fn batch_inclusion_proofs_verify() {
        for size in 1_u64..=24 {
            let values = leaves(size);
            let expected = root(SUITE, &values).unwrap();

            for a in 0..size {
                for b in a + 1..size {
                    let proof = prove(SUITE, &values, &[a, b], None).unwrap();
                    let claimed = vec![(a, values[a as usize]), (b, values[b as usize])];
                    let got = verify(SUITE, size, &claimed, None, &proof).unwrap();
                    assert_eq!(got, expected, "size {size}, leaves {a} and {b}");
                }
            }

            let all: Vec<u64> = (0..size).collect();
            let proof = prove(SUITE, &values, &all, None).unwrap();
            assert!(
                proof.elements.is_empty(),
                "size {size}: nothing left to prove"
            );
            let claimed: Vec<Leaf> = all.iter().map(|i| (*i, values[*i as usize])).collect();
            assert_eq!(
                verify(SUITE, size, &claimed, None, &proof).unwrap(),
                expected
            );
        }
    }

    /// The §3.2 consistency figure: from a five-leaf log to a seven-leaf one, the
    /// prover supplies leaf 5 and leaf 6.
    #[test]
    fn consistency_proof_matches_the_figure() {
        let values = leaves(7);
        let retained = Retained::from_leaves(SUITE, 5, &values).unwrap();
        assert_eq!(retained.full_subtrees.len(), 2);

        let proof = prove(SUITE, &values, &[], Some(&retained)).unwrap();
        assert_eq!(proof.elements.len(), 2);
        assert_eq!(proof.elements[0], values[5]);
        assert_eq!(proof.elements[1], values[6]);

        let got = verify(SUITE, 7, &[], Some(&retained), &proof).unwrap();
        assert_eq!(got, root(SUITE, &values).unwrap());
    }

    /// Consistency between every pair of sizes up to 40, with and without a
    /// batched inclusion proof alongside.
    #[test]
    fn consistency_proofs_verify_everywhere() {
        let values = leaves(40);
        for new in 1_u64..=40 {
            let expected = root(SUITE, &values[..new as usize]).unwrap();
            for old in 1..=new {
                let retained = Retained::from_leaves(SUITE, old, &values).unwrap();
                let proof = prove(SUITE, &values[..new as usize], &[], Some(&retained)).unwrap();
                let got = verify(SUITE, new, &[], Some(&retained), &proof).unwrap();
                assert_eq!(got, expected, "{old} -> {new}");
            }
        }
    }

    /// §12.1's `MUST`: when inclusion is proven for a leaf inside a retained
    /// subtree, the head becomes recomputable, and a wrong retained value has to
    /// be caught rather than papered over.
    #[test]
    fn retained_head_is_checked_when_it_is_recomputable() {
        let values = leaves(7);
        let honest = Retained::from_leaves(SUITE, 5, &values).unwrap();

        // Leaf 1 is inside the retained 0..4 subtree.
        let proof = prove(SUITE, &values, &[1], Some(&honest)).unwrap();
        let claimed = vec![(1, values[1])];
        let expected = root(SUITE, &values).unwrap();
        assert_eq!(
            verify(SUITE, 7, &claimed, Some(&honest), &proof).unwrap(),
            expected
        );

        // Now corrupt the retained head for 0..4. The proof still recomputes it
        // from leaf 1 and the supplied copath, so the disagreement must surface.
        let mut tampered = honest.clone();
        tampered.full_subtrees[0] = HashValue::from_bytes([0xff; 32]);
        assert_eq!(
            verify(SUITE, 7, &claimed, Some(&tampered), &proof),
            Err(Error::RetainedMismatch { start: 0, len: 4 })
        );

        // Without the inclusion proof the head is not recomputable, so the
        // corrupted value is used and simply produces a different root — which is
        // why the check above is the one that matters.
        let plain = prove(SUITE, &values, &[], Some(&tampered)).unwrap();
        let other = verify(SUITE, 7, &[], Some(&tampered), &plain).unwrap();
        assert_ne!(other, expected);
    }

    /// A tampered proof element must change the root rather than be absorbed.
    #[test]
    fn tampering_with_an_element_changes_the_root() {
        let values = leaves(9);
        let expected = root(SUITE, &values).unwrap();
        let proof = prove(SUITE, &values, &[3], None).unwrap();

        for i in 0..proof.elements.len() {
            let mut broken = proof.clone();
            let mut bytes = *broken.elements[i].as_bytes();
            bytes[0] ^= 0x01;
            broken.elements[i] = HashValue::from_bytes(bytes);
            let got = verify(SUITE, 9, &[(3, values[3])], None, &broken).unwrap();
            assert_ne!(got, expected, "element {i}");
        }
    }

    /// A proof of the wrong length is a shape error, not a panic and not a
    /// silently different root.
    #[test]
    fn wrong_element_count_is_rejected() {
        let values = leaves(9);
        let proof = prove(SUITE, &values, &[3], None).unwrap();
        let needed = proof.elements.len();

        let mut short = proof.clone();
        short.elements.pop();
        assert_eq!(
            verify(SUITE, 9, &[(3, values[3])], None, &short),
            Err(Error::ProofShape {
                expected: needed,
                actual: needed - 1
            })
        );

        let mut long = proof.clone();
        long.elements.push(HashValue::ZERO);
        assert_eq!(
            verify(SUITE, 9, &[(3, values[3])], None, &long),
            Err(Error::ProofShape {
                expected: needed,
                actual: needed + 1
            })
        );
    }

    #[test]
    fn malformed_requests_are_rejected() {
        let values = leaves(8);
        assert_eq!(root(SUITE, &[]), Err(Error::InvalidSize { size: 0 }));
        assert_eq!(
            prove(SUITE, &values, &[8], None),
            Err(Error::LeafOutOfRange { index: 8, size: 8 })
        );
        assert_eq!(
            prove(SUITE, &values, &[3, 3], None),
            Err(Error::LeavesNotSorted)
        );
        assert_eq!(
            prove(SUITE, &values, &[5, 2], None),
            Err(Error::LeavesNotSorted)
        );

        let retained = Retained {
            size: 9,
            full_subtrees: vec![HashValue::ZERO],
        };
        assert_eq!(
            prove(SUITE, &values, &[], Some(&retained)),
            Err(Error::RetainedTooLarge {
                retained: 9,
                size: 8
            })
        );
        let wrong_shape = Retained {
            size: 5,
            full_subtrees: vec![HashValue::ZERO],
        };
        assert_eq!(
            prove(SUITE, &values, &[], Some(&wrong_shape)),
            Err(Error::RetainedShape {
                expected: 2,
                actual: 1
            })
        );
    }
}
