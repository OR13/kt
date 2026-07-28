//! Implicit binary search tree over log positions
//! (`draft-ietf-keytrans-protocol-05` §4.1, Appendix A).
//!
//! The leaves of the log tree, viewed as a flat array, are also a binary search
//! tree — not a balanced one: the root of a log with `n` entries is
//! `2^floor(log2(n)) - 1`, the greatest power of two minus one below `n`, so it
//! sits wherever the last doubling put it. A log of 50 entries has its root at
//! entry 31, not entry 25, and keeps it there until the log approaches 64
//! entries (§4.1).
//!
//! That choice is what makes the log cheap to monitor: every user checks the same
//! handful of entries, so a misbehaving log has to lie to everyone in the same
//! place. Users enforce the search-tree property on timestamps — everything in
//! the root's left subtree is at or before the root, everything in its right
//! subtree at or after — which is how monotonicity is verified without reading
//! the whole log (§4.1, §4.2).
//!
//! # About the pseudocode
//!
//! Appendix A gives `log2`, `level`, `root`, `left`, and `right` in Python, where
//! integers are unbounded and a leaf's missing child raises. Here the domain is
//! `u64` and the missing cases are [`Error`] values, because these functions get
//! called with tree sizes and node indices that came off the wire:
//!
//! - `log2` and `level` are the same functions written with bit intrinsics.
//!   Appendix A's `log2` counts shifts and its `level` counts trailing one-bits;
//!   `u64::leading_zeros` and `u64::trailing_ones` compute both without a loop
//!   that could shift by 64 and panic. The unit tests check the equivalence
//!   against a literal transcription of the pseudocode.
//! - `root(0)` is [`Error::EmptyLog`] rather than 0. Appendix A's `log2(0)`
//!   returns 0, which makes `root(0)` return 0 — the index of the first entry of
//!   a log that has no entries. That is a value no caller can use correctly.
//! - `right` has one case the pseudocode does not: the rightmost entry of the log
//!   has no right child ([`Error::NoRightChild`]). Appendix A's `right` walks left
//!   from the right child until it lands inside the tree, which for `x == n-1`
//!   walks off the bottom and calls `left` on a leaf.

use alloc::vec::Vec;
use core::fmt;

/// A node or size outside the implicit binary search tree's domain.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Error {
    /// A log with no entries has no root and no frontier.
    EmptyLog,
    /// A leaf was asked for a child. Leaves are the even indices (§4.1).
    LeafHasNoChildren {
        /// The leaf's index.
        index: u64,
    },
    /// The rightmost entry of the log has nothing to its right, so its right
    /// subtree is empty.
    NoRightChild {
        /// The node's index, equal to `size - 1`.
        index: u64,
        /// The log size the query was made against.
        size: u64,
    },
    /// A node index was not inside a log of the given size.
    IndexOutOfRange {
        /// The index asked about.
        index: u64,
        /// The log size it was asked about, so valid indices are `0..size`.
        size: u64,
    },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyLog => f.write_str("an empty log has no implicit binary search tree"),
            Self::LeafHasNoChildren { index } => {
                write!(f, "log entry {index} is a leaf and has no children")
            }
            Self::NoRightChild { index, size } => {
                write!(
                    f,
                    "log entry {index} is the rightmost of {size} and has no right child"
                )
            }
            Self::IndexOutOfRange { index, size } => {
                write!(f, "log entry {index} is outside a log of {size} entries")
            }
        }
    }
}

impl core::error::Error for Error {}

/// A specialized [`Result`] for tree navigation.
pub type Result<T> = core::result::Result<T, Error>;

/// The exponent of the largest power of two not greater than `x`
/// (Appendix A `log2`).
///
/// `log2(0)` is 0, following the pseudocode. That is a convention, not a
/// mathematical claim; [`root`] rejects an empty log rather than relying on it.
#[must_use]
pub const fn log2(x: u64) -> u32 {
    match x {
        0 => 0,
        // 63 - leading_zeros is floor(log2(x)) for x > 0, which is what
        // Appendix A's shift-counting loop computes.
        _ => u64::BITS
            .saturating_sub(1)
            .saturating_sub(x.leading_zeros()),
    }
}

/// The level of a node: 0 for leaves, one more than its highest child otherwise
/// (Appendix A `level`).
///
/// This is the count of trailing one-bits, which is what Appendix A's loop
/// computes: even indices have none and are leaves.
#[must_use]
pub const fn level(x: u64) -> u32 {
    x.trailing_ones()
}

/// Whether `x` is a leaf, i.e. an even index (§4.1).
#[must_use]
pub const fn is_leaf(x: u64) -> bool {
    x & 1 == 0
}

/// The root of the search over a log of `size` entries (Appendix A `root`).
///
/// `2^floor(log2(size)) - 1`: the greatest power of two minus one that is less
/// than `size` (§4.1).
///
/// # Errors
///
/// [`Error::EmptyLog`] if `size` is 0.
pub const fn root(size: u64) -> Result<u64> {
    if size == 0 {
        return Err(Error::EmptyLog);
    }
    // log2(size) <= 63 for size >= 1, so neither the shift nor the subtraction
    // can overflow.
    match 1_u64.checked_shl(log2(size)) {
        Some(power) => Ok(power.saturating_sub(1)),
        None => Err(Error::EmptyLog),
    }
}

/// The left child of an intermediate node (Appendix A `left`).
///
/// The left child does not depend on the log size: every index below a node is
/// present whenever the node itself is.
///
/// # Errors
///
/// [`Error::LeafHasNoChildren`] if `x` is even.
pub const fn left(x: u64) -> Result<u64> {
    let k = level(x);
    if k == 0 {
        return Err(Error::LeafHasNoChildren { index: x });
    }
    match 1_u64.checked_shl(k.saturating_sub(1)) {
        Some(bit) => Ok(x ^ bit),
        None => Err(Error::LeafHasNoChildren { index: x }),
    }
}

/// The right child of an intermediate node in a log of `size` entries
/// (Appendix A `right`).
///
/// Unlike [`left`], this depends on the size: a node's nominal right child may
/// not exist yet, in which case the child is the highest of its descendants that
/// does exist — the pseudocode's `while x >= n: x = left(x)`.
///
/// # Errors
///
/// - [`Error::IndexOutOfRange`] if `x` is not below `size`.
/// - [`Error::LeafHasNoChildren`] if `x` is even.
/// - [`Error::NoRightChild`] if `x` is the rightmost entry, `size - 1`: its
///   right subtree spans `x+1..` and so is empty.
pub const fn right(x: u64, size: u64) -> Result<u64> {
    if x >= size {
        return Err(Error::IndexOutOfRange { index: x, size });
    }
    let k = level(x);
    if k == 0 {
        return Err(Error::LeafHasNoChildren { index: x });
    }
    if x.saturating_add(1) == size {
        return Err(Error::NoRightChild { index: x, size });
    }
    // x < size <= u64::MAX implies k <= 63, so shifting by k-1 <= 62 is in range.
    let Some(bits) = 3_u64.checked_shl(k.saturating_sub(1)) else {
        return Err(Error::IndexOutOfRange { index: x, size });
    };
    let mut node = x ^ bits;
    // Descend left until inside the tree. Each step clears a bit, so the walk
    // terminates; and because x+1 < size, it terminates at a node that exists —
    // the leftmost descendant reachable this way is x+1.
    while node >= size {
        match left(node) {
            Ok(next) => node = next,
            Err(err) => return Err(err),
        }
    }
    Ok(node)
}

/// The frontier of a log with `size` entries (§4.1).
///
/// The root, then the root's right child, that child's right child, and so on
/// until the rightmost entry. For 50 entries this is `[31, 47, 49]`.
///
/// Users retain the frontier rather than just the rightmost timestamp: it is what
/// makes the later timestamp checks in §4.2 cheap.
///
/// # Errors
///
/// [`Error::EmptyLog`] if `size` is 0.
pub fn frontier(size: u64) -> Result<Vec<u64>> {
    let mut node = root(size)?;
    let last = size.saturating_sub(1);
    let mut out = alloc::vec![node];
    while node != last {
        node = right(node, size)?;
        out.push(node);
    }
    Ok(out)
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

    /// Appendix A's `log2`, transcribed literally, with the one guard Python
    /// does not need: shifting a `u64` by 64 panics in Rust.
    fn log2_reference(x: u64) -> u32 {
        if x == 0 {
            return 0;
        }
        let mut k = 0_u32;
        while x.checked_shr(k).unwrap_or(0) > 0 {
            k += 1;
        }
        k - 1
    }

    /// Appendix A's `level`, transcribed literally.
    fn level_reference(x: u64) -> u32 {
        if x & 0x01 == 0 {
            return 0;
        }
        let mut k = 0_u32;
        while (x.checked_shr(k).unwrap_or(0) & 0x01) == 1 {
            k += 1;
        }
        k
    }

    /// The bit-intrinsic forms must agree with the pseudocode everywhere, not
    /// just on the values a vector file happens to contain.
    #[test]
    fn bit_tricks_match_the_pseudocode() {
        for x in 0_u64..=200_000 {
            assert_eq!(log2(x), log2_reference(x), "log2({x})");
            assert_eq!(level(x), level_reference(x), "level({x})");
        }
        for x in [
            u64::MAX,
            u64::MAX - 1,
            1 << 62,
            (1 << 62) - 1,
            1 << 63,
            (1 << 63) - 1,
            u64::MAX / 3,
        ] {
            assert_eq!(log2(x), log2_reference(x), "log2({x})");
            assert_eq!(level(x), level_reference(x), "level({x})");
        }
    }

    /// §4.1: "the index of the root log entry [...] is the greatest power of two,
    /// minus one, that is less than the size of the log."
    #[test]
    fn root_is_the_greatest_power_of_two_minus_one() {
        assert_eq!(root(0), Err(Error::EmptyLog));
        assert_eq!(root(1).unwrap(), 0);
        assert_eq!(root(2).unwrap(), 1);
        assert_eq!(root(3).unwrap(), 1);
        assert_eq!(root(4).unwrap(), 3);
        assert_eq!(root(14).unwrap(), 7);
        // The worked example from §4.1: a log of 50 entries roots at 31, not 25,
        // and moves to 63 only once the log has 64 entries.
        assert_eq!(root(50).unwrap(), 31);
        assert_eq!(root(63).unwrap(), 31);
        assert_eq!(root(64).unwrap(), 63);
        assert_eq!(root(65).unwrap(), 63);
        assert_eq!(root(u64::MAX).unwrap(), (1 << 63) - 1);
    }

    /// The example tree in §4.1, drawn for 14 entries. Read off the figure:
    /// 7 is the root, with 3 and 11 below it, and 13 hangs off 11 because 15
    /// does not exist yet.
    #[test]
    fn fourteen_entry_tree_matches_the_figure() {
        let n = 14;
        assert_eq!(root(n).unwrap(), 7);
        assert_eq!(left(7).unwrap(), 3);
        assert_eq!(right(7, n).unwrap(), 11);
        assert_eq!(left(3).unwrap(), 1);
        assert_eq!(right(3, n).unwrap(), 5);
        assert_eq!(left(11).unwrap(), 9);
        assert_eq!(right(11, n).unwrap(), 13);
        assert_eq!(left(1).unwrap(), 0);
        assert_eq!(right(1, n).unwrap(), 2);
        assert_eq!(left(13).unwrap(), 12);
        assert_eq!(
            right(13, n),
            Err(Error::NoRightChild {
                index: 13,
                size: 14
            })
        );
    }

    /// §4.1's other worked example: "the frontier would be entries 31, 47, 49."
    #[test]
    fn frontier_of_fifty_entries() {
        assert_eq!(frontier(50).unwrap(), alloc::vec![31, 47, 49]);
    }

    #[test]
    fn frontier_of_a_perfect_tree_is_just_the_root_path_to_the_end() {
        assert_eq!(frontier(1).unwrap(), alloc::vec![0]);
        assert_eq!(frontier(2).unwrap(), alloc::vec![1]);
        assert_eq!(frontier(8).unwrap(), alloc::vec![7]);
        assert_eq!(frontier(9).unwrap(), alloc::vec![7, 8]);
        assert_eq!(frontier(0), Err(Error::EmptyLog));
    }

    /// The frontier always starts at the root, ends at the last entry, and
    /// strictly increases — it is a walk rightwards.
    #[test]
    fn frontier_is_increasing_and_ends_at_the_last_entry() {
        for size in 1_u64..=2_000 {
            let f = frontier(size).unwrap();
            assert_eq!(f[0], root(size).unwrap(), "size {size}");
            assert_eq!(*f.last().unwrap(), size - 1, "size {size}");
            for pair in f.windows(2) {
                assert!(pair[0] < pair[1], "size {size}: {pair:?} not increasing");
            }
        }
    }

    /// Leaves are the even indices; asking one for a child is an error, not a
    /// wrapped-around index.
    #[test]
    fn leaves_have_no_children() {
        for x in [0_u64, 2, 4, 100, u64::MAX - 1] {
            assert!(is_leaf(x));
            assert_eq!(left(x), Err(Error::LeafHasNoChildren { index: x }));
            assert_eq!(
                right(x, u64::MAX),
                Err(Error::LeafHasNoChildren { index: x })
            );
        }
    }

    #[test]
    fn out_of_range_nodes_are_rejected() {
        assert_eq!(
            right(7, 7),
            Err(Error::IndexOutOfRange { index: 7, size: 7 })
        );
        assert_eq!(
            right(100, 50),
            Err(Error::IndexOutOfRange {
                index: 100,
                size: 50
            })
        );
    }

    /// The search-tree invariant from §4.1: every index in the left subtree is
    /// below the node, every index in the right subtree is above it, and the
    /// subtrees partition the rest of the range. Checked by walking every tree up
    /// to a few hundred entries.
    #[test]
    fn children_bracket_their_parent() {
        for size in 1_u64..=300 {
            let mut stack = alloc::vec![(root(size).unwrap(), 0_u64, size)];
            let mut seen = alloc::vec![false; usize::try_from(size).unwrap()];
            while let Some((node, low, high)) = stack.pop() {
                assert!(
                    low <= node && node < high,
                    "size {size}: {node} outside {low}..{high}"
                );
                assert!(
                    !seen[usize::try_from(node).unwrap()],
                    "size {size}: {node} twice"
                );
                seen[usize::try_from(node).unwrap()] = true;

                if node > low {
                    let l = left(node).unwrap();
                    assert!(l < node);
                    stack.push((l, low, node));
                }
                if node < high - 1 {
                    let r = right(node, size).unwrap();
                    assert!(r > node, "size {size}: right({node}) = {r}");
                    stack.push((r, node + 1, high));
                }
            }
            assert!(
                seen.iter().all(|s| *s),
                "size {size}: not every entry was reachable"
            );
        }
    }

    /// The root moves only when the log size reaches a power of two, and the old
    /// root becomes the left child of the new one — §4.1's "until the log roughly
    /// doubles in size and a new root is established at entry 63".
    #[test]
    fn a_new_root_is_established_on_each_power_of_two() {
        for exponent in 1_u32..40 {
            let size = 1_u64 << exponent;
            let before = root(size - 1).unwrap();
            let after = root(size).unwrap();
            assert_eq!(after, size - 1, "size {size}");
            assert_eq!(before, (size / 2) - 1, "size {size}");
            assert_eq!(left(after).unwrap(), before, "size {size}");
            // And it stays put for the whole range up to the next power of two.
            assert_eq!(root(size + 1).unwrap(), after, "size {size}");
            assert_eq!(root((size * 2) - 1).unwrap(), after, "size {size}");
        }
        // The worked example: 31 is the root from size 32 through 63, and 63
        // takes over at 64.
        assert_eq!(root(32).unwrap(), 31);
        assert_eq!(root(50).unwrap(), 31);
        assert_eq!(root(63).unwrap(), 31);
        assert_eq!(root(64).unwrap(), 63);
        assert_eq!(left(63).unwrap(), 31);
    }
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod error_tests {
    use super::*;
    use alloc::string::ToString as _;

    /// Every variant renders with the indices it names. An implicit-binary-search-tree
    /// error is what a client reports when a log's timestamps do not line up, so
    /// "invalid" alone would not help anyone debug it.
    #[test]
    fn every_error_renders_its_detail() {
        use core::error::Error as _;

        let cases: [(Error, &[&str]); 4] = [
            (Error::EmptyLog, &["empty"]),
            (Error::LeafHasNoChildren { index: 4 }, &["4", "leaf"]),
            // 13 of 14: both numbers, and the end of the range.
            (
                Error::NoRightChild {
                    index: 13,
                    size: 14,
                },
                &["13", "14"],
            ),
            (
                Error::IndexOutOfRange {
                    index: 20,
                    size: 14,
                },
                &["20", "14"],
            ),
        ];
        for (error, needles) in cases {
            let rendered = error.to_string();
            for needle in needles {
                assert!(rendered.contains(needle), "{rendered:?} omits {needle:?}");
            }
            assert!(error.source().is_none());
        }
    }

    /// `log2` and `level` are total, including at the boundaries where a shift-based
    /// implementation would overflow.
    #[test]
    fn bit_helpers_are_total_at_the_boundaries() {
        assert_eq!(log2(0), 0, "the pseudocode's convention");
        assert_eq!(log2(1), 0);
        assert_eq!(log2(u64::MAX), 63);
        assert_eq!(level(0), 0);
        assert_eq!(level(u64::MAX), 64, "every bit set is 64 trailing ones");
        assert!(is_leaf(0));
        assert!(!is_leaf(1));
    }

    /// The root of the largest expressible log, where `1 << 63` is the last shift
    /// that fits.
    #[test]
    fn the_largest_log_has_a_root() {
        assert_eq!(root(u64::MAX).unwrap(), (1 << 63) - 1);
        assert_eq!(root(1 << 63).unwrap(), (1 << 63) - 1);
    }

    /// `left` on the highest possible intermediate node: `u64::MAX` has level 64, so
    /// the shift is by 63 and stays in range.
    #[test]
    fn left_of_the_deepest_node_is_in_range() {
        assert_eq!(left(u64::MAX).unwrap(), u64::MAX ^ (1 << 63));
    }
}

/// The ancestors of `x` in a log of `size` entries, from the root downwards
/// (§4.2).
///
/// Derived from §4.1's own definition rather than from a node-index formula: the
/// implicit tree is a *search* tree over log indices, so descending from the root
/// and comparing against `x` at each step visits exactly `x`'s ancestors. That also
/// makes the direction obvious, which a bit-twiddling `parent` function does not.
///
/// # Errors
///
/// [`Error::IndexOutOfRange`] if `x` is not below `size`, plus the navigation errors
/// of [`left`] and [`right`].
pub fn direct_path(x: u64, size: u64) -> Result<Vec<u64>> {
    if x >= size {
        return Err(Error::IndexOutOfRange { index: x, size });
    }
    let mut out = Vec::new();
    let mut node = root(size)?;
    while node != x {
        out.push(node);
        node = if x < node {
            left(node)?
        } else {
            right(node, size)?
        };
    }
    Ok(out)
}

/// The log entries whose timestamps a user needs to advance their view (§4.2).
///
/// `advertised` is the tree size the user last observed, if any. The result is the
/// sequence of log entry indices whose timestamps the Transparency Log must provide,
/// **in the order the user checks them**: each timestamp must be greater than or
/// equal to the one before, and the first greater than or equal to the rightmost
/// entry the user retained.
///
/// §4.2 describes it in two parts. From an advertised size, take the direct path of
/// entry `advertised - 1` in the *new* tree and keep the entries at or beyond
/// `advertised` — the ones the user has not seen. The last of those lies on the
/// frontier, so the walk continues along right children to the rightmost entry. With
/// nothing advertised, there is no direct path to take and the whole frontier is
/// provided instead.
///
/// The order within the direct path is closest ancestor first. That is not arbitrary:
/// a nearer right-ancestor sits in the left subtree of a further one, so the
/// search-tree property of §4.1 makes its timestamp the smaller of the two. Walking
/// outwards is what makes the sequence monotonic, which is the property the user is
/// checking.
///
/// Returns an empty sequence when the user is already up to date — and also, per the
/// procedure as written, in a case where they are *not*: see
/// [`leaves_right_edge_unchecked`].
///
/// # Errors
///
/// [`Error::EmptyLog`] if `size` is 0, or [`Error::IndexOutOfRange`] if `advertised`
/// exceeds `size`.
pub fn update_view(size: u64, advertised: Option<u64>) -> Result<Vec<u64>> {
    let last = root(size).and(Ok(size.saturating_sub(1)))?;

    let mut out = match advertised {
        // Already current: nothing to send, nothing to check.
        Some(previous) if previous == size => return Ok(Vec::new()),
        Some(previous) if previous > size => {
            return Err(Error::IndexOutOfRange {
                index: previous,
                size,
            });
        }
        // A user with no previous view, or one who saw an empty log, starts from
        // the root and walks the frontier.
        None | Some(0) => alloc::vec![root(size)?],
        Some(previous) => {
            let from = previous.saturating_sub(1);
            let mut ancestors: Vec<u64> = direct_path(from, size)?
                .into_iter()
                .filter(|ancestor| *ancestor >= previous)
                .collect();
            // Root-downwards becomes closest-ancestor-first.
            ancestors.reverse();
            ancestors
        }
    };

    // Continue along the frontier to the rightmost entry. §4.2: "The last of these
    // log entries will lie on the new tree's frontier. From this log entry, compute
    // the remainder of the frontier." With nothing to start from there is nothing to
    // continue, which is where the gap documented on
    // `leaves_right_edge_unchecked` comes from.
    while out.last().is_some_and(|node| *node != last) {
        let Some(node) = out.last().copied() else {
            break;
        };
        out.push(right(node, size)?);
    }
    Ok(out)
}

/// Whether §4.2's procedure leaves the new rightmost entry's timestamp unchecked.
///
/// The procedure starts from the direct path of entry `advertised - 1`. When that
/// entry *is* the root of the new tree, its direct path is empty, so there is nothing
/// to filter and nothing to continue the frontier walk from — and [`update_view`]
/// yields no entries at all even though the log has grown. The Go peer reproduces
/// this exactly (`UpdateView(12, 8)` is empty there too), so it is a property of the
/// procedure rather than of either implementation.
///
/// It is not a rare corner. The condition is exactly that `advertised - 1` still lies
/// on the *new* tree's frontier: everything above a frontier node is reached by
/// turning left, so such a node has no ancestors greater than itself, so the filter
/// "index at or beyond `advertised`" removes the whole direct path. And a user's
/// previous rightmost entry is `advertised - 1`, which was the end of the frontier
/// they retained — so the case arises whenever the log grows in a way that keeps that
/// entry on the frontier, which is common rather than exotic. `advertised - 1 ==
/// root(size)` is one instance of it.
///
/// What the user then fails to learn is everything §4.2 is for: the timestamps of the
/// entries added since, the monotonic series those timestamps are supposed to form,
/// and the clock bounds `max_ahead` and `max_behind`, which are checked against the
/// rightmost entry's timestamp — the one they are never given.
///
/// This function exists so a client can notice and refuse rather than treat an empty
/// response as "nothing to check". Tracked as `DRAFT-06` in `docs/interop.md`; not filed
/// upstream.
///
/// # Errors
///
/// [`Error::EmptyLog`] if `size` is 0, or [`Error::IndexOutOfRange`] if `advertised`
/// exceeds `size`.
pub fn leaves_right_edge_unchecked(size: u64, advertised: Option<u64>) -> Result<bool> {
    let view = update_view(size, advertised)?;
    let up_to_date = advertised == Some(size);
    Ok(!up_to_date && view.last() != Some(&size.saturating_sub(1)))
}

#[cfg(test)]
#[allow(
    clippy::arithmetic_side_effects,
    clippy::indexing_slicing,
    clippy::unwrap_used,
    reason = "tests fail loudly by panicking; the lints protect the library paths"
)]
mod view_tests {
    use super::*;

    /// The direct path of every entry in every tree up to 300 entries: it starts at
    /// the root, ends at the entry's parent, and every step is a real child link.
    #[test]
    fn direct_paths_descend_from_the_root() {
        for size in 1_u64..=300 {
            let expected_root = root(size).unwrap();
            for x in 0..size {
                let path = direct_path(x, size).unwrap();
                if x == expected_root {
                    assert!(path.is_empty(), "size {size}: the root has no ancestors");
                    continue;
                }
                assert_eq!(path[0], expected_root, "size {size}, entry {x}");
                // Each step is the left or right child of the previous.
                for pair in path.windows(2) {
                    let (parent, child) = (pair[0], pair[1]);
                    let expected = if child < parent {
                        left(parent).unwrap()
                    } else {
                        right(parent, size).unwrap()
                    };
                    assert_eq!(
                        child, expected,
                        "size {size}, entry {x}: {parent} -> {child}"
                    );
                }
                // And the last element really is x's parent.
                let last = *path.last().unwrap();
                let child = if x < last {
                    left(last).unwrap()
                } else {
                    right(last, size).unwrap()
                };
                assert_eq!(child, x, "size {size}, entry {x}");
                assert!(!path.contains(&x));
            }
        }
        assert_eq!(
            direct_path(5, 5),
            Err(Error::IndexOutOfRange { index: 5, size: 5 })
        );
    }

    /// §4.2's worked shape, on the tree the §3.2 consistency figure uses: a user who
    /// saw 5 entries and is shown 7 needs entries 5 and 6.
    #[test]
    fn update_view_matches_the_consistency_figure() {
        assert_eq!(update_view(7, Some(5)).unwrap(), alloc::vec![5, 6]);
    }

    /// A user with no previous view gets the frontier, which is what §4.2 says.
    #[test]
    fn a_new_user_gets_the_frontier() {
        for size in 1_u64..=200 {
            assert_eq!(
                update_view(size, None).unwrap(),
                frontier(size).unwrap(),
                "size {size}"
            );
            assert_eq!(
                update_view(size, Some(0)).unwrap(),
                frontier(size).unwrap(),
                "size {size}"
            );
        }
    }

    /// A user who is already current needs nothing.
    #[test]
    fn an_up_to_date_user_gets_nothing() {
        for size in 1_u64..=50 {
            assert!(
                update_view(size, Some(size)).unwrap().is_empty(),
                "size {size}"
            );
        }
        assert_eq!(
            update_view(5, Some(6)),
            Err(Error::IndexOutOfRange { index: 6, size: 5 })
        );
    }

    /// The properties §4.2 relies on, over every pair of sizes up to 120: the
    /// sequence is strictly increasing in index, every entry is one the user has not
    /// seen, it ends at the rightmost entry, and it is logarithmic in the number of
    /// entries added.
    #[test]
    fn update_view_is_an_increasing_walk_to_the_right_edge() {
        for size in 1_u64..=120 {
            for advertised in 0..=size {
                let view = update_view(size, Some(advertised)).unwrap();
                if advertised == size {
                    assert!(view.is_empty());
                    continue;
                }
                if view.is_empty() {
                    // The §4.2 gap, which has its own test below. Not an error here,
                    // but not something to paper over either.
                    assert!(
                        leaves_right_edge_unchecked(size, Some(advertised)).unwrap(),
                        "size {size}, advertised {advertised}: empty for another reason"
                    );
                    continue;
                }
                assert_eq!(
                    *view.last().unwrap(),
                    size - 1,
                    "size {size}, advertised {advertised}: must reach the right edge"
                );
                for pair in view.windows(2) {
                    assert!(
                        pair[0] < pair[1],
                        "size {size}, advertised {advertised}: {pair:?} not increasing"
                    );
                }
                for node in &view {
                    assert!(
                        *node >= advertised.saturating_sub(1),
                        "size {size}, advertised {advertised}: {node} is already retained"
                    );
                }
                // Logarithmic: two walks up and along a tree of this size.
                let bound = 2 * usize::try_from(log2(size)).unwrap() + 4;
                assert!(
                    view.len() <= bound,
                    "size {size}, advertised {advertised}: {} entries is not logarithmic",
                    view.len()
                );
            }
        }
    }

    /// §4.2 provides nothing when the user's previous rightmost entry is still on the
    /// new frontier, leaving everything added since unverified. The Go peer does the
    /// same, so this is the procedure and not an implementation choice; the test pins
    /// the condition so a future draft revision changing it shows up as a failure.
    #[test]
    fn the_procedure_checks_nothing_from_a_frontier_size() {
        // The example from the write-up: a user who saw 8 entries, shown 12.
        assert!(update_view(12, Some(8)).unwrap().is_empty());
        assert!(leaves_right_edge_unchecked(12, Some(8)).unwrap());
        // Yet the frontier grew, so there was something the user should have checked.
        assert_eq!(frontier(12).unwrap(), alloc::vec![7, 11]);
        assert_eq!(frontier(8).unwrap(), alloc::vec![7]);

        // The condition is exactly that `advertised - 1` is still on the frontier:
        // a frontier node is reached only by turning left from above, so it has no
        // ancestors greater than itself and the direct path filters away entirely.
        for size in 2_u64..=400 {
            let edge = frontier(size).unwrap();
            for advertised in 1..size {
                let unchecked = leaves_right_edge_unchecked(size, Some(advertised)).unwrap();
                assert_eq!(
                    unchecked,
                    edge.contains(&(advertised - 1)),
                    "size {size}, advertised {advertised}"
                );
            }
        }

        // How often that is: for a log of 1000 entries, these advertised sizes get
        // nothing back — the frontier shifted by one, less the up-to-date case.
        let affected: Vec<u64> = (1..1000)
            .filter(|m| leaves_right_edge_unchecked(1000, Some(*m)).unwrap())
            .collect();
        assert_eq!(affected, alloc::vec![512, 768, 896, 960, 992]);
        assert_eq!(
            frontier(1000).unwrap(),
            alloc::vec![511, 767, 895, 959, 991, 999]
        );

        // A user who is up to date, or who has never synchronised, is unaffected.
        assert!(!leaves_right_edge_unchecked(12, Some(12)).unwrap());
        assert!(!leaves_right_edge_unchecked(12, None).unwrap());
    }

    /// The monotonicity §4.2 depends on, checked against timestamps built to respect
    /// the search-tree property: if the log is honest, the sequence a user is given is
    /// non-decreasing. This is the property that makes the order in `update_view`
    /// load-bearing rather than cosmetic.
    #[test]
    fn an_honest_log_yields_monotonic_timestamps() {
        // A timestamp assignment that satisfies §4.1: entry i gets timestamp i, which
        // is monotonic in index and therefore respects every subtree relation.
        for size in 1_u64..=120 {
            for advertised in 0..size {
                let view = update_view(size, Some(advertised)).unwrap();
                let timestamps: Vec<u64> = view.to_vec();
                for pair in timestamps.windows(2) {
                    assert!(pair[0] <= pair[1], "size {size}, advertised {advertised}");
                }
            }
        }
    }
}
