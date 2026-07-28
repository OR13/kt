//! Distinguished log entries (§6.1), and walking them (§10.1).
//!
//! Users cannot check every log entry, so the protocol picks out a sparse set of them as
//! **distinguished** and asks everyone to check consistency against those. That makes them
//! the common reference points in the log: if two users agree about a distinguished entry
//! they are looking at the same log, and if a label owner inspects every distinguished
//! entry since they last looked, nothing can have been hidden from them in between.
//!
//! Two properties make that work, and both come out of *how* the set is chosen rather than
//! from any check a user performs:
//!
//! **Regularly spaced.** §6.1 marks an entry distinguished when the gap between the
//! timestamps bracketing it reaches the Reasonable Monitoring Window, then recurses into
//! both halves. So there is roughly one per RMW of elapsed time no matter how fast entries
//! are added — which is what stops a busy log from drowning label owners in reference
//! points, or a quiet one from leaving them with none.
//!
//! **Stable.** Once distinguished, always distinguished. The recursion at a node depends
//! only on the two timestamps bracketing it, and those are fixed once the entries either
//! side exist. A log therefore cannot let an entry quietly stop being distinguished to keep
//! it out of a label owner's inspection.
//!
//! # What is derived from what
//!
//! [`enumerate`] is §6.1's recursion written out, and everything else here is defined in
//! terms of the set it produces: [`rightmost`] is that set's greatest element,
//! [`previous_rightmost`] its greatest element left of the rightmost log entry. That is
//! deliberate. The Go peer computes both by walking the frontier instead, which is much
//! cheaper and not obviously the same thing — so `distinguished.json` compares the two, and
//! the shortcut being right is a result rather than an assumption.

use crate::ibst;
use alloc::vec::Vec;

/// Why a distinguished-entry query could not be answered.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    /// A timestamp the algorithm needs was not available.
    ///
    /// An auditor or a user holds timestamps only for the entries it has been shown, so
    /// this is a real case rather than a defensive one: it means the log did not send
    /// enough to decide the question.
    MissingTimestamp {
        /// The position whose timestamp is missing.
        position: u64,
    },
    /// Timestamps decreased from left to right.
    ///
    /// §4.2 requires the timestamps a log presents to be monotonic, and §6.1 subtracts one
    /// from another. Without this the subtraction would wrap and the gap would look
    /// enormous, which is the difference between "not distinguished" and "distinguished".
    NonMonotonic {
        /// The earlier position, whose timestamp was the larger.
        left: u64,
        /// The later position.
        right: u64,
    },
    /// The implicit binary search tree could not be navigated.
    Ibst(ibst::Error),
}

impl From<ibst::Error> for Error {
    fn from(err: ibst::Error) -> Self {
        Self::Ibst(err)
    }
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingTimestamp { position } => {
                write!(f, "no timestamp for log entry {position}")
            }
            Self::NonMonotonic { left, right } => write!(
                f,
                "timestamps are not monotonic: entry {left} is later than entry {right}"
            ),
            Self::Ibst(err) => write!(f, "walking the search tree: {err}"),
        }
    }
}

impl core::error::Error for Error {
    fn source(&self) -> Option<&(dyn core::error::Error + 'static)> {
        match self {
            Self::Ibst(err) => Some(err),
            _ => None,
        }
    }
}

type Result<T> = core::result::Result<T, Error>;

/// Whether an entry bracketed by these two timestamps is distinguished (§6.1 step 2).
///
/// §6.1 says to terminate when the difference is "less than" the window, and points out
/// that this is specifically not "less than or equal to" so that a window of zero makes
/// every entry distinguished rather than none.
///
/// # Errors
///
/// [`Error::NonMonotonic`] if `right` is before `left`.
pub fn is_distinguished(window: u64, left: (u64, u64), right: (u64, u64)) -> Result<bool> {
    let (left_position, left_timestamp) = left;
    let (right_position, right_timestamp) = right;
    let gap = right_timestamp
        .checked_sub(left_timestamp)
        .ok_or(Error::NonMonotonic {
            left: left_position,
            right: right_position,
        })?;
    Ok(gap >= window)
}

/// Every distinguished log entry in a log of `size` entries, ascending (§6.1).
///
/// `timestamp` supplies the timestamp of a log entry, or `None` if the caller does not have
/// it. The algorithm asks only for what it needs: the rightmost entry, then each entry it
/// finds distinguished. A caller holding the whole log can answer everything; one holding a
/// retained view will be told which position it is missing.
///
/// # Errors
///
/// [`Error::MissingTimestamp`], [`Error::NonMonotonic`], or [`Error::Ibst`] if `size` is
/// out of range.
pub fn enumerate(
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
) -> Result<Vec<u64>> {
    if size == 0 {
        // No entries, so no reference points. Not an error: an auditor sees this state
        // once, before the log's first entry.
        return Ok(Vec::new());
    }
    let rightmost_position = size.saturating_sub(1);
    let rightmost_timestamp = lookup(timestamp, rightmost_position)?;

    let mut out = Vec::new();
    // §6.1 initializes with the root, a left timestamp of 0, and the timestamp of the
    // rightmost entry. The left timestamp is 0 rather than the first entry's, so a log
    // whose entries all fall inside one window still has distinguished entries.
    visit(
        ibst::root(size)?,
        (0, 0),
        (rightmost_position, rightmost_timestamp),
        size,
        window,
        timestamp,
        &mut out,
    )?;
    out.sort_unstable();
    Ok(out)
}

/// §6.1's recursion. `left` and `right` are the bracketing (position, timestamp) pairs.
fn visit(
    x: u64,
    left: (u64, u64),
    right: (u64, u64),
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
    out: &mut Vec<u64>,
) -> Result<()> {
    if !is_distinguished(window, left, right)? {
        return Ok(());
    }
    out.push(x);

    // The recursion needs this entry's own timestamp to bracket its children, and only
    // now that it is known to be distinguished — which is why a caller with a partial
    // view can often still answer the question.
    let own = (x, lookup(timestamp, x)?);

    if !ibst::is_leaf(x) {
        visit(ibst::left(x)?, left, own, size, window, timestamp, out)?;
    }
    // A node whose nominal right subtree is empty has no right child; §6.1's step 4 is
    // conditional for exactly that reason.
    if let Ok(child) = ibst::right(x, size) {
        visit(child, own, right, size, window, timestamp, out)?;
    }
    Ok(())
}

/// The rightmost distinguished log entry, or `None` if there is none (§6.1).
///
/// # Errors
///
/// As [`enumerate`].
pub fn rightmost(
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
) -> Result<Option<u64>> {
    Ok(enumerate(size, window, timestamp)?.last().copied())
}

/// The rightmost distinguished log entry strictly left of the rightmost log entry (§6.1).
///
/// This is the question a log asks while building a new entry: which distinguished entries
/// already existed to its left. Note that it is *not* [`rightmost`] of a log one entry
/// smaller — adding one entry can create several distinguished entries at once, because it
/// moves the right bracket for every node on the frontier.
///
/// # Errors
///
/// As [`enumerate`].
pub fn previous_rightmost(
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
) -> Result<Option<u64>> {
    let last = size.saturating_sub(1);
    Ok(enumerate(size, window, timestamp)?
        .into_iter()
        .rfind(|position| *position != last))
}

/// The rightmost distinguished entry, using only the timestamps along the frontier (§6.1).
///
/// [`rightmost`] runs §6.1's recursion, which visits every distinguished entry and so needs
/// a timestamp for each. An auditor cannot supply that: it retains the frontier and nothing
/// else. This reaches the same answer from the frontier alone, and the reason it can is a
/// property of the recursion rather than a shortcut around it:
///
/// The set is **ancestor-closed** — `visit` reaches a node only from a distinguished parent,
/// so every ancestor of a distinguished entry is distinguished. Therefore every distinguished
/// entry greater than `x` lies in `x`'s right subtree, whose root is `x`'s right child: if
/// any of them were distinguished, that child would be. So when the right child is not
/// distinguished, `x` is the greatest, and otherwise the search continues there. The path
/// that walk takes — the root, then right children — is exactly the frontier.
///
/// The brackets follow too. Going right inherits the right bracket unchanged all the way
/// down, and the left bracket of each step is the previous node's timestamp, starting from
/// §6.1's initial 0.
///
/// [`rightmost`] is the definition and this is the one an auditor can afford; a test asserts
/// they agree across every size to 256 and a range of windows.
///
/// # Errors
///
/// As [`enumerate`], but asking only about frontier entries.
pub fn rightmost_from_frontier(
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
) -> Result<Option<u64>> {
    if size == 0 {
        return Ok(None);
    }
    let last = size.saturating_sub(1);
    let right = (last, lookup(timestamp, last)?);

    // Only the root needs the initial left bracket of 0: from there on, each step's
    // decision is whether the *right child* is distinguished, and that child's brackets are
    // the current node's timestamp and the unchanged right bracket.
    let mut current = ibst::root(size)?;
    if !is_distinguished(window, (0, 0), right)? {
        // The root is not distinguished, so by ancestor-closure nothing is.
        return Ok(None);
    }
    loop {
        let own = (current, lookup(timestamp, current)?);
        let Ok(child) = ibst::right(current, size) else {
            return Ok(Some(current));
        };
        if !is_distinguished(window, own, right)? {
            return Ok(Some(current));
        }
        current = child;
    }
}

/// [`previous_rightmost`], from the frontier of the *previous* tree plus the new entry.
///
/// This is the question §15.2 step 5 asks, and the shape of an auditor's state is why it
/// needs its own function: the entries this consults are the frontier of the log as it was,
/// which are exactly the entries an auditor retained, plus the one being added.
///
/// The derivation continues [`rightmost_from_frontier`]'s. If the greatest distinguished
/// entry is not the log's last, it is also the greatest one left of the last. If it *is* the
/// last, the answer is the greatest distinguished entry below it, and there are only two
/// places to look: inside its left subtree, or at its parent. Its left subtree lies entirely
/// between the parent and it — a frontier node's subtree starts just past its parent — so the
/// subtree wins whenever anything in it is distinguished, which by ancestor-closure is
/// exactly when its left child is. Otherwise the parent is the answer, and the parent is
/// distinguished because ancestors always are.
///
/// # Errors
///
/// As [`enumerate`], but asking only about the retained frontier and the new entry.
pub fn previous_rightmost_from_frontier(
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
) -> Result<Option<u64>> {
    if size == 0 {
        return Ok(None);
    }
    let last = size.saturating_sub(1);
    let right = (last, lookup(timestamp, last)?);

    // Walk the frontier, keeping the parent, so that the branch below has it to fall back on.
    let mut current = ibst::root(size)?;
    let mut parent: Option<(u64, u64)> = None;
    if !is_distinguished(window, (0, 0), right)? {
        return Ok(None);
    }
    let own = loop {
        let own = (current, lookup(timestamp, current)?);
        if current == last {
            break own;
        }
        let Ok(child) = ibst::right(current, size) else {
            // Not the last entry and no right child: `current` is the greatest, and it is
            // already left of the last entry.
            return Ok(Some(current));
        };
        if !is_distinguished(window, own, right)? {
            return Ok(Some(current));
        }
        parent = Some(own);
        current = child;
    };

    // The greatest is the last entry itself, so look below it.
    if !ibst::is_leaf(last) {
        let child = ibst::left(last)?;
        let bracket = parent.unwrap_or((0, 0));
        if is_distinguished(window, bracket, own)? {
            // Its left subtree has distinguished entries; take the greatest, which is found
            // by descending right while they stay distinguished. The right bracket inside
            // this subtree is the last entry's own timestamp.
            let mut cursor = child;
            loop {
                let Ok(next) = ibst::right(cursor, size) else {
                    return Ok(Some(cursor));
                };
                let here = (cursor, lookup(timestamp, cursor)?);
                if !is_distinguished(window, here, own)? {
                    return Ok(Some(cursor));
                }
                cursor = next;
            }
        }
    }
    Ok(parent.map(|(position, _)| position))
}

/// The recent distinguished entries, right to left (§10.1).
///
/// A user walking these gets common reference points with every other user, which is how a
/// fork is detected without a side channel: two users who agree on the same distinguished
/// entries cannot be on different branches. `recent` is the application's definition of
/// recency, which §10.1 requires to be monotonic and suggests be either "one of the `n`
/// rightmost" or "within some duration of the rightmost entry's timestamp". `stop` is the
/// caller's optional stopping position — a point it already knows, so the walk need not go
/// past it.
///
/// The order is the algorithm's, not sorted: right to left is what makes early stopping
/// possible, since everything after the stop is to the left of it.
///
/// # Errors
///
/// As [`enumerate`].
pub fn walk(
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
    stop: Option<u64>,
    recent: &impl Fn(u64) -> bool,
) -> Result<Vec<u64>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    let rightmost_position = size.saturating_sub(1);
    let rightmost_timestamp = lookup(timestamp, rightmost_position)?;

    let mut out = Vec::new();
    descend(
        ibst::root(size)?,
        (0, 0),
        (rightmost_position, rightmost_timestamp),
        size,
        window,
        timestamp,
        stop,
        recent,
        &mut out,
    )?;
    Ok(out)
}

/// §10.1's right-to-left depth-first search.
#[allow(
    clippy::too_many_arguments,
    reason = "one parameter per input of §10.1's recursion; bundling them would hide the \
              correspondence to the numbered steps"
)]
fn descend(
    x: u64,
    left: (u64, u64),
    right: (u64, u64),
    size: u64,
    window: u64,
    timestamp: &impl Fn(u64) -> Option<u64>,
    stop: Option<u64>,
    recent: &impl Fn(u64) -> bool,
    out: &mut Vec<u64>,
) -> Result<()> {
    // Step 1.
    if !is_distinguished(window, left, right)? {
        return Ok(());
    }
    out.push(x);
    let own = (x, lookup(timestamp, x)?);

    // Step 2: the right child first, so the output runs right to left.
    if let Ok(child) = ibst::right(x, size) {
        descend(
            child, own, right, size, window, timestamp, stop, recent, out,
        )?;
    }
    // Step 3: at or past the caller's stopping position, there is nothing left to tell it.
    if stop.is_some_and(|position| x <= position) {
        return Ok(());
    }
    // Step 4.
    if !recent(x) {
        return Ok(());
    }
    // Step 5.
    if !ibst::is_leaf(x) {
        descend(
            ibst::left(x)?,
            left,
            own,
            size,
            window,
            timestamp,
            stop,
            recent,
            out,
        )?;
    }
    Ok(())
}

fn lookup(timestamp: &impl Fn(u64) -> Option<u64>, position: u64) -> Result<u64> {
    timestamp(position).ok_or(Error::MissingTimestamp { position })
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

    /// Timestamps `step` apart, so a window of `k * step` makes gaps of `k` entries the
    /// unit of distinction.
    fn evenly(step: u64) -> impl Fn(u64) -> Option<u64> {
        move |position| Some(position.saturating_mul(step))
    }

    fn all(size: u64) -> impl Fn(u64) -> Option<u64> {
        move |position| (position < size).then_some(position)
    }

    /// A window of zero makes everything distinguished — the case §6.1's "less than"
    /// wording exists to get right. With `>=` reversed, this set would be empty.
    #[test]
    fn a_zero_window_distinguishes_every_entry() {
        for size in 1..20_u64 {
            let found = enumerate(size, 0, &all(size)).unwrap();
            assert_eq!(found, (0..size).collect::<Vec<_>>(), "size {size}");
        }
    }

    /// A window nothing can reach distinguishes nothing.
    #[test]
    fn an_unreachable_window_distinguishes_nothing() {
        for size in 1..20_u64 {
            assert!(enumerate(size, u64::MAX, &all(size)).unwrap().is_empty());
        }
    }

    #[test]
    fn an_empty_log_has_no_distinguished_entries() {
        // And asks for no timestamps: a log with no entries has none to give.
        let none = |_: u64| None;
        assert!(enumerate(0, 1000, &none).unwrap().is_empty());
        assert_eq!(rightmost(0, 1000, &none).unwrap(), None);
        assert_eq!(previous_rightmost(0, 1000, &none).unwrap(), None);
        assert!(walk(0, 1000, &none, None, &|_| true).unwrap().is_empty());
    }

    /// §6.1's stability property, which the whole scheme rests on: an entry that is
    /// distinguished stays distinguished as the log grows. Checked over every size up to 64
    /// rather than argued from the recursion.
    #[test]
    fn distinguished_entries_are_stable_as_the_log_grows() {
        let step = 7_u64;
        for window in [1_u64, step, 3 * step, 10 * step] {
            let mut previous: Vec<u64> = Vec::new();
            for size in 1..=64_u64 {
                let now = enumerate(size, window, &evenly(step)).unwrap();
                for entry in &previous {
                    assert!(
                        now.contains(entry),
                        "entry {entry} stopped being distinguished at size {size}, window {window}"
                    );
                }
                previous = now;
            }
        }
    }

    /// The regular-spacing property, the other half of why the set is useful: with evenly
    /// spaced timestamps, consecutive distinguished entries are never more than one window
    /// apart in time.
    #[test]
    fn distinguished_entries_are_regularly_spaced() {
        let step = 5_u64;
        let window = 8 * step;
        let size = 200_u64;
        let found = enumerate(size, window, &evenly(step)).unwrap();
        assert!(found.len() > 1);

        let last = *found.last().unwrap();
        let mut cursor = 0_u64;
        for entry in &found {
            let gap = entry.saturating_mul(step).saturating_sub(cursor);
            assert!(gap <= window, "gap of {gap} before entry {entry}");
            cursor = entry.saturating_mul(step);
        }
        // And the tail: the rightmost entry is within a window of the last reference point.
        let tail = (size - 1) * step - last * step;
        assert!(tail <= window, "tail gap of {tail}");
    }

    /// `previous_rightmost` is not `rightmost` of a log one smaller. katie's own comment
    /// says so; this is the case that shows it, found by scanning rather than assumed.
    #[test]
    fn previous_rightmost_is_not_rightmost_of_a_smaller_log() {
        let step = 3_u64;
        let window = 4 * step;
        let mut witnessed = false;
        for size in 2..=128_u64 {
            let previous = previous_rightmost(size, window, &evenly(step)).unwrap();
            let smaller = rightmost(size - 1, window, &evenly(step)).unwrap();
            if previous != smaller {
                witnessed = true;
            }
            // Whatever it is, it must be a distinguished entry of *this* log, and left of
            // the rightmost one.
            if let Some(position) = previous {
                let set = enumerate(size, window, &evenly(step)).unwrap();
                assert!(set.contains(&position), "size {size}");
                assert!(position < size - 1, "size {size}");
            }
        }
        assert!(
            witnessed,
            "adding one entry never created more than one distinguished entry, \
             so the distinction this function draws was never exercised"
        );
    }

    /// The frontier-only functions must agree with the definition everywhere, because an
    /// auditor uses them to decide §15.2 step 5 and the definition is what the draft says.
    /// Swept across every size to 256 and a spread of windows, in both timestamp shapes.
    #[test]
    fn the_frontier_walks_agree_with_the_definition() {
        let step = 6_u64;
        let bursty = |position: u64| {
            if position < 40 {
                position
            } else {
                40 + (position - 40) * 11 * step
            }
        };
        for shape in 0..2 {
            let at = move |position: u64| {
                Some(if shape == 0 {
                    position.saturating_mul(step)
                } else {
                    bursty(position)
                })
            };
            for window in [0_u64, 1, step, 2 * step, 5 * step, 40 * step, u64::MAX] {
                for size in 0..=256_u64 {
                    assert_eq!(
                        rightmost_from_frontier(size, window, &at).unwrap(),
                        rightmost(size, window, &at).unwrap(),
                        "rightmost: shape {shape}, window {window}, size {size}"
                    );
                    assert_eq!(
                        previous_rightmost_from_frontier(size, window, &at).unwrap(),
                        previous_rightmost(size, window, &at).unwrap(),
                        "previous: shape {shape}, window {window}, size {size}"
                    );
                }
            }
        }
    }

    /// And they must reach those answers from the frontier alone — the whole reason they
    /// exist. Every position either function asks about has to be one an auditor retained:
    /// the frontier of the log before the entry was added, plus the entry itself.
    #[test]
    fn the_frontier_walks_only_read_what_an_auditor_retains() {
        let step = 6_u64;
        for window in [1_u64, step, 4 * step, 40 * step] {
            for size in 1..=256_u64 {
                let retained: Vec<u64> = ibst::frontier(size.saturating_sub(1))
                    .unwrap_or_default()
                    .into_iter()
                    .chain(core::iter::once(size - 1))
                    .collect();
                let at = |position: u64| {
                    retained
                        .contains(&position)
                        .then(|| position.saturating_mul(step))
                };
                assert!(
                    rightmost_from_frontier(size, window, &at).is_ok(),
                    "rightmost read outside the retained set at size {size}, window {window}"
                );
                assert!(
                    previous_rightmost_from_frontier(size, window, &at).is_ok(),
                    "previous read outside the retained set at size {size}, window {window}"
                );
            }
        }
    }

    /// §10.1's walk visits distinguished entries right to left, and only distinguished
    /// ones.
    #[test]
    fn the_walk_runs_right_to_left_over_distinguished_entries() {
        let step = 5_u64;
        let window = 6 * step;
        let size = 100_u64;
        let set = enumerate(size, window, &evenly(step)).unwrap();

        let walked = walk(size, window, &evenly(step), None, &|_| true).unwrap();
        let mut sorted = walked.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, set, "the walk visits exactly the distinguished set");

        // Right to left is a property of the descent, not of the list: §10.1 starts at the
        // root, so the root is emitted first, and only then does step 2 descend right and
        // step 5 descend left. What "right to left" buys is that everything in a node's
        // right subtree is emitted before anything in its left — which is what makes step
        // 3's early stop safe, since a caller that has seen enough can be sure the rest is
        // further left.
        let root = ibst::root(size).unwrap();
        assert_eq!(walked.first(), Some(&root));
        let after_root: Vec<u64> = walked[1..].to_vec();
        let boundary = after_root
            .iter()
            .position(|entry| *entry < root)
            .unwrap_or(after_root.len());
        assert!(
            after_root[..boundary].iter().all(|entry| *entry > root),
            "the root's right subtree comes first"
        );
        assert!(
            after_root[boundary..].iter().all(|entry| *entry < root),
            "and its left subtree comes after, with nothing interleaved"
        );
    }

    /// A stopping position truncates the walk, and everything dropped is at or left of it.
    #[test]
    fn a_stopping_position_truncates_the_walk() {
        let step = 5_u64;
        let window = 6 * step;
        let size = 100_u64;
        let full = walk(size, window, &evenly(step), None, &|_| true).unwrap();
        let stop = full[full.len() / 2];

        let stopped = walk(size, window, &evenly(step), Some(stop), &|_| true).unwrap();
        assert!(stopped.len() < full.len());
        assert!(
            stopped.contains(&stop),
            "the stopping position is still reported"
        );
        for entry in &full {
            if !stopped.contains(entry) {
                assert!(
                    *entry <= stop,
                    "dropped entry {entry} was right of the stop"
                );
            }
        }
    }

    /// Recency truncates it too, and the two simplest definitions §10.1 suggests both work.
    #[test]
    fn recency_truncates_the_walk() {
        let step = 5_u64;
        let window = 6 * step;
        let size = 100_u64;
        let full = walk(size, window, &evenly(step), None, &|_| true).unwrap();

        // "One of the n rightmost", n = 2.
        let cutoff = full.get(1).copied().unwrap_or(0);
        let by_count = walk(size, window, &evenly(step), None, &|x| x >= cutoff).unwrap();
        assert!(by_count.len() < full.len());

        // "Within some duration of the rightmost entry's timestamp."
        let newest = (size - 1) * step;
        let by_time = walk(size, window, &evenly(step), None, &|x| {
            newest.saturating_sub(x * step) < 10 * step
        })
        .unwrap();
        assert!(by_time.len() < full.len());
    }

    /// A caller with only some timestamps is told which one it is missing, rather than
    /// getting an answer computed from what it happened to have.
    #[test]
    fn a_missing_timestamp_is_reported() {
        let sparse = |position: u64| (position != 3).then_some(position * 10);
        // Size 8's root is 3, and a window of zero makes it distinguished, so its own
        // timestamp is needed to bracket its children.
        assert_eq!(
            enumerate(8, 0, &sparse),
            Err(Error::MissingTimestamp { position: 3 })
        );

        // The rightmost entry's timestamp is needed before anything else.
        let no_rightmost = |position: u64| (position != 7).then_some(position * 10);
        assert_eq!(
            enumerate(8, 0, &no_rightmost),
            Err(Error::MissingTimestamp { position: 7 })
        );
    }

    /// Timestamps that go backwards would wrap the subtraction §6.1 performs, turning "not
    /// distinguished" into "distinguished".
    #[test]
    fn non_monotonic_timestamps_are_refused() {
        let backwards = |position: u64| Some(100_u64.saturating_sub(position));
        assert!(matches!(
            enumerate(8, 10, &backwards),
            Err(Error::NonMonotonic { .. })
        ));
        assert_eq!(
            is_distinguished(0, (0, 10), (1, 5)),
            Err(Error::NonMonotonic { left: 0, right: 1 })
        );
    }

    /// The walk refuses on the same grounds the enumeration does, rather than silently
    /// returning the part of the list it managed to build — a truncated list of reference
    /// points is indistinguishable from a log that simply has fewer.
    #[test]
    fn the_walk_refuses_rather_than_truncating() {
        let missing_root = |position: u64| (position != 3).then_some(position * 10);
        assert_eq!(
            walk(8, 0, &missing_root, None, &|_| true),
            Err(Error::MissingTimestamp { position: 3 })
        );

        let backwards = |position: u64| Some(100_u64.saturating_sub(position));
        assert!(matches!(
            walk(8, 10, &backwards, None, &|_| true),
            Err(Error::NonMonotonic { .. })
        ));

        let no_rightmost = |position: u64| (position != 7).then_some(position * 10);
        assert_eq!(
            walk(8, 0, &no_rightmost, None, &|_| true),
            Err(Error::MissingTimestamp { position: 7 })
        );
    }

    #[test]
    fn errors_describe_themselves() {
        use alloc::string::ToString;
        assert!(
            !Error::MissingTimestamp { position: 1 }
                .to_string()
                .is_empty()
        );
        assert!(
            !Error::NonMonotonic { left: 1, right: 2 }
                .to_string()
                .is_empty()
        );
        let wrapped = Error::from(ibst::Error::EmptyLog);
        assert!(!wrapped.to_string().is_empty());
        assert!(core::error::Error::source(&wrapped).is_some());
        assert!(core::error::Error::source(&Error::MissingTimestamp { position: 1 }).is_none());
    }

    /// A window equal to the whole span distinguishes the root and nothing else — every
    /// other node's brackets are strictly narrower.
    ///
    /// With one exception, which is why the size here is not a power of two: when `size` is
    /// a power of two the root *is* the rightmost entry, so its own timestamp is the right
    /// bracket, and its left child inherits the identical pair `(0, rightmost)`. The whole
    /// left spine is then distinguished too. Worth knowing before reading a distinguished
    /// set and concluding the window was misconfigured.
    #[test]
    fn a_window_of_the_whole_span_distinguishes_only_the_root() {
        let step = 4_u64;
        let size = 33_u64;
        let span = (size - 1) * step;
        let found = enumerate(size, span, &evenly(step)).unwrap();
        assert_eq!(found, vec![ibst::root(size).unwrap()]);
        assert_eq!(
            rightmost(size, span, &evenly(step)).unwrap(),
            found.last().copied()
        );

        // The power-of-two case, measured rather than asserted away.
        let power = 32_u64;
        let power_span = (power - 1) * step;
        let spine = enumerate(power, power_span, &evenly(step)).unwrap();
        assert_eq!(spine, vec![15, 31], "the root is the rightmost entry here");
        assert_eq!(ibst::root(power).unwrap(), 31);
    }
}
