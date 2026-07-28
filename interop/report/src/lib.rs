//! Vector-driven interop verification, and the evidence report it publishes.
//!
//! This crate is the harness described in `docs/interop.md` Tier 1: it loads the
//! committed vectors under `interop/vectors/`, recomputes each one with the `kt-*`
//! crates, and reports the comparison.
//!
//! # Why the tests and the published page share one code path
//!
//! `AGENTS.md` rule 4 is that there are no unproven interop claims: "interoperates"
//! means a vector or a live test asserts it. A hand-written status page would
//! break that rule the first time it drifted from reality. So
//! [`check::run`] produces the results, `tests/vectors.rs` fails the build if any
//! of them disagree, and `kt-interop-report` renders the same results as
//! [HTML][html::render] and JSON. The page cannot claim something CI does not
//! enforce, because the page *is* the CI run's output.
//!
//! # Layout
//!
//! - [`vectors`] — the on-disk file format, as serde types.
//! - [`check`] — running the vectors, producing results without panicking.
//! - [`report`] — the result model, plus the hand-maintained coverage table.
//! - [`html`] — rendering a report as one self-contained page.
//!
//! This crate is not published to crates.io: it is test infrastructure, and it is
//! the only part of the workspace that is allowed to know about `interop/`.

pub mod check;
pub mod html;
pub mod report;
pub mod vectors;

use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use report::{Provenance, Report};

/// The draft revision this workspace implements.
pub const DRAFT: &str = kt_wire::DRAFT;

/// Builds a full report from the vectors in `dir`.
///
/// # Errors
///
/// [`check::Error`] if a vector file is missing or does not match the format
/// contract. Disagreements are results, not errors.
pub fn build(dir: &Path, provenance: Provenance) -> Result<Report, check::Error> {
    Ok(Report {
        draft: DRAFT.to_owned(),
        provenance,
        suites: check::run(dir)?,
        coverage: report::coverage_table(),
    })
}

/// The default vector directory, resolved relative to this crate.
///
/// Used by the tests so they do not depend on the working directory.
#[must_use]
pub fn default_vector_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../vectors")
}

/// The current UTC time, formatted as RFC 3339.
///
/// Hand-rolled rather than pulling in a date library for one line of output: this
/// crate is test infrastructure and its dependency list is part of what a reader
/// has to trust. Returns the epoch if the system clock is before 1970, which is
/// not a case worth an error type.
#[must_use]
pub fn now_utc() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs());
    format_rfc3339(secs)
}

/// Formats a Unix timestamp as RFC 3339 in UTC.
///
/// Days-to-civil-date conversion after Howard Hinnant's `civil_from_days`, which
/// shifts the epoch to 1 March 0000 so that the leap day lands at the end of the
/// year and the month arithmetic has no special cases.
#[must_use]
#[allow(
    clippy::arithmetic_side_effects,
    reason = "every intermediate is bounded by construction: for any u64 input, `days` is \
              at most 2.1e14 and no product here exceeds ~1e12, and each subtraction is \
              non-negative by the algorithm's own invariants. Rewriting it in saturating \
              operations would hide the algorithm without changing its behaviour, and the \
              unit test pins the boundary cases the workspace lint is really aimed at."
)]
pub fn format_rfc3339(unix_seconds: u64) -> String {
    let days = unix_seconds / 86_400;
    let secs_of_day = unix_seconds % 86_400;
    let (hour, minute, second) = (
        secs_of_day / 3_600,
        (secs_of_day % 3_600) / 60,
        secs_of_day % 60,
    );

    // Shift to an era starting 0000-03-01.
    let z = days.saturating_add(719_468);
    let era = z / 146_097;
    let day_of_era = z % 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 {
        month_prime + 3
    } else {
        month_prime - 9
    };
    let year = era * 400 + year_of_era + u64::from(month <= 2);

    format!("{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}Z")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Checked against known Unix timestamps, including the leap-year cases that
    /// a hand-rolled conversion gets wrong.
    #[test]
    fn rfc3339_formatting() {
        assert_eq!(format_rfc3339(0), "1970-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(1), "1970-01-01T00:00:01Z");
        assert_eq!(format_rfc3339(86_399), "1970-01-01T23:59:59Z");
        assert_eq!(format_rfc3339(86_400), "1970-01-02T00:00:00Z");
        assert_eq!(format_rfc3339(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format_rfc3339(1_078_012_800), "2004-02-29T00:00:00Z");
        assert_eq!(format_rfc3339(1_709_164_800), "2024-02-29T00:00:00Z");
        assert_eq!(format_rfc3339(1_735_689_599), "2024-12-31T23:59:59Z");
        assert_eq!(format_rfc3339(1_735_689_600), "2025-01-01T00:00:00Z");
        assert_eq!(format_rfc3339(4_102_444_800), "2100-01-01T00:00:00Z");
    }
}
