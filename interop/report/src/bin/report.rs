//! Builds the interop evidence page from the committed vectors.
//!
//! ```sh
//! cargo run -p kt-interop --bin kt-interop-report -- \
//!   --vectors interop/vectors --out site
//! ```
//!
//! Writes `index.html` and `report.json` into the output directory, and **exits
//! non-zero if any check disagrees** — so a red result cannot be published as a
//! green page. Provenance that the process cannot know for itself (the commit, the
//! CI run, the toolchain versions) is passed in by the caller, which keeps this
//! binary free of subprocesses and of guesses about its environment.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use kt_interop::report::Provenance;

/// Command-line options.
struct Options {
    vectors: PathBuf,
    out: PathBuf,
    provenance: Provenance,
}

const USAGE: &str = "\
usage: kt-interop-report [options]

  --vectors <dir>    directory of committed vector files (default: interop/vectors)
  --out <dir>        directory to write index.html and report.json into (default: site)
  --commit <sha>     commit of this repository being reported on
  --commit-url <url> link to that commit
  --run-url <url>    link to the CI run that produced the page
  --rustc <string>   Rust toolchain version, e.g. \"$(rustc --version)\"
  --go <string>      Go toolchain that generated the vectors, e.g. \"$(go version)\"
  --generated <ts>   RFC 3339 timestamp to stamp (default: now, UTC)
  -h, --help         this message
";

fn main() -> ExitCode {
    let options = match parse_args() {
        Ok(None) => {
            print!("{USAGE}");
            return ExitCode::SUCCESS;
        }
        Ok(Some(options)) => options,
        Err(message) => {
            eprintln!("kt-interop-report: {message}\n\n{USAGE}");
            return ExitCode::from(2);
        }
    };

    let report = match kt_interop::build(&options.vectors, options.provenance) {
        Ok(report) => report,
        Err(err) => {
            eprintln!("kt-interop-report: {err}");
            return ExitCode::FAILURE;
        }
    };

    if let Err(err) = write_site(&options.out, &report) {
        eprintln!("kt-interop-report: {err}");
        return ExitCode::FAILURE;
    }

    let failed = report.failed();
    println!(
        "{} checks across {} cases in {} suites; {} disagreements",
        report.checks(),
        report.cases(),
        report.suites.len(),
        failed
    );
    for suite in &report.suites {
        println!(
            "  {:<32} {:>5} checks  {}",
            suite.file,
            suite.checks(),
            if suite.passing() {
                "agrees"
            } else {
                "DISAGREES"
            }
        );
    }
    println!(
        "wrote {}/index.html and {}/report.json",
        options.out.display(),
        options.out.display()
    );

    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        // Refuse to let a page claiming interop be published over failing checks.
        eprintln!("kt-interop-report: {failed} checks disagree; not a publishable result");
        ExitCode::FAILURE
    }
}

fn write_site(out: &Path, report: &kt_interop::report::Report) -> Result<(), std::io::Error> {
    fs::create_dir_all(out)?;
    fs::write(out.join("index.html"), kt_interop::html::render(report))?;
    let json = serde_json::to_string_pretty(report)
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidData, err))?;
    fs::write(out.join("report.json"), json + "\n")?;
    // Tell GitHub Pages not to run the output through Jekyll: nothing here needs
    // it, and it would silently drop any file starting with an underscore.
    fs::write(out.join(".nojekyll"), [])?;
    Ok(())
}

/// Parses arguments. `Ok(None)` means help was requested.
fn parse_args() -> Result<Option<Options>, String> {
    let mut vectors = PathBuf::from("interop/vectors");
    let mut out = PathBuf::from("site");
    let mut provenance = Provenance::default();
    let mut generated = None;

    let mut args = std::env::args().skip(1);
    while let Some(arg) = args.next() {
        let mut value = || args.next().ok_or_else(|| format!("{arg} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--vectors" => vectors = PathBuf::from(value()?),
            "--out" => out = PathBuf::from(value()?),
            "--commit" => provenance.commit = Some(value()?),
            "--commit-url" => provenance.commit_url = Some(value()?),
            "--run-url" => provenance.run_url = Some(value()?),
            "--rustc" => provenance.rustc = Some(value()?),
            "--go" => provenance.go = Some(value()?),
            "--generated" => generated = Some(value()?),
            other => return Err(format!("unknown argument {other}")),
        }
    }

    // Empty strings arrive from CI expressions like `${{ github.event.x }}` when
    // the field is absent; treat them as unset rather than rendering blanks.
    provenance.commit = provenance.commit.filter(|s| !s.is_empty());
    provenance.commit_url = provenance.commit_url.filter(|s| !s.is_empty());
    provenance.run_url = provenance.run_url.filter(|s| !s.is_empty());
    provenance.rustc = provenance.rustc.filter(|s| !s.is_empty());
    provenance.go = provenance.go.filter(|s| !s.is_empty());
    provenance.generated_at = generated
        .filter(|s| !s.is_empty())
        .unwrap_or_else(kt_interop::now_utc);

    Ok(Some(Options {
        vectors,
        out,
        provenance,
    }))
}
