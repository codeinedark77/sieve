use anyhow::Result;
use clap::{Parser, Subcommand, ValueEnum};
use sieve::{scan_path, Confidence, Finding, ScanOptions};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    name = "sieve",
    version,
    about = "Local-first secrets scanner with optional LLM triage"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Scan a path (and optionally its full git history) for secrets
    Scan {
        /// Path to scan
        #[arg(default_value = ".")]
        path: PathBuf,

        /// Also scan full git history — finds secrets purged from HEAD but
        /// still sitting in .git
        #[arg(short = 'H', long)]
        history: bool,

        /// Scan only staged changes (the git index) instead of the working
        /// tree — what the pre-commit hook uses. Fast: only the diff, not
        /// a full walk. `path` is treated as the repo root.
        #[arg(long)]
        staged: bool,

        /// Output format
        #[arg(long, value_enum, default_value = "text")]
        format: Format,

        /// Minimum confidence to report: low, medium, high
        #[arg(long, default_value = "low")]
        min_confidence: Confidence,

        /// Cap on commits scanned with --history (default: all reachable commits)
        #[arg(long)]
        max_commits: Option<usize>,

        /// Don't respect .gitignore / .ignore / .sieveignore
        #[arg(long)]
        no_gitignore: bool,

        /// Shannon entropy threshold for the generic high-entropy detector
        #[arg(long, default_value_t = 4.3)]
        entropy_threshold: f64,

        /// Minimum token length considered by the entropy detector
        #[arg(long, default_value_t = 20)]
        entropy_min_len: usize,

        /// Skip files larger than this many megabytes rather than reading
        /// them fully into memory. Measured, not a guess: an unguarded
        /// 129MB file took ~3s and ~134MB of RSS — fine once, not fine if
        /// a stray multi-GB file ends up inside the scan root.
        #[arg(long, default_value_t = 10)]
        max_file_size_mb: u64,

        /// By default, the entropy detector skips known lockfiles
        /// (package-lock.json, go.sum, Cargo.lock, ...) since their
        /// checksums/SRI hashes read as false positives. Pass this to scan
        /// them anyway.
        #[arg(long)]
        scan_lockfile_entropy: bool,

        /// Also run the optional SAST-lite rules (shell=True, eval/exec,
        /// disabled TLS verification, ...) alongside secret detection.
        /// Off by default — these flag risky code *patterns*, not leaked
        /// values, which is a different kind of finding.
        #[arg(long)]
        sast: bool,

        /// EXPERIMENTAL, untested in this build: send each finding to a
        /// local Ollama model to filter out likely false positives
        #[arg(long)]
        triage: bool,

        #[arg(long, default_value = "http://localhost:11434")]
        triage_url: String,

        #[arg(long, default_value = "qwen2.5-coder:7b")]
        triage_model: String,
    },
}

#[derive(Clone, ValueEnum)]
enum Format {
    Text,
    Json,
    Sarif,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("sieve: error: {e:#}");
            ExitCode::from(2)
        }
    }
}

fn run(cli: Cli) -> Result<ExitCode> {
    let Commands::Scan {
        path,
        history,
        staged,
        format,
        min_confidence,
        max_commits,
        no_gitignore,
        entropy_threshold,
        entropy_min_len,
        max_file_size_mb,
        scan_lockfile_entropy,
        sast,
        triage,
        triage_url,
        triage_model,
    } = cli.command;

    if staged && history {
        anyhow::bail!("--staged and --history are mutually exclusive (staged changes vs. full commit history)");
    }

    let skip_lockfile_entropy = !scan_lockfile_entropy;

    let mut findings = if staged {
        let detectors = sieve::detectors::all_detectors(entropy_threshold, entropy_min_len, sast);
        let mut f = sieve::staged::scan_staged(
            &path,
            &detectors,
            skip_lockfile_entropy,
            (max_file_size_mb * 1024 * 1024) as usize,
        )?;
        f.retain(|finding| finding.confidence >= min_confidence);
        f
    } else {
        let opts = ScanOptions {
            root: path.clone(),
            include_history: history,
            min_confidence,
            max_commits,
            respect_gitignore: !no_gitignore,
            entropy_threshold,
            entropy_min_len,
            skip_lockfile_entropy,
            include_sast: sast,
            max_file_size_bytes: max_file_size_mb * 1024 * 1024,
        };
        scan_path(&opts)?
    };

    if triage {
        findings = run_triage(&path, findings, &triage_url, &triage_model);
    }

    match format {
        Format::Json => println!("{}", sieve::report::to_json(&findings)?),
        Format::Sarif => println!("{}", sieve::report::to_sarif(&findings)?),
        Format::Text => println!("{}", sieve::report::to_text(&findings)),
    }

    Ok(if findings.is_empty() {
        ExitCode::from(0)
    } else {
        ExitCode::from(1)
    })
}

/// EXPERIMENTAL — see src/triage.rs for the "not verified in this sandbox"
/// caveat. Fails open: if triage errors on a finding (Ollama unreachable,
/// bad JSON back, model doesn't support `format: json`, ...) that finding
/// is kept rather than silently dropped.
fn run_triage(root: &Path, findings: Vec<Finding>, url: &str, model: &str) -> Vec<Finding> {
    let client = sieve::triage::OllamaTriage::new(url, model);
    findings
        .into_iter()
        .filter(|f| {
            let content = read_finding_source(root, f);
            let ctx = sieve::triage::extract_context(&content, f.line, 3);
            match client.triage(f, &ctx) {
                Ok(v) => {
                    eprintln!(
                        "  [triage] {}:{} -> real={} ({}%) {}",
                        f.file, f.line, v.is_real_secret, v.confidence_pct, v.reasoning
                    );
                    v.is_real_secret
                }
                Err(e) => {
                    eprintln!(
                        "  [triage] {}:{} -> triage call failed ({e:#}), keeping finding untriaged",
                        f.file, f.line
                    );
                    true
                }
            }
        })
        .collect()
}

/// History findings point at a file as it existed in a past commit, which
/// may no longer exist (or may have changed) in the working tree — so pull
/// context from that commit's blob, not from disk, when we have a commit.
fn read_finding_source(root: &Path, f: &Finding) -> String {
    match &f.commit {
        Some(c) => std::process::Command::new("git")
            .args([
                "-C",
                root.to_str().unwrap_or("."),
                "show",
                &format!("{}:{}", c.hash, f.file),
            ])
            .output()
            .ok()
            .filter(|o| o.status.success())
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default(),
        None => std::fs::read_to_string(root.join(&f.file)).unwrap_or_default(),
    }
}
