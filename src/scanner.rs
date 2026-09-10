use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

/// What kind of thing a `Finding` represents. `Secret` findings get their
/// matched value redacted before display (see `detectors::redact`) —
/// there's a real value to protect. `Sast` findings are dangerous *code
/// patterns* (`shell=True`, `eval(...)`, disabled TLS verification, ...)
/// where the match itself isn't sensitive, so it's shown in full — masking
/// `subprocess.run(cmd, shell=True)` would just make the report useless.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum FindingCategory {
    Secret,
    Sast,
}

impl std::str::FromStr for Confidence {
    type Err = anyhow::Error;
    fn from_str(s: &str) -> Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "low" => Ok(Confidence::Low),
            "medium" | "med" => Ok(Confidence::Medium),
            "high" => Ok(Confidence::High),
            other => Err(anyhow::anyhow!("unknown confidence level: {other}")),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommitInfo {
    pub hash: String,
    pub short_hash: String,
    pub author: String,
    pub date: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub file: String,
    pub line: usize,
    pub detector: String,
    pub confidence: Confidence,
    pub category: FindingCategory,
    pub redacted: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commit: Option<CommitInfo>,
}

pub struct ScanOptions {
    pub root: PathBuf,
    pub include_history: bool,
    pub min_confidence: Confidence,
    pub max_commits: Option<usize>,
    pub respect_gitignore: bool,
    pub entropy_threshold: f64,
    pub entropy_min_len: usize,
    pub skip_lockfile_entropy: bool,
    pub include_sast: bool,
    pub max_file_size_bytes: u64,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            root: PathBuf::from("."),
            include_history: false,
            min_confidence: Confidence::Low,
            max_commits: None,
            respect_gitignore: true,
            entropy_threshold: 4.3,
            entropy_min_len: 20,
            skip_lockfile_entropy: true,
            include_sast: false,
            max_file_size_bytes: 10 * 1024 * 1024,
        }
    }
}

/// Known lockfile formats whose legitimate content (SRI hashes, checksums)
/// reads as high-entropy noise to a generic detector. Verified false
/// positives on real content before adding this: npm's `sha512-<hash>`
/// integrity strings and go.sum's `h1:<hash>` lines both tripped the
/// entropy detector at the default threshold. Matched on exact basename,
/// so it works at any depth. Structural detectors (AWS keys, tokens, ...)
/// still run on these files — only the generic entropy catch-all skips
/// them, and only when `skip_lockfile_entropy` is left at its default.
const KNOWN_LOCKFILES: &[&str] = &[
    "package-lock.json",
    "yarn.lock",
    "pnpm-lock.yaml",
    "Cargo.lock",
    "go.sum",
    "poetry.lock",
    "Pipfile.lock",
    "Gemfile.lock",
    "composer.lock",
    "mix.lock",
    "packages.lock.json",
    "flake.lock",
];

pub fn is_known_lockfile(file: &str) -> bool {
    let basename = Path::new(file)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or(file);
    KNOWN_LOCKFILES.contains(&basename)
}

/// Run detectors against a single line of file content, tagging findings with
/// the given file path, line number, and optional commit metadata.
/// `skip_entropy` drops the `high_entropy_token` detector for this call —
/// used for known lockfiles, see `is_known_lockfile`. A line containing the
/// literal `sieve:ignore` is skipped entirely (all detectors) — an
/// intentional escape hatch for confirmed false positives, checked once
/// here so it applies uniformly to working-tree, history, and staged scans
/// rather than being reimplemented per call site.
pub(crate) fn scan_line(
    detectors: &[Box<dyn crate::detectors::Detector>],
    file: &str,
    line_no: usize,
    line: &str,
    commit: Option<&CommitInfo>,
    skip_entropy: bool,
) -> Vec<Finding> {
    if line.contains("sieve:ignore") {
        return Vec::new();
    }

    let mut out = Vec::new();
    for d in detectors {
        if skip_entropy && d.name() == "high_entropy_token" {
            continue;
        }
        for redacted in d.scan_line(line) {
            out.push(Finding {
                file: file.to_string(),
                line: line_no,
                detector: d.name().to_string(),
                confidence: d.confidence(),
                category: d.category(),
                redacted,
                commit: commit.cloned(),
            });
        }
    }
    out
}

pub fn scan_path(opts: &ScanOptions) -> Result<Vec<Finding>> {
    if !opts.root.exists() {
        anyhow::bail!("path does not exist: {}", opts.root.display());
    }

    let detectors = crate::detectors::all_detectors(
        opts.entropy_threshold,
        opts.entropy_min_len,
        opts.include_sast,
    );
    let mut findings = Vec::new();

    for file in crate::walker::walk(&opts.root, opts.respect_gitignore)? {
        let rel = relative_display(&opts.root, &file);

        // Check size via metadata (a stat syscall, not a read) before
        // pulling the whole file into memory. Measured, not assumed: an
        // unguarded 129MB file took ~3s and ~134MB RSS — linear in file
        // size, fine once, not fine if someone points sieve at a
        // directory containing a stray multi-GB dataset/dump/build
        // artifact that isn't gitignored yet.
        match std::fs::metadata(&file) {
            Ok(meta) if meta.len() > opts.max_file_size_bytes => continue,
            Ok(_) => {}
            Err(_) => continue,
        }

        let Ok(bytes) = std::fs::read(&file) else {
            continue;
        };
        if is_binary(&bytes) {
            continue;
        }
        let skip_entropy = opts.skip_lockfile_entropy && is_known_lockfile(&rel);
        let text = String::from_utf8_lossy(&bytes);
        for (i, line) in text.lines().enumerate() {
            findings.extend(scan_line(&detectors, &rel, i + 1, line, None, skip_entropy));
        }
    }

    if opts.include_history {
        findings.extend(crate::git_history::scan_history(
            &opts.root,
            &detectors,
            opts.max_commits,
            opts.skip_lockfile_entropy,
            opts.max_file_size_bytes as usize,
        )?);
    }

    findings.retain(|f| f.confidence >= opts.min_confidence);
    Ok(findings)
}

/// Display path for a scanned file, relative to the scan root. Falls back
/// to the bare filename when `root` and `file` are the same path (a
/// single-file scan: `sieve scan config.py` rather than `sieve scan .`) —
/// stripping the full path as a prefix of itself leaves an empty string,
/// which would otherwise show up as `""` in every report and, worse,
/// silently break anything that re-joins `root` with an empty relative
/// path expecting to get the file back (found via `--triage` on a
/// single-file scan showing `:4` instead of `config.py:4`).
fn relative_display(root: &Path, file: &Path) -> String {
    let rel = file.strip_prefix(root).unwrap_or(file);
    if rel.as_os_str().is_empty() {
        file.file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| file.to_string_lossy().to_string())
    } else {
        rel.to_string_lossy().to_string()
    }
}

/// Cheap binary-file sniff: presence of a NUL byte in the first 8KB.
fn is_binary(bytes: &[u8]) -> bool {
    bytes.iter().take(8192).any(|&b| b == 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nonexistent_root_is_an_error_not_a_silent_empty_scan() {
        let opts = ScanOptions {
            root: PathBuf::from("/definitely/does/not/exist/on/this/machine"),
            ..ScanOptions::default()
        };
        let result = scan_path(&opts);
        assert!(
            result.is_err(),
            "scanning a missing path must error, not silently report clean"
        );
    }

    #[test]
    fn oversized_files_are_skipped_not_read_into_memory() {
        let dir = tempfile::tempdir().unwrap();
        // Small threshold so the test doesn't need to generate multi-MB
        // fixtures to prove the logic — the mechanism doesn't care what
        // the actual number is, only that files above it get skipped.
        std::fs::write(
            dir.path().join("small.py"),
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n", // sieve:ignore
        )
        .unwrap();
        std::fs::write(
            dir.path().join("huge.py"),
            format!("AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n{}", "x".repeat(1000)), // sieve:ignore
        )
        .unwrap();

        let opts = ScanOptions {
            root: dir.path().to_path_buf(),
            max_file_size_bytes: 100, // huge.py is well over this, small.py is well under
            ..ScanOptions::default()
        };
        let findings = scan_path(&opts).unwrap();

        assert!(
            findings.iter().any(|f| f.file == "small.py"),
            "file under the limit must still be scanned"
        );
        assert!(
            !findings.iter().any(|f| f.file == "huge.py"),
            "file over the limit must be skipped, not scanned"
        );
    }

    #[test]
    fn confidence_ordering_low_lt_medium_lt_high() {
        assert!(Confidence::Low < Confidence::Medium);
        assert!(Confidence::Medium < Confidence::High);
    }

    #[test]
    fn known_lockfiles_matched_by_basename_at_any_depth() {
        assert!(is_known_lockfile("package-lock.json"));
        assert!(is_known_lockfile("frontend/package-lock.json"));
        assert!(is_known_lockfile("a/b/c/go.sum"));
        assert!(!is_known_lockfile("package.json"));
        assert!(!is_known_lockfile("lockfile.txt"));
    }

    #[test]
    fn relative_display_falls_back_to_basename_for_single_file_scans() {
        // Scanning a file directly (root == file) used to strip the whole
        // path against itself and report an empty file name — this is
        // what a single-file `sieve scan config.py` invocation hits.
        let root = Path::new("tests/fixtures/dirty/config.py");
        let file = Path::new("tests/fixtures/dirty/config.py");
        assert_eq!(relative_display(root, file), "config.py");
    }

    #[test]
    fn relative_display_still_shows_relative_path_for_directory_scans() {
        let root = Path::new("tests/fixtures/dirty");
        let file = Path::new("tests/fixtures/dirty/config.py");
        assert_eq!(relative_display(root, file), "config.py");
    }

    #[test]
    fn skip_entropy_flag_suppresses_only_the_entropy_detector() {
        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let line = "\"integrity\": \"sha512-v2kDEe57lecTulaDIuNTPy3Ry4GqVAj5J6gpQ4Y8SwsYy5U\"";

        let with_entropy = scan_line(&detectors, "package-lock.json", 1, line, None, false);
        assert!(
            with_entropy
                .iter()
                .any(|f| f.detector == "high_entropy_token"),
            "sanity check: this line should trip entropy when not skipped"
        );

        let skipped = scan_line(&detectors, "package-lock.json", 1, line, None, true);
        assert!(
            !skipped.iter().any(|f| f.detector == "high_entropy_token"),
            "high_entropy_token must be suppressed when skip_entropy is true"
        );
    }

    #[test]
    fn inline_sieve_ignore_suppresses_the_whole_line() {
        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let flagged = scan_line(
            &detectors,
            "config.py",
            1,
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"", // sieve:ignore
            None,
            false,
        );
        assert_eq!(
            flagged.len(),
            1,
            "sanity check: this line should normally flag"
        );

        let ignored = scan_line(
            &detectors,
            "config.py",
            1,
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"  # sieve:ignore -- rotated, doc example",
            None,
            false,
        );
        assert!(
            ignored.is_empty(),
            "a line with sieve:ignore must produce no findings at all"
        );
    }
}
