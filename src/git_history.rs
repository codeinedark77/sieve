use crate::detectors::Detector;
use crate::git_exec::run_git_capped;
use crate::scanner::{CommitInfo, Finding};
use anyhow::{Context, Result};
use std::path::Path;
use std::process::Command;

/// Scan every commit reachable from any ref for secrets introduced in that
/// commit's diff. This is the whole point of history scanning: a secret
/// that was added and later deleted from HEAD is still sitting in the
/// repo's `.git` forever unless history is rewritten.
///
/// Shells out to the system `git` binary (log + show) instead of linking
/// libgit2. That's a deliberate v0 tradeoff: no native build dependency,
/// and git is already a hard requirement for anything this tool scans.
pub fn scan_history(
    root: &Path,
    detectors: &[Box<dyn Detector>],
    max_commits: Option<usize>,
    skip_lockfile_entropy: bool,
    max_diff_bytes: usize,
) -> Result<Vec<Finding>> {
    if !root.join(".git").exists() {
        return Ok(Vec::new());
    }

    let commits = list_commits(root, max_commits)?;
    let mut findings = Vec::new();
    for hash in commits {
        findings.extend(scan_commit(
            root,
            &hash,
            detectors,
            skip_lockfile_entropy,
            max_diff_bytes,
        )?);
    }
    Ok(findings)
}

fn list_commits(root: &Path, max_commits: Option<usize>) -> Result<Vec<String>> {
    let mut args = vec![
        "-C",
        root.to_str().unwrap_or("."),
        "log",
        "--all",
        "--pretty=format:%H",
    ];
    let max_str;
    if let Some(n) = max_commits {
        max_str = format!("--max-count={n}");
        args.push(&max_str);
    }
    let out = Command::new("git")
        .args(&args)
        .output()
        .context("failed to run `git log` — is git installed?")?;

    if !out.status.success() {
        // Most common cause: repo with zero commits yet. Not an error.
        return Ok(Vec::new());
    }
    let text = String::from_utf8_lossy(&out.stdout);
    Ok(text
        .lines()
        .map(|l| l.to_string())
        .filter(|l| !l.is_empty())
        .collect())
}

fn scan_commit(
    root: &Path,
    hash: &str,
    detectors: &[Box<dyn Detector>],
    skip_lockfile_entropy: bool,
    max_diff_bytes: usize,
) -> Result<Vec<Finding>> {
    let result = run_git_capped(
        root,
        &[
            "show",
            "--no-color",
            "--unified=0",
            "--pretty=format:SIEVE_COMMIT_META:%H|%an|%aI",
            hash,
        ],
        max_diff_bytes,
    )?;

    // `result.success` is false both for a genuine git failure (bad hash,
    // corrupted object) AND for the deliberate kill after hitting
    // max_diff_bytes on an oversized commit — those need different
    // handling. A real failure produces no meaningful stdout (git's
    // errors go to stderr); a capped-but-real diff produces real
    // (truncated) content. Checking for empty stdout distinguishes them
    // without needing to track "was this a cap-kill" as separate state.
    if result.stdout.trim().is_empty() {
        return Ok(Vec::new());
    }

    let mut lines = result.stdout.lines();
    let meta_line = lines.next().unwrap_or_default();
    let commit = parse_meta(meta_line);
    let diff_body = lines.collect::<Vec<_>>().join("\n");

    Ok(crate::diff_scan::scan_diff(
        &diff_body,
        detectors,
        commit.as_ref(),
        skip_lockfile_entropy,
    ))
}

fn parse_meta(line: &str) -> Option<CommitInfo> {
    let rest = line.strip_prefix("SIEVE_COMMIT_META:")?;
    let mut parts = rest.splitn(3, '|');
    let hash = parts.next()?.to_string();
    let author = parts.next()?.to_string();
    let date = parts.next()?.to_string();
    let short_hash = hash.chars().take(7).collect();
    Some(CommitInfo {
        hash,
        short_hash,
        author,
        date,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scanner::scan_line;
    use std::fs;
    use std::process::Command as Cmd;

    fn git(root: &Path, args: &[&str]) {
        let status = Cmd::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .expect("git must be installed to run this test");
        assert!(status.success(), "git {:?} failed", args);
    }

    /// Builds a synthetic repo where a secret is added in commit 1 and
    /// deleted (from the working tree) in commit 2 — the exact scenario
    /// working-tree-only scanning misses and history scanning exists for.
    fn build_repo_with_purged_secret() -> tempfile::TempDir {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test User"]);

        fs::write(
            root.join("config.py"),
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n", // sieve:ignore
        )
        .unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "add config with key"]);

        fs::write(
            root.join("config.py"),
            "AWS_KEY = os.environ[\"AWS_KEY\"]\n",
        )
        .unwrap();
        git(root, &["add", "."]);
        git(
            root,
            &["commit", "-q", "-m", "fix: load key from env instead"],
        );

        dir
    }

    #[test]
    fn finds_secret_purged_from_head_but_still_in_history() {
        let dir = build_repo_with_purged_secret();
        let detectors = crate::detectors::all_detectors(4.3, 20, false);

        let head_findings = crate::walker::walk(dir.path(), true)
            .unwrap()
            .into_iter()
            .flat_map(|f| {
                let content = fs::read_to_string(&f).unwrap_or_default();
                let rel = f
                    .strip_prefix(dir.path())
                    .unwrap()
                    .to_string_lossy()
                    .to_string();
                content
                    .lines()
                    .enumerate()
                    .flat_map(|(i, l)| scan_line(&detectors, &rel, i + 1, l, None, false))
                    .collect::<Vec<_>>()
            })
            .filter(|f| f.detector == "aws_access_key_id")
            .count();
        assert_eq!(
            head_findings, 0,
            "the key should be gone from the working tree"
        );

        let history_findings =
            scan_history(dir.path(), &detectors, None, true, 10 * 1024 * 1024).unwrap();
        let aws_hits: Vec<_> = history_findings
            .iter()
            .filter(|f| f.detector == "aws_access_key_id")
            .collect();
        assert_eq!(
            aws_hits.len(),
            1,
            "the key should still be found in history"
        );
        assert_eq!(aws_hits[0].file, "config.py");
        assert!(aws_hits[0].commit.is_some());
    }

    #[test]
    fn empty_repo_returns_no_findings() {
        let dir = tempfile::tempdir().unwrap();
        git(dir.path(), &["init", "-q"]);
        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_history(dir.path(), &detectors, None, true, 10 * 1024 * 1024).unwrap();
        assert!(findings.is_empty());
    }

    #[test]
    fn non_git_dir_returns_no_findings_not_an_error() {
        let dir = tempfile::tempdir().unwrap();
        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_history(dir.path(), &detectors, None, true, 10 * 1024 * 1024).unwrap();
        assert!(findings.is_empty());
    }
}
