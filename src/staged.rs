//! Scans staged changes (the git index) — what `git commit` would actually
//! record. This is what the pre-commit hook runs: fast (just the diff, not
//! a full-tree walk), and checks what's really about to be committed
//! rather than what's sitting on disk, which can differ if there are
//! unstaged edits on top of what's staged.

use crate::detectors::Detector;
use crate::git_exec::run_git_capped;
use crate::scanner::Finding;
use anyhow::Result;
use std::path::Path;

pub fn scan_staged(
    root: &Path,
    detectors: &[Box<dyn Detector>],
    skip_lockfile_entropy: bool,
    max_diff_bytes: usize,
) -> Result<Vec<Finding>> {
    if !root.join(".git").exists() {
        anyhow::bail!("not a git repository: {}", root.display());
    }

    let result = run_git_capped(
        root,
        &["diff", "--cached", "--no-color", "--unified=0"],
        max_diff_bytes,
    )?;

    if !result.success && result.stdout.trim().is_empty() {
        // `success` alone can't distinguish a genuine failure from a
        // deliberate kill after hitting max_diff_bytes on a huge staged
        // diff (same reasoning as git_history's scan_commit) - a real
        // failure produces no meaningful stdout, so that's the actual
        // signal to gate on.
        anyhow::bail!("git diff --cached failed: {}", result.stderr.trim());
    }

    Ok(crate::diff_scan::scan_diff(
        &result.stdout,
        detectors,
        None,
        skip_lockfile_entropy,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::process::Command as Cmd;

    fn git(root: &Path, args: &[&str]) {
        let status = Cmd::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed", args);
    }

    fn init_repo_with_one_commit(root: &Path) {
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "test@example.com"]);
        git(root, &["config", "user.name", "Test"]);
        fs::write(root.join("README.md"), "hello\n").unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "init"]);
    }

    #[test]
    fn finds_secret_in_staged_but_uncommitted_change() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_repo_with_one_commit(root);

        fs::write(
            root.join("config.py"),
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n", // sieve:ignore
        )
        .unwrap();
        git(root, &["add", "config.py"]);
        // deliberately NOT committed — this is exactly the pre-commit-hook moment

        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_staged(root, &detectors, true, 10 * 1024 * 1024).unwrap();
        assert!(findings
            .iter()
            .any(|f| f.detector == "aws_access_key_id" && f.file == "config.py"));
    }

    #[test]
    fn unstaged_changes_are_not_scanned() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_repo_with_one_commit(root);

        // modify on disk but never `git add` it
        fs::write(
            root.join("README.md"),
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n", // sieve:ignore
        )
        .unwrap();

        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_staged(root, &detectors, true, 10 * 1024 * 1024).unwrap();
        assert!(
            findings.is_empty(),
            "unstaged edits must not appear in a staged-only scan"
        );
    }

    #[test]
    fn already_committed_secrets_dont_reappear_as_staged() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_repo_with_one_commit(root);

        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_staged(root, &detectors, true, 10 * 1024 * 1024).unwrap();
        assert!(
            findings.is_empty(),
            "a clean index with nothing staged must report nothing"
        );
    }

    #[test]
    fn non_git_dir_errors_rather_than_reporting_clean() {
        let dir = tempfile::tempdir().unwrap();
        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        assert!(scan_staged(dir.path(), &detectors, true, 10 * 1024 * 1024).is_err());
    }

    #[test]
    fn lockfile_entropy_skip_applies_to_real_staged_diff() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        init_repo_with_one_commit(root);

        fs::write(
            root.join("package-lock.json"),
            "{\"integrity\": \"sha512-v2kDEe57lecTulaDIuNTPy3Ry4GqVAj5J6gpQ4Y8SwsYy5U\"}\n",
        )
        .unwrap();
        git(root, &["add", "package-lock.json"]);

        let detectors = crate::detectors::all_detectors(4.3, 20, false);

        let skipped = scan_staged(root, &detectors, true, 10 * 1024 * 1024).unwrap();
        assert!(skipped.iter().all(|f| f.detector != "high_entropy_token"));

        let not_skipped = scan_staged(root, &detectors, false, 10 * 1024 * 1024).unwrap();
        assert!(not_skipped
            .iter()
            .any(|f| f.detector == "high_entropy_token"));
    }
}
