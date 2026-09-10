//! Shared unified-diff parser. Walks a `git show`/`git diff --cached`
//! style patch (produced with `--unified=0`) and runs detectors against
//! every *added* line, tracking the current file path and new-file line
//! number as it goes. Used by both `git_history` (per past commit) and
//! `staged` (the index, for the pre-commit hook) so the line-accounting
//! logic exists in exactly one place.

use crate::detectors::Detector;
use crate::scanner::{scan_line, CommitInfo, Finding};
use once_cell::sync::Lazy;
use regex::Regex;

static HUNK_HEADER: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,\d+)? @@").unwrap());

/// Parse a unified diff body (no commit-meta prefix line) and scan every
/// added line. `commit` tags every resulting `Finding` — pass `None` for
/// staged/working-tree diffs that aren't tied to a specific commit.
/// `skip_lockfile_entropy` mirrors `ScanOptions` — see
/// `scanner::is_known_lockfile` for why this exists.
pub fn scan_diff(
    diff_text: &str,
    detectors: &[Box<dyn Detector>],
    commit: Option<&CommitInfo>,
    skip_lockfile_entropy: bool,
) -> Vec<Finding> {
    let mut findings = Vec::new();
    let mut current_file: Option<String> = None;
    let mut in_hunk = false;
    let mut cur_line: usize = 1;

    for line in diff_text.lines() {
        if let Some(rest) = line.strip_prefix("+++ ") {
            let p = rest.trim();
            current_file = if p == "/dev/null" {
                None
            } else {
                Some(p.strip_prefix("b/").unwrap_or(p).to_string())
            };
            continue;
        }
        if line.starts_with("diff --git ") {
            current_file = None;
            in_hunk = false;
            continue;
        }
        if line.starts_with("--- ") {
            continue;
        }
        if line.starts_with("@@") {
            if let Some(caps) = HUNK_HEADER.captures(line) {
                cur_line = caps[1].parse().unwrap_or(1);
            }
            in_hunk = true;
            continue;
        }
        if !in_hunk {
            continue; // commit message body / other preamble, before the first hunk
        }
        if let Some(added) = line.strip_prefix('+') {
            if let Some(file) = &current_file {
                let skip_entropy = skip_lockfile_entropy && crate::scanner::is_known_lockfile(file);
                findings.extend(scan_line(
                    detectors,
                    file,
                    cur_line,
                    added,
                    commit,
                    skip_entropy,
                ));
            }
            cur_line += 1;
        } else if line.starts_with('-') {
            // removed line — doesn't exist in the new file, no line-number bump
        } else {
            cur_line += 1;
        }
    }

    findings
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_added_lines_only_and_tracks_file() {
        let diff = "diff --git a/config.py b/config.py\n\
index 0000000..1111111 100644\n\
--- a/config.py\n\
+++ b/config.py\n\
@@ -1 +1 @@\n\
-old_value = 1\n\
+AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"; // sieve:ignore

        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_diff(diff, &detectors, None, true);
        let aws: Vec<_> = findings
            .iter()
            .filter(|f| f.detector == "aws_access_key_id")
            .collect();
        assert_eq!(aws.len(), 1);
        assert_eq!(aws[0].file, "config.py");
    }

    #[test]
    fn deleted_lines_are_never_scanned() {
        let diff = "diff --git a/secret.py b/secret.py\n\
deleted file mode 100644\n\
index 1111111..0000000\n\
--- a/secret.py\n\
+++ /dev/null\n\
@@ -1 +0,0 @@\n\
-AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n"; // sieve:ignore

        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_diff(diff, &detectors, None, true);
        assert!(
            findings.is_empty(),
            "a deleted line must never be reported as an addition"
        );
    }

    #[test]
    fn commit_metadata_is_attached_when_provided() {
        let diff = "diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -0,0 +1 @@\n+AKIA_MARKER = \"AKIAIOSFODNN7EXAMPLE\"\n"; // sieve:ignore
        let commit = CommitInfo {
            hash: "abc123".into(),
            short_hash: "abc123".into(),
            author: "Test".into(),
            date: "2026-01-01".into(),
        };
        let detectors = crate::detectors::all_detectors(4.3, 20, false);
        let findings = scan_diff(diff, &detectors, Some(&commit), true);
        assert!(findings
            .iter()
            .all(|f| f.commit.as_ref().map(|c| c.hash.as_str()) == Some("abc123")));
    }

    #[test]
    fn lockfile_entropy_is_skipped_in_diffs_too() {
        let diff = "diff --git a/package-lock.json b/package-lock.json\n\
--- a/package-lock.json\n\
+++ b/package-lock.json\n\
@@ -0,0 +1 @@\n\
+    \"integrity\": \"sha512-v2kDEe57lecTulaDIuNTPy3Ry4GqVAj5J6gpQ4Y8SwsYy5U\"\n";

        let detectors = crate::detectors::all_detectors(4.3, 20, false);

        let with_skip = scan_diff(diff, &detectors, None, true);
        assert!(with_skip.iter().all(|f| f.detector != "high_entropy_token"));

        let without_skip = scan_diff(diff, &detectors, None, false);
        assert!(without_skip
            .iter()
            .any(|f| f.detector == "high_entropy_token"));
    }
}
