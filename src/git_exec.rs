//! Shared helper for running `git` subprocesses with a *bounded* read on
//! stdout, used by both `git_history.rs` and `staged.rs`.
//!
//! `Command::output()` buffers the entire subprocess stdout into memory
//! before returning — fine for a `git log` hash list, genuinely unbounded
//! for `git show`/`git diff --cached` output on a commit that adds one
//! huge file (the same class of exposure `--max-file-size-mb` closed for
//! the working-tree walker in 0.3.3, just a different code path).
//!
//! The naive fix — spawn, then `Read::take(max_bytes)` on stdout — has a
//! trap: if the real output is bigger than `max_bytes`, the child can end
//! up blocked inside its own `write()` once the pipe buffer fills, since
//! nothing is draining it past our limit. A plain `child.wait()` after
//! that would hang forever. Killing the child before waiting is what
//! prevents it.

use anyhow::{Context, Result};
use std::io::Read;
use std::path::Path;
use std::process::{Command, Stdio};

pub(crate) struct CappedOutput {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// Run `git <args>` in `root`, reading at most `max_stdout_bytes` of
/// stdout. `stdout` may be truncated if the real output was larger —
/// still handed to the diff parser on a best-effort basis (a secret early
/// in an oversized diff is still worth catching) rather than discarding
/// the whole commit.
///
/// `stderr` is captured too (bounded to a small fixed cap), read *after*
/// stdout: git's error messages are short and don't realistically fill a
/// pipe buffer the way diff content does, so this doesn't need the full
/// concurrent-drain-both-streams machinery a general-purpose version
/// would — by the time stdout has been handled (including killing the
/// child if it was still running), whatever's sitting in the stderr pipe
/// is already there to be read in one shot.
pub(crate) fn run_git_capped(
    root: &Path,
    args: &[&str],
    max_stdout_bytes: usize,
) -> Result<CappedOutput> {
    let mut child = Command::new("git")
        .arg("-C")
        .arg(root)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("failed to spawn git — is it installed?")?;

    let stdout_pipe = child.stdout.take().expect("stdout was piped");
    let mut limited = stdout_pipe.take(max_stdout_bytes as u64);
    let mut stdout_buf = Vec::new();
    let _ = limited.read_to_end(&mut stdout_buf);

    // Whether or not the cap was actually hit, make sure the child can't
    // still be sitting on a blocked write() to either stream — kill first
    // (a harmless no-op if it already exited on its own), then reap.
    let _ = child.kill();

    let mut stderr_buf = [0u8; 4096];
    let stderr_n = child
        .stderr
        .take()
        .map(|mut s| s.read(&mut stderr_buf).unwrap_or(0))
        .unwrap_or(0);

    let status = child.wait();

    Ok(CappedOutput {
        success: status.map(|s| s.success()).unwrap_or(false),
        stdout: String::from_utf8_lossy(&stdout_buf).to_string(),
        stderr: String::from_utf8_lossy(&stderr_buf[..stderr_n]).to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::process::Command as Cmd;
    use std::time::Instant;

    fn git(root: &Path, args: &[&str]) {
        let status = Cmd::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success(), "git {:?} failed", args);
    }

    #[test]
    fn caps_output_without_hanging_on_a_genuinely_large_diff() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "t@e.com"]);
        git(root, &["config", "user.name", "T"]);

        // A genuinely large file — several MB — committed in one go.
        std::fs::write(root.join("big.txt"), "x".repeat(5_000_000)).unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "add a big file"]);

        let start = Instant::now();
        let result =
            run_git_capped(root, &["show", "--no-color", "--unified=0", "HEAD"], 1024).unwrap();
        let elapsed = start.elapsed();

        assert!(
            result.stdout.len() <= 1024,
            "captured output must never exceed the requested cap, got {} bytes",
            result.stdout.len()
        );
        assert!(
            elapsed.as_secs() < 5,
            "must not hang waiting on a child blocked writing past the cap, took {elapsed:?}"
        );
    }

    #[test]
    fn small_output_is_unaffected_by_the_cap() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);
        git(root, &["config", "user.email", "t@e.com"]);
        git(root, &["config", "user.name", "T"]);
        std::fs::write(
            root.join("small.py"),
            "AWS_KEY = \"AKIAIOSFODNN7EXAMPLE\"\n", // sieve:ignore
        )
        .unwrap();
        git(root, &["add", "."]);
        git(root, &["commit", "-q", "-m", "small commit"]);

        let result = run_git_capped(
            root,
            &["show", "--no-color", "--unified=0", "HEAD"],
            10 * 1024 * 1024,
        )
        .unwrap();

        assert!(result.success);
        assert!(
            result.stdout.contains("AKIAIOSFODNN7EXAMPLE"), // sieve:ignore
            "small, well-under-cap output must come through whole"
        );
    }

    #[test]
    fn stderr_is_captured_on_failure_for_a_clear_error_message() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        git(root, &["init", "-q"]);

        let result = run_git_capped(
            root,
            &["show", "--no-color", "this-ref-does-not-exist"],
            4096,
        )
        .unwrap();

        assert!(!result.success);
        assert!(
            !result.stderr.is_empty(),
            "a failing command should still surface something on stderr"
        );
    }
}
