use assert_cmd::Command;
use predicates::prelude::*;
use std::fs;
use std::io::{Read, Write};
use std::net::TcpListener;
use std::process::Command as StdCommand;
use std::time::Duration;

use std::sync::Once;

static INIT: Once = Once::new();

fn ensure_dirty_fixtures() {
    INIT.call_once(|| {
        let dir = std::path::Path::new("tests/fixtures/dirty");
        let _ = fs::remove_dir_all(dir); // clean slate
        fs::create_dir_all(dir).unwrap();

        fs::write(
            dir.join("app.js"),
            format!(
                r#"// Notification webhook wiring — quick and dirty, clean up later
const GITHUB_TOKEN = "ghp_{}";
const SLACK_WEBHOOK_TOKEN = "xoxb-{}-FakeFakeFakeFakeFakeFakeFakeFakeFake";

function notify(message) {{
  console.log(`[notify] ${{message}}`);
}}"#,
                 "16C7e42F292c6912E7710c838347Ae178B4a",
                 "0000000000"
            ),
        ).unwrap();

        fs::write(
            dir.join("config.py"),
            format!(
                r#"import os

AWS_ACCESS_KEY_ID = "AKIA{}"
AWS_SECRET_ACCESS_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY")

DB_URL = "postgresql://postgres:{}@localhost:5432/mydb"
"#,
                "IOSFODNN7EXAMPLE",
                "supersecretpassword"
            )
        ).unwrap();

        fs::write(
            dir.join("more_secrets.env"),
            format!(
                r#"# CI environment — do not commit real values here, this is a fixture

GOOGLE_MAPS_KEY=AIza{}
SENDGRID_API_KEY=SG.FakeFakeFakeFakeFakeFa.{}
NPM_TOKEN=npm_{}
SLACK_DEPLOY_WEBHOOK={}/T00000000/B00000000/FakeFakeFakeFakeFakeFake
TWILIO_API_KEY={}1234567890abcdef1234567890abcdef
"#,
                 "SyD-9tSrke72PouQMnMX-a7eZSW0jkFMBWY",
                 "FakeFakeFakeFakeFakeFakeFakeFakeFakeFakeFak",
                 "abcdefghijklmnopqrstuvwxyz0123456789",
                 "https://hooks.slack.com/services",
                 "SK"
            )
        ).unwrap();

        fs::write(
            dir.join("settings.json"),
            format!(
                r#"{{
  "service": "billing-worker",
  "api_key": "{}_live_FakeFakeFakeFakeFakeFakeFakeFakeFake",
  "session_token": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.{}",
  "retry_limit": 3
}}"#,
                "sk",
                "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
            )
        ).unwrap();

        fs::write(
            dir.join("id_rsa"),
            format!(
                r#"-----BEGIN {} PRIVATE KEY-----
TkkA/aW4gcmVhbCBsaWZlLCB0aGlzIHdvdWxkIGJlIGEgYmlnIGJsb2Igb2YgYmFzZTY0IGRhdGEsC3Qg
c3QgaXQncyB0aGUgaGVhZGVyIHdlIGNhcmUgYWJvdXQgZGV0ZWN0aW5nLgoV2UgaGF2ZSB0byBtYWtl
bmV2IGVub3VnaCBzbyB0aGUgZW50cm9weSBkZXRlY3RvciBkb2Vzbid0IGlnbm9yZSBpdCwgYW5k
YWxsIGxpbmVzIG11c3QgYmUgYXQgbGVhc3QgMTYgY2hhcnMgbG9uZyBvciBpdCBza2lwcyB0aGVtLg==
-----END {} PRIVATE KEY-----
"#,
                "RSA",
                "RSA"
            )
        ).unwrap();

        fs::write(
            dir.join("risky_code.py"),
            r#"import subprocess
import pickle
import os
import eval # just a dummy import for eval test since I missed it before, or let me just put eval here
eval("test")

def run_backup(user_supplied_path):
    # Deliberately risky patterns for sieve's --sast fixture tests.
    subprocess.run(f"tar -czf backup.tar.gz {user_supplied_path}", shell=True)
    os.system("rm -rf /tmp/staging")

def load_cache(raw_bytes):
    return pickle.loads(raw_bytes)

def render(user_bio):
    return f"<div dangerouslySetInnerHTML={{__html: user_bio}} />"

def fetch(url):
    import requests
    return requests.get(url, verify=False)

def lookup_user(user_id):
    return f"SELECT * FROM users WHERE id = {user_id}"

DEBUG = True
"#
        ).unwrap();
    });
}

fn sieve() -> Command {
    ensure_dirty_fixtures();
    Command::cargo_bin("sieve").unwrap()
}

#[test]
fn dirty_fixtures_are_flagged_and_exit_code_is_one() {
    sieve()
        .args(["scan", "tests/fixtures/dirty"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("aws_access_key_id"))
        .stdout(predicate::str::contains("private_key_header"))
        .stdout(predicate::str::contains("github_token"))
        .stdout(predicate::str::contains("slack_token"))
        .stdout(predicate::str::contains("stripe_api_key"))
        .stdout(predicate::str::contains("google_api_key"))
        .stdout(predicate::str::contains("sendgrid_api_key"))
        .stdout(predicate::str::contains("npm_token"))
        .stdout(predicate::str::contains("slack_webhook_url"))
        .stdout(predicate::str::contains("twilio_api_key"))
        .stdout(predicate::str::contains(
            "db_connection_string_with_password",
        ));
}

#[test]
fn secret_values_never_appear_unredacted_in_output() {
    // The exact planted secrets must never show up whole in stdout.
    sieve()
        .args(["scan", "tests/fixtures/dirty"])
        .assert()
        .stdout(predicate::str::contains(format!("AKIA{}", "IOSFODNN7EXAMPLE")).not())
        .stdout(predicate::str::contains(format!("ghp_{}", "16C7e42F292c6912E7710c838347Ae178B4a")).not());
    // sieve:ignore
}

#[test]
fn clean_fixtures_produce_no_findings_and_exit_code_zero() {
    // Real-looking noise (a git hash, a UUID) must not trip the entropy detector.
    sieve()
        .args(["scan", "tests/fixtures/clean"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no findings"));
}

#[test]
fn json_output_is_valid_and_parses_to_expected_count() {
    let output = sieve()
        .args(["scan", "tests/fixtures/dirty", "--format", "json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let parsed: Vec<serde_json::Value> =
        serde_json::from_slice(&output).expect("stdout must be valid JSON");
    assert!(!parsed.is_empty());
    assert!(parsed.iter().any(|f| f["detector"] == "aws_access_key_id"));
}

#[test]
fn min_confidence_high_hides_low_and_medium_findings() {
    sieve()
        .args([
            "scan",
            "tests/fixtures/dirty",
            "--min-confidence",
            "high",
            "--format",
            "json",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("\"confidence\": \"low\"").not())
        .stdout(predicate::str::contains("\"confidence\": \"medium\"").not());
}

#[test]
fn history_flag_finds_secret_purged_from_working_tree() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "Test"]);

    fs::write(root.join("secret.py"), format!("TOKEN = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE")).unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "oops, committed a key"]);

    fs::write(root.join("secret.py"), "TOKEN = load_from_vault()\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "remove hardcoded key"]);

    // Working-tree-only scan: the key is gone, exit code should be clean.
    sieve()
        .args(["scan", root.to_str().unwrap()])
        .assert()
        .code(0);

    // With --history: the key is still reachable from an old commit.
    sieve()
        .args(["scan", root.to_str().unwrap(), "--history"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("aws_access_key_id"));
}

#[test]
fn nonexistent_path_errors_with_exit_code_two() {
    sieve()
        .args(["scan", "tests/fixtures/does-not-exist"])
        .assert()
        .code(2);
}

#[test]
fn scanning_a_single_file_directly_reports_its_real_filename_not_empty() {
    // Regression: root == file (a single-file scan, not a directory scan)
    // used to strip the path against itself and report "" as the file.
    let output = sieve()
        .args(["scan", "tests/fixtures/dirty/config.py", "--format", "json"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let parsed: Vec<serde_json::Value> = serde_json::from_slice(&output).unwrap();
    assert!(!parsed.is_empty());
    for f in &parsed {
        assert_eq!(
            f["file"], "config.py",
            "single-file scan must report the real filename, not empty"
        );
    }
}

/// Minimal stub Ollama server for `--triage` end-to-end tests. Speaks the
/// real wire format (reads until it has the full Content-Length body —
/// one `read()` call doesn't reliably see both of the client's separate
/// `write_all` calls, even on loopback; src/triage.rs's own unit tests
/// needed the same fix) and replies with a fixed verdict for every
/// request it gets.
#[test]
fn max_file_size_mb_skips_oversized_files_via_the_real_cli() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("small.py"),
        format!("AWS_KEY = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE"), // sieve:ignore
    )
    .unwrap();
    fs::write(
        dir.path().join("huge.py"),
        format!("AWS_KEY = \"AKIA{}\"\n{}", "IOSFODNN7EXAMPLE", "x".repeat(2000)), // sieve:ignore
    )
    .unwrap();

    // Default (10MB) — both files are tiny, both get scanned.
    sieve()
        .args(["scan", dir.path().to_str().unwrap(), "--format", "json"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("small.py"))
        .stdout(predicate::str::contains("huge.py"));

    // Threshold set below huge.py's size — huge.py is skipped, small.py still isn't.
    let output = sieve()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--max-file-size-mb",
            "0",
            "--format",
            "json",
        ])
        .assert()
        .get_output()
        .stdout
        .clone();
    // --max-file-size-mb 0 means "0 bytes allowed" - both files exceed
    // that, so this just confirms the flag actually reaches the scanner
    // rather than being silently ignored (both should be skipped, 0 findings).
    let parsed: Vec<serde_json::Value> = serde_json::from_slice(&output).unwrap();
    assert!(
        parsed.is_empty(),
        "a 0MB limit must skip everything, proving the flag isn't ignored"
    );
}

#[test]
fn history_scan_does_not_hang_on_a_commit_with_a_large_file() {
    // Permanent regression test for the bug 0.3.4 fixed: git_history's
    // scan_commit used to buffer git show's entire stdout unbounded via
    // Command::output(), and a naive bounded-read fix has a deadlock trap
    // (child blocks writing past a full pipe if nothing drains it). This
    // proves the real --history CLI path completes quickly against a
    // real large commit rather than relying on the manual /usr/bin/time
    // check done while building the fix.
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "t@e.com"]);
    git(&["config", "user.name", "T"]);

    fs::write(
        root.join("secret.py"),
        format!("AWS_KEY = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE"), // sieve:ignore
    )
    .unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "add a secret"]);

    // Several MB in one commit - big enough to exceed any reasonable
    // --max-file-size-mb cap on the diff, small enough to keep the test fast.
    fs::write(root.join("huge.txt"), "x".repeat(5_000_000)).unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "add a huge file"]);

    let start = std::time::Instant::now();
    sieve()
        .args([
            "scan",
            root.to_str().unwrap(),
            "--history",
            "--max-file-size-mb",
            "1",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("aws_access_key_id"));
    let elapsed = start.elapsed();

    assert!(
        elapsed.as_secs() < 10,
        "must not hang on a commit with a large file, took {elapsed:?}"
    );
}

fn spawn_stub_ollama(is_real_secret: bool) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
    let port = listener.local_addr().unwrap().port();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { continue };
            stream.set_read_timeout(Some(Duration::from_secs(5))).ok();

            let mut buf: Vec<u8> = Vec::new();
            let mut chunk = [0u8; 4096];
            loop {
                match stream.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => {
                        buf.extend_from_slice(&chunk[..n]);
                        if let Some(header_end) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                            let headers = String::from_utf8_lossy(&buf[..header_end]);
                            let content_length = headers
                                .lines()
                                .find_map(|l| {
                                    l.to_ascii_lowercase()
                                        .starts_with("content-length:")
                                        .then(|| l.to_string())
                                })
                                .and_then(|l| l.split(':').nth(1).map(|v| v.trim().to_string()))
                                .and_then(|v| v.parse::<usize>().ok())
                                .unwrap_or(0);
                            if buf.len() >= header_end + 4 + content_length {
                                break;
                            }
                        }
                    }
                    Err(_) => break,
                }
            }

            let verdict = serde_json::json!({
                "is_real_secret": is_real_secret,
                "confidence_pct": 90,
                "reasoning": "stub verdict for integration test"
            })
            .to_string();
            let envelope =
                serde_json::json!({"model": "stub", "response": verdict, "done": true}).to_string();
            let body = envelope.as_bytes();
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes());
            let _ = stream.write_all(body);
        }
    });

    format!("http://127.0.0.1:{port}")
}

#[test]
fn triage_end_to_end_keeps_a_finding_the_stub_calls_real() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config.py"),
        format!("AWS_KEY = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE"), // sieve:ignore
    )
    .unwrap();

    let base_url = spawn_stub_ollama(true);

    sieve()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--triage",
            "--triage-url",
            &base_url,
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("aws_access_key_id"));
}

#[test]
fn triage_end_to_end_filters_a_finding_the_stub_calls_false_positive() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("config.py"),
        format!("AWS_KEY = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE"), // sieve:ignore
    )
    .unwrap();

    let base_url = spawn_stub_ollama(false);

    sieve()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--triage",
            "--triage-url",
            &base_url,
        ])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no findings"));
}

#[test]
fn sarif_format_is_valid_via_the_real_cli() {
    let output = sieve()
        .args(["scan", "tests/fixtures/dirty", "--format", "sarif"])
        .assert()
        .code(1)
        .get_output()
        .stdout
        .clone();

    let v: serde_json::Value =
        serde_json::from_slice(&output).expect("stdout must be valid SARIF JSON");
    assert_eq!(v["version"], "2.1.0");
    assert_eq!(v["runs"][0]["tool"]["driver"]["name"], "sieve");
    assert!(v["runs"][0]["results"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["ruleId"] == "aws_access_key_id"));
}

#[test]
fn staged_flag_catches_secret_before_commit() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    let git = |args: &[&str]| {
        let status = StdCommand::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .status()
            .unwrap();
        assert!(status.success());
    };
    git(&["init", "-q"]);
    git(&["config", "user.email", "test@example.com"]);
    git(&["config", "user.name", "Test"]);
    fs::write(root.join("README.md"), "hello\n").unwrap();
    git(&["add", "."]);
    git(&["commit", "-q", "-m", "init"]);

    fs::write(
        root.join("config.py"),
        format!("AWS_KEY = \"AKIA{}\"\n", "IOSFODNN7EXAMPLE"), // sieve:ignore
    )
    .unwrap();
    git(&["add", "config.py"]);

    sieve()
        .args(["scan", root.to_str().unwrap(), "--staged"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("aws_access_key_id"));
}

#[test]
fn staged_and_history_together_is_a_usage_error() {
    let dir = tempfile::tempdir().unwrap();
    StdCommand::new("git")
        .arg("-C")
        .arg(dir.path())
        .args(["init", "-q"])
        .status()
        .unwrap();

    sieve()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--staged",
            "--history",
        ])
        .assert()
        .code(2)
        .stderr(predicate::str::contains("mutually exclusive"));
}

#[test]
fn lockfile_entropy_skipped_by_default_but_scannable_via_flag() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("package-lock.json"),
        "{\"integrity\": \"sha512-v2kDEe57lecTulaDIuNTPy3Ry4GqVAj5J6gpQ4Y8SwsYy5U\"}\n",
    )
    .unwrap();

    // Default: skipped, clean exit.
    sieve()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--min-confidence",
            "low",
        ])
        .assert()
        .code(0);

    // Opted back in: the same content now flags.
    sieve()
        .args([
            "scan",
            dir.path().to_str().unwrap(),
            "--min-confidence",
            "low",
            "--scan-lockfile-entropy",
        ])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("high_entropy_token"));
}

#[test]
fn inline_sieve_ignore_suppresses_a_confirmed_false_positive() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("docs.py"),
        format!(
            "EXAMPLE_KEY = \"AKIA{}\"  # sieve:ignore -- AWS's own doc example, not a real key\n",
            "IOSFODNN7EXAMPLE"
        ), // sieve:ignore
    )
    .unwrap();

    sieve()
        .args(["scan", dir.path().to_str().unwrap()])
        .assert()
        .code(0);
}

#[test]
fn sast_is_off_by_default_but_catches_real_patterns_when_enabled() {
    // Default: SAST detectors don't run at all.
    sieve()
        .args(["scan", "tests/fixtures/dirty/risky_code.py"])
        .assert()
        .code(0)
        .stdout(predicate::str::contains("no findings"));

    // --sast: catches the planted risky patterns, unredacted (there's no
    // secret value here to mask — the code pattern itself is the finding).
    sieve()
        .args(["scan", "tests/fixtures/dirty/risky_code.py", "--sast"])
        .assert()
        .code(1)
        .stdout(predicate::str::contains("shell_injection_risk"))
        .stdout(predicate::str::contains("insecure_deserialization"))
        .stdout(predicate::str::contains("disabled_tls_verification"))
        .stdout(predicate::str::contains("sql_injection_risk"))
        .stdout(predicate::str::contains("hardcoded_debug_mode"))
        .stdout(predicate::str::contains("shell=True")); // shown in full, not masked
}
