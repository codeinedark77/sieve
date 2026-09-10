//! v1 — LLM triage layer.
//!
//! **Status: written, wired into the CLI, NOT verified.** This sandbox has
//! no Ollama instance to call, so nothing in this file has ever actually
//! round-tripped a real request. Treat it as a strong starting point, not a
//! tested feature. Before trusting it: point `--triage-url` at your real
//! Ollama, run it against a repo with a few known findings, and check the
//! verdicts by hand. Report back what breaks — the prompt, the JSON-mode
//! assumption, and the error handling are all first-draft.

use crate::scanner::Finding;
use anyhow::{Context, Result};
use serde::Deserialize;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::Duration;

#[derive(Debug, Deserialize)]
pub struct TriageVerdict {
    pub is_real_secret: bool,
    pub confidence_pct: u8,
    pub reasoning: String,
}

pub struct OllamaTriage {
    base_url: String,
    model: String,
}

impl OllamaTriage {
    pub fn new(base_url: impl Into<String>, model: impl Into<String>) -> Self {
        Self {
            base_url: base_url.into(),
            model: model.into(),
        }
    }

    /// Ask the local model whether a flagged line is a real, live secret or
    /// a false positive (placeholder, test fixture, already-revoked value,
    /// documentation example, etc). `surrounding_code` should be a handful
    /// of lines of context around the match — the finding alone is usually
    /// too little for the model to judge.
    pub fn triage(&self, finding: &Finding, surrounding_code: &str) -> Result<TriageVerdict> {
        let prompt = format!(
            "You are a security triage assistant. A secrets scanner flagged a line as a \
possible `{detector}` (heuristic confidence: {conf:?}).\n\n\
Redacted match: {redacted}\n\
File: {file}:{line}\n\n\
Surrounding code:\n```\n{code}\n```\n\n\
Is this a REAL, live secret — as opposed to a placeholder, documentation example, \
test fixture, or a value that has already been revoked/rotated? Respond with ONLY \
a JSON object, no other text: {{\"is_real_secret\": bool, \"confidence_pct\": 0-100, \
\"reasoning\": \"one sentence\"}}",
            detector = finding.detector,
            conf = finding.confidence,
            redacted = finding.redacted,
            file = finding.file,
            line = finding.line,
            code = surrounding_code,
        );

        let body = serde_json::json!({
            "model": self.model,
            "prompt": prompt,
            "stream": false,
            "format": "json"
        });

        let resp = ollama_post(&self.base_url, "/api/generate", &body)
            .with_context(|| format!("request to Ollama at {} failed", self.base_url))?;

        let raw = resp
            .get("response")
            .and_then(|v| v.as_str())
            .unwrap_or("{}");

        serde_json::from_str(raw)
            .with_context(|| format!("model did not return a parseable verdict: {raw}"))
    }
}

/// Minimal hand-rolled HTTP/1.1 POST, used instead of pulling in a full
/// HTTP client crate for a single "talk to localhost Ollama" call. `ureq`
/// was tried first but its `url`/`idna_adapter` transitive deps require a
/// newer rustc edition than this sandbox's apt-installed toolchain has —
/// so: plain TCP, `Connection: close`, read to EOF. No chunked-encoding or
/// keep-alive handling needed because of that header.
fn ollama_post(base_url: &str, path: &str, body: &serde_json::Value) -> Result<serde_json::Value> {
    let (host, port) = parse_host_port(base_url)?;
    let payload = serde_json::to_vec(body)?;

    let mut stream = TcpStream::connect((host.as_str(), port))
        .with_context(|| format!("could not connect to {host}:{port} — is Ollama running?"))?;
    stream.set_read_timeout(Some(Duration::from_secs(120)))?;
    stream.set_write_timeout(Some(Duration::from_secs(10)))?;

    let request = format!(
        "POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        payload.len()
    );
    stream.write_all(request.as_bytes())?;
    stream.write_all(&payload)?;

    let mut raw = Vec::new();
    stream.read_to_end(&mut raw)?;

    let sep_pos = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .context("malformed HTTP response from Ollama (no header/body separator)")?;
    let status_line = String::from_utf8_lossy(
        &raw[..raw[..sep_pos]
            .iter()
            .position(|&b| b == b'\r')
            .unwrap_or(sep_pos)],
    )
    .to_string();
    if !status_line.contains("200") {
        anyhow::bail!("Ollama returned non-200 status: {status_line}");
    }
    let body_bytes = &raw[sep_pos + 4..];
    serde_json::from_slice(body_bytes).context("Ollama response body was not valid JSON")
}

fn parse_host_port(base_url: &str) -> Result<(String, u16)> {
    let rest = base_url
        .strip_prefix("http://")
        .context("only http:// is supported for --triage-url (Ollama is plain HTTP)")?;
    let authority = rest.split('/').next().unwrap_or(rest);
    match authority.split_once(':') {
        Some((h, p)) => Ok((
            h.to_string(),
            p.parse().context("bad port in --triage-url")?,
        )),
        None => Ok((authority.to_string(), 80)),
    }
}

/// Pull `context_lines` of surrounding code from a file around a 1-indexed
/// line number, for feeding to `OllamaTriage::triage`.
pub fn extract_context(file_content: &str, line: usize, context_lines: usize) -> String {
    let lines: Vec<&str> = file_content.lines().collect();
    if lines.is_empty() {
        return String::new();
    }
    let idx = line.saturating_sub(1).min(lines.len() - 1);
    let start = idx.saturating_sub(context_lines);
    let end = (idx + context_lines + 1).min(lines.len());
    lines[start..end].join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::time::Duration as StdDuration;

    // Only the pure/local pieces are testable without a live Ollama.
    #[test]
    fn extract_context_centers_on_target_line() {
        let content = "a\nb\nc\nd\ne\nf\ng";
        let ctx = extract_context(content, 4, 1);
        assert_eq!(ctx, "c\nd\ne");
    }

    #[test]
    fn extract_context_clamps_at_file_start() {
        let content = "a\nb\nc";
        let ctx = extract_context(content, 1, 2);
        assert_eq!(ctx, "a\nb\nc");
    }

    #[test]
    fn parse_host_port_with_explicit_port() {
        let (h, p) = parse_host_port("http://localhost:11434").unwrap();
        assert_eq!(h, "localhost");
        assert_eq!(p, 11434);
    }

    #[test]
    fn parse_host_port_defaults_to_80() {
        let (h, p) = parse_host_port("http://example.com").unwrap();
        assert_eq!(h, "example.com");
        assert_eq!(p, 80);
    }

    #[test]
    fn parse_host_port_rejects_https() {
        assert!(parse_host_port("https://localhost:11434").is_err());
    }

    // --- Stub Ollama server -------------------------------------------
    //
    // This does NOT verify a real model's judgment — nothing here can,
    // without a real Ollama. What it DOES verify, against a real TCP
    // socket speaking the real wire format, is everything up to that
    // judgment: the request gets built and sent correctly, a
    // stream=false/format=json response gets parsed correctly, the
    // verdict JSON round-trips, and a malformed verdict is reported as an
    // error rather than silently swallowed. That's the entire client —
    // "does the model reason well" is the one thing left unverified, and
    // it's the one thing that was never claimed to be verified.

    /// Binds an OS-assigned port, accepts exactly one connection, replies
    /// with `response_json` as a 200 response, and sends the raw request
    /// bytes it received back over `mpsc` so the test can assert on them.
    ///
    /// Reads in a loop until it has the full request (parsing
    /// Content-Length like a real server would) rather than trusting a
    /// single `read()` to capture everything — the client does two
    /// separate `write_all` calls (headers, then body), and a first draft
    /// of this stub that assumed one `read()` would see both actually
    /// failed here: TCP doesn't guarantee two writes land in one segment,
    /// even on loopback.
    fn spawn_stub_ollama(response_json: String) -> (String, mpsc::Receiver<String>) {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind stub server");
        let port = listener.local_addr().unwrap().port();
        let (tx, rx) = mpsc::channel();

        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .ok();
                let request = read_full_http_request(&mut stream);
                let _ = tx.send(request);

                let body = response_json.as_bytes();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        (format!("http://127.0.0.1:{port}"), rx)
    }

    /// Reads from `stream` until the full HTTP request (headers +
    /// Content-Length body) has arrived, looping over `read()` calls
    /// rather than assuming one call sees everything.
    fn read_full_http_request(stream: &mut std::net::TcpStream) -> String {
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
                Err(_) => break, // timed out or connection error — return whatever we have
            }
        }
        String::from_utf8_lossy(&buf).to_string()
    }

    fn sample_finding() -> Finding {
        Finding {
            file: "config.py".into(),
            line: 4,
            detector: "aws_access_key_id".into(),
            confidence: crate::scanner::Confidence::High,
            category: crate::scanner::FindingCategory::Secret,
            redacted: "AKIA****************MPLE".into(),
            commit: None,
        }
    }

    /// Ollama's real /api/generate shape wraps the model's text output as
    /// a JSON *string* value under "response" — with format:"json" that
    /// string itself happens to contain JSON, which is why triage() has
    /// to parse it twice (once by ollama_post, once by serde_json::from_str
    /// on the extracted "response" field).
    fn ollama_envelope(verdict_json: &str) -> String {
        serde_json::json!({
            "model": "qwen2.5-coder:7b",
            "response": verdict_json,
            "done": true
        })
        .to_string()
    }

    #[test]
    fn triage_parses_a_real_secret_verdict_from_a_real_socket() {
        let envelope = ollama_envelope(
            r#"{"is_real_secret": true, "confidence_pct": 92, "reasoning": "looks like a live key"}"#,
        );
        let (base_url, request_rx) = spawn_stub_ollama(envelope);

        let client = OllamaTriage::new(base_url, "qwen2.5-coder:7b");
        let verdict = client
            .triage(&sample_finding(), "AWS_KEY = \"AKIA...\"")
            .expect("should parse the stub's response");

        assert!(verdict.is_real_secret);
        assert_eq!(verdict.confidence_pct, 92);

        let request = request_rx
            .recv_timeout(StdDuration::from_secs(2))
            .expect("server should capture a request");
        assert!(request.starts_with("POST /api/generate"));
        assert!(request.contains("aws_access_key_id"));
        assert!(request.contains("config.py"));
        assert!(
            request.contains("\"format\":\"json\""),
            "request: {request}"
        );
    }

    #[test]
    fn triage_parses_a_false_positive_verdict() {
        let envelope = ollama_envelope(
            r#"{"is_real_secret": false, "confidence_pct": 88, "reasoning": "matches AWS's own published example key"}"#,
        );
        let (base_url, _rx) = spawn_stub_ollama(envelope);

        let client = OllamaTriage::new(base_url, "qwen2.5-coder:7b");
        let verdict = client
            .triage(&sample_finding(), "EXAMPLE_KEY = \"AKIAIOSFODNN7EXAMPLE\"") // sieve:ignore
            .unwrap();

        assert!(!verdict.is_real_secret);
        assert_eq!(verdict.confidence_pct, 88);
    }

    #[test]
    fn triage_errors_cleanly_on_a_malformed_verdict_instead_of_panicking() {
        // The model returned text that isn't the expected JSON shape at
        // all — this must surface as an Err the caller can fail open on,
        // not a panic.
        let envelope = ollama_envelope("this is not json");
        let (base_url, _rx) = spawn_stub_ollama(envelope);

        let client = OllamaTriage::new(base_url, "qwen2.5-coder:7b");
        let result = client.triage(&sample_finding(), "context");
        assert!(result.is_err());
    }

    #[test]
    fn triage_errors_cleanly_on_non_200_status() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            if let Ok((mut stream, _)) = listener.accept() {
                stream
                    .set_read_timeout(Some(StdDuration::from_secs(5)))
                    .ok();
                let _ = read_full_http_request(&mut stream);
                let body = b"model not found";
                let response = format!(
                    "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes());
                let _ = stream.write_all(body);
            }
        });

        let client = OllamaTriage::new(format!("http://127.0.0.1:{port}"), "nonexistent-model");
        let result = client.triage(&sample_finding(), "context");
        assert!(result.is_err());
    }
}
