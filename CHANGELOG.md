# Changelog

All notable changes to sieve. Versions here match the commit messages in
`git log`, not just a marketing label — every "done" below was actually
run before being called done; see [Verification](README.md#verification)
in the README for the specifics of how.

## 0.3.5 — measure --history at scale instead of hand-waving about it

"Will get slow on repos with tens of thousands of commits" had been sitting
in Known Limitations since early on, unmeasured. Replaced it with real
numbers.

- Generated two real git repos (not synthetic diff text — actual `git
  init`/`add`/`commit` sequences) at 501 and 2,001 commits, and ran the
  real `--history` CLI path against both with `/usr/bin/time -v`.
  - 501 commits: 1.05s, ~6.0MB peak RSS
  - 2,001 commits: 4.63s, ~6.3MB peak RSS
  - ~2.1-2.3ms/commit, consistent across both sizes — roughly linear,
    not quadratic. Memory stays flat because 0.3.4's bounded reads mean
    each commit's diff is read and discarded, not accumulated.
- First attempt at generating the test repos failed and wasted a lot of
  output before this landed: `git add . -q` doesn't work with this git
  version's `add` subcommand (no `-q`/`--quiet` support at all, confirmed
  from its own `--help` text, not just an ordering issue as first
  suspected) — every `git add` in the loop silently failed via a
  redirect, so nothing ever got committed and the first run measured
  nothing. Fixed by dropping `-q` from `git add` entirely (redirecting
  output instead) and verifying at a 5-commit scale before scaling up to
  500+, rather than repeating the same mistake at 1000 commits and
  wasting more output on it.
- Not a permanent automated test — a 2,000-commit repo is too slow to
  regenerate on every `cargo test` run. Documented as a one-time
  measurement, same treatment as the 0.3.3/0.3.4 large-file benchmarks.

## 0.3.4 — bound the last unbounded read (`--history`/`--staged`)

Closed the one open item from 0.3.3 that wasn't blocked by missing
infrastructure: `--history`/`--staged` read `git show`/`git diff --cached`
output via `Command::output()`, buffering the whole subprocess stdout in
memory the same unguarded way the pre-0.3.3 file walker did.

- New `src/git_exec.rs`: a shared `run_git_capped()` used by both
  `git_history.rs` and `staged.rs`, reading stdout through a bounded
  `Read::take()` instead of `Command::output()`'s unbounded buffering.
- **The naive version of this fix has a deadlock trap, and a test proved
  it**: if the real output exceeds the cap, the child can end up blocked
  inside its own `write()` once the pipe fills, since nothing drains it
  past the limit — a plain `child.wait()` after that hangs forever.
  Killing the child before waiting is what prevents it; verified with a
  real 5MB commit and a 1KB cap, asserting completion in under 5 seconds.
- Preserved `staged.rs`'s clear error-message-on-failure behavior (which
  depended on stderr) rather than letting the bounded-read fix silently
  regress it — `run_git_capped` captures a bounded slice of stderr too,
  read after stdout (git's error text is short and doesn't realistically
  fill a pipe the way diff content does, so this doesn't need full
  concurrent dual-stream draining).
- **Measured the real end-to-end impact, and the result was more nuanced
  than expected — reported precisely rather than rounded up to a clean
  story.** Against a real 49MB file committed to a real repo: wall time
  dropped 5.15s → 0.28s (capped), confirming the fix works as intended.
  Peak RSS stayed ~177MB regardless of the cap. Investigated rather than
  waved off: a bare `git show` on the same commit, no sieve involved,
  showed the identical ~177MB — that's git's own diff-computation
  overhead, which no cap on sieve's side can touch. The fix's real,
  confirmed value is eliminating the deadlock-hang risk and bounding
  time, not reducing peak memory on a single genuinely huge file.
- The end-to-end scenario above (real 49MB file, real repo, real CLI) is
  now a permanent test
  (`history_scan_does_not_hang_on_a_commit_with_a_large_file`), not just a
  one-off manual check done while building the fix — it asserts
  completion in under 10 seconds against a real 5MB commit.
- Test count: 89 → 93 (75 unit + 18 integration).

## 0.3.3 — robustness: symlink loops, unbounded file reads

Treated sieve as what it is — a security tool, meaning "does it hold up
against hostile or just-messy input" is a fair question to ask of its own
code, not just the things it scans for.

- **Verified, not assumed: no symlink-loop hang.** Built an actual
  directory symlinked to its own ancestor and confirmed the walker
  terminates and still finds a real planted secret next to the loop,
  rather than trusting the `ignore` crate's default unverified.
- **Measured, not guessed: unbounded file reads.** A 129MB file, scanned
  with no guard, took ~3s and ~134MB RSS (`/usr/bin/time -v`, not a
  hand-wave) — linear in file size, fine once, not fine if a stray
  multi-GB dataset/dump/build artifact ends up inside a scan root before
  it's gitignored.
- **Fix**: `--max-file-size-mb` (default 10) checks size via `stat()`
  before ever reading file content, for the working-tree walker. The same
  129MB file now scans in ~0s at ~5.6MB RSS — re-measured after the fix,
  not assumed fixed.
- **Noted, not silently ignored: `--history`/`--staged` don't have the
  same guard yet.** Both read `git show`/`git diff --cached` output via
  `Command::output()`, which buffers the whole subprocess output in
  memory the same unbounded way the file walker used to. Documented as an
  open item rather than left implicit.
- **Also documented, as a real property rather than an aspiration:**
  Rust's `regex` crate makes ReDoS structurally impossible in this
  codebase — linear-time matching is guaranteed for every pattern,
  precisely because the crate doesn't support the lookahead/backreference
  constructs that would make catastrophic backtracking possible.
- Test count: 87 → 89 (72 unit + 17 integration).

## 0.3.2 — verify --triage's mechanics without a real Ollama

Closed as much of the `--triage` gap as this sandbox actually allows,
rather than leaving it as a single "unverified" line item indefinitely.

- Built a stub Ollama server — a real `TcpListener` on a real socket,
  speaking the actual `/api/generate` wire format (reads until it has the
  full `Content-Length` body, replies with a `stream:false`-shaped JSON
  envelope). Used it to test everything *around* the model call: request
  construction (the prompt actually contains the finding's detector name,
  file, and redacted value), response parsing, malformed-verdict and
  non-200 error handling (fails cleanly, doesn't panic), and — the part
  that actually matters — the filtering decision itself, both directions,
  through the real compiled CLI: a stub "real secret" verdict keeps the
  finding, a stub "false positive" verdict filters it out.
- Found a real bug in the *test* while building this, not the product:
  the first draft of the stub server read the incoming request with one
  `read()` call and assumed that captured everything. It didn't — the
  client's two separate `write_all` calls (headers, then body) don't
  reliably land in the same TCP read, even on loopback. Fixed the stub to
  loop until it actually has the full `Content-Length` worth of body,
  same as a real server would.
- What this does **not** verify, and cannot: whether a real model's
  answers are any good. That still needs a real Ollama and is still
  explicitly called out as the one open item.
- Test count: 78 → 87 (71 unit + 16 integration).

## 0.3.1 — bugfix + polish

- **Fixed**: single-file scans (`sieve scan config.py`, as opposed to a
  directory) reported an empty filename in every output format. Found via
  testing `--triage`'s fail-open path against an unreachable Ollama — the
  error message showed `:4` instead of `config.py:4`. Root cause:
  `relative_display()` strips the scan root as a path prefix, which
  breaks when root *is* the file. Fixed with a fallback to the basename,
  covered by both a unit test and an end-to-end CLI regression test.
- Applied `cargo fmt` for the first time (real diff existed; re-ran the
  full suite + clippy afterward to confirm the formatting-only change
  didn't break anything).
- CI (`.github/workflows/sieve.yml`) previously only ran sieve scanning
  itself for secrets — added a separate `test` job that actually runs
  `cargo fmt --check`, `cargo clippy --all-targets -- -D warnings`, and
  `cargo test`.
- Test count: 78 → 81 (67 unit + 14 integration).

## 0.3.0 — optional SAST-lite layer

- New `--sast` flag (off by default): 7 dangerous-code-pattern detectors —
  `shell_injection_risk`, `dangerous_eval_exec`, `insecure_deserialization`,
  `disabled_tls_verification`, `sql_injection_risk`, `hardcoded_debug_mode`,
  `react_dangerous_innerhtml`.
- New `Finding.category` (`Secret` vs `Sast`): secret matches are redacted,
  SAST matches are shown in full — there's no sensitive value to mask in
  `eval(user_input)`. Carried into SARIF as `properties.tags` for
  code-scanning-UI filtering.
- Verified `--sast`'s off-by-default behavior and its unredacted display
  specifically, not just that the regexes match — getting either wrong
  would have made the feature actively worse than not having it.
- Re-validated SARIF against the real `oasis-tcs/sarif-spec` schema after
  the new rules and `properties.tags` field landed.
- Test count: 63 → 78 (65 unit + 13 integration).

## 0.2.1 — false-positive reduction, detector expansion

- **Fixed**: the entropy detector genuinely false-positived on real
  lockfile content — confirmed by scanning an actual `package-lock.json`
  (npm's `sha512-` SRI hashes) and `go.sum` (`h1:` hashes) before fixing
  it. Fix: 12 known lockfile filenames skip the entropy detector
  specifically (structural detectors still run); `--scan-lockfile-entropy`
  opts back in.
- New inline `sieve:ignore` line suppression (same convention as
  gitleaks' `gitleaks:allow`), checked once at the point where every scan
  mode converges.
- 7 new secret detectors: `stripe_api_key` (live-mode only — test keys are
  deliberately excluded), `google_api_key`, `sendgrid_api_key`,
  `npm_token`, `slack_webhook_url`, `twilio_api_key`,
  `db_connection_string_with_password`. 14 secret detectors total.
- One test-fixture bug caught along the way: a synthetic SendGrid key was
  2 characters short of the real `SG.<22>.<43>` format — fixed the
  fixture, not the regex.
- Dogfooded on its own source and actually traced every finding rather
  than reporting the raw count: all in test fixtures, canary literals in
  `#[cfg(test)]` blocks, or README prose describing the detectors. Zero in
  real logic.
- Test count: 48 → 63 (51 unit + 12 integration).

## 0.2.0 — staged scanning, SARIF, pre-commit hook, CI

- `--staged`: scans `git diff --cached` (the index) instead of the
  working tree — what a pre-commit hook actually needs, and correct even
  with unstaged edits on top of what's staged.
- `--format sarif`: SARIF 2.1.0 output for GitHub code scanning, validated
  against the real official schema (the first `$schema` URL guess 404'd —
  wrong branch, wrong path — found the real one via the repo tarball).
- `hooks/pre-commit`: native git hook, live-tested with real `git commit`
  — blocks on a real staged secret, passes clean, `--no-verify` bypasses,
  fails **closed** if `sieve` is missing from `PATH`.
- `.pre-commit-hooks.yaml`: manifest for the `pre-commit` framework
  (`language: rust`, builds sieve from source), live-tested via
  `pre-commit try-repo` against the real framework.
- `.github/workflows/sieve.yml`: build + scan + SARIF-upload workflow.
  Action versions and the `permissions:` block checked against current
  GitHub docs, not memory — never run on an actual runner (no GitHub
  remote exists for this project).
- Refactored the diff-parsing state machine into `diff_scan.rs`, shared by
  both history scanning and staged scanning instead of duplicated.
- Test count: 36 → 48 (38 unit + 10 integration).

## 0.1.0 — initial scan engine

- gitignore-aware working-tree walker (`ignore` crate).
- 7 secret detectors: AWS access keys, private key headers, GitHub
  tokens, Slack tokens, JWTs, generic `key = "value"` assignments
  (JS/Python/JSON), Shannon-entropy catch-all.
- Full git-history scanning (`--history`) via shelling out to
  `git log`/`git show` rather than linking libgit2 — no native build
  dependency. Proven against a synthetic repo where a key was committed
  and later deleted: still caught.
- JSON + colored text output, exit codes `0`/`1`/`2` (clean / findings /
  scan error — deliberately distinct so a typo'd path can never look like
  a clean scan).
- `--triage`: Ollama-backed LLM triage client, written and wired behind a
  flag. Never verified against a real Ollama — no LLM reachable in the
  sandbox this was built in. Still true as of 0.3.1.
- All dependencies pinned to pre-2025 versions — recent crates.io releases
  increasingly assume Rust's 2024 edition, which the apt-installed rustc
  1.75 in this sandbox can't parse.
- Test count: 36 (unit + integration).

## What's still genuinely unverified / not yet done

- **`--triage`'s actual model judgment.** As of 0.3.2, the entire
  mechanical path — request construction, response parsing, error
  handling, and the filtering decision itself — is tested against a real
  stub server and passes. What's never happened is a real model looking
  at a real finding and giving an opinion worth trusting. No stub can
  substitute for that.
- **The GitHub Actions workflow, on an actual runner.** YAML-valid,
  action references checked against current docs, but no GitHub remote
  exists for this project to push to and watch it run.

Both require infrastructure this sandbox doesn't have — a real Ollama
instance with a model loaded, a real GitHub remote. Everything that was
just scoped work rather than a genuine infrastructure block (the
`--history`/`--staged` memory bound from 0.3.3's list) has been closed as
of 0.3.4.
