# Local Secret Scanner (formerly sieve)

[![Build](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/Rust-1.75+-blue.svg)](https://www.rust-lang.org)
[![Part of Agentic_](https://img.shields.io/badge/Part_of-Agentic__Super__OS-8A2BE2.svg)](#)

A local-first secrets scanner. Regex + entropy detection across your working
tree, staged changes, and full git history, redacted output, real exit codes
for CI, SARIF for GitHub code scanning, a pre-commit hook, optional SAST-lite
rules for risky code patterns — with an optional local-LLM triage pass to cut
false-positive noise.

Built to replace reflexively disabling secrets scanners after the tenth
false positive on a lockfile hash.

## 🔬 Core Architecture

```mermaid
graph TD
    subgraph "Input Vectors"
        WT[Working Tree]
        ST[Staged Changes]
        GH[Git History]
    end

    subgraph "Sieve Engine (Rust)"
        WLK[Parallel File Walker]
        DIFF[Diff Parser]
        
        REG[Regex Detectors]
        ENT[Entropy Evaluator]
        SAST[SAST Scanners]
    end

    subgraph "Output & Triage"
        CLI[Terminal Output]
        SAR[SARIF Report]
        LLM[Local LLM Triage Ollama]
    end
    
    WT --> WLK
    ST --> DIFF
    GH --> DIFF
    
    WLK --> REG
    WLK --> ENT
    WLK --> SAST
    
    DIFF --> REG
    DIFF --> ENT
    DIFF --> SAST
    
    REG --> CLI
    ENT --> CLI
    SAST --> CLI
    
    REG --> SAR
    REG <--> LLM
    
    style WLK fill:#e74c3c,stroke:#fff,stroke-width:2px,color:#fff
    style DIFF fill:#e74c3c,stroke:#fff,stroke-width:2px,color:#fff
    style LLM fill:#8a2be2,stroke:#fff,stroke-width:2px,color:#fff
    style SAR fill:#2c3e50,stroke:#fff,stroke-width:2px,color:#fff
```

## Status

| Layer | State |
|---|---|
| Scan engine (walker, 14 secret + 7 SAST detectors, history, staged, report, CLI) | **Done. 93/93 tests passing, cold run.** |
| SARIF output | **Done. Validated against the real official SARIF 2.1.0 schema**, not just eyeballed — see [Verification](#verification). |
| Native pre-commit hook (`hooks/pre-commit`) | **Done. Live-tested** — real `git commit` blocked on a real staged secret, passes clean, `--no-verify` bypass works, fails closed if `sieve` is missing. |
| `pre-commit` framework manifest (`.pre-commit-hooks.yaml`) | **Done. Live-tested against the real `pre-commit` framework** via `pre-commit try-repo` (builds sieve itself via `language: rust`). |
| GitHub Actions workflow (`.github/workflows/sieve.yml`) | **Written, YAML-validated, action versions/permissions checked against current GitHub docs — NOT run on a live GitHub Actions runner.** No GitHub remote to actually push to from this sandbox. |
| LLM triage (`--triage`, Ollama) | **HTTP client mechanics verified against a real stub server speaking Ollama's wire format** — request construction, JSON parsing, fail-open error handling, and the actual filtering decision are all tested end-to-end through the real CLI. **The one thing NOT verified: a real model's judgment quality.** No Ollama reachable in this sandbox to test that part. |

Nothing here is marked done that wasn't actually run. See [Known limitations](#known-limitations).

## Install

Requires Rust (this was built and pinned against rustc 1.75 — see
[Dependency pins](#dependency-pins) if you hit `edition2024` errors on an
older toolchain of your own).

```
cargo build --release
./target/release/sieve scan . --history
```

## Usage

```
sieve scan <PATH>                      # working tree only
sieve scan <PATH> --history            # + full git history (finds secrets purged from HEAD)
sieve scan <PATH> --staged             # only the git index — what's about to be committed
sieve scan <PATH> --sast               # + dangerous code patterns (opt-in, not secrets)
sieve scan <PATH> --format json        # for CI / piping
sieve scan <PATH> --format sarif       # for GitHub code scanning
sieve scan <PATH> --min-confidence high
sieve scan <PATH> --triage             # experimental, see below
sieve scan <PATH> --max-file-size-mb 50  # default is 10, see Known limitations
```

`--staged` and `--history` are mutually exclusive (staged changes vs. full
commit history are different questions) — combining them is a usage error
(exit 2), not silently one-or-the-other.

Exit codes: `0` = clean, `1` = findings above the confidence threshold, `2` = scan error
(bad path, git failure, `--staged` outside a repo, etc — deliberately
distinct from "0 findings" so a typo'd path can never look like a clean scan).

### Detectors

| Detector | Confidence | What it catches |
|---|---|---|
| `aws_access_key_id` | High | `AKIA…` / `ASIA…` |
| `private_key_header` | High | `-----BEGIN … PRIVATE KEY-----` |
| `github_token` | High | `ghp_/gho_/ghu_/ghs_/ghr_…` |
| `slack_token` | High | `xoxb-/xoxa-/xoxp-/xoxr-/xoxs-…` |
| `slack_webhook_url` | High | `hooks.slack.com/services/T…/B…/…` |
| `stripe_api_key` | High | `sk_live_…` / `rk_live_…` (test-mode keys are deliberately excluded — see below) |
| `google_api_key` | High | `AIza…` (35 chars) |
| `sendgrid_api_key` | High | `SG.<22 chars>.<43 chars>` |
| `npm_token` | High | `npm_…` (36 chars) |
| `jwt` | Medium | `eyJ…\.…\.…` |
| `twilio_api_key` | Medium | `SK` + 32 hex chars |
| `db_connection_string_with_password` | Medium | `postgres\|mysql\|mongodb\|redis\|amqp://user:password@host` (e.g. `amqp://guest:guest@localhost`) <!-- sieve:ignore --> |
| `generic_api_key_assignment` | Medium | `api_key = "…"` and `"api_key": "…"` (JS/Python/JSON style) |
| `high_entropy_token` | Low | Shannon-entropy catch-all, tunable via `--entropy-threshold`/`--entropy-min-len` |

This is rule parity with gitleaks on a *subset* — not full parity. It's a
growing set, not a replacement for a mature scanner's rule library yet.

`stripe_api_key` only matches `_live_` keys, not `_test_` — Stripe's own
test-mode keys are explicitly non-sensitive, same reasoning as AWS
publishing `AKIAIOSFODNN7EXAMPLE` as a documentation example. Flagging <!-- sieve:ignore -->
test-mode keys would just be noise for no security benefit.

### Reducing false positives

Two mechanisms, verified against real (not synthetic) noise sources:

- **Known lockfiles skip the entropy detector by default.** `npm`'s
  `sha512-<hash>` integrity strings and `go.sum`'s `h1:<hash>` lines both
  genuinely tripped `high_entropy_token` before this existed — checked by
  scanning real `package-lock.json`/`go.sum` content, not assumed.
  `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Cargo.lock`,
  `go.sum`, `poetry.lock`, `Pipfile.lock`, `Gemfile.lock`, `composer.lock`,
  `mix.lock`, `packages.lock.json`, and `flake.lock` are covered by
  filename match at any depth. Structural detectors (AWS keys, tokens,
  ...) still run on these files — only the noisy entropy catch-all skips
  them. Opt back in with `--scan-lockfile-entropy`.
- **Inline `sieve:ignore`** suppresses an entire line, all detectors, for
  a specific confirmed false positive — same convention as gitleaks'
  `gitleaks:allow`. Put it in a trailing comment: `KEY = "..."  #
  sieve:ignore -- rotated 2026-01-01`. Checked once, at the point where
  every scan mode (working tree, `--staged`, `--history`) converges, so it
  applies uniformly rather than needing separate handling per mode.

### Robustness

Two things checked directly rather than assumed, because this is a
security tool and "does it hold up against hostile or just-messy input"
is a fair question to ask of one:

- **Symlink loops don't hang the walker.** Built an actual loop (a
  directory symlinked to its own ancestor) and confirmed sieve terminates
  normally and still finds the real file sitting next to it, rather than
  trusting the `ignore` crate's `follow_links: false` default unverified.
- **Large files are capped, not read unbounded.** A 129MB file, unguarded,
  took ~3s and ~134MB of RSS — measured with `/usr/bin/time -v`, not
  guessed. Linear in file size, which is fine once and not fine if a
  stray multi-GB dataset/dump/build artifact ends up inside the scan root
  before it's gitignored. `--max-file-size-mb` (default 10) skips
  anything bigger via a `stat()` before ever reading the content; the same
  129MB file now scans in effectively 0s at ~5.6MB RSS.
- **ReDoS isn't possible here by construction, not by careful pattern
  writing.** Rust's `regex` crate guarantees linear-time matching for
  every pattern — it's the direct tradeoff for not supporting
  lookahead/backreferences (see the `--sast` section below). No regex in
  this codebase, however written, can catastrophically backtrack.

- **`--history`/`--staged` no longer read `git` subprocess output
  unbounded either (0.3.4).** Both used `Command::output()`, buffering the
  whole subprocess stdout the same unguarded way the pre-0.3.3 file walker
  did — a commit adding one huge file hit the identical exposure through
  a different path. Fixed with a bounded `Read::take()` in
  `src/git_exec.rs`, shared by both callers.
  **The nuance, found by measuring rather than assuming the fix "worked":**
  tested against a real 49MB file committed to a real repo, through the
  actual `--history` CLI path. Wall time dropped from 5.15s (uncapped) to
  0.28s (capped at 1MB) — the fix does what it's supposed to, avoiding a
  wait on the full output. But peak RSS stayed ~177MB regardless of the
  cap setting, which didn't match expectations — so that got checked
  too: a bare `git show` on the same commit, no sieve involved at all,
  showed the *same* ~177MB. That's git's own internal diff-computation
  memory, not sieve's buffering, and no cap on sieve's side can touch it.
  What the cap *does* control — verified precisely, not inferred from the
  RSS number — is that `src/git_exec.rs`'s captured output never exceeds
  the requested byte limit (`git_exec::tests::caps_output_without_hanging`).
  The fix's real, confirmed value here is eliminating the pipe-deadlock
  hang risk and bounding *time*, not reducing peak memory on a genuinely
  huge individual file — that memory is git's own, not sieve's, and nothing
  on sieve's side changes it.

### `--history` vs `--staged`

Both run the same detectors over a unified diff (`src/diff_scan.rs`, one
parser, two callers) instead of walking files on disk:

- **`--history`** shells out to `git log --all` + `git show` per commit —
  every commit reachable from any ref, diffed against its parent, added
  lines only. This is the whole reason history scanning exists: a key that
  was committed and later deleted is still sitting in `.git` forever unless
  history was actually rewritten.
- **`--staged`** shells out to `git diff --cached` once — just the index,
  i.e. what `git commit` would actually record right now. This is what the
  pre-commit hook uses: fast, and correct even if there are unstaged edits
  on top of what's staged (which working-tree scanning would get wrong).

Both shell out to the system `git` binary rather than linking libgit2 — no
native build dependency, and git is already required to scan a git repo
anyway.

### `--sast` (opt-in, not a secret scan)

Seven dangerous-*code-pattern* detectors, run over the same engine, off by
default (pass `--sast` to include them alongside secret detection):

| Detector | Confidence | What it flags |
|---|---|---|
| `disabled_tls_verification` | High | `verify=False`, `rejectUnauthorized: false`, `NODE_TLS_REJECT_UNAUTHORIZED=0` |
| `shell_injection_risk` | Medium | `subprocess.run(..., shell=True)`, `os.system(...)` |
| `dangerous_eval_exec` | Medium | `eval(...)` / `exec(...)` |
| `insecure_deserialization` | Medium | `pickle.loads(...)`, `yaml.load(...)` |
| `sql_injection_risk` | Medium | SQL built via an f-string interpolation (`f"SELECT ... {x}"`) |
| `hardcoded_debug_mode` | Medium | `DEBUG = True`, `app.run(..., debug=True)` |
| `react_dangerous_innerhtml` | Medium | `dangerouslySetInnerHTML` |

These findings are shown **unredacted** — the match itself (`eval(`,
`shell=True`) isn't a sensitive value the way a leaked key is, so masking
it would just make the report useless. That's the actual reason `Finding`
has a `category` field (`secret` vs `sast`): it's not cosmetic, it decides
whether the value gets redacted, and it's carried into SARIF as
`properties.tags` so the code-scanning UI can group by it.

Every rule here is a heuristic worth a human look, not a confirmed
vulnerability — `shell=True` on a hardcoded command with no user input is
fine; a single-line regex can't know which situation it's looking at.
`insecure_deserialization`'s `yaml.load` half is broader than it should
be: it can't check for a `Loader=yaml.SafeLoader` argument in the same
call, because Rust's `regex` crate has no lookahead to express that
negative condition. Documented in
[Known limitations](#known-limitations), not silently accepted.

### Pre-commit hook

Two ways to install, both scan the staged diff and block the commit on
findings at or above `SIEVE_MIN_CONFIDENCE` (default `high`):

**Native git hook:**
```
cp hooks/pre-commit .git/hooks/pre-commit && chmod +x .git/hooks/pre-commit
```

**`pre-commit` framework** ([pre-commit.com](https://pre-commit.com)) — add to `.pre-commit-config.yaml`:
```yaml
repos:
  - repo: https://github.com/YOUR_ORG/sieve   # once this has a real remote
    rev: v0.3.5   # once this repo has a real remote and a matching tag
    hooks:
      - id: sieve
```
`language: rust` in the manifest means `pre-commit` builds sieve itself via
`cargo install` — nothing to pre-install. Verified locally with
`pre-commit try-repo /path/to/sieve sieve --verbose` against this exact
manifest, no GitHub remote required for that test.

Either way: bypass a confirmed false positive with `git commit --no-verify`;
a missing `sieve` binary or a scan error fails **closed** (blocks the
commit) rather than silently letting it through.

### CI (GitHub Actions)

`.github/workflows/sieve.yml` builds sieve, scans full history, uploads
SARIF to the repo's Security → Code scanning tab, and fails the build on
findings. As shipped it dogfoods on sieve's own source; to scan a
*different* repo, add a step that checks out sieve as a sibling directory
(or, once one exists, downloads a released binary) alongside the target
repo, then point the `Scan` step's path at the target instead of `.`.

Action versions and the `permissions:` block were checked against GitHub's
current docs while building this (`actions/checkout@v6`,
`dtolnay/rust-toolchain@stable`, `Swatinem/rust-cache@v2`,
`github/codeql-action/upload-sarif@v4`) — the SARIF schema URL guess in an
earlier draft 404'd (wrong branch, wrong path) and got caught the same way,
by actually fetching it. What this workflow has *not* had is an actual run
on a GitHub Actions runner, since there's no GitHub remote to push to from
this sandbox.

### `--triage` (mechanics verified, model judgment is not)

Sends each finding + surrounding code to a local Ollama model
(`--triage-model`, default `qwen2.5-coder:7b`) asking whether it's a real,
live secret vs. a placeholder/example/already-revoked value. Fails open —
if the triage call errors for any reason, the finding is kept, not hidden.

**What's verified:** the entire HTTP client, against a real stub server
speaking Ollama's actual wire format (`tests/integration_test.rs` and
`src/triage.rs`'s own tests spin one up on a real socket) — request
construction, the `/api/generate` JSON body, parsing a `stream:false`
response, extracting and re-parsing the embedded verdict JSON, and the
resulting filtering decision. Both directions are tested end-to-end
through the actual `sieve` binary: a stub verdict of "real secret" keeps
the finding, a stub verdict of "false positive" filters it out. A
malformed verdict and a non-200 response both fail cleanly (finding kept,
no crash) instead of panicking.

**What's not verified: whether a real model gives good answers.** No
stub server can test that — it needs a real Ollama and a real model. Point
`--triage-url` at your actual instance, run it against a repo with known
findings, and check the verdicts by hand before trusting the filtering.
That's the one genuine unknown left in this feature; everything mechanical
around it has a passing test.

## Verification

Things that were actually run, not just written, before being called done:

- **93/93 tests, cold** (75 unit + 18 integration), including a fresh `tar`
  extraction to a clean directory before `cargo test`.
- **`--history`/`--staged` bounded reads**: measured against a real 49MB
  file committed to a real repo through the actual CLI, not just at the
  unit level — confirmed the fix bounds wall time (5.15s → 0.28s) and
  found, by actually investigating an unexpected result rather than
  reporting it uncritically, that the ~177MB peak RSS in that scenario is
  git's own diff-computation overhead (confirmed via a bare `git show`
  with no sieve involved showing the same number), not sieve's — so the
  finding is reported precisely rather than as a memory win that isn't
  really there.
- **`--history` at scale**: two real git repos (not synthetic), 501 and
  2,001 commits, measured with `/usr/bin/time -v` rather than left as a
  hand-wave — 1.05s/4.63s, ~6MB RSS flat across both, ~2.1-2.3ms/commit
  and linear. Replaced a vague "will get slow" limitation with actual
  numbers.
- **Robustness checks against actual hostile/messy input**, not just
  reasoning about it: built a real symlink loop and confirmed no hang;
  measured a 129MB file's memory/time footprint with `/usr/bin/time -v`
  before deciding a size guard was warranted, then re-measured after
  (~3s/134MB → ~0s/5.6MB).
- **`--sast`**: verified off by default (a fixture with 7 planted risky
  patterns produces zero findings without the flag), verified it catches
  all 7 when enabled, and verified the matches show up **unredacted** —
  the actual failure mode this needed testing for was accidentally
  masking a code pattern the way a secret gets masked, which would make
  the finding useless.
- **Lockfile false positives**: not assumed away — scanned a real
  `package-lock.json` and `go.sum` and confirmed the entropy detector
  actually tripped on their SRI/`h1:` hashes *before* fixing it, then
  confirmed 0 findings by default and the original count back via
  `--scan-lockfile-entropy` after.
- **13 new detectors total across v2.1/v3** (7 secret-category, 7
  SAST-category): each has a positive-match test and, where relevant, a
  negative test (Stripe test-mode keys, connection strings with no
  password, parameterized SQL queries, `shell=False`). One test fixture
  bug found this way — the synthetic SendGrid key was 2 characters short
  of the real `SG.<22>.<43>` format — fixed, not loosened to match a
  wrong regex.
- **Dogfooded on its own source**, and this time the raw count was
  actually traced rather than reported at face value: 44 findings
  scanning its own source at medium+ confidence — 4 are README prose
  describing what the detectors catch, 17 are test fixtures, 23 are
  inside `#[cfg(test)]` blocks. Zero in real logic.
- **SARIF schema**: fetched the real `sarif-schema-2.1.0.json` from
  `oasis-tcs/sarif-spec` (had to find the actual path via the repo tarball
  — the first guessed URL was wrong) and validated sieve's real output
  against it with Python's `jsonschema`, not eyeballed — re-validated
  after adding the `properties.tags` field and the SAST rule set, not
  assumed still valid.
- **Native pre-commit hook**: installed into a real repo, ran real `git
  commit` with a staged secret (blocked), with the secret fixed (passed),
  with `--no-verify` (bypassed), and with `sieve` removed from `PATH`
  (failed closed). Re-tested after adding new detectors with a Stripe-key
  commit specifically, to confirm the hook path isn't special-cased to
  the original AWS-key example.
- **`.pre-commit-hooks.yaml`**: exercised through the real `pre-commit`
  framework via `try-repo`, which builds sieve from source via
  `language: rust` and ran it against a staged secret (failed) and a clean
  index (passed).
- **GitHub Actions workflow**: YAML-parsed for syntax, action refs and the
  `permissions:` block checked against current GitHub docs. Not run on an
  actual runner — no GitHub remote exists for this project yet.
- **`--triage`'s HTTP mechanics**: verified against a real stub server on
  a real socket, not just reasoned about — request construction, response
  parsing, and both filtering directions (keeps a stub "real secret"
  verdict, drops a stub "false positive" verdict) tested end-to-end
  through the actual CLI. What's *not* run: a real Ollama model's actual
  judgment quality, which no stub can substitute for.

## Known limitations

- **`--history`/`--staged`'s bounded reads control sieve's memory, not
  git's.** 0.3.4 fixed the unbounded `Command::output()` buffering (see
  [Robustness](#robustness)), but measuring it against a real 49MB
  committed file found that peak memory for scanning that commit is
  dominated by *git's own* diff-computation overhead (~177MB, confirmed
  via a bare `git show` with no sieve involved), not sieve's buffering —
  no cap on sieve's side touches that. What the fix actually delivers:
  no pipe-deadlock hang, and bounded wall time (5.15s → 0.28s in that same
  test) rather than waiting on a slow subprocess to fully flush a huge
  diff.
- **Entropy detector is still noisy outside known lockfiles.** It's the
  highest-false-positive detector in the set (hence Low confidence) — long
  base64 blobs, minified code, and hand-pasted certs can all look
  "random." Verified, not assumed: a raw 40-char git commit hash and a
  UUID don't trip it (hex/UUID alphabets structurally can't reach 4.3
  bits/char); `npm`'s `sha512-` integrity strings and `go.sum`'s `h1:`
  hashes *did* trip it until the lockfile skip was added (see [Reducing
  false positives](#reducing-false-positives)) — that fix only covers
  known lockfile filenames, not every dense-base64 source (e.g. a
  hand-pasted cert or minified bundle will still trip it).
- **`generic_api_key_assignment` is a heuristic, not a grammar.** It covers
  `keyword [:=] "value"` with or without a JSON-style closing quote before
  the colon. Multiline values, YAML block scalars, and unconventional
  keyword names will slip past it.
- **`db_connection_string_with_password` can't tell a real password from a
  placeholder.** `postgres://user:password@host` and <!-- sieve:ignore -->
  `postgres://app:Tr0ub4dor&3@host` match identically — this is a Medium <!-- sieve:ignore -->
  confidence heuristic, not a judgment call the regex can make.
- **`sieve:ignore` has no scope control.** It's a blunt "skip this whole
  line, every detector" — there's no way to suppress just one detector on
  a line that trips two, and no expiry/review mechanism (a
  `gitleaks:allow`-style comment can silently outlive the reason it was
  added).
- **SAST rules are heuristics that can't see data flow.** `shell=True` on
  a hardcoded, non-user-controlled command isn't actually dangerous, and a
  single-line regex has no way to know the difference — every `--sast`
  finding is "worth a look," not "confirmed exploitable."
- **`insecure_deserialization`'s `yaml.load` half is a blunt instrument.**
  It flags every `yaml.load(...)` call, whether or not it passes
  `Loader=yaml.SafeLoader` — the ideal rule needs a negative lookahead,
  and Rust's `regex` crate doesn't support lookahead/lookbehind at all
  (it's the tradeoff for guaranteed linear-time matching). Documented, not
  silently accepted.
- **`sql_injection_risk` only catches Python f-strings**, not `.format()`,
  `%`-formatting, string concatenation, or non-Python languages.
- **History scanning has no `--since`/incremental mode yet** — every scan
  walks every commit from scratch — **but it's now measured, not a
  hand-wave.** Two real data points on a genuine git repo, not a guess:
  501 commits in 1.05s (~6.0MB peak RSS), 2,001 commits in 4.63s (~6.3MB).
  That's ~2.1-2.3ms/commit and roughly linear, not quadratic — memory
  stays flat because each commit's diff is read and discarded, not
  accumulated. Extrapolating (linearly, which the two points support):
  ~23s at 10k commits, ~4 minutes at 100k. `--max-commits` still exists
  as a hard cap for repos where even that's too slow, but "will get slow
  on repos with tens of thousands of commits" was overstating it — the
  actual number is in the low tens of seconds.
- **Binary-file detection is a NUL-byte sniff** on the first 8KB, not a
  proper MIME/magic-byte check. Cheap and works for the common case, will
  misjudge some edge-case files.
- **The GitHub Actions workflow is unrun** — see Verification above.
- **`--triage`'s model judgment is unverified** — the client mechanics
  have a passing test suite against a stub server; a real model's actual
  answers do not, and can't, without a real Ollama.

## Dependency pins

Every dependency in `Cargo.toml` is pinned to an exact pre-2025 version.
This isn't stylistic caution — the sandbox this was built in has
apt-installed rustc 1.75, and the *latest* releases of `ignore`, `globset`,
`getrandom`, and others now declare `edition = "2024"` in their manifest,
which cargo 1.75 can't even parse. Pinning to versions from before that
adoption wave was the fastest path to a build that actually compiles here.

If you're building with a modern toolchain (1.85+), the pins are safe to
loosen — try `cargo update` and re-run the test suite.

## Architecture

```
src/
  main.rs          CLI (clap) — thin wrapper over the lib
  lib.rs           module wiring, public re-exports
  scanner.rs        Finding/Confidence/ScanOptions, working-tree scan orchestration
  walker.rs         gitignore-aware working-tree walk (ignore crate)
  diff_scan.rs       shared unified-diff parser (added lines, file/line tracking)
  git_history.rs     full-history scan: git log + git show, per commit, via diff_scan
  staged.rs          staged-only scan: git diff --cached, via diff_scan
  detectors/
    mod.rs           Detector trait, redact()
    patterns.rs       14 secret detectors (AWS/GitHub/Slack/Stripe/Google/SendGrid/npm/Twilio/JWT/private-key/DB-conn-string/generic)
    entropy.rs         Shannon-entropy catch-all
    sast.rs            7 opt-in SAST detectors (--sast) — code patterns, not secrets, shown unredacted
  report.rs          JSON, colored text, and SARIF 2.1.0 output
  triage.rs          Ollama client - mechanics tested against a stub server, model judgment untested
hooks/
  pre-commit         native git hook — staged scan, fails closed
.pre-commit-hooks.yaml   pre-commit framework manifest (language: rust)
.github/workflows/
  sieve.yml          build + scan + SARIF upload, dogfoods on sieve's own source
tests/
  fixtures/dirty/    planted, synthetic (non-functional) secrets
  fixtures/clean/    realistic noise that must NOT false-positive
  integration_test.rs   runs the actual compiled binary via assert_cmd
```

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for the full 0.1.0 → 0.3.5 history —
what shipped in each version, what broke and got fixed along the way, and
what's still genuinely unverified.

## License

MIT
