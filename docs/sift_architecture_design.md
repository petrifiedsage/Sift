# SecretSentinel — Architecture & Design

_A complete architecture blueprint for an offline, pre-commit, risk-aware Secrets Exposure Detector._

---

## Overview
SecretSentinel is a pre-commit / CLI / CI-capable tool that scans repositories and arbitrary file sets for secrets and sensitive information **before** they are committed or uploaded. It focuses on multi-layer detection (regex, entropy, context), risk scoring, developer-friendly remediation guidance, and enterprise-friendly outputs (JSON, SARIF, Markdown). The tool is designed to run fully offline and be easily integrated into dev workflows.

Goals:
- Detect both known provider tokens and custom secret patterns
- Reduce false positives via contextual heuristics and allowlists
- Provide actionable risk scores and remediation guidance
- Support pre-commit hooks, CLI scanning, and optional API server for centralized scanning

---

## High-level components

1. **CLI / Runner** — user entrypoint. Scans directories or individual files, runs configured detection modules, produces reports, and optionally exits non-zero for CI/pre-commit.

2. **Pre-commit Hook Integration** — small script that calls the Runner on staged files and blocks commits when high-risk secrets are found.

3. **Detection Modules**
   - **Regex Detector**: provider-specific and custom regexes
   - **Entropy Detector**: flags high-entropy strings (possible secrets)
   - **Keyword Context Detector**: flags lines with contextual sensitive keywords (password, secret, api_key)
   - **Credential Heuristics**: detects likely DB credentials, BasicAuth, connection strings
   - **Machine-Learned (optional)**: small lightweight classifier for ambiguous cases (optional, offline-able)

4. **Risk Scoring Engine** — combines evidence from detectors into a normalized risk score (0–100) and classification (LOW/MEDIUM/HIGH/CRITICAL).

5. **False Positive Filter / Allowlist** — supports file-level, repo-level, and global allowlists; fuzzy matching to avoid blocking test fixtures.

6. **Output & Reporters** — CLI text, JSON, SARIF, Markdown, and optional HTML report.

7. **Server Mode (Optional)** — lightweight FastAPI server for scanning remote artifacts or exposing a centralized scan API for CI. Not required for local-only use.

8. **Config** — YAML/JSON config file per repo to tune rules, thresholds, and allowlists.

9. **Tests & Sample Data** — test corpus to tune detectors and CI job for validating behavior.

10. **Metrics & Telemetry (Optional, opt-in)** — internal metrics about scans (not secrets) for usage and tuning.

---

## Dataflow / Sequence

1. Developer runs `secret-sentinel scan` or attempts `git commit`.
2. Pre-commit hook calls `secret-sentinel scan --staged`.
3. Runner enumerates target files.
4. For each file/line, detection modules produce findings with evidence and scores.
5. Findings pass through False Positive Filter (allowlist, file-type heuristics).
6. Scoring Engine computes final risk score and classification.
7. Runner emits report(s). If any findings exceed the configured fail threshold, the process exits non-zero and prints remediation steps.
8. Developer fixes secret (or marks as allowed), re-runs scan, and commits.

---

## Component Details

### CLI / Runner
- Subcommands: `scan`, `init-config`, `hook-install`, `server` (optional), `audit`.
- Flags: `--staged`, `--path`, `--format` (json, sarif, md), `--fail-threshold`, `--config`.
- Behavior: stream findings to stdout and save a report file when requested.

Suggested layout (`src/`):
```
src/
  sentinel/
    __main__.py    # CLI entry
    runner.py      # orchestrates scans
    detectors/
    scoring.py
    reporters/
    config.py
    precommit.py
    server.py
```

---

### Detection Modules

**Regex Detector**
- Contains curated regexes for common providers (AWS, GCP, Azure, Stripe, Slack, Twilio, etc.).
- Supports user-provided regexes via config.
- Stores regex metadata: id, name, severity, example.

**Entropy Detector**
- Sliding-window tokenization per line.
- Shannon entropy calculation for candidate tokens (see formula below).
- Tunable threshold by token length (short tokens require higher thresholds).

**Keyword Context Detector**
- Looks for sensitive keywords near tokens (line-level and +/- N lines context).
- Keywords: password, passwd, secret, api_key, token, private_key, rsa_private

**Credential Heuristics**
- DB connection string patterns
- BasicAuth `user:pass` patterns (Base64 detection)
- PEM/key file detection (BEGIN RSA PRIVATE KEY)

**ML Classifier (optional)**
- Small distilled model (or feature-based classifier) trained on labeled corpus to further reduce false positives.
- Designed to be optional and offline-friendly (scikit-learn joblib or tiny ONNX).

---

### Risk Scoring Engine

Elements used to compute score:
- **Base severity** from detector type (regex = 60, entropy = 40, keyword = 25, credential heuristic = 70 by default)
- **Entropy multiplier** (higher entropy increases score)
- **Context multiplier** (if keyword appears nearby +20)
- **File weight** (configurable; `secrets.yaml` > production configs > test files)
- **Occurrence count** (multiple occurrences increase score)

Sample formula (normalized to 0–100):

```
raw = base_severity * (1 + (entropy-entropy_threshold)/10) * context_multiplier * file_weight
score = min(100, round(raw))
```

Classification buckets:
- 0–24: LOW
- 25–49: MEDIUM
- 50–74: HIGH
- 75–100: CRITICAL

Each finding returns: `{file, line, snippet, detector_ids, entropy, raw_score, score, classification, recommendation}`.

---

### False Positive Reduction
- Default allowlist locations:
  - `.secret-sentinel/allowlist.yaml`
  - `sentinel.config.json`
  - global `~/.secret-sentinel/allowlist.yaml`
- Pattern types: full token match, regex, file path glob, commit message allow (for known test values).
- Heuristics to ignore:
  - UUIDs, common hashes (MD5/SHA1) when in contexts that indicate hashing
  - Known test fixtures (by filename patterns like `*_test_data*`)

---

### Output Formats
- **CLI**: colored table with file:line → score → short recommendation
- **JSON**: full data structure for automation
- **SARIF**: compatible with many security scanners and code scanning UIs
- **Markdown**: human-readable report for PRs
- **HTML (optional)**: local hostable report

Sample JSON finding:

```json
{
  "file": "config/prod.env",
  "line": 12,
  "snippet": "DB_PASS=Prod_DB_2024!",
  "detectors": ["regex-db-pass","entropy-high"],
  "entropy": 4.8,
  "raw_score": 92.3,
  "score": 92,
  "classification": "CRITICAL",
  "recommendation": "Move DB_PASS into environment variables or secret store; rotate the exposed credential."
}
```

---

### Pre-commit Hook
- Small shim that calls `secret-sentinel scan --staged --format=json` and exits with the highest finding score > `fail-threshold`.
- Fails fast but prints clear remediation guidance.
- Provide `--staged` to only scan staged files and be fast.

Example hook entry for `.git/hooks/pre-commit` (or `pre-commit` framework):
```bash
#!/bin/sh
secret-sentinel scan --staged --fail-threshold 50 || exit 1
```

---

### Config
Example `sentinel.yaml` (repo root):

```yaml
fail_threshold: 60
entropy_thresholds:
  default: 3.8
  min_length: 16
file_weights:
  "**/config/*.env": 1.4
  "**/tests/**": 0.3
custom_regexes:
  - id: "internal-api-key"
    pattern: "INTERNAL_[A-Z0-9]{30}"
    severity: 65
allowlist:
  tokens:
    - "TEST_TOKEN_XXXXX"
  paths:
    - "docs/**/*"
```

---

### Server Mode (Optional)
- Lightweight FastAPI service with endpoints:
  - `POST /scan` -> accepts zip or file list -> returns JSON report
  - `GET /rules` -> list active rules
  - `POST /allowlist` -> add allowlist entries (auth protected)
- Use case: centralize scanning for CI runners or heavier scheduled scans

Security: server must not persist secrets; only store findings metadata. If server is used, encrypt at rest and require auth.

---

## Performance & Implementation Notes
- Use streaming file reads to keep memory usage low.
- Limit binary file scanning by MIME sniffing and file extension heuristics.
- Regex engine: compile patterns once; run provider regexes before entropy to short-circuit.
- Parallelize per-file scanning using worker pool for large repos; keep `--staged` fast (single-thread sufficient).
- Provide a `--max-lines` and `--max-file-size` guard rails.

---

## Testing Strategy
- Unit tests for detectors with labeled positive/negative samples.
- A small golden dataset of sample repos (benign + leaked-secrets). Keep test dataset offline and under the repo `tests/fixtures/`.
- Fuzzing: random token generation to validate entropy thresholds.
- CI job to ensure detectors don't regress (fail on high-risk examples).

---

## Security Considerations
- Never log full secrets to remote telemetry (mask tokens in outputs > log only hashes or first/last 3 chars).
- Default to offline-first; if telemetry is enabled, make it opt-in.
- Recommendations should always suggest rotation and remediation.

---

## Deployment
- Distribute as a pip package and a small standalone binary via `pyinstaller` or `shiv` if desired.
- Provide a Docker image for CI/Server mode.

---

## Roadmap & Milestones (2–3 week plan)

**Week 1** – MVP
- CLI runner, regex detector, entropy detector, basic scoring, JSON + CLI output, `--staged` flag, simple pre-commit hook, README

**Week 2** – Usability
- Config support, allowlist, SARIF output, Markdown reporter, packaging (pip), tests

**Week 3** – Polish
- Optional server mode, ML optional classifier, HTML report, sample GitHub Actions integration, project website

---

## Example repository layout

```
secret-sentinel/
  README.md
  pyproject.toml
  src/secret_sentinel/
    __main__.py
    runner.py
    detectors/
      regex.py
      entropy.py
      keywords.py
    scoring.py
    reporters/
      json_reporter.py
      sarif_reporter.py
      md_reporter.py
    precommit.py
    config.py
  tests/
    fixtures/
    test_regex.py
    test_entropy.py
```

---

## Quick Appendix: Shannon Entropy (token)

Shannon entropy of a token `s`:

```
H(s) = - sum(p_i * log2(p_i))  over each unique symbol i in s
```

Normalized by token length or used raw. Typical thresholds:
- length < 8: ignore
- length 8–15: entropy > 3.5
- length >=16: entropy > 3.8–4.5

Tune thresholds empirically on your test corpus.

---

## Final Notes
- Emphasize **prevention** and **developer UX**: clear messages, quick fixes, configurability.
- Aim for a small, high-impact codebase — a focused MVP will be more persuasive on GitHub than a sprawling product.

---

If you want, I can now:
- Generate the starter `pyproject.toml` + minimal CLI scaffold, or
- Create the `regex` + `entropy` detector implementations (with unit tests), or
- Draft the `README.md` with badges, demo, and usage examples.

Which one should I build next?

