# appsec-guardrails

Custom Semgrep rules and a GitHub Actions pipeline that moves a repository from
**report-only scanning** to **merge-blocking checks** without flooding developers
with false positives.

## What's here

| Path | What it is |
|---|---|
| `rules/python/*.yaml` | Custom Semgrep rules: SSRF, SQL injection, insecure deserialization, JWT auth bypass |
| `rules/python/*.py` | Rule tests: `# ruleid:` lines must match, `# ok:` lines must not |
| `demo-app/` | A deliberately vulnerable Flask app for the rules to find. **Do not deploy.** |
| `.github/workflows/appsec.yml` | The pipeline |

## How the pipeline works

1. **Rule tests first.** Rules are code. Every rule ships with true-positive and
   true-negative test cases, and CI fails if a rule change breaks them.
2. **Report everything, block little.** The full scan goes to GitHub Code Scanning
   as SARIF, so the existing backlog is visible but does not break builds.
3. **Block only new, high-confidence findings.** On pull requests, Semgrep runs
   with `--baseline-commit`, so only issues *introduced by that PR* count, and only
   `ERROR` severity (high-confidence rules) fails the check. `WARNING` rules such as
   `pickle-loads` stay advisory until their false-positive rate is known.
4. **Supply chain.** `pip-audit` checks dependencies against known CVEs and the
   job publishes a CycloneDX SBOM as a build artifact.

## Design notes

- **Taint mode** for SSRF and SQLi: a finding needs a real path from
  `flask.request` to the sink, which cuts the false positives a plain pattern match
  would produce (for example, a hard-coded URL passed to `requests.get`).
- **Sanitizers** (`validate_url`) model the fix, so code that follows the
  guidance stops being flagged.
- **Severity = gate.** A rule is promoted from `WARNING` to `ERROR` only once it
  has been tested against real code and its false-positive rate is acceptable.

## Run locally

```bash
pip install semgrep pip-audit
semgrep --test rules/
semgrep scan --config rules/ --exclude rules demo-app/
pip-audit -r demo-app/requirements.txt --no-deps --disable-pip
```
