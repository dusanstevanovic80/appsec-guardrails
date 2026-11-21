#!/usr/bin/env python3
"""Flatten Semgrep SARIF into a compact findings list for triage.

Usage: sarif_findings.py FULL_SARIF NEW_SARIF OUT_JSON

FULL_SARIF is the full scan of the PR's code; NEW_SARIF is the --baseline-commit
scan (findings introduced by the PR). Writes OUT_JSON and prints
`count=` / `new=` lines for $GITHUB_OUTPUT.
"""
import json
import sys

SEVERITY = {"error": "ERROR", "warning": "WARNING", "note": "INFO", "none": "INFO"}
SNIPPET_LIMIT = 300


def load_run(path):
    try:
        with open(path, encoding="utf-8") as fh:
            runs = json.load(fh).get("runs") or [{}]
    except FileNotFoundError:
        return {}
    return runs[0]


def key(result):
    loc = result["locations"][0]["physicalLocation"]
    region = loc.get("region", {})
    return (
        result.get("ruleId"),
        loc["artifactLocation"]["uri"],
        region.get("startLine"),
        region.get("startColumn"),
    )


def main(full_path, new_path, out_path):
    full = load_run(full_path)
    if not full:
        sys.exit(f"missing or empty SARIF: {full_path}")
    new_keys = {key(r) for r in load_run(new_path).get("results", [])}
    rules = {r["id"]: r for r in full.get("tool", {}).get("driver", {}).get("rules", [])}

    findings = []
    for result in full.get("results", []):
        rule = rules.get(result.get("ruleId"), {})
        loc = result["locations"][0]["physicalLocation"]
        region = loc.get("region", {})
        tags = rule.get("properties", {}).get("tags", [])
        level = result.get("level") or rule.get("defaultConfiguration", {}).get("level", "warning")
        snippet = region.get("snippet", {}).get("text", "").strip()
        findings.append({
            "rule_id": result.get("ruleId", "").rsplit(".", 1)[-1],
            "severity": SEVERITY.get(level, level.upper()),
            "cwe": next((t for t in tags if t.startswith("CWE-")), ""),
            "message": result.get("message", {}).get("text", ""),
            "path": loc["artifactLocation"]["uri"],
            "line": region.get("startLine"),
            "snippet": snippet[:SNIPPET_LIMIT],
            "new_in_pr": key(result) in new_keys,
        })

    # Stable default order: new first, then severity, then location.
    order = {"ERROR": 0, "WARNING": 1, "INFO": 2}
    findings.sort(key=lambda f: (not f["new_in_pr"], order.get(f["severity"], 3), f["path"], f["line"] or 0))
    for i, finding in enumerate(findings, 1):
        finding["id"] = f"F{i}"

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(findings, fh, indent=1)
    print(f"count={len(findings)}")
    print(f"new={sum(f['new_in_pr'] for f in findings)}")


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(__doc__)
    main(*sys.argv[1:])
