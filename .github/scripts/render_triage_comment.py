#!/usr/bin/env python3
"""Render the PR comment from findings.json plus Claude's ranking.

Usage: render_triage_comment.py FINDINGS_JSON > comment.md

Environment:
  RANKING         Claude's structured output (JSON), may be empty
  CLAUDE_OUTCOME  outcome of the Claude step: success | failure | skipped
  HAS_KEY         "true" when the ANTHROPIC_API_KEY secret is set
  CLAUDE_MODEL    model name for the footer
  HEAD_SHA        PR head commit for the footer

Facts (rule, severity, location, new/existing) always come from the SARIF.
Claude supplies only the order, exploitability rating, rationale and fix, and
that text is sanitized: no HTML, links, images or @-mentions reach the comment.
"""
import json
import os
import re
import sys

MARKER = "<!-- appsec-guardrails:claude-triage -->"
LEVELS = {
    "critical": "🔴 Critical",
    "high": "🟠 High",
    "medium": "🟡 Medium",
    "low": "🔵 Low",
    "not_exploitable": "⚪ Not exploitable",
}


def clean(text, limit=600):
    """Make model-written text inert: plain prose only."""
    text = str(text or "")
    text = re.sub(r"<[^>]*>", "", text)                    # HTML / comments
    text = re.sub(r"!\[[^\]]*\]\([^)]*\)", "", text)       # images
    text = re.sub(r"\[([^\]]*)\]\([^)]*\)", r"\1", text)   # links -> text
    text = re.sub(r"https?://\S+", lambda m: "`" + m.group(0).replace("`", "") + "`", text)
    text = re.sub(r"@(?=[A-Za-z0-9_-])", "@​", text)  # no mentions
    text = " ".join(text.split())
    return text if len(text) <= limit else text[: limit - 1] + "…"


def cell(text):
    return text.replace("|", "\\|")


def load_ranking(findings):
    """Return ([(finding, entry)], overview); entry is None for unranked."""
    by_id = {f["id"]: f for f in findings}
    try:
        data = json.loads(os.environ.get("RANKING") or "null")
    except json.JSONDecodeError:
        data = None
    if not isinstance(data, dict) or not isinstance(data.get("ranking"), list):
        return None, ""
    ordered, seen = [], set()
    for entry in data["ranking"]:
        fid = entry.get("id") if isinstance(entry, dict) else None
        if fid in by_id and fid not in seen and entry.get("exploitability") in LEVELS:
            ordered.append((by_id[fid], entry))
            seen.add(fid)
    ordered += [(f, None) for f in findings if f["id"] not in seen]
    return ordered, clean(data.get("overview"), 800)


def main(findings_path):
    with open(findings_path, encoding="utf-8") as fh:
        findings = json.load(fh)
    total, new = len(findings), sum(f["new_in_pr"] for f in findings)
    model = os.environ.get("CLAUDE_MODEL", "Claude")
    sha = (os.environ.get("HEAD_SHA") or "")[:7]

    out = [MARKER, "### Semgrep findings ranked by exploitability", ""]
    was_ranked = False
    if not findings:
        out += ["✅ No Semgrep findings in this pull request's code.", ""]
    else:
        out += [f"**{new} new in this PR** · {total - new} already on the base branch · {total} total", ""]
        ranked, overview = load_ranking(findings)
        if ranked is None:
            if os.environ.get("HAS_KEY") != "true":
                why = "the `ANTHROPIC_API_KEY` repository secret is not set"
            elif os.environ.get("CLAUDE_OUTCOME") == "failure":
                why = "the Claude step failed (see the `triage` job log)"
            else:
                why = "Claude returned no usable ranking"
            out += [f"> ⚠️ Exploitability ranking unavailable: {why}. "
                    "Listed by severity, new findings first.", ""]
            ranked = [(f, None) for f in findings]
        elif overview:
            out += [f"> {overview}", ""]

        out += ["| # | Exploitability | Rule | Severity | Location | |",
                "|---|---|---|---|---|---|"]
        for i, (f, entry) in enumerate(ranked, 1):
            level = LEVELS[entry["exploitability"]] if entry else "—"
            out.append(f"| {i} | {level} | `{cell(f['rule_id'])}` | {f['severity']} | "
                       f"`{cell(f['path'])}:{f['line']}` | {'🆕 new' if f['new_in_pr'] else ''} |")
        out.append("")

        details = [(i, f, e) for i, (f, e) in enumerate(ranked, 1) if e]
        was_ranked = bool(details)
        if details:
            out += ["<details><summary>Why each finding is ranked where it is, and how to fix it</summary>", ""]
            for i, f, e in details:
                out += [f"**{i}. `{f['rule_id']}` at `{f['path']}:{f['line']}`** · "
                        f"{LEVELS[e['exploitability']]}{' · 🆕 new' if f['new_in_pr'] else ''}",
                        "",
                        clean(e.get("rationale")),
                        "",
                        f"**Fix:** {clean(e.get('fix'), 400)}",
                        ""]
            out += ["</details>", ""]
        unranked = sum(1 for f, e in ranked if e is None)
        if details and unranked:
            out += [f"_{unranked} finding(s) were not ranked by Claude and are listed last._", ""]

    source = f"Ranked by {model} from the Semgrep SARIF." if was_ranked else "From the Semgrep SARIF."
    footer = f"{source} Advisory only: the `sast` check decides whether this PR can merge."
    if sha:
        footer += f" Updated for {sha}."
    out.append(f"<sub>{footer}</sub>")
    print("\n".join(out))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    main(sys.argv[1])
