"""Findings summaries and rendering."""

import json

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def summarize(findings):
    """Count findings by severity."""
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in findings:
        counts[f["severity"]] = counts.get(f["severity"], 0) + 1
    return counts


def render_text(policy_name, findings):
    """Render findings as plain text, most severe first."""
    lines = [f"policy: {policy_name} — {len(findings)} finding(s)"]
    ordered = sorted(findings, key=lambda f: SEVERITY_ORDER[f["severity"]])
    for f in ordered:
        lines.append(
            f"[{f['severity']}] {f['check']} ({f['sid']}): {f['message']}")
    return "\n".join(lines)


def render_json(policy_name, findings):
    """Render findings as JSON."""
    return json.dumps({
        "policy": policy_name,
        "counts": summarize(findings),
        "findings": findings,
    }, indent=2)
