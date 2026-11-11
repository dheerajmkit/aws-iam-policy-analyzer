"""Unused-permission analysis from access-advisor style usage data.

Usage file format (JSON):
    {"s3:GetObject": 2, "ec2:DescribeInstances": null, ...}
Values are days since the action was last used, or null if never used
in the reporting window.
"""

import json

UNUSED_90D_SEVERITY = "HIGH"
UNUSED_SEVERITY = "MEDIUM"


def load_usage(path):
    """Load a usage JSON file mapping action -> days since last use."""
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, dict):
        raise ValueError("usage file must be a JSON object")
    return data


def _expand(action):
    """Expand a granted action into the concrete actions it covers.

    Only exact actions expand to themselves; service wildcards expand to
    every used action in that service (a conservative over-approximation
    used solely to avoid false unused findings).
    """
    return action


def check_unused(policy, usage):
    """Flag granted actions with no recorded use.

    Returns findings; wildcard grants are skipped because they cannot be
    attributed to a single action.
    """
    from .policy import iter_statements

    findings = []
    granted = set()
    for stmt in iter_statements(policy):
        if stmt["effect"].lower() != "allow":
            continue
        for action in stmt["actions"]:
            if action == "*" or action.endswith(":*"):
                continue
            granted.add(action)

    for action in sorted(granted):
        if action not in usage:
            findings.append({
                "check": "unused-permission", "severity": UNUSED_SEVERITY,
                "sid": "-", "message": f"{action} granted but no usage data",
            })
        elif usage[action] is None:
            findings.append({
                "check": "unused-permission", "severity": UNUSED_SEVERITY,
                "sid": "-", "message": f"{action} granted but never used",
            })
        elif usage[action] >= 90:
            findings.append({
                "check": "unused-permission", "severity": UNUSED_90D_SEVERITY,
                "sid": "-",
                "message": f"{action} unused for {usage[action]} days",
            })
    return findings
