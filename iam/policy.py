"""Load and normalize AWS IAM policy documents."""

import json


def load_policy(path):
    """Load a policy JSON file.

    Accepts a single policy document (``{"Version": ..., "Statement": [...]}``)
    or a list of policy documents. Returns a list of policy dicts.
    """
    with open(path, encoding="utf-8") as fh:
        data = json.load(fh)
    if isinstance(data, dict):
        return [data]
    if isinstance(data, list):
        return data
    raise ValueError("policy file must contain a policy object or a list of them")


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    return list(value)


def iter_statements(policy):
    """Yield normalized statements from one policy document.

    Each yielded statement is a dict with keys: sid, effect, actions,
    not_actions, resources, not_resources, conditions.
    """
    for idx, stmt in enumerate(policy.get("Statement", [])):
        yield {
            "sid": stmt.get("Sid") or f"S{idx + 1}",
            "effect": str(stmt.get("Effect", "Allow")),
            "actions": _as_list(stmt.get("Action")),
            "not_actions": _as_list(stmt.get("NotAction")),
            "resources": _as_list(stmt.get("Resource")),
            "not_resources": _as_list(stmt.get("NotResource")),
            "conditions": stmt.get("Condition") or {},
        }
