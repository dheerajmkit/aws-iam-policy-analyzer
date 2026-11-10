"""Over-privilege checks for normalized IAM policy statements."""

# Actions where a wildcard resource is especially dangerous.
SENSITIVE_PREFIXES = ("iam:", "kms:", "secretsmanager:", "sts:",
                      "organizations:", "sso:", "identitystore:")

# Actions that should never be granted without a Condition.
CONDITION_WORTHY = ("iam:PassRole", "iam:CreateUser", "iam:AttachRolePolicy",
                    "kms:Decrypt", "secretsmanager:GetSecretValue",
                    "sts:AssumeRole")


def _is_wildcard(value):
    return value == "*" or value.endswith(":*")


def _is_admin(actions):
    return "*" in actions


def _has_sensitive_action(actions):
    return any(a.lower().startswith(SENSITIVE_PREFIXES) for a in actions)


def check_statement(stmt):
    """Return findings (list of dicts) for one normalized statement."""
    findings = []
    sid = stmt["sid"]
    if stmt["effect"].lower() != "allow":
        return findings  # Deny statements do not grant privilege.

    actions = stmt["actions"]
    resources = stmt["resources"]

    if _is_admin(actions):
        findings.append({
            "check": "admin-wildcard", "severity": "CRITICAL", "sid": sid,
            "message": 'Action "*" grants full admin',
        })
        return findings  # Nothing else to say about a full-admin statement.

    for action in actions:
        if action.endswith(":*"):
            findings.append({
                "check": "wildcard-action", "severity": "HIGH", "sid": sid,
                "message": f'service wildcard "{action}"',
            })

    if "*" in resources:
        if "iam:PassRole" in actions:
            findings.append({
                "check": "wildcard-resource", "severity": "HIGH", "sid": sid,
                "message": 'iam:PassRole with Resource "*"',
            })
        elif _has_sensitive_action(actions):
            findings.append({
                "check": "wildcard-resource", "severity": "HIGH", "sid": sid,
                "message": "sensitive action scoped to Resource \"*\"",
            })
        elif any(":" in a for a in actions
                  if not a.split(":", 1)[1].startswith(
                      ("Get", "List", "Describe", "Head"))):
            findings.append({
                "check": "broad-resource", "severity": "MEDIUM", "sid": sid,
                "message": 'write action scoped to Resource "*"',
            })

    if stmt["not_actions"]:
        findings.append({
            "check": "not-action", "severity": "MEDIUM", "sid": sid,
            "message": "NotAction allow-lists everything except the named actions",
        })

    if not stmt["conditions"]:
        for action in actions:
            if action in CONDITION_WORTHY and "*" in resources:
                findings.append({
                    "check": "unconditioned-sensitive", "severity": "MEDIUM",
                    "sid": sid,
                    "message": f"{action} granted without any Condition",
                })
                break

    return findings


def check_policy(policy):
    """Return all findings for one policy document."""
    from .policy import iter_statements

    findings = []
    for stmt in iter_statements(policy):
        findings.extend(check_statement(stmt))
    return findings
