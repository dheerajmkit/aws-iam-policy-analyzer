# aws-iam-policy-analyzer

Scans AWS IAM policy JSON for over-privileged grants: wildcard actions,
wildcard resources, admin (`*`) access, `iam:PassRole` with broad scope,
and sensitive actions without conditions. Policies are scored by severity
so the riskiest grants surface first.

This is a **personal portfolio project** exploring IAM least-privilege
analysis and security automation. It is a learning exercise, not a
production tool, and it has never been deployed at any employer.

## Quickstart

No dependencies to install — the standard library is all you need:

```bash
python3 run.py samples/bad-policy.json
python3 run.py samples/good-policy.json
```

Exit codes: `2` = usage error or unreadable policy, `1` = at least one
high or critical finding, `0` = no high or critical findings.

## Day-1 scope

- Policy loading: JSON files with `Statement` lists (single policy or a
  list of policies).
- Checks: admin wildcard, service wildcards (`s3:*`), wildcard resources
  on sensitive actions, `iam:PassRole` with `*`, `NotAction` use, and
  write actions scoped to `*` without conditions.
- Text and JSON (`--json`) findings reports with severity counts.

## Sample output

```
policy: samples/bad-policy.json — 4 finding(s)
[CRITICAL] admin-wildcard (S1): Action "*" grants full admin
[HIGH] wildcard-resource (S2): iam:PassRole with Resource "*"
[HIGH] wildcard-action (S3): service wildcard "s3:*"
[MEDIUM] broad-resource (S3): write action scoped to Resource "*"
```
