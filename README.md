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
python3 run.py samples/bad-policy.json --usage samples/access-advisor.json
```

Exit codes: `2` = usage error or unreadable policy, `1` = at least one
high or critical finding, `0` = no high or critical findings.

## Day-3 scope

- Unit tests (`tests/test_checks.py`): run with
  `python3 -m unittest discover -s tests -v`.
- Full usage guide (`docs/USAGE.md`) and a demo script
  (`examples/run-all.sh`).

## Day-2 scope

- Unused-permission analysis (`--usage`): compares granted actions
  against access-advisor style usage data (days since last use, or
  never used). Actions unused for 90+ days are HIGH; never-used or
  undocumented grants are MEDIUM. Wildcard grants are skipped — they
  cannot be attributed to a single action.

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
