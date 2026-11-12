# Usage

## Scanning a policy

```bash
python3 run.py policy.json
python3 run.py policy.json --json        # machine-readable output
```

A policy file may hold a single policy document or a list of them.
Exit code `1` means at least one HIGH or CRITICAL finding; `0` means
none; `2` means the file could not be read or parsed.

## Unused-permission analysis

Pass an access-advisor style usage file (JSON object mapping action to
days since last use, or `null` for never used):

```bash
python3 run.py policy.json --usage access-advisor.json
```

Findings:

| Check | Severity | Meaning |
|---|---|---|
| admin-wildcard | CRITICAL | `Action: "*"` — full admin |
| wildcard-action | HIGH | service wildcard such as `s3:*` |
| wildcard-resource | HIGH | sensitive action or `iam:PassRole` on `Resource: "*"` |
| unused-permission | HIGH | granted action unused for 90+ days |
| broad-resource | MEDIUM | write action scoped to `Resource: "*"` |
| not-action | MEDIUM | `NotAction` allow-lists everything else |
| unconditioned-sensitive | MEDIUM | sensitive action with no `Condition` |
| unused-permission | MEDIUM | granted but never used / no usage data |

Wildcard grants are skipped by the usage analysis — they cannot be
attributed to a single action.

## Running the tests

```bash
python3 -m unittest discover -s tests -v
```
