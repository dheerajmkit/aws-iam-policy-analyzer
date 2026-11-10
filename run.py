#!/usr/bin/env python3
"""Scan AWS IAM policy JSON for over-privileged grants.

Usage:
    python3 run.py <policy.json> [--json]

Exit codes: 2 = usage error / unreadable policy,
            1 = at least one high or critical finding,
            0 = no high or critical findings.
"""

import argparse
import sys

from iam.policy import load_policy
from iam.checks import check_policy
from iam.report import summarize, render_text, render_json


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("policy", help="IAM policy JSON file")
    parser.add_argument("--json", action="store_true",
                        help="emit findings as JSON")
    args = parser.parse_args(argv)

    try:
        policies = load_policy(args.policy)
    except (OSError, ValueError) as exc:
        print(f"error: cannot load policy: {exc}", file=sys.stderr)
        return 2

    all_findings = []
    for policy in policies:
        all_findings.extend(check_policy(policy))

    if args.json:
        print(render_json(args.policy, all_findings))
    else:
        print(render_text(args.policy, all_findings))

    counts = summarize(all_findings)
    return 1 if (counts["CRITICAL"] or counts["HIGH"]) else 0


if __name__ == "__main__":
    sys.exit(main())
