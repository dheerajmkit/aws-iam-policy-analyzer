"""Unit tests for the IAM policy checks and unused-permission analysis.

Run from the project root:  python3 -m unittest discover -s tests -v
"""

import json
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from iam.checks import check_statement, check_policy
from iam.usage import load_usage, check_unused


def stmt(**overrides):
    base = {"sid": "T1", "effect": "Allow", "actions": [],
            "not_actions": [], "resources": [], "not_resources": [],
            "conditions": {}}
    base.update(overrides)
    return base


class TestChecks(unittest.TestCase):
    def test_admin_wildcard_is_critical(self):
        findings = check_statement(stmt(actions=["*"], resources=["*"]))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "CRITICAL")
        self.assertEqual(findings[0]["check"], "admin-wildcard")

    def test_deny_statement_is_ignored(self):
        findings = check_statement(
            stmt(effect="Deny", actions=["*"], resources=["*"]))
        self.assertEqual(findings, [])

    def test_service_wildcard_is_high(self):
        findings = check_statement(
            stmt(actions=["s3:*"], resources=["arn:aws:s3:::b/*"]))
        self.assertTrue(any(f["check"] == "wildcard-action"
                            and f["severity"] == "HIGH" for f in findings))

    def test_readonly_describe_with_star_resource_is_clean(self):
        findings = check_statement(
            stmt(actions=["ec2:DescribeInstances"], resources=["*"]))
        self.assertEqual(findings, [])

    def test_passrole_star_is_high(self):
        findings = check_statement(
            stmt(actions=["iam:PassRole"], resources=["*"]))
        self.assertTrue(any(f["check"] == "wildcard-resource"
                            and f["severity"] == "HIGH" for f in findings))

    def test_least_privilege_is_clean(self):
        findings = check_statement(stmt(
            actions=["s3:GetObject"],
            resources=["arn:aws:s3:::acme-reports/*"]))
        self.assertEqual(findings, [])


class TestUnused(unittest.TestCase):
    def test_never_used_is_medium(self):
        policy = {"Statement": [{"Sid": "A", "Effect": "Allow",
                                  "Action": "iam:PassRole", "Resource": "*"}]}
        findings = check_unused(policy, {"iam:PassRole": None})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["severity"], "MEDIUM")

    def test_unused_90_days_is_high(self):
        policy = {"Statement": [{"Sid": "A", "Effect": "Allow",
                                  "Action": "kms:Decrypt", "Resource": "*"}]}
        findings = check_unused(policy, {"kms:Decrypt": 120})
        self.assertEqual(findings[0]["severity"], "HIGH")

    def test_recently_used_is_clean(self):
        policy = {"Statement": [{"Sid": "A", "Effect": "Allow",
                                  "Action": "s3:GetObject", "Resource": "*"}]}
        self.assertEqual(check_unused(policy, {"s3:GetObject": 2}), [])

    def test_load_usage_rejects_non_object(self):
        with tempfile.NamedTemporaryFile("w", suffix=".json",
                                         delete=False) as fh:
            json.dump(["not", "an", "object"], fh)
            path = fh.name
        try:
            with self.assertRaises(ValueError):
                load_usage(path)
        finally:
            os.unlink(path)


if __name__ == "__main__":
    unittest.main()
