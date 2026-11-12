#!/bin/sh
# Scan both sample policies, with and without usage data.
set -e
cd "$(dirname "$0")/.."
python3 run.py samples/good-policy.json
python3 run.py samples/bad-policy.json --usage samples/access-advisor.json || true
python3 -m unittest discover -s tests -v
