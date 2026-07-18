#!/usr/bin/env python3
"""Runs Parliament and Cloudsplaining against a single IAM policy JSON file,
printing {"parliament": N, "cloudsplaining": N} finding counts as JSON.

Called by run.js — kept separate because both tools are Python; run.js stays
Node so @shieldly/iam-lint (JS) can be imported directly, in-process.
"""
import json
import subprocess
import sys

from parliament import analyze_policy_string


def parliament_count(path):
    with open(path) as f:
        policy_str = f.read()
    result = analyze_policy_string(policy_str, include_community_auditors=True)
    return len(result.findings)


def cloudsplaining_count(path):
    proc = subprocess.run(
        ["cloudsplaining", "scan-policy-file", "--input-file", path],
        capture_output=True,
        text=True,
        check=False,
    )
    return proc.stdout.count("Potential Issue found")


if __name__ == "__main__":
    policy_path = sys.argv[1]
    print(
        json.dumps(
            {
                "parliament": parliament_count(policy_path),
                "cloudsplaining": cloudsplaining_count(policy_path),
            }
        )
    )
