#!/usr/bin/env python3
"""Fail if any tracked file (or, with --history, any commit) contains a
credential-shaped literal. Mirrors what GitHub push protection and common
secret scanners flag, so fixtures never block a push or alarm a customer's
scanner. Detector test vectors must use the `b64:` form instead.

Usage: tests/secrets/scan.py [--history]
"""
import re, subprocess, sys

PATTERNS = {
    "aws_access_key_id": re.compile(r"\b(?:AKIA|ASIA|AIDA|AROA)[A-Z0-9]{16}\b"),
    "aws_secret_like": re.compile(r"(?<![A-Za-z0-9/+])(?=[A-Za-z0-9/+]*[a-z])(?=[A-Za-z0-9/+]*[A-Z])(?=[A-Za-z0-9/+]*[0-9])[A-Za-z0-9/+]{40}(?![A-Za-z0-9/+=])"),
    "jwt": re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}"),
    "github_token": re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{60,})\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}"),
    "private_key_block": re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    "url_with_password": re.compile(r"\b(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqps?|mssql)://[^\s:@/\"']+:[^\s@/\"']+@"),
}
# A bare 40-char mixed string is only an AWS secret candidate with AWS context on
# the same line (same rule as GitHub push protection and our own detector).
AWS_CONTEXT = re.compile(r"(?i)aws|secret_?access|secretaccesskey")
SKIP = re.compile(r"(^|/)(Cargo\.lock|go\.sum)$")

def git(*args):
    return subprocess.run(["git", *args], check=True, capture_output=True, text=True).stdout

def scan_blob(label, text):
    found = []
    for n, line in enumerate(text.splitlines(), 1):
        for name, rx in PATTERNS.items():
            if rx.search(line):
                if name == "aws_secret_like" and not AWS_CONTEXT.search(line):
                    continue
                found.append(f"{label}:{n}: {name}")
    return found

def scan_rev(rev):
    found = []
    for path in git("ls-tree", "-r", "--name-only", rev).splitlines():
        if SKIP.search(path):
            continue
        try:
            text = git("show", f"{rev}:{path}")
        except (subprocess.CalledProcessError, UnicodeDecodeError):
            continue  # binary
        found += scan_blob(f"{rev[:8]}:{path}", text)
    return found

def main():
    revs = git("rev-list", "HEAD").split() if "--history" in sys.argv else ["HEAD"]
    found = [f for r in revs for f in scan_rev(r)]
    if found:
        print("credential-shaped literals found (use b64: vectors or assemble from parts):")
        print("\n".join(found))
        return 1
    print(f"secret-shape scan clean ({len(revs)} commit(s))")
    return 0

if __name__ == "__main__":
    sys.exit(main())
