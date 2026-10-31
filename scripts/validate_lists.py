#!/usr/bin/env python3
"""Validate the generated lists before CI commits them.

A second line of defence after generate.py's own checks, written against
the published file formats rather than the generator's code:

  - every generated file exists and is non-empty
  - .rsc and blocklist_ga*.rsc files contain only the expected lines
  - each .txt list's size is within absolute bounds
  - no list moved by more than its delta limit vs the last commit (HEAD)

Writes per-list entry counts to the GitHub step summary when
$GITHUB_STEP_SUMMARY is set. Prints ::error:: annotations and exits 1 on
any failure.

usage: python3 scripts/validate_lists.py [dir]
"""

import os
import re
import subprocess
import sys

# (name, .txt, .rsc, global-array .rsc, .json, min entries, max entries, max delta %)
LISTS = [
    ("Standard", "blocklist.txt", "blocklist.rsc", "blocklist_ga.rsc", "blocklist.json", 8000, 60000, 30),
    ("Large", "blocklist_l.txt", "blocklist_l.rsc", "blocklist_ga_l.rsc", "blocklist_l.json", 15000, 80000, 30),
    ("Extra Large", "blocklist_xl.txt", "blocklist_xl.rsc", "blocklist_ga_xl.rsc", "blocklist_xl.json", 40000, 150000, 30),
    # Tor exits churn faster.
    ("Tor exits", "tor_blocklist.txt", "tor_blocklist.rsc", "blocklist_ga_tor.rsc", "tor_blocklist.json", 200, 10000, 50),
]
STATE_FILE = "feed_state.json"

RSC_HEADER = "/ip firewall address-list"
RSC_LINE = re.compile(r'add list=new_blocklist address="[0-9./]+" comment="blocklist"')
GA_HEADER = ':global newips [:toarray ""]'
GA_LINE = re.compile(r':set newips \(\$newips,"[0-9./]+"\)')


def previous_count(name):
    """Line count of `name` at HEAD, or None if it isn't committed there."""
    r = subprocess.run(["git", "show", f"HEAD:{name}"], capture_output=True)
    return r.stdout.count(b"\n") if r.returncode == 0 else None


def check_shape(path, header, line_re):
    with open(path) as f:
        lines = f.read().splitlines()
    if not lines or lines[0] != header:
        return "header wrong"
    if any(not line_re.fullmatch(line) for line in lines[1:]):
        return "contains unexpected line(s)"
    return None


def validate(d=".", previous=previous_count, lists=LISTS):
    """Return (errors, rows); rows are (list name, entries, delta text)."""
    errors = []
    files = [STATE_FILE] + [f for row in lists for f in row[1:5]]
    missing = [f for f in files if not os.path.isfile(os.path.join(d, f)) or os.path.getsize(os.path.join(d, f)) == 0]
    errors += [f"{f} is missing or empty" for f in missing]

    rows = []
    for name, txt, rsc, ga, _json, lo, hi, max_delta in lists:
        if {txt, rsc, ga} & set(missing):
            continue
        for path, header, line_re in ((rsc, RSC_HEADER, RSC_LINE), (ga, GA_HEADER, GA_LINE)):
            problem = check_shape(os.path.join(d, path), header, line_re)
            if problem:
                errors.append(f"{path} {problem}")
        with open(os.path.join(d, txt), "rb") as f:
            n = f.read().count(b"\n")
        if not lo <= n <= hi:
            errors.append(f"{name} out of range ({n}, expected {lo}..{hi})")
        delta = "new"
        old = previous(txt)
        if old:
            pct = int(abs(n - old) / old * 100 + 0.5)
            delta = f"{old} -> {n} ({pct}%)"
            if pct > max_delta:
                errors.append(f"{txt} delta {pct}% exceeds {max_delta}% threshold")
        rows.append((name, n, delta))
    return errors, rows


def main():
    errors, rows = validate(sys.argv[1] if len(sys.argv) > 1 else ".")
    for name, n, delta in rows:
        print(f"  {name}: {n} entries ({delta})")
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a") as f:
            f.write("# Blocklist regeneration\n\n| List | Entries | vs last commit |\n|---|---|---|\n")
            f.writelines(f"| {name} | {n} | {delta} |\n" for name, n, delta in rows)
    for e in errors:
        print(f"::error::{e}")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
