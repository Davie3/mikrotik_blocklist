#!/usr/bin/env python3
"""Validate the generated lists before CI commits them.

A second line of defence after generate.py's own checks. The list file
names come from generate.LISTS, so a new list can't go unchecked; the
format rules and size bounds are defined here, independently of the
generator's code:

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

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import generate  # noqa: E402

# Per list (by generate.LISTS base name): display name, min entries,
# max entries, max delta % vs the last commit.
BOUNDS = {
    "blocklist": ("Standard", 8000, 60000, 30),
    "blocklist_l": ("Large", 15000, 80000, 30),
    "blocklist_xl": ("Extra Large", 40000, 150000, 30),
    "tor_blocklist": ("Tor exits", 200, 10000, 50),  # Tor exits churn faster
}
STATE_FILE = generate.STATE_FILE

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


def generator_lists(gen_lists=None, bounds=None):
    """(name, .txt, .rsc, global-array .rsc, .json, min, max, max delta %) for
    every list generate.py writes. Raises ValueError for a list without bounds."""
    gen_lists = generate.LISTS if gen_lists is None else gen_lists
    bounds = BOUNDS if bounds is None else bounds
    out = []
    for base, _tiers, ga in gen_lists:
        if base not in bounds:
            raise ValueError(f"no bounds configured for {base} in validate_lists.py")
        name, lo, hi, max_delta = bounds[base]
        out.append((name, f"{base}.txt", f"{base}.rsc", ga, f"{base}.json", lo, hi, max_delta))
    return out


def validate(d=".", previous=previous_count, lists=None):
    """Return (errors, rows); rows are (list name, entries, delta text)."""
    if lists is None:
        try:
            lists = generator_lists()
        except ValueError as exc:
            return [str(exc)], []
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
