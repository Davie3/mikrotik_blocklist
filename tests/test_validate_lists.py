"""Tests for scripts/validate_lists.py."""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "scripts"))

import validate_lists as v  # noqa: E402

# One small list with tiny bounds, so fixtures stay short.
LISTS = [("Tiny", "t.txt", "t.rsc", "t_ga.rsc", "t.json", 2, 5, 30)]
ENTRIES = ["1.2.3.4", "5.6.7.0/24", "8.8.8.8"]


class TestValidate(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.d = self.tmp.name
        self.write("t.txt", "".join(f"{a}\n" for a in ENTRIES))
        self.write("t.rsc", v.RSC_HEADER + "\n" + "".join(f'add list=new_blocklist address="{a}" comment="blocklist"\n' for a in ENTRIES))
        self.write("t_ga.rsc", v.GA_HEADER + "\n" + "".join(f':set newips ($newips,"{a}")\n' for a in ENTRIES))
        self.write("t.json", "{}")
        self.write(v.STATE_FILE, "{}\n")

    def write(self, name, text):
        with open(os.path.join(self.d, name), "w") as f:
            f.write(text)

    def run_validate(self, previous=lambda name: None):
        return v.validate(self.d, previous=previous, lists=LISTS)

    def test_valid(self):
        errors, rows = self.run_validate(previous=lambda name: 3)
        self.assertEqual(errors, [])
        self.assertEqual(rows, [("Tiny", 3, "3 -> 3 (0%)")])

    def test_first_run_has_no_delta(self):
        self.assertEqual(self.run_validate(), ([], [("Tiny", 3, "new")]))

    def test_missing_or_empty_file(self):
        os.remove(os.path.join(self.d, "t.json"))
        self.write(v.STATE_FILE, "")
        errors, _ = self.run_validate()
        self.assertEqual(sorted(errors), ["feed_state.json is missing or empty", "t.json is missing or empty"])

    def test_rsc_shape(self):
        self.write("t.rsc", v.RSC_HEADER + '\n/user add name=x\nadd list=new_blocklist address="1.2.3.4" comment="blocklist"\n')
        self.write("t_ga.rsc", ":global wrong\n")
        errors, _ = self.run_validate()
        self.assertEqual(errors, ["t.rsc contains unexpected line(s)", "t_ga.rsc header wrong"])

    def test_bounds(self):
        self.write("t.txt", "1.2.3.4\n")
        errors, _ = self.run_validate()
        self.assertEqual(errors, ["Tiny out of range (1, expected 2..5)"])

    def test_delta(self):
        errors, _ = self.run_validate(previous=lambda name: 2)  # 2 -> 3 is +50%
        self.assertEqual(errors, ["t.txt delta 50% exceeds 30% threshold"])


if __name__ == "__main__":
    unittest.main()
