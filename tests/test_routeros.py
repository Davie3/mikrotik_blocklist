"""Consistency checks for the RouterOS scripts in routeros/.

They only run on the router, so this checks what the scripts expect of
each other and of the published lists.
"""

import os
import re
import sys
import unittest

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..")
sys.path.insert(0, ROOT)

import generate as g  # noqa: E402

NOTICE = "# Required Notice: Copyright 2021-2026 multiduplikator (https://gitlab.com/multiduplikator-group/mikrotik_blocklist)"


def read(name):
    with open(os.path.join(ROOT, "routeros", name)) as f:
        return f.read()


def local(src, name):
    m = re.search(rf'^:local {name} "([^"]*)"$', src, re.M)
    return m.group(1) if m else None


class TestRouterOS(unittest.TestCase):
    def setUp(self):
        self.update = read("blocklist-update.rsc")

    def test_update_fetches_a_published_list(self):
        url, file = local(self.update, "url"), local(self.update, "file")
        self.assertIn(file.removesuffix(".json"), [base for base, _, _ in g.LISTS])
        self.assertEqual(url, f"https://raw.githubusercontent.com/Davie3/mikrotik_blocklist/main/{file}")

    def test_update_block_size_matches_generator(self):
        self.assertEqual(f":local block {g.JSON_BLOCK}", re.search(r"^:local block \d+$", self.update, re.M).group(0))

    def test_selftest_can_redirect_the_update(self):
        # selftest.rsc swaps these quoted names for scratch ones and refuses
        # to run if prod_blocklist is still mentioned anywhere afterwards.
        self.assertEqual(self.update.count('"prod_blocklist"'), 1)
        self.assertEqual(self.update.count("prod_blocklist"), 1)
        self.assertIn(f'"{local(self.update, "file")}"', read("selftest.rsc"))

    def test_install_does_not_mistake_the_update_for_the_old_setup(self):
        # install.rsc reads the update script in one 32 KB /file read and
        # treats scripts mentioning these as the old .rsc setup.
        self.assertLessEqual(len(self.update.encode()), 32768)
        self.assertNotIn("blocklist_ga", self.update)
        self.assertNotIn("newips", self.update)
        self.assertEqual(local(self.update, "listName"), "prod_blocklist")

    def test_adapted_files_carry_the_license_notice(self):
        for name in ("blocklist-update.rsc", "selftest.rsc"):
            head = read(name).splitlines()[:3]
            self.assertEqual(head[0], "# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0", name)
            self.assertEqual(head[1], NOTICE, name)


if __name__ == "__main__":
    unittest.main()
