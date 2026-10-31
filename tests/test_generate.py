"""Tests for generate.py. Run with: python3 -m unittest discover -s tests -v

Offline only: feeds are fixture files written to a temp directory and read
via the generator's offline mode.
"""

import datetime
import ipaddress
import json
import os
import random
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

import generate as g  # noqa: E402

T0 = datetime.datetime(2026, 10, 1, tzinfo=datetime.timezone.utc)


def net(cidr):
    n = ipaddress.ip_network(cidr)
    return int(n.network_address), int(n.broadcast_address)


def oracle(cidr_strings):
    """Minimal CIDR cover of the inputs, computed by the ipaddress module."""
    nets = ipaddress.collapse_addresses(ipaddress.IPv4Network(c, strict=False) for c in cidr_strings)
    return [str(n.network_address) if n.prefixlen == 32 else str(n) for n in nets]


class TestConfig(unittest.TestCase):
    def test_feeds_are_consistent(self):
        ids = [f.id for f in g.FEEDS]
        self.assertEqual(len(ids), len(set(ids)), "duplicate feed id")
        list_tiers = {t for _, tiers, _ in g.LISTS for t in tiers}
        feed_tiers = {f.tier for f in g.FEEDS}
        self.assertEqual(feed_tiers, list_tiers, "every feed tier used by a list, every list tier has feeds")
        for f in g.FEEDS:
            self.assertRegex(f.id, r"^[a-z0-9_]+$")
            self.assertGreaterEqual(f.min_ranges, 1, f.id)
            self.assertTrue(f.url.startswith("https://"), f.id)
        for t in g.REQUIRED_TIERS:
            self.assertIn(t, feed_tiers)


class TestExtract(unittest.TestCase):
    def test_addresses_and_cidrs(self):
        self.assertEqual(g.extract("1.2.3.4"), [net("1.2.3.4/32")])
        self.assertEqual(g.extract("x 8.8.8.8/24 ; comment"), [net("8.8.8.0/24")], "host bits cleared")
        self.assertEqual(g.extract("1.2.3.4,5.6.7.8"), [net("1.2.3.4/32"), net("5.6.7.8/32")])

    def test_invalid_skipped(self):
        self.assertEqual(g.extract("300.1.1.1 1.2.3.4/33 1.2.3.999"), [])

    def test_reserved_skipped(self):
        for a in (
            "0.1.2.3",
            "10.1.2.3",
            "100.64.0.1",
            "100.127.255.255",
            "127.0.0.1",
            "169.254.1.1",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "224.0.0.1",
            "240.0.0.1",
            "255.255.255.255",
        ):
            self.assertEqual(g.extract(a), [], a)

    def test_range_overlapping_reserved_skipped(self):
        self.assertEqual(g.extract("8.0.0.0/6"), [], "covers 10.0.0.0/8")
        self.assertEqual(g.extract("100.128.0.0/10"), [net("100.128.0.0/10")], "adjacent to CGNAT, kept")
        self.assertEqual(g.extract("172.32.0.1"), [net("172.32.0.1/32")])

    def test_whitelist_exact_host_only(self):
        self.assertEqual(g.extract("52.113.194.132 35.186.224.25/32"), [])
        self.assertEqual(g.extract("52.113.194.0/24"), [net("52.113.194.0/24")])


class TestDShield(unittest.TestCase):
    def test_rows_to_cidrs(self):
        text = "# header 1.1.1.1\n1.2.3.0\t1.2.3.255\t24\t42\n5.6.0.0\t5.6.1.255\t23\n"
        self.assertEqual(g.preprocess_dshield(text), "1.2.3.0/24\n5.6.0.0/23")

    def test_format_drift_drops_feed(self):
        text = "1.2.3.0\t1.2.3.255\t\n5.6.7.0\t5.6.7.255\t\n7.7.7.0\t7.7.7.255\tx\n9.9.9.0\t9.9.9.255\t24\n"
        self.assertIsNone(g.preprocess_dshield(text))


class TestBuild(unittest.TestCase):
    def test_cidrs_minimal(self):
        rnd = random.Random(1)
        for _ in range(500):
            s = rnd.randrange(1 << 24, 0xDFFFFFFF)
            e = min(s + rnd.randrange(1 << rnd.randrange(1, 20)), 0xDFFFFFFF)
            want = [
                str(n.network_address) if n.prefixlen == 32 else str(n)
                for n in ipaddress.summarize_address_range(ipaddress.IPv4Address(s), ipaddress.IPv4Address(e))
            ]
            self.assertEqual(g.cidrs(s, e), want, (s, e))

    def test_dedupe_overlap_adjacent(self):
        inputs = [
            "1.2.3.4",
            "1.2.3.4",
            "1.2.3.5",
            "1.2.3.6/31",
            "1.2.3.0/30",  # dup, adjacent, overlap
            "9.0.0.0/16",
            "9.0.1.2",
            "9.1.0.0/16",
            "8.8.8.8",
        ]
        ranges = [r for c in inputs for r in g.extract(c)]
        entries = g.build_entries(ranges)
        self.assertEqual(entries, oracle(inputs))
        self.assertEqual(entries, ["1.2.3.0/29", "8.8.8.8", "9.0.0.0/15"])

    def test_random_lists_minimal_and_disjoint(self):
        rnd = random.Random(2)
        inputs = [
            f"{rnd.randrange(1, 9)}.{rnd.randrange(256)}.{rnd.randrange(256)}.{rnd.randrange(256)}"
            f"/{rnd.choice([32, 32, 32, 30, 28, 24, 20])}"
            for _ in range(5000)
        ]
        entries = g.build_entries(r for c in inputs for r in g.extract(c))
        self.assertEqual(entries, oracle(inputs))
        self.assertEqual(len(entries), len(set(entries)))


class TestJson(unittest.TestCase):
    ENTRIES = ["1.2.3.4", "1.2.3.8/30", "1.2.9.1", "1.7.0.0/16", "5.6.7.8", "5.6.7.9", "5.9.0.1", "8.8.4.4", "8.8.8.8", "9.0.0.0/8"]

    def test_round_trip_multi_block(self):
        block = 56
        data = g.pack_json(self.ENTRIES, 1760000000, block)
        blocks = [data[i : i + block] for i in range(0, len(data), block)]
        self.assertGreater(len(blocks), 2)
        self.assertTrue(all(len(b) == block for b in blocks[:-1]), "every block but the last is padded")
        g.check_json(data, self.ENTRIES, block)
        decoded = {}
        for b in blocks:
            for o1, grp in json.loads(b).items():
                if o1 != "#":
                    decoded.setdefault(o1, {}).update(grp)
        self.assertEqual(sorted(f"{a}.{b}.{c}" for a, gs in decoded.items() for b, rs in gs.items() for c in rs), sorted(self.ENTRIES))
        first_octets_per_block = [[k for k in json.loads(b) if k != "#"] for b in blocks]
        continued = [o for i in range(1, len(blocks)) for o in first_octets_per_block[i][:1] if o in first_octets_per_block[i - 1]]
        self.assertTrue(continued, "fixture should make a first-octet object continue across blocks")

    def test_single_block_header(self):
        data = g.pack_json(self.ENTRIES, 1760000000)
        obj = json.loads(data)
        self.assertEqual(obj["#"], {"format": 1, "entries": len(self.ENTRIES), "generated": 1760000000})
        self.assertEqual(list(obj)[0], "#")

    def test_group_too_big(self):
        with self.assertRaisesRegex(ValueError, "group 1.2 does not fit"):
            g.pack_json([f"1.2.3.{i}" for i in range(1, 50)], 0, 100)

    def test_header_too_big(self):
        with self.assertRaisesRegex(ValueError, "header does not fit"):
            g.pack_json(self.ENTRIES, 1760000000, 40)

    def test_checker_rejects(self):
        entries = ["1.2.3.4", "1.2.3.5", "5.6.7.8"]
        hdr = '{"#":{"format":1,"entries":3,"generated":1}'
        good = (hdr + ',"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}}}').encode()
        g.check_json(good, entries, 4096)
        bad = {
            "repeated within one object": hdr + ',"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}},"5":{"9":{}}}',
            "split group": None,
            "value other than 1": hdr + ',"1":{"2":{"3.4":1,"3.5":2}},"5":{"6":{"7.8":1}}}',
            "not in the list": hdr + ',"1":{"2":{"3.4":1,"3.5":1,"3.6":1}},"5":{"6":{"7.8":1}}}',
            "header says": '{"#":{"format":1,"entries":4,"generated":1},"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}}}',
            "data after": hdr + ',"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}}} x',
            "header missing": '{"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}}}',
            "decoded 2": hdr + ',"1":{"2":{"3.4":1,"3.5":1}}}',
            "not a complete": hdr + ',"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}}',
            "does not start": " " + hdr + ',"1":{"2":{"3.4":1,"3.5":1}},"5":{"6":{"7.8":1}}}',
        }
        # A second-octet group split over two blocks: the router keeps only one half.
        b1 = (hdr + ',"1":{"2":{"3.4":1}}}').ljust(64)
        b2 = '{"1":{"2":{"3.5":1}},"5":{"6":{"7.8":1}}}'
        for reason, text in bad.items():
            data = (b1 + b2).encode() if text is None else text.encode()
            block = 64 if text is None else 4096
            with self.subTest(reason=reason):
                with self.assertRaisesRegex(ValueError, "appears in two places" if text is None else reason):
                    g.check_json(data, entries, block)


class TestRun(unittest.TestCase):
    """End-to-end runs in offline mode with small fixture feeds."""

    FEEDS = [
        g.Feed("s", "alpha", 3, "Alpha", "https://example.invalid/a"),
        g.Feed("s", "dshield", 1, "DShield", "https://example.invalid/d"),
        g.Feed("s", "gamma", 2, "Gamma", "https://example.invalid/g"),
        g.Feed("s", "delta", 2, "Delta", "https://example.invalid/x"),
        g.Feed("l", "large", 2, "Large", "https://example.invalid/l"),
        g.Feed("xl", "xlarge", 2, "XLarge", "https://example.invalid/xl"),
        g.Feed("tor", "tor", 2, "Tor", "https://example.invalid/t"),
    ]
    CONTENT = {
        "alpha": "# alpha\n1.2.3.4\n1.2.3.5\n1.2.3.6 ; dup below\n1.2.3.6\n10.0.0.1\n",
        "dshield": "# dshield\n20.0.0.0\t20.0.0.255\t24\n",
        "gamma": "30.0.0.1,c2\n30.0.0.2,c2\n52.113.194.132\n",
        "delta": "40.0.0.0/24\n40.0.1.0/24\n",
        "large": "50.0.0.1\n50.0.0.3\n1.2.3.4\n",
        "xlarge": "60.0.0.1\n60.0.0.2\n",
        "tor": "70.0.0.1\n70.0.0.2\n",
    }

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.feeds_dir = os.path.join(self.tmp.name, "feeds")
        self.out = os.path.join(self.tmp.name, "out")
        os.mkdir(self.feeds_dir)
        os.mkdir(self.out)
        self.state = os.path.join(self.out, "feed_state.json")
        self.write_feeds(self.CONTENT)

    def write_feeds(self, content):
        for name in os.listdir(self.feeds_dir):
            os.remove(os.path.join(self.feeds_dir, name))
        for fid, text in content.items():
            with open(os.path.join(self.feeds_dir, fid), "w") as f:
                f.write(text)

    def run_gen(self, now=T0):
        return g.run(self.out, self.state, now, feeds=self.FEEDS, feeds_dir=self.feeds_dir, block=64)

    def read(self, name):
        with open(os.path.join(self.out, name)) as f:
            return f.read()

    def test_outputs(self):
        self.assertEqual(self.run_gen(), 0)
        self.assertEqual(
            self.read("blocklist.txt").split(), ["1.2.3.4/31", "1.2.3.6", "20.0.0.0/24", "30.0.0.1", "30.0.0.2", "40.0.0.0/23"]
        )
        self.assertEqual(
            self.read("blocklist_l.txt").split(),
            ["1.2.3.4/31", "1.2.3.6", "20.0.0.0/24", "30.0.0.1", "30.0.0.2", "40.0.0.0/23", "50.0.0.1", "50.0.0.3"],
        )
        self.assertEqual(self.read("blocklist_xl.txt").split()[-1], "60.0.0.2")
        self.assertEqual(self.read("tor_blocklist.txt").split(), ["70.0.0.1", "70.0.0.2"])
        rsc = self.read("blocklist.rsc").splitlines()
        self.assertEqual(rsc[0], "/ip firewall address-list")
        self.assertEqual(rsc[1], 'add list=new_blocklist address="1.2.3.4/31" comment="blocklist"')
        ga = self.read("blocklist_ga_tor.rsc").splitlines()
        self.assertEqual(ga, [':global newips [:toarray ""]', ':set newips ($newips,"70.0.0.1")', ':set newips ($newips,"70.0.0.2")'])
        for base in ("blocklist", "blocklist_l", "blocklist_xl", "tor_blocklist"):
            with open(os.path.join(self.out, base + ".json"), "rb") as f:
                g.check_json(f.read(), self.read(base + ".txt").split(), 64)
        state = json.loads(self.read("feed_state.json"))
        self.assertEqual(set(state), {f.id for f in self.FEEDS})
        self.assertEqual(state["alpha"]["changed"], "2026-10-01T00:00:00Z")

    def test_one_feed_below_minimum_is_dropped(self):
        self.write_feeds({**self.CONTENT, "gamma": "<html>error</html>"})
        self.assertEqual(self.run_gen(), 0)
        self.assertNotIn("30.0.0.1", self.read("blocklist.txt"))

    def test_too_many_failed_feeds_abort_without_writing(self):
        self.write_feeds({k: v for k, v in self.CONTENT.items() if k not in ("alpha", "gamma", "delta")})
        self.assertEqual(self.run_gen(), 1)
        self.assertEqual(os.listdir(self.out), [])

    def test_missing_required_tier_aborts(self):
        self.write_feeds({k: v for k, v in self.CONTENT.items() if k != "tor"})
        self.assertEqual(self.run_gen(), 1)
        self.assertEqual(os.listdir(self.out), [])

    def test_dshield_format_drift_drops_feed(self):
        self.write_feeds({**self.CONTENT, "dshield": "20.0.0.0\t20.0.0.255\t\n"})
        self.assertEqual(self.run_gen(), 0)
        self.assertNotIn("20.0.0.0", self.read("blocklist.txt"))

    def test_stale_feed_dropped_and_reported(self):
        self.assertEqual(self.run_gen(T0), 0)
        later = T0 + datetime.timedelta(days=g.STALE_DAYS, hours=1)
        changed = {k: v + "99.0.0.1\n" for k, v in self.CONTENT.items() if k != "delta"}
        self.write_feeds({**self.CONTENT, **changed})
        self.assertEqual(self.run_gen(later), 2, "lists written, stale feed reported")
        self.assertNotIn("40.0.0.0", self.read("blocklist.txt"), "stale Delta left out")
        self.assertIn("99.0.0.1", self.read("blocklist.txt"))
        state = json.loads(self.read("feed_state.json"))
        self.assertEqual(state["delta"]["changed"], "2026-10-01T00:00:00Z", "stale feed keeps its date")
        self.assertEqual(state["alpha"]["changed"], g.iso(later))

    def test_unchanged_within_limit_is_fresh(self):
        self.assertEqual(self.run_gen(T0), 0)
        self.assertEqual(self.run_gen(T0 + datetime.timedelta(days=g.STALE_DAYS)), 0)

    def test_failed_feed_keeps_state(self):
        self.assertEqual(self.run_gen(T0), 0)
        self.write_feeds({k: v for k, v in self.CONTENT.items() if k != "gamma"})
        self.assertEqual(self.run_gen(T0 + datetime.timedelta(days=1)), 0)
        state = json.loads(self.read("feed_state.json"))
        self.assertEqual(state["gamma"]["changed"], "2026-10-01T00:00:00Z")

    def test_removed_feed_pruned_from_state(self):
        with open(self.state, "w") as f:
            json.dump({"retired": {"sha256": "x", "changed": "2020-01-01T00:00:00Z"}}, f)
        self.assertEqual(self.run_gen(), 0)
        self.assertNotIn("retired", json.loads(self.read("feed_state.json")))


if __name__ == "__main__":
    unittest.main()
