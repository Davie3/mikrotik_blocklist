#!/usr/bin/env python3
"""Blocklist aggregator (Davie3 fork).

Downloads public threat feeds, extracts IPv4 addresses and CIDRs, drops
reserved address space, merges overlapping and adjacent ranges into the
minimal set of CIDR blocks, and writes four lists -- Standard, Large, XL and
Tor -- each in four formats:

  <list>.txt          one address or CIDR per line
  <list>.rsc          RouterOS import into the address-list new_blocklist
  blocklist_ga*.rsc   RouterOS script that fills the global array $newips
  <list>.json         fixed-size JSON blocks for :deserialize (see pack_json)

Feed health:
  - A feed that yields fewer than its min_ranges ranges is dropped (failed
    download, deprecated feed still serving its header, truncated file,
    error page).
  - A feed whose ranges have not changed for STALE_DAYS is dropped as stale.
    The date each feed last changed is tracked in feed_state.json, which CI
    commits alongside the lists.
  Up to MAX_FAILED_FEEDS dropped feeds are tolerated; more abort the run.

Exit codes:
  0  lists written
  1  error; nothing written
  2  lists written, but stale feeds were left out. CI publishes the lists
     and then fails the run, so GitHub sends a notification.

Requires: Python 3.10+ (standard library only) and curl.
"""

import argparse
import concurrent.futures
import datetime
import hashlib
import ipaddress
import itertools
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass

# ============================================================
# CONFIG
# ============================================================

UA = "Davie3/mikrotik_blocklist regenerator (github.com/Davie3/mikrotik_blocklist)"

MAX_FAILED_FEEDS = 2

# A feed whose extracted ranges are identical for longer than this is stale.
# Every current feed normally changes at least daily.
STALE_DAYS = 7

CURL_CONNECT_TIMEOUT = 30
CURL_MAX_TIME = 180
CURL_RETRIES = 3
CURL_RETRY_DELAY = 5

# Block size of the .json lists. RouterOS's /file read returns at most
# 32768 bytes per call, so every block must be one complete JSON object of
# at most this size.
JSON_BLOCK = 32768

STATE_FILE = "feed_state.json"

# ============================================================
# FEEDS
# ============================================================
# tier:
#   s   -> Standard (also in Large and XL)
#   l   -> Large (also in XL)
#   xl  -> XL only
#   tor -> Tor list (separate; never in main tiers)
#
# id: short unique name; also the key in feed_state.json and the file name
#   read in offline mode (--feeds-dir). Feeds that need format-specific
#   preprocessing are dispatched on it in PREPROCESS below.
#
# min_ranges: the feed is dropped if it yields fewer ranges than this. Set
#   to roughly 10-20% of the normal count so that dead, deprecated,
#   truncated or error-page downloads are caught -- a non-empty file is not
#   enough (deprecated feeds keep serving headers).


@dataclass(frozen=True)
class Feed:
    tier: str
    id: str
    min_ranges: int
    name: str
    url: str


FEEDS = [
    Feed("s", "spamhaus_drop", 500, "Spamhaus DROP", "https://www.spamhaus.org/drop/drop.txt"),
    Feed("s", "c2intel", 30, "C2IntelFeeds", "https://raw.githubusercontent.com/drb-ra/C2IntelFeeds/master/feeds/IPC2s-30day.csv"),
    Feed("s", "blocklist_de", 5000, "Blocklist.de", "https://lists.blocklist.de/lists/all.txt"),
    Feed("s", "dshield", 15, "DShield", "https://www.dshield.org/block.txt"),
    Feed("s", "et_compromised", 100, "ET Compromised IPs", "https://rules.emergingthreats.net/blockrules/compromised-ips.txt"),
    Feed("s", "firehol_l1", 1000, "FireHOL L1", "https://iplists.firehol.org/files/firehol_level1.netset"),
    Feed("s", "ipsum_l3", 3000, "IPsum L3", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt"),
    Feed("s", "binarydefense", 50, "Binary Defense", "https://www.binarydefense.com/banlist.txt"),
    Feed("l", "cinsarmy", 3000, "CINS Army", "https://cinsscore.com/list/ci-badguys.txt"),
    Feed("l", "turris", 1500, "Turris Sentinel", "https://view.sentinel.turris.cz/greylist-data/greylist-latest.csv"),
    Feed("xl", "ipsum_l1", 20000, "IPsum L1", "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt"),
    Feed("tor", "tor_exits", 200, "Tor Exit Nodes", "https://check.torproject.org/torbulkexitlist"),
]

# ============================================================
# LISTS
# ============================================================
# (base name, feed tiers included, RouterOS global-array script)

LISTS = [
    ("blocklist", ("s",), "blocklist_ga.rsc"),
    ("blocklist_l", ("s", "l"), "blocklist_ga_l.rsc"),
    ("blocklist_xl", ("s", "l", "xl"), "blocklist_ga_xl.rsc"),
    ("tor_blocklist", ("tor",), "blocklist_ga_tor.rsc"),
]

# Tiers that must yield ranges, or the run aborts rather than publishing
# lists with whole tiers missing. (Large and XL include Standard.)
REQUIRED_TIERS = ("s", "tor")

# ============================================================
# FILTERS
# ============================================================

# Any range overlapping one of these is dropped.
RESERVED = [
    ipaddress.ip_network(n)
    for n in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",  # CGNAT, RFC 6598
        "127.0.0.0/8",
        "169.254.0.0/16",  # link-local, RFC 3927
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/3",  # multicast + reserved
    )
]
RESERVED_RANGES = [(int(n.network_address), int(n.broadcast_address)) for n in RESERVED]

# Never block these exact /32 entries (Microsoft Teams).
WHITELIST = {int(ipaddress.ip_address(a)) for a in ("52.113.194.132", "35.186.224.25")}

# ============================================================
# EXTRACTION
# ============================================================

ADDR_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(?:/[0-9]+)?")


def extract(text):
    """Return (start, end) integer ranges for every address or CIDR in text.

    Host bits are cleared ("1.2.3.4/24" -> 1.2.3.0/24). Invalid octets or
    prefix lengths, reserved space and whitelisted /32s are skipped.
    """
    ranges = []
    for m in ADDR_RE.finditer(text):
        addr, _, pfx = m.group().partition("/")
        octets = [int(o) for o in addr.split(".")]
        if any(o > 255 for o in octets):
            continue
        plen = int(pfx) if pfx else 32
        if plen > 32:
            continue
        s = (octets[0] << 24) | (octets[1] << 16) | (octets[2] << 8) | octets[3]
        size = 1 << (32 - plen)
        s &= ~(size - 1)
        e = s + size - 1
        if any(s <= re_ and e >= rs for rs, re_ in RESERVED_RANGES):
            continue
        if plen == 32 and s in WHITELIST:
            continue
        ranges.append((s, e))
    return ranges


def preprocess_dshield(text):
    """Convert DShield's "startIP<TAB>endIP<TAB>netmask" rows to CIDRs.

    The generic extractor would see only the two edge IPs of each row as
    /32s. Column 3 must be a valid prefix length; if fewer than half of the
    data rows convert, the format has changed and None is returned (the
    feed is then dropped rather than silently shrunk to single hosts).
    """
    rows = 0
    out = []
    for line in text.split("\n"):
        if not line[:1].isascii() or not line[:1].isdigit():
            continue
        rows += 1
        f = re.split(r"[ \t]+", line.strip(" \t"))
        if len(f) >= 3 and re.fullmatch(r"[0-9]+", f[2]) and 1 <= int(f[2]) <= 32:
            out.append(f"{f[0]}/{f[2]}")
    if rows and len(out) < rows // 2:
        print(f"  ! DShield preprocess kept {len(out)}/{rows} rows (format change?); dropping feed")
        return None
    return "\n".join(out)


PREPROCESS = {"dshield": preprocess_dshield}

# ============================================================
# LIST BUILDING
# ============================================================


def merge(ranges):
    """Merge (start, end) ranges; overlapping and adjacent ones are joined."""
    merged = []
    for s, e in sorted(ranges):
        if merged and s <= merged[-1][1] + 1:
            if e > merged[-1][1]:
                merged[-1][1] = e
        else:
            merged.append([s, e])
    return merged


def ip_str(n):
    return f"{n >> 24 & 255}.{n >> 16 & 255}.{n >> 8 & 255}.{n & 255}"


def cidrs(s, e):
    """Cover [s, e] with the minimal list of CIDR blocks ("a.b.c.d[/len]")."""
    out = []
    while s <= e:
        b = 0  # host bits of the largest aligned block starting at s
        while b < 32:
            size = 1 << (b + 1)
            if s & (size - 1) or s + size - 1 > e:
                break
            b += 1
        out.append(ip_str(s) if b == 0 else f"{ip_str(s)}/{32 - b}")
        s += 1 << b
    return out


def build_entries(ranges):
    return [c for s, e in merge(ranges) for c in cidrs(s, e)]


# ============================================================
# JSON
# ============================================================


def pack_json(entries, generated, block=JSON_BLOCK):
    """Pack sorted entries into fixed-size JSON blocks for RouterOS.

    Every block is exactly `block` bytes, padded with spaces (the last one is
    not padded), and holds one JSON object mapping first octet -> second
    octet -> rest of the address -> 1, e.g.

      {"#":{"format":1,"entries":3,"generated":1760000000},
       "1":{"2":{"3.4":1,"3.8/30":1}},"5":{...}}

    The "#" header is only in the first block. A first-octet object may
    continue in the next block; a second-octet group never spans blocks.
    RouterOS reads each block with one /file read and one :deserialize.
    """
    blocks = []
    body = '{"#":{"format":1,"entries":%d,"generated":%d}' % (len(entries), generated)
    if len(body) + 1 > block:
        raise ValueError(f"json: header does not fit into a {block}-byte block")
    has_members = True
    open_o1 = None

    def split(entry):
        o1, o2, rest = entry.split(".", 2)
        return o1, o2, rest

    for (o1, o2), group in itertools.groupby(map(split, entries), key=lambda t: t[:2]):
        grp = '"%s":{%s}' % (o2, ",".join('"%s":1' % t[2] for t in group))
        if o1 == open_o1:
            piece = "," + grp
        else:
            piece = ("}" if open_o1 is not None else "") + ("," if has_members else "") + '"%s":{%s' % (o1, grp)
        # +2: room for closing the open first-octet object and the block.
        if len(body) + len(piece) + 2 > block:
            blocks.append(body + ("}" if open_o1 is not None else "") + "}")
            body, open_o1, has_members = "{", None, False
            piece = '"%s":{%s' % (o1, grp)
            if len(body) + len(piece) + 2 > block:
                raise ValueError(f"json: group {o1}.{o2} does not fit into a {block}-byte block")
        body += piece
        open_o1 = o1
        has_members = True
    blocks.append(body + ("}" if open_o1 is not None else "") + "}")
    return ("".join(b.ljust(block) for b in blocks[:-1]) + blocks[-1]).encode("ascii")


def _no_duplicate_keys(pairs):
    keys = [k for k, _ in pairs]
    if len(keys) != len(set(keys)):
        dup = next(k for k in keys if keys.count(k) > 1)
        raise ValueError(f"key {dup} repeated within one object")
    return dict(pairs)


def check_json(data, entries, block=JSON_BLOCK):
    """Decode a .json list block by block, as RouterOS does, and verify it.

    Each block must be one JSON object followed only by space padding, with
    the header first in block 1, no first octet repeated within a block, no
    second-octet group in two blocks (the router would keep only one), and
    every leaf equal to 1. The decoded entries must equal `entries` exactly
    and match the header's count. Raises ValueError with the reason.
    """
    want = set(entries)
    if len(want) != len(entries):
        raise ValueError("list contains duplicate entries")
    if not data:
        raise ValueError("empty file")
    decoder = json.JSONDecoder(object_pairs_hook=_no_duplicate_keys)
    header = None
    groups = set()
    got = set()
    for n, off in enumerate(range(0, len(data), block), 1):
        try:
            text = data[off : off + block].decode("ascii")
        except UnicodeDecodeError:
            raise ValueError(f"block {n}: non-ASCII data") from None
        if not text.startswith("{"):
            raise ValueError(f"block {n} does not start an object")
        try:
            obj, end = decoder.raw_decode(text)
        except json.JSONDecodeError as exc:
            raise ValueError(f"block {n} is not a complete JSON object: {exc}") from None
        if text[end:].strip(" "):
            raise ValueError(f"block {n}: data after the object")
        for i, (o1, g) in enumerate(obj.items()):
            if o1 == "#":
                if n != 1 or i != 0 or header is not None:
                    raise ValueError("misplaced header")
                if not isinstance(g, dict) or set(g) != {"format", "entries", "generated"}:
                    raise ValueError("header must have exactly format, entries, generated")
                header = g
                continue
            if not o1.isdigit() or not isinstance(g, dict) or not g:
                raise ValueError(f"block {n}: bad first-octet key {o1!r}")
            for o2, rs in g.items():
                if (o1, o2) in groups:
                    raise ValueError(f"second-octet group {o1}.{o2} appears in two places")
                groups.add((o1, o2))
                if not isinstance(rs, dict) or not rs:
                    raise ValueError(f"block {n}: bad group {o1}.{o2}")
                for rest, v in rs.items():
                    entry = f"{o1}.{o2}.{rest}"
                    if type(v) is not int or v != 1:
                        raise ValueError(f"block {n}: entry {entry} has a value other than 1")
                    if entry not in want:
                        raise ValueError(f"block {n}: entry {entry} is not in the list")
                    if entry in got:
                        raise ValueError(f"block {n}: entry {entry} appears twice")
                    got.add(entry)
    if header is None or header["format"] != 1:
        raise ValueError("header missing or format is not 1")
    if header["entries"] != len(want):
        raise ValueError(f"header says {header['entries']} entries, list has {len(want)}")
    if type(header["generated"]) is not int:
        raise ValueError("header has no generation time")
    if len(got) != len(want):
        raise ValueError(f"decoded {len(got)} entries, list has {len(want)}")


# ============================================================
# FEED STATE (freshness)
# ============================================================


def iso(ts):
    return ts.strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(s):
    return datetime.datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=datetime.timezone.utc)


def digest(ranges):
    h = hashlib.sha256()
    for s, e in sorted(set(ranges)):
        h.update(b"%d %d\n" % (s, e))
    return h.hexdigest()


def load_state(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}


# ============================================================
# DOWNLOADS
# ============================================================


def fetch(feed, feeds_dir):
    """Return the feed's raw bytes, or None if it could not be fetched."""
    if feeds_dir:
        try:
            with open(os.path.join(feeds_dir, feed.id), "rb") as f:
                data = f.read()
        except OSError:
            data = None
    else:
        r = subprocess.run(
            [
                "curl",
                "-sfL",
                "--connect-timeout",
                str(CURL_CONNECT_TIMEOUT),
                "--max-time",
                str(CURL_MAX_TIME),
                "--retry",
                str(CURL_RETRIES),
                "--retry-delay",
                str(CURL_RETRY_DELAY),
                "--retry-connrefused",
                "--retry-all-errors",
                "-A",
                UA,
                feed.url,
            ],
            capture_output=True,
        )
        data = r.stdout if r.returncode == 0 else None
    if data is None:
        print(f"  ! {feed.name} (failed)")
    elif not data:
        print(f"  ! {feed.name} (empty)")
        data = None
    else:
        print(f"  + {feed.name}")
    return data


def annotate(level, title, msg):
    """Surface a message on the GitHub Actions run page."""
    if os.environ.get("GITHUB_ACTIONS") == "true":
        print(f"::{level} title={title}::{msg}")


# ============================================================
# MAIN
# ============================================================


def write_atomic(path, data):
    tmp = path + ".tmp"
    with open(tmp, "wb") as f:
        f.write(data)
    os.replace(tmp, path)


def run(out_dir, state_path, now, feeds=FEEDS, feeds_dir=None, block=JSON_BLOCK):
    print("Downloading blocklists...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(feeds)) as pool:
        raw = dict(zip((f.id for f in feeds), pool.map(lambda f: fetch(f, feeds_dir), feeds), strict=True))

    print("Checking feeds...")
    old_state = load_state(state_path)
    state = {}
    ranges = {}
    failed = 0
    stale = []
    for feed in feeds:
        prev = old_state.get(feed.id)
        if prev is not None:
            state[feed.id] = prev  # kept as-is unless the feed changed
        data = raw[feed.id]
        text = data.decode("latin-1") if data else ""
        if text and feed.id in PREPROCESS:
            text = PREPROCESS[feed.id](text) or ""
        r = extract(text)
        if len(r) < feed.min_ranges:
            msg = f"{feed.name}: {len(r)} ranges (minimum {feed.min_ranges}); dropping feed"
            print(f"  ! {msg}")
            annotate("warning", "Feed dropped", msg)
            failed += 1
            continue
        h = digest(r)
        if prev is None or prev.get("sha256") != h:
            state[feed.id] = {"sha256": h, "changed": iso(now)}
        elif now - parse_iso(prev["changed"]) > datetime.timedelta(days=STALE_DAYS):
            msg = f"{feed.name}: unchanged since {prev['changed']} (limit {STALE_DAYS} days); dropping feed as stale"
            print(f"  ! {msg}")
            annotate("error", "Stale feed", msg)
            failed += 1
            stale.append(feed.name)
            continue
        print(f"  {feed.name}: {len(r)} ranges")
        ranges[feed.id] = r
    if failed > MAX_FAILED_FEEDS:
        print(f"  ! {failed} feeds failed (threshold: {MAX_FAILED_FEEDS}). Aborting.")
        return 1
    print(f"Feeds checked ({failed} failed, within tolerance).")

    # Every required tier must produce ranges. Otherwise fail loudly so CI
    # surfaces the outage rather than shipping yesterday's data.
    missing = [t for t in REQUIRED_TIERS if not any(f.id in ranges for f in feeds if f.tier == t)]
    if missing:
        for t in missing:
            print(f"  ! No ranges extracted for tier '{t}'", file=sys.stderr)
        print("  ! Aborting to avoid committing stale lists.", file=sys.stderr)
        return 1

    print("Building lists...")
    outputs = {}
    generated = int(now.timestamp())
    for base, tiers, ga_name in LISTS:
        entries = build_entries(r for f in feeds if f.tier in tiers for r in ranges.get(f.id, ()))
        if not entries:
            print(f"  ! {base}: no entries; aborting", file=sys.stderr)
            return 1
        try:
            js = pack_json(entries, generated, block)
            check_json(js, entries, block)
        except ValueError as exc:
            print(f"  ! {base}.json: {exc}; aborting", file=sys.stderr)
            return 1
        outputs[base + ".txt"] = "".join(f"{a}\n" for a in entries).encode()
        outputs[base + ".rsc"] = (
            "/ip firewall address-list\n" + "".join(f'add list=new_blocklist address="{a}" comment="blocklist"\n' for a in entries)
        ).encode()
        outputs[ga_name] = (':global newips [:toarray ""]\n' + "".join(f':set newips ($newips,"{a}")\n' for a in entries)).encode()
        outputs[base + ".json"] = js
        print(f"  {base}: {len(entries)} entries")

    # Write only once every list has been built and checked.
    for name, data in outputs.items():
        write_atomic(os.path.join(out_dir, name), data)
    write_atomic(state_path, (json.dumps(state, indent=2, sort_keys=True) + "\n").encode())

    if stale:
        print(f"Done, but stale feeds were left out: {', '.join(stale)}")
        return 2
    print("Done!")
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Blocklist aggregator (Davie3 fork).")
    p.add_argument("--out-dir", default=".", help="where the lists are written (default: current directory)")
    p.add_argument("--state", help=f"feed state file (default: <out-dir>/{STATE_FILE})")
    p.add_argument("--feeds-dir", help="offline mode: read each feed from <dir>/<id> instead of downloading")
    p.add_argument("--now", help="current time as YYYY-MM-DDTHH:MM:SSZ (testing)")
    args = p.parse_args(argv)
    now = parse_iso(args.now) if args.now else datetime.datetime.now(datetime.timezone.utc).replace(microsecond=0)
    state = args.state or os.path.join(args.out_dir, STATE_FILE)
    os.makedirs(args.out_dir, exist_ok=True)
    return run(args.out_dir, state, now, feeds_dir=args.feeds_dir)


if __name__ == "__main__":
    sys.exit(main())
