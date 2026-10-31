# MikroTik Blocklist

_Fork of [multiduplikator/mikrotik_blocklist](https://github.com/multiduplikator/mikrotik_blocklist) with a self-hosted GitHub Actions generator ([`generate.py`](generate.py), [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml)). Adds DShield, C2IntelFeeds, ET Compromised IPs, Binary Defense, and Turris Sentinel; splits Tor exits into a separate list. Upstream has since moved to [GitLab](https://gitlab.com/multiduplikator-group/mikrotik_blocklist)._

An aggregated IP blocklist for MikroTik RouterOS firewalls, compiled from multiple threat intelligence sources. The RouterOS scripts in [`routeros/`](routeros/) are run on a hEX (RB750Gr3) with RouterOS 7.23.5 and need RouterOS 7.13 or later.

## Overview

This project provides pre-aggregated blocklists optimized for MikroTik routers. By using CIDR prefix aggregation, we minimize the number of address-list entries while maintaining comprehensive coverage — improving router performance and reducing memory usage.

**Update frequency:** Every 3 hours

## Available Lists

| List                 | Files                                                               | Entries | Sources                                       |
| -------------------- | ------------------------------------------------------------------- | ------- | --------------------------------------------- |
| Standard             | `blocklist.txt` / `blocklist_ga.rsc` / `blocklist.json`             | ~30k    | Core threat feeds                             |
| Large                | `blocklist_l.txt` / `blocklist_ga_l.rsc` / `blocklist_l.json`       | ~40k    | Core + CINS Army + Turris Sentinel            |
| Extra Large          | `blocklist_xl.txt` / `blocklist_ga_xl.rsc` / `blocklist_xl.json`    | ~110k   | All threat sources including IPsum L1         |
| Tor exits (separate) | `tor_blocklist.txt` / `blocklist_ga_tor.rsc` / `tor_blocklist.json` | ~650    | Tor exit nodes (policy list, not threat data) |

Each list comes in four formats: `.txt` (one address or CIDR per line), `.rsc` (RouterOS import into `new_blocklist`), `blocklist_ga*.rsc` (fills the global array `$newips`, see [.rsc Lists](#rsc-lists)), and `.json`, a sequence of 32 KB blocks that the [update script](#routeros-implementation) reads with `/file read` and `:deserialize` — much faster than the `.rsc` import, and data only (nothing is executed). The `.json` format is byte-compatible with the [GitLab upstream](https://gitlab.com/multiduplikator-group/mikrotik_blocklist)'s, so its update script works with these files.

## Sources

Threat feeds — go into the main tiers:

| Source                                                                     | Description                                                        | Standard | Large | XL  |
| -------------------------------------------------------------------------- | ------------------------------------------------------------------ | :------: | :---: | :-: |
| [Spamhaus DROP](https://www.spamhaus.org/drop/)                            | Hijacked / criminal netblocks ("Don't Route Or Peer")              |    ✓     |   ✓   |  ✓  |
| [C2IntelFeeds](https://github.com/drb-ra/C2IntelFeeds)                     | Cobalt Strike C2 servers found by internet scanning (last 30 days) |    ✓     |   ✓   |  ✓  |
| [DShield](https://www.dshield.org/)                                        | SANS ISC top attackers (startIP-endIP-netmask format)              |    ✓     |   ✓   |  ✓  |
| [Blocklist.de](https://lists.blocklist.de/)                                | Fail2ban-reported IPs across participating servers                 |    ✓     |   ✓   |  ✓  |
| [ET Compromised IPs](https://rules.emergingthreats.net/blockrules/)        | Proofpoint Emerging Threats list of known compromised hosts        |    ✓     |   ✓   |  ✓  |
| [FireHOL Level 1](https://iplists.firehol.org/)                            | Aggregated high-confidence threat intelligence                     |    ✓     |   ✓   |  ✓  |
| [IPsum Level 3](https://github.com/stamparm/ipsum)                         | High-confidence threat IPs (3+ list hits)                          |    ✓     |   ✓   |  ✓  |
| [Binary Defense](https://www.binarydefense.com/banlist.txt)                | Artillery honeypot banlist (attackers seen by honeypots)           |    ✓     |   ✓   |  ✓  |
| [CINS Army](https://cinsscore.com/)                                        | Sentinel IPS community feed                                        |          |   ✓   |  ✓  |
| [Turris Sentinel Greylist](https://view.sentinel.turris.cz/greylist-data/) | CZ.NIC: attackers seen by Turris routers' firewalls and honeypots  |          |   ✓   |  ✓  |
| [IPsum Level 1](https://github.com/stamparm/ipsum)                         | Broader threat IPs (1+ list hits)                                  |          |       |  ✓  |

Retired feeds: Spamhaus EDROP (merged into DROP), SSL Blacklist (deprecated by abuse.ch on 2025-01-03), Feodo Tracker (unmaintained since March 2026), ThreatFox (anonymous export returns 410 Gone since 2026-10-21).

C2IntelFeeds, the DShield block list and the Turris Sentinel Greylist are licensed CC BY-NC-SA, and the Binary Defense banlist is for non-commercial use only, so the generated lists are for non-commercial use.

Policy list — separate file, opt-in on the router:

| Source                                                         | Description                                                                                         | File                                      |
| -------------------------------------------------------------- | --------------------------------------------------------------------------------------------------- | ----------------------------------------- |
| [Tor Exit Nodes](https://check.torproject.org/torbulkexitlist) | Public Tor exit relays, from the Tor Project's bulk exit list (privacy users, not attackers per se) | `tor_blocklist.*`, `blocklist_ga_tor.rsc` |

## Filtered Addresses

The following are automatically excluded from feed input:

- Private ranges: `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`
- CGNAT: `100.64.0.0/10` (RFC 6598)
- Loopback: `127.0.0.0/8`
- Link-local: `169.254.0.0/16` (RFC 3927)
- Multicast + reserved: `224.0.0.0/3` (covers `224.0.0.0/4` multicast and `240.0.0.0/4` IANA-reserved)
- Zero-network: `0.0.0.0/8`
- Whitelisted: `52.113.194.132` (Microsoft Teams), `35.186.224.25` (Microsoft Teams)

---

## Blocklist Generation

The generator lives in [`generate.py`](generate.py) and runs under GitHub Actions every 3 hours via [`.github/workflows/update_blocklist.yml`](.github/workflows/update_blocklist.yml). Feed URLs, tier assignments, per-feed minimums, the staleness limit, timeouts and retry counts are all constants at the top of `generate.py` — edit there.

**Dependencies:** Python 3.10+ (standard library only) and `curl`. Both present by default on `ubuntu-latest` GitHub runners.

**Running locally:** `python3 generate.py` downloads the feeds and writes the lists to the current directory (`--out-dir` to change). `--feeds-dir DIR` reads each feed from `DIR/<id>` instead of downloading. Tests: `python3 -m unittest discover -s tests -v` (offline, about a second).

**Development setup:** `mise install && lefthook install` installs the pinned tools and the git pre-commit hook. The hook formats staged Markdown and workflow YAML (Prettier) and Python (ruff), lints workflows (jactionlint), runs the tests when Python changes, and refuses commits that stage generated lists or `feed_state.json` — CI commits those. `mise run lint`, `mise run format`, `mise run test` and `mise run generate` (writes to `build/`) run the same tools by hand.

**Key behaviors:**

- Per-feed HTTP retries with polite `User-Agent` (`curl --retry 3 --retry-delay 5 --retry-connrefused --retry-all-errors`).
- Parallel downloads.
- **Per-feed minimums** — each feed has a `min_ranges` (roughly 10-20% of its normal size). A feed that yields fewer ranges (failed download, deprecated feed still serving its header, truncated file, error page) is dropped.
- **Stale feeds** — [`feed_state.json`](feed_state.json) records a fingerprint of each feed's extracted ranges and when they last changed. A feed unchanged for more than `STALE_DAYS` (7) is dropped, and the workflow run fails, so GitHub sends a failure notification. The lists are published without the feed unless dropping it moves a list past the delta limit below — losing Blocklist.de shrinks Standard by about 40%, and IPsum L1 shrinks XL by about 60%. Then nothing is published and the previous lists stay in place until the feed recovers or is replaced (the same applies to a feed dropped for falling below its minimum). (HTTP `Last-Modified` headers aren't used: several feeds don't send one, and dead feeds were seen reporting recent dates.)
- Soft-fail: tolerates up to `MAX_FAILED_FEEDS` (2) dropped feeds (below minimum or stale) before aborting.
- **Dedupe** — all ranges are merged (duplicates, overlaps and adjacent ranges joined) and written as the minimal set of CIDR blocks.
- **JSON check** — every `.json` list is decoded block by block the way RouterOS reads it and must reproduce its `.txt` exactly before anything is written.
- **DShield preprocess** — DShield ships `startIP<TAB>endIP<TAB>netmask` per row; the generic regex extractor would treat only the two edge IPs as /32s and miss everything between. A dedicated preprocess step converts to CIDR, with a **format-drift guard** that drops the feed if <50% of rows survive (protects against a silent ~99% coverage loss if DShield changes format).
- **Reserved-range filter** removes RFC 1918/6598/3927 space, loopback, multicast, and IANA-reserved from feed input at extract time (see [Filtered Addresses](#filtered-addresses) above).
- Every tier must produce ranges — if any tier is empty, generation aborts loudly so CI surfaces the outage rather than shipping yesterday's committed files.
- **Delta regression check** in CI fails the run if any tier moves >30% vs previous commit (>50% for the Tor list, which churns faster).
- CI runs the test suite before every generation; a failing test stops publishing.
- The workflow steps call scripts in [`scripts/`](scripts/) rather than inline shell: `ci_generate.sh`, `validate_lists.py` (shape, size-bound and delta checks, plus the run summary) and `commit_lists.sh`. Pull requests run `mise run lint` and `mise run test` via [`tests.yml`](.github/workflows/tests.yml).

---

## RouterOS Implementation

One script, `blocklist-update`, downloads `blocklist.json`, verifies it and updates the address-list `prod_blocklist` in place: entries that are no longer listed are removed and new ones added, so the list is active at every moment. The file is only data; nothing downloaded is executed. The scripts are in [`routeros/`](routeros/), each with its usage and settings at the top:

- [`install.rsc`](routeros/install.rsc) installs or updates the script, its scheduler and the [firewall rules](#firewall-rules).
- [`blocklist-update.rsc`](routeros/blocklist-update.rsc) is the update script's source.
- [`selftest.rsc`](routeros/selftest.rsc) runs the installed script against a scratch address-list and checks the update and its failure cases.

The default is the Standard list (~28k entries), the right size for small devices like the hEX (256 MB RAM, 16 MB flash). For Large or XL, change `url` and `file` in `blocklist-update.rsc`, and set `maxChange` high enough for the jump on the first run after switching.

### Firewall Rules

The drops are in the RAW table, as in MikroTik's [Building Advanced Firewall](https://help.mikrotik.com/docs/display/ROS/Building+Advanced+Firewall) guide: RAW rules run before connection tracking, so dropped packets cost the router as little as possible. Two rules cover both directions:

```routeros-script
/ip firewall raw
add chain=prerouting action=drop in-interface-list=WAN src-address-list=prod_blocklist comment="blocklist-update: drop from listed sources"
add chain=prerouting action=drop in-interface-list=LAN dst-address-list=prod_blocklist comment="blocklist-update: drop to listed destinations"
```

- packets **from** listed addresses arriving on the WAN (scans, brute force, exploits, and replies to connections a LAN device opened)
- packets **to** listed addresses from the LAN (an infected client calling its command-and-control server)

The interface lists keep each rule to one direction. Without them, the destination rule also drops everything arriving from the internet once the router's own public address is listed (DShield lists whole /24s). The lists contain IPv4 addresses only.

RAW rules are evaluated top to bottom, so the drops must come before any general accept rule. To exempt addresses from the blocklist (a CDN, a game service), add an accept rule above the drops; it skips the rest of the RAW chain only, and the filter rules still apply:

```routeros-script
/ip firewall raw add chain=prerouting action=accept src-address-list=blocklist_bypass comment="blocklist bypass" place-before=[find comment="blocklist-update: drop from listed sources"]
```

To find out which entry blocked a connection, log the drops for a while, then look the address up in `blocklist.txt`. Replies to a LAN device show the router's public address as destination, because RAW runs before NAT.

```routeros-script
/ip firewall raw set [find comment~"blocklist-update"] log=yes log-prefix="BL"
/log print where message~"BL"
```

### How the Update Works

1. **Safe failure:** the update aborts before changing anything if another run of the script is still in progress, if the download fails, if the file is missing, unreadable or not valid JSON, if the header's entry count does not match what was loaded, or if the list would change by more than `maxChange` (30) percent. The current list then stays as it is. If a single entry can't be added, the others still are, and the run ends with a warning. It never adds an entry wider than `/minPrefix` (10); the widest entries in the lists are FireHOL Level 1's /12s.

2. **First run:** if `prod_blocklist` doesn't exist yet, the script adds all entries; the size check only applies once the list exists.

3. **Policies:** a scheduled `/tool fetch` that saves a file needs `ftp` (since RouterOS 7.13) and `sensitive`, on the script **and** on its scheduler entry (`ftp,read,write,sensitive,test`). A manual run works without them, because it uses your login's rights, so a missing policy only shows in scheduled runs: `cannot open file: permission denied`.

4. **Stale lists:** the script logs a warning when the list it downloaded was generated more than `maxAge` (12) hours ago, which means the GitHub Actions schedule has stopped. CI runs every 3 hours, but GitHub skips scheduled runs at times; gaps of up to 9 hours have been seen. The list is still applied. This needs the router's clock to be correct (NTP).

5. **Security:** the script verifies the server's TLS certificate (`check-certificate=yes-without-crl`). RouterOS 7.21+ trusts its built-in root CAs for `fetch` by default (`/certificate settings print`). As a second line of defence, the size and prefix limits above stop a tampered list from blocking large parts of the internet.

6. **Logging:** the script doesn't change logging rules. RouterOS logs every added or removed entry as `system,info` ("address list entry added by ..."), so a run can add a few thousand lines to the log.

7. **Why JSON blocks:** RouterOS arrays are copied whenever they are modified, so building a list one entry at a time is slow. `:deserialize` builds each block's keyed array natively in one call. The blocks are 32 KB because `/file read` reads at most that much per call.

8. **Performance:** the GitLab upstream measured 21–24 s for its large list (~36k entries) on a CCR2004-16G-2S+. The hEX has a much slower CPU; `:put [:time {/system script run blocklist-update}]` shows yours.

### Troubleshooting

All messages start with `blocklist-DIFF:` (`/log print where message~"blocklist-DIFF"`).

- **Scheduled runs fail with `cannot open file: permission denied`**, manual runs work: the script or its scheduler entry is missing a policy. Run `install.rsc` again; self-test T16 checks this.
- **`is unreadable or not valid JSON` on every run, and self-test T1 fails:** RouterOS may not support `:deserialize`'s `options=json.no-string-conversion`. Remove that option from `blocklist-update.rsc`, then run `install.rsc` and the self-test again.
- **`download failed`:** check DNS and the clock, and that `/certificate settings print` shows the built-in trust store. Running the script's `/tool fetch` line by hand shows the actual error.
- **`list would change from X to Y entries (limit 30%), aborting`:** expected once after switching tiers (raise `maxChange` for one run). Otherwise compare with the run summaries in [Actions](https://github.com/Davie3/mikrotik_blocklist/actions); CI refuses to publish such jumps, so this points to a broken download or an outdated local list.
- **`list was generated N hours ago`:** the lists stopped updating. Check [Actions](https://github.com/Davie3/mikrotik_blocklist/actions) for failed or missing runs; a stale feed freezes publishing until it's fixed (see **Stale feeds** under [Blocklist Generation](#blocklist-generation)).
- **`another run is still in progress, skipped`:** a run started while another one was busy. Harmless; if it shows on every run, check `/system script job print` for a hung job.
- **Self-test T13 fails with `stale-logs=1`:** the last CI run is more than 12 hours old, or the router clock is wrong.

### .rsc Lists

The `.rsc` and `blocklist_ga*.rsc` files are published too, but the update script doesn't use them. `<list>.rsc` adds every entry to `new_blocklist` when imported; `blocklist_ga*.rsc` fills the global array `$newips`. Both run downloaded code on the router, and building `$newips` entry by entry is slow on small devices, because RouterOS copies the array on every append.

---

## License

This project aggregates publicly available threat intelligence feeds. Please respect the terms of use of each source.

**RouterOS scripts:** [`routeros/blocklist-update.rsc`](routeros/blocklist-update.rsc) and [`routeros/selftest.rsc`](routeros/selftest.rsc) are adapted from the [GitLab upstream](https://gitlab.com/multiduplikator-group/mikrotik_blocklist)'s update script and self-test, and are licensed under the [PolyForm Noncommercial License 1.0.0](https://polyformproject.org/licenses/noncommercial/1.0.0): free for personal use and for use by non-commercial organizations, not for commercial use.

```text
Required Notice: Copyright 2021-2026 multiduplikator (https://gitlab.com/multiduplikator-group/mikrotik_blocklist)
```
