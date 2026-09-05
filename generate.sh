#!/bin/sh
# Blocklist aggregator - gawk version (Davie3 fork)
#
# Based on multiduplikator's README script, with:
#   - Spamhaus EDROP, DShield, and ThreatFox added
#   - HTTP retries + polite User-Agent
#   - Soft-fail: tolerates up to 2 failed feeds
#   - Tor exits split into their own list (opt-in on the router side)
#
# Requires: curl, gawk, sed, grep (all default on ubuntu-latest).

set -eu

export LC_ALL=C

UA="Davie3/mikrotik_blocklist regenerator (github.com/Davie3/mikrotik_blocklist)"
MAX_FAILED_FEEDS=2

OUTDIR="$(pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

CACHE="$TMPDIR/.cache"
mkdir -p "$CACHE"

cd "$TMPDIR"

download() {
    url="$1"; output="$2"; name="$3"
    if curl -sfL \
            --connect-timeout 30 --max-time 180 \
            --retry 3 --retry-delay 5 --retry-connrefused --retry-all-errors \
            -A "$UA" \
            "$url" -o "$output" 2>/dev/null; then
        if [ -s "$output" ]; then
            echo "  + $name"
        else
            echo "  ! $name (empty)"
            rm -f "$output"
        fi
    else
        echo "  ! $name (failed)"
        rm -f "$output"
    fi
}

echo "Downloading blocklists..."

# Suffix legend:
#   .out_s    -> Standard tier (also included in Large and XL)
#   .out_l    -> Large tier only (also included in XL)
#   .out_xl   -> XL tier only
#   .out_tor  -> Tor list (separate, never in main tiers)

download "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst" \
         "tor_exits.out_tor" "Tor Exit Nodes" &
download "https://www.spamhaus.org/drop/drop.txt" \
         "spamhaus_drop.out_s" "Spamhaus DROP" &
download "https://www.spamhaus.org/drop/edrop.txt" \
         "spamhaus_edrop.out_s" "Spamhaus EDROP" &
download "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" \
         "sslbl.out_s" "SSL Blacklist" &
download "https://lists.blocklist.de/lists/all.txt" \
         "blocklist_de.out_s" "Blocklist.de" &
download "https://cinsscore.com/list/ci-badguys.txt" \
         "cinsarmy.out_l" "CINS Army" &
download "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
         "feodo.out_s" "Feodo Tracker" &
download "https://threatfox.abuse.ch/export/csv/ip-port/recent/" \
         "threatfox.out_s" "ThreatFox" &
download "https://www.dshield.org/block.txt" \
         "dshield.out_s.raw" "DShield" &
download "https://iplists.firehol.org/files/firehol_level1.netset" \
         "firehol_l1.out_s" "FireHOL L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt" \
         "ipsum_l1.out_xl" "IPsum L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \
         "ipsum_l3.out_s" "IPsum L3" &
wait

# DShield ships as "startIP<TAB>endIP<TAB>netmask<TAB>..." per data row.
# The generic extractor would treat startIP and endIP as isolated /32s and
# miss everything in between, so convert to CIDR before extraction.
if [ -s dshield.out_s.raw ]; then
    awk '/^[0-9]/ {print $1"/"$3}' dshield.out_s.raw > dshield.out_s
    rm -f dshield.out_s.raw
fi

# Soft-fail: count missing/empty feeds; abort only if too many are down.
EXPECTED="tor_exits.out_tor spamhaus_drop.out_s spamhaus_edrop.out_s \
          sslbl.out_s blocklist_de.out_s cinsarmy.out_l feodo.out_s \
          threatfox.out_s dshield.out_s firehol_l1.out_s \
          ipsum_l1.out_xl ipsum_l3.out_s"
missing=0
for f in $EXPECTED; do
    if [ ! -s "$f" ]; then
        echo "  ! Skipping missing/empty feed: $f"
        missing=$((missing + 1))
    fi
done
if [ "$missing" -gt "$MAX_FAILED_FEEDS" ]; then
    echo "  ! $missing feeds failed (threshold: $MAX_FAILED_FEEDS). Aborting."
    exit 1
fi
echo "Downloads complete ($missing failed, within tolerance)."

echo "Extracting ranges..."

gawk '
BEGIN {
    for (i = 0; i <= 32; i++) P[i] = lshift(1, 32-i)
    cache = "'"$CACHE"'/"
}
{
    line = $0
    while (match(line, /[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+(\/[0-9]+)?/)) {
        addr = substr(line, RSTART, RLENGTH)
        line = substr(line, RSTART + RLENGTH)

        n = split(addr, p, "/")
        split(p[1], o, ".")
        if (o[1]>255||o[2]>255||o[3]>255||o[4]>255) continue
        pfx = (n==2) ? p[2]+0 : 32
        if (pfx<0||pfx>32) continue

        s = lshift(o[1],24) + lshift(o[2],16) + lshift(o[3],8) + o[4]
        sz = P[pfx]
        s = and(s, compl(sz-1))
        e = s + sz - 1

        if (s <= 16777215) continue
        if (s <= 184549375 && e >= 167772160) continue
        if (s <= 2147483647 && e >= 2130706432) continue
        if (s <= 2887778303 && e >= 2886729728) continue
        if (s <= 3232301055 && e >= 3232235520) continue
        if (e >= 3758096384) continue
        if (pfx==32 && s==879870596) continue
        if (pfx==32 && s==599449625) continue

        print s, e >> (cache FILENAME ".ranges")
    }
}
' ./*.out_*

echo "Building lists..."

build_list() {
    base="$1"; shift
    outbase="$OUTDIR/$base"

    sort -n -S 50% "$@" | gawk -v base="$base" -v outbase="$outbase" -v outdir="$OUTDIR" '
    BEGIN {
        for (i=0; i<=32; i++) P[i] = lshift(1, i)
        rsc = outbase ".rsc"
        # Map basename -> _ga.rsc filename suffix.
        if (base == "blocklist")        ga_suffix = ""
        else if (base == "blocklist_l") ga_suffix = "_l"
        else if (base == "blocklist_xl") ga_suffix = "_xl"
        else if (base == "tor_blocklist") ga_suffix = "_tor"
        else ga_suffix = "_" base
        ga = outdir "/blocklist_ga" ga_suffix ".rsc"
        txt = outbase ".txt"
        printf "" > txt
        print "/ip firewall address-list" > rsc
        print ":global newips [:toarray \"\"]" > ga
        count = 0
    }
    function ip(n) {
        return and(rshift(n,24),255) "." and(rshift(n,16),255) "." and(rshift(n,8),255) "." and(n,255)
    }
    function emit(s, e,   b, sz, addr) {
        while (s <= e) {
            for (b=0; b<32; b++) {
                sz = P[b+1]
                if (and(s,sz-1) || s+sz-1 > e) break
            }
            sz = P[b]
            addr = (b==0) ? ip(s) : ip(s) "/" (32-b)
            print addr >> txt
            print "add list=new_blocklist address=\"" addr "\" comment=\"blocklist\"" >> rsc
            print ":set newips ($newips,\"" addr "\")" >> ga
            count++
            s += sz
        }
    }
    NR==1 { cs=$1; ce=$2; next }
    $1 <= ce+1 { if ($2>ce) ce=$2; next }
    { emit(cs,ce); cs=$1; ce=$2 }
    END {
        if(NR) emit(cs,ce)
        # Always block reserved 240.0.0.0/4 in the main tiers.
        # (The Tor list is a policy list; do not append reserved space to it.)
        if (base != "tor_blocklist") {
            addr = "240.0.0.0/4"
            print addr >> txt
            print "add list=new_blocklist address=\"" addr "\" comment=\"blocklist\"" >> rsc
            print ":set newips ($newips,\"" addr "\")" >> ga
            count++
        }
        print "  " base ": " count " entries" > "/dev/stderr"
    }'
}

# Nullglob-ish: if a tier has no .ranges files (all its feeds failed), the
# expansion would leave literal patterns; guard with a for-loop check.
have_ranges() {
    for p in "$@"; do
        [ -e "$p" ] && return 0
    done
    return 1
}

if have_ranges "$CACHE"/*.out_s.ranges; then
    build_list "blocklist"    "$CACHE"/*.out_s.ranges &
    build_list "blocklist_l"  "$CACHE"/*.out_s.ranges "$CACHE"/*.out_l.ranges &
    build_list "blocklist_xl" "$CACHE"/*.out_s.ranges "$CACHE"/*.out_l.ranges "$CACHE"/*.out_xl.ranges &
fi
if have_ranges "$CACHE"/*.out_tor.ranges; then
    build_list "tor_blocklist" "$CACHE"/*.out_tor.ranges &
fi
wait

echo "Done!"
