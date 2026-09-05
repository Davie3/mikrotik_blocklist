#!/bin/sh
# Blocklist aggregator - gawk version
#
# Extracted from multiduplikator/mikrotik_blocklist README.md and adapted for
# GitHub Actions (no git push here -- the workflow handles commits).
#
# Requires: curl, gawk, sed, grep (all default on ubuntu-latest).
#
# Audit notes for this fork (review before editing):
#   * Downloads 9 upstream feeds in parallel; aborts on any single failure.
#   * Extracts IPv4/CIDR tokens via a strict regex; anything not matching
#     `\d+\.\d+\.\d+\.\d+(/\d+)?` is ignored.
#   * Filters private/loopback/multicast/reserved ranges plus two hardcoded
#     whitelist IPs (Microsoft Teams).
#   * Emits three tiers: standard (S), large (S+L), extra-large (S+L+XL).

set -eu

export LC_ALL=C

OUTDIR="$(pwd)"
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

CACHE="$TMPDIR/.cache"
mkdir -p "$CACHE"

cd "$TMPDIR"

download() {
    url="$1"; output="$2"; name="$3"
    if curl -sfL --connect-timeout 30 --max-time 120 "$url" -o "$output" 2>/dev/null; then
        if [ -s "$output" ]; then
            echo "  + $name"
        else
            echo "  ! $name (empty)"; exit 1
        fi
    else
        echo "  ! $name (failed)"; exit 1
    fi
}

echo "Downloading blocklists..."

download "https://raw.githubusercontent.com/SecOps-Institute/Tor-IP-Addresses/master/tor-exit-nodes.lst" \
         "tor_exits.out_s" "Tor Exit Nodes" &
download "https://www.spamhaus.org/drop/drop.txt" \
         "spamhaus_drop.out_s" "Spamhaus DROP" &
download "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt" \
         "sslbl.out_s" "SSL Blacklist" &
download "https://lists.blocklist.de/lists/all.txt" \
         "blocklist_de.out_s" "Blocklist.de" &
download "https://cinsscore.com/list/ci-badguys.txt" \
         "cinsarmy.out_l" "CINS Army" &
download "https://feodotracker.abuse.ch/downloads/ipblocklist.txt" \
         "feodo.out_s" "Feodo Tracker" &
download "https://iplists.firehol.org/files/firehol_level1.netset" \
         "firehol_l1.out_s" "FireHOL L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/1.txt" \
         "ipsum_l1.out_xl" "IPsum L1" &
download "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/3.txt" \
         "ipsum_l3.out_s" "IPsum L3" &
wait

for f in tor_exits.out_s spamhaus_drop.out_s sslbl.out_s blocklist_de.out_s \
         cinsarmy.out_l feodo.out_s firehol_l1.out_s ipsum_l1.out_xl ipsum_l3.out_s; do
    [ -s "$f" ] || { echo "  ! Missing: $f"; exit 1; }
done

echo "All downloads successful."
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
        suffix = (base == "blocklist") ? "" : "_" substr(base, 11)
        ga = outdir "/blocklist_ga" suffix ".rsc"
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
        addr = "240.0.0.0/4"
        print addr >> txt
        print "add list=new_blocklist address=\"" addr "\" comment=\"blocklist\"" >> rsc
        print ":set newips ($newips,\"" addr "\")" >> ga
        count++
        print "  " base ": " count " entries" > "/dev/stderr"
    }'
}

build_list "blocklist"    "$CACHE"/*.out_s.ranges &
build_list "blocklist_l"  "$CACHE"/*.out_s.ranges "$CACHE"/*.out_l.ranges &
build_list "blocklist_xl" "$CACHE"/*.ranges &
wait

echo "Done!"
