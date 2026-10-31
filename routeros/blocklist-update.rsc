# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Required Notice: Copyright 2021-2026 multiduplikator (https://gitlab.com/multiduplikator-group/mikrotik_blocklist)
# License: https://polyformproject.org/licenses/noncommercial/1.0.0
#
# Source of the RouterOS script "blocklist-update" (install.rsc loads it).
# Adapted from the GitLab upstream's README update script: list URL and
# file, maxAge 12 h for this fork's 3-hourly GitHub Actions schedule, the
# staleness message, and logging rules are left alone (upstream silences
# the first "info" rule during the change).
:local url "https://raw.githubusercontent.com/Davie3/mikrotik_blocklist/main/blocklist.json"
:local file "blocklist.json"
:local listName "prod_blocklist"
:local block 32768
# Safety limits: abort if the list would grow or shrink by more than
# maxChange percent (raise it once when switching to another tier), and
# never add an entry wider than /minPrefix. Warn if the list is older than
# maxAge hours (the lists are regenerated every 3 hours, but GitHub skips
# scheduled runs at times).
:local maxChange 30
:local minPrefix 10
:local maxAge 12

# Only one run at a time: a second run (e.g. started by hand while the
# scheduled one is busy) stops before changing anything.
:local job [:jobname]
:if (([:len $job] > 0) && ([/system script job print count-only as-value where script=$job] > 1)) do={
    :log warning "blocklist-DIFF: another run is still in progress, skipped"
    :error "blocklist update already running"
}

:log info "blocklist-DIFF: === STARTED ==="
:local startTime [:timestamp]

# ----------------------------------------------------------------------------
# STEP 0: Download. Leave url empty to skip this and use $file as it is.
# ----------------------------------------------------------------------------
:if ($url != "") do={
    :do {
        # Verify the server certificate. Uses RouterOS's built-in root CAs
        # (default since 7.21); on older versions import a CA bundle.
        /tool fetch url=$url dst-path=$file check-certificate=yes-without-crl
    } on-error={
        :log error "blocklist-DIFF: download failed, list left unchanged"
        :error "blocklist download failed"
    }
}

# ----------------------------------------------------------------------------
# STEP 1: Load and verify the new list. Nothing is changed yet.
# The file is a sequence of 32 KB blocks, each one JSON object:
#   first octet -> second octet -> rest of the address -> 1
# deserialize builds each block's nested keyed array in one call.
# ----------------------------------------------------------------------------
:if ([:len [/file find name=$file]] = 0) do={
    :log error "blocklist-DIFF: $file not found, aborting"
    :error "blocklist file missing"
}
:local size [/file get $file size]
:local bl [:toarray ""]
:local format 0
:local expected -1
:local generated ""
:do {
    :for off from=0 to=($size - 1) step=$block do={
        :local r [/file read file=$file offset=$off chunk-size=$block as-value]
        :local data ($r->"data")
        :if ([:typeof $data] = "nothing") do={ :set data $r }
        :foreach o1,g in=[:deserialize from=json options=json.no-string-conversion $data] do={
            :if ($o1 = "#") do={
                :set format ($g->"format")
                :set expected ($g->"entries")
                :set generated ($g->"generated")
            } else={
                :if ([:typeof ($bl->$o1)] = "nothing") do={
                    :set ($bl->$o1) $g
                } else={
                    # first octet continues from the previous block: merge
                    :local b1 ($bl->$o1)
                    :foreach o2,rs in=$g do={ :set ($b1->$o2) $rs }
                    :set ($bl->$o1) $b1
                }
            }
        }
    }
} on-error={
    :log error "blocklist-DIFF: $file is unreadable or not valid JSON (incomplete download?), aborting"
    :error "blocklist file unreadable"
}
:local total 0
:foreach o1,g in=$bl do={ :foreach o2,rs in=$g do={ :set total ($total + [:len $rs]) } }
:if (($format != 1) || ($total = 0) || ($total != $expected)) do={
    :log error "blocklist-DIFF: $file invalid (format $format, $total of $expected entries), aborting"
    :error "blocklist file invalid"
}
# The list is still applied when it is old: stale data beats no update.
:if ([:typeof $generated] = "num") do={
    :local age ((([:tonsec [:timestamp]] / 1000000000) - $generated) / 3600)
    :if ($age >= $maxAge) do={
        :log warning "blocklist-DIFF: list was generated $age hours ago (limit $maxAge); is the GitHub Actions schedule still running?"
    }
} else={
    :log warning "blocklist-DIFF: list has no generation time"
}
:local current [:len [/ip firewall address-list find list=$listName]]
:if ($current > 0) do={
    :local change ($total - $current)
    :if ($change < 0) do={ :set change (0 - $change) }
    :if (($change * 100) > ($current * $maxChange)) do={
        :log error "blocklist-DIFF: list would change from $current to $total entries (limit $maxChange%), aborting"
        :error "blocklist change too large"
    }
}
:log info "blocklist-DIFF: Loaded $total entries, list has $current"

# ----------------------------------------------------------------------------
# STEP 2: Walk the current list. Entries still listed are kept and ticked
# off in $bl; all others are removed. STEP 3: what is left in $bl is new.
# ----------------------------------------------------------------------------
:local kept 0
:local removed 0
:local added 0
:local failed 0
:local skipped 0

:do {
    /ip firewall address-list
    :foreach id in=[find list=$listName] do={
        :local s [:tostr [get $id address]]
        :local i1 [:find $s "."]
        :local i2 [:find $s "." $i1]
        :local p1 [:pick $s 0 $i1]
        :local p2 [:pick $s ($i1 + 1) $i2]
        :local rest [:pick $s ($i2 + 1) [:len $s]]
        :if ([:typeof ((($bl->$p1)->$p2)->$rest)] != "nothing") do={
            # still listed: keep it, and tick it off in $bl
            :set ((($bl->$p1)->$p2)->$rest)
            :set kept ($kept + 1)
        } else={
            remove $id
            :set removed ($removed + 1)
        }
    }

    :foreach o1,g in=$bl do={
        :foreach o2,rs in=$g do={
            :foreach rest,v in=$rs do={
                :local plen 32
                :local slash [:find $rest "/"]
                :if ([:typeof $slash] != "nil") do={ :set plen [:tonum [:pick $rest ($slash + 1) [:len $rest]]] }
                :if (([:typeof $plen] = "num") && ($plen < $minPrefix)) do={
                    :set skipped ($skipped + 1)
                } else={
                    # one bad entry must not stop the others
                    :do {
                        add list=$listName address=($o1 . "." . $o2 . "." . $rest)
                        :set added ($added + 1)
                    } on-error={ :set failed ($failed + 1) }
                }
            }
        }
    }
} on-error={
    :log error "blocklist-DIFF: failed after removing $removed and adding $added entries"
    :error "blocklist update failed"
}

:set bl

:local finalCount [:len [/ip firewall address-list find list=$listName]]
:log info "blocklist-DIFF: === COMPLETED ==="
:log info "blocklist-DIFF: Kept=$kept, Removed=$removed, Added=$added, Total=$finalCount"
:if (($failed + $skipped) > 0) do={
    :log warning "blocklist-DIFF: $failed entries could not be added, $skipped skipped as wider than /$minPrefix"
}
:if ($finalCount != ($total - $failed - $skipped)) do={
    :log warning ("blocklist-DIFF: list has " . $finalCount . " entries, expected " . ($total - $failed - $skipped))
}
:log info ("blocklist-DIFF: Duration=" . ([:timestamp] - $startTime))
