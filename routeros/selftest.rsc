# SPDX-License-Identifier: PolyForm-Noncommercial-1.0.0
# Required Notice: Copyright 2021-2026 multiduplikator (https://gitlab.com/multiduplikator-group/mikrotik_blocklist)
# License: https://polyformproject.org/licenses/noncommercial/1.0.0
#
# Self-test for the blocklist RouterOS update script (RouterOS 7).
# The GitLab upstream's tests/routeros-selftest.rsc, adapted to this fork's
# list file (blocklist.json) and schedule.
#
# Runs your INSTALLED update script against a scratch address-list
# ("blocklist-selftest") and scratch file instead of prod_blocklist /
# blocklist.json, and checks normal and failure behaviour. prod_blocklist
# is never touched: the test refuses to run if any reference to it is left
# after swapping in the scratch names.
#
# Test addresses are from ranges reserved for documentation/testing
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24, 198.18.0.0/15).
# T13 downloads the real list once (~400 KB) into the scratch file to test
# the certificate check and the router clock; it is deleted afterwards.
# T15 creates a temporary script "blocklist-selftest-run" (scratch list and
# file only) to test that a second run is refused; it is removed afterwards.
#
# Usage: upload, then /import file-name=selftest.rsc
# Set the script name below if yours is named differently. Takes about a
# minute, and several on small devices such as the hEX, where every lookup
# in a large address-list takes seconds. Do not run it while the scheduled
# update is running.

{
:local scriptName "blocklist-update"

:local TL "blocklist-selftest"
:local TF "blocklist-selftest.json"
:local pass 0
:local fail 0

# ---------------------------------------------------------------- helpers
# RouterOS does not process \" escapes in arguments to script functions,
# so every string with quotes is built in a variable first.
:local replace do={
    :local s $1
    :local out ""
    :local i [:find $s $2]
    :while ([:typeof $i] != "nil") do={
        :set out ($out . [:pick $s 0 $i] . $3)
        :set s [:pick $s ($i + [:len $2]) [:len $s]]
        :set i [:find $s $2]
    }
    :return ($out . $s)
}
# value of `:local url "..."` in script source $1 ("" if not found)
:local getUrl do={
    :local q "\""
    :local key (":local url " . $q)
    :local i [:find $1 $key]
    :if ([:typeof $i] = "nil") do={ :return "" }
    :local a ($i + [:len $key])
    :local b [:find $1 $q ($a - 1)]
    :return [:pick $1 $a $b]
}
# script source $1 with the url value replaced by $2
:local setUrl do={
    :local q "\""
    :local key (":local url " . $q)
    :local i [:find $1 $key]
    :local a ($i + [:len $key])
    :local b [:find $1 $q ($a - 1)]
    :return ([:pick $1 0 $a] . $2 . [:pick $1 $b [:len $1]])
}
:local writeFile do={
    /file remove [find name=$1]
    /file add name=$1 contents=$2
    :delay 1s
}
:local setList do={
    /ip firewall address-list remove [find list=$1]
    :foreach a in=$2 do={ /ip firewall address-list add list=$1 address=$a }
}
# true if address-list $1 holds exactly the addresses in array $2
:local listIs do={
    :local ids [/ip firewall address-list find list=$1]
    :if ([:len $ids] != [:len $2]) do={ :return false }
    :foreach a in=$2 do={
        :local found false
        :foreach id in=$ids do={
            :if ([:tostr [/ip firewall address-list get $id address]] = [:tostr $a]) do={ :set found true }
        }
        :if (!$found) do={ :return false }
    }
    :return true
}
:local idOf do={
    :foreach id in=[/ip firewall address-list find list=$1] do={
        :if ([:tostr [/ip firewall address-list get $id address]] = $2) do={ :return $id }
    }
    :return ""
}
# disabled-state of the logging rule the update script silences ("" if none)
:local logState do={
    :local rule [:pick [/system logging find where topics~"info"] 0]
    :if ([:typeof $rule] != "id") do={ :return "" }
    :return [:tostr [/system logging get $rule disabled]]
}
# true if policy array $1 contains ftp, read, write, sensitive and test
:local hasPolicies do={
    :foreach p in={"ftp";"read";"write";"sensitive";"test"} do={
        :if ([:typeof [:find $1 $p]] = "nil") do={ :return false }
    }
    :return true
}
# number of log entries whose message contains $1
:local logCount do={ :return [:len [/log find where message~$1]] }
# run script source $1; returns "ok" or "error"
:local run do={
    :local fn [:parse $1]
    :local r "ok"
    :do { $fn } on-error={ :set r "error" }
    :return $r
}
:local check do={
    :if ($1) do={ :put ("  PASS  " . $2) } else={ :put ("  FAIL  " . $2) }
    :return $1
}

# --------------------------------------------- patch the installed script
:if ([:len [/system script find name=$scriptName]] = 0) do={
    :error "selftest: script $scriptName not found -- set the name at the top"
}
:local src [/system script get [find name=$scriptName] source]
:local q "\""
:local pProd ($q . "prod_blocklist" . $q)
:local pFile ($q . "blocklist.json" . $q)
:local pTL ($q . $TL . $q)
:local pTF ($q . $TF . $q)
:if (([:typeof [:find $src $pProd]] = "nil") || ([:typeof [:find $src $pFile]] = "nil")) do={
    :error "selftest: $scriptName does not contain \"prod_blocklist\" and \"blocklist.json\" -- adjust the test"
}
:set src [$replace $src $pProd $pTL]
:set src [$replace $src $pFile $pTF]
:local realUrl [$getUrl $src]
:if ([:len $realUrl] = 0) do={ :error "selftest: no :local url \"...\" found in $scriptName" }
:local srcReal $src
:local srcOffline [$setUrl $src ""]
:local srcBad [$setUrl $src ($realUrl . ".selftest-missing")]
:if (([:typeof [:find $src "prod_blocklist"]] != "nil") || ([:typeof [:find $src $pFile]] != "nil") || ([:typeof [:find $srcOffline $realUrl]] != "nil")) do={
    :error "selftest: could not redirect the script to scratch names -- aborting, nothing was run"
}
:local logBefore [$logState]
/system script remove [find name="blocklist-selftest-run"]

# ------------------------------------------------------------ test data
# Two 32 KB blocks; first octet "198" continues in block 2. 6 entries.
:local now ([:tonsec [:timestamp]] / 1000000000)
:local pad " "
:while ([:len $pad] < 32768) do={ :set pad ($pad . $pad) }
:local b1 ("{\"#\":{\"format\":1,\"entries\":6,\"generated\":" . $now . "},\"198\":{\"51\":{\"100.1\":1,\"100.2\":1,\"100.16/28\":1}},\"203\":{\"0\":{\"113.1\":1}}}")
:local b2 "{\"198\":{\"18\":{\"0.1\":1}},\"192\":{\"0\":{\"2.1\":1}}}"
:local valid ($b1 . [:pick $pad 0 (32768 - [:len $b1])] . $b2)
:local want {"198.51.100.1";"198.51.100.2";"198.51.100.16/28";"203.0.113.1";"198.18.0.1";"192.0.2.1"}
:local before {"198.51.100.1";"203.0.113.1";"198.51.100.16/28";"203.0.113.99";"192.0.2.200"}
:local want9 {"198.51.100.1";"198.51.100.2";"198.51.100.16/28";"203.0.113.1";"198.18.0.1"}
:local small {"198.51.100.1";"192.0.2.200"}
:local r
:local ok

:put "== blocklist self-test =="

# T1: normal update with keep / remove / add, across two blocks
[$writeFile $TF $valid]
[$setList $TL $before]
:local keepId [$idOf $TL "198.51.100.1"]
:set r [$run $srcOffline]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$idOf $TL "198.51.100.1"] = $keepId) && ([$logState] = $logBefore))
:if ([$check $ok "T1 update: 3 kept (same entries), 2 removed, 3 added, CIDR and block continuation"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T2: same file again changes nothing
:set keepId [$idOf $TL "192.0.2.1"]
:set r [$run $srcOffline]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$idOf $TL "192.0.2.1"] = $keepId) && ([$logState] = $logBefore))
:if ([$check $ok "T2 rerun with same file: no change"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T3: first run, list empty: everything added
/ip firewall address-list remove [find list=$TL]
:set r [$run $srcOffline]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$logState] = $logBefore))
:if ([$check $ok "T3 first run (empty list): all 6 added"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T4-T8: bad files must abort with an error and leave the list untouched.
# Each file is built only when needed: variables are limited to ~64 KB.
:foreach name in={"T4 truncated download (header says 6, file has 4)";"T5 corrupt JSON block";"T6 unknown format version";"T7 empty file";"T8 missing file"} do={
    :local content ""
    :local t [:pick $name 0 2]
    :if ($t = "T4") do={ :set content ($b1 . [:pick $pad 0 (32768 - [:len $b1])]) }
    :if ($t = "T5") do={ :set content ($b1 . [:pick $pad 0 (32768 - [:len $b1])] . "{\"198\":{\"18\":{\"0.1\":1}") }
    :if ($t = "T6") do={
        :local fmt1 ($q . "format" . $q . ":1")
        :local fmt2 ($q . "format" . $q . ":2")
        :local f2 [$replace $b1 $fmt1 $fmt2]
        :set content ($f2 . [:pick $pad 0 (32768 - [:len $f2])] . $b2)
    }
    [$setList $TL $before]
    :if ($t = "T8") do={ /file remove [find name=$TF]; :delay 1s } else={ [$writeFile $TF $content] }
    :set r [$run $srcOffline]
    :set ok (($r = "error") && [$listIs $TL $before] && ([$logState] = $logBefore))
    :if ([$check $ok ($name . ": aborted, list untouched")]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }
}

# T9: an entry the router rejects (invalid prefix): the others are
# still added, the run completes, logging restored
:local e21 ($q . "2.1" . $q . ":1")
:local e2bad ($q . "2.1/33" . $q . ":1")
:local b2bad [$replace $b2 $e21 $e2bad]
[$writeFile $TF ($b1 . [:pick $pad 0 (32768 - [:len $b1])] . $b2bad)]
[$setList $TL $before]
:set r [$run $srcOffline]
:set ok (($r = "ok") && [$listIs $TL $want9] && ([$logState] = $logBefore))
:if ([$check $ok "T9 one entry rejected by RouterOS: the other 5 still applied"]) do={ :set pass ($pass + 1) } else={
    :set fail ($fail + 1)
    :put "        result=$r, list now:"
    :foreach id in=[/ip firewall address-list find list=$TL] do={ :put ("          " . [/ip firewall address-list get $id address]) }
}

# T10: an entry wider than /10 is skipped (starts from the 6 valid
# entries, so the change stays below the 30% limit)
:local n6 ($q . "entries" . $q . ":6")
:local n7 ($q . "entries" . $q . ":7")
:local g18 ($q . "18" . $q . ":{" . $q . "0.1" . $q . ":1}")
:local g18w ($g18 . "," . $q . "0" . $q . ":{" . $q . "0.0/8" . $q . ":1}")
:local b1w [$replace $b1 $n6 $n7]
:local b2w [$replace $b2 $g18 $g18w]
[$writeFile $TF ($b1w . [:pick $pad 0 (32768 - [:len $b1w])] . $b2w)]
[$setList $TL $want]
:set r [$run $srcOffline]
:set ok (($r = "ok") && [$listIs $TL $want] && ([$logState] = $logBefore))
:if ([$check $ok "T10 entry wider than /10 (198.0.0.0/8): skipped"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T11: list would change by far more than 30%: abort, list untouched
[$writeFile $TF $valid]
[$setList $TL $small]
:set r [$run $srcOffline]
:set ok (($r = "error") && [$listIs $TL $small] && ([$logState] = $logBefore))
:if ([$check $ok "T11 change from 2 to 6 entries (>30%): aborted, list untouched"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }

# T12: failed download: error, list untouched; info on the previous file
[$writeFile $TF $valid]
[$setList $TL $before]
:local sizeBefore [/file get [find name=$TF] size]
:set r [$run $srcBad]
:local sizeAfter "missing"
:if ([:len [/file find name=$TF]] > 0) do={ :set sizeAfter [/file get [find name=$TF] size] }
:set ok (($r = "error") && [$listIs $TL $before] && ([$logState] = $logBefore))
:if ([$check $ok "T12 failed download: error, list untouched"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r" }
:put ("  info  previous file after a failed download: " . $sizeBefore . " -> " . $sizeAfter . " bytes")

# T13: real download with certificate check. The real list (~28k entries)
# against the 5-entry scratch list trips the size guard after download,
# verification and the age check, so nothing is changed. A list CI
# generated within the last hours must not be reported as stale: this
# also checks that the router clock and [:timestamp] are right.
[$setList $TL $before]
:local staleBefore [$logCount "list was generated"]
:local guardBefore [$logCount "list would change from"]
:set r [$run $srcReal]
:local got 0
:if ([:len [/file find name=$TF]] > 0) do={ :set got [/file get [find name=$TF] size] }
:local staleNew ([$logCount "list was generated"] - $staleBefore)
:local guardNew ([$logCount "list would change from"] - $guardBefore)
:set ok (($r = "error") && ($got > 100000) && ($guardNew = 1) && ($staleNew = 0) && [$listIs $TL $before] && ([$logState] = $logBefore))
:if ([$check $ok "T13 real download with certificate check: verified, not stale, list untouched"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r size=$got guard-logs=$guardNew stale-logs=$staleNew" }

# T14: a list generated in 2001 is still applied, with a staleness warning
:local gNow ($q . "generated" . $q . ":" . $now)
:local gOld ($q . "generated" . $q . ":1000000000")
:local b1old [$replace $b1 $gNow $gOld]
[$writeFile $TF ($b1old . [:pick $pad 0 (32768 - [:len $b1old])] . $b2)]
[$setList $TL $before]
:set staleBefore [$logCount "list was generated"]
:set r [$run $srcOffline]
:set staleNew ([$logCount "list was generated"] - $staleBefore)
:set ok (($r = "ok") && [$listIs $TL $want] && ($staleNew = 1) && ([$logState] = $logBefore))
:if ([$check $ok "T14 old list (generated 2001): applied, staleness warning logged"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        result=$r stale-logs=$staleNew" }

# T15: only one run at a time. A copy of the script (scratch list and file,
# same policies as the real one) runs in the background and waits 5 s at
# the end; a second start of the same script during that time must stop
# with a warning, and the first one must complete normally. The test waits
# up to 10 minutes for it, as one run takes about a minute on a hEX.
[$writeFile $TF $valid]
[$setList $TL $before]
/system script add name="blocklist-selftest-run" policy=ftp,read,write,sensitive,test source=($srcOffline . "\n:delay 5s")
:local busyBefore [$logCount "another run is still in progress"]
:local startedBefore [$logCount "blocklist-DIFF: === STARTED ==="]
:local doneBefore [$logCount "blocklist-DIFF: === COMPLETED ==="]
:execute {/system script run blocklist-selftest-run}
:delay 2s
:set r [$run "/system script run blocklist-selftest-run"]
:local waited 0
:while (([:len [/system script job find where script="blocklist-selftest-run"]] > 0) && ($waited < 600)) do={
    :delay 1s
    :set waited ($waited + 1)
}
:local busyNew ([$logCount "another run is still in progress"] - $busyBefore)
:local startedNew ([$logCount "blocklist-DIFF: === STARTED ==="] - $startedBefore)
:local doneNew ([$logCount "blocklist-DIFF: === COMPLETED ==="] - $doneBefore)
:set ok (($busyNew = 1) && ($startedNew = 1) && ($doneNew = 1) && [$listIs $TL $want] && ([$logState] = $logBefore))
/system script remove [find name="blocklist-selftest-run"]
:if ([$check $ok "T15 second run while one is in progress: refused, first run completes"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        second-run=$r refused-logs=$busyNew started=$startedNew completed=$doneNew (expect refused-logs=1 started=1 completed=1)" }

# T16: the script and every scheduler entry that runs it need ftp, read,
# write, sensitive and test. A scheduled fetch that saves a file needs ftp
# (since RouterOS 7.13) and sensitive (measured on 7.24.5); a manual run
# uses your own rights, so a missing policy only breaks scheduled runs
# ("cannot open file: permission denied").
:local scriptOk [$hasPolicies [/system script get [find name=$scriptName] policy]]
:local schedCount 0
:local schedBad ""
:foreach id in=[/system scheduler find where on-event~$scriptName] do={
    :set schedCount ($schedCount + 1)
    :if (![$hasPolicies [/system scheduler get $id policy]]) do={ :set schedBad ($schedBad . " " . [/system scheduler get $id name]) }
}
:set ok ($scriptOk && ($schedCount > 0) && ([:len $schedBad] = 0))
:if ([$check $ok "T16 policies: script and its scheduler entries have ftp, read, write, sensitive, test"]) do={ :set pass ($pass + 1) } else={ :set fail ($fail + 1); :put "        script-ok=$scriptOk scheduler-entries=$schedCount lacking-policies:$schedBad" }

# cleanup
/ip firewall address-list remove [find list=$TL]
/file remove [find name=$TF]
:put ("== " . $pass . " passed, " . $fail . " failed ==")
}
