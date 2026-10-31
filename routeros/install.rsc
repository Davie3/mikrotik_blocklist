# Installs or updates the JSON blocklist update on the router (RouterOS 7).
#
# Usage: upload blocklist-update.rsc and install.rsc, check the settings
# below, then /import file-name=install.rsc
# Safe to run again, e.g. after editing blocklist-update.rsc.
#
# 1. Creates or updates /system script $scriptName from $srcFile. The list
#    URL, file, address-list name and safety limits are set at the top of
#    blocklist-update.rsc.
# 2. Disables the schedulers of the old two-script .rsc setup (scripts that
#    import blocklist_ga*.rsc or fill $newips). The old scripts are kept;
#    remove them once the new update works.
# 3. Creates or updates the scheduler entry.
# 4. Adds two raw prerouting drop rules: from listed sources arriving on
#    $wanList, and to listed destinations from any other interface (LAN,
#    VLANs, VPNs: everything not in $wanList). They go before the
#    first old drop rule for the list (so a bypass rule above it stays
#    above them), or at the top of the chain if there is none. Then the old
#    drop rules are disabled.
#
# It does not run the update: the address-list stays as it is until the
# first run, so protection never lapses.

{
:local scriptName "blocklist-update"
:local srcFile "blocklist-update.rsc"
:local wanList "WAN"
:local interval 3h
:local startTime 00:40:00

:local cSrc "blocklist-update: drop from listed sources"
:local cDst "blocklist-update: drop to listed destinations"

# value of `:local <name> "..."` in script source $1 ("" if not found)
:local getVar do={
    :local q "\""
    :local key (":local " . $2 . " " . $q)
    :local i [:find $1 $key]
    :if ([:typeof $i] = "nil") do={ :return "" }
    :local a ($i + [:len $key])
    :local b [:find $1 $q ($a - 1)]
    :return [:pick $1 $a $b]
}

# ------------------------------------------------------------ checks
:if ([:len [/file find name=$srcFile]] = 0) do={ :error "install: $srcFile not found, upload it first" }
:if ([/file get [find name=$srcFile] size] > 32768) do={ :error "install: $srcFile is larger than 32 KB" }
:local r [/file read file=$srcFile offset=0 chunk-size=32768 as-value]
:local src ($r->"data")
:if ([:typeof $src] = "nothing") do={ :set src $r }
:local listName [$getVar $src "listName"]
:if (([:len $listName] = 0) || ([:typeof [:find $src "blocklist-DIFF"]] = "nil")) do={
    :error "install: $srcFile does not look like the update script"
}
:if ([:len [/interface list find name=$wanList]] = 0) do={ :error "install: interface list $wanList not found, create it or set wanList" }
:if ([:len [/interface list member find list=$wanList]] = 0) do={ :error "install: interface list $wanList has no members" }
:local notWan ("!" . $wanList)

# ------------------------------------------------------- 1. script
# A scheduled /tool fetch that saves a file needs ftp and sensitive on the
# script and on its scheduler entry; a manual run works without them.
:local sid [/system script find name=$scriptName]
:if ([:len $sid] = 0) do={
    /system script add name=$scriptName policy=ftp,read,write,sensitive,test source=$src
    :put "install: added script $scriptName (address-list $listName)"
} else={
    /system script set $sid policy=ftp,read,write,sensitive,test source=$src
    :put "install: updated script $scriptName (address-list $listName)"
}

# ------------------------------------------------- 2. old .rsc setup
:local old [:toarray ""]
:foreach id in=[/system script find where name!=$scriptName] do={
    :local s [/system script get $id source]
    :if (([:typeof [:find $s "blocklist_ga"]] != "nil") || ([:typeof [:find $s "newips"]] != "nil")) do={
        :set old ($old, [/system script get $id name])
    }
}
:foreach id in=[/system scheduler find where name!=$scriptName] do={
    :local ev [/system scheduler get $id on-event]
    :local hit (([:typeof [:find $ev "blocklist_ga"]] != "nil") || ([:typeof [:find $ev "newips"]] != "nil"))
    :foreach n in=$old do={
        :if (($ev = $n) || ([:typeof [:find $ev ("run " . $n)]] != "nil")) do={ :set hit true }
    }
    :if ($hit && ![/system scheduler get $id disabled]) do={
        /system scheduler disable $id
        :put ("install: disabled old scheduler " . [/system scheduler get $id name])
    }
}
:foreach n in=$old do={ :put ("install: old script " . $n . " kept but no longer scheduled; remove it once the new update works") }

# ---------------------------------------------------- 3. scheduler
:local schId [/system scheduler find name=$scriptName]
:if ([:len $schId] = 0) do={
    /system scheduler add name=$scriptName interval=$interval start-time=$startTime on-event=$scriptName policy=ftp,read,write,sensitive,test
    :put "install: added scheduler $scriptName"
} else={
    /system scheduler set $schId interval=$interval start-time=$startTime on-event=$scriptName policy=ftp,read,write,sensitive,test disabled=no
    :put "install: updated scheduler $scriptName"
}

# ---------------------------------------------------- 4. raw rules
:local oldRules ([/ip firewall raw find where chain=prerouting action=drop src-address-list=$listName comment!=$cSrc], [/ip firewall raw find where chain=prerouting action=drop dst-address-list=$listName comment!=$cDst])
:local anchor
:foreach id in=[/ip firewall raw find where chain=prerouting dynamic=no] do={
    :if (([:typeof $anchor] != "id") && (([:len $oldRules] = 0) || ([:typeof [:find $oldRules $id]] != "nil"))) do={ :set anchor $id }
}

:local id [/ip firewall raw find where comment=$cSrc]
:if ([:len $id] = 0) do={
    :if ([:typeof $anchor] = "id") do={
        /ip firewall raw add chain=prerouting action=drop in-interface-list=$wanList src-address-list=$listName comment=$cSrc place-before=$anchor
    } else={
        /ip firewall raw add chain=prerouting action=drop in-interface-list=$wanList src-address-list=$listName comment=$cSrc
    }
    :put "install: added raw rule: $cSrc"
} else={
    /ip firewall raw set $id chain=prerouting action=drop in-interface-list=$wanList src-address-list=$listName disabled=no
}
:set id [/ip firewall raw find where comment=$cDst]
:if ([:len $id] = 0) do={
    :if ([:typeof $anchor] = "id") do={
        /ip firewall raw add chain=prerouting action=drop in-interface-list=$notWan dst-address-list=$listName comment=$cDst place-before=$anchor
    } else={
        /ip firewall raw add chain=prerouting action=drop in-interface-list=$notWan dst-address-list=$listName comment=$cDst
    }
    :put "install: added raw rule: $cDst"
} else={
    /ip firewall raw set $id chain=prerouting action=drop in-interface-list=$notWan dst-address-list=$listName disabled=no
}

:foreach o in=$oldRules do={
    :if (![/ip firewall raw get $o disabled]) do={
        /ip firewall raw disable $o
        :put ("install: disabled old raw rule " . [/ip firewall raw get $o comment])
    }
}

:put "install: done. Check the rule order with /ip firewall raw print, then run the self-test (see README)."
}
