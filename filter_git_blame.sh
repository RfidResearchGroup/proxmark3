#!/usr/bin/env bash

set -euo pipefail

git log --format='%H%n%B%x00' | awk -v RS='\0' '
    BEGIN {
        i = 0
        patterns[i++] = "^make style$"
        patterns[i++] = "^make miscchecks$"
        patterns[i++] = "^cppcheck"
    }
    {
        if (!match($0, /^\n?([0-9A-Fa-f]{40})\n(.*)$/, matches)) next

        # Only print once, even if matches multiple table entries
        do_print = 0

        # message ... remove trailing whitepace and blank lines
        msg = matches[2]
        sub(/( *(\r?\n))+$/, "", msg)

        # try each pattern in the table
        for (i in patterns) {
            if (msg ~ patterns[i]) {
                do_print = 1
            }
        }
        if (do_print) {
            print matches[1]
        }
    }
' | sort -u -f > .git-blame-ignore-revs

