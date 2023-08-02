#!/usr/bin/env sh

if [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "" ]; then
    echo "To report a short string about the current version:"
    echo "   $0 --short"
    echo "To regenerate version_pm3.c if needed:"
    echo "   $0 [--force] [--undecided] path/to/version_pm3.c"
    exit 0
fi

# Output a version_pm3.c file that includes information about the current build
# From mkversion.pl
# pure sh POSIX as now even on Windows we use WSL or ProxSpace with sh available

# Clear environment locale so that git will not use localized strings
export LC_ALL="C"
export LANG="C"

SHORT=false
if [ "$1" = "--short" ]; then
    SHORT=true
    shift
fi
FORCE=false
if [ "$1" = "--force" ]; then
    FORCE=true
    shift
fi
UNDECIDED=false
if [ "$1" = "--undecided" ]; then
    UNDECIDED=true
    shift
fi
VERSIONSRC="$1"

if ! $SHORT && [ "$VERSIONSRC" = "" ]; then
    echo "Error: $0 is missing its destination filename"
    exit 1
fi

if $SHORT && [ "$VERSIONSRC" != "" ]; then
    echo "Error: can't output a short string and generate file at the same time"
    exit 1
fi

# if you are making your own fork,  change this line to reflect your fork-name
fullgitinfo="Iceman"
# GIT status  0 = dirty,  1 = clean ,  2 = undecided
clean=2

# Do we have access to git command?
commandGIT=$(env git)

if [ "$commandGIT" != "" ]; then

    # now avoiding the "fatal: No names found, cannot describe anything." error by fallbacking to abbrev hash in such case
    gitversion=$(git describe --dirty --always)
    gitbranch=$(git rev-parse --abbrev-ref HEAD)
    if $UNDECIDED; then
        if [ "$gitversion" != "${gitversion%-dirty}" ]; then
            clean=0
        else
            clean=1
        fi
    fi
    if [ "$gitbranch" != "" ] && [ "$gitversion" != "" ]; then
        fullgitinfo="${fullgitinfo}/${gitbranch}/${gitversion}"
        ctime="$(date '+%Y-%m-%d %H:%M:%S')"
    else
        fullgitinfo="${fullgitinfo}/master/release (git)"
    fi
else
    fullgitinfo="${fullgitinfo}/master/release (no_git)"
    dl_time=$(stat --printf="%y" ../README.md)
    # POSIX way...
    ctime=${dl_time%.*}
fi
if $SHORT; then
    echo "$fullgitinfo"
    exit 0
fi

# Crop so it fits within 50 characters C string, so max 49 chars
# POSIX way
fullgitinfoextra="${fullgitinfo#??????????????????????????????????????????????}"
if [ "$fullgitinfoextra" != "$fullgitinfo" ]; then
    fullgitinfo46="${fullgitinfo%"${fullgitinfoextra}"}"
    fullgitinfo="${fullgitinfo46}..."
fi
sha=$(
    pm3path=$(dirname -- "$0")/..
    cd "$pm3path" || return
    # did we find the src?
    [ -f armsrc/appmain.c ] || return
    ls armsrc/*.[ch] common_arm/*.[ch]|grep -E -v "(disabled|version_pm3|fpga_version_info)"|sort|xargs sha256sum -t|sha256sum|cut -c -9
)
if [ "$sha" = "" ]; then
  sha="no sha256"
fi

REDO=true
if ! $FORCE && [ -f "$VERSIONSRC" ]; then
    # version src file exists, check if it needs to be updated
    # file parser quite fragile, be careful if you edit VERSIONSRC template below...
    oldclean=$(sed '13s/.*\([0-9]\+\).*/\1/;13!d' "$VERSIONSRC")
    oldfullgitinfo=$(sed '14s/.*"\([^"]*\)".*/\1/;14!d' "$VERSIONSRC")
    oldsha=$(sed '16s/.*"\([^"]*\)".*/\1/;16!d' "$VERSIONSRC")
    if [ "$oldclean" = "$clean" ] && [ "$oldfullgitinfo" = "$fullgitinfo" ] && [ "$oldsha" = "$sha" ]; then
        REDO=false
    fi
fi
if $REDO; then
    # use a tmp file to avoid concurrent call to mkversion to parse a half-written file.
    cat > "${VERSIONSRC}.tmp" <<EOF
#include "common.h"
/* Generated file, do not edit */
#ifndef ON_DEVICE
#define SECTVERSINFO
#else
#define SECTVERSINFO __attribute__((section(".version_information")))
#endif

const struct version_information_t SECTVERSINFO g_version_information = {
    VERSION_INFORMATION_MAGIC,
    1,
    1,
    $clean,
    "$fullgitinfo",
    "$ctime",
    "$sha"
};
EOF
    mv "${VERSIONSRC}.tmp" "${VERSIONSRC}"
fi
