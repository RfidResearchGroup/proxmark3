#!/bin/sh

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

# if you are making your own fork,  change this line to reflect your fork-name
fullgitinfo="RRG/Iceman"
# GIT status  0 = dirty,  1 = clean ,  2 = undecided
clean=2

# Do we have access to git command?
commandGIT=$(env git)

if [ "$commandGIT" != "" ]; then

    # now avoiding the "fatal: No names found, cannot describe anything." error by fallbacking to abbrev hash in such case
    gitversion=$(git describe --dirty --always)
    gitbranch=$(git rev-parse --abbrev-ref HEAD)
    if [ "$1" != "--undecided" ]; then
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
    ls armsrc/*.[ch] common_arm/*.[ch]|grep -v disabled|grep -v version_pm3|xargs sha256sum|sha256sum|grep -o '^.........'
)
cat <<EOF
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
