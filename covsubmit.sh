#!/bin/bash

set -e
. .coverity.conf || exit 1

pre_submit_hook

## delete all previous tarballs
rm -f proxmark3.all.*.tgz proxmark3.all.*.log

TODAY="$(date --date now +%Y%m%d.%H%M)"
VERSION="0.1.$TODAY"
DESCNAME="manual_by_$NICKNAME.$TODAY.$(git describe --dirty --always)"
FILENAME="proxmark3.all.$TODAY.tgz"
LOGFILENAME="${FILENAME/.tgz/.log}"

## create tarball
tar cfz "$FILENAME" "$COVDIR" || exit $?
echo "Coverity build file is ready"

## upload tarball to Coverity.com
curl --progress-bar --fail \
  --form token="$COVTOKEN" \
  --form email="$COVLOGIN" \
  --form file="@$FILENAME" \
  --form version="$VERSION" \
  --form description="$DESCNAME" \
  https://scan.coverity.com/builds?project=Proxmark3+RRG+Iceman+repo | tee -a "${LOGFILENAME}" ; test "${PIPESTATUS[0]}" -eq 0  || exit $?
echo "tarball uploaded to Coverity for analyse"

post_submit_hook
