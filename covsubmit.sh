#!/usr/bin/env bash

set -e
. .coverity.conf || exit 1

pre_submit_hook

echo "Checking upload permissions..."

if ! up_perm="$(wget https://scan.coverity.com/api/upload_permitted --post-data "token=${COVTOKEN}&project=${COVPROJECT}" -q -O -)"; then
    echo "Coverity Scan API access denied: bad token?"
    exit 1
fi

# Really up_perm is a JSON response with either
# {upload_permitted:true} or {next_upload_permitted_at:<date>}
# We do some hacky string parsing instead of properly parsing it.
case "$up_perm" in
    *upload_permitted*true*)
        echo "Coverity Scan: upload permitted"
        ;;
    *next_upload_permitted_at*)
        if [ -z "$COVERITY_DRYRUN" ]; then
            echo "Coverity Scan: upload quota reached; stopping here"
            # Exit success as this isn't a build error.
            exit 0
        else
            echo "Coverity Scan: upload quota reached, continuing dry run"
        fi
        ;;
    *)
        echo "Coverity Scan upload check: unexpected result $up_perm"
        exit 1
        ;;
esac



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
  https://scan.coverity.com/builds?project="${COVPROJECT}" | tee -a "${LOGFILENAME}" ; test "${PIPESTATUS[0]}" -eq 0  || exit $?
echo "tarball uploaded to Coverity for analyse"

post_submit_hook
