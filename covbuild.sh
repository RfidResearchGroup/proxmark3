#!/bin/bash

## 2016-01-16,  Iceman
## build script for Coverity Scan of the proxmark3 source code

## clean up pre-compiled objects.
make clean

## coverity build
/home/user/cov-analysis-linux-2017.07/bin/cov-build --dir cov-int make all

## delete all previous tarballs
rm proxmark3.all.*.tgz

##
VERSION="0.1.`date --date now +%H%M`"
TODAY="`date --date now +%Y%m%d.%H%M`"
DESCNAME="autoMango.$TODAY"
FILENAME=proxmark3.all.$TODAY.tgz

## create tarball
tar cfz $FILENAME cov-int
echo "Coverity build file is ready"

## clean up build folders
rm -rf cov-int
echo "Coverity build cleaned"

## upload tarball to Coverity.com
curl --form token=dY262wIFmfkcRkA5Pyw0eA \
 --form email=herrmann1001@gmail.com \
  --form file=@$FILENAME \
  --form version="$VERSION" \
  --form description="$DESCNAME" \
  https://scan.coverity.com/builds?project=proxmark3_iceman_fork
echo "tarball uploaded to Coverity for analyse"
