#!/bin/bash

## 2016-01-16,  Iceman
## build script for Coverity Scan of the proxmark3 source code

## clean up pre-compiled objects.
make clean

## coverity build
cov-build --dir cov-int make all UBUNTU_1404_QT4=1

## create tarball
tar cfz proxmark3.all.`date --date now +%Y%m%d%H%M%S`.tgz cov-int
echo "Coverity build file is ready"


## clean up build folders
rm -rf cov-int
echo "Coverity build cleaned"

## upload tarball to Coverity.com
## not using it.
# curl --form project=proxmark-iceman-fork --form token=PUT_YOUR_API_TOKEN_HERE --form email=PUT_YOU_EMAIL@HERE --form file=@proxmark3.tgz --form version=0.4.0 --form description=Description http://scan5.coverity.com/cgi-bin/upload.py


