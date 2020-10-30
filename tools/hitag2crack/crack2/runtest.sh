#!/usr/bin/env bash

if [ "$1" == "" ]; then
echo "runtest.sh testfile"
echo "testfile name should be of the form:"
echo "keystream.key-KEY.uid-UID.nR-NR"
exit 1
fi

filename=$1

UIDV=`echo $1 | cut -d'-' -f3 | cut -d'.' -f1`
NR=`echo $1 | cut -d'-' -f4`
KEYV=`echo $1 | cut -d'-' -f2 | cut -d'.' -f1`

echo "********************"
echo "FILENAME      = $filename"
echo "UID           = $UIDV"
echo "NR            = $NR"
echo "Expected KEY  = $KEYV"

./ht2crack2search $filename $UIDV $NR
echo "Expected KEY  = $KEYV"
echo "********************"
echo ""
