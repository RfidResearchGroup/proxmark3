#!/bin/bash

set -e
. .coverity.conf || exit 1

pre_build_hook

rm -rf "$COVDIR"
mkdir "$COVDIR"
make clean
$COVBUILD make -j 4 bootrom
$COVBUILD make -j 4 fullimage
$COVBUILD make -j 4 mfkey
$COVBUILD make -j 4 nonce2key
$COVBUILD make -j 4 fpga_compress
# make sure to do client after ARM because Coverity retains one build info per file
# and we want the client-side of the common/ analysis
$COVBUILD make -j 4 client

post_build_hook
