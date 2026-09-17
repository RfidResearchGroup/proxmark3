#!/usr/bin/env bash

set -e
. .coverity.conf || exit 1

pre_build_hook

mkdir -p "$COVDIR"
make clean
cov-build --dir "$COVDIR" --initialize

#########################################
# Build Host prerequisites              #
#########################################
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD fpga_compress

#########################################
# Build ARM, no test coverage           #
#########################################
cov-build --dir "$COVDIR" make recovery

#########################################
# Build client                          #
#########################################
# make sure to do client after ARM because Coverity retains one build info per file
# and we want the client-side of the common/ analysis
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD cryptorf
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfc_card_only
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfc_card_reader
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfulc_des_brute
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfd_aes_brute
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD hitag2crack
cov-build --dir "$COVDIR" make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD client

# test-capture step dropped — Test Advisor only, not in the free tarball

#########################################
# Import Git annotations (~ git blame)  #
#########################################
cov-import-scm --dir "$COVDIR" --scm git --filename-regex "$PWD" --log "$COVDIR/cov-import-scm-log.txt"

post_build_hook
