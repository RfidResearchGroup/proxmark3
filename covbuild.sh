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
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD fpga_compress

#########################################
# Build ARM, no test coverage           #
#########################################
cov-build --dir "$COVDIR" --no-generate-build-id --force make recovery

#########################################
# Build client                          #
#########################################
# make sure to do client after ARM because Coverity retains one build info per file
# and we want the client-side of the common/ analysis
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfkey
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD nonce2key
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mf_nonce_brute
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfd_aes_brute
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD client

#########################################
# Run tests                             #
#########################################
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --test-capture tools/pm3_tests.sh --long
#cov-manage-emit --dir "$COVDIR" list-coverage-known

#########################################
# Import Git annotations (~ git blame)  #
#########################################
cov-import-scm --dir "$COVDIR" --scm git --filename-regex "$PWD" --log ""$COVDIR"/cov-import-scm-log.txt"

post_build_hook
