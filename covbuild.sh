#!/bin/bash

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
cov-build --dir "$COVDIR" --no-generate-build-id --force make bootrom
cov-build --dir "$COVDIR" --no-generate-build-id --force make fullimage

#########################################
# Build client                          #
#########################################
# make sure to do client after ARM because Coverity retains one build info per file
# and we want the client-side of the common/ analysis
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD mfkey
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD nonce2key
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --no-generate-build-id --force make CC=$HOSTCC CXX=$HOSTCXX LD=$HOSTLD client

#########################################
# Run tests                             #
#########################################
cov-build --dir "$COVDIR" --c-coverage=gcov --no-network-coverage --test-capture ./pm3test.sh long
#cov-manage-emit --dir "$COVDIR" list-coverage-known

#########################################
# Import Git annotations (~ git blame)  #
#########################################
cov-import-scm --dir "$COVDIR" --scm git --filename-regex "$PWD" --log ""$COVDIR"/cov-import-scm-log.txt"

post_build_hook
