#!/usr/bin/env bash

set -e
. .coverity.conf || exit 1

# cov-configure --list-configured-compilers text
cov-configure --template --compiler arm-none-eabi-gcc --comptype gcc
cov-configure --template --compiler $HOSTCC --comptype gcc
