#!/bin/bash

set -e
. .coverity.conf || exit 1

cov-configure --template --compiler arm-none-eabi-gcc --comptype gcc
