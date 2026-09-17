#!/usr/bin/env bash

cd $(dirname "$0")
. openocd_configuration || exit 1

if [ -e "$DUMP" ]; then
    echo "$DUMP exists already. Abort!"
    exit 1
fi
openocd -f $CONFIG_GEN -f $CONFIG_IF -f $CONFIG_BOARD -c "init;halt;dump_image $DUMP 0x100000 0x80000;exit"
