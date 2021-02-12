#!/usr/bin/env bash

cd $(dirname "$0")
. openocd_configuration || exit 1

if [ ! -e "$IMAGE" ]; then
    echo "$IMAGE missing. Abort!"
    exit 1
fi
openocd -f $CONFIG_GEN -f $CONFIG_IF -f $CONFIG_BOARD -c "init;halt;flash erase_sector 0 0 15;flash erase_sector 1 0 15;flash write_image $IMAGE 0x100000;exit"
