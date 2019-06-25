#!/bin/bash

# Example using Segger Jlink:
CONFIG_CHIP=chip-at91sam7s.cfg
CONFIG_IF=interface-jlink.cfg
IMAGE=../../recovery/proxmark3_recovery.bin

if [ ! -e "$IMAGE" ]; then
    echo "$IMAGE missing. Abort!"
    exit 1
fi
openocd -f $CONFIG_IF -f $CONFIG_CHIP -c "init;halt;flash erase_sector 0 0 15;flash erase_sector 1 0 15;flash write_image $IMAGE 0x100000;exit"
