#!/usr/bin/env bash

cd $(dirname "$0")
. openocd_configuration || exit 1

echo "*********************************************"
echo "Connect to OpenOCD via: telnet localhost $(awk '/^telnet_port/{print$2}' $CONFIG_GEN)"
echo "*********************************************"
openocd -f $CONFIG_GEN -f $CONFIG_IF -f $CONFIG_BOARD
