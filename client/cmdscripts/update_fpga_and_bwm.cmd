#!/usr/bin/env -S pm3 -s
hw fpga config -f PM5_FPGA_fix_loedge_bug.bin
hf 14a read --drop

hw bwm setcap --cap 500
hw bwm upgrade -f proxmark5_ble_wifi_module.bin

