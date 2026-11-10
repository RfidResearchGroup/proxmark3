#!/usr/bin/env -S pm3 -s
hw fpga config -f fpga_pm5.bin
hf 14a read --drop

hw bwm setcap --cap 500
hw bwm upgrade -f proxmark5_ble_wifi_module.bin

