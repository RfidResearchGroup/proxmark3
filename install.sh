#!/bin/bash

set -x

# This is for linux ppl and it works on Ubuntu distros. Don't know about Kali.

echo "Updating your system..."

# install dependencies for Proxmark3 source code.
sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev gcc-arm-none-eabi 
sudo apt-get install libusb-0.1-4 libusb-dev libqt4-dev libncurses5-dev perl pkg-config wget

#cleaning up
sudo apt-get install -f -y
sudo apt-get autoremove -y
sudo apt-get autoclean -y
sudo apt-get clean -y
sudo apt-get update

# install iceman fork - proxmark3 
git clone https://github.com/iceman1001/proxmark3.git
(
   cd proxmark3 || exit 1
   git reset --hard
   git clean -dfx
   make clean
   make all
   # Copy blacklist rules into /etc/udev/rules.d
   # check the Makefile for details
   sudo make udev
)

# Where is my device?
#dmesg | tail -10

echo "Done."