#!/usr/bin/env bash
# Iceman 2022
#
# This script is to be run from proxmark root folder inside the docker env
# cd proxmark;
# docker/archlinux/run_tests.sh;
#
# Script contains two phases.
#
# -- Init / setup phase
# Script to be run inside docker env. First install some dependencies for docker image.
#
# -- Build phase begins
# make builds
# cmake client builds
# of the different possible PLATFORM (PM3RDV4 / PM3GENERIC) and BTADDON combos

cat << EOF |sudo tee -a /etc/pacman.conf

[testing]
Include = /etc/pacman.d/mirrorlist

[community-testing]
Include = /etc/pacman.d/mirrorlist

[staging]
Include = /etc/pacman.d/mirrorlist
EOF

sudo pacman -Syu

# search available versions
pacman -Ss '^arm-none-eabi-gcc$'
pacman -Ss '^gcc$'

# depending on where the latest bleeding edge is:
# sudo pacman -S community-testing/arm-none-eabi-gcc
# sudo pacman -S arm-none-eabi-gcc
# sudo pacman -S staging/gcc
# sudo pacman -S testing/gcc
# sudo pacman -S gcc

sudo pacman --noconfirm -S python-pip
python3 -m pip install ansicolors sslcrypto

# replace egrep to silence warning
sed -i 's/egrep/grep -E/g' tools/pm3_tests.sh

# Makefile build tests
make clean; make -j PLATFORM=PM3GENERIC; tools/pm3_tests.sh --long || exit 1
make clean; make -j PLATFORM=PM3RDV4; tools/pm3_tests.sh --long || exit 1
make clean; make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON; tools/pm3_tests.sh --long || exit 1

# cmake client build test
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client --long || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3GENERIC ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client --long || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3RDV4 ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client --long || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client || exit 1

