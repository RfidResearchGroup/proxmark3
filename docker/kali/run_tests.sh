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

sudo apt update
sudo apt install -y python3-minimal
sudo apt install -y python3-pip
python3 -m pip install ansicolors sslcrypto

# replace egrep to silence warning
#sed -i 's/egrep/grep -E/g' tools/pm3_tests.sh

# Makefile build tests
make clean; make -j PLATFORM=PM3GENERIC; tools/pm3_tests.sh --long || exit 1
make clean; make -j PLATFORM=PM3RDV4; tools/pm3_tests.sh --long || exit 1
make clean; make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON; tools/pm3_tests.sh --long || exit 1
# sudo make install; pushd /tmp; proxmark3 -c 'data load -f lf_EM4x05.pm3;lf search -1'; popd; sudo make uninstall

# cmake client build test
#( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client --long || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3GENERIC ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client --long || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3RDV4 ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client --long || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake ..;make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON ); PM3BIN=./client/build/proxmark3 tools/pm3_tests.sh client || exit 1

