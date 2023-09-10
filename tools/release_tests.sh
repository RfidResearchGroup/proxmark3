#!/usr/bin/env bash

# To be run from proxmark3 root directory
set -x
make clean && make -j PLATFORM=PM3GENERIC PLATFORM_EXTRAS= && tools/pm3_tests.sh --long || exit 1
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS= || exit 1
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON || exit 1
make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && INSTALLSUDO=sudo make install PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON && ( cd /tmp; proxmark3 -c 'data load -f lf_EM4x05.pm3;lf search -1'|grep 'Valid FDX-B ID found' ) && INSTALLSUDO=sudo make uninstall || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3GENERIC PLATFORM_EXTRAS= && cp -a ../*scripts ../*libs . && ../../tools/pm3_tests.sh --clientbin $(pwd)/proxmark3 client ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4  PLATFORM_EXTRAS= ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON ) || exit 1

# Hitag2crack, optionally with --long and --opencl...
make hitag2crack/clean && make hitag2crack && tools/pm3_tests.sh hitag2crack || exit 1
echo PASS
