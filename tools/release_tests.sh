#!/usr/bin/env bash

# To be run from proxmark3 root directory
if [ -f Makefile.platform ]; then
  if grep -q "^SKIP_" Makefile.platform; then
  echo "ERROR: SKIP instructions in your Makefile.platform will interfere with this script, aborting..."
  exit 1;
  fi
fi
set -x
make clean && make -j PLATFORM=PM3GENERIC PLATFORM_EXTRAS= STANDALONE=LF_SAMYRUN && tools/pm3_tests.sh --long || exit 1
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS= STANDALONE=HF_ST25_TEAROFF || exit 1
make clean && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON STANDALONE=HF_REBLAY || exit 1
make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON STANDALONE=HF_REBLAY && if sudo true; then INSTALLSUDO=sudo make install SKIP_SETCAP=1 PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON STANDALONE=HF_REBLAY && ( cd /tmp; proxmark3 -c 'data load -f lf_EM4x05.pm3;lf search -1'|grep 'Valid FDX-B ID found' ) && INSTALLSUDO=sudo make uninstall || exit 1; fi
# PM5: different MCU (AT32F435/437) and its own PLATFORM_EXTRAS tokens.
# BTADDON and FPC_USART_DEV are rejected on PM5, so they have no line here.
make clean && make -j PLATFORM=PM5 PLATFORM_EXTRAS= STANDALONE=HF_ST25_TEAROFF || exit 1
make clean && make -j PLATFORM=PM5 PLATFORM_EXTRAS=BWM STANDALONE=GDB_GATEWAY || exit 1
make clean && make -j PLATFORM=PM5 PLATFORM_EXTRAS="NO_LOWBATT_SHUTDOWN NO_LOWBATT_BEEP" SKIP_CEP=1 STANDALONE= || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3GENERIC PLATFORM_EXTRAS= STANDALONE=LF_SAMYRUN && cp -a ../*scripts ../*libs . && ../../tools/pm3_tests.sh --clientbin $(pwd)/proxmark3 client ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS= STANDALONE=HF_ST25_TEAROFF ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake .. && make -j PLATFORM=PM3RDV4 PLATFORM_EXTRAS=BTADDON STANDALONE=HF_REBLAY ) || exit 1
( cd client; rm -rf build; mkdir build;cd build;cmake -DPLATFORM=PM5 .. && make -j && cp -a ../*scripts ../*libs . && ../../tools/pm3_tests.sh --clientbin $(pwd)/proxmark3 client ) || exit 1

# Hitag2crack, optionally with --long and --opencl...
make hitag2crack/clean && make hitag2crack && tools/pm3_tests.sh hitag2crack || exit 1
echo PASS
