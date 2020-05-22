#!/usr/bin/env bash

PM3PATH="$(dirname "$0")/.."
cd "$PM3PATH" || exit 1

SLOWTESTS=false
TESTALL=true
TESTMFKEY=false
TESTNONCE2KEY=false
TESTMFNONCEBRUTE=false
TESTFPGACOMPRESS=false
TESTBOOTROM=false
TESTARMSRC=false
TESTCLIENT=false
TESTRECOVERY=false
TESTCOMMON=false

# https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo """
Usage: $0 [--long] [--clientbin /path/to/proxmark3] [mfkey|nonce2key|mf_nonce_brute|fpga_compress|bootrom|armsrc|client|recovery|common]
    --long:          Enable slow tests
    --clientbin ...: Specify path to proxmark3 binary to test
    If no target given, all targets will be tested
"""
      exit 0
      ;;
    -l|--long)
      SLOWTESTS=true
      shift
      ;;
    --clientbin)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        CLIENTBIN=$2
        shift 2
      else
        echo "Error: Argument for $1 is missing" >&2
        exit 1
      fi
      ;;
    mfkey)
      TESTALL=false
      TESTMFKEY=true
      shift
      ;;
    nonce2key)
      TESTALL=false
      TESTNONCE2KEY=true
      shift
      ;;
    mf_nonce_brute)
      TESTALL=false
      TESTMFNONCEBRUTE=true
      shift
      ;;
    fpga_compress)
      TESTALL=false
      TESTFPGACOMPRESS=true
      shift
      ;;
    bootrom)
      TESTALL=false
      TESTBOOTROM=true
      shift
      ;;
    armsrc)
      TESTALL=false
      TESTARMSRC=true
      shift
      ;;
    client)
      TESTALL=false
      TESTCLIENT=true
      shift
      ;;
    recovery)
      TESTALL=false
      TESTRECOVERY=true
      shift
      ;;
    common)
      TESTALL=false
      TESTCOMMON=true
      shift
      ;;
    -*|--*=) # unsupported flags
      echo "Error: Unsupported flag $1" >&2
      exit 1
      ;;
    *) # preserve positional arguments
      PARAMS="$PARAMS $1"
      shift
      ;;
  esac
done
# set positional arguments in their proper place
eval set -- "$PARAMS"

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_YELLOW='\033[0;33m'
C_BLUE='\033[0;34m'
C_NC='\033[0m' # No Color

# title, file name or file wildcard to check
function CheckFileExist() {

  if [ -f "$2" ]; then
    echo -e "$1 ${C_GREEN}[OK]${C_NC}"
    return 0
  fi

  if ls "$2" 1> /dev/null 2>&1; then
    echo -e "$1 ${C_GREEN}[OK]${C_NC}"
    return 0
  fi

  echo -e "$1 ${C_RED}[Fail]${C_NC}"
  return 1
}

# title, command line, check result, repeat several times if failed, ignore if fail
function CheckExecute() {
  if [ "$1" == "slow" ]; then
    SLOWTEST=true
    shift
  else
    SLOWTEST=false
  fi
  if [ "$4" ]; then
    local RETRY="1 2 3 e"
  else
    local RETRY="e"
  fi

  if $SLOWTEST && ! $SLOWTESTS; then
    echo -e "$1 ${C_YELLOW}[SKIPPED]${C_NC} (slow)\n"
    return 0
  fi

  for I in $RETRY
  do
    RES=$(eval "$2")
    if echo "$RES" | grep -q "$3"; then
      echo -e "$1 ${C_GREEN}[OK]${C_NC}"
      return 0
    fi
    if [ ! $I == "e" ]; then echo "retry $I"; fi
  done

  if [ "$5" ]; then
    echo -e "$1 ${C_YELLOW}[Ignored]${C_NC}"
    return 0
  fi

  echo -e "$1 ${C_RED}[Fail]${C_NC}"
  echo -e "Execution trace:\n$RES"
  return 1
}

echo -e "\n${C_BLUE}RRG/Iceman Proxmark3 test tool ${C_NC}\n"

echo -n "work directory: "
pwd

if [ "$TRAVIS_COMMIT" ]; then
  if [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
    echo "Travis branch: $TRAVIS_BRANCH slug: $TRAVIS_REPO_SLUG commit: $TRAVIS_COMMIT"
  else
    echo "Travis pull request: $TRAVIS_PULL_REQUEST branch: $TRAVIS_BRANCH slug: $TRAVIS_PULL_REQUEST_SLUG commit: $TRAVIS_COMMIT"
  fi
fi

echo -n "git branch: "
git describe --all
echo -n "git sha: "
git rev-parse HEAD
echo ""

while true; do
    if $TESTALL || $TESTCOMMON; then
      echo -e "\n${C_BLUE}Testing common:${C_NC}"
      if ! CheckFileExist "hardnested tables exists"       "./client/resources/hardnested_tables/bitflip_0_001_states.bin.z"; then break; fi
      if ! CheckFileExist "simmodule fw file exists"       "./tools/simmodule/sim011.bin"; then break; fi
      echo -e "\n${C_BLUE}Testing tools:${C_NC}"
      if ! CheckExecute "xorcheck test"                    "tools/xorcheck.py 04 00 80 64 ba" "final LRC XOR byte value: 5A"; then break; fi
      if ! CheckExecute "findbits test"                    "tools/findbits.py 73 0110010101110011" "Match at bit 9: 011001010"; then break; fi
      if ! CheckExecute "findbits_test test"               "tools/findbits_test.py 2>&1" "OK"; then break; fi
      if ! CheckExecute "pm3_eml_mfd test"                 "tools/pm3_eml_mfd_test.py 2>&1" "OK"; then break; fi
    fi
    if $TESTALL || $TESTBOOTROM; then
      echo -e "\n${C_BLUE}Testing bootrom:${C_NC}"
      if ! CheckFileExist "bootrom exists"                 "./bootrom/obj/bootrom.elf"; then break; fi
    fi
    if $TESTALL || $TESTARMSRC; then
      echo -e "\n${C_BLUE}Testing armsrc:${C_NC}"
      if ! CheckFileExist "arm image exists"               "./armsrc/obj/fullimage.elf"; then break; fi
    fi
    if $TESTALL || $TESTRECOVERY; then
      echo -e "\n${C_BLUE}Testing recovery:${C_NC}"
      if ! CheckFileExist "recovery image exists"          "./recovery/proxmark3_recovery.bin"; then break; fi

    fi
    if $TESTALL || $TESTFPGACOMPRESS; then
      echo -e "\n${C_BLUE}Testing fpgacompress:${C_NC} ${FPGACPMPRESSBIN:=./tools/fpga_compress/fpga_compress}"
      if ! CheckFileExist "fpgacompress exists"            "$FPGACPMPRESSBIN"; then break; fi
    fi
    if $TESTALL || $TESTMFKEY; then
      echo -e "\n${C_BLUE}Testing mfkey:${C_NC} ${MFKEY32V2BIN:=./tools/mfkey/mfkey32v2} ${MFKEY64BIN:=./tools/mfkey/mfkey64}"
      if ! CheckFileExist "mfkey32v2 exists"               "$MFKEY32V2BIN"; then break; fi
      if ! CheckFileExist "mfkey64 exists"                 "$MFKEY64BIN"; then break; fi
      # Need a decent example for mfkey32...
      if ! CheckExecute "mfkey32v2 test"                   "$MFKEY32V2BIN 12345678 1AD8DF2B 1D316024 620EF048 30D6CB07 C52077E2 837AC61A" "Found Key: \[a0a1a2a3a4a5\]"; then break; fi
      if ! CheckExecute "mfkey64 test"                     "$MFKEY64BIN 9c599b32 82a4166c a1e458ce 6eea41e0 5cadf439" "Found Key: \[ffffffffffff\]"; then break; fi
      if ! CheckExecute "mfkey64 long trace test"          "$MFKEY64BIN 14579f69 ce844261 f8049ccb 0525c84f 9431cc40 7093df99 9972428ce2e8523f456b99c831e769dced09 8ca6827b ab797fd369e8b93a86776b40dae3ef686efd c3c381ba 49e2c9def4868d1777670e584c27230286f4 fbdcd7c1 4abd964b07d3563aa066ed0a2eac7f6312bf 9f9149ea" "Found Key: \[091e639cb715\]"; then break; fi
    fi
    if $TESTALL || $TESTNONCE2KEY; then
      echo -e "\n${C_BLUE}Testing nonce2key:${C_NC} ${NONCE2KEYBIN:=./tools/nonce2key/nonce2key}"
      if ! CheckFileExist "nonce2key exists"               "$NONCE2KEYBIN"; then break; fi
      if ! CheckExecute "nonce2key test"                   "$NONCE2KEYBIN e9cadd9c a8bf4a12 a020a8285858b090 050f010607060e07 5693be6c00000000" "key recovered: fc00018778f7"; then break; fi
    fi
    if $TESTALL || $TESTMFNONCEBRUTE; then
      echo -e "\n${C_BLUE}Testing mf_nonce_brute:${C_NC} ${MFNONCEBRUTEBIN:=./tools/mf_nonce_brute/mf_nonce_brute}"
      if ! CheckFileExist "mf_nonce_brute exists"          "$MFNONCEBRUTEBIN"; then break; fi
      if ! CheckExecute slow "mf_nonce_brute test"         "$MFNONCEBRUTEBIN 9c599b32 5a920d85 1011 98d76b77 d6c6e870 0000 ca7e0b63 0111 3e709c8a" "Key.*: \[ffffffffffff\]"; then break; fi
    fi
    if $TESTALL || $TESTCLIENT; then
      echo -e "\n${C_BLUE}Testing client:${C_NC} ${CLIENTBIN:=./client/proxmark3}"
      if ! CheckFileExist "proxmark3 exists"               "$CLIENTBIN"; then break; fi
      echo -e "\n${C_BLUE}Testing basic help:${C_NC}"
      if ! CheckExecute "proxmark help"                    "$CLIENTBIN -h" "wait"; then break; fi
      if ! CheckExecute "proxmark help text ISO7816"       "$CLIENTBIN -t 2>&1" "ISO7816"; then break; fi
      if ! CheckExecute "proxmark help text hardnested"    "$CLIENTBIN -t 2>&1" "hardnested"; then break; fi

      echo -e "\n${C_BLUE}Testing data manipulation:${C_NC}"
      if ! CheckExecute "reveng readline test"    "$CLIENTBIN -c 'reveng -h;reveng -D'" "CRC-64/GO-ISO"; then break; fi
      if ! CheckExecute "reveng -g test"          "$CLIENTBIN -c 'reveng -g abda202c'" "CRC-16/ISO-IEC-14443-3-A"; then break; fi
      if ! CheckExecute "reveng -w test"          "$CLIENTBIN -c 'reveng -w 8 -s 01020304e3 010204039d'" "CRC-8/SMBUS"; then break; fi
      if ! CheckExecute "mfu pwdgen test"         "$CLIENTBIN -c 'hf mfu pwdgen t'" "Selftest OK"; then break; fi
      if ! CheckExecute "trace load/list 14a"     "$CLIENTBIN -c 'trace load traces/hf_mfu.trace; trace list 1;'" "READBLOCK(8)"; then break; fi
      if ! CheckExecute "trace load/list x"       "$CLIENTBIN -c 'trace load traces/hf_mfu.trace; trace list x 1;'" "0.0101840425"; then break; fi

      echo -e "\n${C_BLUE}Testing LF:${C_NC}"
      if ! CheckExecute "lf EM4x05 test"        "$CLIENTBIN -c 'data load traces/em4x05.pm3;lf search 1'" "FDX-B ID found"; then break; fi
      if ! CheckExecute "lf EM410x test"        "$CLIENTBIN -c 'data load traces/EM4102-1.pm3;lf search 1'" "EM410x ID found"; then break; fi
      if ! CheckExecute "lf VISA2000 test"      "$CLIENTBIN -c 'data load traces/visa2000.pm3;lf search 1'" "Visa2000 ID found"; then break; fi
      if ! CheckExecute "lf AWID test"          "$CLIENTBIN -c 'data load traces/AWID-15-259.pm3;lf search 1'" "AWID ID found"; then break; fi
      if ! CheckExecute "lf SECURAKEY test"     "$CLIENTBIN -c 'data load traces/securakey-64169.pm3;lf search 1 '" "Securakey ID found"; then break; fi
      if ! CheckExecute "lf NEXWATCH test"      "$CLIENTBIN -c 'data load traces/quadrakey-521512301.pm3;lf search 1 '" "NexWatch ID found"; then break; fi
      if ! CheckExecute "lf KERI test"          "$CLIENTBIN -c 'data load traces/keri.pm3;lf search 1'" "Pyramid ID found"; then break; fi
      if ! CheckExecute "lf HID Prox test"      "$CLIENTBIN -c 'data load traces/hid-proxCardII-05512-11432784-1.pm3;lf search 1'" "HID Prox ID found"; then break; fi
      if ! CheckExecute "lf PARADOX test"       "$CLIENTBIN -c 'data load traces/Paradox-96_40426-APJN08.pm3;lf search 1'" "Paradox ID found"; then break; fi
      if ! CheckExecute "lf PAC test"           "$CLIENTBIN -c 'data load traces/pac-8E4C058E.pm3;lf search 1'" "PAC/Stanley ID found"; then break; fi
      if ! CheckExecute "lf VIKING test"        "$CLIENTBIN -c 'data load traces/Transit999-best.pm3;lf search 1'" "Viking ID found"; then break; fi
      if ! CheckExecute "lf FDX-B test"         "$CLIENTBIN -c 'data load traces/homeagain1600.pm3;lf search 1'" "FDX-B ID found"; then break; fi
      if ! CheckExecute "lf INDALA test"        "$CLIENTBIN -c 'data load traces/indala-504278295.pm3;lf search 1'" "Indala ID found"; then break; fi
      if ! CheckExecute "lf FDX/BioThermo test" "$CLIENTBIN -c 'data load traces/lf_fdx_biothermo.pm3; lf fdx demo'" "95.2 F / 35.1 C"; then break; fi

      echo -e "\n${C_BLUE}Testing HF:${C_NC}"
      if ! CheckExecute "hf mf offline text"               "$CLIENTBIN -c 'hf mf'" "at_enc"; then break; fi
      if ! CheckExecute slow "hf mf hardnested long test"  "$CLIENTBIN -c 'hf mf hardnested t 1 000000000000'" "found:" "repeat" "ignore"; then break; fi
      if ! CheckExecute slow "hf iclass long test"         "$CLIENTBIN -c 'hf iclass loclass t l'" "verified ok"; then break; fi
      if ! CheckExecute slow "emv long test"               "$CLIENTBIN -c 'emv test -l'" "Test(s) \[ OK"; then break; fi
      if ! $SLOWTESTS; then
        if ! CheckExecute "hf iclass test"                 "$CLIENTBIN -c 'hf iclass loclass t'" "key diversification (ok)"; then break; fi
        if ! CheckExecute "emv test"                       "$CLIENTBIN -c 'emv test'" "Test(s) \[ OK"; then break; fi
      fi
    fi
  echo -e "\n${C_GREEN}Tests [OK]${C_NC}\n"
  exit 0
done
echo -e "\n${C_RED}Tests [FAIL]${C_NC}\n"
exit 1
