#!/usr/bin/env bash

PM3PATH="$(dirname "$0")/.."
cd "$PM3PATH" || exit 1

SLOWTESTS=false
GPUTESTS=false
TESTALL=true
TESTMFKEY=false
TESTNONCE2KEY=false
TESTMFNONCEBRUTE=false
TESTHITAG2CRACK=false
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
Usage: $0 [--long] [--gpu] [--clientbin /path/to/proxmark3] [mfkey|nonce2key|mf_nonce_brute|fpga_compress|bootrom|armsrc|client|recovery|common]
    --long:          Enable slow tests
    --gpu:           Enable tests requiring GPU
    --clientbin ...: Specify path to proxmark3 binary to test
    If no target given, all targets will be tested
"""
      exit 0
      ;;
    -l|--long)
      SLOWTESTS=true
      shift
      ;;
    --gpu)
      GPUTESTS=true
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
    hitag2crack)
      TESTALL=false
      TESTHITAG2CRACK=true
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

  printf "%-40s" "$1 "

  if [ -f "$2" ]; then
    echo -e "${C_GREEN}[OK]${C_NC}"
    return 0
  fi

  if ls "$2" 1> /dev/null 2>&1; then
    echo -e "${C_GREEN}[OK]${C_NC}"
    return 0
  fi

  echo -e "${C_RED}[FAIL]${C_NC}"
  return 1
}

# [slow] [gpu] [retry] [ignore] <title> <command_line> <check_result_regex>
# slow:   test takes more than ~5s
# gpu:    test requires GPU presence
# retry:  test repeated up to 3 times in case of failure
# ignore: test failure is not fatal
function CheckExecute() {
  if [ "$1" == "slow" ]; then
    local SLOWTEST=true
    shift
  else
    local SLOWTEST=false
  fi
  if [ "$1" == "gpu" ]; then
    local GPUTEST=true
    shift
  else
    local GPUTEST=false
  fi
  if [ "$1" == "retry" ]; then
    local RETRY="1 2 3 e"
    shift
  else
    local RETRY="e"
  fi
  if [ "$1" == "ignore" ]; then
    local IGNOREFAILURE=true
    shift
  else
    local IGNOREFAILURE=false
  fi

  printf "%-40s" "$1 "

  if $SLOWTEST && ! $SLOWTESTS; then
    echo -e "${C_YELLOW}[SKIPPED]${C_NC} (slow)\n"
    return 0
  fi
  if $GPUTEST && ! $GPUTESTS; then
    echo -e "${C_YELLOW}[SKIPPED]${C_NC} (gpu)\n"
    return 0
  fi

  for I in $RETRY
  do
    RES=$(eval "$2")
    if echo "$RES" | grep -q "$3"; then
      echo -e "${C_GREEN}[OK]${C_NC}"
      return 0
    fi
    if [ ! $I == "e" ]; then echo "retry $I"; fi
  done

  if $IGNOREFAILURE; then
    echo -e "${C_YELLOW}[IGNORED]${C_NC}"
    return 0
  fi

  echo -e "${C_RED}[FAIL]${C_NC}"
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
    # hitag2crack not yet part of "all"
    # if $TESTALL || $TESTHITAG2CRACK; then
    if $TESTHITAG2CRACK; then
      echo -e "\n${C_BLUE}Testing ht2crack2:${C_NC} ${HT2CRACK2PATH:=./tools/hitag2crack/crack2/}"
      if ! CheckFileExist "ht2crack2buildtable exists"     "$HT2CRACK2PATH/ht2crack2buildtable"; then break; fi
      if ! CheckFileExist "ht2crack2gentest exists"        "$HT2CRACK2PATH/ht2crack2gentest"; then break; fi
      if ! CheckFileExist "ht2crack2search exists"         "$HT2CRACK2PATH/ht2crack2search"; then break; fi
      # 1.5Tb tables are supposed to be absent, so it's just a fast check without real cracking
      if ! CheckExecute "ht2crack2 quick test"             "cd $HT2CRACK2PATH; ./ht2crack2gentest 1 && ./runalltests.sh; rm keystream*" "searching on bit"; then break; fi

      echo -e "\n${C_BLUE}Testing ht2crack3:${C_NC} ${HT2CRACK3PATH:=./tools/hitag2crack/crack3/}"
      if ! CheckFileExist "ht2crack3 exists"               "$HT2CRACK3PATH/ht2crack3"; then break; fi
      if ! CheckFileExist "ht2crack3test exists"           "$HT2CRACK3PATH/ht2crack3test"; then break; fi
      HT2CRACK3UID=AABBCCDD
      # Test fast only for HT2CRACK3KEY in begin of keyspace!
      HT2CRACK3KEY=000102030405
      HT2CRACK3N=32
      HT2CRACK3NRAR=hitag2_${HT2CRACK3UID}_nrar_${HT2CRACK3N}emul.txt
      if ! CheckExecute "ht2crack3 gen testfile"           "cd $HT2CRACK3PATH; python3 ../hitag2_gen_nRaR.py $HT2CRACK3KEY $HT2CRACK3UID $HT2CRACK3N > $HT2CRACK3NRAR && echo SUCCESS" "SUCCESS"; then break; fi
      if ! CheckExecute "ht2crack3test test"               "cd $HT2CRACK3PATH; ./ht2crack3test $HT2CRACK3NRAR $HT2CRACK3KEY $HT2CRACK3UID|grep -v SUCCESS||echo SUCCESS" "SUCCESS"; then break; fi
      if ! CheckExecute "ht2crack3 test"                   "cd $HT2CRACK3PATH; ./ht2crack3 $HT2CRACK3UID $HT2CRACK3NRAR |egrep -v '(trying|partial)'" "key = $HT2CRACK3KEY"; then break; fi
      if ! CheckExecute "ht2crack3 rm testfile"            "cd $HT2CRACK3PATH; rm $HT2CRACK3NRAR && echo SUCCESS" "SUCCESS"; then break; fi

      echo -e "\n${C_BLUE}Testing ht2crack4:${C_NC} ${HT2CRACK4PATH:=./tools/hitag2crack/crack4/}"
      if ! CheckFileExist "ht2crack4 exists"               "$HT2CRACK4PATH/ht2crack4"; then break; fi
      HT2CRACK4UID=12345678
      HT2CRACK4KEY=AABBCCDDEEFF
      HT2CRACK4N=32
      HT2CRACK4NRAR=hitag2_${HT2CRACK4UID}_nrar_${HT2CRACK4N}emul.txt
      # The success is probabilistic: a fresh random nRaR file is required for each run
      # Order of magnitude to crack it: ~15s -> tagged as "slow"
      if ! CheckExecute slow retry ignore "ht2crack4 test" "cd $HT2CRACK4PATH; \
                                                            python3 ../hitag2_gen_nRaR.py $HT2CRACK4KEY $HT2CRACK4UID $HT2CRACK4N > $HT2CRACK4NRAR; \
                                                            ./ht2crack4 -u $HT2CRACK4UID -n $HT2CRACK4NRAR -N 16 -t 500000 2>&1; \
                                                            rm $HT2CRACK4NRAR" "key = $HT2CRACK4KEY"; then break; fi

      echo -e "\n${C_BLUE}Testing ht2crack5:${C_NC} ${HT2CRACK5PATH:=./tools/hitag2crack/crack5/}"
      if ! CheckFileExist "ht2crack5 exists"               "$HT2CRACK5PATH/ht2crack5"; then break; fi
      HT2CRACK5UID=12345678
      HT2CRACK5KEY=AABBCCDDEEFF
      # The speed depends on the nRaR so we'll use two pairs known to work fast
      HT2CRACK5NRAR="71DA20AA 7EFDF3FA 2A4265F9 59653B07"
      # Order of magnitude to crack it: ~12s on 1 core, ~3s on 4 cores -> tagged as "slow"
      if ! CheckExecute slow "ht2crack5 test"              "cd $HT2CRACK5PATH; ./ht2crack5 $HT2CRACK5UID $HT2CRACK5NRAR" "Key: $HT2CRACK5KEY"; then break; fi

      echo -e "\n${C_BLUE}Testing ht2crack5gpu:${C_NC} ${HT2CRACK5GPUPATH:=./tools/hitag2crack/crack5gpu/}"
      if ! CheckFileExist "ht2crack5gpu exists"            "$HT2CRACK5GPUPATH/ht2crack5gpu"; then break; fi
      HT2CRACK5GPUUID=12345678
      HT2CRACK5GPUKEY=AABBCCDDEEFF
      # The speed depends on the nRaR so we'll use two pairs known to work fast
      HT2CRACK5GPUNRAR="B438220C 944FFD74 942C59E3 3D450B34"
      # Order of magnitude to crack it: ~15s -> tagged as "slow"
      if ! CheckExecute slow gpu "ht2crack5gpu test"        "cd $HT2CRACK5GPUPATH; ./ht2crack5gpu $HT2CRACK5GPUUID $HT2CRACK5GPUNRAR" "Key: $HT2CRACK5GPUKEY"; then break; fi
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
      if ! CheckExecute slow retry ignore "hf mf hardnested long test"  "$CLIENTBIN -c 'hf mf hardnested t 1 000000000000'" "found:"; then break; fi
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
