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
      if ! CheckFileExist "hardnested tables exists"       "./client/resources/hardnested_tables/bitflip_0_001_states.bin.bz2"; then break; fi
      if ! CheckFileExist "simmodule fw file exists"       "./client/resources/sim011.bin"; then break; fi
      echo -e "\n${C_BLUE}Testing tools:${C_NC}"
      if ! CheckExecute "xorcheck test"                    "tools/xorcheck.py 04 00 80 64 ba" "final LRC XOR byte value: 5A"; then break; fi
      if ! CheckExecute "findbits test"                    "tools/findbits.py 73 0110010101110011" "Match at bit 9: 011001010"; then break; fi
      if ! CheckExecute "findbits_test test"               "tools/findbits_test.py 2>&1" "OK"; then break; fi
      if ! CheckExecute "pm3_eml_mfd test"                 "tools/pm3_eml_mfd_test.py 2>&1" "OK"; then break; fi
      if ! CheckExecute "recover_pk test"                  "tools/recover_pk.py selftests 2>&1" "Tests:.*\[OK\]"; then break; fi
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

      echo -e "\n${C_BLUE}Testing ht2crack5opencl:${C_NC} ${HT2CRACK5OPENCLPATH:=./tools/hitag2crack/crack5opencl/}"
      if ! CheckFileExist "ht2crack5opencl exists"            "$HT2CRACK5OPENCLPATH/ht2crack5opencl"; then break; fi
      HT2CRACK5OPENCLUID=12345678
      HT2CRACK5OPENCLKEY=AABBCCDDEEFF
      # The speed depends on the nRaR so we'll use two pairs known to work fast
      HT2CRACK5OPENCLNRAR="B438220C 944FFD74 942C59E3 3D450B34"
      # Order of magnitude to crack it: ~15s -> tagged as "slow"
      if ! CheckExecute slow gpu "ht2crack5opencl test"        "cd $HT2CRACK5OPENCLPATH; ./ht2crack5opencl $HT2CRACK5OPENCLUID $HT2CRACK5OPENCLNRAR" "Key found.*: $HT2CRACK5OPENCLKEY"; then break; fi
    fi
    if $TESTALL || $TESTCLIENT; then
      echo -e "\n${C_BLUE}Testing client:${C_NC} ${CLIENTBIN:=./client/proxmark3}"
      if ! CheckFileExist "proxmark3 exists"               "$CLIENTBIN"; then break; fi
      # Avoid mangling history and logs
      CLIENTBIN="$CLIENTBIN --incognito"
      echo -e "\n${C_BLUE}Testing basic help:${C_NC}"
      if ! CheckExecute "proxmark help"                    "$CLIENTBIN -h" "wait"; then break; fi
      if ! CheckExecute "proxmark help text ISO7816"       "$CLIENTBIN -t 2>&1" "ISO7816"; then break; fi
      if ! CheckExecute "proxmark help text hardnested"    "$CLIENTBIN -t 2>&1" "hardnested"; then break; fi

      echo -e "\n${C_BLUE}Testing data manipulation:${C_NC}"
      if ! CheckExecute "reveng readline test"    "$CLIENTBIN -c 'reveng -h;reveng -D'" "CRC-64/GO-ISO"; then break; fi
      if ! CheckExecute "reveng -g test"          "$CLIENTBIN -c 'reveng -g abda202c'" "CRC-16/ISO-IEC-14443-3-A"; then break; fi
      if ! CheckExecute "reveng -w test"          "$CLIENTBIN -c 'reveng -w 8 -s 01020304e3 010204039d'" "CRC-8/SMBUS"; then break; fi
      if ! CheckExecute "mfu pwdgen test"         "$CLIENTBIN -c 'hf mfu pwdgen -t'" "Selftest OK"; then break; fi
      if ! CheckExecute "trace load/list 14a"     "$CLIENTBIN -c 'trace load -f traces/hf_14a_mfu.trace; trace list -1 -t 14a;'" "READBLOCK(8)"; then break; fi
      if ! CheckExecute "trace load/list x"       "$CLIENTBIN -c 'trace load -f traces/hf_14a_mfu.trace; trace list -x1 -t 14a;'" "0.0101840425"; then break; fi

      echo -e "\n${C_BLUE}Testing LF:${C_NC}"
      if ! CheckExecute "lf AWID test"          "$CLIENTBIN -c 'data load -f traces/lf_AWID-15-259.pm3;lf search -1'" "AWID ID found"; then break; fi
      if ! CheckExecute "lf EM410x test"        "$CLIENTBIN -c 'data load -f traces/lf_EM4102-1.pm3;lf search -1'" "EM410x ID found"; then break; fi
      if ! CheckExecute "lf EM4x05 test"        "$CLIENTBIN -c 'data load -f traces/lf_EM4x05.pm3;lf search -1'" "FDX-B ID found"; then break; fi
      if ! CheckExecute "lf FDX-A FECAVA test"  "$CLIENTBIN -c 'data load -f traces/lf_EM4305_fdxa_destron.pm3;lf search -1'" "FDX-A FECAVA Destron ID found"; then break; fi
      if ! CheckExecute "lf FDX-B test"         "$CLIENTBIN -c 'data load -f traces/lf_HomeAgain1600.pm3;lf search -1'" "FDX-B ID found"; then break; fi
      if ! CheckExecute "lf FDX/BioThermo test" "$CLIENTBIN -c 'data load -f traces/lf_FDXB_Bio-Thermo.pm3; lf fdxb demod'" "95.2 F / 35.1 C"; then break; fi
      if ! CheckExecute "lf GPROXII test"       "$CLIENTBIN -c 'data load -f traces/lf_GProx_36_30_14489.pm3; lf search -1'" "Guardall G-Prox II ID found"; then break; fi
      if ! CheckExecute "lf HID Prox test"      "$CLIENTBIN -c 'data load -f traces/lf_HID-proxCardII-05512-11432784-1.pm3;lf search -1'" "HID Prox ID found"; then break; fi
      if ! CheckExecute "lf IDTECK test"        "$CLIENTBIN -c 'data load -f traces/lf_IDTECK_4944544BAC40E069.pm3; lf search -1'" "Idteck ID found"; then break; fi
      if ! CheckExecute "lf INDALA test"        "$CLIENTBIN -c 'data load -f traces/lf_Indala-504278295.pm3;lf search -1'" "Indala ID found"; then break; fi
      if ! CheckExecute "lf KERI test"          "$CLIENTBIN -c 'data load -f traces/lf_Keri.pm3;lf search -1'" "Pyramid ID found"; then break; fi
      if ! CheckExecute "lf NEXWATCH test"      "$CLIENTBIN -c 'data load -f traces/lf_NEXWATCH_Quadrakey-521512301.pm3;lf search -1 '" "NexWatch ID found"; then break; fi
      if ! CheckExecute "lf SECURAKEY test"     "$CLIENTBIN -c 'data load -f traces/lf_NEXWATCH_Securakey-64169.pm3;lf search -1 '" "Securakey ID found"; then break; fi
      if ! CheckExecute "lf PAC test"           "$CLIENTBIN -c 'data load -f traces/lf_PAC-8E4C058E.pm3;lf search -1'" "PAC/Stanley ID found"; then break; fi
      if ! CheckExecute "lf PARADOX test"       "$CLIENTBIN -c 'data load -f traces/lf_Paradox-96_40426-APJN08.pm3;lf search -1'" "Paradox ID found"; then break; fi
      if ! CheckExecute "lf VIKING test"        "$CLIENTBIN -c 'data load -f traces/lf_Transit999-best.pm3;lf search -1'" "Viking ID found"; then break; fi
      if ! CheckExecute "lf VISA2000 test"      "$CLIENTBIN -c 'data load -f traces/lf_VISA2000.pm3;lf search -1'" "Visa2000 ID found"; then break; fi

      if ! CheckExecute slow "lf T55 awid 26 test"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_awid_26.pm3; lf search -1'" "AWID ID found"; then break; fi
      if ! CheckExecute slow "lf T55 awid 26 test2"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_awid_26.pm3; lf awid demod'" \
                                                                     "AWID - len: 26 FC: 224 Card: 1337 - Wiegand: 3c00a73"; then break; fi
      if ! CheckExecute slow "lf T55 awid 50 test"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_awid_50.pm3; lf search -1'" "AWID ID found"; then break; fi
      if ! CheckExecute slow "lf T55 awid 50 test2"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_awid_50.pm3; lf awid demod'" \
                                                                     "AWID - len: 50 FC: 2001 Card: 13371337 - Wiegand: 20fa201980f92, Raw: 0128b12eb1811d7117e22111"; then break; fi
      if ! CheckExecute slow "lf T55 em410x test"                "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_em410x.pm3; lf search -1'" "EM410x ID found"; then break; fi
      if ! CheckExecute slow "lf T55 em410x test2"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_em410x.pm3; lf em 410x demod'" \
                                                                     "EM 410x ID 0F0368568B"; then break; fi
      if ! CheckExecute slow "lf T55 fdxb_animal test"           "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_fdxb_animal.pm3; lf search -1'" "FDX-B ID found"; then break; fi
      if ! CheckExecute slow "lf T55 fdxb_animal test2"          "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_fdxb_animal.pm3; lf fdxb demod'" \
                                                                     "Animal ID          999-000000112233"; then break; fi
      if ! CheckExecute slow "lf T55 fdxb_extended test"         "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_fdxb_extended.pm3; lf search -1'" "FDX-B ID found"; then break; fi
      if ! CheckExecute slow "lf T55 fdxb_extended test2"        "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_fdxb_extended.pm3; lf fdxb demod'" \
                                                                     "temperature     95.2 F / 35.1 C"; then break; fi
      if ! CheckExecute slow "lf T55 gallagher test"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_gallagher.pm3; lf search -1'" "GALLAGHER ID found"; then break; fi
      if ! CheckExecute slow "lf T55 gallagher test2"            "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_gallagher.pm3; lf gallagher demod'" \
                                                                     "GALLAGHER - Region: 0 FC: 27865 CN: 682758 Issue Level: 13"; then break; fi
      if ! CheckExecute slow "lf T55 gproxii test"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_gproxii.pm3; lf search -1'" "Guardall G-Prox II ID found"; then break; fi
      if ! CheckExecute slow "lf T55 gproxii test2"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_gproxii.pm3; lf gproxii demod'" \
                                                                     "G-Prox-II - len: 26 FC: 123 Card: 11223, Raw: f98c7038c63356c7ac26398c"; then break; fi
      if ! CheckExecute slow "lf T55 hid test"                   "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_hid.pm3; lf search -1'" "HID Prox ID found"; then break; fi
      if ! CheckExecute slow "lf T55 hid test2"                  "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_hid.pm3; lf hid demod'" \
                                                                     "HID H10301 26-bit;  FC: 118  CN: 1603"; then break; fi
      if ! CheckExecute slow "lf T55 hid_48 test"                "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_hid_48.pm3; lf search -1'" "HID Prox ID found"; then break; fi
      if ! CheckExecute slow "lf T55 hid_48 test2"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_hid_48.pm3; lf hid demod'" \
                                                                     "HID Corporate 1000 48-bit"; then break; fi
      if ! CheckExecute slow "lf T55 indala_hedem test"          "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_indala_hedem.pm3; lf search -1'" "Indala ID found"; then break; fi
      if ! CheckExecute slow "lf T55 indala_hedem test2"         "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_indala_hedem.pm3; lf indala demod'" \
                                                                     "Heden-2L    \| 888"; then break; fi
      if ! CheckExecute slow "lf T55 indala test"                "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_indala.pm3; lf search -1'" "Indala ID found"; then break; fi
      if ! CheckExecute slow "lf T55 indala test2"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_indala.pm3; lf indala demod'" \
                                                                     "Fmt 26 FC: 123 Card: 1337 checksum: 10"; then break; fi
      if ! CheckExecute slow "lf T55 indala_224 test"            "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_indala_224.pm3; lf search -1'" "Indala ID found"; then break; fi
      if ! CheckExecute slow "lf T55 indala_224 test2"           "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_indala_224.pm3; lf indala demod'" \
                                                                     "Indala (len 224)  Raw: 80000001b23523a6c2e31eba3cbee4afb3c6ad1fcf649393928c14e5"; then break; fi
      if ! CheckExecute slow "lf T55 io test"                    "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_io.pm3; lf search -1'" "IO Prox ID found"; then break; fi
      if ! CheckExecute slow "lf T55 io test2"                   "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_io.pm3; lf io demod'" \
                                                                     "IO Prox - XSF(01)01:01337, Raw: 007840603059cf3f (ok)"; then break; fi
      if ! CheckExecute slow "lf T55 jablotron test"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_jablotron.pm3; lf search -1'" "Jablotron ID found"; then break; fi
      if ! CheckExecute slow "lf T55 jablotron test2"            "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_jablotron.pm3; lf jablotron demod'" \
                                                                     "Printed: 1410-00-0011-2233"; then break; fi
      if ! CheckExecute slow "lf T55 keri test"                  "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_keri.pm3; lf search -1'" "KERI ID found"; then break; fi
      if ! CheckExecute slow "lf T55 keri test2"                 "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_keri.pm3; lf keri demod'" \
                                                                     "KERI - Internal ID: 112233, Raw: E00000008001B669"; then break; fi
      if ! CheckExecute slow "lf T55 keri_internalid test"       "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_keri_internalid.pm3; lf search -1'" "KERI ID found"; then break; fi
      if ! CheckExecute slow "lf T55 keri_internalid test2"      "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_keri_internalid.pm3; lf keri demod'" \
                                                                     "KERI - Internal ID: 12345, Raw: E000000080003039"; then break; fi
      if ! CheckExecute slow "lf T55 keri_msid test"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_keri_msid.pm3; lf search -1'" "KERI ID found"; then break; fi
      if ! CheckExecute slow "lf T55 keri_msid test2"            "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_keri_msid.pm3; lf keri demod'" \
                                                                     "Descrambled MS - FC: 6 Card: 12345"; then break; fi
#      if ! CheckExecute slow "lf T55 motorola test"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_motorola.pm3; lf search -1'" "Indala ID found"; then break; fi
      if ! CheckExecute slow "lf T55 motorola test2"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_motorola.pm3; lf motorola demod'" \
                                                                     "Motorola - fmt: 26 FC: 258 Card: 2, Raw: A0000000A0002021"; then break; fi
      if ! CheckExecute slow "lf T55 nedap test"                 "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nedap.pm3; lf search -1'" "NEDAP ID found"; then break; fi
      if ! CheckExecute slow "lf T55 nedap test2"                "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nedap.pm3; lf nedap demod'" \
                                                                     "NEDAP (64b) - ID: 12345 subtype: 1 customer code: 291 / 0x123 Raw: FF82246508209953"; then break; fi
      if ! CheckExecute slow "lf T55 nexwatch test"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nexwatch.pm3; lf search -1'" "NexWatch ID found"; then break; fi
      if ! CheckExecute slow "lf T55 nexwatch test2"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nexwatch.pm3; lf nexwatch demod'" \
                                                                     "Raw : 5600000000213C9F8F150C00"; then break; fi
      if ! CheckExecute slow "lf T55 nexwatch_nexkey test"       "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nexwatch_nexkey.pm3; lf search -1'" "NexWatch ID found"; then break; fi
      if ! CheckExecute slow "lf T55 nexwatch_nexkey test2"      "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nexwatch_nexkey.pm3; lf nexwatch demod'" \
                                                                     "88bit id : 521512301 (0x1f15a56d)"; then break; fi
      if ! CheckExecute slow "lf T55 nexwatch_quadrakey test"    "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nexwatch_quadrakey.pm3; lf search -1'" "NexWatch ID found"; then break; fi
      if ! CheckExecute slow "lf T55 nexwatch_quadrakey test2"   "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_nexwatch_quadrakey.pm3; lf nexwatch demod'" \
                                                                     "88bit id : 521512301 (0x1f15a56d)"; then break; fi
      if ! CheckExecute slow "lf T55 noralsy test"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_noralsy.pm3; lf search -1'" "Noralsy ID found"; then break; fi
      if ! CheckExecute slow "lf T55 noralsy test2"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_noralsy.pm3; lf noralsy demod'" \
                                                                     "Noralsy - Card: 112233, Year: 2000, Raw: BB0214FF0110002233070000"; then break; fi
      if ! CheckExecute slow "lf T55 pac test"                   "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_pac.pm3; lf search -1'" "PAC/Stanley ID found"; then break; fi
      if ! CheckExecute slow "lf T55 pac test2"                  "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_pac.pm3; lf pac demod'" \
                                                                     "PAC/Stanley - Card: CD4F5552, Raw: FF2049906D8511C593155B56D5B2649F"; then break; fi
      if ! CheckExecute slow "lf T55 paradox test"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_paradox.pm3; lf search -1'" "Paradox ID found"; then break; fi
      if ! CheckExecute slow "lf T55 paradox test2"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_paradox.pm3; lf paradox demod'" \
                                                                     "Paradox - ID: 004209dea FC: 96 Card: 40426, Checksum: b2, Raw: 0f55555695596a6a9999a59a"; then break; fi
      if ! CheckExecute slow "lf T55 presco test"                "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_presco.pm3; lf search -1'" "Presco ID found"; then break; fi
      if ! CheckExecute slow "lf T55 presco test2"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_presco.pm3; lf presco demod'" \
                                                                     "Presco Site code: 30 User code: 8665 Full code: 1E8021D9 Raw: 10D0000000000000000000001E8021D9"; then break; fi
      if ! CheckExecute slow "lf T55 pyramid test"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_pyramid.pm3; lf search -1'" "Pyramid ID found"; then break; fi
      if ! CheckExecute slow "lf T55 pyramid test2"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_pyramid.pm3; lf pyramid demod'" \
                                                                     "Pyramid - len: 26, FC: 123 Card: 11223 - Wiegand: 2f657ae, Raw: 00010101010101010101016eb35e5da4"; then break; fi
      if ! CheckExecute slow "lf T55 securakey test"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_securakey.pm3; lf search -1'" "Securakey ID found"; then break; fi
      if ! CheckExecute slow "lf T55 securakey test2"            "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_securakey.pm3; lf securakey demod'" \
                                                                     "Securakey - len: 26 FC: 0x35 Card: 64169, Raw: 7FCB400001ADEA5344300000"; then break; fi
      if ! CheckExecute slow "lf T55 viking test"                "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_viking.pm3; lf search -1'" "Viking ID found"; then break; fi
      if ! CheckExecute slow "lf T55 viking test2"               "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_viking.pm3; lf viking demod'" \
                                                                     "Viking - Card 0001A337, Raw: F200000001A337CF"; then break; fi
      if ! CheckExecute slow "lf T55 visa2000 test"              "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_visa2000.pm3; lf search -1'" "Visa2000 ID found"; then break; fi
      if ! CheckExecute slow "lf T55 visa2000 test2"             "$CLIENTBIN -c 'data load -f traces/lf_ATA5577_visa2000.pm3; lf visa2000 demod'" \
                                                                     "Visa2000 - Card 112233, Raw: 564953320001B66900000183"; then break; fi

      echo -e "\n${C_BLUE}Testing HF:${C_NC}"
      if ! CheckExecute "hf mf offline text"               "$CLIENTBIN -c 'hf mf'" "at_enc"; then break; fi
      if ! CheckExecute slow retry ignore "hf mf hardnested long test"  "$CLIENTBIN -c 'hf mf hardnested t 1 000000000000'" "found:"; then break; fi
      if ! CheckExecute slow "hf iclass long test"         "$CLIENTBIN -c 'hf iclass loclass --long'" "verified (ok)"; then break; fi
      if ! CheckExecute slow "emv long test"               "$CLIENTBIN -c 'emv test -l'" "Test(s) \[ ok"; then break; fi
      if ! $SLOWTESTS; then
        if ! CheckExecute "hf iclass test"                 "$CLIENTBIN -c 'hf iclass loclass --test'" "key diversification (ok)"; then break; fi
        if ! CheckExecute "emv test"                       "$CLIENTBIN -c 'emv test'" "Test(s) \[ ok"; then break; fi
      fi
    fi
  echo -e "\n${C_GREEN}Tests [OK]${C_NC}\n"
  exit 0
done
echo -e "\n${C_RED}Tests [FAIL]${C_NC}\n"
exit 1
