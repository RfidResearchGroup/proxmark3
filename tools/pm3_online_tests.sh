#!/usr/bin/env bash

# Online tests that require actual PM3 device connection
# This is used to make sure that the language for the functions is english instead of the system default language.
LANG=C.UTF-8

PM3PATH="$(dirname "$0")/.."
cd "$PM3PATH" || exit 1

TESTALL=false
TESTDESFIREVALUE=false
TESTHIDWIEGAND=false
TESTMFHIDENCODE=false

# https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo """
Usage: $0 [--pm3bin /path/to/pm3] [desfire_value|hid_wiegand|mf_hid_encode]
    --pm3bin ...:    Specify path to pm3 binary to test
    desfire_value:   Test DESFire value operations with card
    hid_wiegand:     Test LF HID simulate/clone Wiegand flows
    mf_hid_encode:   Test MIFARE Classic HID encoding flows
    You must specify a test target - no default 'all' for online tests
"""
      exit 0
      ;;
    --pm3bin)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        PM3BIN=$2
        shift 2
      else
        echo "Error: Argument for $1 is missing" >&2
        exit 1
      fi
      ;;
    desfire_value)
      TESTALL=false
      TESTDESFIREVALUE=true
      shift
      ;;
    hid_wiegand)
      TESTALL=false
      TESTHIDWIEGAND=true
      shift
      ;;
    mf_hid_encode)
      TESTALL=false
      TESTMFHIDENCODE=true
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
C_OK='\xe2\x9c\x94\xef\xb8\x8f'
C_FAIL='\xe2\x9d\x8c'

# Check if file exists
function CheckFileExist() {
  printf "%-40s" "$1 "
  if [ -f "$2" ]; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
    return 0
  fi
  if ls "$2" 1> /dev/null 2>&1; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
    return 0
  fi
  echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
  return 1
}

# Execute command and check result
function CheckExecute() {
  printf "%-40s" "$1 "
  
  start=$(date +%s)
  TIMEINFO=""
  RES=$(eval "$2")
  end=$(date +%s)
  delta=$(expr $end - $start)
  if [ $delta -gt 2 ]; then
    TIMEINFO="  ($delta s)"
  fi
  if echo "$RES" | grep -E -q "$3"; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK} $TIMEINFO"
    return 0
  fi
  echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
  echo "Execution trace:"
  echo "$RES"
  return 1
}

function WaitForEnter() {
  echo ""
  echo "$1"
  echo "Press Enter when ready, or Ctrl-C to abort."
  read -r
}

echo -e "${C_BLUE}Iceman Proxmark3 online test tool${C_NC}"
echo ""
echo "work directory: $(pwd)"

if command -v git >/dev/null && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  echo -n "git branch: "
  git describe --all
  echo -n "git sha: "
  git rev-parse HEAD
  echo ""
fi

# Check that user specified a test
if [ "$TESTDESFIREVALUE" = false ] && [ "$TESTHIDWIEGAND" = false ] && [ "$TESTMFHIDENCODE" = false ]; then
  echo "Error: You must specify a test target. Use -h for help."
  exit 1
fi

while true; do
    # DESFire value tests
    if $TESTDESFIREVALUE; then
      echo -e "\n${C_BLUE}Testing DESFire card value operations${C_NC} ${PM3BIN:=./pm3}"
      echo "  PLACE A FACTORY DESFIRE CARD ON THE READER NOW"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi
      
      echo "  Formatting card to clean state..."
      if ! CheckExecute "format card"                  "$PM3BIN -c 'hf mfdes formatpicc'" "done"; then break; fi
      
      echo "  Running value operation tests..."
      if ! CheckExecute "card auth test"          "$PM3BIN -c 'hf mfdes auth -n 0 -t 2tdea -k 00000000000000000000000000000000 --kdf none'" "authenticated.*succes"; then break; fi
      if ! CheckExecute "card app creation"       "$PM3BIN -c 'hf mfdes createapp --aid 123456 --ks1 0F --ks2 0E --numkeys 1'" "successfully created"; then break; fi
      if ! CheckExecute "card value file creation" "$PM3BIN -c 'hf mfdes createvaluefile --aid 123456 --fid 02 --lower 00000000 --upper 000003E8 --value 00000064'" "created successfully"; then break; fi
      if ! CheckExecute "card value get plain"    "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op get -m plain'" "Value.*100"; then break; fi
      if ! CheckExecute "card value get mac"      "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op get -m mac'" "Value.*100"; then break; fi
      if ! CheckExecute "card value credit plain" "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op credit -d 00000032 -m plain'" "Value.*changed"; then break; fi
      if ! CheckExecute "card value get after credit" "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op get -m plain'" "Value.*150"; then break; fi
      if ! CheckExecute "card value credit mac"   "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op credit -d 0000000A -m mac'" "Value.*changed"; then break; fi
      if ! CheckExecute "card value debit plain"  "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op debit -d 00000014 -m plain'" "Value.*changed"; then break; fi
      if ! CheckExecute "card value debit mac"    "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op debit -d 00000014 -m mac'" "Value.*changed"; then break; fi
      if ! CheckExecute "card value final check"  "$PM3BIN -c 'hf mfdes value --aid 123456 --fid 02 --op get -m mac'" "Value.*120"; then break; fi
      if ! CheckExecute "card cleanup"            "$PM3BIN -c 'hf mfdes selectapp --aid 000000; hf mfdes auth -n 0 -t 2tdea -k 00000000000000000000000000000000 --kdf none; hf mfdes deleteapp --aid 123456'" "application.*deleted"; then break; fi
      echo "  card value operation tests completed successfully!"
    fi

    if $TESTHIDWIEGAND; then
      echo -e "\n${C_BLUE}Testing LF HID Wiegand flows${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      if ! CheckExecute "lf hid sim 26-bit bin"       "$PM3BIN -c 'lf hid sim --bin 10001111100000001010100011'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim raw oversize"     "$PM3BIN -c 'lf hid sim -r 01400076000c86' 2>&1" "LF HID simulation supports only packed credentials up to 37 bits"; then break; fi
      if ! CheckExecute "lf hid sim bin oversize"     "PAT=\$(printf '01%.0s' {1..48}); $PM3BIN -c \"lf hid sim --bin \$PAT\" 2>&1" "LF HID simulation supports only packed credentials up to 37 bits"; then break; fi
      if ! CheckExecute "lf hid sim new oversize"     "$PM3BIN -c 'lf hid sim --new 0000A4550148AB' 2>&1" "LF HID simulation supports only packed credentials up to 37 bits"; then break; fi

      WaitForEnter "PLACE A REWRITABLE T55xx TAG ON THE PM3 NOW"
      if ! CheckExecute "lf hid clone 26-bit bin"     "$PM3BIN -c 'lf hid clone --bin 10001111100000001010100011'" "Done!"; then break; fi
      if ! CheckExecute "lf hid clone raw oversize"   "$PM3BIN -c 'lf hid clone -r 01400076000c86' 2>&1" "LF HID clone supports only packed credentials up to 37 bits"; then break; fi
      if ! CheckExecute "lf hid clone bin oversize"   "PAT=\$(printf '01%.0s' {1..48}); $PM3BIN -c \"lf hid clone --bin \$PAT\" 2>&1" "LF HID clone supports only packed credentials up to 37 bits"; then break; fi
      if ! CheckExecute "lf hid clone new oversize"   "$PM3BIN -c 'lf hid clone --new 0000A4550148AB' 2>&1" "LF HID clone supports only packed credentials up to 37 bits"; then break; fi
    fi

    if $TESTMFHIDENCODE; then
      echo -e "\n${C_BLUE}Testing MIFARE Classic HID encoding${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      WaitForEnter "PLACE A BLANK MIFARE CLASSIC 1K CARD ON THE PM3 NOW"
      if ! CheckExecute "hf mf encodehid bin"        "$PM3BIN -c 'hf mf encodehid --bin 10001111100000001010100011; hf mf rdbl --blk 5 -k FFFFFFFFFFFF'" "023E02A3"; then break; fi
      if ! CheckExecute "hf mf encodehid raw"        "$PM3BIN -c 'hf mf encodehid --raw 023E02A3; hf mf rdbl --blk 5 -k FFFFFFFFFFFF'" "023E02A3"; then break; fi
      if ! CheckExecute "hf mf encodehid new"        "$PM3BIN -c 'hf mf encodehid --new 068F80A8C0; hf mf rdbl --blk 5 -k FFFFFFFFFFFF'" "023E02A3"; then break; fi
    fi
  
  echo -e "\n------------------------------------------------------------"
  echo -e "Tests [ ${C_GREEN}OK${C_NC} ] ${C_OK}\n"
  exit 0
done
echo -e "\n------------------------------------------------------------"
echo -e "\nTests [ ${C_RED}FAIL${C_NC} ] ${C_FAIL}\n"
exit 1
