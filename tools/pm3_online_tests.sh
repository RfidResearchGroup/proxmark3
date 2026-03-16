#!/usr/bin/env bash

# Online tests that require actual PM3 device connection
# This is used to make sure that the language for the functions is english instead of the system default language.
LANG=C.UTF-8

PM3PATH="$(dirname "$0")/.."
cd "$PM3PATH" || exit 1

TESTALL=false
TESTDESFIREVALUE=false
TESTHFMFEMUMEM=false
TESTHFMFENCODEHIDEMU=false
TESTHFMFENCODEHIDCARD=false
TESTHFEMUSMOKE=false
TESTLFHIDSIM=false

# https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo """
Usage: $0 [--pm3bin /path/to/pm3] [desfire_value|hf_mf_emu_mem|hf_mf_encodehid_emu|hf_mf_encodehid_card|hf_emu_smoke|lf_hid_sim]
    --pm3bin ...:    Specify path to pm3 binary to test
    desfire_value:   Test DESFire value operations with card
    hf_mf_emu_mem:   Test MIFARE Classic emulator memory write/read
    hf_mf_encodehid_emu:
                     Test hf mf encodehid --bin/--raw/--new equivalence in emulator memory
    hf_mf_encodehid_card:
                     Test HID encoding write/read against a blank MIFARE Classic card
    hf_emu_smoke:    Run HF emulator/card smoke tests
    lf_hid_sim:      Test lf hid sim --bin/--new and reject >37-bit simulation
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
    hf_mf_emu_mem)
      TESTALL=false
      TESTHFMFEMUMEM=true
      shift
      ;;
    hf_mf_encodehid_emu)
      TESTALL=false
      TESTHFMFENCODEHIDEMU=true
      shift
      ;;
    hf_mf_encodehid_card)
      TESTALL=false
      TESTHFMFENCODEHIDCARD=true
      shift
      ;;
    hf_emu_smoke)
      TESTALL=false
      TESTHFEMUSMOKE=true
      shift
      ;;
    lf_hid_sim)
      TESTALL=false
      TESTLFHIDSIM=true
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

function CheckOutputContains() {
  printf "%-40s" "$1 "
  RES=$(eval "$2")
  if printf '%s' "$RES" | grep -F -q "$3"; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
    return 0
  fi
  echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
  echo "Execution trace:"
  echo "$RES"
  return 1
}

function CheckHexOutputContains() {
  local EXPECTED_SPACED
  EXPECTED_SPACED=$(printf '%s' "$3" | sed 's/../& /g; s/ $//')
  CheckOutputContains "$1" "$2" "$EXPECTED_SPACED"
}

function LoadEncodeHidFixtures() {
  local RES

  RES=$($PM3BIN -c 'wiegand encode -w H10301 --fc 31 --cn 337 --new -v')
  ENCODEHID_FIXTURE_BIN=$(printf '%s\n' "$RES" | sed -n 's/.*Without Sentinel\. .*0b \([01][01]*\).*/\1/p' | tail -n 1)
  ENCODEHID_FIXTURE_RAW=$(printf '%s\n' "$RES" | sed -n 's/.*Wiegand --raw.... .*0x \([0-9A-Fa-f][0-9A-Fa-f]*\).*/\1/p' | tail -n 1)
  ENCODEHID_FIXTURE_NEW=$(printf '%s\n' "$RES" | sed -n 's/.*New PACS......... .*0x \([0-9A-Fa-f][0-9A-Fa-f]*\).*/\1/p' | tail -n 1)

  [ -n "$ENCODEHID_FIXTURE_BIN" ] && [ -n "$ENCODEHID_FIXTURE_RAW" ] && [ -n "$ENCODEHID_FIXTURE_NEW" ]
}

function CleanupEncodeHidCard() {
  local DEFAULT_TRAILER="FFFFFFFFFFFFFF078069FFFFFFFFFFFF"

  echo "  Restoring test card blocks 1-7 to default blank state..."
  if ! CheckExecute "wipe card block 1" "$PM3BIN -c 'hf mf wrbl --blk 1 -b -k 89ECA97F8C2A -d 00000000000000000000000000000000'" "Write.*ok"; then return 1; fi
  if ! CheckExecute "wipe card block 2" "$PM3BIN -c 'hf mf wrbl --blk 2 -b -k 89ECA97F8C2A -d 00000000000000000000000000000000'" "Write.*ok"; then return 1; fi
  if ! CheckExecute "restore trailer 3" "$PM3BIN -c 'hf mf wrbl --blk 3 -b -k 89ECA97F8C2A -d $DEFAULT_TRAILER'" "Write.*ok"; then return 1; fi
  if ! CheckExecute "wipe card block 4" "$PM3BIN -c 'hf mf wrbl --blk 4 -b -k 204752454154 -d 00000000000000000000000000000000'" "Write.*ok"; then return 1; fi
  if ! CheckExecute "wipe card block 5" "$PM3BIN -c 'hf mf wrbl --blk 5 -b -k 204752454154 -d 00000000000000000000000000000000'" "Write.*ok"; then return 1; fi
  if ! CheckExecute "wipe card block 6" "$PM3BIN -c 'hf mf wrbl --blk 6 -b -k 204752454154 -d 00000000000000000000000000000000'" "Write.*ok"; then return 1; fi
  if ! CheckExecute "restore trailer 7" "$PM3BIN -c 'hf mf wrbl --blk 7 -b -k 204752454154 -d $DEFAULT_TRAILER'" "Write.*ok"; then return 1; fi
  return 0
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
if [ "$TESTHFEMUSMOKE" = true ]; then
  TESTHFMFEMUMEM=true
  TESTHFMFENCODEHIDEMU=true
  TESTHFMFENCODEHIDCARD=true
fi

if [ "$TESTDESFIREVALUE" = false ] && [ "$TESTHFMFEMUMEM" = false ] && [ "$TESTHFMFENCODEHIDEMU" = false ] && [ "$TESTHFMFENCODEHIDCARD" = false ] && [ "$TESTLFHIDSIM" = false ]; then
  echo "Error: You must specify a test target. Use -h for help."
  exit 1
fi

while true; do
    if $TESTHFMFEMUMEM; then
      echo -e "\n${C_BLUE}Testing MIFARE Classic emulator memory${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      if ! CheckExecute "clear emulator memory"      "$PM3BIN -c 'hf mf eclr'" "pm3 -->"; then break; fi
      if ! CheckExecute "write emulator block 1"     "$PM3BIN -c 'hf mf esetblk --blk 1 -d 11223344556677889900AABBCCDDEEFF'" "pm3 -->"; then break; fi
      if ! CheckExecute "write emulator block 2"     "$PM3BIN -c 'hf mf esetblk --blk 2 -d 0102030405060708090A0B0C0D0E0F10'" "pm3 -->"; then break; fi
      if ! CheckHexOutputContains "read emulator block 1" "$PM3BIN -c 'hf mf egetblk --blk 1'" "11223344556677889900AABBCCDDEEFF"; then break; fi
      if ! CheckHexOutputContains "read emulator block 2" "$PM3BIN -c 'hf mf egetblk --blk 2'" "0102030405060708090A0B0C0D0E0F10"; then break; fi
      echo "  emulator memory tests completed successfully!"
    fi

    if $TESTHFMFENCODEHIDEMU; then
      echo -e "\n${C_BLUE}Testing hf mf encodehid emulator fixtures${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi
      if ! LoadEncodeHidFixtures; then
        echo "Failed to derive encodehid fixtures from wiegand encode output"
        break
      fi

      EXPECTED_BLOCK5="020000000000000000000000063E02A3"

      if ! CheckExecute "encode HID --bin to emulator" "$PM3BIN -c 'hf mf encodehid --bin $ENCODEHID_FIXTURE_BIN --emu'" "Credential written to emulator memory"; then break; fi
      if ! CheckHexOutputContains "read emulator block 5 from --bin" "$PM3BIN -c 'hf mf egetblk --blk 5'" "$EXPECTED_BLOCK5"; then break; fi

      if ! CheckExecute "encode HID --raw to emulator" "$PM3BIN -c 'hf mf encodehid --raw $ENCODEHID_FIXTURE_RAW --emu'" "Credential written to emulator memory"; then break; fi
      if ! CheckHexOutputContains "read emulator block 5 from --raw" "$PM3BIN -c 'hf mf egetblk --blk 5'" "$EXPECTED_BLOCK5"; then break; fi

      if ! CheckExecute "encode HID --new to emulator" "$PM3BIN -c 'hf mf encodehid --new $ENCODEHID_FIXTURE_NEW --emu'" "Credential written to emulator memory"; then break; fi
      if ! CheckHexOutputContains "read emulator block 5 from --new" "$PM3BIN -c 'hf mf egetblk --blk 5'" "$EXPECTED_BLOCK5"; then break; fi

      echo "  encodehid emulator fixture tests completed successfully!"
    fi

    if $TESTHFMFENCODEHIDCARD; then
      CARD_TEST_RESTORE_NEEDED=false
      echo -e "\n${C_BLUE}Testing hf mf encodehid against card${C_NC} ${PM3BIN:=./pm3}"
      echo "  PLACE A BLANK DEFAULT-KEY MIFARE CLASSIC CARD ON THE READER NOW"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      if ! CheckExecute "encode HID to card"         "$PM3BIN -c 'hf mf encodehid -w H10301 --fc 31 --cn 337'" "pm3 -->"; then break; fi
      CARD_TEST_RESTORE_NEEDED=true
      if ! CheckHexOutputContains "read card block 1"   "$PM3BIN -c 'hf mf rdbl --blk 1 -k A0A1A2A3A4A5'" "1B014D48000000000000000000000000"; then CleanupEncodeHidCard; break; fi
      if ! CheckHexOutputContains "read card block 3 acl"   "$PM3BIN -c 'hf mf rdbl --blk 3 -k A0A1A2A3A4A5'" "000000000000787788C1000000000000"; then CleanupEncodeHidCard; break; fi
      if ! CheckHexOutputContains "read card block 5"   "$PM3BIN -c 'hf mf rdbl --blk 5 -k 484944204953'" "020000000000000000000000063E02A3"; then CleanupEncodeHidCard; break; fi
      if ! CheckHexOutputContains "read card block 7 acl"   "$PM3BIN -c 'hf mf rdbl --blk 7 -k 484944204953'" "000000000000787788AA000000000000"; then CleanupEncodeHidCard; break; fi
      if ! CleanupEncodeHidCard; then break; fi
      CARD_TEST_RESTORE_NEEDED=false
      echo "  encodehid card write/read tests completed successfully!"
    fi

    if $TESTLFHIDSIM; then
      echo -e "\n${C_BLUE}Testing lf hid sim input modes${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi

      LFHIDSIM_REJECT_BIN=$(printf '01%.0s' {1..19})
      LFHIDSIM_REJECT_NEW="025555555554"

      if ! CheckExecute "lf hid sim --bin" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim --bin 10001111100000001010100011'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim --new" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim --new 068F80A8C0'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim 35-bit raw" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim -r 2e0ec00c87'" "Simulating HID tag using raw"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit --bin reject" "$PM3BIN -c 'lf hid sim --bin $LFHIDSIM_REJECT_BIN' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit --new reject" "$PM3BIN -c 'lf hid sim --new $LFHIDSIM_REJECT_NEW' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 40-bit raw reject" "$PM3BIN -c 'lf hid sim -r 01f0760643c3' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit format reject" "$PM3BIN -c 'lf hid sim -w BQT38 --fc 1 --cn 1 -i 1' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi

      echo "  lf hid sim tests completed successfully!"
    fi

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
  
  echo -e "\n------------------------------------------------------------"
  echo -e "Tests [ ${C_GREEN}OK${C_NC} ] ${C_OK}\n"
  exit 0
done
echo -e "\n------------------------------------------------------------"
echo -e "\nTests [ ${C_RED}FAIL${C_NC} ] ${C_FAIL}\n"
exit 1
