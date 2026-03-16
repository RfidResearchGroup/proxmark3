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
TESTHFICLASSENCODEEMU=false
TESTHFMFENCODEHIDCARD=false
TESTHFEMUSMOKE=false
TESTLFHIDSIM=false
TESTWIEGANDEMUSMOKE=false
TESTLFHIDCLONE=false
TESTLFT55XXROUNDTRIP=false
TESTLFT55XXDETECT=false
TESTLFT55XXDETECTWAKEUP=false
TESTLFT55XXSMOKE=false

# https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo """
Usage: $0 [--pm3bin /path/to/pm3] [desfire_value|hf_mf_emu_mem|hf_mf_encodehid_emu|hf_iclass_encode_emu|hf_mf_encodehid_card|hf_emu_smoke|wiegand_emu_smoke|lf_hid_sim|lf_hid_clone|lf_t55xx_roundtrip|lf_t55xx_detect|lf_t55xx_detect_wakeup|lf_t55xx_smoke]
    --pm3bin ...:    Specify path to pm3 binary to test
    desfire_value:   Test DESFire value operations with card
    hf_mf_emu_mem:   Test MIFARE Classic emulator memory write/read
    hf_mf_encodehid_emu:
                     Test hf mf encodehid --bin/--raw/--new equivalence in emulator memory
    hf_iclass_encode_emu:
                     Test hf iclass encode --bin/--wiegand equivalence in emulator memory
    hf_mf_encodehid_card:
                     Test HID encoding write/read against a blank MIFARE Classic card
    hf_emu_smoke:    Run HF emulator smoke tests without cards
    wiegand_emu_smoke:
                     Run non-card Wiegand emulator tests
    lf_hid_sim:      Test lf hid sim across 26/35-bit fixtures and reject >37-bit simulation
    lf_hid_clone:    Test lf hid clone on a writable T55x7 tag
    lf_t55xx_roundtrip:
                     Test first-class T55x7 clone+reader credential round trips
    lf_t55xx_detect:
                     Test lf t55xx detect across representative T55x7 configs
    lf_t55xx_detect_wakeup:
                     Test lf t55xx detect wakeup/init-delay recovery on T55x7
    lf_t55xx_smoke:  Run T55x7 round-trip, detect, and wakeup tests
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
    hf_iclass_encode_emu)
      TESTALL=false
      TESTHFICLASSENCODEEMU=true
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
    wiegand_emu_smoke)
      TESTALL=false
      TESTWIEGANDEMUSMOKE=true
      shift
      ;;
    lf_hid_sim)
      TESTALL=false
      TESTLFHIDSIM=true
      shift
      ;;
    lf_hid_clone)
      TESTALL=false
      TESTLFHIDCLONE=true
      shift
      ;;
    lf_t55xx_roundtrip)
      TESTALL=false
      TESTLFT55XXROUNDTRIP=true
      shift
      ;;
    lf_t55xx_detect)
      TESTALL=false
      TESTLFT55XXDETECT=true
      shift
      ;;
    lf_t55xx_detect_wakeup)
      TESTALL=false
      TESTLFT55XXDETECTWAKEUP=true
      shift
      ;;
    lf_t55xx_smoke)
      TESTALL=false
      TESTLFT55XXSMOKE=true
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

function CheckOutputContainsAll() {
  local LABEL="$1"
  local CMD="$2"
  shift 2
  printf "%-40s" "$LABEL "
  RES=$(eval "$CMD")
  while [ "$#" -gt 0 ]; do
    if ! printf '%s' "$RES" | grep -F -q "$1"; then
      echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
      echo "Execution trace:"
      echo "$RES"
      return 1
    fi
    shift
  done
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  return 0
}

function CheckHexOutputContains() {
  local EXPECTED_SPACED
  EXPECTED_SPACED=$(printf '%s' "$3" | sed 's/../& /g; s/ $//')
  CheckOutputContains "$1" "$2" "$EXPECTED_SPACED"
}

function GetMifareEGetBlkLine() {
  eval "$PM3BIN -c 'hf mf egetblk --blk $1'" | sed -n 's/.*| \(.*\) | .*/\1/p' | tail -n 1
}

function GetMifareRdBlkLine() {
  eval "$PM3BIN -c 'hf mf rdbl --blk $1 -k $2'" | sed -n 's/.*| \(.*\) | .*/\1/p' | tail -n 1
}

function WaitForUserCard() {
  echo "  $1"
  if [ -t 0 ]; then
    read -r -p "  Press Enter when ready..." _
  fi
}

function WaitForUserLFTag() {
  echo "  $1"
  if [ -t 0 ]; then
    read -r -p "  Press Enter when ready..." _
  fi
}

function BackupT55xxTag() {
  T55XX_DUMP_BASE=$(mktemp /tmp/pm3-t55xx-online-XXXXXX)
  rm -f "$T55XX_DUMP_BASE"
  local RES
  RES=$($PM3BIN -c "lf t55xx detect; lf t55xx dump -f $T55XX_DUMP_BASE")
  if [ ! -f "${T55XX_DUMP_BASE}.bin" ]; then
    echo "Failed to save T55xx dump"
    echo "$RES"
    return 1
  fi
  T55XX_BACKUP_ACTIVE=true
  return 0
}

function GetT55xxConfigBlock0() {
  eval "$PM3BIN -c 'lf t55xx config $1'" | sed -n 's/.*Block0............ \([0-9A-F]*\).*/\1/p' | tail -n 1
}

function RestoreT55xxTag() {
  if [ "$T55XX_BACKUP_ACTIVE" != true ] || [ ! -f "${T55XX_DUMP_BASE}.bin" ]; then
    return 0
  fi
  CheckExecute "restore T55xx tag" "$PM3BIN -c 'lf t55xx restore -f ${T55XX_DUMP_BASE}.bin'" "Done|Restoring" || return 1
  return 0
}

function CleanupT55xxBackupFiles() {
  if [ -n "$T55XX_DUMP_BASE" ]; then
    rm -f "${T55XX_DUMP_BASE}.bin" "${T55XX_DUMP_BASE}.json"
  fi
  T55XX_BACKUP_ACTIVE=false
}

function CheckT55xxDetectResult() {
  local LABEL="$1"
  local MOD="$2"
  local RATE="$3"
  local BLOCK0="$4"
  CheckOutputContainsAll "$LABEL" "$PM3BIN -c 'lf t55xx detect'" \
    "Chip type......... T55x7" \
    "Modulation........ $MOD" \
    "Bit rate.......... $RATE" \
    "Block0............ $BLOCK0"
}

function CheckT55xxDetectFixture() {
  local LABEL="$1"
  local CLONE_CMD="$2"
  local MOD="$3"
  local RATE="$4"
  local BLOCK0="$5"

  if ! CheckExecute "clone $LABEL" "$CLONE_CMD" "Done!|Tag T55x7 written"; then return 1; fi
  if ! CheckT55xxDetectResult "detect $LABEL" "$MOD" "$RATE" "$BLOCK0"; then return 1; fi
  return 0
}

function CheckT55xxDetectConfigFixture() {
  local LABEL="$1"
  local CONFIG_ARGS="$2"
  local EXPECT_MOD="$3"
  local EXPECT_RATE="$4"
  local EXPECT_ST="$5"
  local BLOCK0

  BLOCK0=$(GetT55xxConfigBlock0 "$CONFIG_ARGS")
  if [ -z "$BLOCK0" ]; then
    echo "Failed to derive block0 for $LABEL using: $CONFIG_ARGS"
    return 1
  fi

  if ! CheckExecute "write $LABEL block0" "$PM3BIN -c 'lf t55xx write -b 0 -d $BLOCK0'" "Writing page 0  block: 00|Done"; then
    return 1
  fi

  CheckOutputContainsAll "detect $LABEL" "$PM3BIN -c 'lf t55xx detect'" \
    "Modulation........ $EXPECT_MOD" \
    "Bit rate.......... $EXPECT_RATE" \
    "Seq. terminator... $EXPECT_ST" \
    "Block0............ $BLOCK0" || return 1

  return 0
}

function CheckT55xxDetectWakeupFixture() {
  local AOR_POR_BLOCK0="$2"

  if ! CheckExecute "clone wakeup fixture" "$PM3BIN -c 'lf hid clone -w H10301 --fc 31 --cn 337'" "Done!"; then return 1; fi
  if ! CheckExecute "enable AOR/POR" "$PM3BIN -c 'lf t55xx write -b 0 -d $AOR_POR_BLOCK0'" "Writing page 0  block: 00"; then return 1; fi
  if ! CheckOutputContainsAll "detect wakeup fixture" "$PM3BIN -c 'lf t55xx detect'" \
    "Chip type......... T55x7" \
    "Modulation........ FSK2a" \
    "Bit rate.......... 4 - RF/50" \
    "Block0............ $AOR_POR_BLOCK0"; then return 1; fi
  return 0
}

function LoadWiegandFixtures() {
  local FORMAT="$1"
  local FC="$2"
  local CN="$3"
  local ISSUE="$4"
  local RES
  local CMD="wiegand encode -w $FORMAT --fc $FC --cn $CN --new -v"
  local PRE_RES
  local PRE_CMD="wiegand encode -w $FORMAT --fc $FC --cn $CN --pre -v"

  if [ -n "$ISSUE" ]; then
    CMD="$CMD --issue $ISSUE"
    PRE_CMD="$PRE_CMD --issue $ISSUE"
  fi

  RES=$($PM3BIN -c "$CMD")
  PRE_RES=$($PM3BIN -c "$PRE_CMD")
  WIEGAND_FIXTURE_BIN=$(printf '%s\n' "$RES" | sed -n 's/.*Without Sentinel\. .*0b \([01][01]*\).*/\1/p' | tail -n 1)
  WIEGAND_FIXTURE_RAW=$(printf '%s\n' "$RES" | sed -n 's/.*Wiegand --raw.... .*0x \([0-9A-Fa-f][0-9A-Fa-f]*\).*/\1/p' | tail -n 1)
  WIEGAND_FIXTURE_NEW=$(printf '%s\n' "$RES" | sed -n 's/.*New PACS......... .*0x \([0-9A-Fa-f][0-9A-Fa-f]*\).*/\1/p' | tail -n 1)
  WIEGAND_FIXTURE_LF_RAW=$(printf '%s\n' "$PRE_RES" | sed -n 's/.*Wiegand: \([0-9A-Fa-f][0-9A-Fa-f]*\).*/\1/p' | tail -n 1)
  if [ $(( ${#WIEGAND_FIXTURE_LF_RAW} % 2 )) -ne 0 ]; then
    WIEGAND_FIXTURE_LF_RAW="0${WIEGAND_FIXTURE_LF_RAW}"
  fi
  [ -n "$WIEGAND_FIXTURE_BIN" ] && [ -n "$WIEGAND_FIXTURE_RAW" ] && [ -n "$WIEGAND_FIXTURE_NEW" ] && [ -n "$WIEGAND_FIXTURE_LF_RAW" ]
}

function CheckMifareEncodeHidFixture() {
  local LABEL="$1"
  local FORMAT="$2"
  local FC="$3"
  local CN="$4"
  local ISSUE="$5"
  local EXPECTED_BLOCK5="$6"

  if ! LoadWiegandFixtures "$FORMAT" "$FC" "$CN" "$ISSUE"; then
    echo "Failed to derive $LABEL fixtures from wiegand encode output"
    return 1
  fi

  if ! CheckExecute "encode $LABEL --bin to emulator" "$PM3BIN -c 'hf mf encodehid --bin $WIEGAND_FIXTURE_BIN --emu'" "Credential written to emulator memory"; then return 1; fi
  MIFARE_BLOCK5_BIN=$(GetMifareEGetBlkLine 5)
  if [ -z "$MIFARE_BLOCK5_BIN" ]; then
    echo "Failed to read MIFARE block 5 for $LABEL --bin"
    return 1
  fi
  printf "%-40s" "read $LABEL block 5 from --bin "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  if [ -n "$EXPECTED_BLOCK5" ] && ! printf '%s' "$MIFARE_BLOCK5_BIN" | grep -F -q "$(printf '%s' "$EXPECTED_BLOCK5" | sed 's/../& /g; s/ $//')"; then
    echo "Expected block 5 not found for $LABEL --bin"
    echo "$MIFARE_BLOCK5_BIN"
    return 1
  fi

  if ! CheckExecute "encode $LABEL --raw to emulator" "$PM3BIN -c 'hf mf encodehid --raw $WIEGAND_FIXTURE_RAW --emu'" "Credential written to emulator memory"; then return 1; fi
  MIFARE_BLOCK5_RAW=$(GetMifareEGetBlkLine 5)
  if [ "$MIFARE_BLOCK5_RAW" != "$MIFARE_BLOCK5_BIN" ]; then
    echo "MIFARE block 5 mismatch for $LABEL --raw"
    echo "$MIFARE_BLOCK5_RAW"
    return 1
  fi
  printf "%-40s" "compare $LABEL block 5 --raw "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"

  if ! CheckExecute "encode $LABEL --new to emulator" "$PM3BIN -c 'hf mf encodehid --new $WIEGAND_FIXTURE_NEW --emu'" "Credential written to emulator memory"; then return 1; fi
  MIFARE_BLOCK5_NEW=$(GetMifareEGetBlkLine 5)
  if [ "$MIFARE_BLOCK5_NEW" != "$MIFARE_BLOCK5_BIN" ]; then
    echo "MIFARE block 5 mismatch for $LABEL --new"
    echo "$MIFARE_BLOCK5_NEW"
    return 1
  fi
  printf "%-40s" "compare $LABEL block 5 --new "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  return 0
}

function CheckMifareEncodeHidLongNewFixture() {
  local LABEL="$1"
  local BIN="$2"
  local EXPECTED_BLOCK5="$3"
  local RES
  local LONG_NEW

  RES=$($PM3BIN -c "wiegand encode --bin $BIN --new -v")
  LONG_NEW=$(printf '%s\n' "$RES" | sed -n 's/.*New PACS......... .*0x \([0-9A-Fa-f][0-9A-Fa-f]*\).*/\1/p' | tail -n 1)
  if [ -z "$LONG_NEW" ]; then
    echo "Failed to derive $LABEL long new PACS fixture"
    echo "$RES"
    return 1
  fi

  if ! CheckExecute "encode $LABEL --bin to emulator" "$PM3BIN -c 'hf mf encodehid --bin $BIN --emu'" "Credential written to emulator memory"; then return 1; fi
  MIFARE_BLOCK5_BIN=$(GetMifareEGetBlkLine 5)
  if [ -z "$MIFARE_BLOCK5_BIN" ]; then
    echo "Failed to read MIFARE block 5 for $LABEL --bin"
    return 1
  fi
  printf "%-40s" "read $LABEL block 5 from --bin "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  if [ -n "$EXPECTED_BLOCK5" ] && ! printf '%s' "$MIFARE_BLOCK5_BIN" | grep -F -q "$(printf '%s' "$EXPECTED_BLOCK5" | sed 's/../& /g; s/ $//')"; then
    echo "Expected block 5 not found for $LABEL --bin"
    echo "$MIFARE_BLOCK5_BIN"
    return 1
  fi

  if ! CheckExecute "encode $LABEL --new to emulator" "$PM3BIN -c 'hf mf encodehid --new $LONG_NEW --emu'" "Credential written to emulator memory"; then return 1; fi
  MIFARE_BLOCK5_NEW=$(GetMifareEGetBlkLine 5)
  if [ "$MIFARE_BLOCK5_NEW" != "$MIFARE_BLOCK5_BIN" ]; then
    echo "MIFARE block 5 mismatch for $LABEL --new"
    echo "$MIFARE_BLOCK5_NEW"
    return 1
  fi
  printf "%-40s" "compare $LABEL block 5 --new "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  return 0
}

function GetIClassEView() {
  eval "$PM3BIN -c 'hf iclass eview'" | sed -n 's/.*\(  [6-9]\/0x0[6-9] | .*User AA2\)/\1/p'
}

function CheckIClassEncodeFixture() {
  local LABEL="$1"
  local FORMAT="$2"
  local FC="$3"
  local CN="$4"
  local ISSUE="$5"
  local EXPECT6="$6"
  local EXPECT7="$7"
  local EXPECT8="$8"
  local EXPECT9="$9"
  local ICLASS_ENCODE_KEY="000102030405060708090A0B0C0D0E0F"

  if ! LoadWiegandFixtures "$FORMAT" "$FC" "$CN" "$ISSUE"; then
    echo "Failed to derive $LABEL fixtures from wiegand encode output"
    return 1
  fi

  if ! CheckExecute "encode $LABEL iClass --bin" "$PM3BIN -c 'hf iclass encode --bin $WIEGAND_FIXTURE_BIN --emu --enckey $ICLASS_ENCODE_KEY'" "uploaded 32 bytes to emulator memory"; then return 1; fi
  ICLASS_EVIEW_BIN=$(GetIClassEView)
  if [ -n "$EXPECT6" ] && ! printf '%s' "$ICLASS_EVIEW_BIN" | grep -F -q "$EXPECT6"; then echo "$ICLASS_EVIEW_BIN"; return 1; fi
  if [ -n "$EXPECT7" ] && ! printf '%s' "$ICLASS_EVIEW_BIN" | grep -F -q "$EXPECT7"; then echo "$ICLASS_EVIEW_BIN"; return 1; fi
  if [ -n "$EXPECT8" ] && ! printf '%s' "$ICLASS_EVIEW_BIN" | grep -F -q "$EXPECT8"; then echo "$ICLASS_EVIEW_BIN"; return 1; fi
  if [ -n "$EXPECT9" ] && ! printf '%s' "$ICLASS_EVIEW_BIN" | grep -F -q "$EXPECT9"; then echo "$ICLASS_EVIEW_BIN"; return 1; fi
  printf "%-40s" "read $LABEL iClass blocks from --bin "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"

  local WIEGAND_CMD="$PM3BIN -c 'hf iclass encode -w $FORMAT --fc $FC --cn $CN --emu --enckey $ICLASS_ENCODE_KEY'"
  if [ -n "$ISSUE" ]; then
    WIEGAND_CMD="$PM3BIN -c 'hf iclass encode -w $FORMAT --fc $FC --cn $CN --issue $ISSUE --emu --enckey $ICLASS_ENCODE_KEY'"
  fi
  if ! CheckExecute "encode $LABEL iClass --wiegand" "$WIEGAND_CMD" "uploaded 32 bytes to emulator memory"; then return 1; fi
  ICLASS_EVIEW_WIEGAND=$(GetIClassEView)
  if [ "$ICLASS_EVIEW_WIEGAND" != "$ICLASS_EVIEW_BIN" ]; then
    echo "iClass emulator mismatch for $LABEL --wiegand"
    echo "$ICLASS_EVIEW_WIEGAND"
    return 1
  fi
  printf "%-40s" "compare $LABEL iClass --wiegand "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  return 0
}

function CheckLFCloneFixture() {
  local LABEL="$1"
  local FORMAT="$2"
  local FC="$3"
  local CN="$4"
  local ISSUE="$5"
  local EXPECT_FORMAT="$6"
  local EXPECT_FC="$7"
  local EXPECT_CN="$8"

  if ! LoadWiegandFixtures "$FORMAT" "$FC" "$CN" "$ISSUE"; then
    echo "Failed to derive $LABEL fixtures from wiegand encode output"
    return 1
  fi

  if ! CheckExecute "clone $LABEL --bin" "$PM3BIN -c 'lf hid clone --bin $WIEGAND_FIXTURE_BIN'" "Done!"; then return 1; fi
  if ! CheckExecute "read $LABEL after --bin" "$PM3BIN -c 'lf hid reader'" "$EXPECT_FORMAT.*FC: $EXPECT_FC.*CN: $EXPECT_CN"; then return 1; fi

  if ! CheckExecute "clone $LABEL --raw" "$PM3BIN -c 'lf hid clone --raw $WIEGAND_FIXTURE_LF_RAW'" "Done!"; then return 1; fi
  if ! CheckExecute "read $LABEL after --raw" "$PM3BIN -c 'lf hid reader'" "$EXPECT_FORMAT.*FC: $EXPECT_FC.*CN: $EXPECT_CN"; then return 1; fi

  if ! CheckExecute "clone $LABEL --new" "$PM3BIN -c 'lf hid clone --new $WIEGAND_FIXTURE_NEW'" "Done!"; then return 1; fi
  if ! CheckExecute "read $LABEL after --new" "$PM3BIN -c 'lf hid reader'" "$EXPECT_FORMAT.*FC: $EXPECT_FC.*CN: $EXPECT_CN"; then return 1; fi

  local CLONE_CMD="$PM3BIN -c 'lf hid clone -w $FORMAT --fc $FC --cn $CN'"
  if [ -n "$ISSUE" ]; then
    CLONE_CMD="$PM3BIN -c 'lf hid clone -w $FORMAT --fc $FC --cn $CN -i $ISSUE'"
  fi
  if ! CheckExecute "clone $LABEL --wiegand" "$CLONE_CMD" "Done!"; then return 1; fi
  if ! CheckExecute "read $LABEL after --wiegand" "$PM3BIN -c 'lf hid reader'" "$EXPECT_FORMAT.*FC: $EXPECT_FC.*CN: $EXPECT_CN"; then return 1; fi
  return 0
}

function CheckLFReaderRoundTripFixture() {
  local LABEL="$1"
  local CLONE_CMD="$2"
  local READER_CMD="$3"
  local EXPECT_RE="$4"

  if ! CheckExecute "clone $LABEL" "$CLONE_CMD" "Done!|Tag T55x7 written"; then return 1; fi
  if ! CheckExecute "read $LABEL" "$READER_CMD" "$EXPECT_RE"; then return 1; fi
  return 0
}

function CheckLFReaderRoundTripContainsAll() {
  local LABEL="$1"
  local CLONE_CMD="$2"
  local READER_CMD="$3"
  shift 3

  if ! CheckExecute "clone $LABEL" "$CLONE_CMD" "Done!|Tag T55x7 written"; then return 1; fi
  if ! CheckOutputContainsAll "read $LABEL" "$READER_CMD" "$@"; then return 1; fi
  return 0
}

function RunLFHidCloneFixtures() {
  if ! CheckLFCloneFixture "H10301" "H10301" "31" "337" "" "H10301" "31" "337"; then return 1; fi
  if ! CheckLFCloneFixture "C1k35s" "C1k35s" "222" "12345" "" "C1k35s" "222" "12345"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "HID 48 raw" "$PM3BIN -c 'lf hid clone -r 01400076000c86'" "$PM3BIN -c 'lf hid reader'" "HID Corporate 1000 48-bit"; then return 1; fi
  return 0
}

function RunLFT55xxRoundTripFixtures() {
  # Keep HID on the same round-trip matrix so T55x7 clone coverage stays in one place.
  if ! RunLFHidCloneFixtures; then return 1; fi

  if ! CheckLFReaderRoundTripFixture "AWID 26" "$PM3BIN -c 'lf awid clone --fmt 26 --fc 224 --cn 1337'" "$PM3BIN -c 'lf awid reader'" "AWID - len: 26 FC: 224 Card: 1337"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Destron" "$PM3BIN -c 'lf destron clone --uid 1A2B3C4D5E'" "$PM3BIN -c 'lf destron reader'" "FDX-A FECAVA Destron: 1A2B3C4D5E"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "EM410x" "$PM3BIN -c 'lf em 410x clone --id 0F0368568B'" "$PM3BIN -c 'lf em 410x reader'" "EM 410x ID 0F0368568B"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "FDX-B animal" "$PM3BIN -c 'lf fdxb clone --country 999 --national 112233 --animal'" "$PM3BIN -c 'lf fdxb reader'" "Animal ID.*999-000000112233"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Gallagher" "$PM3BIN -c 'lf gallagher clone --raw 0FFD5461A9DA1346B2D1AC32'" "$PM3BIN -c 'lf gallagher reader'" "GALLAGHER - Region: 1 Facility: 16640 Card No\\.: 201 Issue Level: 1"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Guardall G-Prox II" "$PM3BIN -c 'lf gproxii clone --xor 102 --fmt 26 --fc 123 --cn 11223'" "$PM3BIN -c 'lf gproxii reader'" "G-Prox-II - Len: 26 FC: 123 Card: 11223"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Idteck" "$PM3BIN -c 'lf idteck clone --raw 4944544B351FBE4B'" "$PM3BIN -c 'lf idteck reader'" "Raw: 4944544B351FBE4B"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Indala 26" "$PM3BIN -c 'lf indala clone --fc 123 --cn 1337'" "$PM3BIN -c 'lf indala reader'" "Fmt 26 FC: 123 Card: 1337"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "ioProx" "$PM3BIN -c 'lf io clone --vn 1 --fc 101 --cn 1337'" "$PM3BIN -c 'lf io reader'" "IO Prox - XSF\\(01\\)65:01337"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Jablotron" "$PM3BIN -c 'lf jablotron clone --cn 01B669'" "$PM3BIN -c 'lf jablotron reader'" "Printed: 1410-00-0002-1669"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "KERI MS" "$PM3BIN -c 'lf keri clone -t m --fc 6 --cn 12345'" "$PM3BIN -c 'lf keri reader'" "Descrambled MS - FC: 6 Card: 12345"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "NEDAP 64b" "$PM3BIN -c 'lf nedap clone --st 1 --cc 291 --id 12345'" "$PM3BIN -c 'lf nedap reader'" "NEDAP \\(64b\\) - ID: 12345 subtype: 1 customer code: 291 / 0x123"; then return 1; fi
  if ! CheckLFReaderRoundTripContainsAll "NexWatch Nexkey" "$PM3BIN -c 'lf nexwatch clone --cn 521512301 -m 1 --nc'" "$PM3BIN -c 'lf nexwatch reader'" "fingerprint : Nexkey" "88bit id : 521512301"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Noralsy" "$PM3BIN -c 'lf noralsy clone --cn 112233'" "$PM3BIN -c 'lf noralsy reader'" "Noralsy - Card: 112233, Year: 2000"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "PAC/Stanley" "$PM3BIN -c 'lf pac clone --cn CD4F5552'" "$PM3BIN -c 'lf pac reader'" "PAC/Stanley - Card: CD4F5552"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Paradox" "$PM3BIN -c 'lf paradox clone --fc 96 --cn 40426'" "$PM3BIN -c 'lf paradox reader'" "Paradox - ID: .* FC: 96 Card: 40426"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Presco" "$PM3BIN -c 'lf presco clone -c 1E8021D9'" "$PM3BIN -c 'lf presco reader'" "Presco Site code: 30 User code: 8665 Full code: 1E8021D9"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Pyramid" "$PM3BIN -c 'lf pyramid clone --fc 123 --cn 11223'" "$PM3BIN -c 'lf pyramid reader'" "Pyramid - len: 26, FC: 123 Card: 11223"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Securakey" "$PM3BIN -c 'lf securakey clone --raw 7FCB400001ADEA5344300000'" "$PM3BIN -c 'lf securakey reader'" "Securakey - len: 26 FC: 0x35 Card: 64169"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Viking" "$PM3BIN -c 'lf viking clone --cn 01A337'" "$PM3BIN -c 'lf viking reader'" "Viking - Card 0001A337"; then return 1; fi
  if ! CheckLFReaderRoundTripFixture "Visa2000" "$PM3BIN -c 'lf visa2000 clone --cn 112233'" "$PM3BIN -c 'lf visa2000 reader'" "Visa2000 - Card 112233"; then return 1; fi
  return 0
}

function GetMifareCardExpectedBlock5() {
  local CMD="$1"
  local PREP_RES
  PREP_RES=$(eval "$CMD")
  if ! printf '%s' "$PREP_RES" | grep -F -q "Credential written to emulator memory"; then
    echo "Failed to prepare expected MIFARE emulator block 5" >&2
    echo "$PREP_RES" >&2
    return 1
  fi
  GetMifareEGetBlkLine 5
}

function CheckMifareEncodeHidCardFixture() {
  local LABEL="$1"
  local WRITE_CMD="$2"
  local EXPECTED_BLOCK5="$3"
  local EXPECTED_BLOCK5_HEX
  local BLOCK5_HEX

  if ! CheckExecute "encode $LABEL to card" "$WRITE_CMD" "pm3 -->"; then return 1; fi
  CARD_TEST_RESTORE_NEEDED=true

  local BLOCK1
  local BLOCK3
  local BLOCK5
  local BLOCK7
  BLOCK1=$(GetMifareRdBlkLine 1 A0A1A2A3A4A5)
  BLOCK3=$(GetMifareRdBlkLine 3 A0A1A2A3A4A5)
  BLOCK5=$(GetMifareRdBlkLine 5 484944204953)
  BLOCK7=$(GetMifareRdBlkLine 7 484944204953)
  EXPECTED_BLOCK5_HEX=$(printf '%s' "$EXPECTED_BLOCK5" | tr -d '[:space:]')
  BLOCK5_HEX=$(printf '%s' "$BLOCK5" | tr -d '[:space:]')

  if ! printf '%s' "$BLOCK1" | grep -F -q "1B 01 4D 48"; then echo "$BLOCK1"; return 1; fi
  if ! printf '%s' "$BLOCK3" | grep -F -q "78 77 88 C1"; then echo "$BLOCK3"; return 1; fi
  if [ "$BLOCK5_HEX" != "$EXPECTED_BLOCK5_HEX" ]; then echo "$BLOCK5"; return 1; fi
  if ! printf '%s' "$BLOCK7" | grep -F -q "78 77 88 AA"; then echo "$BLOCK7"; return 1; fi

  printf "%-40s" "verify $LABEL card blocks "
  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"

  if ! CleanupEncodeHidCard; then return 1; fi
  CARD_TEST_RESTORE_NEEDED=false
  return 0
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
  TESTHFICLASSENCODEEMU=true
fi

if [ "$TESTWIEGANDEMUSMOKE" = true ]; then
  TESTHFMFEMUMEM=true
  TESTHFMFENCODEHIDEMU=true
  TESTHFICLASSENCODEEMU=true
  TESTLFHIDSIM=true
fi

if [ "$TESTLFT55XXSMOKE" = true ]; then
  TESTLFT55XXROUNDTRIP=true
  TESTLFT55XXDETECT=true
  TESTLFT55XXDETECTWAKEUP=true
fi

if [ "$TESTDESFIREVALUE" = false ] && [ "$TESTHFMFEMUMEM" = false ] && [ "$TESTHFMFENCODEHIDEMU" = false ] && [ "$TESTHFICLASSENCODEEMU" = false ] && [ "$TESTHFMFENCODEHIDCARD" = false ] && [ "$TESTLFHIDSIM" = false ] && [ "$TESTWIEGANDEMUSMOKE" = false ] && [ "$TESTLFHIDCLONE" = false ] && [ "$TESTLFT55XXROUNDTRIP" = false ] && [ "$TESTLFT55XXDETECT" = false ] && [ "$TESTLFT55XXDETECTWAKEUP" = false ] && [ "$TESTLFT55XXSMOKE" = false ]; then
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

      if ! CheckMifareEncodeHidFixture "H10301" "H10301" "31" "337" "" "020000000000000000000000063E02A3"; then break; fi
      if ! CheckMifareEncodeHidFixture "C1k35s" "C1k35s" "222" "12345" "" ""; then break; fi
      if ! CheckMifareEncodeHidFixture "P10001" "P10001" "12" "3456" "" ""; then break; fi
      if ! CheckMifareEncodeHidLongNewFixture "96-bit direct PACS" "101010101100110011110000000011110101010110101010110011001111000000001111010101011010101011001100" "020000D5667807AAD5667807AAD56600"; then break; fi

      echo "  encodehid emulator fixture tests completed successfully!"
    fi

    if $TESTHFICLASSENCODEEMU; then
      echo -e "\n${C_BLUE}Testing hf iclass encode emulator fixtures${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi

      if ! CheckIClassEncodeFixture "H10301" "H10301" "31" "337" "" "03 03 03 03 00 03 E0 17" "1D 21 B3 16 EE D4 A5 E2" "DD AD A1 61 E8 D7 96 73" "DD AD A1 61 E8 D7 96 73"; then break; fi
      if ! CheckIClassEncodeFixture "C1k35s" "C1k35s" "222" "12345" "" "" "" "" ""; then break; fi
      if ! CheckIClassEncodeFixture "P10001" "P10001" "12" "3456" "" "" "" "" ""; then break; fi

      echo "  iClass encode emulator fixture tests completed successfully!"
    fi

    if $TESTHFMFENCODEHIDCARD; then
      CARD_TEST_RESTORE_NEEDED=false
      echo -e "\n${C_BLUE}Testing hf mf encodehid against card${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      WaitForUserCard "PLACE A BLANK DEFAULT-KEY MIFARE CLASSIC CARD ON THE READER NOW"

      EXPECTED_CARD_BLOCK5=$(GetMifareCardExpectedBlock5 "$PM3BIN -c 'hf mf encodehid -w H10301 --fc 31 --cn 337 --emu'")
      if [ -z "$EXPECTED_CARD_BLOCK5" ]; then break; fi
      if ! CheckMifareEncodeHidCardFixture "H10301 --wiegand" "$PM3BIN -c 'hf mf encodehid -w H10301 --fc 31 --cn 337'" "$EXPECTED_CARD_BLOCK5"; then CleanupEncodeHidCard; break; fi

      if ! LoadWiegandFixtures "C1k35s" "222" "12345" ""; then break; fi
      EXPECTED_CARD_BLOCK5=$(GetMifareCardExpectedBlock5 "$PM3BIN -c 'hf mf encodehid --new $WIEGAND_FIXTURE_NEW --emu'")
      if [ -z "$EXPECTED_CARD_BLOCK5" ]; then break; fi
      if ! CheckMifareEncodeHidCardFixture "C1k35s --new" "$PM3BIN -c 'hf mf encodehid --new $WIEGAND_FIXTURE_NEW'" "$EXPECTED_CARD_BLOCK5"; then CleanupEncodeHidCard; break; fi

      if ! LoadWiegandFixtures "P10001" "12" "3456" ""; then break; fi
      EXPECTED_CARD_BLOCK5=$(GetMifareCardExpectedBlock5 "$PM3BIN -c 'hf mf encodehid --bin $WIEGAND_FIXTURE_BIN --emu'")
      if [ -z "$EXPECTED_CARD_BLOCK5" ]; then break; fi
      if ! CheckMifareEncodeHidCardFixture "P10001 --bin" "$PM3BIN -c 'hf mf encodehid --bin $WIEGAND_FIXTURE_BIN'" "$EXPECTED_CARD_BLOCK5"; then CleanupEncodeHidCard; break; fi

      echo "  encodehid card write/read tests completed successfully!"
    fi

    if $TESTLFHIDSIM; then
      echo -e "\n${C_BLUE}Testing lf hid sim input modes${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi

      if ! LoadWiegandFixtures "H10301" "31" "337" ""; then break; fi
      if ! CheckExecute "lf hid sim H10301 --bin" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim --bin $WIEGAND_FIXTURE_BIN'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim H10301 --new" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim --new $WIEGAND_FIXTURE_NEW'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim H10301 --raw" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim -r $WIEGAND_FIXTURE_LF_RAW'" "Simulating HID tag using raw"; then break; fi
      if ! CheckExecute "lf hid sim H10301 --wiegand" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim -w H10301 --fc 31 --cn 337'" "Simulating HID tag"; then break; fi

      if ! LoadWiegandFixtures "C1k35s" "222" "12345" ""; then break; fi
      if ! CheckExecute "lf hid sim C1k35s --bin" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim --bin $WIEGAND_FIXTURE_BIN'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim C1k35s --new" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim --new $WIEGAND_FIXTURE_NEW'" "Simulating HID tag"; then break; fi
      if ! CheckExecute "lf hid sim C1k35s --raw" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim -r $WIEGAND_FIXTURE_LF_RAW'" "Simulating HID tag using raw"; then break; fi
      if ! CheckExecute "lf hid sim C1k35s --wiegand" "timeout -s KILL 5 $PM3BIN -c 'lf hid sim -w C1k35s --fc 222 --cn 12345'" "Simulating HID tag"; then break; fi

      if ! LoadWiegandFixtures "BQT38" "1" "1" "1"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit --bin reject" "$PM3BIN -c 'lf hid sim --bin $WIEGAND_FIXTURE_BIN' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit --new reject" "$PM3BIN -c 'lf hid sim --new $WIEGAND_FIXTURE_NEW' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit --raw reject" "$PM3BIN -c 'lf hid sim -r $WIEGAND_FIXTURE_LF_RAW' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! LoadWiegandFixtures "P10001" "12" "3456" ""; then break; fi
      if ! CheckExecute "lf hid sim 40-bit --bin reject" "$PM3BIN -c 'lf hid sim --bin $WIEGAND_FIXTURE_BIN' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 40-bit --new reject" "$PM3BIN -c 'lf hid sim --new $WIEGAND_FIXTURE_NEW' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 40-bit raw reject" "$PM3BIN -c 'lf hid sim -r $WIEGAND_FIXTURE_LF_RAW' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 40-bit format reject" "$PM3BIN -c 'lf hid sim -w P10001 --fc 12 --cn 3456' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi
      if ! CheckExecute "lf hid sim 38-bit format reject" "$PM3BIN -c 'lf hid sim -w BQT38 --fc 1 --cn 1 -i 1' 2>&1" "LF HID simulation supports up to 37-bit credentials"; then break; fi

      echo "  lf hid sim tests completed successfully!"
    fi

    if $TESTLFHIDCLONE; then
      echo -e "\n${C_BLUE}Testing lf hid clone against T55x7${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi
      WaitForUserLFTag "PLACE A WRITABLE T55x7 TAG ON THE LF ANTENNA NOW"

      if ! RunLFHidCloneFixtures; then break; fi

      echo "  lf hid clone tests completed successfully!"
    fi

    if $TESTLFT55XXROUNDTRIP; then
      T55XX_BACKUP_ACTIVE=false
      echo -e "\n${C_BLUE}Testing first-class T55x7 clone+reader round trips${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi
      WaitForUserLFTag "PLACE A WRITABLE T55x7 TAG ON THE LF ANTENNA NOW"
      if ! BackupT55xxTag; then break; fi

      if ! RunLFT55xxRoundTripFixtures; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi

      if ! RestoreT55xxTag; then CleanupT55xxBackupFiles; break; fi
      CleanupT55xxBackupFiles
      echo "  T55x7 clone+reader round-trip tests completed successfully!"
    fi

    if $TESTLFT55XXDETECT; then
      T55XX_BACKUP_ACTIVE=false
      echo -e "\n${C_BLUE}Testing lf t55xx detect across representative configs${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi
      WaitForUserLFTag "PLACE A WRITABLE T55x7 TAG ON THE LF ANTENNA NOW"
      if ! BackupT55xxTag; then break; fi

      if ! CheckT55xxDetectFixture "EM410x" "$PM3BIN -c 'lf em 410x clone --id 1122334455'" "ASK" "5 - RF/64" "00148040"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectFixture "HID H10301" "$PM3BIN -c 'lf hid clone -w H10301 --fc 31 --cn 337'" "FSK2a" "4 - RF/50" "00107060"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectFixture "Destron" "$PM3BIN -c 'lf destron clone --uid 1A2B3C4D5E'" "FSK2" "4 - RF/50" "00105060"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectFixture "Jablotron" "$PM3BIN -c 'lf jablotron clone --cn 01B669'" "BIPHASE" "5 - RF/64" "00158040"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectFixture "Indala 64" "$PM3BIN -c 'lf indala clone --fc 123 --cn 1337'" "PSK1" "2 - RF/32" "00081040"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectFixture "PAC" "$PM3BIN -c 'lf pac clone --cn CD4F5552'" "DIRECT/NRZ" "2 - RF/32" "00080080"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectConfigFixture "ASK + ST" "--ASK --rate 64 --st" "ASK" "5 - RF/64" "Yes"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectConfigFixture "FSK1" "--FSK1 --rate 50" "FSK1" "4 - RF/50" "No"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectConfigFixture "FSK1A" "--FSK1A --rate 50" "FSK1a" "4 - RF/50" "No"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectConfigFixture "PSK2" "--PSK2 --rate 32" "PSK2" "2 - RF/32" "No"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi
      if ! CheckT55xxDetectConfigFixture "BIA" "--BIA --rate 64" "BIPHASEa - (CDP)" "5 - RF/64" "No"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi

      if ! RestoreT55xxTag; then CleanupT55xxBackupFiles; break; fi
      CleanupT55xxBackupFiles
      echo "  T55xx detect fixture tests completed successfully!"
    fi

    if $TESTLFT55XXDETECTWAKEUP; then
      T55XX_BACKUP_ACTIVE=false
      echo -e "\n${C_BLUE}Testing lf t55xx detect wakeup recovery${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists" "$PM3BIN"; then break; fi
      WaitForUserLFTag "PLACE A WRITABLE T55x7 TAG ON THE LF ANTENNA NOW"
      if ! BackupT55xxTag; then break; fi

      if ! CheckT55xxDetectWakeupFixture "00107060" "00107261"; then RestoreT55xxTag; CleanupT55xxBackupFiles; break; fi

      if ! RestoreT55xxTag; then CleanupT55xxBackupFiles; break; fi
      CleanupT55xxBackupFiles
      echo "  T55xx wakeup detect test completed successfully!"
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
