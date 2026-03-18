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
TESTICLASSENCODE=false
NEED_MF_HID_ENCODE_WIPE=false
TESTMANUAL=false

# https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo """
Usage: $0 [--pm3bin /path/to/pm3] [desfire_value|hid_wiegand|mf_hid_encode|iclass_encode]
    --pm3bin ...:    Specify path to pm3 binary to test
    --manual ...:    Pause for external reader verification for supported card-flow checks
    desfire_value:   Test DESFire value operations with card
    hid_wiegand:     Test LF HID T55xx clone and PM3 readback flows
    mf_hid_encode:   Test MIFARE Classic HID encoding flows
    iclass_encode:   Test physical iCLASS HID encoding roundtrip
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
    --manual)
      TESTMANUAL=true
      shift
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
    iclass_encode)
      TESTALL=false
      TESTICLASSENCODE=true
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

function CheckLfHidCloneReadback() {
  printf "%-40s" "$1 "

  start=$(date +%s)
  TIMEINFO=""
  RES=$($PM3BIN -c "lf hid clone $2; lf hid reader" 2>&1)
  end=$(date +%s)
  delta=$(expr $end - $start)
  if [ $delta -gt 2 ]; then
    TIMEINFO="  ($delta s)"
  fi

  if echo "$RES" | grep -E -q "$3"; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK} $TIMEINFO"
    if $TESTMANUAL; then
      echo "  Manual check: $4"
      WaitForEnter "PRESENT THE T55xx TAG TO ANOTHER READER AND CONFIRM: $4"
    fi
    return 0
  fi

  echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
  echo "Execution trace:"
  echo "$RES"
  return 1
}

function HexToBin() {
  local hex="${1^^}"
  local bin=""
  local i ch
  for ((i=0; i<${#hex}; i++)); do
    ch="${hex:i:1}"
    case "$ch" in
      0) bin+="0000" ;;
      1) bin+="0001" ;;
      2) bin+="0010" ;;
      3) bin+="0011" ;;
      4) bin+="0100" ;;
      5) bin+="0101" ;;
      6) bin+="0110" ;;
      7) bin+="0111" ;;
      8) bin+="1000" ;;
      9) bin+="1001" ;;
      A) bin+="1010" ;;
      B) bin+="1011" ;;
      C) bin+="1100" ;;
      D) bin+="1101" ;;
      E) bin+="1110" ;;
      F) bin+="1111" ;;
      *) return 1 ;;
    esac
  done
  printf "%s" "$bin"
}

function StripAnsiCodes() {
  LC_ALL=C printf '%s' "$1" | LC_ALL=C sed -E 's/\x1B\[[0-9;?]*[[:alpha:]]//g'
}

function ExtractIClassBlockHex() {
  local BLOCK="$1"
  local OUTPUT="$2"
  local LINE

  while IFS= read -r LINE; do
    local CLEANLINE
    CLEANLINE=$(printf '%s\n' "$LINE" | sed -E 's/\x1B\[[0-9;?]*[[:alpha:]]//g')

    # Support both spaced and compact block print formats from different pm3 versions
    # (for example: `6/0x06 -> ...` and `  6 | xx xx ...` style output).
    if [[ "$CLEANLINE" =~ ${BLOCK}/0x[0-9A-Fa-f]{2}.*(\||:|->)[[:space:]]*([0-9A-Fa-f]{16}|([0-9A-Fa-f]{2}([[:space:]]+[0-9A-Fa-f]{2}){7})).* ]]; then
      local HEX="${BASH_REMATCH[2]}"
      HEX=${HEX// /}
      printf '%s' "$HEX"
      return 0
    fi
  done <<< "$OUTPUT"
  return 1
}

function RestoreMfHidEncodeSector0() {
  $PM3BIN -c "hf mf wrbl --blk 3 -b -k 89ECA97F8C2A -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF" >/dev/null 2>&1 || true
  $PM3BIN -c "hf mf wrbl --blk 3 -k FFFFFFFFFFFF -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF" >/dev/null 2>&1 || true
  $PM3BIN -c "hf mf wrbl --blk 3 -k A0A1A2A3A4A5 -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF" >/dev/null 2>&1 || true
  $PM3BIN -c "hf mf wrbl --blk 2 -k FFFFFFFFFFFF -d 00000000000000000000000000000000; \
hf mf wrbl --blk 1 -k FFFFFFFFFFFF -d 00000000000000000000000000000000" >/dev/null 2>&1 || return 1
}

function RestoreMfHidEncodeSector1() {
  $PM3BIN -c "hf mf wrbl --blk 7 -b -k 204752454154 -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF" >/dev/null 2>&1 || true
  $PM3BIN -c "hf mf wrbl --blk 7 -k FFFFFFFFFFFF -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF" >/dev/null 2>&1 || true
  $PM3BIN -c "hf mf wrbl --blk 7 -k 484944204953 -d FFFFFFFFFFFFFF078069FFFFFFFFFFFF" >/dev/null 2>&1 || true
  $PM3BIN -c "hf mf wrbl --blk 6 -k FFFFFFFFFFFF -d 00000000000000000000000000000000; \
hf mf wrbl --blk 5 -k FFFFFFFFFFFF -d 00000000000000000000000000000000; \
hf mf wrbl --blk 4 -k FFFFFFFFFFFF -d 00000000000000000000000000000000" >/dev/null 2>&1 || return 1
}

function RestoreMfHidEncodeCard() {
  RestoreMfHidEncodeSector0 || return 1
  RestoreMfHidEncodeSector1 || return 1

  local verify
  verify=$($PM3BIN -c 'hf mf rdbl --blk 1 -k FFFFFFFFFFFF; hf mf rdbl --blk 2 -k FFFFFFFFFFFF; hf mf rdbl --blk 4 -k FFFFFFFFFFFF; hf mf rdbl --blk 5 -k FFFFFFFFFFFF; hf mf rdbl --blk 6 -k FFFFFFFFFFFF' 2>&1) || return 1
  echo "$verify" | grep -E -q "  1 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$verify" | grep -E -q "  2 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$verify" | grep -E -q "  4 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$verify" | grep -E -q "  5 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$verify" | grep -E -q "  6 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
}

function CleanupMfHidEncodeCard() {
  if [ "$NEED_MF_HID_ENCODE_WIPE" != true ]; then
    return 0
  fi

  echo ""
  printf "%-40s" "hf mf encodehid cleanup "
  if RestoreMfHidEncodeCard; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
  else
    echo -e "[ ${C_YELLOW}WARN${C_NC} ]"
    echo "Cleanup could not restore sectors 0 and 1 to the default usable state."
  fi
}

function CheckMfHidEncodeRoundTrip() {
  printf "%-40s" "$1 "

  start=$(date +%s)
  TIMEINFO=""
  if ! RestoreMfHidEncodeCard >/dev/null 2>&1; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Execution trace:"
    echo "Failed to restore sectors 0 and 1 to the default usable state before running the test."
    return 1
  fi

  RES=$($PM3BIN -c "hf mf encodehid $2; hf mf rdbl --blk 5 -k 484944204953" 2>&1)
  end=$(date +%s)
  delta=$(expr $end - $start)
  if [ $delta -gt 2 ]; then
    TIMEINFO="  ($delta s)"
  fi

  BLOCKHEX=$(printf "%s\n" "$RES" | LC_ALL=C grep -aoE '02( [0-9A-F]{2}){15}' | tail -n1 | tr -d ' ')
  if [ -z "$BLOCKHEX" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
    echo "Execution trace:"
    echo "$RES"
    return 1
  fi

  if [[ "$BLOCKHEX" != 02* ]]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
    echo "Expected block 5 to start with the 0x02 HID marker."
    echo "Actual block 5 data: $BLOCKHEX"
    echo "Execution trace:"
    echo "$RES"
    return 1
  fi

  RAWPAYLOAD=${BLOCKHEX#02}
  PAYLOADBIN=$(HexToBin "$RAWPAYLOAD") || {
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
    echo "Execution trace:"
    echo "$RES"
    return 1
  }

  while [[ "$PAYLOADBIN" == 0* ]]; do
    PAYLOADBIN=${PAYLOADBIN#0}
  done

  if [[ "$PAYLOADBIN" != 1* ]]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
    echo "Expected a sentinel-prefixed Wiegand payload in block 5."
    echo "Actual payload bits: $PAYLOADBIN"
    echo "Execution trace:"
    echo "$RES"
    return 1
  fi

  RECOVERED_BIN=${PAYLOADBIN#1}
  if [ "$RECOVERED_BIN" != "$3" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
    echo "Expected Wiegand bits: $3"
    echo "Actual Wiegand bits:   $RECOVERED_BIN"
    echo "Execution trace:"
    echo "$RES"
    return 1
  fi

  DECODE_RES=$($PM3BIN -c "wiegand decode --bin $RECOVERED_BIN" 2>&1)
  if echo "$DECODE_RES" | grep -E -q "$4"; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK} $TIMEINFO"
    return 0
  fi

  echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
  echo "Decode trace:"
  echo "$DECODE_RES"
  return 1
}

function CheckMfHidEncodeCleanup() {
  printf "%-40s" "$1 "
  RES=$($PM3BIN -c 'hf mf rdbl --blk 1 -k FFFFFFFFFFFF; hf mf rdbl --blk 2 -k FFFFFFFFFFFF; hf mf rdbl --blk 4 -k FFFFFFFFFFFF; hf mf rdbl --blk 5 -k FFFFFFFFFFFF; hf mf rdbl --blk 6 -k FFFFFFFFFFFF' 2>&1)
  if echo "$RES" | grep -E -q "  1 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$RES" | grep -E -q "  2 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$RES" | grep -E -q "  4 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$RES" | grep -E -q "  5 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00" \
    && echo "$RES" | grep -E -q "  6 \| 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK}"
    return 0
  fi

  echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
  echo "Execution trace:"
  echo "$RES"
  return 1
}

function CheckIClassEncodeRoundTrip() {
  local LABEL="$1"
  local ENCODE_ARGS="$2"
  # Expected decoded PACS length lets us validate that both short and long payload encodings
  # survive a full physical write/read roundtrip and client-side decode.
  local EXPECTED_BITS_LEN="$3"

  printf "%-40s" "$LABEL "

  start=$(date +%s)
  TIMEINFO=""

  local ENCODE_CMD="$PM3BIN -c 'hf iclass encode -v $ENCODE_ARGS'"
  local ENCODE_OUTPUT
  ENCODE_OUTPUT=$(eval "$ENCODE_CMD" 2>&1)

  local EXPECTED6="$(ExtractIClassBlockHex 6 "$ENCODE_OUTPUT")"
  local EXPECTED7="$(ExtractIClassBlockHex 7 "$ENCODE_OUTPUT")"
  local EXPECTED8="$(ExtractIClassBlockHex 8 "$ENCODE_OUTPUT")"
  local EXPECTED9="$(ExtractIClassBlockHex 9 "$ENCODE_OUTPUT")"

  if [ -z "$EXPECTED6" ] || [ -z "$EXPECTED7" ] || [ -z "$EXPECTED8" ] || [ -z "$EXPECTED9" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL} $TIMEINFO"
    echo "Failed to extract expected credential blocks from encode output."
    echo "$ENCODE_OUTPUT"
    return 1
  fi

  local RES

  RES=$(eval "$PM3BIN -c 'hf iclass rdbl --ki 0 --blk 6'" 2>&1)
  local READ6="$(ExtractIClassBlockHex 6 "$RES")"
  if [ -z "$READ6" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Failed to read block 6 from iCLASS card."
    echo "$RES"
    return 1
  fi

  RES=$(eval "$PM3BIN -c 'hf iclass rdbl --ki 0 --blk 7'" 2>&1)
  local READ7="$(ExtractIClassBlockHex 7 "$RES")"
  if [ -z "$READ7" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Failed to read block 7 from iCLASS card."
    echo "$RES"
    return 1
  fi

  RES=$(eval "$PM3BIN -c 'hf iclass rdbl --ki 0 --blk 8'" 2>&1)
  local READ8="$(ExtractIClassBlockHex 8 "$RES")"
  if [ -z "$READ8" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Failed to read block 8 from iCLASS card."
    echo "$RES"
    return 1
  fi

  RES=$(eval "$PM3BIN -c 'hf iclass rdbl --ki 0 --blk 9'" 2>&1)
  local READ9="$(ExtractIClassBlockHex 9 "$RES")"
  if [ -z "$READ9" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Failed to read block 9 from iCLASS card."
    echo "$RES"
    return 1
  fi

  if [ "${EXPECTED6^^}" != "${READ6^^}" ] || [ "${EXPECTED7^^}" != "${READ7^^}" ] || [ "${EXPECTED8^^}" != "${READ8^^}" ] || [ "${EXPECTED9^^}" != "${READ9^^}" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Expected:"
    echo "  6/0x06: $EXPECTED6"
    echo "  7/0x07: $EXPECTED7"
    echo "  8/0x08: $EXPECTED8"
    echo "  9/0x09: $EXPECTED9"
    echo "Observed:"
    echo "  6/0x06: $READ6"
    echo "  7/0x07: $READ7"
    echo "  8/0x08: $READ8"
    echo "  9/0x09: $READ9"
    return 1
  fi

  # Persist a fresh tag dump so the existing `hf iclass view` decode path can be exercised.
  # This catches payload extraction regressions that are not visible from raw block reads alone.
  local DUMP_FILE
  DUMP_FILE="$(mktemp)"
  trap 'rm -f "$DUMP_FILE"' RETURN

  # Verify that we can read the full iCLASS tag contents from the physical card.
  RES=$($PM3BIN -c "hf iclass dump --ki 0 -f $DUMP_FILE" 2>&1)
  if [ $? -ne 0 ] || [ ! -f "$DUMP_FILE" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Failed to dump iCLASS card for client decode check."
    echo "$RES"
    return 1
  fi

  # Run the client decode path used by normal inspection. Encrypted transport modes need
  # `decrypt`, plain mode can use `view` directly.
  local DECODE_RES
  local DECODE_CMD="hf iclass view -f $DUMP_FILE"
  if [[ "$ENCODE_ARGS" =~ --enc[[:space:]]+(des|2k3des) ]]; then
    DECODE_CMD="hf iclass decrypt -f $DUMP_FILE --ns"
  fi
  DECODE_RES=$($PM3BIN -c "$DECODE_CMD" 2>&1)
  if echo "$DECODE_RES" | grep -E -q "Invalid legacy PACS payload|missing sentinel bit"; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Client-side decode reported invalid PACS payload."
    echo "$DECODE_RES"
    return 1
  fi

  # Extract the decoded legacy PACS binary line so we can confirm we got back the same payload size.
  local DECODE_CLEAN
  DECODE_CLEAN="$(StripAnsiCodes "$DECODE_RES")"

  local DECODE_LINE
  DECODE_LINE="$(printf '%s\n' "$DECODE_CLEAN" | LANG=C grep -a -m1 -E 'Binary\.\.\.')"
  local DECODE_BINARY=""
  local DECODE_LEN=0
  if [ -n "$DECODE_LINE" ]; then
    DECODE_BINARY="$(printf '%s\n' "$DECODE_LINE" | LANG=C sed -E 's/.*Binary\.\.\.[[:space:]]+([01]+).*/\1/')"
    DECODE_LEN="$(printf '%s\n' "$DECODE_LINE" | LANG=C sed -E 's/.*\(([[:space:]]*[0-9]+)[[:space:]]*\).*/\1/' | tr -d '[:space:]')"
  fi

  # If decode output exists but lacks a parseable bitstring/length, treat as a regression.
  if [ -z "$DECODE_BINARY" ] || [ "$DECODE_LEN" -eq 0 ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Failed to extract legacy PACS payload from client decode output."
    echo "$DECODE_CLEAN"
    return 1
  fi

  # Keep test output strict: the decoded PACS length should match the requested encode length.
  if [ -n "$EXPECTED_BITS_LEN" ] && [ "$DECODE_LEN" -ne "$EXPECTED_BITS_LEN" ]; then
    echo -e "[ ${C_RED}FAIL${C_NC} ] ${C_FAIL}"
    echo "Expected client decode payload length: $EXPECTED_BITS_LEN"
    echo "Actual payload length:           $DECODE_LEN"
    echo "$DECODE_CLEAN"
    return 1
  fi

  end=$(date +%s)
  delta=$(expr $end - $start)
  if [ $delta -gt 2 ]; then
    TIMEINFO="  (${delta} s)"
  fi

  if $TESTMANUAL; then
    echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK} $TIMEINFO"
    local MANUAL_PROMPT="PRESENT THE CARD TO ANOTHER READER AND CONFIRM: iCLASS H10301 FC 31 CN 337"
    if [ "$EXPECTED_BITS_LEN" -eq 143 ]; then
      MANUAL_PROMPT="PRESENT THE CARD TO ANOTHER READER AND CONFIRM: iCLASS 143-bit CREDENTIAL"
    fi
    WaitForEnter "$MANUAL_PROMPT"
    return 0
  fi

  echo -e "[ ${C_GREEN}OK${C_NC} ] ${C_OK} $TIMEINFO"
  return 0
}

function WaitForEnter() {
  echo ""
  echo "$1"
  echo "Press Enter when ready, or Ctrl-C to abort."
  if [ -r /dev/tty ]; then
    stty sane < /dev/tty 2>/dev/null || true
    IFS= read -r < /dev/tty
  else
    read -r
  fi
}

trap CleanupMfHidEncodeCard EXIT

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
if [ "$TESTDESFIREVALUE" = false ] && [ "$TESTHIDWIEGAND" = false ] && [ "$TESTMFHIDENCODE" = false ] && [ "$TESTICLASSENCODE" = false ]; then
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
      echo -e "\n${C_BLUE}Testing LF HID T55xx clone flows${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      if ! CheckExecute "lf hid clone raw oversize"    "$PM3BIN -c 'lf hid clone -r 01400076000c86' 2>&1" "LF HID clone supports only packed credentials up to 37 bits"; then break; fi
      if ! CheckExecute "lf hid clone bin oversize"    "PAT=\$(printf '01%.0s' {1..48}); $PM3BIN -c \"lf hid clone --bin \$PAT\" 2>&1" "Packed HID encoding supports up to 84 Wiegand bits"; then break; fi
      if ! CheckExecute "lf hid clone new oversize"    "$PM3BIN -c 'lf hid clone --new 0000A4550148AB' 2>&1" "LF HID clone supports only packed credentials up to 37 bits"; then break; fi

      if $TESTMANUAL; then
        WaitForEnter "PLACE A REWRITABLE T55xx TAG ON THE PM3 NOW"
      fi
      if ! CheckLfHidCloneReadback "lf hid clone H10301 26-bit" "-w H10301 --fc 118 --cn 1603" "H10301.*FC: 118.*CN: 1603" "H10301 26-bit, FC 118, CN 1603"; then break; fi
      if ! CheckLfHidCloneReadback "lf hid clone C1k35s 35-bit" "-w C1k35s --fc 118 --cn 1603" "C1k35s.*FC: 118.*CN: 1603" "C1k35s 35-bit, FC 118, CN 1603"; then break; fi
      if ! CheckLfHidCloneReadback "lf hid clone H10304 37-bit" "-w H10304 --fc 118 --cn 1603" "H10304.*FC: 118.*CN: 1603" "H10304 37-bit, FC 118, CN 1603"; then break; fi
    fi

    if $TESTMFHIDENCODE; then
      echo -e "\n${C_BLUE}Testing MIFARE Classic HID encoding${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      if $TESTMANUAL; then
        WaitForEnter "PLACE A BLANK MIFARE CLASSIC 1K CARD ON THE PM3 NOW"
      fi
      NEED_MF_HID_ENCODE_WIPE=true
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid bin roundtrip"      "--bin 10001111100000001010100011" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid raw roundtrip"      "--raw 063E02A3" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid new roundtrip"      "--new 068F80A8C0" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid format roundtrip"   "-w H10301 --fc 31 --cn 337" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! RestoreMfHidEncodeCard; then break; fi
      if ! CheckMfHidEncodeCleanup "hf mf encodehid cleanup verify"; then break; fi
    fi

    if $TESTICLASSENCODE; then
      echo -e "\n${C_BLUE}Testing physical iCLASS HID encoding${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      if $TESTMANUAL; then
        WaitForEnter "PLACE A BLANK iCLASS TAG ON THE PM3 NOW"
      fi
      # Build a deterministic 143-bit "all-ones" payload to exercise the legacy max-width path.
      ICLASS_143_BIN=
      ICLASS_143_BIN=$(awk 'BEGIN { for (i = 0; i < 143; i++ ) { printf "1" } }')
      if ! CheckIClassEncodeRoundTrip "hf iclass encode bin roundtrip plain" "--bin 10001111100000001010100011 --ki 0 --enc none" 26; then break; fi
      if ! CheckIClassEncodeRoundTrip "hf iclass encode bin roundtrip des"   "--bin 10001111100000001010100011 --ki 0 --enc des" 26; then break; fi
      if ! CheckIClassEncodeRoundTrip "hf iclass encode bin roundtrip 3des"  "--bin 10001111100000001010100011 --ki 0 --enc 2k3des" 26; then break; fi
      if ! CheckIClassEncodeRoundTrip "hf iclass encode bin 143-bit roundtrip" "--bin $ICLASS_143_BIN --ki 0 --enc none" 143; then break; fi
      if ! CheckIClassEncodeRoundTrip "hf iclass encode raw roundtrip"     "--raw 063E02A3 --ki 0 --enc none" 26; then break; fi
      if ! CheckIClassEncodeRoundTrip "hf iclass encode new roundtrip"     "--new 068F80A8C0 --ki 0 --enc none" 26; then break; fi
      if ! CheckIClassEncodeRoundTrip "hf iclass encode format roundtrip"  "-w H10301 --fc 31 --cn 337 --ki 0 --enc none" 26; then break; fi
    fi
  
  echo -e "\n------------------------------------------------------------"
  echo -e "Tests [ ${C_GREEN}OK${C_NC} ] ${C_OK}\n"
  exit 0
done
echo -e "\n------------------------------------------------------------"
echo -e "\nTests [ ${C_RED}FAIL${C_NC} ] ${C_FAIL}\n"
exit 1
