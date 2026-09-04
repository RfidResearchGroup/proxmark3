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
TESTICLASSREADER=false
TESTSMARTCARD=false
TESTICLASSEMU=false
TESTHITAG2=false
NEED_MF_HID_ENCODE_WIPE=false
TESTMANUAL=false

# https://medium.com/@Drew_Stokes/bash-argument-parsing-54f3b81a6a8f
PARAMS=""
while (( "$#" )); do
  case "$1" in
    -h|--help)
      echo """
Usage: $0 [--pm3bin /path/to/pm3] [--pm3port /dev/tty...] [desfire_value|hid_wiegand|mf_hid_encode|iclass_emu|iclass_reader|hitag2]
    --pm3bin ...:    Specify path to pm3 binary to test
    --pm3port ...:   Specify serial port for client/proxmark3
    --manual ...:    Pause after successful online LF HID clone/read checks for external reader verification
    desfire_value:   Test DESFire value operations with card
    hid_wiegand:     Test LF HID T55xx clone and PM3 readback flows
    mf_hid_encode:   Test MIFARE Classic HID encoding flows
    iclass_emu:      Test iCLASS emulator memory load/write/read flows
    iclass_reader:   Load iCLASS HID credentials into emulator memory for external reader verification
    smartcard:       Test the RDV4 SIM module and an ISO 7816 contact card
    hitag2:          Test Hitag 2 against a genuine card and a genuine reader
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
    --pm3port)
      if [ -n "$2" ] && [ ${2:0:1} != "-" ]; then
        PM3PORT=$2
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
    iclass_reader)
      TESTALL=false
      TESTICLASSREADER=true
      shift
      ;;
    smartcard)
      TESTALL=false
      TESTSMARTCARD=true
      shift
      ;;
    iclass_emu)
      TESTALL=false
      TESTICLASSEMU=true
      shift
      ;;
    hitag2)
      TESTALL=false
      TESTHITAG2=true
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

HITAG2_DUMP="${HITAG2_DUMP:-traces/lf-hitag-CE129911-dump.bin}"

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

function WaitForEnter() {
  echo ""
  echo "$1"

  # Only prompt when there is really a terminal to prompt on.
  #
  # `[ -r /dev/tty ]` is not that test: the node can exist and be readable by
  # mode bits while the process has no controlling terminal, and the redirect
  # then fails with "No such device or address" and the run carries on with the
  # rig unconfirmed.  Opening it is the only reliable check.
  if [ -n "${PM3_ONLINE_NOPROMPT:-}" ]; then
    echo "PM3_ONLINE_NOPROMPT set - assuming the rig is ready."
    return
  fi

  if (exec < /dev/tty) 2>/dev/null; then
    echo "Press Enter when ready, or Ctrl-C to abort."
    stty sane < /dev/tty 2>/dev/null || true
    IFS= read -r < /dev/tty
  elif [ -t 0 ]; then
    echo "Press Enter when ready, or Ctrl-C to abort."
    IFS= read -r
  else
    echo "No terminal to prompt on - assuming the rig is ready."
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
if [ "$TESTDESFIREVALUE" = false ] && [ "$TESTHIDWIEGAND" = false ] && [ "$TESTMFHIDENCODE" = false ] && [ "$TESTICLASSEMU" = false ] && [ "$TESTICLASSREADER" = false ] && [ "$TESTSMARTCARD" = false ] && [ "$TESTHITAG2" = false ]; then
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

      WaitForEnter "PLACE A REWRITABLE T55xx TAG ON THE PM3 NOW"
      if ! CheckLfHidCloneReadback "lf hid clone H10301 26-bit" "-w H10301 --fc 118 --cn 1603" "H10301.*FC: 118.*CN: 1603" "H10301 26-bit, FC 118, CN 1603"; then break; fi
      if ! CheckLfHidCloneReadback "lf hid clone C1k35s 35-bit" "-w C1k35s --fc 118 --cn 1603" "C1k35s.*FC: 118.*CN: 1603" "C1k35s 35-bit, FC 118, CN 1603"; then break; fi
      if ! CheckLfHidCloneReadback "lf hid clone H10304 37-bit" "-w H10304 --fc 118 --cn 1603" "H10304.*FC: 118.*CN: 1603" "H10304 37-bit, FC 118, CN 1603"; then break; fi
    fi

    if $TESTMFHIDENCODE; then
      echo -e "\n${C_BLUE}Testing MIFARE Classic HID encoding${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi

      WaitForEnter "PLACE A BLANK MIFARE CLASSIC 1K CARD ON THE PM3 NOW"
      NEED_MF_HID_ENCODE_WIPE=true
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid bin roundtrip"      "--bin 10001111100000001010100011" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid raw roundtrip"      "--raw 063E02A3" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid new roundtrip"      "--new 068F80A8C0" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! CheckMfHidEncodeRoundTrip "hf mf encodehid format roundtrip"   "-w H10301 --fc 31 --cn 337" "10001111100000001010100011" "H10301.*FC: 31.*CN: 337"; then break; fi
      if ! RestoreMfHidEncodeCard; then break; fi
      if ! CheckMfHidEncodeCleanup "hf mf encodehid cleanup verify"; then break; fi
    fi

    if $TESTICLASSEMU; then
      echo -e "\n${C_BLUE}Testing iCLASS emulator memory${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi
      PM3CMD="$PM3BIN"
      if [ -n "${PM3PORT:-}" ]; then
        PM3CMD="$PM3CMD -p $PM3PORT"
      fi
      if ! CheckExecute "hf iclass esetblk preserves emu" "$PM3CMD -c 'hf iclass eload -f traces/iclass/hf-iclass-dump.json; hw fpgaoff; hf iclass esetblk --blk 7 -d A55AC33C9669F00F; hf iclass eview -s 64' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "0/0x00.*6D C2 5B 15 FE FF 12 E0.*7/0x07.*A5 5A C3 3C 96 69 F0 0F"; then break; fi
      if ! CheckExecute "hf iclass sim preserves emu" "$PM3CMD -c 'hf iclass eload -f traces/iclass/hf-iclass-dump.json; hf iclass sim -t 3; hf iclass eview -s 64' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "6D C2 5B 15 FE FF 12 E0.*03 03 03 03 00 03 E0 17"; then break; fi
      if ! CheckExecute "hf iclass sim break preserves emu" "$PM3CMD -c 'hf iclass eload -f traces/iclass/hf-iclass-dump.json; hf iclass sim -t 3; hw break; hf iclass eview -s 64' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "6D C2 5B 15 FE FF 12 E0.*03 03 03 03 00 03 E0 17"; then break; fi
      if ! CheckExecute "hf iclass tagsim bin exits cleanly" "printf '\n' | $PM3CMD -c 'hf iclass tagsim --bin 10001111100000001010100011 --enc none; hf iclass eview -s 80' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "Uploaded .* bytes to emulator memory.*0/0x00.*6/0x06.*03 03 03 03 00 03 E0 14.*7/0x07.*00 00 00 00 06 3E 02 A3"; then break; fi
      if ! CheckExecute "hf iclass tagsim bin back-to-back updates" "timeout 25 $PM3CMD -c 'hf iclass tagsim --bin 10001111100000001010100011 --enc none; hf iclass tagsim --bin 01010101010101010101010101010101 --enc none; hf iclass eview -s 80' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "7/0x07.*00 00 00 01 55 55 55 55"; then break; fi
      if ! CheckExecute "hf iclass tagsim live update exits cleanly" "printf '\033[C' | $PM3CMD -c 'hf iclass tagsim -w H10301 --fc 31 --cn 337 --enc none; hf iclass eview -s 80' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "CN: 338.*0/0x00.*BD 0F 60 10 F7 FF 12 E0"; then break; fi
      if ! CheckExecute "hf 15 uid sim resets emu state" "timeout 15 $PM3CMD -c 'hf 15 sim -u E011223344556677 -t 100; hf 15 eview' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "UID.*E0 11 22 33 44 55 66 77.*4 bytes / blocks x 64 blocks"; then break; fi
    fi

    # Hitag 2, against a genuine card and a genuine reader.
    #
    # The card is a password mode Hitag 2 (configuration byte 0x06).  Its UID and
    # password are read from the card itself rather than hardcoded, so the tests
    # work with whatever fob is on the bench; only the ones that need a known
    # password use HITAG2_KEY, which defaults to the Paxton fob this was developed
    # against and can be overridden from the environment.
    if $TESTHITAG2; then
      echo -e "\n${C_BLUE}Testing Hitag 2 with a genuine card and reader${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"                "$PM3BIN"; then break; fi
      PM3CMD="$PM3BIN"
      if [ -n "${PM3PORT:-}" ]; then
        echo "Using PM3 port: $PM3PORT"
        PM3CMD="$PM3CMD -p $PM3PORT"
      fi
      HITAG2_KEY="${HITAG2_KEY:-BDF5E846}"

      WaitForEnter "PLACE THE GENUINE HITAG 2 CARD ON THE PM3 LF ANTENNA"

      # Reading the card: identification, then a full password mode dump.  The
      # config byte has to come back as a Hitag 2 in password mode, and every one
      # of the eight pages has to be present - a partial dump is the failure this
      # is here to catch, since one lost frame used to end the read early.
      if ! CheckExecute "lf hitag info genuine card" "$PM3CMD -c 'lf hitag info' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "UID.*Password mode.*Hitag 2"; then break; fi
      if ! CheckExecute "lf hitag read genuine card" "$PM3CMD -c 'lf hitag read -2 --pwd -k $HITAG2_KEY' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "0/0x00.*1/0x01.*2/0x02.*3/0x03.*4/0x04.*5/0x05.*6/0x06.*7/0x07"; then break; fi

      # Writing: put a known value in page 4 and read it back.  Page 4 is the
      # first user page, so this does not touch the UID, the key or the config.
      if ! CheckExecute "lf hitag wrbl genuine card"  "$PM3CMD -c 'lf hitag wrbl -2 -k $HITAG2_KEY -p 4 -d 11223344' 2>&1" "Write \( ok \)"; then break; fi
      if ! CheckExecute "lf hitag write readback"     "$PM3CMD -c 'lf hitag read -2 --pwd -k $HITAG2_KEY' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "4/0x04 \| 11 22 33 44"; then break; fi

      # Sniffing a genuine exchange.  Both directions have to appear: the reader's
      # START_AUTH and password, and the tag's answers.  A capture with reader
      # frames but no tag frames is the defect this catches - the tag side decoder
      # used to fabricate rows with no card present and miss real ones.
      WaitForEnter "PUT THE PM3 BETWEEN THE GENUINE CARD AND THE GENUINE READER, THEN PRESS ENTER. PRESS ENTER AGAIN IN THE CLIENT TO STOP THE SNIFF"
      if ! CheckExecute "lf hitag sniff genuine pair" "$PM3CMD -c 'lf hitag sniff; lf hitag list' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "Rdr.*START AUTH.*Tag.*32:"; then break; fi

      # Simulating to a genuine reader.  Only the operator can confirm the reader
      # actually accepted it, so this asks - the client cannot see the beep.
      WaitForEnter "REMOVE THE CARD, PRESENT THE PM3 TO THE GENUINE READER. THE SIM RUNS FOR 20s - LISTEN FOR THE READER TO BEEP, THEN PRESS ENTER"
      if ! CheckExecute "lf hitag sim to reader"      "timeout 30 $PM3CMD -c 'lf hitag eload -f $HITAG2_DUMP -2; lf hitag sim -2' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "Starting Hitag 2 simulation"; then break; fi
      WaitForEnter "DID THE READER BEEP / ACCEPT THE SIMULATED CARD? PRESS ENTER IF YES, CTRL-C IF NO"
    fi
    if $TESTICLASSREADER; then
      echo -e "\n${C_BLUE}Testing iCLASS reader verification${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"               "$PM3BIN"; then break; fi
      PM3CMD="$PM3BIN"
      if [ -n "${PM3PORT:-}" ]; then
        echo "Using PM3 port: $PM3PORT"
        PM3CMD="$PM3CMD -p $PM3PORT"
      fi

      WaitForEnter "PRESS ENTER TO START ICLASS PLAIN SIM, PRESENT THE PM3 TO ANOTHER READER, CONFIRM: iCLASS H10301 FC 31 CN 337, THEN PRESS THE PM3 BUTTON TO STOP SIM"
      if ! CheckExecute "hf iclass emu reader plain"  "$PM3CMD -c 'hf iclass tagsim -w H10301 --fc 31 --cn 337 --enc none' 2>&1" "Uploaded .* bytes to emulator memory"; then break; fi
      WaitForEnter "PRESS ENTER TO START ICLASS DES SIM, PRESENT THE PM3 TO ANOTHER READER, CONFIRM: iCLASS H10301 FC 31 CN 337, THEN PRESS THE PM3 BUTTON TO STOP SIM"
      if ! CheckExecute "hf iclass emu reader des"    "$PM3CMD -c 'hf iclass tagsim -w H10301 --fc 31 --cn 337 --enc des' 2>&1" "Uploaded .* bytes to emulator memory"; then break; fi
      WaitForEnter "PRESS ENTER TO START ICLASS 2K3DES SIM, PRESENT THE PM3 TO ANOTHER READER, CONFIRM: iCLASS H10301 FC 31 CN 337, THEN PRESS THE PM3 BUTTON TO STOP SIM"
      if ! CheckExecute "hf iclass emu reader 2k3des" "$PM3CMD -c 'hf iclass tagsim -w H10301 --fc 31 --cn 337 --enc 2k3des' 2>&1" "Uploaded .* bytes to emulator memory"; then break; fi
      if ! CheckExecute "hf iclass sim preserves emu" "$PM3CMD -c 'hf iclass eview -s 80' 2>&1 | LC_ALL=C tr -cd '\11\12\15\40-\176' | tr '\n' ' '" "0/0x00.*BD 0C 60 10 F7 FF 12 E0.*6/0x06.*03 03 03 03 00 03 E0 17.*7/0x07.*10 A1 45 91 9E D1 6F 50"; then break; fi
    fi

    # SIM module / ISO 7816 contact card tests.
    #
    # Card agnostic: asserts that answers come back and are stable, never what
    # they contain. Several checks repeat an exchange and require every answer
    # to match - a bus driven too fast returns the occasional corrupted frame
    # rather than failing outright, which a single shot would not catch.
    if $TESTSMARTCARD; then
      echo -e "\n${C_BLUE}Testing SIM module and contact smartcard${C_NC} ${PM3BIN:=./pm3}"
      if ! CheckFileExist "pm3 exists"                "$PM3BIN"; then break; fi
      PM3CMD="$PM3BIN"
      if [ -n "${PM3PORT:-}" ]; then
        echo "Using PM3 port: $PM3PORT"
        PM3CMD="$PM3CMD -p $PM3PORT"
      fi

      WaitForEnter "INSERT AN ISO 7816 CONTACT CARD INTO THE RDV4 SIM SLOT"

      # --- the module itself answers over I2C ---
      if ! CheckExecute "sim module present"          "$PM3CMD -c 'hw status' 2>&1" "Smart card module"; then break; fi
      if ! CheckExecute "sim module version ok"       "$PM3CMD -c 'hw status' 2>&1" "version\.+ v[0-9]+\.[0-9]+ \( .*ok"; then break; fi

      # --- the card answers, and answers the same way every time ---
      if ! CheckExecute "smart info returns an ATR"   "$PM3CMD -c 'smart info' 2>&1" "ISO7816-3 ATR\.+ 3[BF]"; then break; fi
      if ! CheckExecute "ATR stable over 5 reads"     "for i in 1 2 3 4 5; do $PM3CMD -c 'smart info' 2>&1 | grep -oE 'ISO7816-3 ATR\.+ [0-9A-F ]+'; done | sort -u | wc -l" "^ *1$"; then break; fi

      # any status word will do - the point is that the exchange completed
      if ! CheckExecute "T=0 apdu gets a status word" "$PM3CMD -c 'smart raw -a -s -0 -d 00a4040007a0000000041010' 2>&1" "\[[+-]\] [0-9A-Fa-f]{4} \|"; then break; fi
      if ! CheckExecute "T=0 answer stable over 3"    "for i in 1 2 3; do $PM3CMD -c 'smart raw -a -s -0 -d 00a4040007a0000000041010' 2>&1 | grep -oE '^\[[+-]\] [0-9A-Fa-f]{4}'; done | sort -u | wc -l" "^ *1$"; then break; fi

      # loose guard against the 1200 ms per-read wait coming back
      echo -n "  timing three exchanges... "
      SMART_T0=$(date +%s)
      $PM3CMD -c 'smart info; smart info; smart info' >/dev/null 2>&1
      SMART_DT=$(( $(date +%s) - SMART_T0 ))
      echo "${SMART_DT}s"
      if ! CheckExecute "three exchanges under 5s"    "echo $SMART_DT" "^[0-5]$"; then break; fi

      # --- T=1, only if this card offers it ---
      if $PM3CMD -c 'smart info' 2>&1 | grep -q "Protocol T1"; then
        echo "  card offers T=1"
        if ! CheckExecute "module reports T=1 support" "$PM3CMD -c 'hw status' 2>&1" "T=1, PPS\.+ \( .*supported"; then break; fi
        if ! CheckExecute "T=1 apdu gets a status word" "$PM3CMD -c 'smart raw --t1 -s -d 00a4040007a000000004101000' 2>&1" "\[[+-]\] [0-9A-Fa-f]{4} \|"; then break; fi
        if ! CheckExecute "T=1 answer stable over 3"   "for i in 1 2 3; do $PM3CMD -c 'smart raw --t1 -s -d 00a4040007a000000004101000' 2>&1 | grep -oE '^\[[+-]\] [0-9A-Fa-f]{4}'; done | sort -u | wc -l" "^ *1$"; then break; fi
      else
        echo "  card is T=0 only, skipping the T=1 checks"
      fi

    fi

  
  echo -e "\n------------------------------------------------------------"
  echo -e "Tests [ ${C_GREEN}OK${C_NC} ] ${C_OK}\n"
  exit 0
done
echo -e "\n------------------------------------------------------------"
echo -e "\nTests [ ${C_RED}FAIL${C_NC} ] ${C_FAIL}\n"
exit 1
