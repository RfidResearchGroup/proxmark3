#!/bin/bash

PM3PATH=$(dirname "$0")
cd "$PM3PATH" || exit 1

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_BLUE='\033[0;34m'
C_NC='\033[0m' # No Color

function CheckFileExist() {
 
  if [ -f "$2" ]; then
    echo -e "$1 ${C_GREEN}[OK]${C_NC}"
	return 0
  fi  
  
  if ls $2 1> /dev/null 2>&1; then
    echo -e "$1 ${C_GREEN}[OK]${C_NC}"
	return 0
  fi
  
  echo -e "$1 ${C_RED}[Fail]${C_NC}"
  return 1
}

function CheckExecute() {

  if eval "$2 | grep -q '$3'"; then
    echo -e "$1 ${C_GREEN}[OK]${C_NC}"
	return 0
  fi
  
  echo -e "$1 ${C_RED}[Fail]${C_NC}"
  return 1
}

printf "\n${C_BLUE}RRG Proxmark3 test tool ${C_NC}\n\n"

if [ "$TRAVIS_COMMIT" ]; then
  if [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
    echo "Travis branch: $TRAVIS_REPO_SLUG commit: $TRAVIS_PULL_REQUEST_SHA"
  else
    echo "Travis pull request: $TRAVIS_PULL_REQUEST branch: $TRAVIS_PULL_REQUEST_SLUG commit: $TRAVIS_COMMIT"
  fi
fi

printf "git branch: " 
git describe --all
printf "git sha: " 
git rev-parse HEAD
echo ""

while true; do
  if ! CheckFileExist "proxmark3 exists" "./client/proxmark3"; then break; fi
  if ! CheckFileExist "arm image exists" "./armsrc/obj/fullimage.elf"; then break; fi
  if ! CheckFileExist "bootrom exists" "./bootrom/obj/bootrom.elf"; then break; fi
  if ! CheckFileExist "hardnested tables exists" "./client/hardnested/tables/*.z"; then break; fi

  if ! CheckExecute "proxmark help" "./client/proxmark3 -h" "wait"; then break; fi
  if ! CheckExecute "proxmark help text ISO7816" "./client/proxmark3 -t 2>&1" "ISO7816"; then break; fi
  if ! CheckExecute "proxmark help text hardnested" "./client/proxmark3 -t 2>&1" "hardnested"; then break; fi

  if ! CheckExecute "hf mf offline text" "./client/proxmark3 -c 'hf mf'" "at_enc"; then break; fi

  if ! CheckExecute "hf mf hardnested test" "./client/proxmark3 -c 'hf mf hardnested t 1 000000000000'" "found:"; then break; fi
  if ! CheckExecute "emv test" "./client/proxmark3 -c 'emv test'" "Test(s) \[ OK"; then break; fi
  
  printf "\n${C_GREEN}Tests [OK]${C_NC}\n\n"
  exit 0
done

printf "\n${C_RED}Tests [FAIL]${C_NC}\n\n"
exit 1
