#!/bin/bash

PM3PATH=$(dirname "$0")
cd "$PM3PATH" || exit 1

C_RED='\033[0;31m'
C_GREEN='\033[0;32m'
C_BLUE='\033[0;34m'
C_NC='\033[0m' # No Color

function CheckFileExist() {
 
  if [ -f "$2" ]; then
    echo "$1 [OK]"
	return 0
  fi  
  
  if ls $2 1> /dev/null 2>&1; then
    echo "$1 [OK]"
	return 0
  fi
  
  echo "$1 [Fail]"
  return 1
}

printf "\n${C_BLUE}RRG Proxmark3 test tool ${C_NC}\n\n"

while true; do
  if ! CheckFileExist "proxmark3 exists" "client/proxmark3"; then break; fi
  if ! CheckFileExist "arm image exists" "armsrc/obj/fullimage.elf"; then break; fi
  if ! CheckFileExist "bootrom exists" "bootrom/obj/bootrom.elf"; then break; fi
  if ! CheckFileExist "hardnested tables exists" "client/hardnested/tables/*.z"; then break; fi

  printf "\n${C_GREEN}Tests [OK]${C_NC}\n\n"
  exit 0
done

printf "\n${C_RED}Tests [FAIL]${C_NC}\n\n"
exit 1