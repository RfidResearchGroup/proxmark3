#!/usr/bin/env bash

PM3PATH=$(dirname "$0")
cd "$PM3PATH" || exit 1

if [ "$1" == "long" ]; then
    SLOWTESTS=true
else
    SLOWTESTS=false
fi

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

  if ls $2 1> /dev/null 2>&1; then
    echo -e "$1 ${C_GREEN}[OK]${C_NC}"
    return 0
  fi

  echo -e "$1 ${C_RED}[Fail]${C_NC}"
  return 1
}

# title, command line, check result, repeat several times if failed, ignore if fail
function CheckExecute() {

  if [ $4 ]; then
    local RETRY="1 2 3 e"
  else
    local RETRY="e"
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


  if [ $5 ]; then
    echo -e "$1 ${C_YELLOW}[Ignored]${C_NC}"
    return 0
  fi

  echo -e "$1 ${C_RED}[Fail]${C_NC}"
  echo -e "Execution trace:\n$RES"
  return 1
}

printf "\n${C_BLUE}RRG/Iceman Proxmark3 test tool ${C_NC}\n\n"

printf "work directory: "
pwd

if [ "$TRAVIS_COMMIT" ]; then
  if [ "$TRAVIS_PULL_REQUEST" == "false" ]; then
    echo "Travis branch: $TRAVIS_BRANCH slug: $TRAVIS_REPO_SLUG commit: $TRAVIS_COMMIT"
  else
    echo "Travis pull request: $TRAVIS_PULL_REQUEST branch: $TRAVIS_BRANCH slug: $TRAVIS_PULL_REQUEST_SLUG commit: $TRAVIS_COMMIT"
  fi
fi

printf "git branch: "
git describe --all
printf "git sha: "
git rev-parse HEAD
echo ""

while true; do
  printf "\n${C_BLUE}Testing files:${C_NC}\n"
  if ! CheckFileExist "xorcheck exists" "tools/xorcheck.py"; then break; fi

  printf "\n${C_BLUE}Testing tools:${C_NC}\n"
  if ! CheckExecute "xorcheck test" "tools/xorcheck.py 04 00 80 64 ba" "final LRC XOR byte value: 5A"; then break; fi
  printf "\n${C_GREEN}Tests [OK]${C_NC}\n\n"
  exit 0
done

printf "\n${C_RED}Tests [FAIL]${C_NC}\n\n"
exit 1
