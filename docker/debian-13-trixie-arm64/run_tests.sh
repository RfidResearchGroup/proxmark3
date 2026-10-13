#!/usr/bin/env bash
# This script is to be run from proxmark root folder inside the docker env
# docker/debian-13-trixie-arm64/run_tests.sh;

# sudo not supported in this docker image, update packages before running as rrg user
if [ "$EUID" -eq 0 ]; then
    apt update && sudo apt upgrade -y
fi

# Re-execute the script as rrg user if not already running as rrg
if [[ $(id -un) != rrg ]]; then
    script_path=$(readlink -f -- "${BASH_SOURCE[0]}")
    working_directory=$(pwd -P)
    exec su - rrg -c 'cd "$1" && exec bash "$2" "${@:3}"' bash \
        "$working_directory" "$script_path" "$@"
fi

# Check that we are not running as root
if [ "$EUID" -eq 0 ]; then
    echo "Error: This script should not be run as root" >&2
    exit 1
fi

git config --global --add safe.directory /home/rrg/proxmark3
tools/release_tests.sh
# beeps
for ((i=0; i<10;i++)) do echo -e "\a";sleep 0.3; done
