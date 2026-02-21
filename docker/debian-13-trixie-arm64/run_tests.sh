#!/usr/bin/env bash
# This script is to be run from proxmark root folder inside the docker env
# docker/debian-13-trixie-arm64/run_tests.sh;

# Check that we are not running as root
if [ "$EUID" -eq 0 ]; then
    echo "Error: This script should not be run as root" >&2
    exit 1
fi

# sudo not supported in this docker image, update packages before running as rrg user
# sudo apt update && sudo apt upgrade -y
git config --global --add safe.directory /home/rrg/proxmark3
tools/release_tests.sh
