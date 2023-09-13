#!/usr/bin/env bash
# This script is to be run from proxmark root folder inside the docker env
# docker/debian-13-trixie/run_tests.sh;

sudo apt update && sudo apt upgrade -y
python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
python3 -m pip install --use-pep517 pyaes
python3 -m pip install ansicolors sslcrypto
tools/release_tests.sh
deactivate
