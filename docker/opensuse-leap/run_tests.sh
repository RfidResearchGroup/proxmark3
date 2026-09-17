#!/usr/bin/env bash
# Iceman 2022
#
# This script is to be run from proxmark root folder inside the docker env
# docker/opensuse-leap/run_tests.sh;

sudo zypper refresh && sudo zypper --non-interactive update
tools/release_tests.sh
# beeps
for ((i=0; i<10;i++)) do echo -e "\a";sleep 0.3; done
