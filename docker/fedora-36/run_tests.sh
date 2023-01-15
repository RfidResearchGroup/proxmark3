#!/usr/bin/env bash
# Iceman 2022
#
# This script is to be run from proxmark root folder inside the docker env
# docker/fedora-36/run_tests.sh;

sudo apt update && sudo apt upgrade -y
tools/release_tests.sh
