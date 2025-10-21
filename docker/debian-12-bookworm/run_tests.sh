#!/usr/bin/env bash
# This script is to be run from proxmark root folder inside the docker env
# docker/debian-12-bookworm/run_tests.sh;

sudo apt update && sudo apt upgrade -y
tools/release_tests.sh
