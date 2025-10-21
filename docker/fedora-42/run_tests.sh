#!/usr/bin/env bash
# Iceman 2022
#
# This script is to be run from proxmark root folder inside the docker env
# docker/fedora-42/run_tests.sh;

sudo yum -y update
tools/release_tests.sh
