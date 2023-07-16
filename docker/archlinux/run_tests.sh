#!/usr/bin/env bash
# Iceman 2022
#
# This script is to be run from proxmark root folder inside the docker env
# docker/archlinux/run_tests.sh;
#
# Script contains two phases.
#
# -- Init / setup phase
# Script to be run inside docker env. First install some dependencies for docker image.
#
# -- Build phase begins
# make builds
# cmake client builds
# of the different possible PLATFORM (PM3RDV4 / PM3GENERIC) and BTADDON combos

cat << EOF |sudo tee -a /etc/pacman.conf

[testing]
Include = /etc/pacman.d/mirrorlist

[community-testing]
Include = /etc/pacman.d/mirrorlist

[staging]
Include = /etc/pacman.d/mirrorlist
EOF

sudo pacman -Syu

# search available versions
pacman -Ss '^arm-none-eabi-gcc$'
pacman -Ss '^gcc$'

# depending on where the latest bleeding edge is:
# sudo pacman -S community-testing/arm-none-eabi-gcc
# sudo pacman -S arm-none-eabi-gcc
# sudo pacman -S staging/gcc
# sudo pacman -S testing/gcc
# sudo pacman -S gcc

python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
python3 -m pip install --use-pep517 pyaes
python3 -m pip install ansicolors sslcrypto
tools/release_tests.sh
deactivate
