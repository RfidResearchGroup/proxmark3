#!/bin/bash

for os in archlinux debian-12-bookworm fedora-36 fedora-37 homebrew kali opensuse-leap opensuse-tumbleweed parrot-core-latest ubuntu-20.04 ubuntu-22.04; do
  (  cd $os && ./docker_build.sh )
done
