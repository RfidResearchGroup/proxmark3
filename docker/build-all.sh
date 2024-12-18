#!/bin/bash

for os in archlinux debian-12-bookworm debian-12-bookworm-arm64 debian-12-bookworm-armhf debian-13-trixie fedora-36 fedora-37 homebrew kali opensuse-leap opensuse-tumbleweed parrot-core-latest ubuntu-20.04 ubuntu-22.04; do
  (  cd $os && ../build.sh )
done
