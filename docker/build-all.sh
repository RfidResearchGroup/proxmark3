#!/bin/bash

for os in archlinux debian-12-bookworm debian-12-bookworm-arm64 debian-12-bookworm-armhf debian-13-trixie debian-14-forky fedora-41 fedora-42 fedora-43 homebrew kali opensuse-leap opensuse-tumbleweed parrot-core-latest ubuntu-24.04 ubuntu-24.10 ubuntu-25.04; do
  echo -e "\n\n================= Building for $os ======================\n"
  (  cd $os && ../build.sh )
done
