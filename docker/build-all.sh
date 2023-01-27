#!/bin/bash

for os in archlinux debian-buster fedora-36 fedora-37 homebrew kali opensuse-leap opensuse-tumbleweed parrot-core-latest ubuntu-18.04 ubuntu-20.04 ubuntu-22.04; do
  (  cd $os && ./docker_build.sh )
done
