#!/bin/bash

for os in archlinux debian-buster fedora-34 homebrew opensuse-leap opensuse-tumbleweed ubuntu-18.04 ubuntu-20.04; do
  (  cd $os && ./docker_build.sh )
done
