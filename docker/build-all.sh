#!/bin/bash

for os in archlinux debian fedora homebrew opensuse ubuntu; do
  (  cd $os && ./docker_build.sh )
done
