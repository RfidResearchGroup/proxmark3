#!/bin/bash

cd ..
rm -rf build
mkdir build
(
  cd build
  cmake ..
  make -j
)
