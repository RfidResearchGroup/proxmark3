#!/bin/bash

(
  cd ..
  rm -rf build
  mkdir build
  (
    cd build
    cmake ..
    make -j
  )
  rm proxmark3
  ln -s build/proxmark3 .
)
ln -s ../pyscripts/pm3.py
