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
  ln -sf build/proxmark3 .
)
ln -sf ../pyscripts/pm3.py
ln -sf ../lualibs/dkjson.lua
