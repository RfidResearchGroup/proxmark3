#!/bin/bash

(
  cd ..
  # Remove cmake artifact
  rm proxmark3
  make client/clean
  make -j
)
ln -sf ../pyscripts/pm3.py
ln -sf ../lualibs/dkjson.lua
