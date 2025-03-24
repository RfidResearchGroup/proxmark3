#!/bin/bash

(
  cd ..
  make -j
)
ln -sf ../pyscripts/pm3.py
ln -sf ../lualibs/dkjson.lua
