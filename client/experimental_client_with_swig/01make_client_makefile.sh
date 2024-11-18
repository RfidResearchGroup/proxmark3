#!/bin/bash

(
  cd ..
  make -j
)
ln -s ../pyscripts/pm3.py
ln -s ../lualibs/dkjson.lua
