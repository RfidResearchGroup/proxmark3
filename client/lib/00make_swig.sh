#!/bin/bash

swig -lua -o ../src/pm3_luawrap.c ../src/pm3.i
swig -python -o ../src/pm3_pywrap.c ../src/pm3.i
