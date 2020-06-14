#!/bin/bash

swig -lua -o ../src/pm3_luawrap.c ../include/pm3.i
swig -python -o ../src/pm3_pywrap.c ../include/pm3.i
