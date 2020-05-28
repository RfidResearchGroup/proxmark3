#!/bin/bash

swig -lua -o ../src/pm3_luawrap.c ../include/pm3.h
swig -python -o ../src/pm3_pywrap.c ../include/pm3.h
