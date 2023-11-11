#!/bin/bash

gcc -o test test.c -I../../include -lpm3rrg_rdv4 -L../build -lpthread
gcc -o test_grab test_grab.c -I../../include -lpm3rrg_rdv4 -L../build -lpthread
