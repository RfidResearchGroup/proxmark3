#!/bin/bash

#/usr/local/lib/python3/dist-packages/pm3.py
#/usr/lib/python3/dist-packages/pm3.py

# need access to pm3.py
PYTHONPATH=../src ../build/proxmark3 /dev/ttyACM1 -c "script run testembedded_grab.py" -i
