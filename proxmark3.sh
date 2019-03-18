#!/bin/bash

function wait4proxmark_Linux {
    echo >&2 "Waiting for Proxmark to appear..."
    while [ ! -c /dev/ttyACM? -a ! -c /dev/pm3-? ]; do
        sleep .1
    done
    local PM3=`ls -1 /dev/pm3-? /dev/ttyACM? 2>/dev/null | head -1`
    echo >&2 -e "Found proxmark on ${PM3}\n"
    echo $PM3
}

function wait4proxmark_macOS {
    echo >&2 "Waiting for Proxmark to appear..."
    while true; do
        PM3=$(ls /dev/pm3-* /dev/cu.usbmodem* 2>/dev/null | head -1)
        if [[ $PM3 != "" ]]; then
            #echo >&2 -e "Found proxmark on $(ls /dev/pm3-* /dev/cu.usbmodem* 2>/dev/null | head -1)\n"
            break
        fi
        sleep .1
    done
    echo $PM3
}

# start proxmark with first detected interface

if [[ $(uname | awk '{print toupper($0)}') == "LINUX" ]]; then
    client/proxmark3 $(wait4proxmark_Linux)
elif [[ $(uname | awk '{print toupper($0)}') == "DARWIN" ]]; then
    client/proxmark3 $(wait4proxmark_macOS)
fi
