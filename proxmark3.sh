#!/bin/bash

FULLIMAGE="armsrc/obj/fullimage.elf"
BOOTIMAGE="bootrom/obj/bootrom.elf"

cd $(dirname "$0")

function wait4proxmark_Linux {
    echo >&2 "Waiting for Proxmark to appear..."
    while [ ! -c /dev/ttyACM? -a ! -c /dev/pm3-? ]; do
        sleep .1
    done
    local PM3=`ls -1 /dev/pm3-? /dev/ttyACM? 2>/dev/null | head -1`
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

function wait4proxmark_Windows {
    echo >&2 "Waiting for Proxmark to appear..."
    while true; do
        device=$(wmic path Win32_SerialPort where "PNPDeviceID like '%VID_9AC4&PID_4B8F%'" get DeviceID,PNPDeviceID 2>/dev/null | awk 'NR==2')
        if [[ $device != "" ]]; then
            PM3=${device/ */}
            break
        fi
        sleep .1
    done
    echo $PM3
}

function wait4proxmark_WSL {
    echo >&2 "Waiting for Proxmark to appear..."
    while true; do
        device=$(wmic.exe path Win32_SerialPort where "PNPDeviceID like '%VID_9AC4&PID_4B8F%'" get DeviceID,PNPDeviceID 2>/dev/null | awk 'NR==2')
        if [[ $device != "" ]]; then
            PM3=${device/ */}
            PM3="/dev/ttyS${PM3#COM}"
            break
        fi
        sleep .1
    done
    echo $PM3
}

SCRIPT=$(basename -- "$0")

if [ "$SCRIPT" = "proxmark3.sh" ]; then
  CMD=client/proxmark3
elif [ "$SCRIPT" = "flash-all.sh" ]; then
  CMD=client/flasher
  ARG1="-b $BOOTIMAGE"
  ARG2="$FULLIMAGE"
elif [ "$SCRIPT" = "flash-fullimage.sh" ]; then
  CMD=client/flasher
  ARG2="$FULLIMAGE"
elif [ "$SCRIPT" = "flash-bootrom.sh" ]; then
  CMD=client/flasher
  ARG1="-b $BOOTIMAGE"
else
  echo "Script ran under unknown name, abort: $SCRIPT"
  exit 1
fi
HOSTOS=$(uname | awk '{print toupper($0)}')
if [ "$HOSTOS" = "LINUX" ]; then
    if uname -a|grep -q Microsoft; then
        PORT=$(wait4proxmark_WSL)
    else
        PORT=$(wait4proxmark_Linux)
    fi
elif [ "$HOSTOS" = "DARWIN" ]; then
    PORT=$(wait4proxmark_macOS)
elif [[ "$HOSTOS" =~ MINGW(32|64)_NT* ]]; then
    PORT=$(wait4proxmark_Windows)
else
    echo "Host OS not recognized, abort: $HOSTOS"
    exit 1
fi
if [ "$PORT" = "" ]; then
    echo "No port, abort"
    exit 1
fi

#echo Running "$CMD" "$PORT" $ARG1 $ARG2 "$@"
"$CMD" "$PORT" $ARG1 $ARG2 "$@"
exit $?
