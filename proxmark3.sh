#!/bin/bash

FULLIMAGE="armsrc/obj/fullimage.elf"
BOOTIMAGE="bootrom/obj/bootrom.elf"

PM3PATH=$(dirname "$0")
cd "$PM3PATH" || exit 1

function wait4proxmark_Linux {
    echo >&2 "[=] Waiting for Proxmark3 to appear..."
    while true; do
        PM3=$(find /dev/pm3-* /dev/ttyACM* 2>/dev/null | head -1)
        if [[ $PM3 != "" ]]; then
            break
        fi
        sleep .1
    done
    echo "$PM3"
}

function wait4proxmark_macOS {
    echo >&2 "[=] Waiting for Proxmark3 to appear..."
    while true; do
        PM3=$(find /dev/pm3-* /dev/tty.usbmodem* 2>/dev/null | head -1)
        if [[ $PM3 != "" ]]; then
            break
        fi
        sleep .1
    done
    echo "$PM3"
}

function wait4proxmark_Windows {
    echo >&2 "[=] Waiting for Proxmark3 to appear..."
    while true; do
        device=$(wmic path Win32_SerialPort where "PNPDeviceID like '%VID_9AC4&PID_4B8F%'" get DeviceID,PNPDeviceID 2>/dev/null | awk 'NR==2')
        if [[ $device != "" ]]; then
            PM3=${device/ */}
            break
        fi
        sleep .1
    done
    echo "$PM3"
}

function wait4proxmark_WSL {
    echo >&2 "[=] Waiting for Proxmark3 to appear..."
    while true; do
        device=$(wmic.exe path Win32_SerialPort where "PNPDeviceID like '%VID_9AC4&PID_4B8F%'" get DeviceID,PNPDeviceID 2>/dev/null | awk 'NR==2')
        if [[ $device != "" ]]; then
            PM3=${device/ */}
            PM3="/dev/ttyS${PM3#COM}"
            break
        fi
        sleep .1
    done
    if [ -e "$PM3" ] && [ ! -w "$PM3" ]; then
        echo "[!!] We need to give current user read/write access to $PM3"
        sudo chmod 666 "$PM3"
    fi
    echo "$PM3"
}

SCRIPT=$(basename -- "$0")

if [ "$SCRIPT" = "proxmark3.sh" ]; then
  CMD() { client/proxmark3 "$@"; }
elif [ "$SCRIPT" = "flash-all.sh" ]; then
  CMD() { client/flasher "$1" -b "$BOOTIMAGE" "$FULLIMAGE"; }
elif [ "$SCRIPT" = "flash-fullimage.sh" ]; then
  CMD() { client/flasher "$1" "$FULLIMAGE"; }
elif [ "$SCRIPT" = "flash-bootrom.sh" ]; then
  CMD() { client/flasher "$1" -b "$BOOTIMAGE"; }
else
  echo "[!!] Script ran under unknown name, abort: $SCRIPT"
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
    echo "[!!] Host OS not recognized, abort: $HOSTOS"
    exit 1
fi
if [ "$PORT" = "" ]; then
    echo "[!!] No port, abort"
    exit 1
fi

CMD "$PORT" "$@"
exit $?
