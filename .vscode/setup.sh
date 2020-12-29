#!/bin/bash
###############################
#            Linux            #
#    Uncomment to override    #
###############################
#export SerialPort="/dev/ttyACM0"
#export DebuggerPath="/usr/bin/gdb"
#export JLinkServerPath="/opt/SEGGER/JLink/JLinkGDBServerCLExe"

###############################
#             WSL             #
#    Uncomment to override    #
###############################
#export SerialPort="/dev/ttyS4"
#export DebuggerPath="/usr/bin/gdb"
#export JLinkServerPath="/mnt/c/Program Files (x86)/SEGGER/JLink/JLinkGDBServerCL.exe"

###############################
#          ProxSpace          #
#    Uncomment to override    #
###############################
#export SerialPort="COM5"
#export DebuggerPath="${workspaceFolder}/../../msys2/mingw64/bin/gdb.exe"
#export JLinkServerPath="c/Program Files (x86)/SEGGER/JLink/JLinkGDBServerCL.exe"

#Debugging on 256KB systems is not recommended
#This option does not override PLATFORM_SIZE
export DeviceMem="512"


VSCODEPATH=$(dirname "$0")

function get_serial_port {
	if [ -z "$SerialPort" ]; then
		pm3list=$($VSCODEPATH/../pm3 --list 2>/dev/null)
		#Use first port listed 
		SerialPort=$(echo $pm3list | head -n 1 | cut -c 4-)
		if [ -z "$SerialPort" ]; then
			echo >&2 "[!!] No serial port found, please set SerialPort manually"
			exit 1
		fi
	fi
	
	echo "Using $SerialPort as port"
}


HOSTOS=$(uname | awk '{print toupper($0)}')
if [ "$HOSTOS" = "LINUX" ]; then
    if uname -a|grep -q Microsoft; then
        echo "WSL"
    else
        echo "LINUX"
    fi
elif [ "$HOSTOS" = "DARWIN" ]; then
	echo >&2 "[!!] MacOS not supported, sorry!"
	exit 1
elif [[ "$HOSTOS" =~ MINGW(32|64)_NT* ]]; then
    echo "ProxSpace"
else
    echo >&2 "[!!] Host OS not recognized, abort: $HOSTOS"
    exit 1
fi

get_serial_port