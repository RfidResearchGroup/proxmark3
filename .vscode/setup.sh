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

function print_config {
	echo "Updating with following configuration:"
	echo "SerialPort: $SerialPort"
	echo "DebuggerPath: $DebuggerPath"
	echo "JLinkServerPath: $JLinkServerPath"
}

function setup_serial_port {
	if [ -z "$SerialPort" ]; then
		pm3list=$($VSCODEPATH/../pm3 --list 2>/dev/null)
		#Use first port listed 
		SerialPort=$(echo $pm3list | head -n 1 | cut -c 4-)
		if [ -z "$SerialPort" ]; then
			echo >&2 "[!!] No serial port found, please set SerialPort manually"
			exit 1
		fi
	fi
}

function setup_gdb_linux {
	if [ -z "$DebuggerPath" ]; then
		export DebuggerPath="/usr/bin/gdb"
	fi
	if [ ! -x "$DebuggerPath" ]; then
		echo >&2 "[!!] gdb not found, please set DebuggerPath manually"
		exit 1
	fi
}

function setup_jlink_linux {
	if [ -z "$JLinkServerPath" ]; then
		export JLinkServerPath="/opt/SEGGER/JLink/JLinkGDBServerCLExe"
	fi
	if [ ! -x "$JLinkServerPath" ]; then
		echo >&2 "[!!] JLinkGDBServerCLExe not found, please set JLinkServerPath manually"
		exit 1
	fi
	
}

function setup_jlink_wsl {
	if [ -z "$JLinkServerPath" ]; then
		export JLinkServerPath="/mnt/c/Program Files (x86)/SEGGER/JLink/JLinkGDBServerCL.exe"
	fi
	if [ ! -x "$JLinkServerPath" ]; then
		echo >&2 "[!!] JLinkGDBServerCLExe not found, please set JLinkServerPath manually"
		exit 1
	fi
}

function setup_wsl {
	setup_serial_port
	setup_gdb_linux
	setup_jlink_wsl
	print_config
	cp "$VSCODEPATH/templates/tasks_wsl.json" "$VSCODEPATH/tasks.json"
	envsubst '${SerialPort} ${DebuggerPath} ${JLinkServerPath} ${DeviceMem}' <"$VSCODEPATH/templates/launch_wsl.json" > "$VSCODEPATH/launch.json"
}

function setup_linux {
	setup_serial_port
	setup_gdb_linux
	setup_jlink_linux
	print_config
	cp "$VSCODEPATH/templates/tasks_linux.json" "$VSCODEPATH/tasks.json"
	envsubst '${SerialPort} ${DebuggerPath} ${JLinkServerPath} ${DeviceMem}' <"$VSCODEPATH/templates/launch_linux.json" > "$VSCODEPATH/launch.json"
}

function setup_ps {
	setup_serial_port
	if [ -z "$JLinkServerPath" ]; then
		export JLinkServerPath="c/Program Files (x86)/SEGGER/JLink/JLinkGDBServerCL.exe"
	fi
	print_config
}

if [ -f "$VSCODEPATH/launch.json" ] || [ -f "$VSCODEPATH/tasks.json"  ]; then
	read -p "Existing configuration found, do you want to override it? " -n 1 -r
	if [[ $REPLY =~ ^[Yy]$ ]]
	then
		rm "$VSCODEPATH/launch.json.bak" 2> /dev/null
		rm "$VSCODEPATH/tasks.json.bak" 2> /dev/null
		mv "$VSCODEPATH/launch.json" "$VSCODEPATH/launch.json.bak" 2> /dev/null
		mv "$VSCODEPATH/tasks.json" "$VSCODEPATH/tasks.json.bak" 2> /dev/null
	else
		echo >&2 "[!!] user abort"
		exit 1
	fi

fi

HOSTOS=$(uname | awk '{print toupper($0)}')
if [ "$HOSTOS" = "LINUX" ]; then
    if uname -a|grep -q Microsoft; then
		setup_wsl
    else
		setup_linux
    fi
elif [ "$HOSTOS" = "DARWIN" ]; then
	echo >&2 "[!!] MacOS not supported, sorry!"
	exit 1
elif [[ "$HOSTOS" =~ MINGW(32|64)_NT* ]]; then
	setup_ps
else
    echo >&2 "[!!] Host OS not recognized, abort: $HOSTOS"
    exit 1
fi