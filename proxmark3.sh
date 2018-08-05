#!/bin/bash

function wait4proxmark {
	echo >&2 "Waiting for Proxmark to appear..."
	while [ ! -c /dev/ttyACM? -a ! -L /dev/pm3-? ]; do
		sleep .1
	done
	local PM3=`ls -1 /dev/pm3-? /dev/ttyACM? 2>/dev/null | head -1`
	echo >&2 -e "Found proxmark on ${PM3}\n"
	echo $PM3
}

# start proxmark with first detected interface
client/proxmark3 $(wait4proxmark)
