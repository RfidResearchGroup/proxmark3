#!/bin/bash

function wait4proxmark {
	echo "Waiting for Proxmark to appear..."
	while [ ! -e /dev/ttyACM? ]; do
		sleep .1
	done
}

# start proxmark with first detected interface
wait4promark
client/proxmark3 /dev/ttyACM?
