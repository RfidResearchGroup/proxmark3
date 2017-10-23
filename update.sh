#!/bin/bash

function wait4proxmark {
	echo "Waiting for Proxmark to appear..."
	while [ ! -e /dev/ttyACM? ]; do
		sleep .1
	done
}

# flash bootroom
wait4proxmark
client/flasher /dev/ttyACM? -b bootrom/obj/bootrom.elf

# flash system image
wait4proxmark
client/flasher /dev/ttyACM? armsrc/obj/fullimage.elf 
