#!/bin/bash

. docker_conf
UART_PORT="$(../../pm3 --list|grep dev|head -n1|cut -d' ' -f2)"
if [ -n "$UART_PORT" ]; then
    DEV="--device=/dev/tty0 --device=$UART_PORT"
else
    DEV=""
fi
docker run $DEV --volume="$(pwd)/../..:/home/rrg/proxmark3" -w /home/rrg/proxmark3 -it "$DOCKER_IMAGE"
