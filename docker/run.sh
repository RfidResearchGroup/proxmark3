#!/bin/bash

if [ ! -e docker_conf.inc ]; then
    echo "This script must be run from within one of the subfolders"
    exit 1
fi
. docker_conf.inc
UART_PORT="$(../../pm3 --list|grep dev|head -n1|cut -d' ' -f2)"
if [ -n "$UART_PORT" ]; then
    DEV="--device=/dev/tty0 --device=$UART_PORT"
else
    DEV=""
fi
docker run $DEV $DOCKER_PLATFORM --volume="$(pwd)/../..:/home/rrg/proxmark3" -w /home/rrg/proxmark3 --net=host --rm -it "$DOCKER_IMAGE"
