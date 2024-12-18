#!/bin/bash

. docker_conf
# Make sure to connect a Proxmark3 when building if you want to be able to access it from within the Docker instance
UART_PORT="$(../../pm3 --list|grep /dev|head -n1|cut -d' ' -f2)"
if [ -n "$UART_PORT" ]; then
    UART_GID="$(stat -c '%g' $UART_PORT)"
    BUILDARG="--build-arg UART_GID=$UART_GID"
else
    BUILDARG=""
fi
docker build $BUILDARG -t "$DOCKER_IMAGE" .
