#!/bin/bash

. docker_conf
UART_PORT="$(../../pm3 --list|head -n1|cut -d' ' -f2)"
UART_GID="$(stat -c '%g' $UART_PORT)"
docker build --build-arg UART_GID="$UART_GID" -t "$DOCKER_IMAGE" .
