#!/bin/bash

if [ ! -e docker_conf.inc ]; then
    echo "This script must be run from within one of the subfolders"
    exit 1
fi
. docker_conf.inc
# Make sure to connect a Proxmark3 when building if you want to be able to access it from within the Docker instance
UART_PORT="$(../../pm3 --list|grep /dev|head -n1|cut -d' ' -f2)"
if [ -n "$UART_PORT" ]; then
    UART_GID="$(stat -c '%g' $UART_PORT)"
    BUILDARG="--build-arg UART_GID=$UART_GID"
else
    BUILDARG=""
fi

# For cross-platform support:
# cf https://github.com/multiarch/qemu-user-static
#sudo apt install qemu-user-static
# credential=yes needed to get proper sudo support in cross-platform Docker instances
#docker run --rm --privileged multiarch/qemu-user-static --reset -p yes --credential yes
#docker buildx create --use
#docker buildx inspect --bootstrap
#docker buildx build $DOCKER_PLATFORM $BUILDARG -t "$DOCKER_IMAGE" --load .
# Seems to work without buildx:
docker build $DOCKER_PLATFORM $BUILDARG -t "$DOCKER_IMAGE" .
