#!/bin/bash

if [ ! -e docker_conf.inc ]; then
    echo "This script must be run from within one of the subfolders"
    exit 1
fi
. docker_conf.inc
CONTAINER=$(docker ps -aq --filter ancestor="$DOCKER_IMAGE")
if [ -n "$CONTAINER" ]; then
    docker rm $CONTAINER
fi
docker image rm "$DOCKER_IMAGE"
