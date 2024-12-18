#!/bin/bash

. docker_conf
docker rm $(docker ps -aq --filter ancestor="$DOCKER_IMAGE")
docker image rm "$DOCKER_IMAGE"
