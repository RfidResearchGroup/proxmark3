#!/bin/bash

docker rm $(docker ps -aq --filter ancestor=pm3-fedora-37:1.0)
docker image rm pm3-fedora-37:1.0
