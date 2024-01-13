#!/bin/bash

docker rm $(docker ps -aq --filter ancestor=pm3-parrotsec-core-latest:1.0)
docker image rm pm3-parrotsec-core-latest:1.0
