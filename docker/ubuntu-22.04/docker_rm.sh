#!/bin/bash

docker rm $(docker ps -aq --filter ancestor=pm3-ubuntu-22.04:1.0)
docker image rm pm3-ubuntu-22.04:1.0
