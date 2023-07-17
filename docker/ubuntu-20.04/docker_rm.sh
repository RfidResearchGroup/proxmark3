#!/bin/bash

docker rm $(docker ps -aq --filter ancestor=pm3-ubuntu-20.04:1.0)
docker image rm pm3-ubuntu-20.04:1.0
