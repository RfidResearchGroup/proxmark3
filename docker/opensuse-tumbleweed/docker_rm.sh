#!/bin/bash

docker rm $(docker ps -aq --filter ancestor=pm3-suse-tumbleweed:1.0)
docker image rm pm3-suse-tumbleweed:1.0
