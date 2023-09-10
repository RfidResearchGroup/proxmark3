#!/bin/bash

docker rm $(docker ps -aq --filter ancestor=pm3-suse-leap:1.0)
docker image rm pm3-suse-leap:1.0
