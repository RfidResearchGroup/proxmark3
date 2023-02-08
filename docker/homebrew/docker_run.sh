#!/bin/bash

docker run --volume=$(pwd)/../..:/home/linuxbrew/proxmark3 -w /home/rrg/proxmark3 -it pm3-brew:1.0
# if needed, run brew as user linuxbrew
