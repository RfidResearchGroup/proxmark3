#!/bin/bash

docker run --volume=$(pwd)/../..:/home/rrg/proxmark3 -w /home/rrg/proxmark3 -it pm3-debian-bullseye:1.0
