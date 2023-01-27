#!/bin/bash

docker run --volume=$(pwd)/../..:/home/rrg/proxmark3 -w /home/rrg/proxmark3 -it pm3-fedora-36:1.0
