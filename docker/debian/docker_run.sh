#!/bin/bash

docker run --volume=$(pwd)/../..:/home/rrg/proxmark3 -it pm3-debian:1.0
