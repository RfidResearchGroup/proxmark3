#!/bin/bash

docker run --volume=$(pwd)/../..:/home/rrg/proxmark3 -it pm3-kali:1.0
