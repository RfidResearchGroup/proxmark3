# Notes on run_tests.sh script
This script setups the mirrors and then runs a bunch of different builds with make
and cmake together with the different combos of RDV4, GENERIC, BTADDON 

If all tests OK,  the script will finish with PASS.


# Notes to run tests

The release test build script is to be run in proxmark root folder inside the docker env.
```
docker/archlinux/run_tests.sh;
```

Or if you want to run single test,

```
make clean; make -j

tools/pm3_tests.sh --long
```
