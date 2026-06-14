# Notes on run_tests.sh script
This script runs a bunch of different builds with make and cmake together
with the different combos of RDV4, GENERIC, BTADDON combos.

If all tests OK,  the script will finish with PASS.

# Notes to run tests
The script is to be run in proxmark root folder inside the docker env.

```
docker/opensuse-tumbleweed/run_tests.sh;
```

Or if you want to run single test,

```
sudo zypper refresh && sudo zypper --non-interactive update
make clean; make -j
tools/pm3_tests.sh --long
```
