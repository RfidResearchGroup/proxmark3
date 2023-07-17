# Notes on run_tests.sh script
This script runs a bunch of different builds with make and cmake together
with the different combos of RDV4, GENERIC, BTADDON combos.

If all tests OK,  the script will finish with PASS.


# Notes to run tests
The script is to be run in proxmark root folder inside the docker env.

```
docker/debian-13-trixie/run_tests.sh;
```

Or if you want to run single test,

```
sudo apt update
make clean; make -j
python3 -m venv /tmp/venv
source /tmp/venv/bin/activate
python3 -m pip install --use-pep517 pyaes
python3 -m pip install ansicolors sslcrypto
tools/pm3_tests.sh --long
deactivate
```
