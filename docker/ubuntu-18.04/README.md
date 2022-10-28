# Notes on run_tests.sh script
This script does both setup the mirrors and pip install and then run a 
bunch of different builds with make and cmake together with the different combos 
of RDV4, GENERIC, BTADDON combos. 

If all tests OK,  the script will finish.


# Notes to run tests
The script is to be run in proxmark root folder inside the docker env.

```
docker/ubuntu-18.04/run_tests.sh;
``` 

Or if you want to run single test,  

```
sudo apt update
make clean; make -j
tools/pm3_tests.sh --long
```
