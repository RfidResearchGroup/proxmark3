# Notes on run_tests.sh script
This script does both strip the "recover_pk test" in pm3_tests.sh and then run a 
bunch of different builds with make and cmake together with the different combos 
of RDV4, GENERIC, BTADDON combos. 

If all tests OK,  the script will finish.


# Notes to run tests
The script is to be run in proxmark root folder inside the docker env.

```
docker/fedora-35/run_tests.sh;
``` 

Or if you want to run single test,  

```
sudo yum -y update
make clean; make -j
tools/pm3_tests.sh --long
```

Warning, `recover_pk selftests` will fail on Fedora because they stripped down the available ECC curves in their OpenSSL.

So just comment the "recover_pk test"
