# Notes on run_tests.sh script
This script does both setup and then run a 
bunch of different builds with make and cmake together with the different combos 
of RDV4, GENERIC, BTADDON combos. 

If all tests OK,  the script will finish.


# Notes to run tests
The script is to be run in proxmark root folder inside the docker env.

```
docker/opensuse-leap/run_tests.sh;
``` 

Or if you want to run single test,  

```
make clean; make -j
tools/pm3_tests.sh --long mfkey nonce2key mf_nonce_brute fpga_compress common client
```


No ARM compiler available ?
