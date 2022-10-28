# Notes to run tests

No ARM compiler available ?

```
make clean; make -j
tools/pm3_tests.sh --long mfkey nonce2key mf_nonce_brute fpga_compress common client
```
