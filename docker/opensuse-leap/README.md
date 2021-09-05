# Notes to run tests

No ARM compiler available ?

```
sudo zypper --non-interactive install cmake
sudo zypper --non-interactive install python3
sudo zypper --non-interactive install python3-pip
python3 -m pip install ansicolors sslcrypto
tools/pm3_tests.sh --long mfkey nonce2key mf_nonce_brute fpga_compress common client
```
