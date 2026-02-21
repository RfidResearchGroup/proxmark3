# Termux release tests

Not Docker but part of the release tests...

## SSH

`sshd` => runs on port 8022

## Setup

```
pkg install make clang readline libc++ git binutils libgd
pip install sslcrypto ansicolors
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

## Update

```
pkg upgrade
cd proxmark3
git pull
```

## Tests

```
cd proxmark3
make -j host
tools/pm3_tests.sh --long mfkey nonce2key mf_nonce_brute staticnested mfd_aes_brute mfulc_des_brute cryptorf fpga_compress client common
make -j hitag2crack/crack2/all
make -j hitag2crack/crack3/all
make -j hitag2crack/crack4/all
make -j hitag2crack/crack5/all
tools/pm3_tests.sh --long hitag2crack
```
