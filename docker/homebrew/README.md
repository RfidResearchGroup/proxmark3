# Notes on linux homebrew

If needed to install sth, run brew as user linuxbrew

Do not `brew install arm-none-eabi-gcc`, it's a Mach-O executable.

So only host bins can be built (except tools/hitag2crack/crack5opencl which needs OpenCL)

## Makefile

```sh
make -j client USE_BREW=1 SKIPREADLINE=1
make -j cryptorf
make -j mfc_card_only
make -j mfc_card_reader
make -j mfd_aes_brute
make -j hitag2crack SKIPOPENCL=1
make -j fpga_compress
```

## CMake

```sh
cd client
mkdir build
cd build
cmake -DEMBED_BZIP2=1 -DEMBED_LZ4=1 ..
make -j
```
