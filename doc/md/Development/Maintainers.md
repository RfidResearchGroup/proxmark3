# Hi maintainers!

Here are some tips how to integrate this repo in some nice package for your distro.
Feel free to contact us via Github issues for any question, suggestion or if you want to share useful tricks in this file for other maintainers.

Makefile
========

`PREFIX` and `UDEV_PREFIX` can be provided by environment variable, else it defaults to `/usr/local/share` and `/etc/udev/rules.d`.

`DESTDIR` can be provided by environment variable, it can be a relative path and it will be prepended to `PREFIX`, so you can use e.g.:

```
make -j
make install DESTDIR=build PREFIX=/usr UDEV_PREFIX=/lib/udev/rules.d
```

and it will be deployed as

```
./build/lib/udev/rules.d/77-pm3-usb-device-blacklist.rules
./build/usr/bin/proxmark3 ...
./build/usr/share/doc/proxmark3/...
./build/usr/share/proxmark3/firmware/fullimage.elf
etc.
```

That should be a good start for you to create your package :)

It's possible to add other firmwares as well with tagged names (`FWTAG=<mytag>`), e.g. here we're compiling another image for non-RDV4 devices:

```
make -j fullimage PLATFORM=PM3OTHER PLATFORM_EXTRAS=
make fullimage/install PLATFORM=PM3OTHER PLATFORM_EXTRAS= DESTDIR=build PREFIX=/usr FWTAG=other
```

and it will be added along the other firmware as:

```
./build/usr/share/proxmark3/firmware/fullimage-other.elf
```

For verbose usage and see the actual commands being executed, add `V=1`.

`CFLAGS` and `LDFLAGS` can be overriden by environment variables.

Default compiler is gcc but you can use clang for the non-ARM parts with e.g. `make client CC=clang CXX=clang++ LD=clang++`.

`make install` is actually triggering the following individual targets which can be accessed individually:

* `make client/install`
* `make bootrom/install`
* `make fullimage/install` (alias of `make armsrc/install`)
* `make recovery/install`
* `make mfkey/install`
* `make nonce2key/install`
* `make fpga_compress/install` (dummy)
* `make common/install` (some shared content installation:)
  * `pm3-*` scripts
  * `tools/jtag_openocd`, `traces`
  * `doc/md`, `doc/*.md`
  * Tools scripts (`pm3_eml2lower.sh` etc)
  * SIM firmware (beware currently it's binary blob, may break your distro policies on open source)
  * udev rule on Linux

Same logic for `make all`, `make clean`, `make uninstall`
