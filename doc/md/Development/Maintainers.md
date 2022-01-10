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

If you need to tune some more paths, see their definition in `Makefile.defs`.
E.g. you might need to move the documentation elsewhere according to your distro policy:

```
make install PREFIX=/usr INSTALLDOCSRELPATH=share/doc/proxmark3-${version}
```

It's possible to add other firmwares as well with tagged names (`FWTAG=<mytag>`), e.g. here we're compiling another image for generic Proxmark3 devices:

```
make -j fullimage PLATFORM=PM3GENERIC PLATFORM_EXTRAS=
make fullimage/install PLATFORM=PM3GENERIC PLATFORM_EXTRAS= DESTDIR=build PREFIX=/usr FWTAG=generic
```

and it will be added along the other firmwares as:

```
./build/usr/share/proxmark3/firmware/fullimage-generic.elf
```

For verbose usage and see the actual commands being executed, add `V=1`.

`CFLAGS` and `LDFLAGS` can be overridden by environment variables for client-side components.

Default compiler is gcc but you can use clang for the non-ARM parts with e.g. `make client CC=clang CXX=clang++ LD=clang++`. Note that `CC`, `CXX` and `LD` must be provided as explicit arguments, they won't be overridden by environment variables.

Similarly, for ARM-side components, `CROSS_CFLAGS` and `CROSS_LDFLAGS` can be overridden by environment variables and `CROSS_CC`, `CROSS_LD` and `CROSS_OBJCOPY` can be provided as explicit arguments.

If your platform needs specific lib/include paths for the client, you can use `LDLIBS` and `INCLUDES_CLIENT` *as envvars*, e.g. `LDLIBS="-L/some/more/lib" INCLUDES_CLIENT="-I/some/more/include" make client ...`

It's also possible to skip parts even if libraries are present in the compilation environment:

* `make client SKIPQT=1` to skip GUI even if Qt is present
* `make client SKIPBT=1` to skip native Bluetooth support even if libbluetooth is present
* `make client SKIPPYTHON=1` to skip embedded Python 3 interpreter even if libpython3 is present
* `make client SKIPLUASYSTEM=1` to skip system Lua lib even if liblua5.2 is present, use embedded Lua lib instead
* `make client SKIPJANSSONSYSTEM=1` to skip system Jansson lib even if libjansson is present, use embedded Jansson lib instead
* `make client SKIPWHEREAMISYSTEM=1` to skip system Whereami lib even if libwhereami is present, use embedded whereami lib instead

By default, the client is using Readline, but this can be disabled:
* `make client SKIPREADLINE=1` to skip system Readline lib even if libreadline is present

When Readline is disabled, it is possible to use Linenoise instead. Note that Linenoise-ng contains `ConvertUTF.cpp` which is under a redistribution-only license, therefore think twice before including it in a release. To get Linenoise-ng, see `client/deps/get_linenoise.sh`.

If you're cross-compiling, these ones might be useful:

* `make client SKIPREVENGTEST=1` to skip compilation and execution of a consistency test for reveng, which can be problematic in case of cross-compilation
* `make client cpu_arch=generic` to skip Intel specialized hardnested components, which is required e.g. if cross-compilation host is Intel but not the target

On some architectures, pthread library is not present:

* `make client SKIPPTHREAD=1` to skip `-lpthread` at linker stage.

One tool requires a CUDA compilation environment, it can be skipped as well:

* `make hitag2crack SKIPOPENCL=1` to skip ht2crack5opencl tool when compiling the hitag2crack toolsuite.

Some unittests are available via `make check`, which is actually triggering individual targets as for `make install`.

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
  * SIM firmware
  * udev rule on Linux

Same logic for `make all`, `make clean`, `make uninstall` and `make check`.
