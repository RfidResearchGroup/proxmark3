# Makefile vs CMake

## Client

The client can be compiled both with the historical Makefile and with a newer CMakeLists.txt.
At the moment both are maintained because they don't perfectly overlap yet.

* *in_common*: src in /common
* *in_deps*: src in /client/deps
* *opt*: optional dependency
* *pc*: use pkg-config
* *sys*: system library

| Feature | Makefile | CMake | Remarks |
|-----|---|---|---|
| verbose | V=1 | VERBOSE=1 |   |
| warnings management | yes (1) | **no** | (1) cf Makefile.defs |
| compilation | in place | in build dir (1) | |
| user `CFLAGS`/`LDFLAGS` | honored (1) | **no/auto?** | (1) also `LDLIBS` and `INCLUDES_CLIENT` as envvars for more tuning |
| `PKG_CONFIG_ENV` | yes | **no/auto?** | |
| Mingw gnu printf | `_ISOC99_SOURCE` | `_ISOC99_SOURCE` | |
| C++ | c++11 | gnu++14 | |
| dep amiibo | in_deps | in_deps |   |
| dep atomic | sys, for RPiZ | sys, for RPiZ | `-Wl,--as-needed -latomic -Wl,--no-as-needed` unless OSX |
| atomic detection | **none** | **none** | |
| dep bluez | opt, sys | opt, sys |  |
| bluez detection | pc | pkg_search_module |   |
| `SKIPBT` | yes | yes |   |
| dep bzip2 | sys | sys |   |
| bzip2 detection | **none** | **none**, Android:gitclone | |
| dep cliparser | in_deps | in_deps |   |
| dep hardnested | in_deps | in_deps |   |
| arch autodetection | (1) | (2) | (1) uname -m == 86|amd64; gcc -E -mavx512f? +-AVX512 (2) CMAKE_SYSTEM_PROCESSOR == x86|x86_64|i686|AMD64 (always incl. AVX512) |
| `cpu_arch` | yes | **no/auto?** | e.g. cpu_arch=generic for cross-compilation
| dep jansson | sys / in_deps | **in_deps only** |   |
| jansson detection | pc | **none** |   |
| `SKIPJANSSONSYSTEM` | yes | **no** |   |
| dep lua | sys / in_deps(1) | **in_deps only**(2) | (1) manual def of `LUAPLATFORM` for mingw/macosx/linux (2) manual, different?, for Android too |
| lua detection | pc | **none** |   |
| `SKIPLUASYSTEM` | yes | **no** |   |
| lualibs/pm3_cmd.lua | yes | **add_custom_command used?** |
| lualibs/mfc_default_keys.lua | yes | **add_custom_command used?** |
| dep lz4 |  |  | (common) not yet used, future |
| dep libm | sys | sys | |
| libm detection | none | **none/auto?** | |
| dep mbedtls | in_common | in_common | no sys lib: missing support for CMAC in def conf (btw no .pc available) |
| dep python3 | opt, sys, <3.8 & 3.8 | opt, sys, <3.8 & 3.8 |   |
| python3 detection | pc | pkg_search_module | |
| `SKIPPYTHON`  | yes | yes |   |
| dep pthread | sys | sys |  |
| pthread detection | **none** | **none** |   |
| `SKIPPTHREAD` | yes | yes | e.g. for termux |
| dep Qt | opt, sys, Qt5 & Qt4 | opt, sys, Qt5 |  |
| Qt detection | pc(qt5)/pc(qt4)/`QTDIR`(1) (2) | find_package(qt5) (3) | (1) if `QTDIR`: hardcode path (2) OSX: pkg-config hook for Brew (3) OSX: add search path|
| `SKIPQT` | yes | yes | |
| dep readline | sys  | sys |  |
| readline detection | **none** (1) | find*(2), Android:getzip | (1) OSX: hardcoded path (2) additional paths for OSX |
| `SKIPREADLINE` | yes | yes | CLI not fully functional without Readline |
| dep reveng | in_deps | in_deps | |
| `SKIPREVENGTEST` | yes(1) | **no**(2) | (1) e.g. if cross-compilation (2) tests aren't compiled/ran with cmake |
| dep tinycbor | in_deps | in_deps |   |
| dep whereami | sys / in_deps | **in_deps only** |   |
| whereami detection | **search /usr/include/whereami.h** | **none** | no .pc available |
| `SKIPWHEREAMISYSTEM` | yes | **no** |   |
| version | mkversion | mkversion | |
| install | yes (1) | **no** | (1) supports `DESTDIR`, `PREFIX`, `UDEV_PREFIX`. Installs resources as well, `INSTALL*RELPATH` |
| deb | no | partial? | |
| tarbin | yes, unused? | no | |
| Android cross- | **no** | yes | |
| SWIG Lua+Python embedded | **no** | *ongoing* | cf libpm3_experiments branch |
| libpm3 with SWIG Lua+Python| **no** | *ongoing* | cf libpm3_experiments branch |

## Tools

`makefile` only at the moment

`SKIPGPU`

## ARM

`makefile` only at the moment

`PLATFORM`, `PLATFORM_EXTRAS`, `DESTDIR`, `PREFIX`, `FWTAG`

## Global

`makefile` only at the moment
