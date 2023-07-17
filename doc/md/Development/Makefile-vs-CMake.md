# Makefile vs CMake
<a id="Top"></a>


# Table of Contents
- [Makefile vs CMake](#makefile-vs-cmake)
- [Table of Contents](#table-of-contents)
  - [Client](#client)
  - [Tools](#tools)
  - [ARM](#arm)
    - [Features to be used via `Makefile.platform`](#features-to-be-used-via-makefileplatform)
    - [Other features](#other-features)
  - [Global](#global)
  


## Client
^[Top](#top)

The client can be compiled both with the historical Makefile and with a newer CMakeLists.txt.
At the moment both are maintained because they don't perfectly overlap yet.

* *in_common*: src in /common
* *in_deps*: src in /client/deps
* *opt*: optional dependency
* *pc*: use pkg-config
* *sys*: system library

| Feature | Makefile | CMake | Remarks |
|-----|---|---|---|
| verbose | `V=1` | `VERBOSE=1` |   |
| debug build | `DEBUG=1` | `-DCMAKE_BUILD_TYPE=Debug` | client only |
| warnings management | yes (1) | **no** | (1) cf Makefile.defs |
| extra GCC warnings | `GCCEXTRA=1` | **no** |   |
| extra Clang warnings | `CLANGEXTRA=1` | **no** | only on host |
| AddressSanitize | `SANITIZE=1` | **no** | only on host |
| compilation | in place | in build dir | |
| user `CFLAGS`/`LDFLAGS` | envvars honored (1) | envvars honored (2) | (1) also `LDLIBS` and `INCLUDES_CLIENT` for more tuning (2) only at first cmake call |
| Mingw gnu printf | `_ISOC99_SOURCE` | `_ISOC99_SOURCE` | and in cbor.h: `__attribute__((format (__MINGW_PRINTF_FORMAT, 2, 3)))`|
| C++ | c++11 | gnu++14 | |
| dep amiibo | in_deps | in_deps |   |
| dep atomic | sys, for RPiZ | sys, for RPiZ | `-Wl,--as-needed -latomic -Wl,--no-as-needed` unless OSX |
| atomic detection | **none** | **none** | |
| dep bluez | opt, sys | opt, sys |  |
| bluez detection | pc | pkg_search_module |   |
| `SKIPBT` | yes | yes |   |
| dep bzip2 | sys | sys |   |
| bzip2 detection | **none** | find_package, Cross:gitclone | |
| dep cliparser | in_deps | in_deps |   |
| dep hardnested | in_deps | in_deps |   |
| hardn arch autodetect | `uname -m` =? 86 or amd64; `$(CC) -E -mavx512f`? +`AVX512` |  `CMAKE_SYSTEM_PROCESSOR` =? x86 or x86_64 or i686 or AMD64 (1) | (1) currently it always includes AVX512 on Intel arch |
| `cpu_arch` | yes | **no/auto?** | e.g. `cpu_arch=generic` for cross-compilation
| dep jansson | sys / in_deps | sys / in_deps |   |
| jansson detection | pc | pc/find* |   |
| `SKIPJANSSONSYSTEM` | yes | yes |   |
| dep lua | sys / in_deps(1) | **in_deps only**(2) | (1) manual def of `LUAPLATFORM` for mingw/macosx/linux (2) manual, different?, for Android too |
| lua detection | pc | **none** |   |
| `SKIPLUASYSTEM` | yes | **no** |   |
| lualibs/pm3_cmd.lua | yes | add_custom_command **but unused** | |
| lualibs/mfc_default_keys.lua | yes | add_custom_command **but unused** | |
| dep lz4 | sys | sys | + in_common only used by FW. See `get_lz4.sh` for upstream fetch & patch |
| lz4 detection | **none** | find, Cross:gitclone | |
| dep libm | sys | sys | |
| libm detection | **none** | **none** (1) | (1) cf https://cmake.org/pipermail/cmake/2019-March/069168.html ? |
| dep mbedtls | in_common | in_common | no sys lib: missing support for CMAC in def conf (btw no .pc available) |
| dep python3 | opt, sys, < 3.8 & 3.8 | opt, sys, < 3.8 & 3.8 |   |
| python3 detection | pc | pkg_search_module | |
| `SKIPPYTHON`  | yes | yes |   |
| dep pthread | sys | sys |  |
| pthread detection | **none** | **none** (1) | (1) cf https://stackoverflow.com/questions/1620918/cmake-and-libpthread ? |
| `SKIPPTHREAD` | yes | yes | e.g. for termux |
| dep Qt | opt, sys, Qt5 & Qt4 | opt, sys, Qt5 |  |
| Qt detection | pc(qt5)/pc(qt4)/`QTDIR`(1) (2) | find_package(qt5) (3) | (1) if `QTDIR`: hardcode path (2) OSX: pkg-config hook for Brew (3) OSX: add search path|
| `SKIPQT` | yes | yes | |
| dep readline | sys  | sys |  |
| readline detection | **none** (1) | find*(2), Cross:getzip | (1) OSX: hardcoded path (2) additional paths for OSX |
| `SKIPREADLINE` | yes | yes | CLI not fully functional without Readline |
| `SKIPLINENOISE` | yes | yes | replacement of Readline, not as complete |
| dep reveng | in_deps | in_deps | |
| `SKIPREVENGTEST` | yes(1) | **no**(2) | (1) e.g. if cross-compilation (2) tests aren't compiled/ran with cmake |
| dep tinycbor | in_deps | in_deps |   |
| dep whereami | sys / in_deps | sys / in_deps |   |
| whereami detection | **search /usr/include/whereami.h** | find* | no .pc available |
| `SKIPWHEREAMISYSTEM` | yes | yes |   |
| version | mkversion | mkversion | |
| install | yes (1) | **no** | (1) supports `DESTDIR`, `PREFIX`, `UDEV_PREFIX`. Installs resources as well, `INSTALL*RELPATH` |
| deb | no | partial? | |
| tarbin | yes, unused? | no | |
| Android cross- | **no** | yes | |
| SWIG Lua+Python embedded | **no** | *ongoing* | cf libpm3_experiments branch |
| libpm3 with SWIG Lua+Python| **no** | *ongoing* | cf libpm3_experiments branch |

## Tools
^[Top](#top)

`makefile` only at the moment

| Feature | Makefile | Remarks |
|-----|---|---|
| Skip OpenCL-dependent code | `SKIPOPENCL=1` | to skip ht2crack5opencl tool when compiling the hitag2crack toolsuite |

## ARM
^[Top](#top)

`makefile` only at the moment

### Features to be used via `Makefile.platform`
^[Top](#top)

`SKIP_*`, `STANDALONE`

| Feature | Makefile | Remarks |
|-----|---|---|
| Platform choice | `PLATFORM=` | values: `PM3RDV4`, `PM3GENERIC`, `PM3ICOPYX` |
| Platform size | `PLATFORM_SIZE=` | values: `256`, `512` |
| Platform extras | `PLATFORM_EXTRAS=` | values: `BTADDON`, `FPC_USART_DEV` |
| Skip LF/HF techs in the firmware | `SKIP_`*`=1` | see `common_arm/Makefile.hal` for a list |
| Standalone mode choice | `STANDALONE=` | see `doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md` for a list |

### Other features
^[Top](#top)

| Feature | Makefile | Remarks |
|-----|---|---|
| ARM debug build | `DEBUG_ARM=1` | to be used with JLink and VSCode |
| Install dest dir | `DESTDIR=` | for maintainers |
| Install prefix dir | `PREFIX=` | for maintainers |
| Tag firmware image | `FWTAG=` | for maintainers |

## Global
^[Top](#top)

`makefile` only at the moment
