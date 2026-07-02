# AGENTS.md

## Cursor Cloud specific instructions

This repo is the **Proxmark3 (Iceman fork)** — firmware + host client for an RFID research
device. The cloud VM has **no physical Proxmark3 attached**, so all device I/O commands are
unavailable; develop and test against the **host client in OFFLINE mode** plus the offline
test suite.

### Build (non-obvious gotcha: use gcc, not the default clang)
- The VM's default `cc`/`c++` alternatives point to **clang**, but the client fails to build
  under clang (`-Werror` macro redefinition in `client/deps/reveng/config.h`). CI uses gcc.
  Always build with gcc:
  - Full build (firmware `bootrom`/`armsrc`/`recovery` + host `client` + tools):
    `make clean && make -j$(nproc) CC=gcc CXX=g++ LD=g++`
  - Client only: `make client -j$(nproc) CC=gcc CXX=g++ LD=g++`
- Firmware always cross-compiles with `arm-none-eabi-gcc` regardless of the `CC` setting.
- Standard build/flash/run docs: `doc/md/Use_of_Proxmark/0_Compilation-Instructions.md`.

### Test / lint
- Offline test suite (matches CI): `make check` (full) or `make client/check` (client only).
  Driven by `tools/pm3_tests.sh`. Tests marked `( slow )` are skipped by default.
- `make style` (needs `astyle`) and `make miscchecks` (needs `recode`) are the formatting/lint
  helpers; both are optional and not installed by default.

### Run (offline, no hardware)
- Interactive offline client: `client/proxmark3` (run with **no port** argument) or `./pm3 --offline`.
- Device commands like `hw status`, `hw tune`, and any tag read/write report "not available in
  this mode" — this is expected without hardware. Offline compute commands work, e.g.
  `wiegand encode/decode`, `data`/trace analysis, `hf mf` offline, key-recovery tools.
- The runtime warning `QStandardPaths: XDG_RUNTIME_DIR not set` is harmless.
