# kgh_tools

## Running

`kgh_tools` is a small CLI wrapper around the LEGIC migration helpers.

Examples:

```bash
./kgh_tools COM13 read_badge_number
./kgh_tools COM13 read_info
./kgh_tools COM13 read_stamp
./kgh_tools COM13 read_stamp -o stamp.bin
./kgh_tools COM13 write_card 600001 --stamp-file stamp.bin
```

Commands:

- `read_badge_number` prints the badge number only.
- `read_info` prints one-line JSON.
- `read_stamp` prints the stamp as 8 hex chars, or writes raw 4 bytes with `-o/--output-file`.
- `write_card <badge> (--stamp-file <path> | --stamp-hex <8hex>)` writes the card.

Notes:

- Windows ProxSpace examples use `COM13`.
- The stamp is 4 bytes and specific to your site.
    It can be specified as a .bin (use .e.g hexedit to create it)
    Or as a command-line option (less secure) as --stamp-hex (e.g.) 003EF417
   You can find the stamp on any card in use at your site by using read_info (see above)
- Linux examples usually use `/dev/ttyACM0` or similar.
- `--verbose` can be useful for `read_badge_number` and `write_card`, if they fail for mysterious reasons.

## Building in ProxSpace (for Windows)

Do this in ProxSpace:

```bash
cd ~/proxmark3/client/experimental_lib
rm -rf build-lite
cmake -G "MSYS Makefiles" -S . -B build-lite \
  -DSKIPPYTHON=1 \
  -DSKIPREADLINE=1 \
  -DSKIPJANSSYSTEM=1 \
  -DSKIPWHEREAMISYSTEM=1 \
  -DSKIPBT=1
cmake --build build-lite --target kgh_tools -j
objdump -p build-lite/kgh_tools.exe | grep -i "DLL Name"
```

## Building Linux

```bash
cd client/experimental_lib
rm -rf build-linux
cmake -S . -B build-linux \
  -DSKIPPYTHON=1 \
  -DSKIPREADLINE=1 \
  -DSKIPJANSSYSTEM=1 \
  -DSKIPWHEREAMISYSTEM=1 \
  -DSKIPBT=1
cmake --build build-linux --target kgh_tools -j
ldd build-linux/kgh_tools
```

## Static Link Notes

- `kgh_tools` is linked against `pm3rrg_rdv4_static`.
- On MinGW, CMake adds `-static -static-libgcc` for the target.
- Linux builds are not the same as the ProxSpace single-EXE deployment.
- If CMakeCache paths change between ProxSpace and a native shell, delete the build dir and reconfigure.

## Existing Helper Scripts

- `01make_lib.sh` creates `build/`, runs `cmake ..`, then `make -j`.
- `01make_lib_continue.sh` reruns `make -j` in `build/`.
- `00make_swig.sh` regenerates the SWIG wrappers before building the library.
