# legic_kgh_tool

## Running

`legic_kgh_tool` reads KGH LEGIC card information, badge numbers, and stamps,
and writes the supported KGH card layout.

Examples:

```bash
./legic_kgh_tool COM13 read_badge_number
./legic_kgh_tool COM13 read_info
./legic_kgh_tool COM13 read_stamp
./legic_kgh_tool COM13 read_stamp -o stamp.bin
./legic_kgh_tool COM13 write_card 600001 --stamp-file stamp.bin
```

Commands:

- `read_badge_number` prints the badge number only.
- `read_info` prints one-line JSON.
- `read_stamp` prints the stamp as 8 hex chars, or writes raw 4 bytes with `-o/--output-file`.
- `write_card <badge> (--stamp-file <path> | --stamp-hex <8hex>)` writes the supported KGH layout.

Notes:

- Windows ProxSpace examples use `COM13`.
- The stamp is 4 bytes and specific to your site.
  It can be specified as a `.bin` file or as `--stamp-hex` (for example, `003EF417`).
- You can retrieve the stamp from a supported KGH card with `read_info` or `read_stamp`.
- Linux examples usually use `/dev/ttyACM0` or similar.
- `--verbose` can be useful for `read_badge_number` and `write_card`, if they fail for mysterious reasons.

## Building in ProxSpace (for Windows)

Do this in ProxSpace:

```bash
cd ~/proxmark3/tools/kgh
rm -rf build-lite
cmake -G "MSYS Makefiles" -S . -B build-lite \
  -DSKIPPYTHON=1 \
  -DSKIPREADLINE=1 \
  -DSKIPJANSSONSYSTEM=1 \
  -DSKIPWHEREAMISYSTEM=1 \
  -DSKIPBT=1
cmake --build build-lite --target legic_kgh_tool -j
objdump -p build-lite/legic_kgh_tool.exe | grep -i "DLL Name"
```

## Building Linux

```bash
cd tools/kgh
rm -rf build-linux
cmake -S . -B build-linux \
  -DSKIPPYTHON=1 \
  -DSKIPREADLINE=1 \
  -DSKIPJANSSONSYSTEM=1 \
  -DSKIPWHEREAMISYSTEM=1 \
  -DSKIPBT=1
cmake --build build-linux --target legic_kgh_tool -j
ldd build-linux/legic_kgh_tool
```

## Static Link Notes

- `legic_kgh_tool` is linked against `pm3rrg_rdv4_static`.
- On MinGW, CMake adds `-static -static-libgcc` for the target.
- Linux builds are not the same as the ProxSpace single-EXE deployment.
- If CMakeCache paths change between ProxSpace and a native shell, delete the build dir and reconfigure.
