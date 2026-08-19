# kgh_tools Build Notes

## Configure And Build

Do this in ProxSpace:

```bash
cd ~/proxmark3_rfrg/client/experimental_lib
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

## Static Link Notes

- `kgh_tools` is linked against `pm3rrg_rdv4_static`.
- On MinGW, CMake adds `-static -static-libgcc` for the target.
- If CMakeCache paths change between ProxSpace and a native shell, delete `build-lite` and reconfigure.

## Existing Helper Scripts

- `01make_lib.sh` creates `build/`, runs `cmake ..`, then `make -j`.
- `01make_lib_continue.sh` reruns `make -j` in `build/`.
- `00make_swig.sh` regenerates the SWIG wrappers before building the library.
