# Building Proxmark3 on Windows without ProxSpace

Three approaches for building outside the ProxSpace MSYS2 shell.

## Option 1: PowerShell + ProxSpace toolchain (recommended)

Use the `Build-Proxmark3.ps1` wrapper from [ProxSpace](https://github.com/Gator96100/ProxSpace):

```powershell
cd C:\ProxSpace
.\Build-Proxmark3.ps1                     # build all
.\Build-Proxmark3.ps1 -Flash -Port COM5   # build + flash
.\Build-Proxmark3.ps1 -Target client      # client only
```

The wrapper sets `TMP`, `TEMP`, `CC`, `CXX`, `MINGW_HOME` to avoid the `/tmp` path translation bug that causes `Cannot create temporary file in C:\WINDOWS\` linker errors when building from git-bash.

### Manual PowerShell build (without wrapper)

```powershell
$env:TEMP = 'C:\ProxSpace\msys2\tmp'
$env:TMP  = 'C:\ProxSpace\msys2\tmp'
$env:PATH = 'C:\ProxSpace\msys2\mingw64\bin;C:\ProxSpace\msys2\usr\bin;' + $env:PATH
$env:MSYSTEM = 'MINGW64'
New-Item -ItemType Directory -Force -Path 'C:\ProxSpace\msys2\tmp'

& 'C:\ProxSpace\msys2\usr\bin\make.exe' -C 'C:\ProxSpace\pm3' bootrom/all
& 'C:\ProxSpace\msys2\usr\bin\make.exe' -C 'C:\ProxSpace\pm3' armsrc/all
& 'C:\ProxSpace\msys2\usr\bin\make.exe' -C 'C:\ProxSpace\pm3' SKIPREVENGTEST=1 client
```

## Option 2: WSL2 (Windows Subsystem for Linux)

Treat it as a standard Linux build. From a WSL2 Ubuntu terminal:

```bash
# Install dependencies
bash setup-ubuntu.sh

# Build
make clean && make -j$(nproc)

# Flash — use the Windows COM port path
./client/proxmark3 /dev/ttyS4 --flash --unlock-bootloader --image bootrom/obj/bootrom.elf
./client/proxmark3 /dev/ttyS4 --flash --image armsrc/obj/fullimage.elf
```

Note: WSL2 COM port mapping is `/dev/ttySN` where N is the Windows COM port number.

## Option 3: Native MSYS2 (without ProxSpace)

Install MSYS2 from https://www.msys2.org/ and add the required packages:

```bash
pacman -S --needed \
    mingw-w64-x86_64-gcc \
    mingw-w64-x86_64-arm-none-eabi-gcc \
    mingw-w64-x86_64-arm-none-eabi-newlib \
    mingw-w64-x86_64-qt6-base \
    mingw-w64-x86_64-readline \
    mingw-w64-x86_64-lua \
    mingw-w64-x86_64-jansson \
    mingw-w64-x86_64-bzip2 \
    mingw-w64-x86_64-lz4 \
    mingw-w64-x86_64-python \
    make git pkg-config

cd /c/path/to/proxmark3
make clean && make -j$(nproc)
```

This approach uses a standard MSYS2 installation rather than ProxSpace's bundled snapshot, so packages are always up to date.

## Flash procedure (all options)

Always flash bootrom first, then fullimage:

```bash
./pm3-flash-bootrom
./pm3-flash-fullimage
./pm3
hw version
```

Note: The COM port may change after flashing the bootloader. Re-check with:
```powershell
Get-PnpDevice -Class 'Ports' -Status OK
```
