<a id="Top"></a>

# Linux Installation Instructions

# Table of Contents
- [Linux Installation Instructions](#linux-installation-instructions)
- [Table of Contents](#table-of-contents)
- [External resources](#external-resources)
- [Install the required dependencies](#install-the-required-dependencies)
  - [On Debian / Ubuntu / Kali / ParrotOS / Raspbian / DragonOS](#on-debian--ubuntu--kali--parrotos--raspbian--dragonos)
    - [If you don't need...](#if-you-dont-need)
    - [Failed to load module...](#failed-to-load-module)
  - [On ArchLinux](#on-archlinux)
    - [If you don't need...](#if-you-dont-need-1)
  - [On Fedora](#on-fedora)
    - [If you don't need...](#if-you-dont-need-2)
  - [On openSUSE Leap 15.6](#on-opensuse-leap-156)
  - [On openSUSE Tumbleweed](#on-opensuse-tumbleweed)
    - [If you don't need...](#if-you-dont-need-3)
  - [On NixOS](#on-nixos)
    - [If you don't need...](#if-you-dont-need-4)
- [Clone the repository](#clone-the-repository)
- [Check your build environment](#check-your-build-environment)
  - [Tell it which Proxmark you have](#tell-it-which-proxmark-you-have)
  - [Let it install what is missing](#let-it-install-what-is-missing)
- [Check ModemManager](#check-modemmanager)
    - [⚠️ Very important ⚠️](#️-very-important-️)
- [Check connection](#check-connection)
- [Get permissions to use /dev/ttyACM0](#get-permissions-to-use-devttyacm0)
- [Compile and use the project](#compile-and-use-the-project)



# External resources
^[Top](#top)

You might want to follow one of these external resources to get an overview, but please still read carefully this page as some instructions may have evolved.

* [Kali Video Installation guide](https://youtu.be/t5eBPS6lV3E "Kali Linux Installation Tutorial")
* [Ubuntu Video Installation guide](https://youtu.be/DThmkH8CdMo "Ubuntu Installation Tutorial")
* [ParrotOS Video Installation guide](https://youtu.be/Wl9AsrU4igo "ParrotOS Installation Tutorial")

![Linux Installation Video Screenshot](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)

* ParrotOS: some further notes can be found at @5w0rdfish repo [Proxmark Installation for Parrot OS](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS)


# Install the required dependencies
^[Top](#top)

## On Debian / Ubuntu / Kali / ParrotOS / Raspbian / DragonOS
^[Top](#top)

First what we want to do is get an update for the system. If you need to apply updates do this **before** installing the Proxmark3 software.  
An system upgrade was carried out prior to following these instructions. 

Update the packages list
```sh
sudo apt-get update
sudo apt-get upgrade -y
sudo apt-get auto-remove -y
``` 
Install the requirements

```sh
sudo apt-get install --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi libnewlib-dev qt6-base-dev \
libbz2-dev liblz4-dev zlib1g-dev libbluetooth-dev libpython3-dev libssl-dev libgd-dev
```

On recent distros such as Debian Forky, you may have a conflict between `gcc-arm-none-eabi` and `libnewlib-dev`. In this case, ignore `libnewlib-dev` in favor of `picolibc-arm-none-eabi`:

```sh
sudo apt-get install --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi picolibc-arm-none-eabi qt6-base-dev \
libbz2-dev liblz4-dev zlib1g-dev libbluetooth-dev libpython3-dev libssl-dev libgd-dev
```

If you want to compile `crack5opencl`, you will also need `opencl-dev` or, on newer distros such as Debian Forky, `ocl-icd-opencl-dev`.

### If you don't need... 
👉 If you don't need the native Bluetooth support in the client,  
you can skip the installation of `libbluetooth-dev`.

👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qt6-base-dev`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `libpython3-dev`.

👉 If you don't need support for decompressing compressed Google Smart Tap payloads in the Proxmark3 client,
you can skip the installation of `zlib1g-dev`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `libgd-dev`.

### Failed to load module... 
⚠️ If you get some (non blocking) error at runtime such as _Gtk-Message: Failed to load module "canberra-gtk-module"_  
you may have to install `libcanberra-gtk-module`.


## On ArchLinux
^[Top](#top)

```sh
sudo pacman -Syu git base-devel readline bzip2 lz4 zlib arm-none-eabi-gcc \
arm-none-eabi-newlib qt6-base bluez python gd --needed
```

If you want to compile `crack5opencl`, you will also need `ocl-icd`.

### If you don't need... 
👉 If you don't need the native Bluetooth support in the client,  
you can skip the installation of `bluez`.

👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qt6-base`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `python`.

👉 If you don't need support for decompressing compressed Google Smart Tap payloads in the Proxmark3 client,
you can skip the installation of `zlib`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `gd`.


## On Fedora
^[Top](#top)

```sh
sudo dnf install git make gcc gcc-c++ arm-none-eabi-gcc-cs arm-none-eabi-newlib \
readline-devel bzip2-devel lz4-devel zlib-ng-compat-devel qt6-qtbase-devel bluez-libs-devel \
python3-devel libatomic openssl-devel gd-devel
```

If you want to compile `crack5opencl`, you will also need `mesa-libOpenCL` and  `ocl-icd-devel`.

### If you don't need... 
👉 If you don't need the native Bluetooth support in the client,  
you can skip the installation of `bluez-libs-devel`.

👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qt6-qtbase-devel`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `python3-devel`.

👉 If you don't need support for decompressing compressed Google Smart Tap payloads in the Proxmark3 client,
you can skip the installation of `zlib-ng-compat-devel`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `gd-devel`.


## On openSUSE Leap 15.6
^[Top](#top)

```sh
sudo zypper install git patterns-devel-base-devel_basis gcc-c++ \
readline-devel libbz2-devel liblz4-devel zlib-devel \
python3-devel libqt5-qtbase-devel libopenssl-devel gd-devel
sudo zypper addrepo https://download.opensuse.org/repositories/home:wkazubski/15.6/home:wkazubski.repo && \
sudo zypper --gpg-auto-import-keys refresh && \
sudo zypper install cross-arm-none-eabi-gcc15 cross-arm-none-eabi-newlib
```

Note that Bluez is not available on openSUSE Leap so the native Bluetooth support won't be available in the client.

Note that the instructions above are for an usage with Qt5. In case of conflict with the presence of development files of Qt6, you can force Qt5 with `make SKIPQT6=1`.

It is possible to compile the proxmark3 client with Qt6 but with some caveats because the default compiler is GCC 7 and Qt6 requires at least GCC 8:
- install `gcc15 gcc15-c++` instead of `gcc-c++`
- install `qt6-core-devel qt6-widgets-devel` instead of `libqt5-qtbase-devel`
- set default compiler to GCC 15 instead of GCC 7
```
sudo update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-15 100 && \
sudo update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-15 100 && \
sudo update-alternatives --install /usr/bin/cc cc /usr/bin/gcc-15 100 && \
sudo update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-15 100
```

## On openSUSE Tumbleweed
^[Top](#top)

```sh
sudo zypper install git patterns-devel-base-devel_basis gcc-c++ \
readline-devel libbz2-devel liblz4-devel zlib-devel bluez-devel \
python3-devel qt6-core-devel qt6-widgets-devel libopenssl-devel gd-devel \
cross-arm-none-gcc12 cross-arm-none-newlib-devel
```

If you want to compile `crack5opencl`, you will also need `ocl-icd-devel`

### If you don't need... 
👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qt6-core-devel qt6-widgets-devel`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `python3-devel`.

👉 If you don't need support for decompressing compressed Google Smart Tap payloads in the Proxmark3 client,
you can skip the installation of `zlib-devel`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `gd-devel`.


## On NixOS
^[Top](#top)

While in the cloned proxmark repo, run
```sh
nix-shell tools/shell.nix
```
This will bring in all required packages to build the client and firmware with all available features.

Please note, the shell does not change device permissions, so your user must be a part of the dialout group. see [here](https://nixos.wiki/wiki/Serial_Console) for information on adding your user to that group.


### If you don't need...
👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can comment out `qt6Packages.qtbase` and  `qt6Packages.wrapQtAppsHook` in shell.nix.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can comment out `python3` in shell.nix.

👉 If you don't need support for decompressing compressed Google Smart Tap payloads in the Proxmark3 client,
you can comment out `zlib` in shell.nix.

👉 If you don't need support for NFC ePaper devices,  
you can comment out `gd` in shell.nix.

# Clone the repository
^[Top](#top)

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
cd proxmark3
```

# Check your build environment
^[Top](#top)

Before the first build, let the repo check itself over:

```sh
./configure_environment.sh
```

It reports, one line per check, whether this machine has what the project needs:

* GNU make, gcc / g++, pkg-config, git, and a `gcc` new enough for Qt6
* the `arm-none-eabi` toolchain and a linkable ARM C library, needed for the firmware
* the required client libraries (readline, bz2, lz4, libcrypto) and the optional ones
  (zlib, bluez, libpython3, Qt, libgd), each labelled with the feature it enables
* which `PLATFORM` your `Makefile.platform` selects, and whether the
  `PLATFORM_EXTRAS` tokens are valid for it
* a Python venv and the packages from `tools/requirements.txt`
* membership of the `dialout` (or `uucp`) group, the udev blacklist rule, whether
  ModemManager is running, and the access rights on `/dev/ttyACM0`
* the tracked `.dummy` files that hold the firmware object directories in git

Nothing is installed and nothing is changed, apart from the two questions below.
The last lines tell you what, if anything, is still missing, as one ready-to-paste
install command for your distribution. Exit status is 0 when the build can proceed.

`make configure` runs the same thing. Call the script directly when `make` itself
refuses to start, for instance after a typo in `PLATFORM`, since `make` stops on
that before it could run any target.

## Tell it which Proxmark you have
^[Top](#top)

Without a `Makefile.platform` every build targets a **Proxmark3 RDV4**, and that
image does not work on another board. When the file is absent the script lists the
platforms and offers to write one for your device:

```
[ warn ] no Makefile.platform, every build will be for PLATFORM=PM3RDV4
         flashing an RDV4 image to another board gives a non-working device
         PM3RDV4      Proxmark3 RDV4                                 (the default)
         PM3GENERIC   Proxmark3 RDV1, RDV2, Easy, rysccorps, clones
         PM3ICOPYX    iCopy-X and Proxmark3 Max, with PLATFORM_EXTRAS=FLASH
         PM3ULTIMATE  Proxmark3 Ultimate (XC2S50)
         PM5          Proxmark5 Iceman Edition (Artery AT32F435/437)

         Which device do you have?
           1) Proxmark3 RDV4
           2) Proxmark3 RDV4 with the Blue Shark BT add-on
           3) Proxmark3 RDV1 / RDV2 / Easy / generic clone
           4) Proxmark5 Iceman Edition
           5) Proxmark5 with the Battery Wireless Mod
           6) iCopy-X or Proxmark3 Max
           7) Proxmark3 Ultimate
           0) skip, I will write Makefile.platform myself
```

Answer `0` and copy `Makefile.platform.sample` yourself if you want the standalone
mode, the 256KB options or anything else it does not ask about. An existing
`Makefile.platform` is never overwritten, only checked.

If you already have one, the script confirms what it resolves to and catches the
combinations the firmware build rejects later on, such as `PLATFORM_EXTRAS=BWM`
on anything other than `PLATFORM=PM5`.

## Let it install what is missing
^[Top](#top)

```sh
./configure_environment.sh --install
```

This asks before each step, then installs the missing system packages with
`apt-get` / `pacman` / `dnf` / `zypper`, creates the Python venv and installs
`tools/requirements.txt` into it. Add `-y` to skip the questions, `--extras` to
also consider the optional requirement files under `fpga/`, `tools/ePassport/`
and `tools/btaddon/`, and `--help` for the rest.

On NixOS, use `nix-shell tools/shell.nix` instead; the script says so.

# Check ModemManager
^[Top](#top)

### ⚠️ Very important ⚠️
^[Top](#top)

make sure ModemManager will not interfere, otherwise it could brick your Proxmark3!
Read carefully [this page about ModemManager](ModemManager-Must-Be-Discarded.md) and follow its instructions.

# Check connection
^[Top](#top)

Check the proxmark is being picked up by your computer. Plug it in, then:

```sh
sudo dmesg | grep -i usb
```
It should show up as a CDC device:
```
usb 2-1.2: Product: PM3
usb 2-1.2: Manufacturer: proxmark.org
cdc_acm 2-1.2:1.0: ttyACM0: USB ACM device
```
And a new `/dev/ttyACM0` should have appeared.

# Get permissions to use /dev/ttyACM0
^[Top](#top)

Add current user to the proper groups to get permission to use `/dev/ttyACM0`.

This step can be done from the Iceman Proxmark3 repo with:

```sh
make accessrights
```

Then, you *need* to logout and login in again for your new group membership to be fully effective.

To test you have the proper read & write rights, plug the Proxmark3 and execute:
```sh
[ -r /dev/ttyACM0 ] && [ -w /dev/ttyACM0 ] && echo ok
```
It must return `ok`. Otherwise this means you've got a permission problem to fix.

# Compile and use the project
^[Top](#top)

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).
