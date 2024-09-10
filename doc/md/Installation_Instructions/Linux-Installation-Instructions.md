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
- [Clone the repository](#clone-the-repository)
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
libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev \
libbz2-dev liblz4-dev libbluetooth-dev libpython3-dev libssl-dev libgd-dev
```

### If you don't need... 
👉 If you don't need the native Bluetooth support in the client,  
you can skip the installation of `libbluetooth-dev`.

👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qtbase5-dev`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `libpython3-dev`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `libgd-dev`.

### Failed to load module... 
⚠️ If you get some (non blocking) error at runtime such as _Gtk-Message: Failed to load module "canberra-gtk-module"_  
you may have to install `libcanberra-gtk-module`.


## On ArchLinux
^[Top](#top)

```sh
sudo pacman -Syu git base-devel readline bzip2 lz4 arm-none-eabi-gcc \
arm-none-eabi-newlib qt5-base bluez python gd --needed
```

### If you don't need... 
👉 If you don't need the native Bluetooth support in the client,  
you can skip the installation of `bluez`.

👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qt5-base`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `python`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `gd`.


## On Fedora
^[Top](#top)

```sh
sudo dnf install git make gcc gcc-c++ arm-none-eabi-gcc-cs arm-none-eabi-newlib \
readline-devel bzip2-devel lz4-devel qt5-qtbase-devel bluez-libs-devel \
python3-devel libatomic openssl-devel gd-devel
```

### If you don't need... 
👉 If you don't need the native Bluetooth support in the client,  
you can skip the installation of `bluez-libs-devel`.

👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `qt5-qtbase-devel`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `python3-devel`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `gd-devel`.


## On openSUSE Leap 15.6
^[Top](#top)

```sh
sudo zypper install git patterns-devel-base-devel_basis gcc-c++ \
readline-devel libbz2-devel liblz4-devel \
python3-devel libqt5-qtbase-devel libopenssl-devel gd-devel
sudo zypper addrepo https://download.opensuse.org/repositories/home:wkazubski/15.6/home:wkazubski.repo && \
sudo zypper --gpg-auto-import-keys refresh && \
sudo zypper install cross-arm-none-eabi-gcc13 cross-arm-none-eabi-newlib
```

Note that Bluez is not available on openSUSE so the native Bluetooth support won't be available in the client.

## On openSUSE Tumbleweed
^[Top](#top)

```sh
sudo zypper install git patterns-devel-base-devel_basis gcc-c++ \
readline-devel libbz2-devel liblz4-devel bluez-devel \
python3-devel libqt5-qtbase-devel libopenssl-devel gd-devel \
cross-arm-none-gcc12 cross-arm-none-newlib-devel
```

### If you don't need... 
👉 If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`),  
you can skip the installation of `libqt5-qtbase-devel`.

👉 If you don't need support for Python3 scripts in the Proxmark3 client,  
you can skip the installation of `python3-devel`.

👉 If you don't need support for NFC ePaper devices,  
you can skip the installation of `gd-devel`.


# Clone the repository
^[Top](#top)

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

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
