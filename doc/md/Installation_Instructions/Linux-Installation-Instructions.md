# External resources

You might want to follow one of these external resources to get an overview, but please still read carefully this page as some instructions may have evolved.

* [Kali Video Installation guide](https://youtu.be/t5eBPS6lV3E "Kali Linux Installation Tutorial")
* [Ubuntu Video Installation guide](https://youtu.be/DThmkH8CdMo "Ubuntu Installation Tutorial")
* [ParrotOS Video Installation guide](https://youtu.be/Wl9AsrU4igo "ParrotOS Installation Tutorial")

![Linux Installation Video Screenshot](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)

* ParrotOS: some further notes can be found at @5w0rdfish repo [Proxmark Installation for Parrot OS](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS)


# Install the required dependencies

## On Debian / Ubuntu / Kali / ParrotOS / Raspbian

First what we want to do is get an update for the system. If you need to upgrade do this **before** the install. An upgrade was carried out prior to following these instructions. 

Update the packages list
```sh
sudo apt-get update
``` 
Install the requirements

```sh
sudo apt-get install --no-install-recommends git ca-certificates build-essential pkg-config \
libreadline-dev gcc-arm-none-eabi libnewlib-dev qtbase5-dev libbz2-dev libbluetooth-dev
```

If you don't need the native Bluetooth support in the client, you can skip the installation of `libbluetooth-dev`.

If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`), you can skip the installation of `qtbase5-dev`.

If you get some (non blocking) error at runtime such as _Gtk-Message: Failed to load module "canberra-gtk-module"_ you may have to install `libcanberra-gtk-module`.

## On ArchLinux

```sh
sudo pacman -Sy git base-devel readline bzip2 arm-none-eabi-gcc arm-none-eabi-newlib qt5-base bluez --needed
```

If you don't need the native Bluetooth support in the client, you can skip the installation of `bluez`.

If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`), you can skip the installation of `qt5-base`.

## On Fedora

```sh
sudo dnf install git make gcc gcc-c++ arm-none-eabi-gcc-cs arm-none-eabi-newlib readline-devel bzip2-devel qt5-qtbase-devel bluez-libs-devel libatomic
```

If you don't need the native Bluetooth support in the client, you can skip the installation of `bluez-libs-devel`.

If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`), you can skip the installation of `qt5-qtbase-devel`.

## On openSUSE

```sh
sudo zypper install git patterns-devel-base-devel_basis gcc-c++ readline-devel libbz2-devel cross-arm-none-gcc9 cross-arm-none-newlib-devel libqt5-qtbase-devel
```

If you don't need the graphical components of the Proxmark3 client (such as in `hw tune`), you can skip the installation of `libqt5-qtbase-devel`.

Note that Bluez is not available on openSUSE so the native Bluetooth support won't be available in the client.

# Clone the RRG/Iceman repository

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

# Check ModemManager

### ⚠️ Very important ⚠️
make sure ModemManager will not interfere, otherwise it could brick your Proxmark3!
Read carefully [this page about ModemManager](ModemManager-Must-Be-Discarded.md) and follow its instructions.

# Check connection

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

Add current user to the proper group to get permission to use `/dev/ttyACM0`.

This step can be done from the RRG/Iceman Proxmark3 repo with:

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

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).
