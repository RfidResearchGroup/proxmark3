# External resources

You might want to follow one of these external resources to get an overview, but please still read carefully this page as some instructions may vary.

* [Kali Video Installation guide](https://youtu.be/t5eBPS6lV3E "Kali Linux Installation Tutorial")
* [Ubuntu Video Installation guide](https://youtu.be/DThmkH8CdMo "Ubuntu Installation Tutorial")
* [ParrotOS Video Installation guide](https://youtu.be/Wl9AsrU4igo "ParrotOS Installation Tutorial")

![Linux Installation Video Screenshot](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)

* ParrotOS: some further notes can be found at @5w0rdfish repo [Proxmark Installation for Parrot OS](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS)
* Ubuntu 14.04.2 LTS, 15.10 or 16.04 GC updates on the [Proxmark3 Ubuntu wiki page](https://github.com/Proxmark/proxmark3/wiki/Ubuntu%20Linux)
* A nice and cool install script made by @daveio is found here: https://github.com/daveio/attacksurface/blob/master/proxmark3/pm3-setup.sh (unavailable?)
* Iceman has also added this script to the fork. https://github.com/RfidResearchGroup/proxmark3/blob/master/install.sh


# Install the required dependencies

## On Debian / Ubuntu / Kali / ParrotOS

First what we want to do is get an update for the system. If you need to upgrade do this **before** the install. An upgrade was carried out prior to following these instructions. 

Update the packages list
```sh
sudo apt-get update
``` 
Install the requirements

```sh
sudo apt-get install p7zip git ca-certificates build-essential libreadline5 libreadline-dev \
libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi libstdc++-arm-none-eabi-newlib
```

## On ArchLinux

```sh
sudo pacman -Sy base-devel p7zip libusb readline ncurses arm-none-eabi-newlib --needed
```
```sh
yaourt -S termcap
```

# Clone the RRG/Iceman repository

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

# Check ModemManager

**Very important**: make sure ModemManager will not interfer, otherwise it could brick your Proxmark3!
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
It must return `ok`. Otherwise this means you've a permissions problem to fix.

# Compile and use the project

Now you're ready to follow the [compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md).
