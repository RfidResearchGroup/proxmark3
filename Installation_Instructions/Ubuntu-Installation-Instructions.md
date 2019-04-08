# Setup and build for UBUNTU
## Notes
GC made updates to allow this to build easily on Ubuntu 14.04.2 LTS, 15.10 or 16.04
See the [Proxmark3 Ubuntu wiki page](https://github.com/Proxmark/proxmark3/wiki/Ubuntu%20Linux)

A nice and cool install script made by @daveio is found here: 
https://github.com/daveio/attacksurface/blob/master/proxmark3/pm3-setup.sh

Iceman has also added this script to the fork.
https://github.com/RfidResearchGroup/proxmark3/blob/master/install.sh

# Video Installation guide
[![ParrotOS Installation tutorial](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)](https://youtu.be/DThmkH8CdMo "Ubuntu Installation Tutorial")

---
## Manual Installation
### Update

```sh
sudo apt-get update
```
### Requirements

```sh
sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi
```

### Clone Fork 

```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```
### Change Directory

```sh
cd proxmark3
```

### Get the latest commits

```sh
git pull
```

### Install the blacklist rules and add user to dialout group. 

```sh
sudo make udev
```

### Restart
Restart Ubuntu

### Enter proxmark folder
```sh
cd proxmark3
```
### Clean and Compile
```sh
make clean && make all
```
### Check Connection
Once this is complete run the following comands to make sure the proxmark is being picked up by your computer. 

```sh
sudo dmesg | grep -i usb
```

### Flash the BOOTROM & FULLIMAGE
 ```sh
 client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf
```

### Issues 
If you have issues with the install please try the following below or head on over to the proxmark forum.
#### Remove Modem Manager

```sh
sudo apt remove modemmanager
```
and then restart ubuntu.

### Change into the client folder
```sh
cd client
```
	
### Run the client
 ``` sh 
./proxmark3 /dev/pm #press tab on the keyboard for it to detect the proxmark
```
or  

### Run the client 
 ```sh
./proxmark3 /dev/ttyACM0
```
 
### Run a test command
 ```sh
hw tune
```
