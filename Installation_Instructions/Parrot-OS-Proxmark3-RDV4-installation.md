
# Parrot OS Installation

## Notes

Some further notes can be found at @5w0rdfish repo [Proxmark Installation for Parrot OS](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS)

# Video Installation guide
[![ParrotOS Installation tutorial](https://github.com/5w0rdfish/Proxmark3-RDV4-ParrotOS/blob/master/screenshot-www.youtube.com-2019.03.17-20-44-33.png)](https://youtu.be/Wl9AsrU4igo "ParrotOS Installation Tutorial")


---
## Manual Install
First what we want to do is get an update for the system. If you need to upgrade do this **before** the install

### Update
```sh
sudo apt-get update
``` 
### Requirements.

```sh
sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev \
libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi
```
If you do get any issues during the requirements installation, I have found it to help using the synaptic package manager. 

### Clone Fork 
```sh
git clone https://github.com/RfidResearchGroup/proxmark3.git
```

### Change directory into the directory created
```sh
cd proxmark3
```

### Get the latest commits
```sh
git pull
```

### Make Udev
Iceman has made the udev script which takes care of the blacklist rules. This should take care of the remove modem manager.
The make udev command also create's an alias for the pm3 under /dev which you will use to connect to the proxmark. 

```sh
sudo make udev
```

> **Note**  If you have any issues connecting or during the flash, follow the steps listed [here](https://github.com/RfidResearchGroup/proxmark3/issues/35) and use the command sudo apt remove modemmanager 

Log out and log back in again. And now we are all set to take the next step. 

### Clean and Compile
Clean and complete compilation *within the proxmark3 folder*

```sh
 make clean && make all
```
### Check Connection
Once this is complete run the following comands to make sure the proxmark is being picked up by your computer. 

```sh
sudo dmesg | grep -i usb
```
It should show up as a CDC device:
```sh
[10416.555108] usb 2-1.2: Product: PM3
[10416.555111] usb 2-1.2: Manufacturer: proxmark.org
[10416.555871] cdc_acm 2-1.2:1.0: ttyACM0: USB ACM device
```

### Flash the BOOTROM & FULLIMAGE
 ```sh
 client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf
```
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

