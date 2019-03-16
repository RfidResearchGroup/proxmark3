Proxmark3 RDV40
===============
[![Latest release](https://img.shields.io/github/release/RfidResearchGroup/proxmark3.svg)](https://github.com/RfidResearchGroup/proxmark3/releases/latest)


Notice
-------
This repository is based on [iceman fork](https://github.com/iceman1001/proxmark3) for
[proxmark3](https://github.com/Proxmark/proxmark3). It is dedicated to bring the most out of the new features for
proxmark3 RDV40 device. However, you can still use it with other proxmark3 version. Have a look at
[wiki](https://github.com/RfidResearchGroup/proxmark3/wiki/How-to-compile-this-repo-for-non-rdv4).


Donations
---------
Nothing says thank you as much as a donation: https://www.patreon.com/iceman1001


Table of Content
----------------
* Setup and Build on Linux
* Setup and Build on Mac OS X (Homebrew)
* Setup and Build on Windows
* Validating Proxmark3 Client Functionality
* First Things on your RDV40
* Tested Operating Systems
* Proxmark3 GUI
* Coverity Scan Config & Run
* Frequently Asked Questions



Setup and Build on Linux
------------------------
* Install the dependencies
	* Ubuntu  
`sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi`
	* Arch Linux  
`sudo pacman -S base-devel p7zip libusb readline ncurses arm-none-eabi-newlib`  
`yay -S termcap` (AUR)
* Clone this repository  
`git clone https://github.com/RfidResearchGroup/proxmark3.git`
* Install the udev rules and add user to `dialout` group (if you are on Ubuntu/Debian) or `uucp` group (if your are
	on Arch Linux). You need to logout and login in again to apply the group changes.  
`make udev`
* Clean and complete compilation  
`make clean && make all`
* Flash the bootrom (only needed if there where changes in the bootloader)  
`./client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf`
* Flash the fullimage (FPGA and the ARM code)  
`./client/flasher /dev/ttyACM0 armsrc/obj/fullimage.elf`
* Change into the client folder and run the client  
`cd client`  
`./proxmark3 /dev/ttyACM0`


### Issues with ModemManager
A lot of Linux distributions ship with the ModemManager preinstalled. This program causes several issues in
combination with the Proxmark3. It must be deactivated before using the Proxmark3.
* Deactivate the ModemManager temporarily  
`systemctl stop ModemManager`
* Deactivate the ModemManager permanently  
`systemctl disable ModemManager`


### Install Script
A nice and cool install script made by [@daveio](https://github.com/daveio/) is found here:
https://github.com/daveio/attacksurface/blob/master/proxmark3/pm3-setup.sh.
This script has also been added to this repository:
https://github.com/RfidResearchGroup/proxmark3/blob/master/install.sh.



Setup and Build on Mac OS X (Homebrew)
--------------------------------------
These instructions comes from [@Chrisfu](https://github.com/chrisfu/), where I got the proxmark3.rb scriptfile from.
Further questions about Mac & Homebrew, contact [@Chrisfu](https://github.com/chrisfu/).

* Install homebrew if you haven't yet already done so: http://brew.sh/
* Tap this repository  
`brew tap RfidResearchGroup/proxmark3`
* Install Proxmark3  
`brew install proxmark3` (stable releases)  
`brew install --HEAD proxmark3` (latest non-stable from GitHub)

### Upgrading Homebrew Tap Formula
This method is useful for those looking to run bleeding-edge versions. Keep this in mind when attempting to update
your Homebrew tap formula as this procedure could easily cause a build to break if an update is unstable on macOS.

Note: This assumes you have already installed Proxmark3 from Homebrew as mentioned above.
Tested on macOS High Sierra 10.13.2.

* Force Homebrew to pull the latest source from Github  
`brew upgrade --fetch-HEAD RfidResearchGroup/proxmark3`
* Flash the bootloader & fullimage .With your Proxmark3 unplugged from your machine, press and hold the button
on your Proxmark3 as you plug it into a USB port. Continue to hold the button until after this step is complete
and the `proxmark3-flasher` command outputs "Have a nice day!"  
`sudo proxmark3-flasher /dev/tty.usbmodem881 -b /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/bootrom.elf /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/fullimage.elf`



Setup and Build on Windows
--------------------------
Clone and build the software like described in the Linux section. To build the source you will need the dependencies
(e.g. GNU Arm Embedded Toolchain, git, readline, etc.). Assuming you have Proxmark3 Windows drivers installed you
can run the Proxmark3 software where "X" is the com port number assigned to proxmark3 under Windows.

Flash the bootrom (only needed if there where changes in the bootloader)  
`client/flasher.exe comX -b bootrom/obj/bootrom.elf`
* Flash the fullimage (FPGA and the ARM code)  
`client/flasher.exe comX armsrc/obj/fullimage.elf`
* Change into the client folder and run the client  
`cd client`  
`proxmark3.exe comX`

### Gator96100 Distro
Rather than download and install all the dependencies, a new ProxSpace environment archive file will be made
available for download on the project page at [@Gator96100](https://github.com/Gator96100)'s repository. Afterwards
just clone this repository. Read instructions on [@Gator96100](https://github.com/Gator96100) repository page:
https://github.com/Gator96100/ProxSpace/



Validating Proxmark3 Client Functionality
-----------------------------------------
If all went well you should get some information about the firmware and memory usage as well as the prompt,
something like this.

```
[=] UART Setting serial baudrate 460800

Proxmark3 RFID instrument


 [ CLIENT ]
 client: iceman build for RDV40 with flashmem; smartcard;

 [ ARM ]
 bootrom: iceman/master/4517531c-dirty-unclean 2018-12-13 15:42:24
			os: iceman/master/5a34550a-dirty-unclean 2019-01-07 23:04:07

 [ FPGA ]
 LF image built for 2s30vq100 on 2018/ 9/ 8 at 13:57:51
 HF image built for 2s30vq100 on 2018/ 9/ 3 at 21:40:23

 [ Hardware ]
--= uC: AT91SAM7S512 Rev B
--= Embedded Processor: ARM7TDMI
--= Nonvolatile Program Memory Size: 512K bytes, Used: 247065 bytes (47%) Free: 277223 bytes (53%)
--= Second Nonvolatile Program Memory Size: None
--= Internal SRAM Size: 64K bytes
--= Architecture Identifier: AT91SAM7Sxx Series
--= Nonvolatile Program Memory Type: Embedded Flash Memory

 pm3 -->
```

The following commands can help as well:
* `hw status`
* `hw version`
* `hw tune`

You are now ready to use your newly upgraded proxmark3 device.  Many commands uses the `h` parameter to show a help
text. The client uses a arcaic command structure which will be hard to grasp at first. Here are some commands to
start off with.
* `hf`
* `hf 14a info`
* `lf`
* `lf search`

Quit the client:
* `quit`


First Things on your RDV40
--------------------------
You will need to run these commands to make sure your RDV40 is prepared:
* `mem load f default_keys m`
* `mem load f default_pwd t`
* `mem load f default_iclass_keys i`
* `lf t55xx deviceconfig a 29 b 17 c 15 d 47 e 15 p`

Verify SIM module firmware version to make sure you got the latest SIM module firmware:
Version 3.11
* `hw status`

Look for these two lines:
```
#db# Smart card module (ISO 7816)
#db#   version.................v2.06
```

This version is outdated. The following command upgrades your device sim module firmware.
Don't not turn of your device during the execution of this command.
* `sc upgrade f ../tools/simmodule/SIM011.BIN`

A successful update will look like the this:
```
[!] WARNING - Smartcard socket firmware upgrade.
[!] A dangerous command, do wrong and you will brick the smart card socket
[+] Smartcard socket firmware uploading to PM3
..
[+] Smartcard socket firmware updating,  don't turn off your PM3!
#db# FW 0000
#db# FW 0080
#db# FW 0100
#db# FW 0180
#db# FW 0200
#db# FW 0280
[+] Smartcard socket firmware upgraded successful
```


Tested Operating Systems
------------------------
This fork now compiles just fine on:
* Windows/mingw environment with Qt5.6.1 & GCC 4.8
* Ubuntu 14.04, 15.10, 16.04, 18.04
* Mac OS X / Homebrew
* ParrotOS
* WSL (Windows subsystem linux) on Windows 10
* Arch Linux
* Kali Linux
* Docker Container



Proxmark3 GUI
-------------
The official PM3-GUI from Gaucho will not work. The new [Proxmark3 Univerisal GUI](https://github.com/burma69/PM3UniversalGUI)
should work.



Coverity Scan Config & Run
--------------------------
Download the Coverity Scan Self-buld and install it. You will need to configure ARM-NON-EABI- Compiler for it to use:

* Configure  
`cov-configure --comptype gcc --compiler  /opt/devkitpro/devkitARM/bin/arm-none-eabi-gcc`
* Run it (I'm running on Ubuntu)  
`cov-build --dir cov-int make all`
* Make a tarball  
`tar czvf proxmark3.tgz cov-int`
* Upload it to coverity.com



Frequently Asked Questions
--------------------------

### Proxmark3 vs. Proxmark3 RDV40
There have been several changes to the hardware for the Proxmark3 RDV40
* Added flash memory 256KB
* Added smart card module
* Added FPC connector


### Why didn't you based it on offical PM3 Master?
The separation from [official PM3 repository](https://github.com/Proxmark/proxmark3) gives us very much freedom to
create a firmware/client that suits the RDV40 features. We don't want to mess up the official PM3 repository
with RDV40 specific code.


### Why don't you add this or that functionality?
Give us a hint, and we'll see if we can't merge in the stuff you have.

----------------------------------------------------------------------------------

iceman at host iuse.se, January 2019, Sweden
