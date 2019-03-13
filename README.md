Proxmark3 RDV40 dedicated repo,  based on iceman fork
===============
[![Latest release](https://img.shields.io/github/release/RfidResearchGroup/proxmark3.svg)](https://github.com/RfidResearchGroup/proxmark3/releases/latest)

## Notice      
This repo is based on iceman fork for proxmark3. It is dedicated to bring the most out of the new features for proxmark3 RDV40 device.

# Donations
Nothing says thank you as much as a donation,  https://www.patreon.com/iceman1001

## ToC

- Coverity Scan Config & Run
- Whats changed?
- Why didn't you based it on offical PM3 Master?
- Why don't you add this or that functionality?	
- PM3 GUI
- Development
- KALI and ARCHLINUX users
- Setup and build for UBUNTU
- Setup and build for ArchLinux
- Homebrew (Mac OS X)
- Upgrading HomeBrew tap formula
- Building on Windows
- Gator96100 distro
- Build and run
- Validating proxmark client functionality
- Run the following commands
- Quit client
- First things on your RDV40
- Verify sim module firmware version

- The end

## Coverity Scan Config & Run
Download the Coverity Scan Self-buld and install it.
You will need to configure  ARM-NON-EABI- Compiler for it to use:

- Configure

`cov-configure --comptype gcc --compiler  /opt/devkitpro/devkitARM/bin/arm-none-eabi-gcc`

- Run it (I'm running on Ubuntu)

`cov-build --dir cov-int make all`

- Make a tarball

`tar czvf proxmark3.tgz cov-int`

- Upload it to coverity.com


## Whats changed?
	* added flash memory 256kb.
	* added smart card module
	* added FPC connector
	
---	
## Why didn't you based it on offical PM3 Master?
The separation from offical pm3 repo gives us very much freedom to create a firmware/client that suits the RDV40 features. We don't want to mess up the offical pm3 repo with RDV40 specific code.

## Why don't you add this or that functionality?
Give us a hint, and we'll see if we can't merge in the stuff you have. 
	
## PM3 GUI
The official PM3-GUI from Gaucho will not work.
The new universial GUI will work. [Proxmark3 Univerisal GUI](https://github.com/burma69/PM3UniversalGUI) 

## Development
This fork now compiles just fine on 
   - Windows/mingw environment with Qt5.6.1 & GCC 4.8
   - Ubuntu 1404, 1510, 1604, 1804
   - Mac OS X / Homebrew
   - ParrotOS
   - WSL (Windows subsystem linux) on Windows 10
   - Docker container

## KALI and ARCHLINUX users
Kali and ArchLinux users usually must kill their modem manager in order for the proxmark3 to enumerate properly.   
```sh
sudo apt remove modemmanager
```
or 
```sh
systemctl stop ModemManager
systemctl disable ModemManager
```

## Setup and build for UBUNTU
GC made updates to allow this to build easily on Ubuntu 14.04.2 LTS, 15.10 or 16.04
See https://github.com/Proxmark/proxmark3/wiki/Ubuntu%20Linux

A nice and cool install script made by @daveio is found here: 
https://github.com/daveio/attacksurface/blob/master/proxmark3/pm3-setup.sh
I have also added this script to the fork.
https://github.com/RfidResearchGroup/proxmark3/blob/master/install.sh

- Run
`sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi`

- Clone fork
`git clone https://github.com/RfidResearchGroup/proxmark3.git`

- Get the latest commits
`git pull`

- Install the blacklist rules and  add user to dialout group (if you on a Linux/ubuntu/debian). If you do this one, you need to logout and login in again to make sure your rights got changed.
`make udev`

- Clean and complete compilation
`make clean && make all`
	
- Flash the BOOTROM & FULLIMAGE
`client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf`
	
- Change into the client folder
`cd client`
	
- Run the client
`./proxmark3 /dev/ttyACM0`

## Setup and build for ArchLinux
- Run
`sudo pacman -Sy base-devel p7zip libusb readline ncurses arm-none-eabi-newlib --needed`
`yaourt -S termcap`

- Remove modemmanager
`sudo apt remove modemmanager`

- Clone fork
`git clone https://github.com/RfidResearchGroup/proxmark3.git`

- Get the latest commits
`git pull`

- Install the blacklist rules and  add user to dialout group (if you on a Linux/ubuntu/debian). If you do this one, you need to logout and login in again to make sure your rights got changed.
`make udev`

- Clean and complete compilation
`make clean && make all`
	
- Flash the BOOTROM & FULLIMAGE
`client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf`
	
- Change into the client folder
`cd client`
	
- Run the client
`./proxmark3 /dev/ttyACM0`
						   
## Homebrew (Mac OS X)
These instructions comes from @Chrisfu, where I got the proxmark3.rb scriptfile from.
Further questions about Mac & Homebrew,  contact @Chrisfu  (https://github.com/chrisfu/)

1. Install homebrew if you haven't yet already done so: http://brew.sh/

2. Tap this repo: `brew tap RfidResearchGroup/proxmark3`

3. Install Proxmark3: `brew install proxmark3` for stable release or `brew install --HEAD proxmark3` for latest non-stable from GitHub.

Upgrading HomeBrew tap formula
-----------------------------
*This method is useful for those looking to run bleeding-edge versions of iceman's client. Keep this in mind when attempting to update your HomeBrew tap formula as this procedure could easily cause a build to break if an update is unstable on macOS.* 

Tested on macOS High Sierra 10.13.2

*Note: This assumes you have already installed iceman's fork from HomeBrew as mentioned above*

1. Force HomeBrew to pull the latest source from github
`brew upgrade --fetch-HEAD RfidResearchGroup/proxmark3`
 
2. Flash the bootloader & fullimage.elf
  * With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark 3 as you plug it into a USB port. Continue to hold the button until after this step is complete and the `proxmark3-flasher` command outputs "Have a nice day!"*
   `$ sudo proxmark3-flasher /dev/tty.usbmodem881 -b /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/bootrom.elf /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/fullimage.elf`


`$ sudo proxmark3-flasher /dev/tty.usbmodem881 `

4. Enjoy the update


## Building on Windows

### Gator96100 distro
Rather than download and install every one of these packages, a new ProxSpace 
environment archive file will be made available for download on the project
page at @Gator96100's repo

Afterwards just clone the iceman repo or download someone elses.
Read instructions on @Gator96100 repo page. (https://github.com/Gator96100/ProxSpace/)

Links
- https://github.com/Gator96100/ProxSpace/releases/tag/v3.1   (release v3.1 with gcc v7.3.0 )
- https://github.com/Gator96100/ProxSpace/releases/tag/v2.2   (release v2.2 with gcc v5.3.0 arm-none-eabi-gcc v7.1.0)


### Build and run

- Clone fork
`git clone https://github.com/RfidResearchGroup/proxmark3.git`

- Get the latest commits	
`git pull`

- CLEAN COMPILE
`make clean && make all`

Assuming you have Proxmark3 Windows drivers installed you can run the Proxmark software where "X" is the com port number assigned to proxmark3 under Windows. 
	
- Flash the BOOTROM & FULLIMAGE
`client/flasher.exe comX -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf`
	
- Change into the client folder
`cd client`
	
- Run the client	
`proxmark3.exe comX`


## Validating proxmark client functionality

If all went well you should get some information about the firmware and memory usage as well as the prompt,  something like this.

>[=] UART Setting serial baudrate 460800
>
>Proxmark3 RFID instrument
>
> [ CLIENT ]
>
> client: iceman build for RDV40 with flashmem; smartcard;
>
> [ ARM ]
>
> bootrom: iceman/master/4517531c-dirty-unclean 2018-12-13 15:42:24
>
>   os: iceman/master/5a34550a-dirty-unclean 2019-01-07 23:04:07
>
> [ FPGA ]
>
> LF image built for 2s30vq100 on 2018/ 9/ 8 at 13:57:51
>
> HF image built for 2s30vq100 on 2018/ 9/ 3 at 21:40:23
>
> [ Hardware ]
>
>--= uC: AT91SAM7S512 Rev B
>
>--= Embedded Processor: ARM7TDMI
>
>--= Nonvolatile Program Memory Size: 512K bytes, Used: 247065 bytes (47%) Free: 277223 bytes (53%)
>
>--= Second Nonvolatile Program Memory Size: None
>
>--= Internal SRAM Size: 64K bytes
>
>--= Architecture Identifier: AT91SAM7Sxx Series
>
>--= Nonvolatile Program Memory Type: Embedded Flash Memory
>
> pm3 -->

### Run the following commands
    pm3 --> hw status
    pm3 --> hw version
    pm3 --> hw tune

You are now ready to use your newly upgraded proxmark3 device.  Many commands uses the **h** parameter to show a help text. The client uses a arcaic command structure which will be hard to grasp at first.  Here are some commands to start off with.

    pm3 --> hf
    pm3 --> hf 14a info
    pm3 --> lf
    pm3 --> lf search

### Quit client
    pm3 --> quit


### First things on your RDV40
You will need to run these commands to make sure your rdv4 is prepared

    pm3 --> mem load f default_keys m
    pm3 --> mem load f default_pwd t
    pm3 --> mem load f default_iclass_keys i
    pm3 --> lf t55xx deviceconfig a 29 b 17 c 15 d 47 e 15 p

### Verify sim module firmware version
To make sure you got the latest sim module firmware.
_Lastest version is v3.11_

    pm3 --> hw status

Find version in the long output,  look for these two lines

    #db# Smart card module (ISO 7816)
    #db#   version.................v2.06

This version is obselete. The following command upgrades your device sim module firmware.
Don't not turn of your device during the execution of this command.

    pm3 --> sc upgrade f ../tools/simmodule/SIM011.BIN 
    
You get the following output,  this is a successful execution.    
    
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
    

## the end

`iceman at host iuse.se`
`July 2018, Sweden`
