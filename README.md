Proxmark3 RDV40 dedicated repo,  based on iceman fork
===============
[![Latest release](https://img.shields.io/github/release/RfidResearchGroup/proxmark3.svg)](https://github.com/RfidResearchGroup/proxmark3/releases/latest)

## Notice      
This repo is based on iceman fork for proxmark3. It is dedicated to bring the most out of the new features for proxmark3 RDV40 device.

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
The new universial GUI will work.

## Development
This fork now compiles just fine on 
   - Windows/mingw environment with Qt5.6.1 & GCC 4.8
   - Ubuntu 1404, 1510, 1604
   - Mac OS X / Homebrew
   - Docker container

## KALI and ARCHLINUX users
Kali and ArchLinux users usually must kill their modem manager in order for the proxmark3 to enumerate properly.   
   
## Setup and build for UBUNTU
GC made updates to allow this to build easily on Ubuntu 14.04.2 LTS, 15.10 or 16.04
See https://github.com/Proxmark/proxmark3/wiki/Ubuntu%20Linux

A nice and cool install script made by @daveio is found here: 
https://github.com/daveio/attacksurface/blob/master/proxmark3/pm3-setup.sh
I have also added this script to the fork.
https://github.com/RfidResearchGroup/proxmark3/blob/master/install.sh

- Run
`sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi libjansson-dev`

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
`sudo pacman -Sy base-devel p7zip libusb readline ncurses libjansson-dev arm-none-eabi-newlib --needed`
`yaourt -S termcap`

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


### 7. Build and run

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

iceman at host iuse.se
July 2018, Sweden
