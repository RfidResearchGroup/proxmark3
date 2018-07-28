Iceman fork
===============
[![Build Status](https://travis-ci.org/iceman1001/proxmark3.svg?branch=master)](https://travis-ci.org/iceman1001/proxmark3)[![Coverity Status](https://scan.coverity.com/projects/5117/badge.svg)](https://scan.coverity.com/project/proxmark3_iceman_fork)[![Latest release](https://img.shields.io/github/release/iceman1001/proxmark3.svg)](https://github.com/iceman1001/proxmark3/releases/latest)

## This fork is HIGHLY experimental and bleeding edge


The kickstarter for the latest revision of proxmark is out. 
[proxmark3 rdv4.0](https://www.kickstarter.com/projects/1408815241/proxmark3-rdv-40)

That one is a beauty!




## Nothing says thank you as much as a donation 
https://paypal.me/iceman1001/  Feel free to donate. All support is welcome.

monereo:  43mNJLpgBVaTvyZmX9ajcohpvVkaRy1kbZPm8tqAb7itZgfuYecgkRF36rXrKFUkwEGeZedPsASRxgv4HPBHvJwyJdyvQuP

## Notice      
There is so much in this fork,  with all fixes and additions its basically the most enhanced fork to this day for the Proxmark3 device. Which makes it so awesum to play with. Do please play with it. Get excited and experiment. As a side note with all coverity scan fixes this client is much more stable than PM3 Master even if I tend to break it sometimes. I'll try to make a release when this fork becomes stable between my experiments.

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
Whats so special with this fork?  I have scraped the web for different enhancements to the PM3 source code and not all of them ever found their way to the master branch. 
Among the stuff is

	* Jonor's hf 14a raw timing patch
	* Piwi's updates. (usually gets into the master)
	* Piwi's "topaz" branch
	* Piwi's "hardnested" branch 
	* Holiman's iclass, (usually gets into the master)
	* Marshmellow's fixes (usually gets into the master)
	* Midnitesnake's Ultralight,  Ultralight-c enhancements
	* Izsh's lf peak modification / iir-filtering
	* Aspers's tips and tricks from inside the PM3-gui-tool, settings.xml and other stuff.
	* My own desfire, Ultralight extras, LF T55xx enhancements, bugs fixes (filelength, hf mf commands ), TNP3xxx lua scripts,  Awid26,  skidata scripts (will come)
	* other obscure patches like for the sammy-mode,  (offline you know), tagidentifications, defaultkeys. 
	* Minor textual changes here and there.
	* Simulation of Ultralight/Ntag.
	* Marshmellow's and my "RevEng" addon for the client.  Ref: http://reveng.sourceforge.net/    Now using reveng1.44
	* J-Run alternative bruteforce Mifare nested auths.. (you need one other exe to make it work)
	* A Bruteforce for T55XX passwords against tag.
	* A Bruteforce for AWID 26, starting w a facilitycode then trying all 0xFFFF cardnumbers via simulation. To be used against a AWID Reader.
	* A Bruteforce for HID,  starting w a facilitycode then trying all 0xFFFF cardnumbers via simulation. To be used against a HID Reader.
	* Blaposts Crapto1 v3.3
    * Icsom's  legic script and legic enhancements
    * Aczid's bitsliced bruteforce solver in 'hf mf hardnested'
	
---	
## Why don't you merged with offical PM3 Master?
Me fiddling with the code so much, there is a nightmare in merging a PR. I will never find time to do PR because of it. Much of what you find here is not in the interest for offical PM3. However and luckily I have @marshmellow42 who takes some stuff and push PR's back.  The separation from offical pm3 repo gives me very much freedom to create a firmware/client in the way I want to use the PM3.

## Why don't you add this or that functionality?
Give me a hint, and I'll see if I can't merge in the stuff you have. 
	
## PM3 GUI
I do tend to rename and move stuff around, the official PM3-GUI from Gaucho will not work so well. *sorry*	

## Development
This fork now compiles just fine on 
   - Windows/mingw environment with Qt5.6.1 & GCC 4.8
   - Ubuntu 1404, 1510, 1604
   - Mac OS X / Homebrew
   - Docker container

## Setup and build for UBUNTU
GC made updates to allow this to build easily on Ubuntu 14.04.2 LTS, 15.10 or 16.04
See https://github.com/Proxmark/proxmark3/wiki/Ubuntu%20Linux

A nice and cool install script made by @daveio is found here: 
https://github.com/daveio/attacksurface/blob/master/proxmark3/pm3-setup.sh
I have also added this script to the fork.
https://github.com/iceman1001/proxmark3/blob/master/install.sh

- Run
`sudo apt-get install p7zip git build-essential libreadline5 libreadline-dev libusb-0.1-4 libusb-dev libqt4-dev perl pkg-config wget libncurses5-dev gcc-arm-none-eabi`

- Clone iceman fork
`git clone https://github.com/iceman1001/proxmark3.git`

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

- Clone iceman fork
`git clone https://github.com/iceman1001/proxmark3.git`

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

2. Tap this repo: `brew tap iceman1001/proxmark3`

3. Install Proxmark3: `brew install proxmark3` for stable release or `brew install --HEAD proxmark3` for latest non-stable from GitHub.

Upgrading HomeBrew tap formula
-----------------------------
*This method is useful for those looking to run bleeding-edge versions of iceman's client. Keep this in mind when attempting to update your HomeBrew tap formula as this procedure could easily cause a build to break if an update is unstable on macOS.* 

Tested on macOS High Sierra 10.13.2

*Note: This assumes you have already installed iceman's fork from HomeBrew as mentioned above*

1. Force HomeBrew to pull the latest source from github
`brew upgrade --fetch-HEAD iceman1001/proxmark3/proxmark3`
 
2. Flash the bootloader & fullimage.elf
  * With your Proxmark3 unplugged from your machine, press and hold the button on your Proxmark 3 as you plug it into a USB port. Continue to hold the button until after this step is complete and the `proxmark3-flasher` command outputs "Have a nice day!"*
   `$ sudo proxmark3-flasher /dev/tty.usbmodem881 -b /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/bootrom.elf /usr/local/Cellar/proxmark3/HEAD-6a710ef/share/firmware/fullimage.elf`


`$ sudo proxmark3-flasher /dev/tty.usbmodem881 `

4. Enjoy the update

## Docker container
I recently added a docker container on Docker HUB.  You find it here: https://hub.docker.com/r/iceman1001/proxmark3/
Follow those instructions to get it up and running.  No need for the old proxspace-environment anymore.

-[1.6.0] How to start:   https://www.youtube.com/watch?v=b5Zta89Cf6Q
-[1.6.0] How to connect: https://youtu.be/0ZS2t5C-caI
-[1.6.1] How to flash:   https://www.youtube.com/watch?v=WXouhuGYEiw

Recommendations:  Use only latest container.


## Building on Windows

### Gator96100 distro
Rather than download and install every one of these packages, a new ProxSpace 
environment archive file will be made available for download on the project
page at @Gator96100's repo

Afterwards just clone the iceman repo or download someone elses.
Read instructions on @Gator96100 repo page. (https://github.com/Gator96100/ProxSpace/)

Links
- https://github.com/Gator96100/ProxSpace/archive/master.zip
- https://github.com/Gator96100/ProxSpace/releases/tag/v2.2     (release v2.2   with gcc v5.3.0 arm-none-eabi-gcc v7.1.0)
- https://github.com/Gator96100/ProxSpace/releases/tag/v2.1     (release v2.1   with gcc v5.3.0)


### 7. Build and run

- Clone iceman fork
`git clone https://github.com/iceman1001/proxmark3.git`

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
January 2015, Sweden
