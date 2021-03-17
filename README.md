# RRG / Iceman - Proxmark3


| Releases     | Coverity    | Contributors |
| ------------------- | -------------------:| -------------------:|
| [![Latest release](https://img.shields.io/github/v/release/rfidresearchgroup/proxmark3)](https://github.com/RfidResearchGroup/proxmark3/releases/latest) | [![Coverity Status](https://scan.coverity.com/projects/19334/badge.svg)](https://scan.coverity.com/projects/proxmark3-rrg-iceman-repo)| ![GitHub contributors](https://img.shields.io/github/contributors/rfidresearchgroup/proxmark3) |


| Actions OSX CI    |  Actions Ubuntu CI    | Windows CI |
| ------------------- | -------------------:| -------------------:|
| ![MacOS Build and Test](https://github.com/RfidResearchGroup/proxmark3/workflows/MacOS%20Build%20and%20Test/badge.svg?branch=master) | ![Ubuntu Build and Test](https://github.com/RfidResearchGroup/proxmark3/workflows/Ubuntu%20Build%20and%20Test/badge.svg?branch=master) | [![Build status](https://ci.appveyor.com/api/projects/status/b4gwrhq3nc876cuu/branch/master?svg=true)](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/branch/master) |



# PROXMARK3 INSTALLATION AND OVERVIEW

| FAQ's & Updates     | Installation        | Use of the Proxmark |
| ------------------- |:-------------------:| -------------------:|
|[What has changed?](#what-has-changed)  | **[Setup and build for Linux](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)** | [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)|
|[Development](#development) | **[Important notes on ModemManager for Linux users](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md)** | [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md) |
|[Why didn't you base it on official Proxmark3 Master?](#why-didnt-you-base-it-on-official-proxmark3-master)| **[Homebrew (Mac OS X) & Upgrading HomeBrew Tap Formula](/doc/md/Installation_Instructions/Mac-OS-X-Homebrew-Installation-Instructions.md)** | [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)|
|[Proxmark3 GUI](#proxmark3-gui)|**[Setup and build for Windows](/doc/md/Installation_Instructions/Windows-Installation-Instructions.md)**|[Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
|[Issues](#issues)|[Blue shark manual](/doc/bt_manual_v10.md) ||
|[Donations](#Donations)|[Maintainers](/doc/md/Development/Maintainers.md)|[Command Cheat sheet](/doc/cheatsheet.md)|
||[Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)|[More cheat sheets](https://github.com/RfidResearchGroup/proxmark3/wiki/More-cheat-sheets)|
||**[Troubleshooting](/doc/md/Installation_Instructions/Troubleshooting.md)**|[Complete client command set](/doc/commands.md)|
||**[JTAG](/doc/jtag_notes.md)**|[T55xx Guide](/doc/T5577_Guide.md)|


## Notes / helpful documents

| Notes |||
| ------------------- |:-------------------:| -------------------:|
|[Notes on UART](/doc/uart_notes.md)|[Notes on Termux / Android](/doc/termux_notes.md)|[Notes on paths](/doc/path_notes.md)|
|[Notes on frame format](/doc/new_frame_format.md)|[Notes on tracelog / wireshark](/doc/trace_notes.md)|[Notes on EMV](/doc/emv_notes.md)|
|[Notes on external flash](/doc/ext_flash_notes.md)|[Notes on loclass](/doc/loclass_notes.md)|[Notes on Coverity Scan Config & Run](/doc/md/Development/Coverity-Scan-Config-and-Run.md)|
|[Notes on file formats used with Proxmark3](/doc/extensions_notes.md)|[Notes on MFU binary format](/doc/mfu_binary_format_notes.md)|[Notes on FPGA & ARM](/doc/fpga_arm_notes.md)|
|[Developing standalone mode](/armsrc/Standalone/readme.md)|[Wiki about standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode)|[Notes on Magic cards](/doc/magic_cards_notes.md)|
|[Notes on Color usage](/doc/colors_notes.md)|[Makefile vs CMake](/doc/md/Development/Makefile-vs-CMake.md)|[Notes on Cloner guns](/doc/cloner_notes.md)|
|[Notes on cliparser usage](/doc/cliparser.md)|[Notes on clocks](/doc/clocks.md)||


## Build for Proxmark3 RDV4
See the instruction links in the tables above to build, flash and run for your Proxmark3 RDV4 device.

## Build for generic Proxmark3 platforms
In order to build this repo for generic Proxmark3 platforms we urge you to read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)

With generic Proxmark3 platforms we mean: 
  - RDV1
  - RDV2
  - RDV3 easy
  - Proxmark Evolution (needs extra care)
  - Radiowar black PCB version
  - Ryscorp green PCB version
  - Ryscorp Pm3Pro
  - VX
  - numerous Chinese adapted versions of the RDV3 easy (kkmoon, pisworks etc)

> ⚠ **Note**: About flash memory size of other Proxmark3 platforms. You need to keep a eye on how large your ARM chip built-in flash memory is. With 512kb you are fine but if its 256kb you need to compile this repo with even less functionality.  When running the `./pm3-flash-all` you can see which size your device have if you have the bootloader from this repo installed. Otherwise you will find the size reported in the start message when running the Proxmark3 client `./pm3`.

## What has changed?

On the hardware side:

  * added flash memory 256kb.
  * added smart card module
  * added FPC connector

On the software side:

quite a lot, see the [Changelog file](CHANGELOG.md) which we try to keep updated.

## Development

> ⚠ **Note**: This is a bleeding edge repository. The maintainers actively is working out of this repository and will be periodically re-structuring the code to make it easier to comprehend, navigate, build, test, and contribute to, so **DO expect significant changes to code layout on a regular basis**.

This repo compiles nicely on 
   - Proxspace v3.x
     - [latest release v3.7.2](https://github.com/Gator96100/ProxSpace/releases)
   - Windows/mingw environment with Qt5.6.1 & GCC 4.9
   - Ubuntu 16.04 -> 20.04
   - ParrotOS, Gentoo, Pentoo, Kali, Nethunter, Archlinux, Fedora, Debian
   - Rasbian
   - Android / Termux
   - Mac OS X / Homebrew / Apple Silicon
   - WSL1  (Windows subsystem linux) on Windows 10
   - Docker container
      - [ RRG / Iceman repo based ubuntu 18.04 container ](https://hub.docker.com/r/secopsconsult/proxmark3)
      - [ Iceman fork based container v1.7 ](https://hub.docker.com/r/iceman1001/proxmark3/)

Hardware to run client on
   - PC
   - Android
   - Raspberry Pi, Raspberry Pi Zero
   - Nvidia Jetson Nano

## Precompiled binaries
We don't maintain any precompiled binaries in this repo. There is community effort over at the Proxmark3 forum where [@gator96100](https://github.com/gator96100) has set up a AWS bucket with precompiled Proxspace (Mingw) binaries which is recompiled every night and with that also up-to-date. We link to these files here as to make it easier for users.

_If you use his pre-compiled Proxspace binaries do consider buy him a coffee for his efforts. Remember nothing says thank you as good as a donation._

If you are having troubles with these files, contact the package maintainer [@gator96100](https://github.com/gator96100) and read the [homepage of his proxmark builds](https://www.proxmarkbuilds.org/) or read the [sticky thread at forum](http://www.proxmark.org/forum/viewtopic.php?pid=24763#p24763) where known issues has been documented with regards to the precompiled builds.  

### Proxmark3 RDV4 devices
- [Precompiled builds for RDV40 dedicated x64](https://www.proxmarkbuilds.org/#rdv40-64/)
- [Precompiled builds for RDV40 dedicated with Bluetooth addon x64](https://www.proxmarkbuilds.org/#rdv40_bt-64/)

### Generic Proxmark3 devices
- [Precompiled builds for RRG / Iceman repository x64](https://www.proxmarkbuilds.org/#rrg_other-64/)


## Roadmap
The [public roadmap](https://github.com/RfidResearchGroup/proxmark3/wiki/Public-Roadmap) is an excellent start to read if you are interesting in contributing.

> 👉 **Remember!** If you intend to contribute to the code, please read the [coding style notes](HACKING.md) first.
We usually merge your contributions fast since we do like the idea of getting a functionality in the Proxmark3 and weed out the bugs afterwards.


## Issues & Troubleshooting
Please search the [issues](https://github.com/rfidresearchgroup/proxmark3/issues) page here and see if your issue is listed in the first instance.
Read the [Troubleshooting guide](/doc/md/Installation_Instructions/Troubleshooting.md) to weed out most known problems.

Next place to visit is the [Proxmark3 Forum](http://www.proxmark.org/forum/index.php). Learn to search it well and finally Google / duckduckgo is your friend :) 
You will find many blogposts, youtube videos, tweets, reddit

### Offical channels
   - [RFID Hacking community discord server](https://discord.gg/QfPvGFRQxH)
   - [Proxmark3 IRC channel](http://webchat.freenode.net/?channels=#proxmark3)
   - [Proxmark3 sub reddit](https://www.reddit.com/r/proxmark3/)
   - [Proxmark3 Twitter](https://twitter.com/proxmark3/)   
   - [Proxmark3 forum](http://www.proxmark.org/forum/index.php)
   -  _no slack channel_


### Youtube channels
Iceman has quite a few videos on his channel and Quentyn has risen up the last year with good informative videos. We suggest you check them out and smash that subscribe buttons!

 - [Iceman channel](https://www.youtube.com/c/ChrisHerrmann1001)
 - [Quentyn Taylor](https://www.youtube.com/channel/UCL91C3IZDv3wfj2ABhdRIrw)
 - [Hacker warehouse channel](https://www.youtube.com/channel/UCimS6P854cQ23j6c_xst7EQ)

_if you think of some more good youtube channels to be on this list, let us know!_

## Cheat sheet

You can enjoy a [command cheat sheet](/doc/cheatsheet.md) and we are trying to keep it updated. 
[Thanks to Alex Dib!](https://github.com/scund00r)

## Maintainers ( package, distro )

To all distro, package maintainers, we tried to make your life easier.

`make install` is now available and if you want to know more.
- [Notes for maintainers](/doc/md/Development/Maintainers.md)

## Why didn't you base it on official Proxmark3 Master?

The separation from official Proxmark3 repo gives us a lot of freedom to create a firmware/client that suits the RDV40 features. We don't want to mess up the official Proxmark3 repo with RDV40 specific code.

## Proxmark3 GUI

The official PM3-GUI from Gaucho will not work. Not to mention is quite old and not maintained any longer.

The new [Proxmark3 Universal GUI](https://github.com/burma69/PM3UniversalGUI) will work more or less. Change is needed in order to show helptext when client isn't connected to a device.  We don't know how active the maintainers are.  There has been brought to our attention that there is quite a few Chinese Windows GUI available. Usually you find them on alibaba / taobao ads but we have no idea which fw/client they are compatible with.  Proceed with caution if you decide to go down that road.

# Donations

Nothing says thank you as much as a donation. So if you feel the love, do feel free to become a iceman patron. For some tiers it comes with rewards.

https://www.patreon.com/iceman1001

