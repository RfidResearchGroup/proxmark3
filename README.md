# RRG / Iceman repo - Proxmark3




| Releases     | Linux & OSX CI       | Windows CI | Coverity    | Contributors |
| ------------------- |:-------------------:| -------------------:| -------------------:| -------------------:|
| [![Latest release](https://img.shields.io/github/v/release/rfidresearchgroup/proxmark3)](https://github.com/RfidResearchGroup/proxmark3/releases/latest) | [![Build status](https://api.travis-ci.com/RfidResearchGroup/proxmark3.svg?branch=master)](https://travis-ci.com/RfidResearchGroup/proxmark3) | [![Build status](https://ci.appveyor.com/api/projects/status/b4gwrhq3nc876cuu/branch/master?svg=true)](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/branch/master) | [![Coverity Status](https://scan.coverity.com/projects/19334/badge.svg)](https://scan.coverity.com/projects/proxmark3-rrg-iceman-repo)| ![GitHub contributors](https://img.shields.io/github/contributors/rfidresearchgroup/proxmark3) |



# PROXMARK INSTALLATION AND OVERVIEW

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
||**[JTAG](/doc/jtag_notes.md)**||


## Notes / helpful documents

| Notes |||
| ------------------- |:-------------------:| -------------------:|
|[Notes on UART](/doc/uart_notes.md)|[Notes on Termux / Android](/doc/termux_notes.md)|[Notes on paths](/doc/path_notes.md)|
|[Notes on frame format](/doc/new_frame_format.md)|[Notes on tracelog / wireshark](/doc/trace_notes.md)|[Notes on EMV](/doc/emv_notes.md)|
|[Notes on external flash](/doc/ext_flash_notes.md)|[Notes on loclass](/doc/loclass_notes.md)|[Notes on Coverity Scan Config & Run](/doc/md/Development/Coverity-Scan-Config-and-Run.md)|
|[Notes on file formats used with Proxmark3](/doc/extensions_notes.md)|[Notes on MFU binary format](/doc/mfu_binary_format_notes.md)|[Notes on FPGA & ARM](/doc/fpga_arm_notes.md)|
|[Developing standalone mode](/armsrc/Standalone/readme.md)|[Wiki about standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode)|[Notes on Magic cards](/doc/magic_cards_notes.md)|
|[Notes on Color usage](/doc/colors_notes.md)|[Makefile vs CMake](/doc/md/Development/Makefile-vs-CMake.md)|[Notes on Cloner guns](/doc/cloner_notes.md)|
|[Notes on cliparser usage](/doc/cliparser.md)|||

## Build for non-RDV4 Proxmark3 platforms

In order to build this repo for other Proxmark3 platforms we urge you to read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)


## What has changed?

On the hardware side:

  * added flash memory 256kb.
  * added smart card module
  * added FPC connector

On the software side: quite a lot, see the [Changelog file](CHANGELOG.md).

## Development

> ⚠ **Note**: This is a bleeding edge repository. The maintainers actively is working out of this repository and will be periodically re-structuring the code to make it easier to comprehend, navigate, build, test, and contribute to, so **DO expect significant changes to code layout on a regular basis**.

This repo compiles nicely on 
   - Proxspace v3.x
     - [latest release v3.7](https://github.com/Gator96100/ProxSpace/releases)
   - Windows/mingw environment with Qt5.6.1 & GCC 4.9
   - Ubuntu 16.04 -> 20.04
   - ParrotOS, Gentoo, Pentoo, Kali, Nethunter, Archlinux, Fedora, Debian
   - Rasbian
   - Android / Termux
   - Mac OS X / Homebrew
   - WSL1  (Windows subsystem linux) on Windows 10
   - Docker container
      - [ RRG / Iceman repo based ubuntu 18.04 container ](https://hub.docker.com/r/secopsconsult/proxmark3)
      - [ Iceman fork based container v1.7 ](https://hub.docker.com/r/iceman1001/proxmark3/)

Hardware to run client on
   - PC
   - Android
   - Raspberry Pi & Raspberry Pi Zero
   - Nvidia Jetson Nano

## Precompiled binaries
We don't maintain any precompiled binaries in this repo. There is community effort over at the Proxmark3 forum where @gator96100 has set up a google drive with many mingw binaries which is up-to-date. We link to these files here as to make it easier for users.
If you are having troubles with these files, contact the package maintainer @gator96100 and read the [sticky thread at forum](http://www.proxmark.org/forum/viewtopic.php?pid=24763#p24763) where known issues has been documented.


Ref:
For Proxmark3 RDV4
- [Precompiled builds for RDV40 dedicated x86](https://drive.google.com/open?id=13zUs-aiQkYaSl5KWrBtuW5IWCoHJPsue)
- [Precompiled builds for RDV40 dedicated x64](https://drive.google.com/open?id=1SyPB8t5Vo8O0Lh7PjNm3Kv-mO4BNbxjX)

For Proxmark3 RDV4 with blueshark addon
- [Precompiled builds for RDV40 dedicated with Bluetooth addon x86](https://drive.google.com/open?id=1TqWYctkRvkLshQ1ZRBHPLDzYHR-asuMO)
- [Precompiled builds for RDV40 dedicated with Bluetooth addon x64](https://drive.google.com/open?id=17ful7u2QyYmMQzQzc5fAf8nJvyoDJfSL)

Generice Proxmark3 devices (non RDV4),  for Proxmark3 Easy,  RDV1, RDV2, RDV3, etc etc
- [Precompiled builds for RRG / Iceman repository x86](https://drive.google.com/open?id=1PI3Xr1mussPBPnYGu4ZjWzGPARK4N7JR)
- [Precompiled builds for RRG / Iceman repository x64](https://drive.google.com/open?id=1uX9RtYGinuFrpHybu4xq_BE3HrobI20e)


## Roadmap
The [public roadmap](https://github.com/RfidResearchGroup/proxmark3/wiki/Public-Roadmap) is an excellent start to read if you are interesting in contributing.

> 👉 **Remember!** If you intend to contribute to the code, please read the [coding style notes](HACKING.md) first.
We usually merge your contributions fast since we do like the idea of getting a functionality in the Proxmark3 and weed out the bugs afterwards.


## Issues & Troubleshooting
Please search the [issues](https://github.com/rfidresearchgroup/proxmark3/issues) page here and see if your issue is listed in the first instance.
Read the [Troubleshooting](/doc/md/Installation_Instructions/Troubleshooting.md) guide to weed out most known problems.

Next place to visit is the [Proxmark Forum](http://www.proxmark.org/forum/index.php). Learn to search it well and finally Google / duckduckgo is your friend :)    You will find many blogposts, youtube videos, tweets, reddit

### Offical channels
   - [Proxmark3 IRC channel](http://webchat.freenode.net/?channels=#proxmark3)
   - [Proxmark3 sub reddit](https://www.reddit.com/r/proxmark3/)
   - [Twitter](https://twitter.com/proxmark3/)
   - [Proxmark3 community discord server](https://discord.gg/zjxc8ZB)
 
 _no slack channel_

Iceman has quite a few videos on his [youtube channel](https://www.youtube.com/c/ChrisHerrmann1001)

## Cheat sheet

Thanks to Alex Dibs, you can enjoy a [command cheat sheet](/doc/cheatsheet.md)

## Maintainers ( package, distro )

To all distro, package maintainers, we tried to make your life easier. `make install` is now available and if you want to know more.
- [Maintainers](/doc/md/Development/Maintainers.md)

## Why didn't you base it on official Proxmark3 Master?

The separation from official Proxmark3 repo gives us a lot of freedom to create a firmware/client that suits the RDV40 features. We don't want to mess up the official Proxmark3 repo with RDV40 specific code.

## Proxmark3 GUI

The official PM3-GUI from Gaucho will not work.
The new [Proxmark3 Universal GUI](https://github.com/burma69/PM3UniversalGUI) will work more or less. Change is needed in order to show helptext when client isn't connected to a device.  We don't know how active the maintainers.

## The end

- July 2018 [@herrmann1001](https://mobile.twitter.com/herrmann1001)
- updated Feb 2019 [@5w0rdfish](https://mobile.twitter.com/5w0rdFish)
- updated 2019 [@doegox](https://mobile.twitter.com/doegox)

# Donations

Nothing says thank you as much as a donation. So if you feel the love, do feel free to become a iceman patron. For some tiers it comes with rewards.

https://www.patreon.com/iceman1001

