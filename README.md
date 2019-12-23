# RRG / Iceman repo - Proxmark3


| Releases     | Linux & OSX CI       | Windows CI | Coverity    |
| ------------------- |:-------------------:| -------------------:| -------------------:|
| [![Latest release](https://img.shields.io/github/release/RfidResearchGroup/proxmark3.svg)](https://github.com/RfidResearchGroup/proxmark3/releases/latest) | [![Build status](https://travis-ci.org/RfidResearchGroup/proxmark3.svg?branch=master)](https://travis-ci.org/RfidResearchGroup/proxmark3) | [![Build status](https://ci.appveyor.com/api/projects/status/b4gwrhq3nc876cuu/branch/master?svg=true)](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/branch/master) | [![Coverity Status](https://scan.coverity.com/projects/19334/badge.svg)](https://scan.coverity.com/projects/proxmark3-rrg-iceman-repo)|



# PROXMARK INSTALLATION AND OVERVIEW

| FAQ's & Updates     | Installation        | Use of the Proxmark |
| ------------------- |:-------------------:| -------------------:|
|[What has changed?](#what-has-changed)  | [Setup and build for Linux](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md) | [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)|
|[Development](#development) | [Important notes on ModemManager for Linux users](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md) | [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md) |
|[Why didn't you base it on official Proxmark3 Master?](#why-didnt-you-base-it-on-official-proxmark3-master)| [Homebrew (Mac OS X) & Upgrading HomeBrew Tap Formula](/doc/md/Installation_Instructions/Mac-OS-X-Homebrew-Installation-Instructions.md) | [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)|
|[Proxmark3 GUI](#proxmark3-gui)|[Setup and build for Windows](/doc/md/Installation_Instructions/Windows-Installation-Instructions.md)|[Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
|[Issues](#issues)|[Blue shark manual](/doc/bt_manual_v10.md) |[Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)|
|[Notes on UART](/doc/uart_notes.md)|[Maintainers](/doc/md/Development/Maintainers.md)|[Command Cheat sheet](/doc/cheatsheet.md)|
|[Notes on frame format](/doc/new_frame_format.md)||[More cheat sheets](https://github.com/RfidResearchGroup/proxmark3/wiki/More-cheat-sheets)|
|[Notes on external flash](/doc/ext_flash_notes.md)||[EMV](/doc/emv_notes.md)|
|[Notes on Termux / Android](/doc/termux_notes.md)||[Troubleshooting](/doc/md/Installation_Instructions/Troubleshooting.md)|
|[Notes on wireshark / tracedata](/doc/trace_wireshark_notes.md)||[JTAG](/doc/jtag_notes.md)|
|[Notes on loclass](/doc/loclass_notes.md)|||
|[Notes on paths](/doc/path_notes.md)|||
|[Developing standalone mode](/armsrc/Standalone/readme.md)|[Wiki about standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode) ||
|[Donations](#Donations)|||


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
   - Proxspace v3.2
   - Windows/mingw environment with Qt5.6.1 & GCC 4.8
   - Ubuntu 1404, 1510, 1604, 1804, 1904
   - Mac OS X / Homebrew
   - ParrotOS, Gentoo, Pentoo, Kali, Nethunter, Archlinux, Fedora
   - WSL, WSL2  (Windows subsystem linux) on Windows 10
   - Docker container

The [public roadmap](https://github.com/RfidResearchGroup/proxmark3/wiki/Public-Roadmap) is an excellent start to read if you are interesting in contributing.

> 👉 **Remember!** If you intend to contribute to the code, please read the [coding style notes](HACKING.md) first.
We usually merge your contributions fast since we do like the idea of getting a functionality in the Proxmark3 and weed out the bugs afterwards.

## Notes / helpful documents
- notes on [Coverity Scan Config & Run](/doc/md/Development/Coverity-Scan-Config-%26-Run.md).
- notes on [UART](/doc/uart_notes.md)
- notes on [Frame format](/doc/new_frame_format.md)
- notes on [external flash](/doc/ext_flash_notes.md)
- notes on [standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode)
- notes on [Termux / Android](/doc/termux_notes.md)
- notes on [Wireshark / tracedata](/doc/trace_wireshark_notes.md)
- notes on [loclass](/doc/loclass_notes.md)
- notes on [EMV](/doc/emv_notes.md)
- notes on [Paths](/doc/path_notes.md)
- notes on [file formats used with Proxmark3](/doc/extensions_notes.md)
## Cheat sheet

Thanks to Alex Dibs, you can enjoy a [command cheat sheet](/doc/cheatsheet.md)

## Maintainers ( package, distro )

To all distro, package maintainers, we tried to make your life easier. `make install` is now available and if you want to know more.
- [Maintainers](/doc/md/Development/Maintainers.md)

## Why didn't you base it on official Proxmark3 Master?

The separation from official Proxmark3 repo gives us a lot of freedom to create a firmware/client that suits the RDV40 features. We don't want to mess up the official Proxmark3 repo with RDV40 specific code.

## Proxmark3 GUI

The official PM3-GUI from Gaucho will not work.
The new universal GUI will work. [Proxmark3 Universal GUI](https://github.com/burma69/PM3UniversalGUI) Almost, change needed in order to show helptext when client isn't connected to a device.

## Issues

Please see the [Proxmark Forum](http://www.proxmark.org/forum/index.php) and see if your issue is listed in the first instance Google is your friend :) Questions will be answered via the forum by Iceman and the team. 

Read the [Troubleshooting](/doc/md/Installation_Instructions/Troubleshooting.md) guide to weed out most known problems.


## The end

- July 2018 [@herrmann1001](https://mobile.twitter.com/herrmann1001)
- updated Feb 2019 [@5w0rdfish](https://mobile.twitter.com/5w0rdFish)
- updated 2019 [@doegox](https://mobile.twitter.com/doegox)

# Donations

Nothing says thank you as much as a donation. So if you feel the love, do feel free to become a iceman patron. For some tiers it comes with rewards.

https://www.patreon.com/iceman1001

