# RRG / Iceman repo - Proxmark3 RDV4.0 and other Proxmark3 platforms.

This repo is based on iceman fork for Proxmark3.  It supports other Proxmark3 platforms as well.

It is dedicated to bringing the most out of the new features for Proxmark3 RDV4.0 new hardware and design.


| Releases     | Linux & OSX CI       | Windows CI |
| ------------------- |:-------------------:| -------------------:|
| [![Latest release](https://img.shields.io/github/release/RfidResearchGroup/proxmark3.svg)](https://github.com/RfidResearchGroup/proxmark3/releases/latest) | [![Build status](https://travis-ci.org/RfidResearchGroup/proxmark3.svg?branch=master)](https://travis-ci.org/RfidResearchGroup/proxmark3) | [![Build status](https://ci.appveyor.com/api/projects/status/b4gwrhq3nc876cuu/branch/master?svg=true)](https://ci.appveyor.com/project/RfidResearchGroup/proxmark3/branch/master) |

---

# PROXMARK INSTALLATION AND OVERVIEW

| FAQ's & Updates     | Installation        | Use of the Proxmark |
| ------------------- |:-------------------:| -------------------:|
|[What has changed?](#what-has-changed)  | [Setup and build for Linux](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md) | [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)|
|[Development](#development) | [Important notes on ModemManager for Linux users](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md) | [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md) |
|[Why didn't you base it on official Proxmark3 Master?](#why-didnt-you-base-it-on-official-proxmark3-master)| [Homebrew (Mac OS X) & Upgrading HomeBrew Tap Formula](/doc/md/Installation_Instructions/Mac-OS-X-Homebrew-Installation-Instructions.md) | [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)|
|[Proxmark3 GUI](#proxmark3-gui)|[Setup and build for Windows](/doc/md/Installation_Instructions/Windows-Installation-Instructions.md)|[Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
|[Issues](#issues)|[Blue shark manual](/doc/bt_manual_v10.md) |[Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)|
|[Notes on UART](/doc/uart_notes.md)|[Maintainers](/doc/md/Development/Maintainers.md)|[Command Cheat sheet](/doc/cheatsheet.md)|
|[Notes on Frame format](/doc/new_frame_format.md)||[More cheat sheets](https://github.com/RfidResearchGroup/proxmark3/wiki/More-cheat-sheets)|
|[Notes on external flash](/doc/ext_flash_notes.md)||[EMV](/doc/emv_notes.md)|
|[Notes on Termux / Android](/doc/termux_notes.md)||[Troubleshooting](/doc/md/Installation_Instructions/Troubleshooting.md)|
|[Notes on Wireshark / tracedata](/doc/trace_wireshark_notes.md)||[JTAG](/doc/jtag_notes.md)|
|[Notes on loclass](/doc/loclass_notes.md)|||
|[Developing standalone mode](/armsrc/Standalone/readme.md)|[Wiki about standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode) ||
|[Donations](#Donations)|||

## Support on other Proxmark3 platforms

In order to build this repo for other Proxmark3 platforms we urge you to read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)

## What has changed?

On the hardware side:

  * added flash memory 256kb.
  * added smart card module
  * added FPC connector

On the software side: quite a lot, see the [Changelog file](CHANGELOG.md).

## Development

This repo now compiles just fine on 
   - Proxspace v3.2
   - Windows/mingw environment with Qt5.6.1 & GCC 4.8
   - Ubuntu 1404, 1510, 1604, 1804, 1904
   - Mac OS X / Homebrew
   - ParrotOS, Gentoo, Pentoo, Kali, Nethunter, Archlinux, Fedora
   - WSL, WSL2  (Windows subsystem linux) on Windows 10
   - Docker container

If you intend to contribute to the code, please read the [coding style notes](HACKING.md) first.

- Internal notes on [Coverity Scan Config & Run](/doc/md/Development/Coverity-Scan-Config-%26-Run.md).
- Internal notes on [UART](/doc/uart_notes.md)
- Internal notes on [Frame format](/doc/new_frame_format.md)
- Internal notes on [external flash](/doc/ext_flash_notes.md)
- Internal notes on [standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode)
- Internal notes on [Termux / Android](/doc/termux_notes.md)
- Internal notes on [Wireshark / tracedata](/doc/trace_wireshark_notes.md)
- Internal notes on [loclass](/doc/loclass_notes.md)
- Internal notes on [EMV](/doc/emv_notes.md)

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

It's needed to have a good USB cable to connect Proxmark3 to USB. If you have stability problems (Proxmark3 resets, firmware hangs, especially firmware hangs just after start, etc.) - check your cable with a USB tester (or try to change it). It needs to have a resistance smaller or equal to 0.3 Ohm.

## The end

- [@herrmann1001](https://mobile.twitter.com/herrmann1001) July 2018
- updated Feb 2019 [@5w0rdfish](https://mobile.twitter.com/5w0rdFish)

# Donations

Nothing says thank you as much as a donation. So if you feel the love, do feel free to become a iceman patron. For some tiers it comes with rewards.

https://www.patreon.com/iceman1001

All support is welcome!
