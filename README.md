# Iceman Fork - Proxmark3

The Proxmark3 is the swiss-army tool of RFID, allowing for interactions with the vast majority of RFID tags on a global scale. Originally built by Jonathan Westhues, the device is now the goto tool for RFID Analysis for the enthusiast. Iceman repository is considered to be the pinnacle of features and functionality, enabling a huge range of extremely useful and convenient commands and LUA scripts to automate chip identification, penetration testing, and programming


| Latest Release | Coverity | Contributors |
|:--------------:|:--------:|:------------:|
| [![Latest release](https://img.shields.io/github/v/release/rfidresearchgroup/proxmark3)](https://github.com/RfidResearchGroup/proxmark3/releases/latest) | [![Coverity Status](https://scan.coverity.com/projects/19334/badge.svg)](https://scan.coverity.com/projects/proxmark3-rrg-iceman-repo)| ![GitHub contributors](https://img.shields.io/github/contributors/rfidresearchgroup/proxmark3) |


| Actions OSX CI |  Actions Ubuntu CI | Actions Windows CI |
|:--------------:|:------------------:|:------------------:|
| ![MacOS Build and Test](https://github.com/RfidResearchGroup/proxmark3/workflows/MacOS%20Build%20and%20Test/badge.svg?branch=master) | ![Ubuntu Build and Test](https://github.com/RfidResearchGroup/proxmark3/workflows/Ubuntu%20Build%20and%20Test/badge.svg?branch=master) | [![Windows Build and Test](https://github.com/RfidResearchGroup/proxmark3/actions/workflows/windows.yml/badge.svg?branch=master)](https://github.com/RfidResearchGroup/proxmark3/actions/workflows/windows.yml) |


# Table of Contents
 1. [PROXMARK3 INSTALLATION AND OVERVIEW](#proxmark3-installation-and-overview)
 2. [Notes / helpful documents](#notes--helpful-documents)
 3. [How to build?](#how-to-build)
     1. [Proxmark3 RDV4](#proxmark3-rdv4)
     2. [Generic Proxmark3 platforms](#generic-proxmark3-platforms)
 4. [What has changed?](#what-has-changed)
 5. [Development](#development)
 6. [Supported operative systems](#supported-operative-systems)
 7. [Precompiled binaries](#precompiled-binaries)
 8. [Proxmark3 GUI](#proxmark3-gui)
 9. [Official channels](#official-channels)
10. [Maintainers](#maintainers)
11. [Citation](#citation)
12. [Copyright and licensing terms](#copyright-and-licensing-terms)

# PROXMARK3 INSTALLATION AND OVERVIEW

| Installation         | Use of the Proxmark3 |
| :------------------: | :------------------: |
| [Linux - Setup and Build](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md) | [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)|
| [Linux - Important notes on ModemManager](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md) | [Validating Proxmark3 Client Functionality](/doc/md/Use_of_Proxmark/1_Validation.md)|
| [macOS - Homebrew & Upgrading HomeBrew Tap Formula](/doc/md/Installation_Instructions/macOS-Homebrew-Installation-Instructions.md) | [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)|
| [macOS - MacPorts](/doc/md/Installation_Instructions/macOS-MacPorts-Installation-Instructions.md) | [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
| [macOS - Setup and Build](/doc/md/Installation_Instructions/macOS-Compile-From-Source-Instructions.md) ||
| [Windows - Setup and Build](/doc/md/Installation_Instructions/Windows-Installation-Instructions.md) ||
| [Termux / Android - Setup and Build](/doc/termux_notes.md) ||
| [Blue Shark Manual](/doc/bt_manual_v10.md) | [Command Cheat Sheet](/doc/cheatsheet.md)|
| [Advanced Compilation Parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md) | [More Cheat Sheets](https://github.com/RfidResearchGroup/proxmark3/wiki/More-cheat-sheets)|
| [Troubleshooting](/doc/md/Installation_Instructions/Troubleshooting.md) | [Complete Client Command Set](/doc/commands.md) |
| [JTAG](/doc/jtag_notes.md) | [T5577 Introduction Guide](/doc/T5577_Guide.md)|



## Notes / helpful documents

| Notes |||
| ------------------- |:-------------------:| -------------------:|
|[Notes on UART](/doc/uart_notes.md)|[Notes on Termux / Android](/doc/termux_notes.md)|[Notes on paths](/doc/path_notes.md)|
|[Notes on frame format](/doc/new_frame_format.md)|[Notes on tracelog / wireshark](/doc/trace_notes.md)|[Notes on EMV](/doc/emv_notes.md)|
|[Notes on external flash](/doc/ext_flash_notes.md)|[Notes on loclass](/doc/loclass_notes.md)|[Notes on Coverity Scan Config & Run](/doc/md/Development/Coverity-Scan-Config-and-Run.md)|
|[Notes on file formats used with Proxmark3](/doc/extensions_notes.md)|[Notes on MFU binary format](/doc/mfu_binary_format_notes.md)|[Notes on FPGA & ARM](/doc/fpga_arm_notes.md)|
|[Developing standalone mode](/armsrc/Standalone/readme.md)|[Wiki about standalone mode](https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode)|[Notes on Magic UID cards](/doc/magic_cards_notes.md)|
|[Notes on Color usage](/doc/colors_notes.md)|[Makefile vs CMake](/doc/md/Development/Makefile-vs-CMake.md)|[Notes on Cloner guns](/doc/cloner_notes.md)|
|[Notes on cliparser usage](/doc/cliparser.md)|[Notes on clocks](/doc/clocks.md)|[Notes on MIFARE DESFire](/doc/desfire.md)|
|[Notes on CIPURSE](/doc/cipurse.md)|[Notes on NDEF type4a](/doc/ndef_type4a.md)||

# How to build?

## Proxmark3 RDV4

See the instruction links in the tables above to build, flash and run for your Proxmark3 RDV4 device.

## Generic Proxmark3 platforms

In order to build this repo for generic Proxmark3 platforms we urge you to read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)

We define generic Proxmark3 platforms as following devices.

**Supported**
  - RDV1, RDV2, RDV3 easy
  - Ryscorp green PCB version
  - Radiowar black PCB version
  - numerous Chinese adapted versions of the RDV3 easy (kkmoon, PiSwords etc)

**Not supported**
 - ⚠  Proxmark Evolution (EVO) 
   - **Note**: unknown pin assignments.
 - ⚠  Ryscorp Proxmark3 Pro 
   - **Note**: device has different fpga and unknown pin assignments.
   - **Note**: Company have disappeared, leaving their customers in the dark.
 - ⚠  iCopy-X
   - **Note**: experimental support, currently incompatible with iCopy-X GUI as Proxmark client commands are now using cliparser.
   - **Note**: see also [icopyx-community repos](https://github.com/iCopy-X-Community/) for upstream sources, reversed hw etc.
   - **Note**: Uses DRM to lock down tags, ignores the open source licences. Use on your own risk. 

**Unknown support status**
 - ⚠  VX
   - **Note**: unknown device hw
-  ⚠ Proxmark3 X 
   - **Note**: unknown device hw
-  ⚠ Proxmark3 Ultimate
   - **Note**: unknown device hw
-  ⚠ Proxmark3 SE
   - **Note**: unknown device hw

When it comes to these new unknown models we are depending on the community to report in if this repo works and what they did to make it work.


**256KB flash memory size of generic Proxmark3 platforms**

> ⚠ **Note**: 
> You need to keep a eye on how large your ARM chip built-in flash memory is. 
> With 512KB you are fine but if its 256KB you need to compile this repo with even less functionality.
> When running the `./pm3-flash-all` you can see which size your device have if you have the bootloader from this repo installed. 
> Otherwise you will find the size reported in the start message when running the Proxmark3 client `./pm3`.
>
> [OBS! Read the 256KB flash memory advisory](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md#256KB-versions)


# What has changed?

Proxmark3 RDV4 hardware modifications:
  * added flash memory 256KB
  * added smart card module
  * added FPC connector for peripherals such as Bluetooth+battery addon
  * improved antennas
    * swappable
    * LF Q factor switch
    * LF 125/134 frequency switch
  * tiny PCB form factor
  * ABS case

This repo vs official Proxmark3 repo:

See the [Changelog file](CHANGELOG.md) which we try to keep updated.

In short this repo gives you a completely different user experience when it comes to Proxmark3.

  * Supports command tab complete
  * Richer CLI with use of colors / emojis
  * Help text system implemented everywhere
  * Hints system
  * User preference settings
  * Extensive testing with continuous integration build systems on Linux, OSX and Windows, and regular usage of static analysis tools like 
    * [Coverity Scan](https://scan.coverity.com/projects/proxmark3-rrg-iceman-repo/)
    * Cppcheck (v2.6)
    * GCC and Clang aggressive enforcement of diagnostic flags
  * Auto detection of serial ports and seamless integration with Bluetooth addon
  * Reconnect to device from inside client
  * Supports tearoff attacks
  * Supports NFC NDEF type1, type2, type4a, type4b, mifare, barcode
  * Supports pm3 client scripts,  lua scripts,  python scripts
  * Most comprehensive collection of scripts available
  * Wiegand encoding, decoding.
  * Supports EMV
  * Supports CIPURSE
  * Most standalone modes available with easy compilation
  * Extensive test script for client and external tools
  * Most comprehensive compiled known keys dictionaries
  * Slimed down usb communications with NG-frames
  * The most compiled public known key recovery software
  * The fastest implementations of said software
  * Support multiple fileformats for dump files (BIN/EML/JSON) 
  * Interoperability of said fileformats with libnfc, MFC tool app etc
  * Supports more RFID based protocols than ever
  * Easy install for package maintainers, distro maintainers
  * Supports cmake, make
  * Builds without errors or warnings on more OS/platforms than ever
  * Available as package on known distros like Gentoo, Kali, Termux, Macports, Homebrew
  * Much more documentation 


# Development

> ⚠ **Note**: This is a bleeding edge repository. The maintainers actively is working out of this repository and will be periodically re-structuring the code to make it easier to comprehend, navigate, build, test, and contribute to, so **DO expect significant changes to code layout on a regular basis**.

> 👉 **Remember!** If you intend to contribute to the code, please read the [coding style notes](CONTRIBUTING.md) first.
We usually merge your contributions fast since we do like the idea of getting a functionality in the Proxmark3 and weed out the bugs afterwards.

The [public roadmap](https://github.com/RfidResearchGroup/proxmark3/wiki/Public-Roadmap) is an excellent start to read if you are interesting in contributing.


## Supported operative systems 

This repo compiles nicely on 
   - WSL1 on Windows 10
   - Proxspace environment [release v3.10](https://github.com/Gator96100/ProxSpace/releases)
   - Windows/MinGW environment
   - Ubuntu, ParrotOS, Gentoo, Pentoo, Kali, NetHunter, Arch Linux, Fedora, Debian, Raspbian
   - Android / Termux
   - macOS / Homebrew (or MacPorts, experimental) / Apple Silicon M1
   - Docker container
      - [ Iceman repo based ubuntu 18.04 container ](https://hub.docker.com/r/secopsconsult/proxmark3)
      - [ Iceman fork based container v1.7 ](https://hub.docker.com/r/iceman1001/proxmark3/)


## Precompiled binaries

See [Proxmark3 precompiled builds](https://www.proxmarkbuilds.org/) 


## Proxmark3 GUI

The official PM3-GUI from Gaucho will not work. Not to mention is quite old and not maintained any longer.

- [Proxmark3 Universal GUI](https://github.com/burma69/PM3UniversalGUI) will work more or less.
- [Proxmark3 GUI cross-compiled](https://github.com/wh201906/Proxmark3GUI/) which is recently updated and claims to support latest source of this repo.
- [Proxmark3_GUI](https://github.com/Phreak87/Proxmark3_GUI) simple gui in vb.net


## Official channels
Where do you find the community?
   - [RFID Hacking community discord server](https://t.ly/d4_C)
   - [Proxmark3 IRC channel](https://web.libera.chat/?channels=#proxmark3)
   - [Proxmark3 sub reddit](https://www.reddit.com/r/proxmark3/)
   - [Proxmark3 forum](http://www.proxmark.org/forum/index.php)


## Maintainers

To all distro, package maintainers, we tried to make your life easier.

`make install` is now available and if you want to know more.

This document will be helpful for you
- [Notes for maintainers](/doc/md/Development/Maintainers.md)


## Citation
Use this bibtex to cite this repository globally:
```
@misc{proxmark3,
  author = {C. {Herrmann} and P. {Teuwen} and O. {Moiseenko} and M. {Walker} and others},
  title = {{Proxmark3 -- Iceman repo}},
  howpublished = {\url{https://github.com/RfidResearchGroup/proxmark3}},
  keywords = {rfid nfc iceman proxmark3 125khz 134khz 13.56mhz},
}
```
If you need to refer to a specific state of the repository, use a commit number or a date of access, e.g.:
```
  note = {Accessed: commit 12327f71a27da23831901847886aaf20e8ad3ca0}
  note = {Accessed: 2021-01-01}
```

## Copyright and licensing terms

Each contribution is under the copyright of its author. See [AUTHORS](AUTHORS.md).

The Proxmark3 source code is covered by the following licensing terms, usually referred as **GPLv3 or later**.

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

A copy of the GPLv3 is available in [LICENSE](LICENSE.txt).  

Some dependencies may be under other free licensing terms compatible with the Proxmark3 licensing terms, see their respective description.
