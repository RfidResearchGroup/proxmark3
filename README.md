# Proxmark3 RDV4.0 Dedicated Github

This repo is based on iceman fork for proxmark3. It is dedicated to bringing the most out of the new features for proxmark3 RDV4.0 new hardware and design.

[![Build status](https://ci.appveyor.com/api/projects/status/ct5blik2wa96bv0x/branch/master?svg=true)](https://ci.appveyor.com/project/iceman1001/proxmark3-ji4wj/branch/master)
[![Latest release](https://img.shields.io/github/release/RfidResearchGroup/proxmark3.svg)](https://github.com/RfidResearchGroup/proxmark3/releases/latest)

<a href="http://www.youtube.com/watch?feature=player_embedded&v=uyJ-y0kSWfc
" target="_blank"><img src="https://github.com/5w0rdfish/proxmark3/blob/master/prox.png" 
alt="Yuotube" width="100%" height="auto" border="10" /></a>

---

# PROXMARK INSTALLATION AND OVERVIEW

| FAQ's & Updates     | Installation        | Use of the Proxmark |
| ------------------- |:-------------------:| -------------------:|
|[What has changed?](#what-has-changed)  | [Setup and build for Linux](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md) | [Compilation Instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)|
|[Development](#development) | [Important notes on ModemManager for Linux users](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md) | [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md) |
|[Why didn't you base it on official PM3 Master?](#why-didnt-you-base-it-on-official-pm3-master)| [Homebrew (Mac OS X) & Upgrading HomeBrew Tap Formula](/doc/md/Installation_Instructions/Mac-OS-X-Homebrew-Installation-Instructions.md) | [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)|
|[PM3 GUI](#pm3-gui)|[Setup and build for Windows](/doc/md/Installation_Instructions/Windows-Installation-Instructions.md)|[Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)|
|[Issues](#issues)|[Blue shark](/doc/bt_manual_v10.md) ||
|[Donations](#Donations)|||

## What has changed?

On the hardware side:

  * added flash memory 256kb.
  * added smart card module
  * added FPC connector

On the software side: quite a lot, see the [Changelog file](CHANGELOG.md).

## Development
This fork now compiles just fine on 
   - Windows/mingw environment with Qt5.6.1 & GCC 4.8
   - Ubuntu 1404, 1510, 1604, 1804, 1904
   - Mac OS X / Homebrew
   - ParrotOS
   - WSL (Windows subsystem linux) on Windows 10
   - Docker container

If you intend to contribute to the code, please read the [coding style notes](HACKING.md) first.

Internal notes on [Coverity Scan Config & Run](/doc/md/Development/Coverity-Scan-Config-%26-Run.md).

---

## Why didn't you base it on official PM3 Master?

The separation from official pm3 repo gives us a lot of freedom to create a firmware/client that suits the RDV40 features. We don't want to mess up the official pm3 repo with RDV40 specific code.

## PM3 GUI
The official PM3-GUI from Gaucho will not work.
The new universal GUI will work. [Proxmark3 Universal GUI](https://github.com/burma69/PM3UniversalGUI) 

## Issues

Please see the [Proxmark Forum](http://www.proxmark.org/forum/index.php) and see if your issue is listed in the first instance Google is your friend :) Questions will be answered via the forum by Iceman and the team. 

It's needed to have a good USB cable to connect Proxmark3 to USB. If you have stability problems (Proxmark3 resets, firmware hangs, especially firmware hangs just after start, etc.) - check your cable with a USB tester (or try to change it). It needs to have a resistance smaller or equal to 0.3 Ohm.

## The end

- [@herrmann1001](https://mobile.twitter.com/herrmann1001) July 2018
- updated Feb 2019 [@5w0rdfish](https://mobile.twitter.com/5w0rdFish)

# Donations
Nothing says thank you as much as a donation,  https://www.patreon.com/iceman1001
