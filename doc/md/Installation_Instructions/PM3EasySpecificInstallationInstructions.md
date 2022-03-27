# Installation tips and tricks for the Proxmark3 Easy devices

## Installation instructions on MacOS (with Homebrew)

See the documentation for the generic version of the Homebrew install of the 
[Proxmark3 suite here](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Mac-OS-X-Homebrew-Installation-Instructions.md#install-proxmark3-tools).

## Installation instructions from source (Linux and other OS)

On MacOSX, see 
[this document](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Mac-OS-X-Compile-From-Source-Instructions.md). 
For Linux and other Unix platforms, see 
[this document](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/md/Installation_Instructions/Linux-Installation-Instructions.md). 
The key point is to run ``cp Makefile.platform.sample Makefile.platform`` and edit ``Makefile.platform`` to look something (not exactly) like the following:
```make
# If you want to use it, copy this file as Makefile.platform and adjust it to your needs
# Run 'make PLATFORM=' to get an exhaustive list of possible parameters for this file.

#PLATFORM=PM3RDV4
PLATFORM=PM3GENERIC
# If you want more than one PLATFORM_EXTRAS option, separate them by spaces:
#PLATFORM_EXTRAS=BTADDON
#STANDALONE=LF_SAMYRUN

# To accelerate repetitive compilations:
# Install package "ccache" -> Debian/Ubuntu: /usr/lib/ccache, Fedora/CentOS/RHEL: /usr/lib64/ccache
# And uncomment the following line
#export PATH := /usr/lib64/ccache:/usr/lib/ccache:${PATH}
```

## Flashing the device

A key detail that is not widely publicized on the manufacturer's (DangerousThings™) discussion boards came up recently 
in [this issue thread](https://github.com/RfidResearchGroup/proxmark3/issues/1616). 
A known way to flash the firmware is as follows after installing and building the ``PM3GENERIC`` firmware binaries for your OS as above 
__**while holding down the PM3 button during the entire flashing process**__:
```bash
pm3-flash-bootrom && pm3-flash-all && pm3
```
If something goes awry, you may see error messages approximately like (on MacOS for the logs below)
```bash
$ pm3-flash-all
[=] Session log /Users/localusernameredacted/.proxmark3/logs/log_20220302.txt
[+] loaded from JSON file /Users/localusernameredacted/.proxmark3/preferences.json
[+] About to use the following files:
[+]    /usr/local/Cellar/proxmark3/HEAD-ab52131/bin/../share/proxmark3/firmware/bootrom.elf
[+]    /usr/local/Cellar/proxmark3/HEAD-ab52131/bin/../share/proxmark3/firmware/fullimage.elf
[+] Loading ELF file /usr/local/Cellar/proxmark3/HEAD-ab52131/bin/../share/proxmark3/firmware/bootrom.elf
[+] ELF file version Iceman/master/v4.14831-404-gab5213126 2022-03-02 05:49:24 ea44b0c23

[+] Loading ELF file /usr/local/Cellar/proxmark3/HEAD-ab52131/bin/../share/proxmark3/firmware/fullimage.elf
[+] ELF file version Iceman/master/v4.14831-404-gab5213126 2022-03-02 05:49:38 ea44b0c23

[+] Waiting for Proxmark3 to appear on /dev/tty.usbmodem14601
 🕑  59 found
[+] Entering bootloader...
[+] (Press and release the button only to abort)
[+] Waiting for Proxmark3 to appear on /dev/tty.usbmodem14601
 🕓  59 found
[!!] 🚨 ====================== OBS ! ===========================================
[!!] 🚨 Note: Your bootloader does not understand the new CMD_BL_VERSION command
[!!] 🚨 It is recommended that you first update your bootloader alone,
[!!] 🚨 reboot the Proxmark3 then only update the main firmware


[!!] 🚨 ------------- Follow these steps -------------------

[!!] 🚨  1)   ./pm3-flash-bootrom
[!!] 🚨  2)   ./pm3-flash-all
[!!] 🚨  3)   ./pm3

[=] ---------------------------------------------------

[=] Available memory on this board: UNKNOWN

[!!] 🚨 ====================== OBS ! ======================================
[!!] 🚨 Note: Your bootloader does not understand the new CHIP_INFO command
[=] Permitted flash range: 0x00100000-0x00140000
[!!] 🚨 ====================== OBS ! ========================================
[!!] 🚨 Note: Your bootloader does not understand the new START_FLASH command
[+] Loading usable ELF segments:
[+]    0: V 0x00100000 P 0x00100000 (0x00000200->0x00000200) [R X] @0x94
[+]    1: V 0x00200000 P 0x00100200 (0x00000d1c->0x00000d1c) [R X] @0x298

[+] Loading usable ELF segments:
[+]    1: V 0x00102000 P 0x00102000 (0x0003ff3c->0x0003ff3c) [R X] @0xb8
[!!] 🚨 Error: PHDR is not contained in Flash
[!!] 🚨 Firmware is probably too big for your device
[!!] 🚨 See README.md for information on compiling for platforms with 256KB of flash memory
[!] ⚠️  The flashing procedure failed, follow the suggested steps!
[+] All done

[=] Have a nice day!
```
