# Getting Started with the Proxmark5

## Contents

- [Assumptions](#Assumptions)
- [Makefile Changes](#Makefile-Changes)
- [Build](#Build)
- [Flashing](#Flashing)
- [Flash the Bootrom](#Flash-The-Bootrom)
- [Flash the Fullimage](#Flash-The-Fullimage)
- [Flash FPGA - No BWM](#Flash-The-FPGA)
- [Flash the FPGA and the BWM Together](#I-Have-A-BWM-Now-What)
- [DFU Install](#DFU-Install)
- [Build Extras](#Build-Extras)
- [Standalone Modes](#Standalone-Modes)
- [The Danger Zone](#Specific-commands)
- [Further Reading](#Links-to-Further-Reading)
---


## Assumptions
* If the BWM is connected, disconnect it for the first full flashing. (Bootrom and Fullimage)
* You have compiled the source before and your PM3 is or was working on the target machine previously.  (If not, start [here](https://github.com/RfidResearchGroup/proxmark3/tree/master#proxmark3-installation-and-overview) for your OS of choice.)



## Makefile Changes

Your `Makefile.platform` needs to specify `PM5` as your `PLATFORM` along with any `PLATFORM_EXTRAS` that are appropriate for your configuration.

Example:
```
PLATFORM=PM5
PLATFORM_EXTRAS=BWM
```

## Build

Clone/pull the latest master from this repo then

```
make clean
make -j
```

For more options, look [here](#Build-Extras)

## Flashing

### Flashing Considerations
* The same client can handle both Proxmark3 and Proxmark5, there is no need to compile separate clients if you own both pieces of hardware.
* Don't forget to [disable ModemManager](../Installation_Instructions/ModemManager-Must-Be-Discarded.md)
* There can be only one proxmark plugged into your PC.  Do not plug in both a pm3 and pm5 during flashing.


## Flash the Bootrom

* DO NOT use the USB Port on the side.
* DO use the USB Port on the same side as the button (Yellow)
* Put your Proxmark5 into *Boot Mode*.  Plug in your Proxmark5 while holding the button for about 4 seconds until you see 2 LEDs (B and D) illuminated.  You are now in *Boot Mode*.
* If you see 2 lights (B & D) go on and then OFF, you're in *DFU mode*.  Unplug, and try the previous step again.
* Run `./pm3-flash-bootrom`
  * If you see "🚨 The elf file is not applicable to the currently connected device.", you probably forgot to add `PLATFORM=PM5` in your `Makefile.platform`
  * `./pm3-flash-bootrom` uses the repo version.
  * `pm3-flash-bootrom` uses the system installed version.
  * Using the wrong version can throw unexpected errors for the Proxmark5 like these:
  * `[=] Permitted flash range: 0x08000000-0x08100000`
  * `[!!]  The elf file is not applicable to the currently connected device.`
* If the above hangs or thows and error, try this: [DFU Install](#DFU-Install)
* Unplug.

## Flash the FullImage
* Put your Proxmark5 into Boot Mode. (See above)
* Run `./pm3-flash-fullimage`


### Did you Proxmark5 come with a battery pre-installed?  Do this next:
* **IF AND ONLY IF** your Proxmark5 came with a battery pre-installed. 
* [Reinstall the BWM now](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32/blob/master/INSTALL.md)
* Let it charge for a while (about an hour should do)
* [Shut the Proxmark5 off](#Operation) and remove the BWM.

## Flash the FPGA

This writes `client/resources/fpga_pm5.bin` to the FPGA flash.
```
./pm3
script run update_fpga
```


## I Have A BWM Now What

### Install the BWM
* You acknowledge that the BWM is not yet fully supported.  It won't brick your Proxmark5, but bugs may still exist, and things may break.  If you need stability, it's currently recommended that you use your Proxmark3.  (If you insist... continue.)
* [Physically install the BWM and (if applicable) Battery](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32/blob/master/INSTALL.md)

## Flash the BWM and the FPGA Together
* Make sure your BWM has enough charge in the battery `hw status` 50%+ should work.
```
./pm3
script run update_fpga_and_bwm
```
* Run `hw status` and verify that `BWM fw version` matches this:
```
[#]   BWM fw version...... V4
```
  * You have finished flashing the FPGA and BWM.


### Operation
* Power on: Briefly pressing the button will wake the Proxmark5.
  * The RGB will turn green.
* Power off: Press and hold the button.
  * The LEDs will start running.
  * Releasing the button will power off the Proxmark5.


## DFU Install

### Prepare for DFU
* Install dfu-util
```
sudo apt-get install dfu-util
```


### DFU Mode
* Press and hold the button while plugging in the Proxmark5 to the USB port on the same side as the button.  You will know that you are in DFU Mode when the lights go off.  Continue to hold the button down the entire time you are running `dfu-util` commands.


### You're here because your Proxmark5 failed to flash or is unresponsive/won't enter *Boot Mode*.

* The Proxmark5 does not require J-Link or similar tools for unbricking.
* Put your Proxmark5 into [DFU Mode](#DFU-Mode)
* Backup the existing firmware ( technically optional )
```
sudo dfu-util -d 2e3c:df11 -a 0 -s 0x08000000:1048576 -U pm5-full-flash-backup.bin
```
* Flash All to recovery version
```
sudo dfu-util -d 2e3c:df11 -a 0 -s 0x08000000:leave -D recovery/recovery.bin
```
* Unplug
* If this is your first time through this document [Go back where you were in the process and continue from there.](#Flash-the-Bootrom)


### Windows Options

On Windows, you can try the following:
- Download and extract the [AT32 ISP Programmer](https://www.arterychip.com/file/download/1764)
- Install the USB driver present in `Artery_DFU_DriverInstall/`
- Enter DFU mode as explained above
- Open the `Artery ISP Programmer` , select `HEX` file to flash, and use the Bootrom & Fullimage is required.
- When flash done, disconnect usb and reconnect for restart device to exit ISP mode.
- Open the proxmark client to try to connect to verify your device is re-working.


##

## Build Extras
The Proxmark5 platform must be specified when compiling the firmware.
You have several options:
* Update your `Makefile.platform` with `PLATFORM=PM5` then `make -j`
* Specify it on-the-fly with `make -j PLATFORM=PM5`
* If you have both Proxmark3 and Proxmark5, you can maintain a separate file like `Makefile.pm5.platform` and specify it when compiling, with `make -j PLATFORM_FILE=Makefile.pm5.platform`.
* ⚠️ Make sure to not have any conflicting `PLATFORM_EXTRAS` such as `BTADDON` or `FPC_USART_DEV` which are specific to the RDV4.


## Standalone Modes

Standalone modes are disabled for now, to ease debugging.

## Specific commands

Do not use them unless you fully understand what you're doing.

* `hw fpga config`: to upload the FPGA firmware
* `hw fpga pwrpwm`: to adjust the antenna's drive voltage TODO: acceptable ranges?
* `hw ant_pm5 -m --set <8bit data>` command can be used to modify the frequency and Q value. Note: High Q is only allowed at 125kHz/134kHz to prevent excessive resonant voltage from damaging the device.
  > 8bit map: 125 134 250 375 500 HFLED LFLED Q (lsb)
* `hw qc_pm5`: factory quality check command, will activate the RBG, the buzzer and the antenna LEDs. Press the button to report success. Use `-t/--timeout <s>` to change how long the test sequence runs before it fails (default 20 seconds).
* `hw factorydata`: read/write the factory data (originality signature etc)


## Links to Further Reading
- [BWM Usage Document](./PM5-BWM-USAGE.md)
- [PM5 ANT Controller](./PM5_Controllers/PM5_ANT_Controller_RM.md)
- [PM5 Button Controller](./PM5_Controllers/PM5_Button_Controller_RM.md)
- [PM5 RGB Controller](./PM5_Controllers/PM5_RGB_Controller_RM.md)
- [PM5 BWM Install](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32/blob/master/INSTALL.md)
- [PM5 <--> Flipper Usage](./PM5-FLIPPER-USAGE.md)
- [Compile the FPGA Image From Source](./Compiling_the_FGPA.md)
