# Getting Started with the Proxmark5

## Contents

- [Assumptions](#Assumptions)
- [Makefile Changes](#Makefile-Changes)
- [Build](#Build)
- [Flash Bootrom](#Flash-Bootrom)
- [Flash Fullimage](#Flash-Fullimage)
- [Flash FPGA](#Flash-FPGA)


- [Build Extras](#Build-Extras)


- [1. Battery / BWM control](#1-battery--bwm-control)
- [2. BLE](#2-ble)
- [3. WiFi](#3-wifi)
- [Notes](#notes)

---



## Assumptions
* If the BWM is connected, disconnect it for the first full flashing. (bootrom and fullimage)
* You have compiled the source before and your PM3 is or was working on the target machine previously.  (If not, start [here](https://github.com/RfidResearchGroup/proxmark3/tree/master#proxmark3-installation-and-overview) for your OS of choice.)



## Makefile Changes

Your Makefile.platform should needs to specify PM5 as your PLATFORM along with any PLATFORM_EXTRAS that are appropriate for your configuration.

Example:
```
PLATFORM=PM5
PLATFORM_EXTRAS=BWM
```

## Build

* clone/pull the latest master from this repo then

```make clean
make -j
```

For more options, look [here](#Build-Extras)

## Flash Bootrom

### Flashing Considerations
* The same client can handle both Proxmark3 and Proxmark5, no need to compile separate clients if you own both hardwares.
* Don't forget to [disable ModemManager](../Installation_Instructions/ModemManager-Must-Be-Discarded.md)
* There can be only one proxmark plugged into your PC.  Do not plug in both a pm3 and pm5 during flashing.


## Flash the Bootrom

* DO use the USB Port on the same side as the button (Yellow)
* DO NOT use the USB Port on the side.
* Put your Proxmark into Boot Mode.  Plug in your Proxmark5 while holding the button for about 4 seconds until you see 2 LEDs illuminated (B and D) You are now in Boot Mode.
* If you see 2 lights (B & D) go on and then off, you're in DFU mode.  Unplug, and try the previous step again.


Use the yellow USB-C on the same side as the button.

You'll first need to update the bootrom with the latest code available on the repository.
The bootrom in your device is not yet able to enter automatically the boot mode properly, so you will have to enter boot mode manually as follows, a procedure slightly different from the Proxmark3.

* Plug in your Proxmark5 while holding the button for about 4 seconds until you see 2 LEDs illuminated (B and D). Don't wait too long. If the LEDs are now off again, you entered DFU mode. Unplug and try again.

* Run `./pm3-flash-bootrom`
* Unplug.
* Plug in your Proxmark5 while holding the button for about 4 seconds until you see 2 LEDs illuminated (B and D).
* Run `./pm3-flash-fullimage`

⚠️ In case your battery came pre-installed, we recommend to plug it back, connect the client, run `hw status` and check the charge level (line `Battery SoC`). If very low, let it charge for a while. Then shut the Proxmark5 off and remove the BWM.

Next, follow [FPGA flashing instuctions](#fpga-flashing-instructions).

### Devices with a firmware > 2026-08-20

With the new bootrom, you don't need to enter manually the boot mode by pressing the button anymore and the flashing experience will be as smooth as on the Proxmark3.

* Use the yellow USB-C on the same side as the button.

* Run `./pm3-flash-fullimage` to update the main image, and occasionally `./pm3-flash-bootrom` if needed.

If you see "🚨 The elf file is not applicable to the currently connected device.", you probably forgot to add the `PLATFORM=PM5` when compiling.

If the main image gets seriously buggy and can't jump to boot mode automatically, you can enter boot mode using the button as explained in [the previous section](#new-devices-with-factory-firmware).

If the device seems unresponsive and unable to enter boot mode when the button is pressed when plugged, you can [reflash the bootrom over DFU](#recovery-flashing-via-dfu).

## FPGA flashing instructions

The FPGA code for the Proxmark5 has not yet been pushed to the repository. To flash the FGPA with the latest image:

```
wget https://github.com/user-attachments/files/31105593/PM5_FPGA_fix_loedge_bug.zip
unzip PM5_FPGA_fix_loedge_bug.zip
./pm3
hw fpga config -f PM5_FPGA_fix_loedge_bug.bin
hf 14a read --drop
```

## Specific commands

Do not use them unless you fully understand what you're doing.

* `hw fpga config`: to upload the FPGA firmware
* `hw fpga pwrpwm`: to adjust the antenna's drive voltage TODO: acceptable ranges?
* `hw ant_pm5 -m --set <8bit data>` command can be used to modify the frequency and Q value. Note: High Q is only allowed at 125kHz/134kHz to prevent excessive resonant voltage from damaging the device.
  > 8bit map: 125 134 250 375 500 HFLED LFLED Q (lsb)
* `hw qc_pm5`: factory quality check command, will activate the RBG, the buzzer and the antenna LEDs. Press the button to report success. Use `-t/--timeout <s>` to change how long the test sequence runs before it fails (default 20 seconds).
* `hw factorydata`: read/write the factory data (originality signature etc)

## Standalone Modes

Standalone modes are disabled for now, to ease debugging.

## BWM aka Battery Wireless Module

⚠️ the BWM is not yet fully supported, it's better not to plug it for now.

* [Installation instructions](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32/blob/master/INSTALL.md)
* The very first time, run ` hw bwmsetcap --cap 500` and do a full charge/discharge cycle for it to learn the real capacity
* Pressing briefly the button will wake the device. The RGB will turn green
* When the device is powered on, pressing and holding the button for a few seconds will start displaying a running light, and then releasing the button will power off the device

## Recovery flashing via DFU

If the device seems unresponsive and unable to enter boot mode when the button is pressed when plugged, you can reflash the bootrom over DFU. The Proxmark5 does not require J-Link or similar tools for unbricking.

```sudo apt install dfu-util```

Enter DFU mode: Plug in your Proxmark5 while holding the button for about 8 seconds until you see 2 LEDs (B and D) going on then off.

Backup current flash content, if needed:

```sudo dfu-util -d 2e3c:df11 -a 0 -s 0x08000000:1048576 -U pm5-full-flash-backup.bin```

Flash bootrom:

```sudo dfu-util -d 2e3c:df11 -a 0 -s 0x08000000       -D recovery/bootrom.bin```

Flash fullimage:

```sudo dfu-util -d 2e3c:df11 -a 0 -s 0x08004000:leave -D recovery/fullimage.bin```

You can also flash bootrom and fullimage in one go:

```sudo dfu-util -d 2e3c:df11 -a 0 -s 0x08000000:leave -D recovery/recovery.bin```


On Windows, you can try the following:
- Download and extract the [AT32 ISP Programmer](https://www.arterychip.com/file/download/1764)
- Install the USB driver present in `Artery_DFU_DriverInstall/`
- Enter DFU mode as explained above
- Open the `Artery ISP Programmer` , select `HEX` file to flash, and use the bootrom & fullimage is required.
- When flash done, disconnect usb and reconnect for restart device to exit ISP mode.
- Open the proxmark client to try to connect to verify your device is re-working.


## Build Extras
The Proxmark5 platform must be specified when compiling the firmware.
You have several options:
* Update your `Makefile.platform` with `PLATFORM=PM5` then `make -j`
* Specify it on-the-fly with `make -j PLATFORM=PM5`
* If you have both Proxmark3 and Proxmark5, you can maintain a separate file like `Makefile.pm5.platform` and specify it when compiling, with `make -j PLATFORM_FILE=Makefile.pm5.platform`.
* ⚠️ Make sure to not have any conflicting `PLATFORM_EXTRAS` such as `BTADDON` or `FPC_USART_DEV` which are specific to the RDV4.




### New devices with factory firmware

The factory firmware has some limitations, therefore the flashing procedure is slightly more complex.

⚠️ If you have a BWM (Battery Wireless Module), and if it came already plugged, disconnect it. See [here](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32/blob/master/INSTALL.md) to understand how it's installed. The reason it came connected when delivered to some countries is customs regulations. But hte factory firmware does not support it and this creates issues when flashing, so just remove it.

