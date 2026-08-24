# Proxmark5 specificities

## Compiling instructions

The Proxmark5 platform must be specified when compiling the firmware.
You have several options:
* Update your `Makefile.platform` with `PLATFORM=PM5` then `make -j`
* Specify it on-the-fly with `make -j PLATFORM=PM5`
* If you have both Proxmark3 and Proxmark5, you can maintain a separate file like `Makefile.pm5.platform` and specify it when compiling, with `make -j PLATFORM_FILE=Makefile.pm5.platform`.
* ⚠️ Make sure to not have any conflicting `PLATFORM_EXTRAS` such as `BTADDON` or `FPC_USART_DEV` which are specific to the RDV4.


💡 The same client can handle both Proxmark3 and Proxmark5, no need to compile separate clients if you own both hardwares.

## Flashing instructions

⚠️ Disconnect the BWM (Battery Wireless Module), it's not supported yet, and creates issues flashing.

⚠️ As usual, make sure [ModemManager won't interfere](ModemManager-Must-Be-Discarded.md).

⚠️ Make sure no other Proxmark (3 or 5) is plugged into your PC.


Use the yellow USB-C on the same side as the button.

You'll first need to update the bootrom with the latest code available on the repository.
The bootrom in your device is not yet able to enter automatically the boot mode properly, so you will have to enter boot mode manually as follows, a procedure slightly different from the Proxmark3.

* Plug in your Proxmark5 while holding the button for about 4 seconds until you see 2 LEDs illuminated (B and D). Don't wait too long. If the LEDs are now off again, you entered DFU mode. Unplug and try again.

* Run `./pm3-flash-bootrom`
* Unplug.
* Plug in your Proxmark5 while holding the button for about 4 seconds until you see 2 LEDs illuminated (B and D).
* Run `./pm3-flash-fullimage`

With the new bootrom, you don't need to enter manually the boot mode by pressing the button anymore and the flashing experience will be as smooth as on the Proxmark3: just run `./pm3-flash-fullimage` to update the main image, and occasionally `./pm3-flash-bootrom` if needed. If the main image gets seriously buggy and can't jump to boot mode automatically, you can enter boot mode using the button as explained above.

If you see "🚨 The elf file is not applicable to the currently connected device.", you probably forgot to add the `PLATFORM=PM5` when compiling.

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
* `hw qc_pm5`: factory quality check command, will activate the RBG, the buzzer and the antenna LEDs.
* `hw factorydata`: read/write the factory data (originality signature etc)

## Standalone Modes

Standalone modes are disabled for now, to ease debugging.

## BWM aka Battery Wireless Module

⚠️ the BWM is not yet fully supported, it's better not to plug it for now.

* [Installation instructions](https://github.com/RfidResearchGroup/Proxmark5_BWM_esp32/blob/master/INSTALL.md)
* Pressing briefly the button will wake the device
* When the device is powered on, pressing and holding the button for a few seconds will start displaying a running light, and then releasing the button will power off the device

⚠️ After using the device over USB and disconnecting it, the Proxmark5 is still powered by the battery. To remind it to you, the RGB will turn green. Press the button a few seconds to turn it off.
