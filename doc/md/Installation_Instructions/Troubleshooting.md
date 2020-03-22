# Troubleshooting guide

## First of all

Always use the latest repository commits from *master* branch. There are always many fixes done almost daily.

## Table of Contents

  * [pm3 or pm3-flash* doesn't see my Proxmark](#pm3-or-pm3-flash-doesnt-see-my-proxmark)
  * [My Proxmark3 seems bricked](#my-proxmark3-seems-bricked)
     * [Maybe just a false alarm?](#maybe-just-a-false-alarm)
     * [Find out why it would be bricked](#find-out-why-it-would-be-bricked)
     * [Determine if the bootloader was damaged or only the main OS image](#determine-if-the-bootloader-was-damaged-or-only-the-main-os-image)
     * [Ok, my bootloader is definitively dead, now what?](#ok-my-bootloader-is-definitively-dead-now-what)
  * [Slow to boot or difficulties to enumerate the device over USB](#slow-to-boot-or-difficulties-to-enumerate-the-device-over-usb)
  * [Troubles with SIM card reader](#troubles-with-sim-card-reader)
  * [Troubles with t5577 commands or MFC/iClass/T55x7 dictionaries](#troubles-with-t5577-commands-or-mfciclasst55x7-dictionaries)
  * [File not found](#file-not-found)
  * [Pixmap / pixbuf warnings](#pixmap--pixbuf-warnings)
  * [Usb cable](#usb-cable)
  * [WSL 2  explorer.exe . doesnt work](WSL-2)

## `pm3` or `pm3-flash*` doesn't see my Proxmark

Try using directly the client:

```
client/proxmark3 <YOUR_PORT_HERE> ...
```

Refer to the installation guide specific to your OS for details about ports.

* [Linux](/doc/md/Installation_Instructions/Linux-Installation-Instructions.md)
* [Mac OSX](/doc/md/Installation_Instructions/Mac-OS-X-Homebrew-Installation-Instructions.md)
* [Windows](/doc/md/Installation_Instructions/Windows-Installation-Instructions.md)

Note that with the Bluetooth adapter, you *have to* use directly the client, and flasher over Bluetooth is not possible.

* [Bluetooth](/doc/bt_manual_v10.md)

## My Proxmark3 seems bricked

### Maybe just a false alarm?

The flasher refused to flash your Proxmark3? Are there any messages in *red*? The most common reason is that the Proxmark3 RDV4 firmware recently got a new bootloader able to handle larger firmwares and... the image grew over 256k almost at the same time. So your old bootloader can't flash such new images. But it's easy, you just need to flash *first* the bootloader *only*, then the image.

```
pm3-flash-bootrom
pm3-flash-fullimage
```
or
```
proxmark3 <YOUR_PORT_HERE> --flash --unlock-bootloader --image bootrom/obj/bootrom.elf
proxmark3 <YOUR_PORT_HERE> --flash --image armsrc/obj/fullimage.elf
```

### Find out why it would be bricked

The most common reason of a flashing failure is the interference of ModemManager, read carefully [how to avoid ModemManager-related issues](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md) and fix your setup!

Another possibility is if, when using the button for entering bootloader mode, the button was released during flashing (for old bootloaders) or the button was pressed again during flashing (for newer bootloaders).

### Determine if the bootloader was damaged or only the main OS image

Unplug, press the Proxmark3 button and keep it pressed when you plug it on USB. If the red LEDs show a "off/on/off/on" pattern, you're goot, you manually entered into the bootloader mode.
On new bootloaders, you can release the button. If the pattern disappears, you're on an older bootloader and you've to do it again and keep the button pressed during all the flashing operation. 

Once in bootloader mode, flash the main image.

```
pm3-flash-fullimage
```
or
```
proxmark3 <YOUR_PORT_HERE> --flash --image armsrc/obj/fullimage.elf
```

You should be back on tracks now. In case the flasher complains about bootloader version, you can follow the button procedure and flash first your bootloader.

```
pm3-flash-bootrom
```
or
```
proxmark3 <YOUR_PORT_HERE> --flash --unlock-bootloader --image bootrom/obj/bootrom.elf
```

### Ok, my bootloader is definitively dead, now what?

At this point, only reflashing via JTAG can revive your Proxmark3.

See [details here](/doc/jtag_notes.md).

## Slow to boot or difficulties to enumerate the device over USB

You're using another Proxmark3 than a RDV4?
The RDV4 firmware can run on other Proxmark3 as such but the booting procedure is a bit slower because of the absence of SIM and external flash.
Make sure to configure properly your `Makefile.platform` to get a firmware better tuned for your Proxmark3 hardware.
See [details here](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md).

## Troubles with SIM card reader

(RDV4 only) Make sure you've the latest SIM firmware according to the [configuration documentation](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md#verify-sim-module-firmware-version).

## Troubles with t5577 commands or MFC/iClass/T55x7 dictionaries

(RDV4 only) Make sure you've set everything up according to the [configuration documentation](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md#first-things-on-your-rdv40).

Instructions evolve over time so check if you're still up to date!

## File not found

If Proxmark3 has been installed with `make install` or packaged for your distro, the binaries should be in your path and you can call them directly:

```
pm3
proxmark3
```

and you must adapt accordingly the file path of some commands, e.g.

```
proxmark3 <YOUR_PORT_HERE> --flash --image /usr/local/share/proxmark3/firmware/fullimage.elf
<>
proxmark3 <YOUR_PORT_HERE> --flash --image /usr/share/proxmark3/firmware/fullimage.elf

pm3 --> sc upgrade f /usr/local/share/proxmark3/firmware/sim011.bin
<>
pm3 --> sc upgrade f /usr/share/proxmark3/firmware/sim011.bin
```

If you didn't install the PRoxmark but you're working from the sources directory and depending how you launch the client, your working directory might be the root of the repository:

```
./pm3 ...
client/proxmark3 ...
```

or the `client/` subdirectory:

```
cd client; ./proxmark3 ...
```

Therefore client commands referring to files of the repo must be adapted, e.g.

```
client/proxmark3 <YOUR_PORT_HERE> --flash --image armsrc/obj/fullimage.elf
<>
./proxmark3 <YOUR_PORT_HERE> --flash --image ../armsrc/obj/fullimage.elf

pm3 --> sc upgrade f tools/simmodule/sim011.bin
<>
pm3 --> sc upgrade f ../tools/simmodule/sim011.bin
```

etc.

## Pixmap / pixbuf warnings

If you get warnings related to pixmap or pixbuf such as *Pixbuf theme: Cannot load pixmap file* or *Invalid borders specified for theme pixmap*, it's a problem of your Theme, try another one and the problem should vanish. See e.g. [#354](https://github.com/RfidResearchGroup/proxmark3/issues/354) (Yaru theme on Ubuntu) and [#386](https://github.com/RfidResearchGroup/proxmark3/issues/386) (Kali-X theme on Kali).

## Usb cable

It's needed to have a good USB cable to connect Proxmark3 to USB. If you have stability problems (Proxmark3 resets, firmware hangs, especially firmware hangs just after start, etc.) 

- check your cable with a USB tester (or try to change it). It needs to have a resistance smaller or equal to 0.3 Ohm.

## WSL 2
When ```explorer.exe .``` doesn't work.  
Trying to access the dump files created in WSL,  you will need to run ```explorer.exe .```  but sometimes this doesn't work.
[As seen here](https://github.com/microsoft/WSL/issues/4027)  they suggest checking the following registry value for *P9NP*

[<img src="http://www.icedev.se/proxmark3/rdv40/wsl2_p9np.png">](www.icedev.se/proxmark3/rdv40/wsl2_p9np.png)

