# Troubleshooting guide

## First of all

Always use the latest repository commits from *master* branch. There are always many fixes done almost daily.

## `./proxmark3.sh` or `./proxmark3-flash-*.sh` doesn't see my Proxmark

Try using directly the client or flasher:

```
client/proxmark3-flasher <YOUR_PORT_HERE> ...
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
./flash-bootrom.sh
./flash-fullimage.sh
```
or
```
client/proxmark3-flasher <YOUR_PORT_HERE> -b bootrom/obj/bootrom.elf
client/proxmark3-flasher <YOUR_PORT_HERE> armsrc/obj/fullimage.elf
```

### Find out why it would be bricked

The most common reason of a flashing failure is the interference of ModemManager, read carefully [how to avoid ModemManager-related issues](/doc/md/Installation_Instructions/ModemManager-Must-Be-Discarded.md) and fix your setup!

Another possibility is if, when using the button for entering bootloader mode, the button was released during flashing (for old bootloaders) or the button was pressed again during flashing (for newer bootloaders).

### Determine if the bootloader was damaged or only the main OS image

Unplug, press the Proxmark3 button and keep it pressed when you plug it on USB. If the red LEDs show a "off/on/off/on" pattern, you're goot, you manually entered into the bootloader mode.
On new bootloaders, you can release the button. If the pattern disappears, you're on an older bootloader and you've to do it again and keep the button pressed during all the flashing operation. 

Once in bootloader mode, flash the main image.

```
./flash-fullimage.sh
```
or
```
client/proxmark3-flasher <YOUR_PORT_HERE> armsrc/obj/fullimage.elf
```

You should be back on tracks now. In case the flasher complains about bootloader version, you can follow the button procedure and flash first your bootloader.

```
./flash-bootrom.sh
```
or
```
client/proxmark3-flasher <YOUR_PORT_HERE> -b bootrom/obj/bootrom.elf
```

### Ok, my bootloader is definitively dead, now what?

At this point, only reflashing via JTAG can revive your Proxmark3.

See [details here](/doc/jtag_notes.md).

## Slow to boot

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

Depending how you launch the client, your working directory might be the root of the repository:

```
./proxmark3.sh ...
client/proxmark3 ...
```

or the `client/` subdirectory:

```
cd client; ./proxmark3 ...
```

Therefore client commands referring to files of the repo must be adapted, e.g.

```
pm3 --> sc upgrade f tools/simmodule/SIM011.BIN
<>
pm3 --> sc upgrade f ../tools/simmodule/SIM011.BIN
```

```
pm3 --> mem load f default_keys m
<>
pm3 --> mem load f client/default_keys m
```

etc.

This also affects where your history and logfile will be read from and written to.

