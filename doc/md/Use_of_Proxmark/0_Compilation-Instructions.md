# Compilation instructions

## Tuning compilation parameters

The client and the Proxmark3 firmware should always be in sync.
Nevertheless, the firmware can be tuned depending on the Proxmark3 platform and options.

Indeed, the RRG/Iceman fork can be used on other Proxmark3 hardware platforms as well.

Via some definitions, you can adjust the firmware for a given platform, but also to add features like the support of the Blue Shark add-on or to select which standalone mode to embed.

To learn how to adjust the firmware, please read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md).

## Get the latest commits

```sh
cd proxmark3
git pull
```

## Clean and compile everything

```sh
make clean && make all
```

## Flash the BOOTROM & FULLIMAGE

In most cases, you can run the script `flash-all.sh` which try to auto-detect the port to use, on several OS.

For the other cases, specify the port by yourself. For example, for a Proxmark3 connected via USB under Linux:

```sh
client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf
```

## Run the client

In most cases, you can run the script `proxmark3.sh` which try to auto-detect the port to use, on several OS.

For the other cases, specify the port by yourself. For example, for a Proxmark3 connected via USB under Linux:

Here, for example, for a Proxmark3 connected via USB under Linux:

```sh
cd client
./proxmark3 /dev/ttyACM0
```

## Next steps

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
