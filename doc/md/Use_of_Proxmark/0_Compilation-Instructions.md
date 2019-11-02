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

## Install

This is an optional step. If you do

```sh
sudo make install
```

Then the required files will be installed on your system, by default in `/usr/local/bin` and `/usr/local/share/proxmark3`.
Maintainers can read [this doc](../Development/Maintainers.md) to learn how to modify installation paths via `DESTDIR` and `PREFIX` Makefile variables.

The commands given in the documentation assume you did the installation step. If you didn't, you've to adjust the commands paths and files paths accordingly,
e.g. calling `./pm3` or `client/proxmark3` instead of just `pm3` or `proxmark3`.

## Flash the BOOTROM & FULLIMAGE

In most cases, you can run the following script which try to auto-detect the port to use, on several OS:

```sh
pm3-flash-all
```

For the other cases, specify the port by yourself. For example, for a Proxmark3 connected via USB under Linux (adjust the port for your OS):

```sh
proxmark3 /dev/ttyACM0 --flash --unlock-bootloader --image bootrom.elf --image fullimage.elf
```

The firmware files will be searched in the expected locations (installed files, working repo files, user folder, etc.). You can also specify their location:

```sh
pm3-flash -b /tmp/my-bootrom.elf /tmp/my-fullimage.elf
```

or

```sh
proxmark3 /dev/ttyACM0 --flash --unlock-bootloader --image /tmp/my-bootrom.elf --image /tmp/my-fullimage.elf
```

## Run the client

In most cases, you can run the script `pm3` which try to auto-detect the port to use, on several OS.

For the other cases, specify the port by yourself. For example, for a Proxmark3 connected via USB under Linux:

Here, for example, for a Proxmark3 connected via USB under Linux (adjust the port for your OS):

```sh
proxmark3 /dev/ttyACM0
```

or from the local repo

```sh
client/proxmark3 /dev/ttyACM0
```

## Next steps

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
