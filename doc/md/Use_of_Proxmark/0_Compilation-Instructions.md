<a id="Top"></a>

# Compilation instructions

# Table of Contents
- [Compilation instructions](#compilation-instructions)
- [Table of Contents](#table-of-contents)
  - [Tuning compilation parameters](#tuning-compilation-parameters)
    - [Compile for Proxmark3 RDV4](#compile-for-proxmark3-rdv4)
    - [Compile for generic Proxmark3 platforms](#compile-for-generic-proxmark3-platforms)
  - [Get the latest commits](#get-the-latest-commits)
  - [Clean and compile everything](#clean-and-compile-everything)
    - [if you got an error](#if-you-got-an-error)
  - [Install](#install)
  - [Flash the BOOTROM & FULLIMAGE](#flash-the-bootrom--fullimage)
  - [Run the client](#run-the-client)
  - [Next steps](#next-steps)



## Tuning compilation parameters
^[Top](#top)

The client and the Proxmark3 firmware should always be in sync.
Nevertheless, the firmware can be tuned depending on the Proxmark3 platform and options.

Indeed, the RRG/Iceman fork can be used on other Proxmark3 hardware platforms as well.

Via some definitions, you can adjust the firmware for a given platform, but also to add features like the support of the Blue Shark add-on or to select which standalone mode to embed. To learn how to adjust the firmware, please read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md).

### Compile for Proxmark3 RDV4
^[Top](#top)

The repo defaults for compiling a firmware and client suitable for Proxmark3 RDV4.

### Compile for generic Proxmark3 platforms
^[Top](#top)

In order to build this repo for generic Proxmark3 platforms we urge you to read [Advanced compilation parameters](/doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md)


## Get the latest commits
^[Top](#top)

```sh
cd proxmark3
git pull
```

## Clean and compile everything
^[Top](#top)

```sh
make clean && make -j
```

### if you got an error
^[Top](#top)

Read the [troubleshooting guide](/doc/md/Installation_Instructions/Troubleshooting.md), 

For instance,  on WSl-1 you usually get the `libQt5Core.so.5 not found` message
[solution](/doc/md/Installation_Instructions/Troubleshooting.md#libQt5Coreso5-not-found)


## Install
^[Top](#top)

This is an optional step. If you do

```sh
sudo make install
```

Then the required files will be installed on your system, by default in `/usr/local/bin` and `/usr/local/share/proxmark3`.
Maintainers can read [this doc](../Development/Maintainers.md) to learn how to modify installation paths via `DESTDIR` and `PREFIX` Makefile variables.

The commands given in the documentation assume you did the installation step. If you didn't, you've to adjust the commands paths and files paths accordingly,
e.g. calling `./pm3` or `client/proxmark3` instead of just `pm3` or `proxmark3`.

## Flash the BOOTROM & FULLIMAGE
^[Top](#top)

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
^[Top](#top)

In most cases, you can run the script `pm3` which try to auto-detect the port to use, on several OS.
```sh
./pm3
```

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
^[Top](#top)

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
