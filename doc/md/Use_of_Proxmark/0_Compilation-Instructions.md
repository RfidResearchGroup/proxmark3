# Compilation instructions

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

```sh
client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf
```

## Run the client

```sh
cd client
./proxmark3 /dev/ttyACM0
```

## Compiling for other boards

Available boards

| BOARD           | PLATFORM                               |
|:---------------:|:---------------------------------------|
| `PM3RDV4` (def) | Proxmark3 rdv4      with AT91SAM7S512  |
| `PM3EVO`        | Proxmark3 EVO       with AT91SAM7S512  |
| `PM3EASY`       | Proxmark3 rdv3 Easy with AT91SAM7S256  |
| `PM3RDV2`       | Proxmark3 rdv2      with AT91SAM7S512  |
| `PM3OLD256`     | Proxmark3 V1        with AT91SAM7S256  |
| `PM3OLD512`     | Proxmark3 V1        with AT91SAM7S512  |

Create a file named `Makefile.platform` in the root directory of the repository:

```sh
# PLATFORM=${BOARD}
# Following example is to compile sources for Proxmark3 rdv3 Easy
PLATFORM=PM3EASY
```

From this point:

```sh
# Clean and compile
make clean && make all

# Flash the BOOTROM & FULLIMAGE
client/flasher /dev/ttyACM0 -b bootrom/obj/bootrom.elf armsrc/obj/fullimage.elf

# Run the client
cd client
./proxmark3 /dev/ttyACM0
```

## Next steps

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
