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

## Next steps

For the next steps, please read the following pages:

* [Validating proxmark client functionality](/doc/md/Use_of_Proxmark/1_Validation.md)
* [First Use and Verification](/doc/md/Use_of_Proxmark/2_Configuration-and-Verification.md)
* [Commands & Features](/doc/md/Use_of_Proxmark/3_Commands-and-Features.md)
 
