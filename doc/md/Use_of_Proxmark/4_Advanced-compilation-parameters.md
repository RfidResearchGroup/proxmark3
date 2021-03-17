# Advanced compilation parameters

The client and the Proxmark3 firmware should always be in sync.
Nevertheless, the firmware can be tuned depending on the Proxmark3 platform and options.

Indeed, the RRG/Iceman fork can be used on other Proxmark3 hardware platforms as well.

Via some definitions, you can adjust the firmware for a given platform, but also to add features like the support of the Blue Shark add-on or to select which standalone mode to embed.

## Client

The client doesn't depend on the capabilities of the Proxmark3 it's connected to.
So you can use the same client for different Proxmark3 platforms, given that everything is running the same version.

It's possible to explicitly skip the Qt support in the compilation even if Qt is present on the host, with:

```
make clean
make SKIPQT=1
```

On Linux hosts, if the Bluez headers and library are present, the client will be compiled with native Bluetooth support. It's possible to explicitly skip Bluetooth support with:

```
make clean
make SKIPBT=1
```


## Firmware

By default, the firmware is of course tuned for the Proxmark3 RDV4 device, which has built-in support for 256kb onboard flash SPI memory, Sim module (smart card support), FPC connector.
These features make it very different from all other Proxmark3 devices, there is non other like this one.

**Recommendation**: if you don't have a RDV4, we strongly recommend your device to have at least a 512kb arm chip, since this repo is crossing 256kb limit. There is still a way to skip parts to make it fit on a 256kb device, see below.

If you need to tune things and save the configuration, create a file `Makefile.platform` in the root directory of the repository, see `Makefile.platform.sample`.
For an up-to-date exhaustive list of options, you can run `make PLATFORM=`.

## PLATFORM

Here are the supported values you can assign to `PLATFORM` in `Makefile.platform`:

| PLATFORM        | DESCRIPTION              |
|-----------------|--------------------------|
| PM3RDV4 (def)   | Proxmark3 RDV4           |
| PM3GENERIC      | Proxmark3 generic target |

By default `PLATFORM=PM3RDV4`.

The MCU version (256 or 512) will be detected automatically during flashing.

Known issues:

* 256kb Arm chip devices: The compiled firmware image from this repo may/will be too large for your device. 
* PM3 Evo: it has a different led/button pin assignment.  It tends to be messed up.
* Proxmark Pro:  it has different fpga and unknown pin assignments.  Will most certainly mess up

## PLATFORM_EXTRAS

Here are the supported values you can assign to `PLATFORM_EXTRAS` in `Makefile.platform`:

| PLATFORM_EXTRAS | DESCRIPTION                            |
|-----------------|----------------------------------------|
| BTADDON         | Proxmark3 rdv4 BT add-on               |

By default `PLATFORM_EXTRAS=`.

If you have installed a Blue Shark add-on on your RDV4, define `PLATFORM_EXTRAS=BTADDON` in your `Makefile.platform`.


## STANDALONE

The RRG/Iceman fork gives you to easily choose which standalone mode to embed in the firmware.

Here are the supported values you can assign to `STANDALONE` in `Makefile.platform`:

| STANDALONE      | DESCRIPTION                            |
|-----------------|----------------------------------------|
|                 | No standalone mode
| LF_SKELETON     | standalone mode skeleton - Iceman1001
| LF_EM4100EMUL   | LF EM4100 simulator standalone mode - temskiy
| LF_EM4100RSWB   | LF EM4100 read/write/clone/brute mode - Monster1024
| LF_EM4100RWC    | LF EM4100 read/write/clone mode - temskiy
| LF_HIDBRUTE     | HID corporate 1000 bruteforce - Federico dotta & Maurizio Agazzini
| LF_ICEHID       | LF HID collector to flashmem - Iceman1001
| LF_PROXBRUTE    | HID ProxII bruteforce - Brad Antoniewicz
| LF_SAMYRUN      | HID26 read/clone/sim - Samy Kamkar
| HF_14ASNIFF     | 14a sniff storing to flashmem - Micolous
| HF_AVEFUL       | MIFARE Ultralight read/simulation - Ave Ozkal
| HF_BOG          | 14a sniff with ULC/ULEV1/NTAG auth storing in flashmem - Bogito
| HF_COLIN        | Mifare ultra fast sniff/sim/clone - Colin Brigato
| HF_ICECLASS     | iCLASS 4-1 mode  sim/read & dump/loclass/glitch & config to flashmem - Iceman1001
| HF_LEGIC        | HF Legic Prime standalone - uhei
| HF_MATTYRUN     | Mifare sniff/clone - Matías A. Ré Medina
| HF_MSDSAL  (def)| EMV Read and emulation - Salvador Mendoza
| HF_TCPRST       | IKEA Rothult ST25TA, Standalone Master Key Dump/Emulation - Nick Draffen
| HF_YOUNG        | Mifare sniff/simulation - Craig Young

By default `STANDALONE=HF_MSDSAL`.

## 256kb versions

If you own a Proxmark3 Easy with only 256kb, you can use a few definitions to help you getting a smaller firmware.

First thing is of course to use the `PLATFORM=PM3GENERIC`.
Adding `PLATFORM_SIZE=256` will provoke an error during compilation of the recovery image if your image is too big, so you can detect the problem before trying to flash the Proxmark3, e.g.
```
[=] GEN proxmark3_recovery.bin
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
ERROR: Firmware image too large for your platform! 262768 > 262144
!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
```

You can skip the standalone support by indicating `STANDALONE=` and
a series of `SKIP_*` allow to skip some of the functionalities and to get a smaller image.

| Definitions         | Rough estimation of the saved space |
|---------------------|-------------------------------------|
|STANDALONE=          | 3.6kb
|SKIP_LF=1            | 25.8kb
|SKIP_HITAG=1         | 24.2kb
|SKIP_EM4x50=1        | 2.9kb
|SKIP_ISO15693=1      | 3.2kb
|SKIP_LEGICRF=1       | 3.9kb
|SKIP_ISO14443b=1     | 3.7kb
|SKIP_ISO14443a=1     | 63.0kb
|SKIP_ICLASS=1        | 10.5kb
|SKIP_FELICA=1        | 4.0kb
|SKIP_NFCBARCODE=1    | 1.4kb
|SKIP_HFSNIFF=1       | 0.5kb
|SKIP_HFPLOT=1        | 0.3kb

So for example, at the time of writing, this is a valid `Makefile.platform` compiling an image for 256k:
```
PLATFORM=PM3GENERIC
PLATFORM_SIZE=256
STANDALONE=
SKIP_HITAG=1
SKIP_FELICA=1
```
Situation might change when the firmware is growing of course, requiring to skip more elements.

Last note: if you skip a tech, be careful not to use a standalone mode which requires that same tech, else the firmware size reduction won't be much.

## Next step

See [Compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)
