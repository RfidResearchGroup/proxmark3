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

## Firmware

By default, the firmware is of course tuned for the Proxmark3 Rdv4.0 device, which has built-in support for 256kb onboard flash SPI memory, Sim module (smart card support), FPC connector.
These features make it very different from all other devices, there is non other like this one.

**Recommendation**: if you don't have a RDV4, we strongly recommend your device to have at least a 512kb arm chip, since this repo is on the very edge of 256kb limit.

A firmware built for the RDV4 can still run on the other platforms as it will auto-detect during boot that external SPI and Sim are not present, still it will boot faster if it's tuned to the platform, which solves USB enumeration issues on some OSes.

If you need to tune things and save the configuration, create a file `Makefile.platform` in the root directory of the repository, see `Makefile.platform.sample`.
For an up-to-date exhaustive list of options, you can run `make PLATFORM=`.

## PLATFORM

Here are the supported values you can assign to `PLATFORM` in `Makefile.platform`:

| PLATFORM        | DESCRIPTION              |
|-----------------|--------------------------|
| PM3RDV4 (def)   | Proxmark3 rdv4           |
| PM3OTHER        | Proxmark3 generic target |

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
| LF_SAMYRUN (def)| HID26 read/clone/sim - Samy Kamkar
| LF_ICERUN       | standalone mode skeleton - iceman
| LF_PROXBRUTE    | HID ProxII bruteforce - Brad Antoniewicz
| LF_HIDBRUTE     | HID corporate 1000 bruteforce - Federico dotta & Maurizio Agazzini
| HF_YOUNG        | Mifare sniff/simulation - Craig Young
| HF_MATTYRUN     | Mifare sniff/clone - Matías A. Ré Medina
| HF_COLIN        | Mifare ultra fast sniff/sim/clone - Colin Brigato
| HF_BOG          | 14a sniff with ULC/ULEV1/NTAG auth storing in flashmem - Bogito

By default `STANDALONE=LF_SAMYRUN`.

## Next step

See [Compilation instructions](/doc/md/Use_of_Proxmark/0_Compilation-Instructions.md)
