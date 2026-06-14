# Standalone Modes
<a id="Top"></a>


# Table of Contents
- [Standalone Modes](#standalone-modes)
- [Table of Contents](#table-of-contents)
- [What are standalone modes?](#what-are-standalone-modes)
   - [Individual mode documentation](#individual-mode-documentation)
- [Developing Standalone Modes](#developing-standalone-modes)
  - [Implementing a standalone mode](#implementing-a-standalone-mode)
  - [Naming your standalone mode](#naming-your-standalone-mode)
  - [Update MAKEFILE.HAL](#update-makefilehal)
  - [Update MAKEFILE.INC](#update-makefileinc)
  - [Adding identification string of your mode](#adding-identification-string-of-your-mode)
  - [Compiling your standalone mode](#compiling-your-standalone-mode)
  - [Submitting your code](#submitting-your-code)


Standalone modes run directly on the Proxmark3 device without a connected host computer.
See [Developing Standalone Modes](#developing-standalone-modes) for how to build your own.
> Only one (1) mode can be compiled into the firmware at a time (except via [DANKARMULTI](../../doc/standalone/dankarmulti.md)).


## Individual Mode Documentation 
>>> NOTE <<<  This documentation below for the individual standalone mode is AI-generated
As such the information inside may be false or hallucinated.


### LF (Low Frequency — 125 kHz) Standalone Modes

| Mode ID | Document | Description | Hardware |
|---------|----------|-------------|----------|
| LF_SAMYRUN | [SamyRun](../../doc/standalone/lf_samyrun.md) | HID26 read/clone/simulate (Samy Kamkar) | Generic |
| LF_EM4100EMUL | [EM4100 Emulator](../../doc/standalone/lf_em4100emul.md) | Simulate predefined EM4100 tag IDs | Generic |
| LF_EM4100RSWB | [EM4100 RSWB](../../doc/standalone/lf_em4100rswb.md) | Read/simulate/write/brute EM4100 (4 slots) | RDV4 (flash) |
| LF_EM4100RSWW | [EM4100 RSWW](../../doc/standalone/lf_em4100rsww.md) | Read/simulate/write/wipe/validate EM4100 | RDV4 (flash) |
| LF_EM4100RWC | [EM4100 RWC](../../doc/standalone/lf_em4100rwc.md) | Read/simulate/clone EM4100 (16 slots) | RDV4 (flash) |
| LF_HIDBRUTE | [HID Corporate Brute](../../doc/standalone/lf_hidbrute.md) | HID Corporate 1000 card number bruteforce | Generic |
| LF_HIDFCBRUTE | [HID FC Brute](../../doc/standalone/lf_hidfcbrute.md) | HID facility code bruteforce (0–255) | RDV4 (flash) |
| LF_ICEHID | [IceHID Collector](../../doc/standalone/lf_icehid.md) | Multi-format LF credential collector to flash | RDV4 (flash) |
| LF_MULTIHID | [MultiHID](../../doc/standalone/lf_multihid.md) | HID 26-bit multi-card simulator | Generic |
| LF_NEDAP_SIM | [Nedap Simulator](../../doc/standalone/lf_nedap_sim.md) | Nedap RFID simple tag simulator | Generic |
| LF_NEXID | [NexID Collector](../../doc/standalone/lf_nexid.md) | Nexwatch credential collector to flash | RDV4 (flash) |
| LF_PROXBRUTE | [ProxBrute](../../doc/standalone/lf_proxbrute.md) | HID ProxII card number bruteforce | Generic |
| LF_PROX2BRUTE | [Prox2Brute](../../doc/standalone/lf_prox2brute.md) | HID ProxII bruteforce v2 (faster, configurable) | Generic |
| LF_THAREXDE | [Tharexde EM4x50](../../doc/standalone/lf_tharexde.md) | EM4x50 simulate/read/collect | RDV4 (flash) |
| LF_SKELETON | [Skeleton Template](../../doc/standalone/lf_skeleton.md) | Development template for new LF modes | Generic |

### HF (High Frequency — 13.56 MHz) Standalone Modes

| Mode ID | Document | Description | Hardware |
|---------|----------|-------------|----------|
| HF_14ASNIFF | [14A Sniffer](../../doc/standalone/hf_14asniff.md) | ISO14443A passive sniffer to flash | RDV4 (flash) |
| HF_14BSNIFF | [14B Sniffer](../../doc/standalone/hf_14bsniff.md) | ISO14443B passive sniffer to flash | RDV4 (flash) |
| HF_15SNIFF | [15693 Sniffer](../../doc/standalone/hf_15sniff.md) | ISO15693 sniffer to flash | RDV4 (flash) |
| HF_15SIM | [15693 Simulator](../../doc/standalone/hf_15sim.md) | ISO15693 dump and simulate | RDV4 (flash) |
| HF_AVEFUL | [Aveful UL Reader](../../doc/standalone/hf_aveful.md) | MIFARE Ultralight read and emulate | Generic |
| HF_BOG | [BogitoRun Auth Sniffer](../../doc/standalone/hf_bog.md) | 14A sniff with ULC/ULEV1/NTAG auth capture | RDV4 (flash) |
| HF_CARDHOPPER | [CardHopper Relay](../../doc/standalone/hf_cardhopper.md) | Long-range 14A relay over serial/IP | RDV4 (BT) |
| HF_COLIN | [VIGIKPWN](../../doc/standalone/hf_colin.md) | MIFARE Classic ultra-fast sniff/sim/clone | RDV4 (flash) |
| HF_CRAFTBYTE | [CraftByte UID Stealer](../../doc/standalone/hf_craftbyte.md) | Scan and emulate ISO14443A UIDs | Generic |
| HF_DOEGOX_AUTH0 | [UL-C/UL-AES Unlocker](../../doc/standalone/hf_doegox_auth0.md) | Unlock password-protected Ultralight tags | Generic |
| HF_EMVPNG | [EMV Visa Reader/Emulator](../../doc/standalone/hf_emvpng.md) | Read Visa EMV cards and emulate transactions | RDV4 (flash) |
| HF_ICECLASS | [IceClass iCLASS](../../doc/standalone/hf_iceclass.md) | iCLASS multi-mode: sim/dump/attack/config | RDV4 (flash) |
| HF_LEGIC | [Legic Prime Reader](../../doc/standalone/hf_legic.md) | Read and simulate Legic Prime tags | Generic |
| HF_LEGICSIM | [Legic Prime Simulator](../../doc/standalone/hf_legicsim.md) | Simulate Legic Prime dumps from flash (15 slots) | RDV4 (flash) |
| HF_MATTYRUN | [MattyRun MFC Clone](../../doc/standalone/hf_mattyrun.md) | MIFARE Classic key check, dump, and emulate | Generic |
| HF_MFCSIM | [MFC Simulator](../../doc/standalone/hf_mfcsim.md) | Simulate MIFARE Classic 1K from flash (15 slots) | RDV4 (flash) |
| HF_MSDSAL | [MSD Visa Reader](../../doc/standalone/hf_msdsal.md) | Read and emulate Visa MSD cards | Generic |
| HF_REBLAY | [Reblay BT Relay](../../doc/standalone/hf_reblay.md) | ISO14443A relay over Bluetooth | RDV4 (BT) |
| HF_ST25_TEAROFF | [ST25TB Tear-off](../../doc/standalone/hf_st25_tearoff.md) | ST25TB store/restore with counter tear-off | RDV4 (flash) |
| HF_TCPRST | [IKEA Rothult](../../doc/standalone/hf_tcprst.md) | IKEA Rothult ST25TA master key dump/emulation | Generic |
| HF_TMUDFORD | [ISO15693 UID Emulator](../../doc/standalone/hf_tmudford.md) | Read and emulate ISO15693 UIDs | Generic |
| HF_UNISNIFF | [Universal Sniffer](../../doc/standalone/hf_unisniff.md) | Multi-protocol sniffer (14A/14B/15/iCLASS) | RDV4 (flash) |
| HF_YOUNG | [Young MFC Sniff/Sim](../../doc/standalone/hf_young.md) | MIFARE sniff/simulation with 2-bank storage | Generic |

### Multi-Mode Loader

| Mode ID | Document | Description |
|---------|----------|-------------|
| DANKARMULTI | [Dankarmulti Loader](../../doc/standalone/dankarmulti.md) | Combine multiple standalone modes into one firmware image |

# Developing Standalone Modes
This contains functionality for different StandAlone modes. The fullimage will be built given the correct compiler flags used. Build targets for these files are contained in `Makefile.inc` and `Makefile.hal`

If you want to implement a new standalone mode, you need to implement the methods provided in `standalone.h`.
Have a look at the skeleton standalone mode, in the file `lf_skeleton.c`.

As it is now, you can only have one standalone mode installed at the time unless you use the dankarmulti mode (see `dankarmulti.c` on how to use it).

To avoid clashes between standalone modes, protect all your static variables with a specific namespace. See how it is done in the existing standalone modes.

## Implementing a standalone mode
^[Top](#top)

We suggest you keep your standalone code inside the `armsrc/Standalone` folder. And that you name your files according to your standalone mode name.

The `standalone.h` states that you must have two functions implemented. 

The ModInfo function, which is your identification of your standalone mode.  This string will show when running the command `hw status` on the client.

The RunMod function, which is your "main" function when running.  You need to check for Usb commands, in order to let the pm3 client break the standalone mode.  See this basic skeleton of main function RunMod() and Modinfo() below.

````
void ModInfo(void) {
    DbpString("  LF good description of your mode - aka FooRun (your name)");
}

void RunMod(void) {
    // led show
    StandAloneMode();

    // Do you target LF or HF?
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);

    // main loop
    for (;;) {
        WDT_HIT();

        // exit from standalone mode, just send a usbcommand
        if (data_available()) break;

        // do your standalone stuff..
    }
````

## Naming your standalone mode
^[Top](#top)

We suggest that you follow these guidelines:
- Use HF/LF to denote which frequency your mode is targeting.  
- Use you own github name/similar for perpetual honour to denote your mode.

sample:
 `LF_FOO`

Which indicates your mode targets LF and is called FOO.

This leads to your next step, your DEFINE name needed in Makefile.

`WITH_STANDALONE_LF_FOO`


## Update MAKEFILE.HAL
^[Top](#top)

Add your mode to the `Makefile.hal` help and modes list (alphabetically):
```
+==========================================================+
| STANDALONE      | DESCRIPTION                            |
+==========================================================+
...
+----------------------------------------------------------+
| LF_FOO          | My foobar mode will make you coffee    |
+----------------------------------------------------------+

STANDALONE_MODES := LF_... LF_FOO
STANDALONE_MODES += HF_...
```

If your mode is using one of the unique features of the RDV4, add it to the proper list:

```
STANDALONE_MODES_REQ_SMARTCARD :=
STANDALONE_MODES_REQ_FLASH :=
STANDALONE_MODES_REQ_BT :=
```

Please respect alphabetic order!

## Update MAKEFILE.INC
^[Top](#top)

Add your source code files like the following sample in the `Makefile.inc`

```
# WITH_STANDALONE_LF_SKELETON
ifneq (,$(findstring WITH_STANDALONE_LF_SKELETON,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_skeleton.c
endif

# WITH_STANDALONE_LF_FOO
ifneq (,$(findstring WITH_STANDALONE_LF_FOO,$(APP_CFLAGS)))
    SRC_STANDALONE = lf_foo.c
endif
```

Please respect alphabetic order!

## Adding identification string of your mode
^[Top](#top)

Do please add a identification string in a function called `ModInfo` inside your source code file.
This will enable an easy way to detect on client side which standalone mode has been installed on the device.

````
void ModInfo(void) {
    DbpString("  LF good description of your mode - aka FooRun (your name)");
}
````

## Compiling your standalone mode
^[Top](#top)

Once all this is done, you and others can now easily compile different standalone modes by just selecting one of the standalone modes (list in `Makefile.hal` or ) , e.g.:

- rename  Makefile.platform.sample -> Makefile.platform
- edit the "STANDALONE" row inside Makefile.platform.  You need to uncomment it and add your standalone mode name

Makefile.platform.sample
```
# If you want to use it, copy this file as Makefile.platform and adjust it to your needs
PLATFORM=PM3RDV4
#PLATFORM_EXTRAS=BTADDON
#STANDALONE=LF_SAMYRUN
```
 becomes
 
 Makefile.platform
 ```
# If you want to use it, copy this file as Makefile.platform and adjust it to your needs
PLATFORM=PM3RDV4
#PLATFORM_EXTRAS=BTADDON
STANDALONE=LF_FOO
```

Remember only one can be selected at a time for now.

The final steps is to 
- force recompilation of all code.  ```make clean```
- compile ```make -j```
- flash your device
- connect to your device
- press button long time to trigger ledshow and enter your new standalone mode
- if connected with usb / fpc ,  you can also see debug statements from your device in standalone mode. Useful for debugging :)

When compiling you will see a header showing what configurations your project compiled with.
Make sure it says your standalone mode name.  

## Submitting your code
^[Top](#top)

Once you're ready to share your mode, please

* add a line in CHANGELOG.md
* add your mode in the modes table in `doc/md/Use_of_Proxmark/4_Advanced-compilation-parameters.md`
* add your mode in `tools/build_all_firmwares.sh` such that it reflects `armsrc/Standalone/Makefile.hal` list of firmwares to build.

Please respect alphabetic order of standalone modes everywhere!

Then submit your PR.

Once approved, add also your mode in https://github.com/RfidResearchGroup/proxmark3/wiki/Standalone-mode

Happy hacking!
