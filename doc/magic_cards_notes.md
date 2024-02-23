<a id="top"></a>

# Notes on Magic Cards, aka UID changeable

This document is based mostly on information posted on http://www.proxmark.org/forum/viewtopic.php?pid=35372#p35372

Useful docs:

* [AN10833 MIFARE Type Identification Procedure](https://www.nxp.com/docs/en/application-note/AN10833.pdf)


# Table of Contents

- [Low frequency](#low-frequency)
  * [T55xx](#t55xx)
  * [EM4x05](#em4x05)
  * [ID82xx series](#id82xx-series)
    * [ID8265](#id8265)
    * [ID-F8268](#id-f8268)
    * [K8678](#k8678)
  * [H series](#h-series)
    * [H1](#h1)
    * [H5.5 / H7](h55--h7)
    * [i57 / i57v2](#i57--i57v2)
- [ISO14443A](#iso14443a)
  * [Identifying broken ISO14443A magic](#identifying-broken-iso14443a-magic)
- [MIFARE Classic](#mifare-classic)
  * [MIFARE Classic block0](#mifare-classic-block0)
  * [MIFARE Classic Gen1A aka UID](#mifare-classic-gen1a-aka-uid)
  * [MIFARE Classic Gen1B](#mifare-classic-gen1b)
  * [Mifare Classic Direct Write OTP](#mifare-classic-direct-write-otp)
  * [MIFARE Classic OTP 2.0](#mifare-classic-otp-20)
  * [MIFARE Classic DirectWrite aka Gen2 aka CUID](#mifare-classic-directwrite-aka-gen2-aka-cuid)
  * [MIFARE Classic Gen3 aka APDU](#mifare-classic-gen3-aka-apdu)
  * [MIFARE Classic USCUID](#mifare-classic-uscuid)
     * [FUID](#fuid)
     * [UFUID](#ufuid)
     * [ZUID](#zuid)
     * [GDM](#gdm)
     * [GDCUID](#gdcuid)
  * [MIFARE Classic, other versions](#mifare-classic-other-versions)
  * [MIFARE Classic Super](#mifare-classic-super)
- [MIFARE Ultralight](#mifare-ultralight)
  * [MIFARE Ultralight blocks 0..2](#mifare-ultralight-blocks-02)
  * [MIFARE Ultralight Gen1A](#mifare-ultralight-gen1a)
  * [MIFARE Ultralight DirectWrite](#mifare-ultralight-directwrite)
  * [MIFARE Ultralight EV1 DirectWrite](#mifare-ultralight-ev1-directwrite)
  * [MIFARE Ultralight C Gen1A](#mifare-ultralight-c-gen1a)
  * [MIFARE Ultralight C DirectWrite](#mifare-ultralight-c-directwrite)
  * [UL series (RU)](#ul-series-ru)
    * [UL-Y](#ul-y)
    * [ULtra](#ultra)
    * [UL-5](#ul-5)
    * [UL, other chips](#ul-other-chips)
- [NTAG](#ntag)
  * [NTAG213 DirectWrite](#ntag213-directwrite)
  * [NTAG21x](#ntag21x)
- [DESFire](#desfire)
  * ["DESFire" APDU, 7b UID](#desfire-apdu-7b-uid)
  * ["DESFire" APDU, 4b UID](#desfire-apdu-4b-uid)
- [ISO14443B](#iso14443b)
  * [Tiananxin TCOS CPU card](#tiananxin-tcos-cpu-card)
- [ISO15693](#iso15693)
  * [ISO15693 magic](#iso15693-magic)
- [Multi](#multi)
  * [UMC](#umc)
- [Other](#other)
  * [SID](#sid)
  * [NSCK-II](#nsck-ii)

# Low frequency

## T55xx

^[Top](#top)

The temic T55xx/Atmel ATA5577 is the most commonly used chip for cloning LF RFIDs.

A useful document can be found [here](https://github.com/RfidResearchGroup/proxmark3/blob/master/doc/T5577_Guide.md).

### Characteristics

* 28/24 bytes of user memory (without/with password)
* Universal output settings (data rate, modulation, etc)
* Password protection (4 bytes), usually "19920427"
* Lock bits per page
* Analog frontend setup
* Other names:
  * 5577
  * 5200 (CN)
    - Cut down version of T55xx chip (no analog frontend setup, no test mode support).
  * H2 (RU)
    - Seems to be renamed 5200 chip.
  * RW125T5 (RU)
* Old variant "T5555" is hard to come across

### Detect

```
[usb] pm3 --> lf search
...
[+] Chipset detection: T55xx
```

This will **not** work if you have a downlink mode other than fixed bit length!

### Commands

*See ATMEL ATA5577C datasheet for sending commands to chip*

* **Do not mix "password read" and "regular write" commands! You risk potentially writing incorrect data.
* When replying, the chip will use the modulation and data rate specified in block 0.

## EM4x05

^[Top](#top)

The EM4305 and EM4205 (and 4469/4569) chips are the 2nd most common used chips for cloning LF RFIDs.
It is also used by HID Global (but with a custom chip) for HIDProx credentials.

### Characteristics

* 36 bytes of user memory
* Output settings are limited (ASK only, FSK added on HID variant)
* Password protection (4 bytes), usually "84AC15E2"
* Lock page used
* Other names:
  * H3 (RU)
  * RW125EM (RU)

### Detect

```
[usb] pm3 --> lf search
...
[+] Chipset detection: EM4x05 / EM4x69
```

### Commands

*See EM microelectronic EM4305 datasheet for sending commands to chip*

## ID82xx series

^[Top](#top)

These are custom chinese chips designed to clone EM IDs only. Often times, these are redesigned clones of Hitag chips.

### ID8265

^[Top](#top)

This is the cheapest and most common ID82xx chip available. It is usually sold as T55xx on AliExpress, with excuses to use cloners.

#### Characteristics

* Chip is likely a Hitag μ (micro)
* Password protection (4b), usually "1AC4999C"
* Currently unimplemented in proxmark3 client
* Other names:
  * ID8210 (CN)
  * H-125 (CN)
  * H5 (RU)
    - The sales of "H5" have been ceased because "the chip was leaked".

#### Detect

```
[usb] pm3 --> lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00011 -s 3000
[usb] pm3 --> data plot
```

Check the green line of the plot. It must be a straight line at the end with no big waves.

### ID-F8268

^[Top](#top)

This is an "improved" variant of ID82xx chips, bypassing some magic detection in China.

#### Characteristics

* Chip is likely a Hitag 1
* Unsure whether password protection is used
* Currently unimplemeneted in proxmark3 client
* Other names:
  - F8278 (CN)
  - F8310 (CN)

#### Detect

```
[usb] pm3 --> lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00110 -s 3000
[usb] pm3 --> data plot
```

Check the green line of the plot. It must be a straight line at the end with no big waves.

### K8678

^[Top](#top)

This is an "even better" chip, manufactured by Hyctec.

#### Characteristics

* Chip is likely a Hitag S256
* Plain mode used, no password protection
* Currently unimplemented in proxmark3 client
* Memory access is odd (chip doesnt reply to memory access commands for unknown reason)

#### Detect

```
[usb] pm3 --> lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00110 -s 3000
[usb] pm3 --> data plot
```

Check the green line of the plot. It must be a straight line at the end with no big waves.

## H series

^[Top](#top)

These are chips sold in Russia, manufactured by iKey LLC. Often times these are custom.

### H1

^[Top](#top)

Simplest EM ID cloning chip available. Officially discontinued.

#### Characteristics

* Currently almost all structure is unknown
* No locking or password protection
  * "OTP" chip is same chip, but with EM ID of zeroes. Locked after first write
* Other names:
  * RW64bit
  * RW125FL


### H5.5 / H7

^[Top](#top)

First "advanced" custom chip with H naming.

#### Characteristics

* Currently all structure is unknown
* No password protection
* Only supported by Russian "TMD"/"RFD" cloners
* H7 is advertised to work with "Stroymaster" access control
* Setting ID to "3F0096F87E" will make the chip show up like T55xx

### i57 / i57v2

\[ Chip is discontinued, no info \]

# ISO14443A

## Identifying broken ISO14443A magic

^[Top](#top)

When a magic card configuration is really messed up and the card is not labeled, it may be hard to find out which type of card it is.

Here are some tips if the card doesn't react or gives error on a simple `hf 14a reader`:

Let's force a 4b UID anticollision and see what happens:
```
hf 14a config --atqa force --bcc ignore --cl2 skip --rats skip
hf 14a reader
```
It it responds, we know it's a TypeA card. But maybe it's a 7b UID, so let's force a 7b UID anticollision:
```
hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip --rats skip
hf 14a reader
```
At this stage, you know if it's a TypeA 4b or 7b card and you can check further on this page how to reconfigure different types of cards.

To restore anticollision config of the Proxmark3:

```
hf 14a config --std
```

# MIFARE Classic

^[Top](#top)

Referred as M1, S50 (1k), S70 (4k)

## MIFARE Classic block0

^[Top](#top)

UID 4b: (actually NUID as there are no more "unique" IDs on 4b)

```
11223344440804006263646566676869
^^^^^^^^                         UID
        ^^                       BCC
          ^^                     SAK(*)
            ^^^^                 ATQA
                ^^^^^^^^^^^^^^^^ Manufacturer data
(*) some cards have a different SAK in their anticollision and in block0: +0x80 in the block0 (e.g. 08->88, 18->98)
```


Computing BCC on UID 11223344: `analyse lcr -d 11223344` = `44`

UID 7b:

```
04112233445566884400c82000000000
^^                               Manufacturer byte
^^^^^^^^^^^^^^                   UID
              ^^                 SAK(*)
                ^^^^             ATQA
                    ^^^^^^^^^^^^ Manufacturer data
(*) all? cards have a different SAK in their anticollision and in block0: +0x80 in the block0 (e.g. 08->88, 18->98)
```

## MIFARE Classic Gen1A aka UID

^[Top](#top)

* Other names:
  - ZERO (RU)

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 1a
```

### Magic commands

^[Top](#top)

* Wipe: `40(7)`, `41` (use 2000ms timeout)
* Read: `40(7)`, `43`, `30xx`+crc
* Write: `40(7)`, `43`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

### Characteristics

^[Top](#top)

* UID: Only 4b versions
* ATQA:
  * all cards play blindly the block0 ATQA bytes, beware!
* SAK:
  * some cards play blindly the block0 SAK byte, beware!
  * some cards use a fix "08" in anticollision, no matter the block0
  * some cards use a fix "08" in anticollision, unless SAK in block0 has most significant bit "80" set, in which case SAK="88"
* BCC:
  * all cards play blindly the block0 BCC byte, beware!
* ATS:
  * no card with ATS

#### MIFARE Classic Gen1A flavour 1

^[Top](#top)

* SAK: play blindly the block0 SAK byte, beware!
* PRNG: static 01200145
* Wipe: filled with 0xFF

#### MIFARE Classic Gen1A flavour 2

^[Top](#top)

* SAK: play blindly the block0 SAK byte, beware!
* PRNG: static 01200145
* Wipe: filled with 0x00

#### MIFARE Classic Gen1A flavour 3

^[Top](#top)

* SAK: 08
* PRNG: static 01200145
* Wipe: filled with 0xFF

#### MIFARE Classic Gen1A flavour 4

^[Top](#top)

* SAK: 08
* PRNG: weak
* Wipe: timeout, no wipe

#### MIFARE Classic Gen1A flavour 5

^[Top](#top)

* SAK: 08
* PRNG: weak
* Wipe: reply ok but no wipe performed

#### MIFARE Classic Gen1A flavour 6

^[Top](#top)

* SAK: 08 or 88 if block0_SAK most significant bit is set
* PRNG: weak
* Wipe: timeout, no wipe

#### MIFARE Classic Gen1A flavour 7

^[Top](#top)

* SAK: 08 or 88 if block0_SAK most significant bit is set
* PRNG: weak
* Wipe: filled with 0x00

### Proxmark3 commands

^[Top](#top)

```
hf mf csetuid
hf mf cwipe
hf mf csetblk
hf mf cgetblk
hf mf cgetsc
hf mf cload 
hf mf csave
hf mf cview
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
# MFC Gen1A 1k:
hf mf cwipe -u 11223344 -a 0004 -s 08
# MFC Gen1A 4k:
hf mf cwipe -u 11223344 -a 0044 -s 18
```
or just fixing block0:
```
# MFC Gen1A 1k:
hf mf csetuid -u 11223344 -a 0004 -s 08
# MFC Gen1A 4k:
hf mf csetuid -u 11223344 -a 0044 -s 18
```

```
script run hf_mf_magicrevive
```

To execute commands manually:
```
hf 14a raw -a -k -b 7       40
hf 14a raw    -k            43
hf 14a raw    -k -c         A000
hf 14a raw       -c -t 1000 11223344440804006263646566676869
```
wipe:
```
hf 14a raw -a -k -b 7       40
hf 14a raw -t 1000          41
```

### libnfc commands

^[Top](#top)

```
nfc-mfsetuid
nfc-mfclassic R a u mydump
nfc-mfclassic W a u mydump
```

## MIFARE Classic Gen1B

^[Top](#top)

Similar to Gen1A, but supports directly read/write after command 40

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 1b
```

### Magic commands

^[Top](#top)

* Read: `40(7)`, `30xx`
* Write: `40(7)`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

## Mifare Classic Direct Write OTP

^[Top](#top)

Chip manufactured by iKey LLC as a bypass for Gen1 filters.
Support Direct Write as CUID, but block0 can be written only once.

The chip had an issue in the protocol implementation.

The reader could interrupt radiofield for 2-3 microseconds (standard pause in the bit period of ISO14443-2).
After the response to first `26 (7)` command, but before the following `93 70` command. In that case original M1 card will stop the flow, but OTP will continue it.

That issue led to the development of the filters against that card and discontinuation of the production.

As a successor, [OTP 2.0](#mifare-classic-otp-20) was created.

### Characteristics

^[Top](#top)

* Initial UID is AA55C396
* Android compatible

### Identify

^[Top](#top)

Only possible before personalization.

```
hf mf info
...
[+] Magic capabilities... Write Once / FUID
```

## MIFARE Classic OTP 2.0

^[Top](#top)

Similar to Gen1A, but after first block 0 edit, tag no longer replies to 0x40 command.
Were manufactured by iKey LLC as a replacement for [OTP](#mifare-classic-direct-write-otp)

### Characteristics

* Initial UID is 00000000
* BCC: unknown
* SAK/ATQA: fixed
* All bytes are 00 from factory wherever possible.

### Identify

^[Top](#top)

Only possible before personalization.

```
hf mf info
...
[=] --- Magic Tag Information
[+] Magic capabilities... Gen 1a

[=] --- PRNG Information
[+] Prng................. hard
```

### Magic commands

^[Top](#top)

* Write: `40(7)`, `43`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

## MIFARE Classic DirectWrite aka Gen2 aka CUID

^[Top](#top)

(also referred as MCT compatible by some sellers)

* Other names:
  * MF-8 (RU)
  * MF-3 (RU)
    - What's so special about this chip in particular..?

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 2 / CUID
```

### Magic commands

^[Top](#top)

Android compatible

* issue regular write to block0

### Characteristics

^[Top](#top)

* UID: 4b and 7b versions
* ATQA:
  * some cards play blindly the block0 ATQA bytes, beware!
  * some cards use a fix ATQA in anticollision, no matter the block0. Including all 7b.
* SAK:
  * some cards play blindly the block0 SAK byte, beware!
  * some cards use a fix "08" or "18" in anticollision, no matter the block0. Including all 7b.
* BCC:
  * some cards play blindly the block0 BCC byte, beware!
  * some cards compute a proper BCC in anticollision. Including all 7b computing their BCC0 and BCC1.
* ATS:
  * some cards don't reply to RATS
  * some reply with an ATS

#### MIFARE Classic DirectWrite flavour 1

^[Top](#top)

* UID 4b
* ATQA: play blindly the block0 ATQA bytes, beware!
* SAK: play blindly the block0 SAK byte, beware!
* BCC: play blindly the block0 BCC byte, beware!
* ATS: no
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 2

^[Top](#top)

* UID 4b
* ATQA: fixed
* SAK: fixed
* BCC: computed
* ATS: 0978009102DABC1910F005
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 3

^[Top](#top)

* UID 4b
* ATQA: play blindly the block0 ATQA bytes, beware!
* SAK: fixed
* BCC: play blindly the block0 BCC byte, beware!
* ATS: no
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 4

^[Top](#top)

* UID 7b
* ATQA: fixed
* SAK: fixed
* BCC: computed
* ATS: 0978009102DABC1910F005
* PRNG: static 00000000

#### MIFARE Classic DirectWrite flavour 5

^[Top](#top)

* UID 4b
* ATQA: fixed
* SAK: play blindly the block0 SAK byte, beware!
* BCC: computed
* ATS: no
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 6

^[Top](#top)

**TODO** need more info

* UID 7b
* ATS: 0D780071028849A13020150608563D

### Proxmark3 commands

^[Top](#top)

```
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344440804006263646566676869 --force

hf mf wipe --gen2
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config -h
```

e.g. for 4b UID:

```
hf 14a config --atqa force --bcc ignore --cl2 skip --rats skip

# for 1k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344440804006263646566676869 --force

# for 4k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344441802006263646566676869 --force

hf 14a config --std
hf 14a reader
```

e.g. for 7b UID:

```
hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip --rats skip

# for 1k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 04112233445566084400626364656667 --force

# for 4k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 04112233445566184200626364656667 --force

hf 14a config --std
hf 14a reader
```

## MIFARE Classic Gen3 aka APDU

^[Top](#top)

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 3 / APDU ( possibly )
```

### Magic commands

^[Top](#top)

Android compatible

* issue special APDUs

```
cla  ins p1  p2  len
 90  F0  CC  CC  10 <block0>  - write block 0
 90  FB  CC  CC  07 <uid>     - change uid (independently of block0 data)
 90  FD  11  11  00           - lock permanently
```
It seems the length byte gets ignored anyway.

Note: it seems some cards only accept the "change UID" command.

It accepts direct read of block0 (and only block0) without prior auth.

Writing to block 0 has some side-effects:

* It changes also the UID. Changing the UID *does not* change block 0.
* ATQA and SAK bytes are automatically replaced by fixed values.
* On 4-byte UID cards, BCC byte is automatically corrected.

### Characteristics

^[Top](#top)

* UID: 4b and 7b versions
* ATQA/SAK: fixed
* BCC: auto
* ATS: none

### Proxmark3 commands

^[Top](#top)

```
# change just UID:
hf mf gen3uid
# write block0:
hf mf gen3blk
# lock (uid/block0?) forever:
hf mf gen3freeze
```
See also
```
script run hf_mf_gen3_writer -h
```

Equivalent:
```
# change just UID:
hf 14a raw -s -c  -t 2000  90FBCCCC07 11223344556677
# read block0:
hf 14a raw -s -c 3000
# write block0:
hf 14a raw -s -c  -t 2000  90F0CCCC10 041219c3219316984200e32000000000
# lock (uid/block0?) forever:
hf 14a raw -s -c 90FD111100
```

## MIFARE Classic USCUID

^[Top](#top)

TLDR: These magic cards have a 16 byte long configuration page, which usually starts with 0x85.
All of the known tags using this, except for Ultralight tags, are listed here.

You cannot turn a Classic tag into an Ultralight and vice-versa!

### Characteristics

^[Top](#top)

* UID: 4/7 bytes
* ATQA: always read from block 0
* SAK: read from backdoor or configuration
* BCC: read from memory, beware!
* ATS: no/unknown

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 4 GDM / USCUID ( Magic Auth/Gen1 Magic Wakeup/Alt Magic Wakeup )
```

Possible tag wakeup mechanisms are:

* Magic Auth
* Gen1 Magic Wakeup
* Alt Magic Wakeup

### Magic commands

^[Top](#top)

* Magic authentication: select, `8000+crc`, `[Crypto1 Auth: 000000000000]`
  - Backdoor read: `38xx+crc`
  - Backdoor write: `A8xx+crc`, `[16 bytes data]+crc`
  - Read configuration: `E000+crc`
  - Write configuration: `E100+crc`; `[16 bytes data]+crc`
* Magic wakeup (A: 00): `40(7)`, `43`
* Magic wakeup (B: 85): `20(7)`, `23`
  - Backdoor read main block: `30xx+crc`
  - Backdoor write main block: `A0xx+crc`, `[16 bytes data]+crc`
  - Read hidden block: `38xx+crc`
  - Write hidden block: `A8xx+crc`, `[16 bytes data]+crc`
  - Read configuration: `E000+crc`
  - Write configuration: `E100+crc`
  
  **DANGER**
  - Set main memory and config to 00 `F000+crc`
  - Set main memory and config to FF `F100+crc`
  - Set main memory and config to 55 (no 0A response) `F600+crc`
  - Set backdoor memory to 00 `F800+crc`
  - Set backdoor memory to FF `F900+crc`
  - Set backdoor memory to 55 (no 0A response) `FE00+crc`

### USCUID configuration guide

^[Top](#top)

1. Configuration

```
85000000000000000000000000000008
      ^^^^^^    ^^          ^^   >> ??? Mystery ???
^^^^                             >> Gen1a mode (works with bitflip)
    ^^                           >> Magic wakeup command (00 for 40-43; 85 for 20-23)
            ^^                   >> Block use of Key B if readable by ACL
              ^^                 >> CUID mode
                  ^^             >> MFC EV1 CL2 Perso config*
                    ^^           >> Shadow mode**
                      ^^         >> Magic Auth command
                        ^^       >> Static encrypted nonce mode
                          ^^     >> Signature sector
                              ^^ >> SAK***

To enable an option, set it to 5A.
* 5A - unfused F0. C3 - F0: CL2 UID; A5 - F1: CL2 UID with anticollision shortcut; 87 - F2: CL1 Random UID; 69 - F3: CL1 non-UID. Anything else is going to be ignored, and set as 4 bytes.
** Do not change the real ACL! Backdoor commands only acknowledge FF0780. To recover, disable this byte and issue regular write to sector trailer.
*** If perso byte is enabled, this SAK is ignored, and hidden SAK is used instead.
```

* Gen1a mode:                            Allow using custom wakeup commands, like real gen1a chip, to run backdoor commands, as well as some extras.
* Magic wakeup command:                  Use different wakeup commands for entering Gen1a mode. A) 00 - 40(7), 43; B) 85 - 20(7), 23.
* Block use of Key B if readable by ACL: Per the MF1ICS50 datasheet, if Key B is readable by the ACL, using it shall give a Cmd Error 04. This option controls whether it happens or not.
* CUID mode:                             Allow direct write to block 0, instead of giving Cmd Error 04.
* MFC EV1 CL2 Perso config:              When configured, the tag behaves like a real Mifare Classic EV1 7B UID tag, and reads UID from backdoor blocks. Otherwise, the tag acts like a 4 byte tag.
* Shadow mode:                           Writes to memory persisting in tag RAM. As soon as no power is left, the contents are restored to saved data.
* Magic Auth Command:                    Acknowledge command `8000` after selection, and call for Crypto1 auth with key `000000000000`.
* Static encrypted nonce mode:           Use static encrypted nonces for authentication, making key recovery impossible.
* Signature sector:                      Acknowledge auth commands to sector 17, which is stored in backdoor sector 1.
* SAK:                                   If perso byte is not set, after UID select, send this value.


2. Backdoor blocks

```

Sector 0
88 04 BD E5 D4 04 6A BB 5B 80 0A 08 44 00 00 00 - Block 0: Perso F0, F1 data
^^ ^^ ^^ ^^                                     - UID0
            ^^                                  - BCC0
               ^^                               - SAK0 (0x04 to call for CL2)
                  ^^ ^^ ^^ ^^                   - UID1
                              ^^                - BCC1
                                 ^^             - SAK1
                                    ^^ ^^ ^^ ^^ - Unused
04 BD E5 6A 36 08 00 00 00 00 00 00 00 00 00 00 - Block 1: Perso F3 data
^^ ^^ ^^ ^^                                     - UID0
            ^^                                  - BCC0
               ^^                               - SAK0
                  ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ ^^ - Unused 
Block 2: unused
Block 3: ignored (custom keys, acl; broken acl ignored - anticollision will still work)
Sector 1
[Signature sector (#17) - needs config byte 13 (from 0) enabled to allow auth]
Sectors 2-15
[Unused]
```

### Proxmark3 commands

^[Top](#top)
```
# Read config block from card
hf mf gdmcfg

# Write config block to card
hf mf gdmsetcfg

# Parse config block to card
hf mf gdmparsecfg

# Write block to card
hf mf gdmsetblk
```

### libnfc commands

^[Top](#top)
No implemented commands today

### Variations

^[Top](#top)
| Factory configuration | Name |
| --- | --- |
| 850000000000000000005A5A00000008 | GDM |
| 850000000000005A00FF005A00000008 | GDCUID |
| 850000000000005A0000005A5A5A0008 | UCUID |
| 8500000000005A00005A005A005A0008 | "7 byte hard" |
| 7AFF850102015A00005A005A005A0008 | M1-7B |
| 7AFF85000000000000FF000000000008 | FUID |
| 7AFF000000000000BAFA358500000008 | PFUID |
| 7AFF000000000000BAFA000000000008 | UFUID |
| 7AFF0000000000000000000000000008 | ZUID |

*Not all tags are the same!* UFUID, ZUID and PFUID* are not full implementations of Magic85 - they only acknowledge the first 8 (except wakeup command) and last config byte(s).

*Read and write config commands are flipped

Well-known variations are described below.

## FUID

^[Top](#top)

Known as "write only once", which is only partially true.

Allows direct write to block 0 only when UID is default `AA55C396`. But always could be rewritten multiple times with backdoors commands.

Backdoor commands are available even after the personalization and makes that tag detectable.

That's a key difference from [OTP](#mifare-classic-direct-write-otp)/[OTP 2.0](#mifare-classic-otp-20) tags.

### Characteristics

^[Top](#top)

* Configuration block value: `7AFF85000000000000FF000000000008`
* Initial UID: `AA55C396`
* Allows direct write to the block 0 (before the personalisation), so is Android compatible
* Responds to magic wakeup `20(7)`, `23` commands

### Identify

^[Top](#top)
```
hf mf info
...
[+] Magic capabilities... Gen 4 GDM / USCUID ( Alt Magic Wakeup )
[+] Magic capabilities... Write Once / FUID

```

### Parsed configuration

^[Top](#top)
```
[usb] pm3 --> hf mf gdmcfg --gdm
[+] Config... 7A FF 85 00 00 00 00 00 00 FF 00 00 00 00 00 08
[+]           7A FF .......................................... Magic wakeup enabled with GDM config block access
[+]                 85 ....................................... Magic wakeup style GDM 20(7)/23
[+]                    00 00 00 .............................. Unknown
[+]                             00 ........................... Key B use allowed when readable by ACL
[+]                                00 ........................ Block 0 Direct Write Disabled (CUID)
[+]                                   00 ..................... Unknown
[+]                                      FF .................. MFC EV1 personalization: 4B UID from Block 0
[+]                                         00 ............... Shadow mode disabled
[+]                                           00 ............. Magic auth disabled
[+]                                             00 ........... Static encrypted nonce disabled
[+]                                               00 ......... MFC EV1 signature disabled
[+]                                                  00 ...... Unknown
[+]                                                     08 ... SAK
```

### Commands

^[Top](#top)

* Commands described under the corresponding section of USCUID chip
* Example of changing block 0 after the personalization:

```
[usb] pm3 --> hf 14a raw -k -a -b 7 20
[+] 0A
[usb] pm3 --> hf 14a raw -k -a 23
[+] 0A
[usb] pm3 --> hf 14a raw -c -k -a A000
[+] 0A
[usb] pm3 --> hf 14a raw -c -k -a B502454EBC0804000168AA8947CE4D1D <- Writing 0 block with the backdoor command
[+] 0A
[usb] pm3 --> hf 14a raw -c -a 5000
[usb] pm3 --> hf mf rdbl --blk 0

[=]   # | sector 00 / 0x00                                | ascii
[=] ----+-------------------------------------------------+-----------------
[=]   0 | B5 02 45 4E BC 08 04 00 01 68 AA 89 47 CE 4D 1D | ..EN.....h..G.M.
```

### Proxmark3 commands

^[Top](#top)

* `hf mf gdmcfg --gdm`
* `hf mf gdmsetcfg --gdm`
* `hf mf gdmsetblk --gdm`

## UFUID

^[Top](#top)

The tag is positioned as "sealable UID", so that means you could use the same commands, as you could use for UID chip in a default state. But after the sealing (changing the configuration) tag will not answer to the backdoor commands and will behave as a normal Mifare Classic tag.

*But at the same time there is some unidentified behavior, which doesn't fully corresponds the protocol and original Mifare Classic tags. So the tag could be filtered out with a protocol-based filters (i.e. Iron Logic OTP2 filter).*

### Characteristics

^[Top](#top)

* Configuration block value: `7AFF000000000000BAFA000000000008`
* No direct write to block 0
* Responds to magic wakeup `40(7)`, `43` commands before the sealing
* Acknowledge only the first (except wakeup command) and last config byte(s), so doesn't have the hidden block

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 1a
[+] Magic capabilities... Gen 4 GDM / USCUID ( Gen1 Magic Wakeup )

```

Currently Proxmark3 doesn't identify it as a separate tag.
Before the sealing could be detected from the config block value.

### Parsed configuration

^[Top](#top)
```
[usb] pm3 --> hf mf gdmcfg --gen1a
[+] Config... 7A FF 00 00 00 00 00 00 BA FA 00 00 00 00 00 08
[+]           7A FF .......................................... Magic wakeup enabled with GDM config block access
[+]                 00 ....................................... Magic wakeup style Gen1a 40(7)/43
[+]                    00 00 00 .............................. Unknown
[+]                             00 ........................... Key B use allowed when readable by ACL
[+]                                00 ........................ Block 0 Direct Write Disabled (CUID)
[+]                                   BA ..................... Unknown
[+]                                      FA .................. MFC EV1 personalization: 4B UID from Block 0
[+]                                         00 ............... Shadow mode disabled
[+]                                           00 ............. Magic auth disabled
[+]                                             00 ........... Static encrypted nonce disabled
[+]                                               00 ......... MFC EV1 signature disabled
[+]                                                  00 ...... Unknown
[+]                                                     08 ... SAK
```

### Commands

^[Top](#top)

All commands are available before sealing.

* Proxmark3 magic Gen1 commands
* Proxmark3 magic Gen4 GDM commands

Example of the sealing, performed by Chinese copiers in raw commands:

```
hf 14a raw -a -k -b 7 40
hf 14a raw    -k      43
hf 14a raw    -k -c   e100
hf 14a raw       -c   85000000000000000000000000000008
```

### Proxmark3 commands

^[Top](#top)

All commands are available before sealing.

* `hf mf gdmcfg --gen1a`
* `hf mf gdmsetcfg --gen1a`
* `hf mf gdmsetblk --gen1a`
* `hf mf csetuid`
* `hf mf cwipe`
* `hf mf csetblk`
* `hf mf cgetblk`
* `hf mf cgetsc`
* `hf mf cload`
* `hf mf csave`
* `hf mf cview`

## ZUID

^[Top](#top)

That tag is a UID tag, built on USCUID chip. It doesn't sold separately, but could be found on marketplaces under the guise of a UID tag.

### Characteristics

^[Top](#top)

* Configuration block value: `7AFF0000000000000000000000000008`
* No direct write to block 0
* Responds to magic wakeup `40(7)`, `43` commands
* Acknowledge only the first (except wakeup command) and last config byte(s), so doesn't have the hidden block

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 1a
[+] Magic capabilities... Gen 4 GDM / USCUID ( Gen1 Magic Wakeup )

```

Currently Proxmark3 doesn't identify it as a separate tag.
Could be detected from the config block value.

### Parsed configuration

^[Top](#top)
```
[usb] pm3 --> hf mf gdmcfg --gen1a
[+] Config... 7A FF 00 00 00 00 00 00 BA FA 00 00 00 00 00 08
[+]           7A FF .......................................... Magic wakeup enabled with GDM config block access
[+]                 00 ....................................... Magic wakeup style Gen1a 40(7)/43
[+]                    00 00 00 .............................. Unknown
[+]                             00 ........................... Key B use allowed when readable by ACL
[+]                                00 ........................ Block 0 Direct Write Disabled (CUID)
[+]                                   BA ..................... Unknown
[+]                                      FA .................. MFC EV1 personalization: 4B UID from Block 0
[+]                                         00 ............... Shadow mode disabled
[+]                                           00 ............. Magic auth disabled
[+]                                             00 ........... Static encrypted nonce disabled
[+]                                               00 ......... MFC EV1 signature disabled
[+]                                                  00 ...... Unknown
[+]                                                     08 ... SAK
```

### Commands

^[Top](#top)

* Proxmark3 magic Gen1 commands
* Proxmark3 magic Gen4 GDM commands

### Proxmark3 commands

^[Top](#top)

* `hf mf gdmcfg --gen1a`
* `hf mf gdmsetcfg --gen1a`
* `hf mf gdmsetblk --gen1a`
* `hf mf csetuid`
* `hf mf cwipe`
* `hf mf csetblk`
* `hf mf cgetblk`
* `hf mf cgetsc`
* `hf mf cload`
* `hf mf csave`
* `hf mf cview`

## GDM

^[Top](#top)

The tag has a shadow mode, which means that every change to normal MFC memory would be restored back from the persistent memory after being off RFID field.

### Characteristics

^[Top](#top)

* Configuration block value: `850000000000000000005A5A00000008`
* No direct write to block 0
* Responds to magic authentication: select, `8000+crc`, `[Crypto1 Auth: 000000000000]`

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 4 GDM / USCUID ( Magic Auth )

```

Could be manually validated with the configuration block value.

### Parsed configuration

^[Top](#top)
```
[usb] pm3 --> hf mf gdmcfg
[+] Config... 85 00 00 00 00 00 00 00 00 00 5A 5A 00 00 00 08
[+]           85 00 .......................................... Magic wakeup disabled
[+]                 00 ....................................... Magic wakeup style Gen1a 40(7)/43
[+]                    00 00 00 .............................. Unknown
[+]                             00 ........................... Key B use allowed when readable by ACL
[+]                                00 ........................ Block 0 Direct Write Disabled (CUID)
[+]                                   00 ..................... Unknown
[+]                                      00 .................. MFC EV1 personalization: 4B UID from Block 0
[+]                                         5A ............... Shadow mode enabled
[+]                                           5A ............. Magic auth enabled
[+]                                             00 ........... Static encrypted nonce disabled
[+]                                               00 ......... MFC EV1 signature disabled
[+]                                                  00 ...... Unknown
[+]                                                     08 ... SAK
```

### Proxmark3 commands

^[Top](#top)

* Backdoor write: `gdmsetcfg`
* Read configuration: `gdmcfg`
* Write configuration: `gdmsetcfg`

## GDCUID

^[Top](#top)

That tag is a CUID tag, built on USCUID chip. It doesn't sold separately, but could be found on marketplaces under the guise of a CUID tag.

### Characteristics

^[Top](#top)

* Configuration block value: `850000000000005A00FF005A00000008`
* Allows direct write to the block 0, so is Android compatible
* Responds to magic authentication: select, `8000+crc`, `[Crypto1 Auth: 000000000000]`

### Identify

^[Top](#top)

```
hf mf info
...
[+] Magic capabilities... Gen 2 / CUID
[+] Magic capabilities... Gen 4 GDM / USCUID ( Magic Auth )

```
Currently Proxmark3 doesn't identify it as a separate tag.
Could be manually validated with the configuration block value.

### Parsed configuration

^[Top](#top)
```
[usb] pm3 --> hf mf gdmcfg
[+] Config... 85 00 00 00 00 00 00 5A 00 FF 00 5A 00 00 00 08
[+]           85 00 .......................................... Magic wakeup disabled
[+]                 00 ....................................... Magic wakeup style Gen1a 40(7)/43
[+]                    00 00 00 .............................. Unknown
[+]                             00 ........................... Key B use allowed when readable by ACL
[+]                                5A ........................ Block 0 Direct Write Enabled (CUID)
[+]                                   00 ..................... Unknown
[+]                                      FF .................. MFC EV1 personalization: 4B UID from Block 0
[+]                                         00 ............... Shadow mode disabled
[+]                                           5A ............. Magic auth enabled
[+]                                             00 ........... Static encrypted nonce disabled
[+]                                               00 ......... MFC EV1 signature disabled
[+]                                                  00 ...... Unknown
[+]                                                     08 ... SAK
```

### Proxmark3 commands

^[Top](#top)

* Backdoor write: `gdmsetcfg`
* Read configuration: `gdmcfg`
* Write configuration: `gdmsetcfg`

## MIFARE Classic, other versions

^[Top](#top)

**TODO**

* ZXUID, EUID, ICUID, KUID?

## MIFARE Classic Super

^[Top](#top)

It behaves like regular Mifare Classic but records reader auth attempts.

### MIFARE Classic Super Gen1

^[Top](#top)

Old type of cards, hard to obtain. They are DirectWrite, UID can be changed via 0 block or backdoor commands.

* UID: 4b version
* ATQA/SAK: fixed
* BCC: auto
* ATS: fixed, 0978009102DABC1910F005

ATQA/SAK matches 1k card, but works as 4k card.

Backdoor commands provided over APDU. Format:

```
00 A6 A0 00 05 FF FF FF FF 00
^^ ^^                         Backdoor command header
      ^^                      Backdoor command (A0 - set UID/B0 - get trace/C0 - reset card)
         ^^                   Type of answer (used in key recovery to select trace number)
            ^^                Length of user provided data
               ^^ ^^ ^^ ^^ ^^ User data
```

👉 You can't change UID with backdoor command if incorrect data is written to the 0 sector trailer!

### MIFARE Classic Super Gen1B

DirectWrite card, ATS unknown. Probably same as Gen1, except backdoor commands.
Implementation: https://github.com/netscylla/super-card/blob/master/libnfc-1.7.1/utils/nfc-super.c

### MIFARE Classic Super Gen2

^[Top](#top)

New generation of cards, based on limited Gen4 chip. Emulates Gen1 backdoor protocol, but can store up to 7 different traces.

Card always answers `ff  ff  ff  ff` as `at`, so reading/writing it via Mifare protocol is impossible.

UID is changeable via UMC backdoor write to 0 block.

* UID: 4b and 7b versions
* ATQA/SAK: fixed
* BCC: auto
* ATS: changeable, default as Gen1

Gen4 commands available:

```
CF <passwd> 34 <1b length><0-16b ATS>            // Configure ATS
CF <passwd> CC                                   // Version information, returns 00 00 00 02 AA
CF <passwd> CD <1b block number><16b block data> // Backdoor write 16b block
CF <passwd> CE <1b block number>                 // Backdoor read 16b block
CF <passwd> FE <4b new_password>                 // Change password
```

### MIFARE Classic Super Furui

^[Top](#top)

#### Characteristics

^[Top](#top)

* SAK/ATQA: play blindly the block0 bytes, beware!
* BCC: play blindly the block0 BCC bytes, beware!
* PRNG: hard

**!!!WARNING!!!** This tag can die for no reason (no reply to WUPA/REQA). We don't know why this happens.

#### Identify

^[Top](#top)

```
[usb] pm3 --> hf 14a raw -sct 250 AAA500000000000000000000000000000000
[+] 90 00
```

#### Magic commands

^[Top](#top)

* Configure: `AAA5[16 byte config]`+crc
* Write block 0: `AAA4[4b UID][1b BCC][1b SAK][2b ATQA reversed]0000000000000000`+crc
* Recover trace: `AAA8[00/01][00-08]`+crc

Caution: tag does not append CRC to magic responses!

Please use config as 00 bytes.

Parsing traces:
```
44 33 22 11 03 61 08 68 7A C7 4B 62 43 A6 11 6F 64 F3
^^ ^^ ^^ ^^                                           -- UID
            ^^ ^^                                     -- auth command, reversed
                  ^^ ^^ ^^ ^^                         -- Auth (nt)
                              ^^ ^^ ^^ ^^             -- Auth (nr)
                                          ^^ ^^ ^^ ^^ -- Auth (ar)
```

### Identify

^[Top](#top)

Only Gen1/Gen2 at this moment (Gen1B is unsupported):

```
hf mf info
...
[+] Magic capabilities... Super card ( Gen ? )
```

### Proxmark3 commands

```
[usb] pm3 --> hf mf supercard
...

[usb] pm3 --> hf mf supercard --furui
...
```

# MIFARE Ultralight

^[Top](#top)

## MIFARE Ultralight blocks 0..2

^[Top](#top)

```
SN0  SN1  SN2  BCC0
SN3  SN4  SN5  SN6
BCC1 Int  LCK0 LCK1
```

UID is made of SN0..SN6 bytes

Computing BCC0 on UID 04112233445566: `analyse lcr -d 88041122` = `bf`

Computing BCC1 on UID 04112233445566: `analyse lcr -d 33445566` = `44`

Int is internal, typically 0x48

Anticol shortcut (CL1/3000) is supported for UL, ULC, NTAG except NTAG I2C

Some cards have a password: `B6AA558D`. Usually "copykey" chips.

## MIFARE Ultralight Gen1A

^[Top](#top)

### Identify

**TODO**

### Characteristics

#### Magic commands

**TODO**

#### UID

Only 7b versions

#### SAK, ATQA, BCC, ATS

**TODO** need more tests

### Proxmark3 commands

^[Top](#top)

```
script run hf_mfu_setuid -h
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config -h
script run hf_mf_magicrevive -u
```

## MIFARE Ultralight DirectWrite

^[Top](#top)

### Identify

^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

It seems so far that all MFUL DW have an ATS.

### Magic commands

^[Top](#top)

Issue three regular MFU write commands in a row to write first three blocks.

### Characteristics

^[Top](#top)

* UID: Only 7b versions
* ATQA:
  * all cards play fix ATQA
* SAK:
  * all cards play fix SAK
* BCC:
  * some cards play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
  * some cards compute proper BCC0 and BCC1 in anticollision
* ATS:
  * all cards reply with an ATS

#### MIFARE Ultralight DirectWrite flavour 1

^[Top](#top)

* BCC: computed
* ATS: 0A78008102DBA0C119402AB5
* Anticol shortcut (CL1/3000): fails

#### MIFARE Ultralight DirectWrite flavour 2

^[Top](#top)

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A00A000AB00000000000000000184D
* Anticol shortcut (CL1/3000): succeeds

### Proxmark3 commands

^[Top](#top)

```
hf mfu setuid -h
```

Equivalent: don't use `hf mfu wrbl` as you need to write three blocks in a row, but do, with proper BCCx:

```
hf 14a raw -s -c -k a2 00 041122bf 
hf 14a raw    -c -k a2 01 33445566
hf 14a raw    -c    a2 02 44480000
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config -h
```

E.g.:
```
hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip --rats skip
hf mfu setuid --uid 04112233445566
hf 14a config --std
hf 14a reader
```

### libnfc commands

^[Top](#top)

```
nfc-mfultralight -h
```
See `--uid` and `--full`

### Android

^[Top](#top)

* MIFARE++ Ultralight

## MIFARE Ultralight EV1 DirectWrite

^[Top](#top)

Similar to MFUL DirectWrite

### Identify

^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Characteristics

^[Top](#top)

* UID: Only 7b versions
* ATQA:
  * all cards play fix ATQA
* SAK:
  * all cards play fix SAK
* BCC:
  * cards play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS:
  * all cards reply with an ATS

#### MIFARE Ultralight EV1 DirectWrite flavour 1

^[Top](#top)

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A000000AC30004030101000B0341DF

#### MIFARE Ultralight EV1 DirectWrite flavour 2

^[Top](#top)

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A00A000AC30004030101000B0316D7

#### MIFARE Ultralight EV1 DirectWrite flavour 3

^[Top](#top)

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A000000A3C0004030101000E03

## MIFARE Ultralight C Gen1A

^[Top](#top)

Similar to MFUL Gen1A

## MIFARE Ultralight C DirectWrite

^[Top](#top)

Similar to MFUL DirectWrite

### Identify

^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Characteristics

^[Top](#top)

* UID: Only 7b versions
* ATQA:
  * all cards play fix ATQA
* SAK:
  * all cards play fix SAK
* BCC:
  * cards compute proper BCC0 and BCC1 in anticollision
* ATS:
  * all cards reply with an ATS

#### MIFARE Ultralight C DirectWrite flavour 1

^[Top](#top)

* BCC: computed
* ATS: 0A78008102DBA0C119402AB5
* Anticol shortcut (CL1/3000): fails

# NTAG

^[Top](#top)

## NTAG213 DirectWrite

^[Top](#top)

Similar to MFUL DirectWrite

### Identify

^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Characteristics

^[Top](#top)

* UID: Only 7b versions
* ATQA:
  * all cards play fix ATQA
* SAK:
  * all cards play fix SAK
* BCC:
  * cards play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS:
  * all cards reply with an ATS

#### NTAG213 DirectWrite flavour 1

^[Top](#top)

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 0A78008102DBA0C119402AB5
* Anticol shortcut (CL1/3000): succeeds

## NTAG21x

^[Top](#top)

### Identify

^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : NTAG21x
```

### Characteristics

^[Top](#top)

Emulates fully NTAG213, 213F, 215, 216, 216F

Emulates partially  UL EV1 48k/128k, NTAG210, NTAG212, NTAGI2C 1K/2K, NTAGI2C 1K/2K PLUS

Anticol shortcut (CL1/3000): fails

### Proxmark3 commands

^[Top](#top)

```
script run hf_mfu_magicwrite -h
```

## UL series (RU)

^[Top](#top)

Custom chips, manufactured by iKey LLC for cloning Ultralight tags used in Visit intercoms. That leads to the non-standard for Ultralight chips tag version.

### UL-Y

^[Top](#top)

Ultralight magic, 16 pages. Recommended for Vizit RF3.1 with markings "3.1" or "4.1".
Behavior: allows writes to page 0-2.

#### Identify

^[Top](#top)

```
hf mfu rdbl --force -b 16
hf 14a raw -sct 250 60
```
If tag replies with
`Cmd Error: 00`
`00 00 00 00 00 00 00 00`
then it is UL-Y.

### ULtra

^[Top](#top)

Ultralight EV1 magic; 41 page. Recommended for Vizit RF3.1 with 41 page.
Behavior: allows writes to page 0-2.

#### Identify

^[Top](#top)

```
hf mfu info
...
[=] TAG IC Signature: 0000000000000000000000000000000000000000000000000000000000000000
[=] --- Tag Version
[=]        Raw bytes: 00 34 21 01 01 00 0E 03
[=]        Vendor ID: 34, Mikron JSC Russia
[=]     Product type: 21, unknown
```

#### ULtra flavour 1

^[Top](#top)

Could be identified by indirect evidence before writing

* Initial UID: `34 D7 08 11 AD D7 D0`
* `hf mfu dump --ns`
  ```
  [=]   3/0x03 | CF 39 A1 C8 | 1 | .9..
  [=]   4/0x04 | B6 69 26 0D | 1 | .i&.
  [=]   5/0x05 | EC A1 73 C4 | 1 | ..s.
  [=]   6/0x06 | 81 3D 29 B8 | 1 | .=).
  [=]  16/0x10 | 6A F0 2D FF | 0 | j.-.
  [=]  20/0x14 | 6A F0 2D FF | 0 | j.-.
  [=]  24/0x18 | 6A F0 2D FF | 0 | j.-.
  [=]  38/0x26 | 00 E2 00 00 | 0 | .... <- E2, Virtual Card Type Identifier is not default

  ```

#### ULtra flavour 2

^[Top](#top)

Could be identified by indirect evidence before writing

* Initial UID: `04 15 4A 23 36 2F 81`
* Values in pages `3, 4, 5, 6, 16, 20, 24, 38` are default for that tag flavour

### UL-5

^[Top](#top)

Ultralight EV1 magic; 41 page. Recommended for Vizit RF3.1 with 41 page.
Created as a response to filters that try to overwrite page 0 (as a detection for [ULtra](#mifare-ultra) tags).

Behavior: similar to Ultra, but after editing page 0 become locked and tag becomes the original Mifare Ultralight EV1 (except the tag version, which remains specific).

**WARNING!** When using UL-5 to clone, write UID pages in inverse (from 2 to 0) and do NOT make mistakes! This tag does not allow reversing one-way actions (OTP page, lock bits).

#### Identify

^[Top](#top)

```
hf mfu info
[=] UID: AA 55 C3 A1 30 61 80
TAG IC Signature: 0000000000000000000000000000000000000000000000000000000000000000
[=] --- Tag Version
[=]        Raw bytes: 00 34 21 01 01 00 0E 03
[=]        Vendor ID: 34, Mikron JSC Russia
```

After personalization it is not possible to identify UL-5.

The manufacturer confirmed unpersonalized tags could be identified by first 3 bytes of UID:

* `AA 55 39...`
* `AA 55 C3...`

### UL, other chips

**TODO**

UL-X, UL-Z - ?

# DESFire

^[Top](#top)

## "DESFire" APDU, 7b UID

### Identify

**TODO**

### Magic commands

Android compatible

* issue special APDUs

### Characteristics

^[Top](#top)

* ATQA: 0344
* SAK: 20
* ATS: 0675338102005110 or 06757781028002F0

Only mimics DESFire anticollision (but wrong ATS), no further DESFire support

### Proxmark commands

^[Top](#top)

UID 04112233445566
```
hf 14a raw -s -c 0200ab00000704112233445566
```
or equivalently
```
hf 14a apdu -s 00ab00000704112233445566
```

### libnfc commands

^[Top](#top)

```
pn53x-tamashell
4a0100
420200ab00000704112233445566
```

## "DESFire" APDU, 4b UID

^[Top](#top)

### Magic commands

^[Top](#top)

Android compatible

* issue special APDUs

### Characteristics

^[Top](#top)

* ATQA: 0008
  * This is FM1208-9, NOT DESFire!
* SAK: 20
* ATS: 0675338102005110 or 06757781028002F0

Only mimics DESFire anticollision (but wrong ATS), no further DESFire support

### Proxmark commands

^[Top](#top)

UID 04112233445566
```
hf 14a raw -s -c 0200ab00000411223344
```
or equivalently
```
hf 14a apdu -s 00ab00000411223344
```

It accepts longer UID but that doesn't affect BCC/ATQA/SAK

### pn53x-tamashell commands

^[Top](#top)
```
4a0100
420200ab00000411223344
```

### Remarks

^[Top](#top)

The same effect (with better ATQA!) can be obtained with a MFC Gen1A that uses SAK defined in block0:

```
hf mf csetblk --blk 0 -d 1122334444204403A1A2A3A4A5A6A7A8
hf 14a info
[+]  UID: 11 22 33 44 
[+] ATQA: 03 44
[+]  SAK: 20 [1]
[+] Possible types:
[+]    MIFARE DESFire MF3ICD40
```

# ISO14443B

^[Top](#top)

## Tiananxin TCOS CPU card

^[Top](#top)

This is a card sold on Taobao for testing readers.
ISO14443-4 compliant.

### Identify

```
hf 14a apdu -s 90B2900000 // Get Card OS version
>>> 90 B2 90 00 00
<<< 54 43 4F 53 20 56 31 2E 34 2E 30 90 00 | TCOS V1.4.0..
```

### Magic commands

All commands in APDU.

```
CL IN P1 P2 Lc Data
90 F4 CC CC 01 [..1 ] // Change protocol used              (1: ISO14443 [AA - type A, BB - type B])
90 F6 CC CC 01 [TA1 ] // Change TA1 value (transfer speed)
90 F8 CC CC 01 [..1 ] // Use random UID/PUPI value         (1: FF: static, AB: random)
90 F8 DD DD 01 [..1 ] // Set UID length                    (1: bytes in UID (04, 07, 0A for 4, 7, 10 bytes accordingly))
90 F8 EE EE 0B [... ] // Set UID/PUPI value                (FF+enter UID value here). To clear, use Lc=01; data=00.
90 FA CC CC 01 [FSCI] // Set FSCI                          (1: value 0-8)
90 FC CC CC 01 [SFGI] // Set SFGI (DO NOT SET TOO HIGH!)   (1: value 0-E)
90 FE CC CC 01 [FWI ] // Set FWI (DO NOT SET BELOW 4!!!)   (value 0-E)
```

More commands to follow. Be careful with some.

# ISO15693

^[Top](#top)

## ISO15693 magic

^[Top](#top)

### Identify

**TODO**

### Proxmark3 commands

^[Top](#top)

Always set a UID starting with `E0`.

```
hf 15 csetuid E011223344556677
```
or (ignore errors):
```
script run hf_15_magic -u E004013344556677  
```

<a id="g4top"></a>

# Multi

^[Top](#top)

## UMC

^[Top](#top)

A.k.a ultimate magic card,  most promenent feature is shadow mode (GTU) and optional password protected backdoor commands.

Can emulate MIFARE Classic, Ultralight/NTAG families, 14b UID & App Data

- [Identify](#identify-16)
- [Magic commands](#magic-commands-9)
- [Characteristics](#characteristics-12)
- [Proxmark3 commands](#proxmark3-commands-9)
- [Change ATQA / SAK](#change-atqa--sak)
- [Change ATS](#change-ats)
- [Set UID length (4, 7, 10)](#set-uid-length-4-7-10)
- [Set 14443A UID](#set-14443a-uid)
- [Set 14443B UID and ATQB](#set-14443b-uid-and-atqb)
- [(De)Activate Ultralight mode](#deactivate-ultralight-mode)
- [Select Ultralight mode](#select-ultralight-mode)
- [Set shadow mode (GTU)](#set-shadow-mode-gtu)
- [Direct block read and write](#direct-block-read-and-write)
- [(De)Activate direct write to block 0](#deactivate-direct-write-to-block-0)
- [Change backdoor password](#change-backdoor-password)
- [Dump configuration](#dump-configuration)
- [Fast configuration](#fast-configuration)
- [Presets](#presets)
- [Version and Signature](#version-and-signature)


### Identify

^[Top](#top) ^^[Gen4](#g4top)

👉 **TODO** If the password is not default, Tag doesn't get identified correctly by latest Proxmark3 client (it might get mislabeled as MFC Gen2/CUID, Gen3/APDU or NTAG21x Modifiable, depending on configured UID/ATQA/SAK/ATS)

👉 **TODO** Using C6 command can change config due to a bug in some cards. CC should be used instead.

```
hf 14a info
[+] Magic capabilities : Gen 4 GTU
```

The card will be identified only if the password is the default one. One can identify manually such card if the password is still the default one, with the command to get the current configuration:
```
hf 14a raw -s -c -t 1000 CF00000000C6
```
If the card is an Ultimate Magic Card, it returns 30 or 32 bytes.

### Magic commands

^[Top](#top) ^^[Gen4](#g4top)

There are two ways to program this card.

   1.  Use the raw commands designated by the `hf 14a` examples.

   ***OR***

   2.  Use the hf_mf_ultimatecard.lua script commands designated but the `script run hf_mf_ultimatecard` examples. This script is nof fully compartible with new version UMC.


script run hf_mf_ultimatecard.lua -h
```
This script enables easy programming of an Ultimate Mifare Magic card
Usage
script run hf_mf_ultimatecard -h -k <passwd> -c -w <type> -u <uid> -t <type> -p <passwd> -a <pack> -s <signature> -o <otp> -v <version> -q <atqa/sak> -g <gtu> -z <ats> -m <ul-mode> -n <ul-protocol>

Arguments
    -h      this help
    -c      read magic configuration
    -u      UID (8-20 hexsymbols), set UID on tag
    -t      tag type to impersonate
                 1 = Mifare Mini S20 4-byte 
                 2 = Mifare Mini S20 7-byte 15 = NTAG 210
                 3 = Mifare Mini S20 10-byte 16 = NTAG 212
                 4 = Mifare 1k S50 4-byte   17 = NTAG 213
                 5 = Mifare 1k S50 7-byte   18 = NTAG 215
                 6 = Mifare 1k S50 10-byte  19 = NTAG 216 
                 7 = Mifare 4k S70 4-byte   20 = NTAG I2C 1K
                 8 = Mifare 4k S70 7-byte   21 = NTAG I2C 2K
                 9 = Mifare 4k S70 10-byte  22 = NTAG I2C 1K PLUS
            ***  10 = UL -   NOT WORKING FULLY   23 = NTAG I2C 2K PLUS
            ***  11 = UL-C - NOT WORKING FULLY   24 = NTAG 213F
                 12 = UL EV1 48b                25 = NTAG 216F
                 13 = UL EV1 128b        
            ***  14 = UL Plus - NOT WORKING YET  

    -p      NTAG password (8 hexsymbols),  set NTAG password on tag.
    -a      NTAG pack ( 4 hexsymbols), set NTAG pack on tag.
    -s      Signature data (64 hexsymbols), set signature data on tag.
    -o      OTP data (8 hexsymbols), set `One-Time Programmable` data on tag.
    -v      Version data (16 hexsymbols), set version data on tag.
    -q      ATQA/SAK (<2b ATQA><1b SAK> hexsymbols), set ATQA/SAK on tag.
    -g      GTU Mode (1 hexsymbol), set GTU shadow mode.
    -z      ATS (<1b length><0-16 ATS> hexsymbols), Configure ATS. Length set to 00 will disable ATS.
    -w      Wipe tag. 0 for Mifare or 1 for UL. Fills tag with zeros and put default values for type selected.
    -m      Ultralight mode (00 UL EV1, 01 NTAG, 02 UL-C, 03 UL) Set type of UL.
    -n      Ultralight protocol (00 MFC, 01 UL), switches between UL and MFC mode
    -k      Ultimate Magic Card Key (IF DIFFERENT THAN DEFAULT 00000000)

Example usage
    -- read magic tag configuration
    script run hf_mf_ultimatecard -c
    -- set uid
    script run hf_mf_ultimatecard -u 04112233445566
    -- set NTAG pwd / pack
    script run hf_mf_ultimatecard -p 11223344 -a 8080
    -- set version to NTAG213
    script run hf_mf_ultimatecard -v 0004040201000f03
    -- set ATQA/SAK to [00 44] [08]
    script run hf_mf_ultimatecard -q 004408
    -- wipe tag with a NTAG213 or Mifare 1k S50 4 byte
    script run hf_mf_ultimatecard -w 1
    -- use a non default UMC key. Only use this if the default key for the MAGIC CARD was changed.
    script run hf_mf_ultimatecard -k ffffffff -w 1
    -- Wipe tag, turn into NTAG215, set sig, version, NTAG pwd/pak, and OTP.
    script run hf_mf_ultimatecard -w 1 -t 18 -u 04112233445566 -s 112233445566778899001122334455667788990011223344556677 -p FFFFFFFF -a 8080 -o 11111111
```

Special raw commands summary:

```
CF <passwd> 32 <00-04>                           // Configure GTU shadow mode
CF <passwd> 34 <1b length><0-16b ATS>            // Configure ATS
CF <passwd> 35 <2b ATQA><1b SAK>                 // Configure ATQA/SAK (swap ATQA bytes)
CF <passwd> 68 <00-02>                           // Configure UID length
CF <passwd> 69 <00-01>                           // (De)Activate Ultralight mode
CF <passwd> 6A <00-03>                           // Select Ultralight mode
CF <passwd> 6B <1b>                              // Set Ultralight and M1 maximum read/write sectors
CF <passwd> C6                                   // Dump configuration
CF <passwd> CC                                   // Version info, returns `00 00 00 [03 A0 (old) / 06 A0 (new) ]`
CF <passwd> CD <1b block number><16b block data> // Backdoor write 16b block
CF <passwd> CE <1b block number>                 // Backdoor read 16b block
CF <passwd> CF <1b param>                        // (De)Activate direct write to block 0
CF <passwd> F0 <30b configuration data>          // Configure all params in one cmd
CF <passwd> F1 <30b configuration data>          // Configure all params in one cmd and fuse the configuration permanently
CF <passwd> FE <4b new_password>                 // change password
```
Default `<passwd>`: `00000000`

### Characteristics

^[Top](#top) ^^[Gen4](#g4top)

* UID: 4b, 7b and 10b versions
* ATQA/SAK: changeable
* BCC: computed
* ATS: changeable, can be disabled
* Card Type: changeable
* Shadow mode: GTU
* Backdoor password mode

### Proxmark3 commands

^[Top](#top) ^^[Gen4](#g4top)

```
# view contents of tag memory:
hf mf gview
# Read a specific block via backdoor command:
hf mf ggetblk 
# Write a specific block via backdoor command:
hf mf gsetblk 
# Load dump to tag:
hf mf gload 
# Save dump from tag:
hf mf gsave
```
👉 **TODO** `hf mf gview` is currently missing Ultralight memory maps

Equivalent:

```
hf 14a raw -s -c -t 1000 CF00000000CE00
hf 14a raw -s -c -t 1000 CF00000000CE01
hf 14a raw -s -c -t 1000 CF00000000CE02
...
```

👉 **TODO** In Mifare Ultralight / NTAG mode, the special writes (`hf mfu restore` option `-s`, `-e`, `-r`) do not apply. Use `script run hf_mf_ultimatecard` for UID and signature, and `hf mfu wrbl` for PWD and PACK.

### Change ATQA / SAK

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>35<2b ATQA><1b SAK>
```

* ⚠ ATQA bytes are swapped in the command
* ⚠ ATQA bytes that result in `iso14443a card select failed` (I.E.  ATQA=0040 in raw form) can be corrected with `hf 14a config --atqa force`
* ⚠ when SAK bit 6 is set (e.g. SAK=20 or 28), ATS must be turned on, otherwise the card may not be recognized by some readers!
* ⚠ never set SAK bit 3 (e.g. SAK=04), it indicates an extra cascade level is required (see `hf 14a config --cl2 skip` or `hf 14a config --cl3 skip` to recover a misconfigured card)

Example: ATQA 0044 SAK 28, default pwd
```
hf 14a raw -s -c -t 1000 CF0000000035440028
```
OR (Note the script will correct the ATQA correctly)
```
script run hf_mf_ultimatecard -q 004428
```

### Change ATS

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>34<1b length><0-16b ATS>
```

 * `<length>`: ATS length byte, set to `00` to disable ATS
 * ⚠ when SAK bit 6 is set (e.g. SAK=20 or 28), ATS must be turned on, otherwise the card may not be recognized by some readers!
 * ATS CRC will be added automatically, don't configure it
 * Max ATS length: 16 bytes (+CRC)

Example: ATS to 0606757781028002F0, default pwd
```
hf 14a raw -s -c -t 1000 CF000000003406067577810280
```

Or

```
script run hf_mf_ultimatecard -z 06067577810280`
```

### Set UID length (4, 7, 10)

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>68<1b param>
```

 * `<param>`
   * `00`: 4 bytes
   * `01`: 7 bytes
   * `02`: 10 bytes

Example: set UID length to 7 bytes, default pwd
```
hf 14a raw -s -c -t 1000 CF000000006801
```

### Set 14443A UID

^[Top](#top) ^^[Gen4](#g4top)

UID is configured according to block0 with a backdoor write.  (Script commands are below the UID length examples)

Example: preparing first two blocks: (Note the UMC has to be in MFC mode and the correct UID byte length set)
```
hf 14a raw -s -c -t 1000 CF00000000CD00000102030405060708090A0B0C0D0E0F
hf 14a raw -s -c -t 1000 CF00000000CD01101112131415161718191A1B1C1D1E1F
hf 14a reader
```
MFC mode 4b UID  

=> UID `00010203`

`script run hf_mf_ultimatecard -t 4 -u 00010203`

MFC mode 7b UID  

=> UID `00010203040506`

`script run hf_mf_ultimatecard -t 5 -u 00010203040506`

MFC mode, 10b UID

=> UID `00010203040506070809`

`script run hf_mf_ultimatecard -t 6 -u 00010203040506070809`

Ultralight mode, 4b UID

=> UID `00010203`

Ultralight mode, 7b UID  

=> UID `00010210111213`  

👉 the UID is composed of first two blocks as in regular Ultralights

 * Examples
   * UL-EV1 48b = `script run hf_mf_ultimatecard -t 12 -u 00010203040506`
   * UL EV1 128b = `script run hf_mf_ultimatecard -t 13 -u 00010203040506`
   * NTAG 215 = `script run hf_mf_ultimatecard -t 18 -u 00010203040506`

Ultralight mode, 10b UID  
=> UID `00010203040506070809`  
👉 the UID is composed only from block0

### Set 14443B UID and ATQB

^[Top](#top) ^^[Gen4](#g4top)

* UID and ATQB are configured according to block0 with a (14a) backdoor write.
* UID size is always 4 bytes.
* 14B will show up only on new cards. (Need more tests on new card. Example not work)

Example:
```
hf 14a raw -s -c -t 1000 CF00000000CD00000102030405060708090A0B0C0D0E0F
hf 14b reader
```
=> UID 00010203  
=> ATQB 0405060708090A

### (De)Activate Ultralight mode

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>69<1b param>
```

 * `<param>`
   * `00`: MIFARE Classic mode
   * `01`: MIFARE Ultralight/NTAG mode

Example: activate Ultralight protocol, default pwd

```
hf 14a raw -s -c -t 1000 CF000000006901
```

Or

```
script run hf_mf_ultimatecard -n 01
```

In this mode, if SAK=`00` and ATQA=`0044`, it acts as an Ultralight card

⚠ only the first four bytes of each block will be mapped in the Ultralight memory map (so the Ultralight block numbers follow backdoor R/W block numbers).

### Select Ultralight mode

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>6A<1b param>
```

 * `<param>`
   * `00`: UL EV1
   * `01`: NTAG
   * `02`: UL-C
   * `03`: UL

⚠ it supposes Ultralight mode was activated (cf command `69`)

Example: set Ultralight mode to Ultralight-C, default pwd

```
hf 14a raw -s -c -t 1000 CF000000006A02
```
Or

```
script run hf_mf_ultimatecard -m 02
```

Now the card supports the 3DES UL-C authentication.

### Set Ultralight and M1 maximum read/write sectors

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>6B<1b blocks>
```
Hexadecimal, maximum sector data, default 0xFF, range 0x00-0xFF

Example: set maximum 63 blocks read/write for Mifare Classic 1K

```
hf 14a raw -s -c -t 1000 CF000000006B3F
```

### Set shadow mode (GTU)

^[Top](#top) ^^[Gen4](#g4top)

This description of shadow modes wroted by seller at marketpalces:

>This mode is divided into four states: off (pre-write), on (on restore), don’t care, and high-speed read and write. If you use it, please enter the pre-write mode first. At this time, write the full card data. After writing, set it to on. At this time, after writing the data, the first time you read the data just written, the next time you read It is the pre-written data. All modes support this operation. It should be noted that using any block to read and write in this mode may give wrong results.

And these conclusions were made after a number of tests with UMC (new version, configured as MFC for example):

| Mode | Buffer | Standart command (rdbl, wrbl e.t.c)     | Backdoor command (gsetblk, ggetblk, gload e.t.c.) |
|------|--------|-----------------------------------------|---------------------------------------------------|
| 2,3  |  buf23 | read/write from/to buf23                | read/write from/to buf23                          |
|  0   |  buf0  | read from buf0, write to buf0 and buf23 | read/write from/to buf23                          |
|  4   |   -    | read from buf0, write to buf23          | read/write from/to buf23                          |

Mode 1: For new card this mode looks like a bug. Reading/writing first two block use *buf23*. Reading other blocks use invalid region of memory and all returned data looks like pseudo-random. All acl looks like invalid. All data is readable by the keys and acl wich was written in *buf0*. Any writing operations in this mode use copy of *buf0* and only it. It`s not affected any other buffers. So if you change keys or/and acl you will must use new keys to read data.

Example (not work with new UMC):
`script run hf_mf_ultimatecard -w 1 -g 00 -t 18 -u 04112233445566 -s 112233445566778899001122334455667788990011223344556677 -p FFFFFFFF -a 8080 -o 11111111 -g 01`

   * -w 1 = wipe the card in Ultralight Mode
   * -g 00 = turn on pre-write mode
   * -t 18 = change the type of card to NTAG 215
   * -u = set the uid
   * -s = set the signature
   * -p = set the NTAG password
   * -a = set the PACK
   * -o = set the OTP
   * -g 01 = turn on restore mode

At this point the card is set to a unwritten NTAG 215. Now any data written to the card will only last for 1 read.  Write a popular game toy to it, read it, now it is back to the unwritten NTAG 215.

👉 Remember to disable GTU mode to get the card back to a normal state.

`script run hf_mf_ultimatecard -g 03`

```
hf 14a raw -s -c -t 1000 CF<passwd>32<1b param>
```

 * `<param>`
   * `00`: pre-write, shadow data can be written
   * `01`: restore mode
     - WARNING: new UMC (06a0) cards return garbage data when using 01
   * `02`: disabled
   * `03`: disabled, high speed R/W mode for Ultralight?
   * `04`: split mode, work with new UMC. With old UMC is untested.

### Direct block read and write

^[Top](#top) ^^[Gen4](#g4top)

Using the backdoor command, one can read and write any area without MFC password, similarly to MFC Gen1 card. It should be noted that this command must be used to modify UID.

Backdoor read 16b block:
```
hf 14a raw -s -c -t 1000 CF<passwd>CE<1b block number>
```
Backdoor write 16b block:
```
hf 14a raw -s -c -t 1000 CF<passwd>CD<1b block number><16b block data>
```

Read/Write operations work on 16 bytes, no matter the Ultralight mode.

Note that only the first four bytes of each block will be mapped in the Ultralight memory map.

Example: read block0, default pwd
```
hf 14a raw -s -c -t 1000 CF00000000CE00
```
Example: write block0 with factory data, default pwd
```
hf 14a raw -s -c -t 1000 CF00000000CD00112233441C000011778185BA18000000
```

### (De)Activate direct write to block 0

^[Top](#top) ^^[Gen4](#g4top)

This command enables/disables direct writes to block 0.

```
hf 14a raw -s -c -t 1000 CF<passwd>CF<1b param>
```

 * `<param>`
   * `00`: Activate direct write to block 0 (Same behaviour of Gen2 cards. Some readers may identify the card as magic)
   * `01`: Deactivate direct write to block 0 (Same behaviour of vanilla cards)
   * `02`: Default value. (Same behaviour as `00` (?))

Example: enable direct writes to block 0, default pwd
```
hf 14a raw -s -c -t 1000 CF00000000CF00
```
Example: disable direct writes to block 0, default pwd
```
hf 14a raw -s -c -t 1000 CF00000000CF01
```

### Change backdoor password

^[Top](#top) ^^[Gen4](#g4top)

All backdoor operations are protected by a password. If password is forgotten, it can't be recovered. Default password is `00000000`.

WARNING: new UMC (06A0) returns 6300 when issuing password change command. Please write the password using F0 and entering the full configuration, but with the new password.

Change password:
```
hf 14a raw -s -c -t 1000 CF <passwd> FE <4b new_password>
```
Example: change password from 00000000 to AABBCCDD
```
hf 14a raw -s -c -t 1000 CF00000000FEAABBCCDD
```
Example: change password from AABBCCDD back to 00000000
```
hf 14a raw -s -c -t 1000 CFAABBCCDDFE00000000
```

### Dump configuration

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>C6
```
Default configuration:
```
00000000000002000978009102DABC191010111213141516040008006B024F6B
                                                            ^^^^ CRC, type unknown
                                                          ^^ cf cmd cf: block0 direct write setting, factory value 0x02
                                                        ^^ cf cmd 6b: maximum read/write sectors, factory value 0x6b
                                                      ^^ cf cmd 6a: UL mode
                                                ^^^^^^ cf cmd 35: ATQA/SAK
              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^ cf cmd 34: ATS length & content
            ^^ cf cmd 32: GTU mode
    ^^^^^^^^ cf cmd fe: password
  ^^ cf cmd 68: UID length
^^ cf cmd 69: Ultralight protocol
```

### Fast configuration

^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>F0<30b configuration data>
```
cf **Dump configuration** for configuration data description.

Example: Write factory configuration, using default password
```
hf 14a raw -s -c -t 1000 CF00000000F000000000000002000978009102DABC191010111213141516040008004F6B
```

⚠ Variant with command `F1` instead of `F0` will set and fuse permanently the configuration. Backdoor R/W will still work.

### Presets

^[Top](#top) ^^[Gen4](#g4top)

Here are some presets available in the FuseTool (but with all ATS disabled)

**MIFARE Mini S20 4-byte UID**
```
hf 14a raw -s -c -t 1000 CF00000000F000000000000002000978009102DABC19101011121314151604000900
```

**MIFARE Mini S20 7-byte UID**
```
hf 14a raw -s -c -t 1000 CF00000000F000010000000002000978009102DABC19101011121314151644000900
```

**MIFARE 1k S50 4-byte UID** (this is the factory setting)
```
hf 14a raw -s -c -t 1000 CF00000000F000000000000002000978009102DABC19101011121314151604000800
```

**MIFARE 1k S50 7-byte UID**
```
hf 14a raw -s -c -t 1000 CF00000000F000010000000002000978009102DABC19101011121314151644000800
```

**MIFARE 4k S70 4-byte UID**
```
hf 14a raw -s -c -t 1000 CF00000000F000000000000002000978009102DABC19101011121314151602001800
```

**MIFARE 4k S70 7 byte UID**
```
hf 14a raw -s -c -t 1000 CF00000000F000010000000002000978009102DABC19101011121314151642001800
```

**Ultralight**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000003FB
```

**Ultralight-C**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000002FB
```

**Ultralight EV1**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000000FB
```

**NTAG21x**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000001FB
```

### Version and Signature

^[Top](#top) ^^[Gen4](#g4top)

Don`t forget configure maximum read/write blocks. It`s can be adjusted directly in config (see *Dump configuration*) or by command 6B:

```
hf 14a raw -s -c -t 1000 CF000000006BFB
```

Note: 0xFB = 251

Ultralight EV1 and NTAG Version info and Signature are stored respectively in blocks 250-251 and 242-249.

Example for an Ultralight EV1 128b with the signature sample from tools/recover_pk.py
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000000FB
hf mfu wrbl -b 0 -d 04C12865
hf mfu wrbl -b 1 -d 5A373080
hf mfu wrbl -b 242 -d CEA2EB0B --force
hf mfu wrbl -b 243 -d 3C95D084 --force
hf mfu wrbl -b 244 -d 4A95B824 --force
hf mfu wrbl -b 245 -d A7553703 --force
hf mfu wrbl -b 246 -d B3702378 --force
hf mfu wrbl -b 247 -d 033BF098 --force
hf mfu wrbl -b 248 -d 7899DB70 --force
hf mfu wrbl -b 249 -d 151A19E7 --force
hf mfu wrbl -b 250 -d 00040301 --force
hf mfu wrbl -b 251 -d 01000E03 --force
hf mfu info
```

Example for an NTAG216 with the signature sample from tools/recover_pk.py
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000001FB
hf mfu wrbl -b 0 -d 04E10C61
hf mfu wrbl -b 1 -d DA993C80
hf mfu wrbl -b 242 -d 8B76052E --force
hf mfu wrbl -b 243 -d E42F5567 --force
hf mfu wrbl -b 244 -d BEB53238 --force
hf mfu wrbl -b 245 -d B3E3F995 --force
hf mfu wrbl -b 246 -d 0707C0DC --force
hf mfu wrbl -b 247 -d C956B5C5 --force
hf mfu wrbl -b 248 -d EFCFDB70 --force
hf mfu wrbl -b 249 -d 9B2D82B3 --force
hf mfu wrbl -b 250 -d 00040402 --force
hf mfu wrbl -b 251 -d 01001303 --force
hf mfu info
```

# Other

^[Top](#top)

These are chips to clone other ICs. Usually the originals are only sold in China.

## SID

^[Top](#top)

- Magic tag for Fudan FM1208-9 chips

### Characteristics

^[Top](#top)

- ISO14443-A tag
- ATQA-SAK: `0008`-`20`
- ATS: `10 78 80 A0 02 00 9D 46 16 40 00 A3 [UID]`
- Compared to real FM1208 chip:
  - CLA byte is ignored
  - Command parsing is irregular (some replies are wrong)

### Magic commands

^[Top](#top)

**WARNING!!!** Risk of bricking tag - cause is unknown

- Below you can find a list of all INS bytes not present on real FM1208 chip, and what their output is when executed (P1, P2, Lc = 00)
  - Results may vary between chips:

```
INS | RES
0A  | 44454641554C540000002018112840000000000000000000000000000000000000000000000000000000400000000000
3B  | 00000000001C0EF90000000000000000000000000000000000000000000000002000000000C09040009002840000000000000000000000000000000000006C0FC08700EB1A9F1BA01801010019000000000000000000000000000090000000000000094B066600000000007D000000000000000000000000000000003B000000107880A002009D46164000A3CA81E15000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
3C* | 0000
3D  | 6700
7D  | Tag does not reply (if 0<Lc<=15, RES=6700)
CD  | 6A82
D5  | 9000
DD  | 6700
DE  | 6700
DF  | 9000
EE  | 6700
F0  | 6A82
FB  | 6A82

* - DO NOT EXECUTE THIS INSTRUCTION!!! After 2nd execution tag will brick (No reply to REQA/WUPA). Very likely you need to add extra data which we do not know
```

## NSCK-II

^[Top](#top)

- Magic tag for "NSC/BS-CPU"

### Characteristics

^[Top](#top)

- Programming is done via ISO14443-A (but not sure how to modulate). Original tag is working somewhere hidden from proxmark.
- ATQA-SAK: `0044`-`20`
- ATS: `05 72 F7 60 02`
- Communications encrypted(?)
   - When writing with copykey, after RATS, this communication takes place (NSC ID programmed: `5800000000`, tag UID: `1D94CE25840000`):
     ```
     >>> 54 03 8A BC DF C1 [CRC]
     <<< A2 [CRC]
     >>> 54 04 57 AA 84 DD [CRC]
     <<< A2 [CRC]
     ```

### Magic commands

^[Top](#top)

- Write NSC UID: `54 [part 1b] [data 4b enc] [CRC]`
    - Tag replies: `A2 [CRC]`
