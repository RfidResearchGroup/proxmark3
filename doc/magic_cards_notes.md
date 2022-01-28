<a id="top"></a>

# Notes on Magic Cards, aka UID changeable
This document is based mostly on information posted on http://www.proxmark.org/forum/viewtopic.php?pid=35372#p35372

Useful docs:
* [AN10833 MIFARE Type Identification Procedure](https://www.nxp.com/docs/en/application-note/AN10833.pdf)


# Table of Contents

- [ISO14443A](#iso14443a)
  * [Identifying broken ISO14443A magic](#identifying-broken-iso14443a-magic)
- [MIFARE Classic](#mifare-classic)
  * [MIFARE Classic block0](#mifare-classic-block0)
  * [MIFARE Classic Gen1A aka UID](#mifare-classic-gen1a-aka-uid)
  * [MIFARE Classic Gen1B](#mifare-classic-gen1b)
  * [MIFARE Classic DirectWrite aka Gen2 aka CUID](#mifare-classic-directwrite-aka-gen2-aka-cuid)
  * [MIFARE Classic DirectWrite, FUID version aka 1-write](#mifare-classic-directwrite-fuid-version-aka-1-write)
  * [MIFARE Classic DirectWrite, UFUID version](#mifare-classic-directwrite-ufuid-version)
  * [MIFARE Classic, other versions](#mifare-classic-other-versions)
  * [MIFARE Classic Gen3 aka APDU](#mifare-classic-gen3-aka-apdu)
  * [MIFARE Classic Super](#mifare-classic-super)
- [MIFARE Ultralight](#mifare-ultralight)
  * [MIFARE Ultralight blocks 0..2](#mifare-ultralight-blocks-02)
  * [MIFARE Ultralight Gen1A](#mifare-ultralight-gen1a)
  * [MIFARE Ultralight DirectWrite](#mifare-ultralight-directwrite)
  * [MIFARE Ultralight EV1 DirectWrite](#mifare-ultralight-ev1-directwrite)
  * [MIFARE Ultralight C Gen1A](#mifare-ultralight-c-gen1a)
  * [MIFARE Ultralight C DirectWrite](#mifare-ultralight-c-directwrite)
- [NTAG](#ntag)
  * [NTAG213 DirectWrite](#ntag213-directwrite)
  * [NTAG21x](#ntag21x)
- [DESFire](#desfire)
  * ["DESFire" APDU, 7b UID](#desfire-apdu-7b-uid)
  * ["DESFire" APDU, 4b UID](#desfire-apdu-4b-uid)
- [ISO14443B](#iso14443b)
  * [ISO14443B magic](#iso14443b-magic)
- [ISO15693](#iso15693)
  * [ISO15693 magic](#iso15693-magic)
- [Multi](#multi)
  * [Gen 4 GTU](#gen-4-gtu)


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

 
Computing BCC on UID 11223344: `hf analyse lcr -d 11223344` = `44`

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

### Identify
^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 1a
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
hf 14a info
...
[+] Magic capabilities : Gen 1b
```

### Magic commands
^[Top](#top)

* Read: `40(7)`, `30xx`
* Write: `40(7)`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

## MIFARE Classic DirectWrite aka Gen2 aka CUID
^[Top](#top)

(also referred as MCT compatible by some sellers)

### Identify
^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

Not all Gen2 cards can be identified with `hf 14a info`, only those replying to RATS.

To identify the other ones, you've to try to write to block0 and see if it works...

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
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344440804006263646566676869

hf mf wipe --gen2
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config -h
```

e.g. for 4b UID:

```
hf 14a config --atqa force --bcc ignore --cl2 skip --rats skip
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344440804006263646566676869 # for 1k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344441802006263646566676869 # for 4k
hf 14a config --std
hf 14a reader
```

e.g. for 7b UID:

```
hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip --rats skip
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 04112233445566084400626364656667 # for 1k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 04112233445566184200626364656667 # for 4k
hf 14a config --std
hf 14a reader
```
## MIFARE Classic DirectWrite, FUID version aka 1-write
^[Top](#top)

Same as MIFARE Classic DirectWrite, but block0 can be written only once.

Initial UID is AA55C396

### Identify
^[Top](#top)

Only possible before personalization.

```
hf 14a info
...
[+] Magic capabilities : Write Once / FUID
```

## MIFARE Classic DirectWrite, UFUID version
^[Top](#top)

Same as MIFARE Classic DirectWrite, but block0 can be locked with special command.

### Identify
^[Top](#top)

**TODO**

### Proxmark3 commands
^[Top](#top)

To lock definitively block0:
```
hf 14a raw -a -k -b 7 40
hf 14a raw    -k      43
hf 14a raw    -k -c   e000
hf 14a raw       -c   85000000000000000000000000000008
```

## MIFARE Classic, other versions
^[Top](#top)

**TODO**

* ZXUID, EUID, ICUID ?
* Some cards exhibit a specific SAK=28 ??

## MIFARE Classic Gen3 aka APDU
^[Top](#top)

### Identify
^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 3 / APDU
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

## MIFARE Classic Super
^[Top](#top)

It behaves like DirectWrite but records reader auth attempts.

To change UID: same commands as for MFC DirectWrite

To do reader-only attack: at least two versions exist.

* type 1: https://github.com/nfc-tools/nfc-supercard for card with ATS: 0978009102DABC1910F005
* type 2: https://github.com/netscylla/super-card/blob/master/libnfc-1.7.1/utils/nfc-super.c for ??

### Identify
^[Top](#top)

Only type 1 at the moment:

```
hf 14a info
...
[+] Magic capabilities : super card
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

* ATQA: 0008 ??? This is not DESFire, 0008/20 doesn't match anything
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

## ISO14443B magic
^[Top](#top)

No such card is available.

Some vendor allow to specify an ID (PUPI) when ordering a card.

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

## Gen 4 GTU
^[Top](#top)

A.k.a ultimate magic card,  most promenent feature is shadow mode (GTU) and optional password protected backdoor commands.


Can emulate MIFARE Classic, Ultralight/NTAG families, 14b UID & App Data

- [Identify](#identify)
- [Magic commands](#magic-commands)
- [Characteristics](#characteristics)
- [Proxmark3 commands](#proxmark3-commands)
- [Change ATQA / SAK](#change-atqa--sak)
- [Change ATS](#change-ats)
- [Set UID length (4, 7, 10)](#set-uid-length-4-7-10)
- [Set 14443A UID](#set-14443a-uid)
- [Set 14443B UID and ATQB](#set-14443b-uid-and-atqb)
- [(De)Activate Ultralight mode](#deactivate-ultralight-mode)
- [Select Ultralight mode](#select-ultralight-mode)
- [Set shadow mode (GTU)](#set-shadow-mode-gtu)
- [Direct block read and write](#direct-block-read-and-write)
- [Change backdoor password](#change-backdoor-password)
- [Dump configuration](#dump-configuration)
- [Fast configuration](#fast-configuration)
- [Presets](#presets)
- [Version and Signature](#version-and-signature)


### Identify
^[Top](#top) ^^[Gen4](#g4top)

👉 **TODO** Tag doesn't get identified correctly by latest Proxmark3 client (it might get mislabeled as MFC Gen2/CUID, Gen3/APDU or NTAG21x Modifiable, depending on configured UID/ATQA/SAK/ATS)

One can identify manually such card if the password is still the default one, with the command to get the current configuration:
```
hf 14a raw -s -c -t 1000 CF00000000C6
```
If the card is an Ultimate Magic Card, it returns 30 bytes.
### Magic commands
^[Top](#top) ^^[Gen4](#g4top)

Special commands summary:

```
CF <passwd> 32 <00-03>                           // Configure GTU shadow mode
CF <passwd> 34 <1b length><0-16b ATS>            // Configure ATS
CF <passwd> 35 <2b ATQA><1b SAK>                 // Configure ATQA/SAK (swap ATQA bytes)
CF <passwd> 68 <00-02>                           // Configure UID length
CF <passwd> 69 <00-01>                           // (De)Activate Ultralight mode
CF <passwd> 6A <00-03>                           // Select Ultralight mode
CF <passwd> C6                                   // Dump configuration
CF <passwd> CC                                   // Factory test, returns 6666
CF <passwd> CD <1b block number><16b block data> // Backdoor write 16b block
CF <passwd> CE <1b block number>                 // Backdoor read 16b block
CF <passwd> F0 <30b configuration data>          // Configure all params in one cmd
CF <passwd> F1 <30b configuration data>          // Configure all params in one cmd and fuse the configuration permanently
CF <passwd> FE <4b new_password>                 // change password
```
Default `<passwd>`: `00000000`

### Characteristics
^[Top](#top) ^^[Gen4](#g4top)

* UID: 4b, 7b and 10b versions
* ATQA/SAK: changeable
* BCC: auto
* ATS: changeable, can be disabled
* Card Type:  changeable
* Shadow mode:  GTU
* Backdoor password mode

### Proxmark3 commands
^[Top](#top) ^^[Gen4](#g4top)

```
# view contents of tag memory:
hf mf gview
```
👉 **TODO** `hf mf gview` is currently missing Ultralight memory maps 

Equivalent:

```
hf 14a raw -s -c -t 1000 CF00000000CE00
hf 14a raw -s -c -t 1000 CF00000000CE01
hf 14a raw -s -c -t 1000 CF00000000CE02
...
```

### Change ATQA / SAK
^[Top](#top) ^^[Gen4](#g4top)

```
hf 14a raw -s -c -t 1000 CF<passwd>35<2b ATQA><1b SAK>
```
* ⚠ ATQA bytes are swapped in the command
* ⚠ when SAK bit 6 is set (e.g. SAK=20 or 28), ATS must be turned on, otherwise the card may not be recognized by some readers!
* ⚠ never set SAK bit 3 (e.g. SAK=04), it indicates an extra cascade level is required (see `hf 14a config --cl2 skip` or `hf 14a config --cl3 skip` to recover a misconfigured card)
 
Example: ATQA 0044 SAK 28, default pwd
```
hf 14a raw -s -c -t 1000 CF0000000035440028
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

UID is configured according to block0 with a backdoor write.

Example: preparing first two blocks:
```
hf 14a raw -s -c -t 1000 CF00000000CD00000102030405060708090A0B0C0D0E0F
hf 14a raw -s -c -t 1000 CF00000000CD01101112131415161718191A1B1C1D1E1F
hf 14a reader
```
MFC mode, 4b UID  
=> UID `00010203`

MFC mode, 7b UID  
=> UID `00010203040506`

MFC mode, 10b UID  
=> UID `00010203040506070809`

Ultralight mode, 4b UID  
=> UID `00010203`

Ultralight mode, 7b UID  
=> UID `00010210111213`  
👉 the UID is composed of first two blocks as in regular Ultralights

Ultralight mode, 10b UID  
=> UID `00010203040506070809`  
👉 the UID is composed only from block0

### Set 14443B UID and ATQB
^[Top](#top) ^^[Gen4](#g4top)

UID and ATQB are configured according to block0 with a (14a) backdoor write.

UID size is always 4 bytes.

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
Now the card supports the 3DES UL-C authentication.
### Set shadow mode (GTU)
^[Top](#top) ^^[Gen4](#g4top)

This mode is divided into four states: off (pre-write), on (on restore), don’t care, and high-speed read and write.
If you use it, please enter the pre-write mode first. At this time, write the full card data.
After writing, set it to on. At this time, after writing the data, the first time you read the data just written, the next time you read It is the pre-written data. All modes support this operation. It should be noted that using any block to read and write in this mode may give wrong results.

```
hf 14a raw -s -c -t 1000 CF<passwd>32<1b param>
```
 * `<param>`
   * `00`: pre-write, shadow data can be written
   * `01`: restore mode
   * `02`: disabled
   * `03`: disabled, high speed R/W mode for Ultralight?

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

### Change backdoor password
^[Top](#top) ^^[Gen4](#g4top)

All backdoor operations are protected by a password. If password is forgotten, the card can't be recovered. Default password is `00000000`.

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
00000000000002000978009102DABC191010111213141516040008004F6B
                                                        ^^^^ ??
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
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000003
```

**Ultralight-C**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000002
```

**Ultralight EV1**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000000
```

**NTAG21x**
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000001
```

### Version and Signature
^[Top](#top) ^^[Gen4](#g4top)

Ultralight EV1 and NTAG Version info and Signature are stored respectively in blocks 250-251 and 242-249.

Example for an Ultralight EV1 128b with the signature sample from tools/recover_pk.py
```
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000000
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
hf 14a raw -s -c -t 1000 CF00000000F001010000000003000978009102DABC19101011121314151644000001
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

