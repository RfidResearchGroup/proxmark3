# Notes on Magic Cards, aka UID changeable
This document is based mostly on information posted on http://www.proxmark.org/forum/viewtopic.php?pid=35372#p35372

Useful docs:
* [AN10833 MIFARE Type Identification Procedure](https://www.nxp.com/docs/en/application-note/AN10833.pdf)

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
  * [MIFARE Classic APDU aka Gen3](#mifare-classic-apdu-aka-gen3)
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


# ISO14443A

## Identifying broken ISO14443A magic

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

Referred as M1, S50 (1k), S70 (4k)

## MIFARE Classic block0

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

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 1a
```

### Magic commands

* Wipe: `40(7)`, `41` (use 2000ms timeout)
* Read: `40(7)`, `43`, `30xx`+crc
* Write: `40(7)`, `43`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

### Characteristics

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

* SAK: play blindly the block0 SAK byte, beware!
* PRNG: static 01200145
* Wipe: filled with 0xFF

#### MIFARE Classic Gen1A flavour 2

* SAK: play blindly the block0 SAK byte, beware!
* PRNG: static 01200145
* Wipe: filled with 0x00

#### MIFARE Classic Gen1A flavour 3

* SAK: 08
* PRNG: static 01200145
* Wipe: filled with 0xFF

#### MIFARE Classic Gen1A flavour 4

* SAK: 08
* PRNG: weak
* Wipe: timeout, no wipe

#### MIFARE Classic Gen1A flavour 5

* SAK: 08
* PRNG: weak
* Wipe: reply ok but no wipe performed

#### MIFARE Classic Gen1A flavour 6

* SAK: 08 or 88 if block0_SAK most significant bit is set
* PRNG: weak
* Wipe: timeout, no wipe

#### MIFARE Classic Gen1A flavour 7

* SAK: 08 or 88 if block0_SAK most significant bit is set
* PRNG: weak
* Wipe: filled with 0x00

### Proxmark3 commands

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

```
nfc-mfsetuid
nfc-mfclassic R a u mydump
nfc-mfclassic W a u mydump
```

## MIFARE Classic Gen1B

Similar to Gen1A, but supports directly read/write after command 40

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 1b
```

### Magic commands

* Read: `40(7)`, `30xx`
* Write: `40(7)`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

## MIFARE Classic DirectWrite aka Gen2 aka CUID

(also referred as MCT compatible by some sellers)

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

Not all Gen2 cards can be identified with `hf 14a info`, only those replying to RATS.

To identify the other ones, you've to try to write to block0 and see if it works...

### Magic commands

Android compatible

* issue regular write to block0

### Characteristics

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

* UID 4b
* ATQA: play blindly the block0 ATQA bytes, beware!
* SAK: play blindly the block0 SAK byte, beware!
* BCC: play blindly the block0 BCC byte, beware!
* ATS: no
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 2

* UID 4b
* ATQA: fixed
* SAK: fixed
* BCC: computed
* ATS: 0978009102DABC1910F005
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 3

* UID 4b
* ATQA: play blindly the block0 ATQA bytes, beware!
* SAK: fixed
* BCC: play blindly the block0 BCC byte, beware!
* ATS: no
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 4

* UID 7b
* ATQA: fixed
* SAK: fixed
* BCC: computed
* ATS: 0978009102DABC1910F005
* PRNG: static 00000000

#### MIFARE Classic DirectWrite flavour 5

* UID 4b
* ATQA: fixed
* SAK: play blindly the block0 SAK byte, beware!
* BCC: computed
* ATS: no
* PRNG: weak

#### MIFARE Classic DirectWrite flavour 6

**TODO** need more info

* UID 7b
* ATS: 0D780071028849A13020150608563D

### Proxmark3 commands

```
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344440804006263646566676869
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config -h
```

e.g. for 4b UID:

```
hf 14a config --atqa force --bcc ignore --cl2 skip --rats skip
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -k 11223344440804006263646566676869 # for 1k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -k 11223344441802006263646566676869 # for 4k
hf 14a config --std
hf 14a reader
```

e.g. for 7b UID:

```
hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip --rats skip
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -k 04112233445566084400626364656667 # for 1k
hf mf wrbl --blk 0 -k FFFFFFFFFFFF -k 04112233445566184200626364656667 # for 4k
hf 14a config --std
hf 14a reader
```
## MIFARE Classic DirectWrite, FUID version aka 1-write

Same as MIFARE Classic DirectWrite, but block0 can be written only once.

Initial UID is AA55C396

### Identify

Only possible before personalization.

```
hf 14a info
...
[+] Magic capabilities : Write Once / FUID
```

## MIFARE Classic DirectWrite, UFUID version

Same as MIFARE Classic DirectWrite, but block0 can be locked with special command.

### Identify

**TODO**

### Proxmark3 commands

To lock definitively block0:
```
hf 14a raw -a -k -b 7 40
hf 14a raw    -k      43
hf 14a raw    -k -c   e000
hf 14a raw       -c   85000000000000000000000000000008
```

## MIFARE Classic, other versions

**TODO**

* ZXUID, EUID, ICUID ?
* Some cards exhibit a specific SAK=28 ??

## MIFARE Classic APDU aka Gen3

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 3 / APDU
```

### Magic commands

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

* UID: 4b and 7b versions
* ATQA/SAK: fixed
* BCC: auto
* ATS: none

### Proxmark3 commands

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

It behaves like DirectWrite but records reader auth attempts.

To change UID: same commands as for MFC DirectWrite

To do reader-only attack: at least two versions exist.

* type 1: https://github.com/nfc-tools/nfc-supercard for card with ATS: 0978009102DABC1910F005
* type 2: https://github.com/netscylla/super-card/blob/master/libnfc-1.7.1/utils/nfc-super.c for ??

### Identify

Only type 1 at the moment:

```
hf 14a info
...
[+] Magic capabilities : super card
```

# MIFARE Ultralight

## MIFARE Ultralight blocks 0..2

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

```
script run hf_mfu_setuid -h
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config -h
script run hf_mf_magicrevive -u
```

## MIFARE Ultralight DirectWrite

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

It seems so far that all MFUL DW have an ATS.

### Magic commands

Issue three regular MFU write commands in a row to write first three blocks.

### Characteristics

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

* BCC: computed
* ATS: 0A78008102DBA0C119402AB5
* Anticol shortcut (CL1/3000): fails

#### MIFARE Ultralight DirectWrite flavour 2

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A00A000AB00000000000000000184D
* Anticol shortcut (CL1/3000): succeeds

### Proxmark3 commands

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

```
nfc-mfultralight -h
```
See `--uid` and `--full`

### Android

* MIFARE++ Ultralight

## MIFARE Ultralight EV1 DirectWrite

Similar to MFUL DirectWrite

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Characteristics

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

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A000000AC30004030101000B0341DF

#### MIFARE Ultralight EV1 DirectWrite flavour 2

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 850000A00A000AC30004030101000B0316D7

## MIFARE Ultralight C Gen1A

Similar to MFUL Gen1A

## MIFARE Ultralight C DirectWrite

Similar to MFUL DirectWrite

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Characteristics

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

* BCC: computed
* ATS: 0A78008102DBA0C119402AB5
* Anticol shortcut (CL1/3000): fails

# NTAG

## NTAG213 DirectWrite

Similar to MFUL DirectWrite

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Characteristics

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

* BCC: play blindly the block0 BCC0 and block2 BCC1 bytes, beware!
* ATS: 0A78008102DBA0C119402AB5
* Anticol shortcut (CL1/3000): succeeds

## NTAG21x

### Identify

```
hf 14a info
...
[+] Magic capabilities : NTAG21x
```

### Characteristics

Emulates fully NTAG213, 213F, 215, 216, 216F

Emulates partially  UL EV1 48k/128k, NTAG210, NTAG212, NTAGI2C 1K/2K, NTAGI2C 1K/2K PLUS

Anticol shortcut (CL1/3000): fails

### Proxmark3 commands

```
script run hf_mfu_magicwrite -h
```

# DESFire

## "DESFire" APDU, 7b UID

### Identify

**TODO**

### Magic commands

Android compatible

* issue special APDUs

### Characteristics

* ATQA: 0344
* SAK: 20
* ATS: 0675338102005110 or 06757781028002F0

Only mimics DESFire anticollision (but wrong ATS), no further DESFire support

### Proxmark commands

UID 04112233445566
```
hf 14a raw -s -c 0200ab00000704112233445566
```
or equivalently
```
hf 14a apdu -s 00ab00000704112233445566
```

### libnfc commands

```
pn53x-tamashell
4a0100
420200ab00000704112233445566
```
## "DESFire" APDU, 4b UID

### Magic commands

Android compatible

* issue special APDUs

### Characteristics

* ATQA: 0008 ??? This is not DESFire, 0008/20 doesn't match anything
* SAK: 20
* ATS: 0675338102005110 or 06757781028002F0

Only mimics DESFire anticollision (but wrong ATS), no further DESFire support

### Proxmark commands

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
```
4a0100
420200ab00000411223344
```

### Remarks

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

## ISO14443B magic

No such card is available.

Some vendor allow to specify an ID (PUPI) when ordering a card.

# ISO15693

## ISO15693 magic

### Identify

**TODO**

### Proxmark3 commands

Always set a UID starting with `E0`.

```
hf 15 csetuid E011223344556677
```
or (ignore errors):
```
script run hf_15_magic -u E004013344556677  
```
