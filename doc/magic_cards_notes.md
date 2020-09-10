# Notes on Magic Cards, aka UID changeable
This document is based mostly on information posted on http://www.proxmark.org/forum/viewtopic.php?pid=35372#p35372

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


# MIFARE Classic

Referred as M1, S50 (1k), S70 (4k)

## MIFARE Classic block0

UID 4b:

```
11223344440804006263646566676869
^^^^^^^^                         UID
        ^^                       BCC
          ^^                     SAK(*)
            ^^^^                 ATQA
                ^^^^^^^^^^^^^^^^ Manufacturer data
(*) some cards have on purpose a different SAK in their anticollision and in block0
```

 
Computing BCC on UID 11223344: `hf analyse lcr 11223344` = `44`

UID 7b:

**todo**

## MIFARE Classic Gen1A aka UID

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 1a
```

### Magic commands

raw commands 40/41/43

**TODO** details, differences in global wipe command?

### Characteristics

* UID: Only 4b versions
* ATQA:
  * all(?) cards play blindly the block0 ATQA bytes
* SAK:
  * some cards play blindly the block0 SAK byte
  * some cards use a fix "08" in anticollision, no matter the block0
* BCC:
* ATS:

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
hf 14a config h
script run remagic
```

## MIFARE Classic Gen1B

Similar to Gen1A, but supports only commands 40/43

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 1b
```

## MIFARE Classic DirectWrite aka Gen2 aka CUID

### Identify

```
hf 14a info
...
[+] Magic capabilities : Gen 2 / CUID
```

### Magic commands

Android compatible

* issue regular write to block0

### Characteristics

* UID: 4b and 7b versions
* ATQA:
* SAK:
* BCC:
* ATS:

**todo**

* some card will die if invalid block0! (or can be recovered with anticol...? "hf 14a config a 1 b 1 ..." then "hf mf wrbl 0 ...")
* some card have always correct anticol no matter block0, e.g. ATS=0948009102DABC1910F005

### Proxmark3 commands

```
hf mf wrbl 0 A FFFFFFFFFFFF 11223344440804006263646566676869
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config h
```

e.g. for 4b UID:

```
hf 14a config a 1 b 2 2 2 3 2 r 2
hf mf wrbl 0 A FFFFFFFFFFFF 11223344440804006263646566676869
hf 14a config a 0 b 0 2 0 3 0 r 0
```
## MIFARE Classic DirectWrite, FUID version aka 1-write

Same as MIFARE Classic DirectWrite, but block0 can be written only once.

Initial UID is AA55C396

### Identify

Only possible before personalisation.

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
hf 14a raw -a -p -b 7 40
hf 14a raw    -p      43
hf 14a raw    -p -c   e000
hf 14a raw       -c   85000000000000000000000000000008
```

## MIFARE Classic, other versions

**TODO**

* ZXUID, EUID, ICUID ?
* Some cards exhibit a specific SAK=28 ??

## MIFARE Classic APDU aka Gen3

### Identify

**TODO**

### Magic commands

Android compatible

* issue special APDUs

```
cla  ins p1  p2  len
 90  F0  CC  CC  10   - write block 0
 90  FB  CC  CC  07   - write uid separated instead of block 0
 90  FD  11  11  00   - lock uid permanently
```

### Characteristics

* UID: 4b and 7b versions
* ATQA:
* SAK:
* BCC:
* ATS:

### Proxmark3 commands

```
# change just UID:
hf mf gen3uid
# write block0:
hf mf gen3blk
# lock block0 forever:
hf mf gen3freez
```
See also
```
script run mfc_gen3_writer -h
```

Equivalent:
```
# change just UID:
hf 14a raw -s -c  -t 2000  90FBCCCC07 11223344556677
# write block0:
hf 14a raw -s -c  -t 2000  90F0CCCC10 041219c3219316984200e32000000000
# lock block0 forever:
hf 14a raw -s -c 90fd11100
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

Computing BCC0 on UID 04112233445566: `analyse lcr 88041122` = `bf`

Computing BCC1 on UID 04112233445566: `analyse lcr 33445566` = `44`

Int is internal, typically 0x48

## MIFARE Ultralight Gen1A

### Identify

**TODO**

### Characteristics

#### Magic commands

**TOOD**

#### UID

Only 7b versions

#### SAK, ATQA, BCC, ATS

**TODO** need more tests

### Proxmark3 commands

```
script run ul_uid -h
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config h
script run remagic -u
```

## MIFARE Ultralight DirectWrite

### Identify

**TODO**

### Characteristics

#### Magic commands

**TODO**

#### UID

Only 7b versions

#### SAK, ATQA, BCC, ATS

Some fix their BCC in anticol, some don't, be careful!

**TODO** need more tests

### Proxmark3 commands

```
hf mfu setuid
```

Equivalent: don't use `hf mfu wrbl` as you need to write three blocks in a row, but do, with proper BCCx:

```
hf 14a raw -s -c -p a2 00 041122bf 
hf 14a raw    -c -p a2 01 33445566
hf 14a raw    -c    a2 02 44480000
```

When "soft-bricked" (by writing invalid data in block0), these ones may help:

```
hf 14a config h
```

## MIFARE Ultralight EV1 DirectWrite

Same commands as for MFUL DirectWrite

## MIFARE Ultralight C Gen1A

Same commands as for MFUL Gen1A

## MIFARE Ultralight C DirectWrite

Same commands as for MFUL DirectWrite

# NTAG

### Identify

**TODO**

## NTAG213 DirectWrite

Same commands as for MFUL DirectWrite

## NTAG21x

### Identify

**TODO**

### Characteristics

Emulates fully NTAG213, 213F, 215, 216, 216F

Emulates partially  UL EV1 48k/128k, NTAG210, NTAG212, NTAGI2C 1K/2K, NTAGI2C 1K/2K PLUS

### Proxmark3 commands

```
script run mfu_magic -h
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

### pn53x-tamashell commands

```
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
hf mf csetblk 0 1122334444204403A1A2A3A4A5A6A7A8
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
script run iso15_magic -u E004013344556677  
```
