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
  * [MIFARE Classic Gen1A OTP/One Time Programming](#mifare-classic-gen1a-otpone-time-programming)
  * [MIFARE Classic DirectWrite aka Gen2 aka CUID](#mifare-classic-directwrite-aka-gen2-aka-cuid)
  * [MIFARE Classic DirectWrite, FUID version aka 1-write](#mifare-classic-directwrite-fuid-version-aka-1-write)
  * [MIFARE Classic DirectWrite, UFUID version](#mifare-classic-directwrite-ufuid-version)
  * [MIFARE Classic, other versions](#mifare-classic-other-versions)
  * [MIFARE Classic Gen3 aka APDU](#mifare-classic-gen3-aka-apdu)
  * [MIFARE Classic Gen4 aka GDM](#mifare-classic-gen4-aka-gdm)
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

aka MF ZERO

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

## MIFARE Classic Gen1A OTP/One Time Programming
^[Top](#top)

aka MF OTP 2.0

Similar to Gen1A, but after first block 0 edit, tag no longer replies to 0x40 command.

Initial UID is 00000000

All bytes are 00 from factory wherever possible.

### Identify
^[Top](#top)

Only possible before personalization.

```
hf 14a info
...
[+] Magic capabilities : Gen 1a
```

### Magic commands
^[Top](#top)

* Write: `40(7)`, `43`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

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

## MIFARE Classic DirectWrite, FUID version aka 1-write
^[Top](#top)

aka MF OTP

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
hf 14a raw    -k -c   e100
hf 14a raw       -c   85000000000000000000000000000008
```

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

## MIFARE Classic Gen4 aka GDM
^[Top](#top)

Tag has shadow mode enabled from start.
Meaning every write or changes to normal MFC memory is restored back to a copy from persistent memory after about 3 seconds 
off rfid field.
Tag also seems to support Gen2 style, direct write,  to block 0 to the normal MFC memory.

The persistent memory is also writable. For that tag uses its own backdoor commands.
for example to write,  you must use a customer authentication byte, 0x80, to authenticate with an all zeros key, 0x0000000000.
Then send the data to be written.

This tag has simular commands to the [UFUID](#mifare-classic-directwrite-ufuid-version)
This indicates that both tagtypes are developed by the same person.

**OBS**

When writing to persistent memory it is possible to write _bad_ ACL and perm-brick the tag. 

**OBS**

It is possible to write a configuration that perma locks the tag, i.e. no more magic

### Identify
^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 4 GDM
```
### Magic commands
^[Top](#top)

* Auth: `80xx`+crc
* Write: `A8xx`+crc,  `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc
* Read config: `E000`+crc
* Write config: `E100`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

### Characteristics
^[Top](#top)

* Have no knowledge in ATQA/SAK/BCC quirks or if there is a wipe, softbrick recover
* Its magic part seem to be three identified custom command. 
* Auth command 0x80, with the key 0x0000000000,  Write 0xA8 allows writing to persistent memory,  Read 0xE0  which seems to return a configuration. This is unknown today what these bytes are.

Read config:
1. sending custom auth with all zeros key
2. send 0xE000,  will return the configuration bytes.
`results: 850000000000000000005A5A00000008`


Mapping of configuration bytes so far:
```
850000000000000000005A5A00000008
                              ^^  --> SAK
```

Write config:
1. sending custom auth with all zeros key
2. send 0xE100
3. send 16 bytes

**Warning**

Example of configuration to Perma lock tag:
`85000000000000000000000000000008`


It is unknown what kind of block 0 changes the tag supports
* UID: 4b
* ATQA/SAK: unknown
* BCC: unknown
* ATS: none

### Proxmark3 commands
^[Top](#top)
```
# Write to persistent memory
hf mf gdmsetblk

# Read configuration (0xE0):
hf mf gdmcfg

# Write configuration (0xE1):
hf mf gdmsetcfg
```

### libnfc commands
^[Top](#top)
No implemented commands today

## MIFARE Classic, other versions
^[Top](#top)

**TODO**

* ZXUID, EUID, ICUID, KUID, HUID, RFUID ?
* Some cards exhibit a specific SAK=28 ??

## MIFARE Classic Super
^[Top](#top)

It behaves like regular Mifare Classic but records reader auth attempts.

#### MIFARE Classic Super Gen1
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

#### MIFARE Classic Super Gen1B

DirectWrite card, ATS unknown. Probably same as Gen1, except backdoor commands. 
Implementation: https://github.com/netscylla/super-card/blob/master/libnfc-1.7.1/utils/nfc-super.c

#### MIFARE Classic Super Gen2
^[Top](#top)

New generation of cards, based on limited Gen4 chip. Emulates Gen1 backdoor protocol, but can store up to 7 different traces.

Card always answer `ff  ff  ff  ff` to auth, so writing/reading it via Mifare protocol is impossible. 

UID is changeable via Gen4 backdoor write to 0 block.

* UID: 4b and 7b versions
* ATQA/SAK: fixed
* BCC: auto
* ATS: changeable, default as Gen1

Gen4 commands available:

```
CF <passwd> 34 <1b length><0-16b ATS>            // Configure ATS
CF <passwd> CC                                   // Factory test, returns 00 00 00 02 AA
CF <passwd> CD <1b block number><16b block data> // Backdoor write 16b block
CF <passwd> CE <1b block number>                 // Backdoor read 16b block
CF <passwd> FE <4b new_password>                 // Change password
```

### Identify
^[Top](#top)

Only Gen1/Gen2 at this moment (Gen1B is unsupported):

```
hf 14a info
...
[+] Magic capabilities : Super card (Gen ?)
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

aka UL2

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

**TODO**

* UL-X, UL-Y, UL-Z, ULtra, UL-5 ?


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

   2.  Use the hf_mf_ultimatecard.lua script commands designated but the `script run hf_mf_ulimatecard` examples.


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
CF <passwd> 32 <00-03>                           // Configure GTU shadow mode
CF <passwd> 34 <1b length><0-16b ATS>            // Configure ATS
CF <passwd> 35 <2b ATQA><1b SAK>                 // Configure ATQA/SAK (swap ATQA bytes)
CF <passwd> 68 <00-02>                           // Configure UID length
CF <passwd> 69 <00-01>                           // (De)Activate Ultralight mode
CF <passwd> 6A <00-03>                           // Select Ultralight mode
CF <passwd> 6B <1b>                              // Set Ultralight and M1 maximum read/write sectors
CF <passwd> C6                                   // Dump configuration
CF <passwd> CC                                   // Factory test, returns 6666
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

This mode is divided into four states: off (pre-write), on (on restore), don’t care, and high-speed read and write.
If you use it, please enter the pre-write mode first. At this time, write the full card data.
After writing, set it to on. At this time, after writing the data, the first time you read the data just written, the next time you read It is the pre-written data. All modes support this operation. It should be noted that using any block to read and write in this mode may give wrong results.

Example: 
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
00000000000002000978009102DABC191010111213141516040008006B024F6B
                                                            ^^^^ ??
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
