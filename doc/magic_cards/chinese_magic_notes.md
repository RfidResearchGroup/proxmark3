<a id="top"></a>

# Notes on Chinese Magic Cards

# Table of Contents

- [Low Frequency](#low-frequency)
  * [5577](#5577)
  * [5200](#5200)
  * [ID82xx series](#id82xx-series)
    - [ID8210](#id8210)
    - [ID8211](#id8211)
    - [ID8265](#id8265)
    - [ID8268/8278/8310](#id826882788310)
  * [K8678](#k8678)
- [High Frequency](#high-frequency)
  * [MIFARE Classic UID](#mifare-classic-uid)
  * [MIFARE Classic CUID](#mifare-classic-cuid)
  * [MIFARE Classic FUID](#mifare-classic-fuid)
  * [Magic "85" cards](#magic-85-cards)
    - [MIFARE Classic UFUID](#mifare-classic-ufuid)
    - [MIFARE Classic GDM aka Gen4](#mifare-classic-gdm-aka-gen4)
  * [MIFARE Classic, QL88](#mifare-classic-ql88)
  * [MIFARE Classic, FURUi detection (super) card](#mifare-classic-furui-detection-super-card)
  * [MIFARE Classic, other chips](#mifare-classic-other-chips)
  

## Low Frequency

### 5577
^[Top](#top)

This is an ATA5577C-compatible tag. 
*The price for this tag tends to be the highest..?*

#### Characteristics
^[Top](#top)

- Configurable as any tag that requires to send no more than 24(28) bytes of data (without password).
- Well documented

#### Deviations
^[Top](#top)

- Some tags have lock bits set on blocks 2-6.
- Some tags do not transmit traceability data, and have it rewritable.
  * These tags tend to ignore page 1 block 3 configuration.

### 5200
^[Top](#top)

No information.

#### Characteristics
^[Top](#top)

- Advertised as PM3 compatible.
- No info.

### ID82xx series

These chips are designed to clone EM410x IDs.

#### ID8210
^[Top](#top)

##### Characteristics
^[Top](#top)

- Alternative names:
  * H-125
- Identification:
    1. Engravings ("H-[freq., kHz]")
- No info.

#### ID8211
^[Top](#top)

##### Characteristics
^[Top](#top)

- Identification:
    1. Engravings ("8211")
- No info.

#### ID8265
^[Top](#top)

##### Characteristics
^[Top](#top)

- Very widespread Chinese magic tag. *May sometimes be sent globally under the name of "T5577/EM4305" with the excuse: "use our cloner".*
- Chip used: HITAG µ (micro)
- Identification:
    1. Engravings (N/A; "F8265-[freq., kHz]K")
    2. Preprogrammed code: `00:00:00:20:49` (CN: 8265)
- Can be detected.
- Currently unsupported by PM3, but being researched. When the proxmark3 supports this tag, more info will be added.

#### ID8268/8278/8310
^[Top](#top)

Sold as "anti-clone bypass".
ID8268 is claimed to be better than ID8278.

##### Characteristics
^[Top](#top)

- Very widespread Chinese magic tag too.
- Chip used: HITAG 1
- Idenification:
    1. Engravings (N/A; "F8268-[freq., kHz]K"; 3. "F8310-[freq., kHz]K"; 4. "F8278-[freq., kHz]K")
    2. Preprogrammed code: `00:00:00:20:4C` (CN: 8268); N/A
- ~~No known way to detect.~~
- Like ID8265, pending support. More info will be added when support is added.

### K8678
^[Top](#top)

Made by Hyctec for CopyKey devices (X100, X3, X5).

#### Characteristics
^[Top](#top)

- Very new
- Chip used: HITAG S
- Sold in 125, 175, 250, 375 and 500 kHz variants
- Identification:
    1. Engravings ("K8678-[freq., kHz]K")
    2. Preprogrammed code: `00:00:00:21:E6` (CN: 8678)

## High Frequency

### MIFARE Classic UID
^[Top](#top)

Sold as magic tag.

#### Identify
^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 1a
```

#### Magic commands
^[Top](#top)

* Wipe: `40(7)`, `41` (use 2000ms timeout)
* Read: `40(7)`, `43`, `30xx`+crc
* Write: `40(7)`, `43`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

#### Characteristics
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

### MIFARE Classic CUID
^[Top](#top)

Sold as the general cloning tag.
Behavior: possible to issue a regular write to block 0.

#### Identify
^[Top](#top)

No way to reliably identify CUID is known. 
The best way is to try writing block 0. Or you can try:
```
hf 14a info
...
[+] Magic capabilities : Gen2 / CUID
```

#### Characteristics
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

Variations of CUID cards are explained in `magic_cards_notes.md`.

#### Alternatives to CUID
^[Top](#top)

- KUID seems to have similar behavior to CUID (allows block 0 direct write).
    * That being said, we do not know its' purpose. Please use CUID.

### MIFARE Classic FUID
^[Top](#top)

Sold as "anti-clone bypass". Also known as RFUID.
Behavior: same as CUID, but after editing block 0, tag becomes original S50 chip.

Initial UID is AA55C396. Block 0 manufacturer data is null.

#### Identify
^[Top](#top)

Only possible before personalization.

```
hf 14a info
...
[+] Magic capabilities : Write Once / FUID
```
*It is possible to simulate a FUID tag using CopyKey X5. This is probably to detect protection against clones.*

#### Alternatives to FUID
^[Top](#top)

- HUID is sold as a cheaper alternative to FUID. However, it is protected with a KDF key in all sectors. *Copykey supports this chip.*

### "Magic 85" cards
^[Top](#top)

TLDR: These magic cards have a 16 byte long configuration page, which always starts with 0x85. 
All of the known tags using this, except for Ultralight tags, are listed here.

#### MIFARE Classic UFUID
^[Top](#top)

Same as CUID, but block0 can be locked with special command.
Sold as "anti-clone bypass".
No detailed info at the moment.

##### Identify
^[Top](#top)

**TODO**

##### Proxmark3 commands
^[Top](#top)

To lock block0 and hide magic capabilities:
```
hf 14a raw -a -k -b 7 40
hf 14a raw    -k      43
hf 14a raw    -k -c   e000
hf 14a raw    -k -c   e100
hf 14a raw       -c   85000000000000000000000000000008
```

#### MIFARE Classic GDM aka Gen4
^[Top](#top)

Sold as "rolling code bypass".

Tag has shadow mode enabled from start.
Meaning every write or changes to normal MFC memory is restored back to a copy from persistent memory after about 3 seconds 
off RF field.
Tag also seems to support Gen2 style, direct write,  to block 0 to the normal MFC memory.

The persistent memory is also writable. To do that, the tag uses its own backdoor commands.
For example: to write,  you must use a custom authentication command, 0x80, to authenticate with an all zeros key, 0x0000000000.
Then send the data to be written.

**OBS**

Do not change ACL in persistent memory! This tag does not acknowledge anything other than `FF0780`, otherwise the sector will be disabled!

##### Identify
^[Top](#top)

```
hf 14a info
...
[+] Magic capabilities : Gen 4 GDM
```
##### Magic commands
^[Top](#top)

* Auth: `80xx`+crc
* Read: `38xx`+crc
* Write: `A8xx`+crc,  `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc
* Read config: `E000`+crc
* Write config: `E100`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

##### Characteristics
^[Top](#top)

* ATQA/BCC: unknown behavior
* SAK: can be configured using `E100` command
* ATS: N/A
* UID: 4b
* No known true backdoors.
* Its magic part seems to be three identified custom commands. 
* Auth command 0x80, with the key 0x0000000000,  Write 0xA8 allows writing to persistent memory,  Read 0xE0  which seems to return a configuration. This is unknown today what these bytes are.

Read config:
1. sending custom auth with all zeros key
2. send 0xE000,  will return the configuration bytes.
`results: 850000000000000000005A5A00000008`


Mapping of configuration bytes so far:
```
850000000000000000005A5A00000008
                              ^^  --> SAK
                      ^^          --> Lock byte
```

Write config:
1. sending custom auth with all zeros key
2. send 0xE100
3. send 16 bytes

**Warning**

Example of configuration to Perma lock tag:
`85000000000000000000000000000008`

##### Proxmark3 commands
^[Top](#top)
```
# Write to persistent memory
hf mf gdmsetblk

# Read configuration (0xE0):
hf mf gdmcfg

# Write configuration (0xE1):
hf mf gdmsetcfg
```

### MIFARE Classic, QL88
^[Top](#top)

Sold for "QinLin Neighbor Technology" access control system.
The differences are presence of sector 17 and having SAK 88.

#### Characteristics
^[Top](#top)

* SAK/ATQA: unknown
* BCC: unknown
* OTP/FUID chip
* PRNG: hard

#### Identify
^[Top](#top)

```
[usb] pm3 --> hf 14a info
...
[+] Magic capabilities: QL88
```

Sector 17 can be accessed using Key B: `707B11FC1481`. Using it, other keys can be recovered.

#### Magic commands

**TODO** Need more info about this tag and original, non-magic IC.

### MIFARE Classic, FURUi detection (super) card
^[Top](#top)

Supercard, aka tag that records authentication attempts (nt, nr, ar). For recovery uses backdoor commands.

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

### MIFARE Classic, other chips
^[Top](#top)

**TODO**

* ZXUID, EUID, ICUID, M1-5A, M1-7B; NSCK-II; TID, BOMB?
* ~~Some cards exhibit a specific SAK=28?~~ Some chips have unusual properties, like SAK 28 (BOMB) or SAK 5A (M1-5A). We are yet to find out the special functions.

* What we know:
  - ZXUID, EUID, ICUID: [ N/A ]
  - M1-5A: tag for CopyKey device to clone Mifare Classic 1K with SAK `5A`.
  - M1-7B: tag for CopyKey device to clone Mifare Classic 1K CL2.
  - NSCK-II: tag for CopyKey device to clone "N•S•C"/"BS-CPU" chips. *ISO14443A (ATQA: 0044, SAK: 20) with FSK modulation and some UID conversion?*
  - TID: tag for cloning FM1208-9 "CPU" card. It is unknown how to write it, and it is very expensive.
  - BOMB: tag for cloning FM1208-xx "CPU" card, however properties do not match original chips (ATS is 18 bytes, not 16). *Exclsuive to "qinglong" software, but it costs way too much to be reasonable.*
