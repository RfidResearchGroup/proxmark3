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
- Idenification:
    1. Engravings (N/A; "F8268-[freq., kHz]K"; 3. "F8310-[freq., kHz]K"; 4. "F8278-[freq., kHz]K")
    2. Preprogrammed code: `00:00:00:20:4C` (CN: 8268); N/A
- No known way to detect.
- Like ID8265, pending support. More info will be added when support is added.

### K8678
^[Top](#top)

Made by Hyctec for CopyKey devices (X100, X3, X5).

#### Characteristics
^[Top](#top)

- Very new
- Sold in 125, 175, 250, 375 and 500 kHz variants
- No info

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

Sold as "anti-clone bypass".
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

- RFUID seems to have similar behavior to FUID. Maybe it is an alternative.
- HUID is sold as a cheaper alternative to FUID.

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

To lock definitively block0:
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
off rfid field.
Tag also seems to support Gen2 style, direct write,  to block 0 to the normal MFC memory.

The persistent memory is also writable. To do that, the tag uses its own backdoor commands.
for example to write,  you must use a customer authentication byte, 0x80, to authenticate with an all zeros key, 0x0000000000.
Then send the data to be written.

**OBS**

When writing to persistent memory it is possible to write _bad_ ACL and perm-brick the tag. 

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

### MIFARE Classic, other chips
^[Top](#top)

**TODO**

* ZXUID, EUID, ICUID; NSCK-II ?
* Some cards exhibit a specific SAK=28 ??
