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
  * [Detection tips](#detection-tips)
- [High Frequency](#high-frequency)
  - [MIFARE Classic](#mifare-classic)
    * [MIFARE Classic UID](#mifare-classic-uid)
    * [MIFARE Classic CUID](#mifare-classic-cuid)
    * [MIFARE Classic FUID](#mifare-classic-fuid)
    * [Magic "85" cards](#magic-85-cards)
    * [MIFARE Classic, QL88](#mifare-classic-ql88)
    * [MIFARE Classic, FURUi detection (super) card](#mifare-classic-furui-detection-super-card)
    * [MIFARE Classic, other chips](#mifare-classic-other-chips)
  - [MIFARE Ultralight](#mifare-ultralight)
    * [MIFARE Ultralight, Copykey](#mifare-ultralight-copykey)
  - [Other chips](#other-chips)
    * [NSCK-II](#nsck-ii)
    * [SID](#sid)
  

## Low Frequency

### 5577
^[Top](#top)

This is an ATA5577C-compatible tag. 
*The price for this tag tends to be the highest..?*

#### Characteristics
^[Top](#top)

- Regular Atmel ATA5577C ~~clone (supports all functions, but traceability is unlocked, and chipset is not detected)~~ __Some__ vendors seem to sell clones. To be confirmed.
- Default data: `EM410x: 0000 0015C9` (CN: 5577)
- Configurable as any tag that requires to send no more than 24(28) bytes of data (without password).
- Well documented

### 5200
^[Top](#top)

After checking, this appears to be a regular T55x7 clone.

#### Characteristics
^[Top](#top)

- Advertised as PM3, T5577 compatible.
  - All pages are writable (including traceability).
  - Traceability data begins with `E039`.
  - Analog front-end is ignored.
  - Test mode is ignored.
- Other names: "ZX-58U"

### ID82xx series

These chips are designed to clone EM410x IDs.
*Chinese vendors pre-program an EM410x ID with card number being the same as chip used*

#### ID8210
^[Top](#top)

##### Characteristics
^[Top](#top)

- Alternative names:
  * H-125
- Identification:
    1. Engravings ("H-[freq., kHz]", "8210-[freq., kHz]")
- Seemingly ID8265. To be confirmed.

#### ID8211
^[Top](#top)

##### Characteristics
^[Top](#top)

- Identification:
    1. Engravings (stamp "8211")
- No info.

#### ID8265
^[Top](#top)

##### Characteristics
^[Top](#top)

- Very widespread Chinese magic tag. *May sometimes be sent globally under the name of "T5577/EM4305" with the excuse: "use our cloner".*
- Chip used: HITAG µ (micro)
- Identification:
    1. Engravings (N/A; "F8265-[freq., kHz]K")
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
- Like ID8265, pending support. More info will be added when support is added.

### K8678
^[Top](#top)

Made by Hyctec for CopyKey devices (X100, X3, X5).

#### Characteristics
^[Top](#top)

- Very new
- Chip used: HITAG S256 (plain mode)
- Sold in 125, 175, 250, 375 and 500 kHz variants
- Identification:
    1. Engravings ("K8678-[freq., kHz]K")

#### Magic commands
^[Top](#top)

* Okay, it's not necessarily magic commands.. it's regular writes.
```
  >>> 18(5)                   // Get UID
  <<< [ tag replies with UID ]
  >>> 00(5) [UID] [CRC]       // Selection
  <<< [ tag replies with con0-2 ]
  >>> 08(4) 04 [CRC]          // Writeblock 4
  <<< 01(2)                   // ACK
  >>> [EM410x raw data 0-3] [CRC]
  <<< 01(2)                   // ACK
  >>> 08(4) 05 [CRC]          // Writeblock 5
  <<< 01(2)                   // ACK
  >>> [EM410x raw data 4-7] [CRC]
  >>> 01(2)                   // ACK
```

### Detection tips

- To check if you have chip A/B/C/..., run this:
  1. `data plot`
  2. Chip-specific info below:
     - ID8265: `lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00011 -s 3000`;
     - F8268: `lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00110 -s 3000`;
     - K8678: `lf cmdread -d 50 -z 116 -o 166 -e W3000 -c W00110 -s 3000`.
  3. Look at the plot window. The green line must be 0 (no big waves) at the end.

## High Frequency

### MIFARE Classic

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
* Other names are:
  - CAID
  - SUID

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
- HUID is a CUID chip, but protected with a KDF key.
    * When key is recovered using Copykey (auth attempt 23), the tag appears to be a regular CUID chip rev.5.
    * When writing, Copykey detects the custom key and locks the ACL to `block 0: read AB; ACL: read AB write --`

### MIFARE Classic FUID
^[Top](#top)

Sold as "anti-clone bypass". Also known as RFUID.
Behavior: same as CUID, but after editing block 0, tag becomes original S50 chip.

Initial UID is AA55C396. Block 0 manufacturer data is null.

#### Identify
^[Top](#top)

Only possible before personalization. *It's possible after, but unknown how..*

```
hf 14a info
...
[+] Magic capabilities : Write Once / FUID
```

### "Magic 85" cards
^[Top](#top)

TLDR: These magic cards have a 16 byte long configuration page, which usually starts with 0x85. Another name is "USCUID".
All of the known tags using this, except for Ultralight tags, are listed here.

You cannot turn a Classic tag into an Ultralight and vice-versa!

#### Characteristics
^[Top](#top)

* UID: 4/7 bytes
* ATQA: always read from block 0
* SAK: read from backdoor or configuration
* BCC: read from memory, beware!
* ATS: no/unknown

#### Magic commands
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
 
#### Magic85 configuration guide
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
88 04 BD E5 D4 0C 6A BB 5B 80 0A 08 44 00 00 00 - Block 0: Perso F0, F1 data
^^ ^^ ^^ ^^                                     - UID0
            ^^                                  - BCC0
               ^^                               - SAK0 (+0x04 to call for CL2)
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

#### Variations
^[Top](#top)
| Factory configuration | Name |
| --- | --- |
| 850000000000000000005A5A00000008 | GDMIC |
| 850000000000005A0000005A5A5A0008 | UCUID |
| 8500000000005A00005A005A005A0008 | "7 byte hard" |
| 7AFF850102015A00005A005A005A0008 | M1-7B |
| 7AFF000000000000BAFA358500000008 | PFUID |
| 7AFF000000000000BAFA000000000008 | UFUID |

*Not all tags are the same!* UFUID and PFUID* are not full implementations of Magic85 - they only acknowledge the first 8 (except wakeup command) and last config byte(s).

*Read and write config commands are flipped

#### Proxmark3 commands
^[Top](#top)
```
Using magic auth:
# Write to persistent memory:
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

Oops, the above is flawed. Some other "SAK88-IC" tags get detected as QL88.

Sector 17 can be accessed using Key B: `707B11FC1481`. ~~Using it, other keys can be recovered.~~ Do not recover keys using this or run `hf 14a info` at all! 

For an unknown reason if you try to get any read access block 0 write protects itself. Without methods of recovery. *To be confirmed*

#### Magic commands

- Block 0 can be written using direct write
- No signature sector backdoor

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

* ZXUID, EUID, ICUID, M1-5A; TID, BOMB?
* ~~Some cards exhibit a specific SAK=28?~~ Some chips have unusual properties, like SAK 28 (BOMB) or SAK 5A (M1-5A). We are yet to find out the special functions.

* What we know:
  - ZXUID, EUID, ICUID, SUID: [ N/A ]
  - M1-5A: tag for CopyKey device to clone Mifare Classic 1K with SAK `5A`.
  - TID: tag for cloning FM1208-9 "CPU" card. It is unknown how to write it, and it is very expensive.
  - BOMB: tag for cloning FM1208-xx "CPU" card, however properties do not match original chips (ATS is 18 bytes, not 16). *Exclsuive to "qinglong" software, but it costs way too much to be reasonable.*
  - SID: cheaper CPU cloning tag. No info right now, to be added. A bit cheaper than TID/BOMB.
      - *do you know why do the reviews of SID tag have image of "proxmark3 pro"?*


### MIFARE Ultralight

### MIFARE Ultralight, Copykey
^[Top](#top)

- Tags covered: UL11, UL21, N213, N215, N216

#### Characteristics 
^[Top](#top)

- Regular Ultralight DirectWrite (use `hf mfu setuid`) 
- Password protected: `B6AA558D` (static)
    - PACK seems to be ignored.

### Other chips

### NSCK-II
^[Top](#top)

- Magic tag for "NSC/BS-CPU"

#### Characteristics
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

#### Magic commands
^[Top](#top)

- Write NSC UID: `54 [part 1b] [data 4b enc] [CRC]`
    - Tag replies: `A2 [CRC]`

### SID
^[Top](#top)

- Magic tag for Fudan FM1208-9 chips

#### Characteristics
^[Top](#top)
- ISO14443-A tag
- ATQA-SAK: `0008`-`20`
- ATS: `10 78 80 A0 02 00 9D 46 16 40 00 A3 [UID]`
- Compared to real FM1208 chip:
  - CLA byte is ignored
  - Command parsing is irregular (some replies are wrong)

#### Magic commands
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
