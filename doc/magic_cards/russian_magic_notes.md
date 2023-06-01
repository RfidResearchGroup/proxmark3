<a id="top"></a>

# Notes on Russian Magic Cards

# Table of Contents

- [Low Frequency](#low-frequency)
  * [H1 (RW125FL, RW64bit)](#h1-rw125fl-rw64bit)
  * [H2 (T5577, RW125T5)](#h2-t5577-rw125t5)
  * [H3 (EM4305, RW125EM)](#h3-em4305-rw125em)
  * [H5](#h5)
  * [H5.5](#h55)
  * [H7](#h7)
  * [OTP](#otp)
  * [i57/i57v2](#i57i57v2)
- [High Frequency](#high-frequency)
  * [MIFARE ZERO](#mifare-zero)
  * [MF-8](#mf-8)
  * [MIFARE OTP](#mifare-otp)
  * [MIFARE OTP 2.0](#mifare-otp-20)
  * [MF3](#mf3)
  * [MIFARE UL-Y](#mifare-ul-y)
  * [MIFARE ULtra](#mifare-ultra)
  * [MIFARE UL-5](#mifare-ul-5)
  * [MIFARE, other chips](#mifare-other-chips)
  

## Low Frequency

### H1 (RW125FL, RW64bit)
^[Top](#top)

Tag supports EM410x format, and nothing else.
No locking functions.
No info, as this tag is ceasing its' existence.

### H2 (T5577, RW125T5)
^[Top](#top)

Tag supports all formats which send data in 24(28) bytes (without password).
Locking is done with lock bits in the beginning of each page, which are not transmitted.

#### Identify

```
lf search
...
[+] Chipset detection: T55xx
```
Not all tags will show up with this, however.
Some H2 tags ignore test mode commands.

### H3 (EM4305, RW125EM)

Tag is original EM4305, and can store 8 bytes of EM410x ID data.
Locking is done with lock pages. Tearoff attacks can be accomplished.

#### Identify
```
lf search
...
[+] Chipset detection: EM4x05
```
H3 chips usually come with a pre-programmed code, with `0x00` as the 2nd byte.

### H5

Tag has ceased production, as it was leaked. Some companies continue its' sale with a major discount.
Because it is hard to obtain this chip, there is no information.

### H5.5

Tag is manufactured by iKey, and is sold as a replacement to [H5](#h5) chips.
Locking support is unknown.

#### Identify

Tag has completely random EM410x ID from factory.
Engravings on fobs: "H5.5"

### H7

Tag is manufactured by iKey, and is sold as the most professional EM410x blank. Targeted to cloning StroyMaster keys.
Locking support cannot be described, as there is conflicting information (see [iKey forums](https://ikey.ru/forum/topic/3199-%D0%BA%D0%BE%D0%BF%D0%B8%D1%80%D0%BE%D0%B2%D0%B0%D0%BD%D0%B8%D0%B5-rfid-%D1%81%D1%87%D0%B8%D1%82%D1%8B%D0%B2%D0%B0%D1%82%D0%B5%D0%BB%D1%8C-atis/))

#### Identify

Tag has completely random EM410x ID from factory.
Engravings on fobs: "H7" (stretched)

### OTP

Tag is similar to [H1](#h1-rw125fl-rw64bit), but after writing new ID, tag becomes original EM410x.

#### Identify

Initial EM410x ID is `0000 000000`
Engravings on fobs: "OTP"

### i57/i57v2

Tag has ceased production, and can no longer be purchased.
No info.

## High Frequency

### MIFARE ZERO
^[Top](#top)

Cheapest cloning tag, pending replacement by [MF-8](#mf-8)

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

### MF-8
^[Top](#top)

Behavior: block 0 can be written with a normal write.
As MF-8 is a very new blank, it is assumed to be the last variation of its' chips.

#### Identify
^[Top](#top)

No way to reliably identify MF-8 is known. 
The best way is to try writing block 0. Or you can try:
```
hf 14a info
...
[+] Magic capabilities : Gen2 / CUID
```

### MIFARE OTP
^[Top](#top)

Behavior: same as [MF-8](#mf-8), but block0 can be written only once.

Initial UID is AA55C396

#### Identify
^[Top](#top)

Only possible before personalization.

```
hf 14a info
...
[+] Magic capabilities : Write Once / FUID
```
*It is possible to identify OTP after personalization. Currently it is unknown to us as to how this is done.*

### MIFARE OTP 2.0
^[Top](#top)

Similar to [ZERO](#mifare-zero), but after first block 0 edit, tag no longer replies to 0x40 command.

Initial UID is 00000000

All bytes are 00 from factory wherever possible.

#### Identify
^[Top](#top)

Only possible before personalization.

```
hf 14a info
...
[+] Magic capabilities : Gen 1a
[+] Prng detection: hard
```

#### Magic commands
^[Top](#top)

* Write: `40(7)`, `43`, `A0xx`+crc, `xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx`+crc

### MF3
^[Top](#top)

Most advanced tag, but possible to detect. Replacement for [OTP2](#mifare-otp-20) tags.

#### Identify
^[Top](#top)

Tag seems to behave like [MF-8](#mf-8), but it is unknown what is special about it.
Try issuing a write to block 0.

### MIFARE UL-Y
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

### MIFARE ULtra
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
```

Remember that this is not a reliable method of identification, as it interferes with locked [UL-5](#mifare-ul-5).

### MIFARE UL-5
^[Top](#top)

Ultralight EV1 magic; 41 page. Recommended for Vizit RF3.1 with 41 page and if [ULtra](#mifare-ultra) has failed.
Behavior: similar to Ultra, but after editing page 0, tag becomes original Mifare Ultralight EV1.

**WARNING!** When using UL-5 to clone, write UID pages in inverse and do NOT make mistakes! This tag does not allow reversing one-way actions (OTP page, lock bits).

#### Identify
^[Top](#top)

```
hf mfu info

[=] UID: AA 55 C3 A1 30 61 80
TAG IC Signature: 0000000000000000000000000000000000000000000000000000000000000000
[=] --- Tag Version
[=]        Raw bytes: 00 34 21 01 01 00 0E 03
```

After personalization it is not possible to identify UL-5. 
Some chips have UID of `AA 55 C3 A4 30 61 80`.

### MIFARE, other chips

**TODO**

UL-X, UL-Z - ?

