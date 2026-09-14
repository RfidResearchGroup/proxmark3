# MIFARE DESFire dump file format

<a id="top"></a>

The `mfdes v1` json format is the on-disk image of a DESFire PICC: the card level
details, every application, every file's settings, and the file contents that
could actually be read. It is what `hf mfdes dump` writes and `hf mfdes view`
reads, and it is the format an emulator-memory loader (`hf mfdes eload`) will be
built on.

# Table of Contents

- [MIFARE DESFire dump file format](#mifare-desfire-dump-file-format)
- [Table of Contents](#table-of-contents)
- [Commands](#commands)
- [File identity](#file-identity)
- [Card level](#card-level)
- [Applications](#applications)
- [Files](#files)
  - [Common fields](#common-fields)
  - [Standard and backup data files](#standard-and-backup-data-files)
  - [Value files](#value-files)
  - [Record files](#record-files)
  - [Transaction MAC files](#transaction-mac-files)
- [Keys](#keys)
- [The Read flag](#the-read-flag)
- [Token spellings](#token-spellings)
- [A complete example](#a-complete-example)
  - [The card](#the-card)
  - [The key file](#the-key-file)
  - [The dump file](#the-dump-file)
  - [What `hf mfdes view` makes of it](#what-hf-mfdes-view-makes-of-it)
- [In-memory representation](#in-memory-representation)
- [Not in v1](#not-in-v1)

## Commands
^[Top](#top)

```
hf mfdes dump                       walk the whole PICC, save hf-mfdes-<UID>-dump.json
hf mfdes dump --aid 123456          dump only that application
hf mfdes dump --keys <fn>           take per-application keys from a `hf mfdes chk` key file
hf mfdes dump --ns                  collect and print, save nothing
hf mfdes dump -f myfile             save under a name of your choosing
hf mfdes view -f <fn>               print a dump file, no device needed
```

With no `--keys`, the dump looks for `hf-mfdes-<UID>-keys.json` by itself, so a
`hf mfdes chk -j hf-mfdes-<UID>-keys` run is picked up on the next dump without
naming the file again.

With no `--aid` / `--isoid` / `--dfname` the command walks every application the
PICC lists. The default filename is `hf-mfdes-<UID>-dump.json`; only json is
written, there is no `.bin` companion.

## File identity
^[Top](#top)

```json
{
  "Created": "proxmark3",
  "FileType": "mfdes v1",
  "Version": 1
}
```

`FileType` is what the loader dispatches on. `Version` is the same number in
machine-readable form. A reader that does not understand a `FileType` must
refuse the file rather than guess -- `mfdes v2` is already taken by the key
recovery output of `hf mfdes chk`, which is a different, much smaller format.

## Card level
^[Top](#top)

Everything under `$.Card` describes the PICC itself.

| Field | Type | Meaning |
|---|---|---|
| `UID` | hex | 4 or 7 byte UID from the 14a select |
| `ATQA` | hex, 2 bytes | wire order, the same way every other pm3 dump format stores it. `hf 14a info` prints the two bytes the other way round |
| `SAK` | hex, 1 byte | |
| `ATS` | hex | answer to RATS, absent when the card gave none |
| `VersionHW` | hex, 7 bytes | first `GetVersion` frame: vendor, type, subtype, major, minor, storage, protocol |
| `VersionSW` | hex, 7 bytes | second `GetVersion` frame, same field order |
| `VersionProd` | hex, 14 bytes | third `GetVersion` frame: UID and production details |
| `Signature` | hex, 56 bytes | NXP originality signature, absent when the card refused it |
| `FreeMem` | int | bytes reported by `GetFreeMem`, absent when the card refused it |

Absent means the field is not written at all. Do not read a missing field as a
zero.

`GetVersion` answers over three chained frames and they are stored as three
fields rather than one blob, because the third frame is not the same shape
across generations: D40 and EV1 close it with `UID || BatchNo[5] || CW || Year`
while EV3 re-cuts it as `UID || BatchNo[3] || TypeID[2] || CW || Year`. Each
frame is kept raw, so any generation round-trips without the format having to
know which one it is holding.

`VersionHW` bytes 3 and 4 -- major and minor -- are what identify the
generation. `client/src/mifare/prime.c` maps them: EV1 is `01 00`, EV2 is
`12 00` or `42 00`, EV2 XL `22 00`, EV3 `33 00`, DuoX `A0 00`. Byte 5 is the
storage size code, `2^(n>>1)` bytes.

Nothing key related lives here. The PICC master key settings and keys belong to
application `000000` -- see [Applications](#applications) -- so every key in the
file states which AID it opens.

## Applications
^[Top](#top)

`$.Applications` is an object keyed by the 3-byte AID as 6 uppercase hex digits.

**The PICC level is application `000000`.** It carries the PICC master key
settings and keys and has no files. Giving it an AID of its own is the point: a
key in this file always says which application it opens.

```json
"Applications": {
  "000000": {
    "KeySettings": "0F",
    "NumKeysRaw": "01",
    "NumKeys": 1,
    "KeyType": "2tdea",
    "Authenticated": true,
    "Keys": {
      "0": { "Version": "00", "Key": "00000000000000000000000000000000" }
    }
  },
  "F51800": {
    "ISOFileID": "DF01",
    "DFName": "D2760000850100",
    "KeySettings": "0B",
    "NumKeysRaw": "81",
    "NumKeys": 1,
    "KeyType": "aes",
    "Authenticated": true,
    "Keys": { },
    "Files": { }
  }
}
```

| Field | Type | Meaning |
|---|---|---|
| `ISOFileID` | hex, 2 bytes | ISO DF ID, absent when the application has none |
| `DFName` | hex, 1-16 bytes | ISO DF name, absent when the application has none |
| `KeySettings` | hex, 1 byte | |
| `NumKeysRaw` | hex, 1 byte | raw key-count byte, carries the key type in the top bits and the ISO-file-id flag in bit 5 |
| `NumKeys` | int | key count decoded from `NumKeysRaw` |
| `KeyType` | token | `des`, `2tdea`, `3tdea` or `aes`. One per application -- every key in an application shares it |
| `Authenticated` | bool | whether the dump ran authenticated against this application |
| `Keys` | object | see [Keys](#keys) |
| `Files` | object | see [Files](#files) |

`Authenticated: false` is the flag that says how much to trust the rest of the
application: settings and contents may be whatever the card hands out to an
unauthenticated reader, which on many cards is nothing at all.

JSON objects are unordered. A reader must look applications and files up by
key, not by position.

## Files
^[Top](#top)

`Files` is an object keyed by the file number as 2 uppercase hex digits.

### Common fields
^[Top](#top)

| Field | Type | Meaning |
|---|---|---|
| `Type` | token | see [Token spellings](#token-spellings) |
| `TypeRaw` | hex, 1 byte | the file type byte as the card reported it. This is the authoritative one, `Type` is for humans |
| `ISOFileID` | hex, 2 bytes | absent when the file has none |
| `CommMode` | token | `plain`, `mac`, `plain_rfu` or `encrypt`, from the raw 2-bit file comm mode |
| `AccessRights` | hex, 2 bytes | raw access rights word: read, write, read/write, change, 4 bits each |
| `AdditionalAccessRights` | object | index -> 2 byte rights word, absent when the file has none |
| `Read` | bool | see [The Read flag](#the-read-flag) |

### Standard and backup data files
^[Top](#top)

`TypeRaw` `00` and `01`.

| Field | Type | Meaning |
|---|---|---|
| `FileSize` | int | size the card reports |
| `Data` | hex | contents. May be shorter than `FileSize` when `hf mfdes dump --length` capped the read |

### Value files
^[Top](#top)

`TypeRaw` `02`. A value file has no `Data`.

| Field | Type | Meaning |
|---|---|---|
| `LowerLimit` | int | |
| `UpperLimit` | int | |
| `LimitedCredit` | hex, 1 byte | |
| `Value` | int | present only when `Read` is true |

### Record files
^[Top](#top)

`TypeRaw` `03` (linear) and `04` (cyclic).

| Field | Type | Meaning |
|---|---|---|
| `RecordSize` | int | bytes per record |
| `MaxRecords` | int | |
| `CurRecords` | int | |
| `Records` | object | record index -> hex string of exactly `RecordSize` bytes |

Records are numbered from `0` and must be contiguous. A record file whose
contents could not be split into whole records falls back to a single flat
`Data` string instead of `Records`.

### Transaction MAC files
^[Top](#top)

`TypeRaw` `05`. Stored like a data file: the 12 byte answer goes in `Data`
(4 byte counter, 8 byte MAC), and is not decoded further.

## Keys
^[Top](#top)

Keys are part of the image, not a side file. A simulator cannot answer an
authentication without them, and splitting them across two files means a card
image that silently cannot be used.

Every application, `000000` included, carries a `Keys` object keyed by key
number in decimal:

```json
"Keys": {
  "0": { "Version": "00", "Key": "E757178E13516A4F3171BC6EA85E165A" },
  "1": { "Version": "03" }
}
```

| Field | Meaning |
|---|---|
| `Version` | the key version, as read from the card. Present whenever we managed to read it |
| `Key` | the key itself. Present only when we actually have it |

A key version is readable without knowing the key, so the two are independent:

* **`Version` and `Key`** -- we read the version and we have the key.
* **`Version` only** -- the key exists, we know its version, we could not
  recover it. This is the normal case for every key but the one we authenticated
  with. A missing `Key` never means the key is all zeros.
* **entry absent entirely** -- we know nothing about that key number.

There is no per-key algorithm. Every key in an application uses the
application's `KeyType`, which fixes the length: `des` 8 bytes, `2tdea` 16,
`3tdea` 24, `aes` 16.

Note the difference from the `mfdes v2` key recovery format written by
`hf mfdes chk`, which nests keys under an algorithm name
(`Applications.112233.AES.0.Key`) because during recovery the key type is not
yet known. In a dump it is, so the algorithm is stated once per application.

`hf mfdes dump` reads a `mfdes v2` key file with `--keys <fn>`, and with no
`--keys` it looks for `hf-mfdes-<UID>-keys.json` on its own -- the same filename
template it saves the dump under. Nothing is reported if that file does not
exist.

## The Read flag
^[Top](#top)

Every file carries `Read`. It is true only when the contents were actually
fetched from the card.

* `Read: true` with `Data` -- these are the card's bytes.
* `Read: true` without `Data` (or with an empty one) -- the card answered, with nothing in it.
* `Read: false` -- we never got the contents. Access was denied, the key was
  wrong, or the session died. There is no `Data` key at all.

A reader must never turn a missing `Data` into zeros. The whole point of the
flag is that "8 bytes of 00" and "we could not read 8 bytes" are different
facts, and a simulator that confuses them will confidently answer a reader with
contents the card never had.

## Token spellings
^[Top](#top)

String tokens match what the `hf mfdes` CLI already accepts, so a value read out
of a dump file can be handed straight back to a command.

| `Type` | `TypeRaw` |
|---|---|
| `standard` | `00` |
| `backup` | `01` |
| `value` | `02` |
| `linear_record` | `03` |
| `cyclic_record` | `04` |
| `transaction_mac` | `05` |

| `CommMode` | raw |
|---|---|
| `plain` | `0` |
| `mac` | `1` |
| `plain_rfu` | `2` |
| `encrypt` | `3` |

`plain_rfu` is the card's second encoding for plain. It is kept distinct from
`plain` so the file records what the card actually said.

| `KeyType` | key length |
|---|---|
| `des` | 8 |
| `2tdea` | 16 |
| `3tdea` | 24 |
| `aes` | 16 |

Hex strings are uppercase with no separators. Byte order is as the bytes travel
on the wire, except `AccessRights` and the ISO file IDs, which are written big
endian the way they are printed.

## A complete example
^[Top](#top)

A real dump of a MIFARE DESFire EV2 2K, set up from blank with the commands
below. Every construct in this document appears in it: the PICC as application
`000000`, an AES application and a 2TDEA one, a standard data file, a value
file, a record file, and keys that are known by version but not by value.

### The card
^[Top](#top)

```
# two applications, one AES with 3 keys, one 2TDEA with 2
hf mfdes createapp -t 2tdea -k 00000000000000000000000000000000 --aid 112233 --fid 1122 --dfname pm3test1 --ks1 0F --ks2 A3
hf mfdes createapp -t 2tdea -k 00000000000000000000000000000000 --aid 445566 --fid 4455 --dfname pm3test2 --ks1 0F --ks2 22

# ks2 carries the key type in the top two bits (0 = 2TDEA, 1 = 3TDEA, 2 = AES),
# the ISO-file-id flag in bit 5 and the key count in the low five.  It overrides
# --dstalgo and --numkeys, so A3 is "AES, ISO file ids, 3 keys"

# files in the AES application
hf mfdes createfile       --aid 112233 -t aes -k 00000000000000000000000000000000 --fid 01 --isofid 0001 --size 000020 --amode encrypt --rrights key0 --wrights key0 --rwrights key0 --chrights key0
hf mfdes createvaluefile  --aid 112233 -t aes -k 00000000000000000000000000000000 --fid 02 --amode mac --lower 00000000 --upper 000003E8 --value 0000002A --lcredit 1 --rrights key0 --wrights key0 --rwrights key0 --chrights key0
hf mfdes createrecordfile --aid 112233 -t aes -k 00000000000000000000000000000000 --fid 03 --isofid 0003 --size 000008 --maxrecord 000005 --amode plain --rrights free --wrights key0 --rwrights key0 --chrights key0

# and one in the 2TDEA application
hf mfdes createfile --aid 445566 -t 2tdea -k 00000000000000000000000000000000 --fid 00 --isofid 0010 --size 000010 --amode plain --rrights free --wrights key0 --rwrights key0 --chrights key0

# contents
hf mfdes write --aid 112233 -t aes -k 00000000000000000000000000000000 --fid 01 -d 50726F786D61726B33204445534669726520746573742064617461212121
hf mfdes write --aid 112233 -t aes -k 00000000000000000000000000000000 --fid 03 --type record -d 5245434F52443031
hf mfdes write --aid 112233 -t aes -k 00000000000000000000000000000000 --fid 03 --type record -d 5245434F52443032
hf mfdes write --aid 445566 -t 2tdea -k 00000000000000000000000000000000 --fid 00 -d 48454C4C4F2050524F584D41524B2133

# recover the application keys, saved under the name the dump will look for
hf mfdes chk -k 00000000000000000000000000000000 -j hf-mfdes-043240CAE45380-keys

# and dump it
hf mfdes dump -t 2tdea -k 00000000000000000000000000000000

# to put the card back the way it was
hf mfdes formatpicc -t 2tdea -k 00000000000000000000000000000000
```

Without that `chk` run, application `112233` cannot be opened with the 2TDEA
PICC key. The dump does not pretend otherwise: it records the application with
`"Authenticated": false` and no files, rather than inventing empty ones.

### The key file
^[Top](#top)

`hf-mfdes-043240CAE45380-keys.json`, written by `hf mfdes chk -j`. This is the
separate `mfdes v2` format, not part of the card image -- `hf mfdes dump` reads
it and folds the keys it contains into the dump.

```json
{
  "Created": "proxmark3",
  "FileType": "mfdes v2",
  "Card": {
    "UID": "043240CAE45380",
    "SAK": "20",
    "ATQA": "4403",
    "ATS": "06757781028002F0"
  },
  "Applications": {
    "112233": {
      "AES": {
        "0": {
          "Key": "00000000000000000000000000000000"
        }
      }
    },
    "445566": {
      "2TDEA": {
        "0": {
          "Key": "00000000000000000000000000000000"
        }
      }
    }
  }
}
```

Two differences from the way the dump stores keys:

* Keys are nested under an **algorithm name** (`Applications.112233.AES.0.Key`)
  because during key recovery the application's key type is not yet known. A
  dump knows it, so it states `KeyType` once per application instead.
* PICC keys are not in this file at all. `hf mfdes chk` only walks the
  application list; the PICC master key is the one you hand it with `-k`.

The dump picks this file up without `--keys` because its name follows the same
`hf-mfdes-<UID>-` template the dump itself is saved under:

```
[=] Loaded keys for 2 application(s) from `hf-mfdes-043240CAE45380-keys`
```

### The dump file
^[Top](#top)

```json
{
  "Created": "proxmark3",
  "FileType": "mfdes v1",
  "Version": 1,
  "Card": {
    "UID": "043240CAE45380",
    "ATQA": "4403",
    "SAK": "20",
    "ATS": "06757781028002F0",
    "VersionHW": "04010112001605",
    "VersionSW": "04010102001605",
    "VersionProd": "043240CAE45380CD651745414216",
    "Signature": "035766BD56631ED57B614CE01A24372BDC29028A310937BC42EE998C66E56E6251083B723099D80EB77291B1A8BDB055C614EC944A11E38E",
    "FreeMem": 1984
  },
  "Applications": {
    "000000": {
      "KeySettings": "0F",
      "NumKeysRaw": "01",
      "NumKeys": 1,
      "KeyType": "2tdea",
      "Authenticated": true,
      "Keys": {
        "0": {
          "Version": "00",
          "Key": "00000000000000000000000000000000"
        }
      }
    },
    "112233": {
      "ISOFileID": "1122",
      "DFName": "706D337465737431",
      "KeySettings": "0F",
      "NumKeysRaw": "83",
      "NumKeys": 3,
      "KeyType": "aes",
      "Authenticated": true,
      "Keys": {
        "0": {
          "Version": "00",
          "Key": "00000000000000000000000000000000"
        },
        "1": {
          "Version": "00"
        },
        "2": {
          "Version": "00"
        }
      },
      "Files": {
        "01": {
          "Type": "standard",
          "TypeRaw": "00",
          "CommMode": "encrypt",
          "AccessRights": "0000",
          "ISOFileID": "0001",
          "FileSize": 32,
          "Read": true,
          "Data": "50726F786D61726B332044455346697265207465737420646174612121210000"
        },
        "02": {
          "Type": "value",
          "TypeRaw": "02",
          "CommMode": "mac",
          "AccessRights": "0000",
          "LowerLimit": 0,
          "UpperLimit": 1000,
          "LimitedCredit": "01",
          "Value": 42,
          "Read": true
        },
        "03": {
          "Type": "linear_record",
          "TypeRaw": "03",
          "CommMode": "plain",
          "AccessRights": "E000",
          "ISOFileID": "0003",
          "RecordSize": 8,
          "MaxRecords": 5,
          "CurRecords": 2,
          "Read": true,
          "Records": {
            "0": "5245434F52443031",
            "1": "5245434F52443032"
          }
        }
      }
    },
    "445566": {
      "ISOFileID": "4455",
      "DFName": "706D337465737432",
      "KeySettings": "0F",
      "NumKeysRaw": "02",
      "NumKeys": 2,
      "KeyType": "2tdea",
      "Authenticated": true,
      "Keys": {
        "0": {
          "Version": "00",
          "Key": "00000000000000000000000000000000"
        },
        "1": {
          "Version": "00"
        }
      },
      "Files": {
        "00": {
          "Type": "standard",
          "TypeRaw": "00",
          "CommMode": "plain",
          "AccessRights": "E000",
          "ISOFileID": "0010",
          "FileSize": 16,
          "Read": true,
          "Data": "48454C4C4F2050524F584D41524B2133"
        }
      }
    }
  }
}
```

Things to read out of it:

* **`FreeMem` is 1984** with the two applications in place. Measured on this same
  card: 2080 free before the example was built, 1984 with it, and 2560 after
  `hf mfdes formatpicc`. A format therefore reclaims space that creating and
  deleting applications leaves behind -- 0 applications on its own does not mean
  a fully free card.
* **`NumKeysRaw` `83`** decodes to `KeyType: aes` (top bits 10), ISO file ids
  enabled (bit 5) and `NumKeys: 3`.
* **Keys 1 and 2 of `112233` have a `Version` but no `Key`.** They exist, we
  read their version, we never recovered them. Key 0 is the one `hf mfdes chk`
  found.
* **The value file has no `Data`**, only `Value`, `LowerLimit`, `UpperLimit`
  and `LimitedCredit`.
* **The record file has `Records`, not `Data`** -- two records of 8 bytes in a
  file with room for five.
* **File `01` reads 32 bytes** where only 30 were written; the card zero-pads to
  the file size, and the dump stores what the card returned.

### What `hf mfdes view` makes of it
^[Top](#top)

```

[=] --- Tag Information ---------------------------
[+] UID.............. 043240CAE45380
[+] ATQA............. 03 44
[+] SAK.............. 20
[+] ATS.............. 06757781028002F0
[+] Version HW....... 04010112001605
[+]                   12.0 ( DESFire EV2 )
[+]   Storage size... 0x16 ( 2048 bytes )
[+] Version SW....... 04010102001605
[+] Production....... 043240CAE45380CD651745414216
[+] Signature........ 035766BD56631ED57B614CE01A24372BDC29028A310937BC42EE998C66E56E6251083B723099D80EB77291B1A8BDB055C614EC944A11E38E
[+] Free memory...... 1984 bytes

[=] --- Applications ------------------------------
[+] 2 application(s) plus the PICC level

[=] --- AID 000000 ( PICC level ) ---------------------
[+]     Key settings. 0F, 1 2tdea key(s)
[+]     Authenticated yes
[+]     Key 00 (ver 00). 00000000000000000000000000000000
[+]     Files........ 0

[=] --- AID 112233 --------------------------------
[+]     ISO DF ID.... 1122
[+]     DF name...... pm3test1 ( 706D337465737431 )
[+]     Key settings. 0F, 3 aes key(s)
[+]     Authenticated yes
[+]     Key 00 (ver 00). 00000000000000000000000000000000
[+]     Key 01 (ver 00). not recovered
[+]     Key 02 (ver 00). not recovered
[+]     Files........ 3

[+]   File 01 - Standard data
[+]     ISO file ID.. 0001
[+]     Comm mode.... encrypt
[+]     Access rights 0000
[+]     File size.... 32

[=]  Offset  | Data                                            | Ascii
[=] ----------------------------------------------------------------------------
[=]   0/0x00 | 50 72 6F 78 6D 61 72 6B 33 20 44 45 53 46 69 72 | Proxmark3 DESFir
[=]  16/0x10 | 65 20 74 65 73 74 20 64 61 74 61 21 21 21 00 00 | e test data!!!..

[+]   File 02 - Value
[+]     Comm mode.... mac
[+]     Access rights 0000
[+]     Limits....... 0 ... 1000
[+]     Value........ 42 (0x0000002A)

[+]   File 03 - Linear Record
[+]     ISO file ID.. 0003
[+]     Comm mode.... plain
[+]     Access rights E000
[+]     Records...... 2 of 5, 8 bytes each

[+]     Record 0
[=]  Offset  | Data                                            | Ascii
[=] ----------------------------------------------------------------------------
[=]   0/0x00 | 52 45 43 4F 52 44 30 31                         | RECORD01
[+]     Record 1
[=]   0/0x00 | 52 45 43 4F 52 44 30 32                         | RECORD02

[=] --- AID 445566 --------------------------------
[+]     ISO DF ID.... 4455
[+]     DF name...... pm3test2 ( 706D337465737432 )
[+]     Key settings. 0F, 2 2tdea key(s)
[+]     Authenticated yes
[+]     Key 00 (ver 00). 00000000000000000000000000000000
[+]     Key 01 (ver 00). not recovered
[+]     Files........ 1

[+]   File 00 - Standard data
[+]     ISO file ID.. 0010
[+]     Comm mode.... plain
[+]     Access rights E000
[+]     File size.... 16

[=]  Offset  | Data                                            | Ascii
[=] ----------------------------------------------------------------------------
[=]   0/0x00 | 48 45 4C 4C 4F 20 50 52 4F 58 4D 41 52 4B 21 33 | HELLO PROXMARK!3
```

## In-memory representation
^[Top](#top)

`desfire_dump_t` in `client/src/fileutils.h`, written by `prepareJSON()` and read
by `loadFileJSONex()` in `client/src/fileutils.c`.

File contents hang off `desfire_dump_file_t` as heap pointers, so an image can
hold real file sizes without the struct itself being enormous. Whoever fills or
loads one owns those buffers and must call `desfire_dump_free()` before dropping
the image.

The struct is bounded by `DESFIRE_MAX_APP_COUNT` (64) applications and
`DESFIRE_MAX_FILE_COUNT` (32) files per application, both in `include/desfire.h`.
Reading a file with more than that logs a warning and keeps the first N.

## Not in v1
^[Top](#top)

Deliberately absent, listed so the next version does not have to rediscover them:

* **No emulator memory layout.** This format is a card image, not a memory map.
  How a PICC image is packed into the 4096 bytes of `CARD_MEMORY_SIZE` is a
  separate problem, and the answer will not fit a large card.
* **No delegated application / DAM slot details.**
* **No key derivation state.** If a key in the file came out of AN10922 or the
  Gallagher KDF, only the derived key is stored, not the diversification input.
* **No LRP / EV2 secure channel state**, no transaction counter, no `TI`.
* **No ISO 7816 file structure** beyond the ISO file IDs.
