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
| `Version` | hex, 28 bytes | raw `GetVersion` answer, hardware + software + production details concatenated |
| `Signature` | hex, 56 bytes | NXP originality signature, absent when the card refused it |
| `FreeMem` | int | bytes reported by `GetFreeMem`, absent when the card refused it |
| `KeySettings` | hex, 1 byte | PICC master key settings |
| `NumKeysRaw` | hex, 1 byte | raw key-count byte, carries the key type in the top bits |
| `NumKeys` | int | key count decoded from `NumKeysRaw` |
| `KeyVersion0` | hex, 1 byte | version of the PICC master key |
| `Keys` | object | see [Keys](#keys) |

Absent means the field is not written at all. Do not read a missing field as a
zero.

## Applications
^[Top](#top)

`$.Applications` is an object keyed by the 3-byte AID as 6 uppercase hex digits.

```json
"Applications": {
  "F51800": {
    "ISOFileID": "DF01",
    "DFName": "D2760000850100",
    "KeySettings": "0B",
    "NumKeysRaw": "81",
    "NumKeys": 1,
    "KeyType": "aes",
    "KeyVersions": { "0": "00" },
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
| `NumKeysRaw` | hex, 1 byte | |
| `NumKeys` | int | |
| `KeyType` | token | `des`, `2tdea`, `3tdea` or `aes` |
| `KeyVersions` | object | key number -> 1 byte version |
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

Both `$.Card` and each application carry the same shape:

```json
"Keys": {
  "0": { "Algo": "aes", "Key": "E757178E13516A4F3171BC6EA85E165A" }
}
```

Keyed by key number in decimal. `Algo` fixes the key length: `des` 8 bytes,
`2tdea` 16, `3tdea` 24, `aes` 16. Only key numbers actually known are written,
so an absent entry means "we do not have this key", never "the key is zero".

`$.Card.Keys` holds the PICC master keys, which are the keys of AID `000000`.
Note the difference from the `mfdes v2` key recovery format, where PICC keys sit
under `Applications.000000` and are indexed by algorithm as well as key number.

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

| `Algo` / `KeyType` | key length |
|---|---|
| `des` | 8 |
| `2tdea` | 16 |
| `3tdea` | 24 |
| `aes` | 16 |

Hex strings are uppercase with no separators. Byte order is as the bytes travel
on the wire, except `AccessRights` and the ISO file IDs, which are written big
endian the way they are printed.

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
