# Notes on MFU binary formats
<a id="Top"></a>


# Table of Contents
- [Notes on MFU binary formats](#notes-on-mfu-binary-formats)
- [Table of Contents](#table-of-contents)
  - [New mfu format](#new-mfu-format)
  - [Old mfu format](#old-mfu-format)
  - [Plain mfu format](#plain-mfu-format)
  - [future mfu format](#future-mfu-format)


  
## New mfu format
^[Top](#top)

The new mfu binary format was created to compensate for different manufactures tag functions.
Like UL-Ev1 has three counter and tearing bytes,  while NTAG only has one counter and tearing byte.
PACK was removed from header, since its just normally part of the tag memory,  unreadable,  but when 
a proxmark3 dumps a tag and we have pwd/pack,  we add those to their normal location in memory.
This makes memory not a exact memory dump from a tag, but a "what it should have looked like" if we could read all memory

```
// New Ultralight/NTAG dump file format
// Length must be aligned to 4 bytes (UL/NTAG page)
#define MFU_DUMP_PREFIX_LENGTH 56

typedef struct {
    uint8_t version[8];
    uint8_t tbo[2];
    uint8_t tbo1[1];
    uint8_t pages;                  // max page number in dump
    uint8_t signature[32];
    uint8_t counter_tearing[3][4];  // 3 bytes counter, 1 byte tearing flag
    uint8_t data[1024];
} PACKED mfu_dump_t;
```

## Old mfu format
^[Top](#top)

The old binary format saved the extra data on tag in order for the Proxmark3 to able to simulate a real tag.

```
// Old Ultralight/NTAG dump file format
#define OLD_MFU_DUMP_PREFIX_LENGTH 48

typedef struct {
    uint8_t version[8];
    uint8_t tbo[2];
    uint8_t tearing[3];
    uint8_t pack[2];
    uint8_t tbo1[1];
    uint8_t signature[32];
    uint8_t data[1024];
} old_mfu_dump_t;
```

## Plain mfu format
^[Top](#top)

The first binary format for MFU was just a memory dump from the tag block 0 to end.
No extra data was saved.  
```
    uint8_t data[1024];
```

## future mfu format
^[Top](#top)

For developers of apps and other tools, like libnfc,   we don't recommend using binary formats.
We decided to adopt a JSON based format,  which is much more flexible to changes of new tag functionality.

Example
```
{
  "Created": "proxmark3",
  "FileType": "mfu",
  "Card": {
    "UID": "04F654CAFC388",
    "Version": "0004030101000B0",
    "TBO_0": "000",
    "TBO_1": "0",
    "Signature": "BC9BFD4B550C16B2B5A5ABA10B644A027B4CB03DDB46F94D992DC0FB02E0C3F",
    "Counter0": "00000",
    "Tearing0": "BD",
    "Counter1": "00000",
    "Tearing1": "BD",
    "Counter2": "00000",
    "Tearing2": "BD"
  },
  "blocks": {
    "0": "04F6542",
    "1": "CAFC388",
    "2": "8E48000",
    "3": "E110120",
    "4": "0103A00",
    "5": "340300F",
    "6": "0000000",
    "7": "0000000",
    "8": "0000000",
    "9": "0000000",
    "10": "0000000",
    "11": "0000000",
    "12": "1122334",
    "13": "0000000",
    "14": "0000000",
    "15": "0000000",
    "16": "000000F",
    "17": "0005000",
    "18": "0000000",
    "19": "0000000"
  }
}
```
