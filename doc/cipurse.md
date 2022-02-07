# Notes on CIPURSE card
<a id="Top"></a>

# Table of Contents

- [Notes on CIPURSE card](#notes-on-cipurse-card)
- [Table of Contents](#table-of-contents)
  - [Documentation](#documentation)
  - [Source code](#source-code)
  - [Communication channel with a card](#communication-channel-with-a-card)
  - [Card architecture](#card-architecture)
  - [Card structure](#card-structure)
  - [How to](#how-to)
  - [How to select application or file](#how-to-select-application-or-file)
  - [How to delete application or file](#how-to-delete-application-or-file)
  - [How to read file](#how-to-read-file)
  - [How to write file](#how-to-write-file)
  - [How to read file attributes](#how-to-read-file-attributes)
  - [How to set file attributes](#how-to-set-file-attributes)
  - [How to update key](#how-to-update-key)
    - [How to personalize card](#how-to-personalize-card)


## Documentation
^[Top](#top)

Useful links to documentation about CIPURSE.
[full documentation accessible from osptalliance](https://www.osptalliance.org/)
[Infineon cipurse](https://www.infineon.com/cms/en/product/security-smart-card-solutions/cipurse-products/)
[Infineon cipurse card SLS 32TLC100(M)](https://www.infineon.com/cms/en/product/security-smart-card-solutions/cipurse-products/sls-32tlc100m/)


## Source code
^[Top](#top)

Useful links to Implementations / Source code on Github.
[cipurse card emulation](https://github.com/duychuongvn/demo-nfc/tree/master/smart-ticket-demo/app/src/main/java/ch/smartlink/smartticketdemo/cipurse)
[cipurse card core](https://github.com/duychuongvn/cipurse-card-core)
[card side some code](https://github.com/duychuongvn/cipurse-card-side)


## Communication channel with a card
^[Top](#top)

The card has two secure channels - the reader to the card and the card to the reader.

And each channel has 3 modes: `open, MACed, Encrypted`

After authentication reader can specify the mode for each channel for each command.

Card answers if the mode that sets by the reader matches the mode of the file and the command matches the key via an access list.


## Card architecture
^[Top](#top)

The card has one master file with FID 0x3F00 that works as the root node.

The card has several applications inside the master file and the applications may have files. There are PxSE (special type) applications that work as an applications directory.

Each application has keys and an access control list that sets what commands can be issued in the session that authenticates with a specific key.

Master file have keys and an access control list that works at the card level.

Each file can only have an access control list that specifies what operation the key can do with this file.

Card have transaction mechanism. Transaction not needs for control structure at application level and to change files without 
transaction mechanism. All the rest changes needs to issue COMMIT command (`--commit` key)

## Card structure
^[Top](#top)

- Master file (MF)
- Keys
- Group security levels and access rights
- files under master file (EF). Usually have no access to them.

- PxSE files (directory files)

- Application 1. Have AID (up to 16-bytes) and FID (2-bytes id)
    - Application keys
    - Group security levels and access rights
    - Application files (EF). Have type (1-byte) and FID ((2-bytes id))

- Application 2
- ...


## How to

### How to select application or file
^[Top](#top)

**1. select PTSE**
```hf cipurse select --aid a0000005070100```

select it with display output in raw and tlv views options
```hf cipurse select --aid a0000005070100 -vt```

2. select application by Application ID (AID)
```hf cipurse select --aid 4144204631```

3. select application/file by file ID (FID)
```hf cipurse select --fid 2000```

4. select master file by file ID (FID)
```hf cipurse select --fid 3F00```

5. select default file (usually it master file)
```hf cipurse select --mfd```


### How to delete application or file
^[Top](#top)

1. delete PTSE by AID
```hf cipurse delete --aid a0000005070100```

2. delete application by AID
```hf cipurse delete --aid 4144204631```

3. delete application/top level file by FID
```hf cipurse delete --fid 2000```

3. delete file by FID from default application `AD F1`

```hf cipurse delete --aid 4144204631 --chfid 0102```


### How to read file
^[Top](#top)

with default key and aid
```hf cipurse read --fid 0102```

with default key and specified aid
```hf cipurse read --aid a0000005070100```

with default key and aid without authentication
```hf cipurse read --fid 0102 --no-auth```


### How to write file
^[Top](#top)

with default key and aid
```hf cipurse read --fid 0102 -d abbbccdd```

with default key and specified aid
```hf cipurse read --aid a0000005070100 -d abbbccdd```

with default key and aid without authentication
```hf cipurse read --fid 0102 -d abbbccdd --no-auth```

with default key and aid, perform commit (works for files with transactions mechanism switched on)
```hf cipurse read --fid 0102 -d abbbccdd --commit```


### How to read file attributes
^[Top](#top)

read master file attributes
```hf cipurse aread --mfd```

read EF.ID_INFO root file attributes
```hf cipurse aread --fid 2ff7```

read PxSE application attributes
```hf cipurse aread --aid a0000005070100```

read application attributes
```hf cipurse aread --aid 4144204632```

read file (EF) attributes

```hf cipurse aread --aid 4144204632 --chfid 0102```

or with default application

```hf cipurse aread --aid 4144204632 --chfid 0102```


### How to set file attributes
^[Top](#top)

set elementary file attributes (EF)

  full access wo keys
```hf cipurse awrite --chfid 0102 -d 020000ffffff```

  read access wo keys and full with all 2 keys
```hf cipurse awrite --chfid 0102 -d 02000040ffff```

set EF.ID_INFO file attributes
```hf cipurse awrite --fid 2ff7 -d 080000C1C1C1C1C1C1C1C1C1``` (as default)

set master file (MF) file attributes
```hf cipurse awrite --mfd -d 080000FFFFFFFFFFFFFFFFFF86023232 --commit``` (full access with/wo keys and tag 86 is set by `22`)


### How to update key
^[Top](#top)

update key for master application
```hf cipurse updakey --newkeyn 1 --newkeya 00 --newkey 73737373737373737373737373737373 --commit```

update key for application
```hf cipurse updakey --aid 4144204631 --newkeyn 1 --newkeya 00 --newkey 73737373737373737373737373737373 --commit```


### How to personalize card
^[Top](#top)

**1. Format card (if it needs)**
```hf cipurse formatall```

**2. Create create PxSE file**

The following command creates PTSE file with FID 0x2000, AID A0000005070100, and space for 8 AIDs

```hf cipurse create -d 9200123F00200008000062098407A0000005070100```

```
9200123F00200008000062098407A0000005070100
          ----                               FID
              --                             Num of AIDs in list
                            --------------   AID
```


**3. Create application file**

```hf cipurse create -d 92002438613F010A05020000FFFFFF021009021009621084054144204631D407A0000005070100A00F2873737373737373737373737373737373015FD67B000102030405060708090A0B0C0D0E0F01C6A13B```

This command creates a application with following details:
  - FID.................... 0x3F01
  - AID.................... 4144204631
  - App type............... 61
  - Max files count........ 10
  - Max SFID count......... 5
  - Minimum command's group security levels: plain/plain/plain/plain (0000)
  - Access rights.......... all two keys can do anything (FFFFFF)
  - Key attributes......... 021009
  - 2 keys.........
    - `73..73`     (add. info 01 / kvv 5FD67B)
    - `0001..0e0f` (01/C6A13B)
  - Register in the PxSE... A0000005070100

**4. Create elementary file(s) (EF) inside the application**

```hf cipurse create --aid 4144204631 -d 92010C010001020030020000FFFFFF --commit```

```
  - parent application ID.. 4144204631
  - file type.............. 0x01 (binary file wo transaction)
  - SFID................... 0x00
  - FID.................... 0x0102
  - File size.............. 0x0030 (48 bytes)
  - Number of keys......... 0x02 (as in the parent application)
  - Minimum command's group security levels: plain/plain/plain/plain (0000)
  - Access rights.......... all two keys can do anything (FFFFFF)
```

**5. Save data to elementary file(s) (EF)**

```hf cipurse write --fid 0102 -d 010203040506070809```

or if file with transaction mechanism


```hf cipurse write --fid 0102 -d 010203040506070809 --commit```


**6. Check file(s) contents (if needs)**
```hf cipurse read --fid 0102```


**8. Set the keys and needed key attributes**

keys for application usually filled at create time with DGI `A00F`

keys for masterfile needs to be updated manually with command:
```hf cipurse updakey --newkeyn 1 --newkeya 00 --newkey 73737373737373737373737373737373 --commit```

update key for application (if needs)
```hf cipurse updakey --aid 4144204631 --newkeyn 1 --newkeya 00 --newkey 73737373737373737373737373737373 --commit```

update key attributes with default attributes
```hf cipurse updakey --aid 4144204631 --trgkeyn 1 --attr 02 -v --commit```


**8. Set the file attributes**

Set file attributes for:
1. All the elementary files (EF)
2. Info files (EF.ID_INFO)
3. Application(s)
4. PxSE application
5. Master file itself (MF)

*(in this specific order!!!)*

