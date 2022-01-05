# Notes on MIFARE DESFire
<a id="Top"></a>

# Table of Contents

- [Notes on MIFARE DESFire](#notes-on-mifare-desfire)
- [Table of Contents](#table-of-contents)
  - [Documentation](#documentation)
  - [Source code](#source-code)
  - [Communication channel with a card](#communication-channel-with-a-card)
  - [Card architecture](#card-architecture)
  - [Card structure](#card-structure)
  - [DESFire Light](#desfire-light)
  - [How to](#how-to)
    - [How to get card UID](#how-to-get-card-uid)
    - [How to get/set default communication channel settings](#how-to-getset-default-communication-channel-settings)
    - [How to guess default communication channel settings](#how-to-guess-default-communication-channel-settings)
    - [How to try communication channel settings](#how-to-try-communication-channel-settings)
    - [How to look at the application list on the card](#how-to-look-at-the-application-list-on-the-card)
    - [How to look/dump files from the application file list](#how-to-lookdump-files-from-the-application-file-list)
    - [How to change key](#how-to-change-key)
    - [How to create the application](#how-to-create-the-application)
    - [How to create files](#how-to-create-files)
    - [How to delete files](#how-to-delete-files)
    - [How to read/write files](#how-to-readwrite-files)
    - [How to work with transaction mac](#how-to-work-with-transaction-mac)
    - [How to switch DESFire Light to LRP mode](#how-to-switch-desfire-light-to-lrp-mode)


## Documentation
^[Top](#top)

[DESFire Light datasheet MF2DL(H)x0](https://www.nxp.com/docs/en/data-sheet/MF2DLHX0.pdf)

[Features and Hints AN12343](https://www.nxp.com/docs/en/application-note/AN12343.pdf)

[Quick Start Guide AN12341](https://www.nxp.com/docs/en/application-note/AN12341.pdf)

[LRP Specification](https://www.nxp.com/docs/en/application-note/AN12304.pdf)

[NTAG 424 DNA NT4H2421Gx](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)

[NTAG features and hints - LRP mode](https://www.nxp.com/docs/en/application-note/AN12321.pdf)

[ev2 samples AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf)

[MIFARE Application Directory AN10787](https://www.nxp.com/docs/en/application-note/AN10787.pdf)

[Symmetric key diversifications AN10922](https://www.nxp.com/docs/en/application-note/AN10922.pdf)

## Source code
^[Top](#top)

[desfire_crypto from proxmark3](https://github.com/RfidResearchGroup/proxmark3/blob/master/armsrc/desfire_crypto.c)

[libfreefare](https://github.com/nfc-tools/libfreefare)

[desfire-tools-for-android](https://github.com/skjolber/desfire-tools-for-android)

[nfcjlib](https://github.com/andrade/nfcjlib/)

[java-card-desfire-emulation](https://github.com/gathigai/java-card-desfire-emulation)

[ChameleonMiniDESFireStack](https://github.com/maxieds/ChameleonMiniDESFireStack/)

[LRP/ev2 nfc-ev2-crypto](https://github.com/icedevml/nfc-ev2-crypto)

## Communication channel with a card
^[Top](#top)

The card can work with a combination of: key type - command set - secure channel - communication mode

*key types:*

**des** - 8-byte key. can be present in a form of **2tdea** key with length 16 bytes by duplicating contents twice.

**2tdea** - 16-byte key

**3tdea** - 24-byte key. can be disabled on the card level.

**aes** - 16-byte AES-128 key

*command sets:*

**native** - raw commands

**native iso** - wraps raw commands into the ISO APDU. **CLA** = 0x90, **INS** = command code, **data** = the remaining data from raw command

**iso** - works only for some commands: ISO select by ISO ID (if enabled), authenticate, read and write in the **plain** mode, read in the **mac** mode

*secure channels:*

**d40** - old secure channel that can work only with **des** and **2tdea** keys

**ev1** - secure channel that can work with all the keys: **des**, **2tdea**, **3tdea**, **aes**

**ev2** - the newest channel that can work with **aes** key only

*communication modes*

**plain** - just plain data between card and reader

**maced** - mac applied to request/response/both (may be sent or not)

**encrypted** - encrypted data in the request/response/both in the ev2 channel data signed with mac.

## Card architecture
^[Top](#top)

The card has several applications on it and the applications have files and some other objects.

Each card has a master application with AID 0x000000 that saves the card's configuration.

Master application has many keys with different purposes, but commands show that there is only one key - card master key.

Each application may have its own key type and set of keys. Each file can only have links to these keys in its access rights.

## Card structure
^[Top](#top)

- Application
- Application number: 1 byte
- Application ISO number: if set at the time of application creation. It can be selected by this ID in the ISO command set.
- Application DF name: 1-16 chars. It can be selected by this name in the ISO command set.
- Key settings: number of keys, key type, key config (what can do/not user with keys)
- Keys: up to 14 keys (indexes 0..d)
- Key versions: key version of corresponding key
- Files:
  - File number: 1 byte
  - File ISO number: should be present if and only if application created with ISO number.
  - File type: standard, backup, value, cyclic record, linear record, transaction mac
  - Some settings that belong to file type (size for standard file for example)
  - File communication mode: plain/maced/encrypted
  - File access right: there are 4 modes: read/write/read-write/change settings. And each mode access can be: key0..keyD, E - free access, F - deny access

## DESFire Light
^[Top](#top)

The card has one preinstalled master file (ISO ID 0x3f00) and one application (0xdf01)

In the application, there are 6 files:

- 0x00 Standard data file with size 256 bytes
- 0x01 Cyclic record file with 5 records with size 16 bytes each
- 0x03 Value file
- 0x04 Standard data file with size 256 bytes
- 0x0f Transaction MAC file with size 256 bytes
- 0x1f Standard data file with size 32 bytes. Used for FCI.

User can't create/delete files (except Transaction MAC file).

ISO file IDs, the other files and application parameters can be changed via SetConfiguration command only.

The card has two secure channels: EV2 and LRP. By default, EV2 is on. LRP can be switched on by issuing SetConfiguration command and after that, it can't be switched off.

Application on the card can't be selected by DESFire native select. Needs to issue ISO select command. All the commands that can work in LRP channel have **--appisoid** option

Transaction MAC file - the only file that can be created and deleted. By default, all transaction operations (operations with Value and Record file) need to issue CommitReaderID command.  
So (to fast check- it is needed to delete this file) it has default file id - 0x0f.

FCI sends from card to reader after selecting the application (df01 by default)

If it needs to have more space for FCI - just change the ID of one of the bigger files to 0x1f (and the current ID to something else) via SetConfiguration command.

## How to


### How to get card UID
^[Top](#top)

The card can return UID in encrypted communication mode. Needs to authenticate with any key from the card.

`hf mfdes getuid` - authenticate with default key

`hf mfdes getuid -s d40` - via d40 secure channel

`hf mfdes getuid -s ev2 -t aes -k 11223344556677889900112233445566` - via ev2 secure channel with specified aes key

### How to get/set default communication channel settings
^[Top](#top)

All the commands use these settings by default if a more important setting is not specified in the command line.

`hf mfdes default` - get channel settings

`hf mfdes default -n 1 -t aes` - set key number 1 and key type aes

### How to guess default communication channel settings
^[Top](#top)

`hf mfdes detect` - simply detect key for master application (PICC level)

`hf mfdes detect --save` - detect key and save to defaults. look after to output of `hf mfdes default`

`hf mfdes detect -s d40` - detect via channel d40

`hf mfdes detect --dict mfdes_default_keys` - detect key with help of dictionary file

`hf mfdes detect --aid 123456 -n 2` - detect key 2 from application with AID 123456

### How to try communication channel settings
^[Top](#top)

`hf mfdes auth -n 0 -t des -k 1122334455667788 --aid 123456` - try application 123456 master key

`hf mfdes auth -n 0 -t aes --save` - try PICC AES master key and save the configuration to defaults if authentication succeeds

### How to look at the application list on the card
^[Top](#top)

`hf mfdes lsapp --no-auth` - show applications list without authentication

`hf mfdes lsapp` - show applications list with authentication from default settings

`hf mfdes lsapp --files` - show applications list with their files

`hf mfdes getaids --no-auth` - this command can return a simple AID list if it is enabled in the card settings

### How to look/dump files from the application file list
^[Top](#top)

`hf mfdes lsfiles --aid 123456 -t aes` - file list for application 123456 with aes key

`hf mfdes dump --aid 123456` - shows files and their contents from application 123456

### How to change key
^[Top](#top)

Changing key algorithm can be done only in one case - change card master key.

Key algorithm for application can be chosen only on its creation.

`hf mfdes changekey -t des --newalgo aes --newkey 11223344556677889900112233445566 --newver a5` - change picc master key from des default to aes

`hf mfdes changekey --aid 123456 -t des -n 0 -k 5555555555555555 --newkey 1122334455667788` - change application master key from one key to another

`hf mfdes changekey --aid 123456 -t des -n 0 --newkeyno 1 --oldkey 5555555555555555 --newkey 1122334455667788` - change key 1 with authentication with key 0 (app master key)

### How to create the application
^[Top](#top)

`hf mfdes createapp --aid 123456 --fid 2345 --dfname aid123456 --dstalgo aes` - create an application with ISO file ID, df name, and key algorithm AES

`hf mfdes createapp --aid 123456` - create an application 123456 with DES key algorithm and without ISO file ID. in this case, iso file id can't be provided for application's files

### How to create files
^[Top](#top)

`hf mfdes createfile --aid 123456 --fid 01 --isofid 0001 --size 000010` - create standard file with ISO ID and default access settings

`hf mfdes createfile --aid 123456 --fid 01 --isofid 0001 --size 000010 --backup` - create backup file

Create standard file with mac access mode and specified access settings. access settings can be changed later with command `hf mfdes chfilesettings`

`hf mfdes createfile --aid 123456 --fid 01 --isofid 0001 --size 000010 --amode mac --rrights free --wrights free --rwrights free --chrights key0`

`hf mfdes createvaluefile --aid 123456 --fid 01 --isofid 0001 --lower 00000010 --upper 00010000 --value 00000100` - create value file

`hf mfdes createrecordfile --aid 123456 --fid 01 --isofid 0001 --size 000010 --maxrecord 000010` - create linear record file

`hf mfdes createrecordfile --aid 123456 --fid 01 --isofid 0001 --size 000010 --maxrecord 000010 --cyclic` - create cyclic record file

`hf mfdes createmacfile --aid 123456 --fid 01 --rawrights 0FF0 --mackey 00112233445566778899aabbccddeeff --mackeyver 01` - create transaction mac file

### How to delete files
^[Top](#top)

`hf mfdes deletefile --aid 123456 --fid 01` - delete file

### How to read/write files
^[Top](#top)

*read:*

`hf mfdes read --aid 123456 --fid 01` - autodetect file type (with `hf mfdes getfilesettings`) and read its contents

`hf mfdes read --aid 123456 --fid 01 --type record --offset 000000 --length 000001` - read one last record from a record file

*read via ISO command set:*

Here it is needed to specify the type of the file because there is no `hf mfdes getfilesettings` in the ISO command set

`hf mfdes read --aid 123456 --fileisoid 1000 --type data -c iso` - select application via native command and then read file via ISO

`hf mfdes read --appisoid 0102 --fileisoid 1000 --type data -c iso` - select all via ISO commands and then read

`hf mfdes read --appisoid 0102 --fileisoid 1100 --type record -c iso --offset 000005 --length 000001` - read one record (number 5) from file ID 1100 via ISO command set

`hf mfdes read --appisoid 0102 --fileisoid 1100 --type record -c iso --offset 000005 --length 000000` - read all the records (from 5 to 1) from file ID 1100 via ISO command set

*write:*

`hf mfdes write --aid 123456 --fid 01 -d 01020304` - autodetect file type (with `hf mfdes getfilesettings`) and write data with offset 0

`hf mfdes write --aid 123456 --fid 01 --type data -d 01020304 --commit` - write backup data file and commit

`hf mfdes write --aid 123456 --fid 01 --type value -d 00000001` increment value file

`hf mfdes write --aid 123456 --fid 01 --type value -d 00000001 --debit` decrement value file

`hf mfdes write --aid 123456 --fid 01 --type record -d 01020304` write data to a record file

`hf mfdes write --aid 123456 --fid 01 --type record -d 01020304 --updaterec 0` update record 0 (latest) in the record file.

*write via iso command set:*

`hf mfdes write --appisoid 1234 --fileisoid 1000 --type data -c iso -d 01020304` write data to std/backup file via ISO command set

`hf mfdes write --appisoid 1234 --fileisoid 2000 --type record -c iso -d 01020304` send record to record file via ISO command set

*transactions:*

For more detailed samples look at the next howto.

`hf mfdes write --aid 123456 --fid 01 -d 01020304 --readerid 010203` write data to the file with CommitReaderID command before and CommitTransaction after write

### How to work with transaction mac
^[Top](#top)

There are two types of transactions with mac: with and without the CommitReaderID command. The type can be chosen by `hf mfdes createmacfile` command.

By default, the application works with transactions. All the write operations except write to standard file need to be committed by CommitTransaction command.

CommitTransaction command issued at the end of each write operation (except standard file).

Mac mode of transactions can be switched on by creating a mac file. There may be only one file with this file type for one application.

Command CommitReaderID enable/disable mode can be chosen at the creation of this file.

When CommitReaderID is enabled, it is needed to issue this command once per transaction. The transaction can't be committed without this command.

When the command is disabled - CommitReaderID returns an error.

*more info from MF2DL(H)x0 datasheet (link at the top of this document):*

10.3.2.1 Transaction MAC Counter (page 41)

10.3.2.5 Transaction MAC Reader ID and its encryption (page 43)

10.3.3 Transaction MAC Enabling (page 44)

10.3.4 Transaction MAC Calculation (page 45)

10.3.4.3 CommitReaderID Command (page 47)

*create mac file:*

`hf mfdes createmacfile --aid 123456 --fid 0f --rawrights 0FF0 --mackey 00112233445566778899aabbccddeeff --mackeyver 01` - create transaction mac file. CommitReaderID disabled

`hf mfdes createmacfile --aid 123456 --fid 0f --rawrights 0F10 --mackey 00112233445566778899aabbccddeeff --mackeyver 01` - create transaction mac file. CommitReaderID enabled with key 1

*read mac and transactions counter from mac file:*

`hf mfdes read --aid 123456 --fid 0f` - with type autodetect

*write to data file without CommitReaderID:*

`hf mfdes write --aid 123456 --fid 01 -d 01020304`

*write to data file with CommitReaderID:*

`hf mfdes write --aid 123456 --fid 01 -d 01020304 --readerid 010203`

*write to data file with CommitReaderID and decode previous reader ID:*

step 1. read mac file or read all the files to get transaction mac counter

`hf mfdes read --aid 123456 --fid 0f` - read mac file

`hf mfdes dump --aid 123456` - read all the files

step 2. write something to a file with CommitReaderID command and provide the key that was set by `hf mfdes createmacfile` command

`hf mfdes write --aid 123456 --fid 01 -d 01020304 --readerid 010203 --trkey 00112233445566778899aabbccddeeff`

### How to switch DESFire Light to LRP mode
^[Top](#top)

Remove failed authentication counters (if needs, but strongly recommended)

`hf mfdes setconfig --appisoid df01 -t aes -s ev2 --param 0a --data 00ffffffff`

or in the LRP mode

`hf mfdes setconfig --appisoid df01 -t aes -s lrp --param 0a --data 00ffffffff`

Switch LRP mode on

`hf mfdes setconfig --appisoid df01 -t aes -s ev2 --param 05 --data 00000000010000000000`


