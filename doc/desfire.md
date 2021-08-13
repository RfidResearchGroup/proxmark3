# Desfire card

## Documentation
[Desfire Light datasheet MF2DLHX0](https://www.nxp.com/docs/en/data-sheet/MF2DLHX0.pdf)
[Features and Hints AN12343](https://www.nxp.com/docs/en/application-note/AN12343.pdf)
[Quick Start Guide AN12341](https://www.nxp.com/docs/en/application-note/AN12341.pdf)
[LRP Specification](https://www.nxp.com/docs/en/application-note/AN12304.pdf)
[NTAG 424 DNA NT4H2421Gx](https://www.nxp.com/docs/en/data-sheet/NT4H2421Gx.pdf)
[NTAG features and hints - LRP mode](https://www.nxp.com/docs/en/application-note/AN12321.pdf)
[ev2 samples AN12196](https://www.nxp.com/docs/en/application-note/AN12196.pdf)
[MIFARE Application Directory AN10787](https://www.nxp.com/docs/en/application-note/AN10787.pdf)
[Symmetric key diversifications AN10922](https://www.nxp.com/docs/en/application-note/AN10922.pdf)

## Source code
[desfire_crypto from proxmark3](https://github.com/RfidResearchGroup/proxmark3/blob/master/armsrc/desfire_crypto.c)
[libfreefare](https://github.com/nfc-tools/libfreefare)
[desfire-tools-for-android](https://github.com/skjolber/desfire-tools-for-android)
[nfcjlib](https://github.com/andrade/nfcjlib/)
[java-card-desfire-emulation](https://github.com/gathigai/java-card-desfire-emulation)
[ChameleonMiniDESFireStack](https://github.com/maxieds/ChameleonMiniDESFireStack/)
[LRP/ev2 nfc-ev2-crypto](https://github.com/icedevml/nfc-ev2-crypto)

## Communication channel with a card:
The card can work in the combination of: key type - command set - secure channel - communication mode

*key types*
**des** - 8 bytes key. can be present in a form of **2tdea** key with length 16 bytes by duplicate contents twice.
**2tdea** - 16 bytes key
**3tdea** - 24 bytes key. can be disabled on the card level.
**aes** - 16 bytes aes-128 key

*command sets:*
**native** - raw commands
**native iso** - wrap raw commands into the iso apdu. **CLA** = 0x90, **INS** = command code, **data** = the rest data from raw command
**iso** - work only several commands: iso select by iso id (if enabled), authenticate, read and write in the **plain** mode, read in the **mac** mode

*secure channels:*
**d40** - old secure channel that can work only with **des** and **2tdea** keys
**ev1** - secure channel that can work with all the keys: **des**, **2tdea**, **3tdea**, **aes**
**ev2** - the newest channel that can work with **aes** key only

*communication modes* 
**plain** - just plain data between card and reader
**maced** - mac applied to reqest/response/both (may be sent and may be not)
**encrypted** - encrypted data in the reqest/response/both. in the ev2 channel data signed with mac.

## Card architecture

Card has several applications on it and the application have files and some other objects
Each card has a master application with AID 0x000000 that saves card's configuration.
Master application has many keys with different purposes, but commands show that there is only one key - card master key.
Each application may have its own key type and set of keys. Each file can only have links to these keys in its access rights.

## Card structure:

- Application
- Application number: 1 byte
- Application ISO number: if set at the time of application creation. It can be selected by this id in the iso command set.
- Application DF name: 1-16 chars. It can be selected by this name in the iso command set.
- Key settings: number of keys, key type, key config (what can do/not user with keys)
- Keys: up to 14 keys (indexes 0..d)
- Key versions: key version of corresponded key
- Files:
  - File number: 1 byte
  - File iso number: should be if application created with iso number and should not be if there is no iso number at the application level.
  - File type: standard, backup, value, cyclic record, linear record, transaction mac
  - Some settings that belonged to file type (size for standard file at sample)
  - File communication mode: plain/maced/encrypted
  - File access right: there is 4 modes: read/write/read-write/change settings. And each mode access can be: key0..keyD, E - free access, F - deny access

## How to

### How to get card UID
The card can return UID in encrypted communication mode. Needs to authenticate with any key from the card.
`hf mfdes getuid` - authenticate with default key
`hf mfdes getuid -s d40` - via d40 secure channel
`hf mfdes getuid -s ev2 -t aes -k 11223344556677889900112233445566` - via ev2 secure channel with specified aes key

### How to get/set default communication channel settings
All the commands use these settings by default if a more important setting is not specified in the command line.
`hf mfdes default` - get channel settings
`hf mfdes default -n 1 -t aes` - set key number 1 and key type aes

### How to guess default communication channel settings
`hf mfdes detect` - simply detect key for master application (PICC level)
`hf mfdes detect --save` - detect key and save to defaults. look after to output of `hf mfdes default`
`hf mfdes detect -s d40` - detect via channel d40
`hf mfdes detect --dict mfdes_default_keys` - detect key with help of dictionary file
`hf mfdes detect --aid 123456 -n 2` - detect key 2 from application with AID 123456

### How to try communication channel settings
`hf mfdes auth -n 0 -t des -k 1122334455667788 --aid 123456` - try application 123456 master key 
`hf mfdes auth -n 0 -t aes --save` - try PICC AES master key and save the configuration to defaults if authentication succeeds

### How to look at the application list on the card
`hf mfdes lsapp --no-auth` - show applications list without authentication
`hf mfdes lsapp` - show applications list with authentication from default settings
`hf mfdes lsapp --files` - show applications list with their files
`hf mfdes getaids --no-auth` - this command can return a simple aid list if it is enabled in the card settings

### How to look/dump files from the application file list
`hf mfdes lsfiles --aid 123456 -t aes` - file list for application 123456 with aes key
`hf mfdes dump --aid 123456` - shows files and their contents from application 123456

### How to create the application
`hf mfdes createapp --aid 123456 --fid 2345 --dfname aid123456 --dstalgo aes` - create an application with iso file id, df name, and key algorithm AES
`hf mfdes createapp --aid 123456` - create an application 123456 with DES key algorithm and without iso file id. in this case, iso file id can't be provided for application's files

### How to create files

### How to read/write files

### How to work with transactions

