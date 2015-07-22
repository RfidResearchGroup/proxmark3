# Change Log
All notable changes to this project will be documented in this file.
This project uses the changelog in accordance with [keepchangelog](http://keepachangelog.com/). Please use this to write notable changes, which is not the same as git commit log...

## [unreleased][unreleased]

### Added
- ISO14443a stand-alone operation with ARM CFLAG="WITH_ISO14443a_StandAlone". This code can read & emulate two banks of 14a tag UIDs and write to "magic" cards  (Craig Young) 
- AWID26 command context added as 'lf awid' containing realtime demodulation as well as cloning/simulation based on tag numbers (Craig Young)
- Added 'hw status'. This command makes the ARM print out some runtime information. (holiman) 
- Added 'hw ping'. This command just sends a usb packets and checks if the pm3 is responsive. Can be used to abort certain operations which supports abort over usb. (holiman)

### Changed
- Changed lf config's `threshold` to a graph (signed) metric and it will trigger on + or - value set to. (example: set to 50 and recording would begin at first graphed value of >= 50 or <= -50) (marshmellow)
- EPA functions (`hf epa`) now support both ISO 14443-A and 14443-B cards (frederikmoellers)
- 'hw version' only talks to ARM at startup, after that the info is cached. (pwpiwi)

## [2.2.0][2015-07-12]

### Changed
- Added `hf 14b raw -s` option to auto select a 14b std tag before raw command 
- Changed `hf 14b write` to `hf 14b sriwrite` as it only applied to sri tags (marshmellow)
- Added `hf 14b info` to `hf search` (marshmellow)
- Added compression of fpga config and data, *BOOTROM REFLASH REQUIRED* (piwi)
- Implemented better detection of mifare-tags that are not vulnerable to classic attacks (`hf mf mifare`, `hf mf nested`) (piwi)


### Added
- Add `hf 14b reader` to find and print general info about known 14b tags (marshmellow)
- Add `hf 14b info` to find and print full info about std 14b tags and sri tags (using 14b raw commands in the client)  (marshmellow)
- Add PACE replay functionality (frederikmoellers)

### Fixed 
- t55xx write timing (marshmellow)


## [2.1.0][2015-06-23]

### Changed
- Added ultralight/ntag tag type detection to `hf 14a read` (marshmellow)
- Improved ultralight dump command to auto detect tag type, take authentication, and dump full memory (or subset specified) of known tag types (iceman1001 / marshmellow)
- Combined ultralight read/write commands and added authentication (iceman1001)
- Improved LF manchester and biphase demodulation and ask clock detection especially for reads with heavy clipping. (marshmellow)
- Iclass read, `hf iclass read` now also reads tag config and prints configuration. (holiman)
- *bootrom* needs to be flashed, due to new address boundaries between os and fpga, after a size optimization (piwi)

### Fixed
- Fixed EM4x50 read/demod of the tags broadcasted memory blocks. 'lf em4x em4x50read' (not page read) (marshmellow)
- Fixed issue #19, problems with LF T55xx commands (iceman1001, marshmellow)
- Fixed various problems with iso14443b, issue #103 (piwi, marshmellow)

### Added
- Added `hf search` - currently tests for 14443a tags, iclass tags, and 15693 tags (marshmellow) 
- Added `hf mfu info` Ultralight/NTAG info command - reads tag configuration and info, allows authentication if needed (iceman1001, marshmellow)
- Added Mifare Ultralight C and Ultralight EV1/NTAG authentication. (iceman1001)
- Added changelog			 
- Added `data fdxbdemod` - Demodulate a FDX-B ISO11784/85 Biphase tag from GraphBuffer aka ANIMAL TAG (marshmellow, iceman1001)

## [2.0.0] - 2015-03-25
### Changed
- LF sim operations now abort when new commands arrive over the USB - not required to push the device button anymore.

### Fixed
- Mifare simulation, `hf mf sim` (was broken a long time) (pwpiwi)
- Major improvements in LF area and data operations. (marshmellow, iceman1001)
- Issues regarding LF simulation (pwpiwi)

### Added
- iClass functionality: full simulation of iclass tags, so tags can be simulated with data (not only CSN). Not yet support for write/update, but readers don't seem to enforce update. (holiman).
- iClass decryption. Proxmark can now decrypt data on an iclass tag, but requires you to have the HID decryption key locally on your computer, as this is not bundled with the sourcecode. 


