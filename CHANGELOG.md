# Change Log
All notable changes to this project will be documented in this file.
This project uses the changelog in accordance with [keepchangelog](http://keepachangelog.com/). Please use this to write notable changes, which is not the same as git commit log...

## [Unreleased][unreleased]
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

### Added
- Added `hf search` - currently tests for 14443a tags, iclass tags, and 15693 tags (marshmellow) 
- Added `hf mfu info` Ultralight/NTAG info command - reads tag configuration and info, allows authentication if needed (iceman1001, marshmellow)
- Added Mifare Ultralight C and Ultralight EV1/NTAG authentication. (iceman1001)
- Added changelog

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


