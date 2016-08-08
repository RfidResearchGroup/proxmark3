# Change Log
All notable changes to this project will be documented in this file.
This project uses the changelog in accordance with [keepchangelog](http://keepachangelog.com/). Please use this to write notable changes, which is not the same as git commit log...

## [unreleased][unreleased]
  -  Added `hf mf key_brute` - adds J-Runs 2nd phase bruteforce ref: https://github.com/J-Run/mf_key_brute   (iceman)
  -  Added `lf jablotron` - adds demod/clone/sim of Jablotron LF tags. (iceman)
  -  Added `lf t55xx recoverpw` - adds a new password recovery using bitflips and partial flips if password write went bad. (alexgrin)
  - `hf legic` - added improved legic data mapping. (jason)
  - `hf mf mifare` - added possibility to target key A|B (douniwan5788)
  -  Added `analyse lcr` - added a new main command group,  to help analysing bytes & bits & nibbles. (iceman)
  -  Added `lf nedap` - added identification of a NEDAP tag. (iceman)
  - `lf viking clone` - fixed a bug. (iceman)
  -  Added bitsliced bruteforce solver in `hf mf hardnested` (Aczid)
  - `hf mf chk` speedup (iceman)
  - `hf 14a/mf sim x` attack mode,  now uses also moebius version of mfkey32 to try finding the key. (iceman)
  - `hf 14a sim` Added emulation of Mifare cards with 10byte UID length. (iceman)
  - `hf mf sim` Added emulation of Mifare cards with 10byte UID length. (iceman)
  -  Added `lf guard clone/sim` (iceman)
  -  Added `lf pyramd clone/sim` (iceman) 
  - trying to fix `hf 14b` command to be able to read CALYPSO card.	 (iceman)
  - `hf legic load`, it now loads faster and a casting bug is gone. (iceman)
  -  Added `hf legic calccrc8` added a method to calculate the legic crc-8 value (iceman)
  - `hf legic decode` fixed the output overflow bugs, better printing (iceman)
  - Coverity Scan fixes a lot of resource leaks, etc (iceman)
  -  Added `lf presco *` commands started (iceman) 
  -  Added `lf hid wiegand` added a method to calculate WIEGAND in different formats, (iceman)
  - `hf mf chkkeys` better printing, same table output as nested, faster execution and added Adam Lauries "try to read Key B if Key A is found" (iceman)
  - `hf mf nested` better printing and added Adam Lauries "try to read Key B if Key A is found" (iceman)
  - `hf mf mifare` fixing the zero parity path, which doesn't got called. (iceman) 
  - Updated the @blapost's Crapto1 implementation to v3.3 (blapost) 
  - `hf mf c*` updated the calling structure and refactored of the chinese magic commands (iceman, marshmellow)
  - Started to add Peter Fillmore's  EMV fork into Iceman fork. ref: https://github.com/peterfillmore/proxmark3  (peter fillmore,  iceman)
  - Added Travis-CI automatic build integration with GitHub fork. (iceman)
  - Updated the Reveng 1.30 sourcecode to 1.31 from Reveng project homepage (iceman)
  - Updated the Reveng 1.31 sourcecode to 1.40 from Reveng project homepage (iceman)
  
  - Added possibility to write direct to a Legic Prime Tag (MIM256/1024) without using values from the 'BigBuffer' -> 'hf legic writeRaw <addr> <value>' (icsom)
  - Added possibility to decrease DCF values at address 0x05 & 0x06 on a Legic Prime Tag 
		DCF-value will be pulled from the BigBuffer (address 0x05 & 0x06) so you have to 
		load the data into the BigBuffer before with 'hf legic load <path/to/legic.dump>' & then
		write the DCF-Values (both at once) with 'hf legic write 0x05 0x02'  (icsom)
  - Added script `legic.lua` for display and edit Data of Legic-Prime Tags (icsom)
  - Added the experimental HITAG_S support (spenneb)
  - Added topaz detection to `hf search` (iceman)
  - Fixed the silent mode for 14b to be used inside `hf search` (iceman)
  
### Added
- Added a LF ASK Sequence Terminator detection option to the standard ask demod - and applied it to `lf search u`, `lf t55xx detect`, and `data rawdemod am s` (marshmellow)
- `lf awid bruteforce <facilitycode>` - Simple bruteforce attack against a AWID reader.
- `lf t55xx bruteforce <start password> <end password> [i <*.dic>]` - Simple bruteforce attack to find password - (iceman and others)
- `lf viking clone`- clone viking tag to t55x7 or Q5 from 4byte hex ID input 
- `lf viking sim`  - sim full viking tag from 4byte hex ID input
- `lf viking read` - read viking tag and output ID
- `lf t55xx wipe`  - sets t55xx back to factory defaults
- Added viking demod to `lf search` (marshmellow)
- `data askvikingdemod` demod viking id tag from graphbuffer (marshmellow)
- `lf t55xx resetread` added reset then read command - should allow determining start of stream transmissions (marshmellow)
- `lf t55xx wakeup` added wake with password (AOR) to allow lf search or standard lf read after (iceman, marshmellow)
- `hf mf eload u` added an ultralight/ntag option. (marshmellow)
- `hf iclass managekeys` to save, load and manage iclass keys.  (adjusted most commands to accept a loaded key in memory) (marshmellow)
- `hf iclass readblk` to select, authenticate, and read 1 block from an iclass card (marshmellow)
- `hf iclass writeblk` to select, authenticate, and write 1 block to an iclass card (or picopass) (marshmellow + others)
- `hf iclass clone` to take a saved dump file and clone selected blocks to a new tag (marshmellow + others)
- `hf iclass calcnewkey` - to calculate the div_key change to change a key - (experimental) (marshmellow + others)
- `hf iclass encryptblk` - to encrypt a data block hex to prep for writing that block (marshmellow)
- ISO14443a stand-alone operation with ARM CFLAG="WITH_ISO14443a_StandAlone". This code can read & emulate two banks of 14a tag UIDs and write to "magic" cards  (Craig Young) 
- AWID26 command context added as 'lf awid' containing realtime demodulation as well as cloning/simulation based on tag numbers (Craig Young)
- Added 'hw status'. This command makes the ARM print out some runtime information. (holiman) 
- Added 'hw ping'. This command just sends a usb packets and checks if the pm3 is responsive. Can be used to abort certain operations which supports abort over usb. (holiman)
- Added `data hex2bin` and `data bin2hex` for command line conversion between binary and hexadecimal (holiman)
- Added 'hf snoop'. This command take digitalized signal from FPGA and put in BigBuffer. (pwpiwi + enio)
- Added Topaz (NFC type 1) protocol support ('hf topaz reader', 'hf list topaz', 'hf 14a raw -T', 'hf topaz snoop'). (piwi)
- Added option c to 'hf list' (mark CRC bytes) (piwi)

### Changed																		
- Added `[l] <length>` option to data printdemodbuffer
- Adjusted lf awid clone to optionally clone to Q5 tags
- Adjusted lf t55xx detect to find Q5 tags (t5555) instead of just t55x7
- Adjusted all lf NRZ demods - works more accurately and consistently (as long as you have strong signal)
- Adjusted lf pskindalademod to reduce false positive reads.
- Small adjustments to psk, nrz, and ask clock detect routines - more reliable.
- Adjusted lf em410x em410xsim to accept a clock argument
- Adjusted lf t55xx dump to allow overriding the safety check and warning text (marshmellow)
- Adjusted lf t55xx write input variables (marshmellow)
- Adjusted lf t55xx read with password safety check and warning text and adjusted the input variables (marshmellow & iceman)
- Adjusted LF FSK demod to account for cross threshold fluctuations (898 count waves will adjust the 9 to 8 now...) more accurate.
- Adjusted timings for t55xx commands.  more reliable now. (marshmellow & iceman)
- `lf cmdread` adjusted input methods and added help text (marshmellow & iceman)
- changed `lf config t <threshold>` to be 0 - 128 and will trigger on + or - threshold value (marshmellow) 
- `hf iclass dump` cli options - can now dump AA1 and AA2 with different keys in one run (does not go to multiple pages for the larger tags yet)
- Revised workflow for StandAloneMode14a (Craig Young)
- EPA functions (`hf epa`) now support both ISO 14443-A and 14443-B cards (frederikmoellers)
- 'hw version' only talks to ARM at startup, after that the info is cached. (pwpiwi)
- Added `r` option to iclass functions - allows key to be provided in raw block 3/4 format 

## [2.2.0][2015-07-12]

### Changed
- Added `hf 14b raw -s` option to auto select a 14b std tag before raw command 
- Changed `hf 14b write` to `hf 14b sriwrite` as it only applied to sri tags (marshmellow)
- Added `hf 14b info` to `hf search` (marshmellow)
- Added compression of fpga config and data, *BOOTROM REFLASH REQUIRED* (piwi)
- Implemented better detection of mifare-tags that are not vulnerable to classic attacks (`hf mf mifare`, `hf mf nested`) (piwi)

### Added
- Add `hf 14b reader` to find and print general info about known 14b tags (marshmellow)
- Add `hf 14b info` to find and print info about std 14b tags and sri tags (using 14b raw commands in the client)  (marshmellow)
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


