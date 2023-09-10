
# Proxmark3 command dump


Some commands are available only if a Proxmark3 is actually connected.  

Check column "offline" for their availability.



|command                  |offline |description
|-------                  |------- |-----------
|`help                   `|Y       |`Use `<command> help` for details of a command`
|`auto                   `|N       |`Automated detection process for unknown tags`
|`clear                  `|Y       |`Clear screen`
|`hints                  `|Y       |`Turn hints on / off`
|`msleep                 `|Y       |`Add a pause in milliseconds`
|`rem                    `|Y       |`Add a text line in log file`
|`quit                   `|Y       |``
|`exit                   `|Y       |`Exit program`


### prefs

 { Edit client/device preferences... }

|command                  |offline |description
|-------                  |------- |-----------
|`prefs help             `|Y       |`This help`
|`prefs show             `|Y       |`Show all preferences`


### prefs get

 { Get a preference }

|command                  |offline |description
|-------                  |------- |-----------
|`prefs get barmode      `|Y       |`Get bar mode preference`
|`prefs get clientdebug  `|Y       |`Get client debug level preference`
|`prefs get clientdelay  `|Y       |`Get client execution delay preference`
|`prefs get color        `|Y       |`Get color support preference`
|`prefs get savepaths    `|Y       |`Get file folder  `
|`prefs get emoji        `|Y       |`Get emoji display preference`
|`prefs get hints        `|Y       |`Get hint display preference`
|`prefs get output       `|Y       |`Get dump output style preference`
|`prefs get plotsliders  `|Y       |`Get plot slider display preference`


### prefs set

 { Set a preference }

|command                  |offline |description
|-------                  |------- |-----------
|`prefs set help         `|Y       |`This help`
|`prefs set barmode      `|Y       |`Set bar mode`
|`prefs set clientdebug  `|Y       |`Set client debug level`
|`prefs set clientdelay  `|Y       |`Set client execution delay`
|`prefs set color        `|Y       |`Set color support`
|`prefs set emoji        `|Y       |`Set emoji display`
|`prefs set hints        `|Y       |`Set hint display`
|`prefs set savepaths    `|Y       |`... to be adjusted next ... `
|`prefs set output       `|Y       |`Set dump output style`
|`prefs set plotsliders  `|Y       |`Set plot slider display`


### analyse

 { Analyse utils... }

|command                  |offline |description
|-------                  |------- |-----------
|`analyse help           `|Y       |`This help`
|`analyse lcr            `|Y       |`Generate final byte for XOR LRC`
|`analyse crc            `|Y       |`Stub method for CRC evaluations`
|`analyse chksum         `|Y       |`Checksum with adding, masking and one's complement`
|`analyse dates          `|Y       |`Look for datestamps in a given array of bytes`
|`analyse lfsr           `|Y       |`LFSR tests`
|`analyse a              `|Y       |`num bits test`
|`analyse nuid           `|Y       |`create NUID from 7byte UID`
|`analyse demodbuff      `|Y       |`Load binary string to DemodBuffer`
|`analyse freq           `|Y       |`Calc wave lengths`
|`analyse foo            `|Y       |`muxer`
|`analyse units          `|Y       |`convert ETU <> US <> SSP_CLK (3.39MHz)`


### data

 { Plot window / data buffer manipulation... }

|command                  |offline |description
|-------                  |------- |-----------
|`data help              `|Y       |`This help`
|`data biphaserawdecode  `|Y       |`Biphase decode bin stream in DemodBuffer`
|`data detectclock       `|Y       |`Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer`
|`data fsktonrz          `|Y       |`Convert fsk2 to nrz wave for alternate fsk demodulating (for weak fsk)`
|`data manrawdecode      `|Y       |`Manchester decode binary stream in DemodBuffer`
|`data modulation        `|Y       |`Identify LF signal for clock and modulation`
|`data rawdemod          `|Y       |`Demodulate the data in the GraphBuffer and output binary`
|`data askedgedetect     `|Y       |`Adjust Graph for manual ASK demod`
|`data autocorr          `|Y       |`Autocorrelation over window`
|`data dirthreshold      `|Y       |`Max rising higher up-thres/ Min falling lower down-thres`
|`data decimate          `|Y       |`Decimate samples`
|`data envelope          `|Y       |`Generate square envelope of samples`
|`data undecimate        `|Y       |`Un-decimate samples`
|`data hide              `|Y       |`Hide graph window`
|`data hpf               `|Y       |`Remove DC offset from trace`
|`data iir               `|Y       |`Apply IIR buttersworth filter on plot data`
|`data grid              `|Y       |`overlay grid on graph window`
|`data ltrim             `|Y       |`Trim samples from left of trace`
|`data mtrim             `|Y       |`Trim out samples from the specified start to the specified stop`
|`data norm              `|Y       |`Normalize max/min to +/-128`
|`data plot              `|Y       |`Show graph window`
|`data cthreshold        `|Y       |`Average out all values between`
|`data rtrim             `|Y       |`Trim samples from right of trace`
|`data setgraphmarkers   `|Y       |`Set blue and orange marker in graph window`
|`data shiftgraphzero    `|Y       |`Shift 0 for Graphed wave + or - shift value`
|`data timescale         `|Y       |`Set cursor display timescale`
|`data zerocrossings     `|Y       |`Count time between zero-crossings`
|`data convertbitstream  `|Y       |`Convert GraphBuffer's 0/1 values to 127 / -127`
|`data getbitstream      `|Y       |`Convert GraphBuffer's >=1 values to 1 and <1 to 0`
|`data asn1              `|Y       |`ASN1 decoder`
|`data atr               `|Y       |`ATR lookup`
|`data bin2hex           `|Y       |`Converts binary to hexadecimal`
|`data bitsamples        `|N       |`Get raw samples as bitstring`
|`data clear             `|Y       |`Clears bigbuf on deviceside and graph window`
|`data diff              `|Y       |`Diff of input files`
|`data hexsamples        `|N       |`Dump big buffer as hex bytes`
|`data hex2bin           `|Y       |`Converts hexadecimal to binary`
|`data load              `|Y       |`Load contents of file into graph window`
|`data num               `|Y       |`Converts dec/hex/bin`
|`data print             `|Y       |`Print the data in the DemodBuffer`
|`data samples           `|N       |`Get raw samples for graph window (GraphBuffer)`
|`data save              `|Y       |`Save signal trace data  (from graph window)`
|`data setdebugmode      `|Y       |`Set Debugging Level on client side`
|`data tune              `|N       |`Measure tuning of device antenna. Results shown in graph window`


### emv

 { EMV ISO-14443 / ISO-7816... }

|command                  |offline |description
|-------                  |------- |-----------
|`emv help               `|Y       |`This help`
|`emv list               `|Y       |`List ISO7816 history`
|`emv test               `|Y       |`Crypto logic test`
|`emv challenge          `|N       |`Generate challenge`
|`emv exec               `|N       |`Executes EMV contactless transaction`
|`emv genac              `|N       |`Generate ApplicationCryptogram`
|`emv gpo                `|N       |`Execute GetProcessingOptions`
|`emv intauth            `|N       |`Internal authentication`
|`emv pse                `|N       |`Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory`
|`emv reader             `|N       |`Act like an EMV reader`
|`emv readrec            `|N       |`Read files from card`
|`emv roca               `|N       |`Extract public keys and run ROCA test`
|`emv scan               `|N       |`Scan EMV card and save it contents to json file for emulator`
|`emv search             `|N       |`Try to select all applets from applets list and print installed applets`
|`emv select             `|N       |`Select applet`


### hf

 { High frequency commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`hf help                `|Y       |`This help`
|`hf list                `|Y       |`List protocol data in trace buffer`
|`hf plot                `|N       |`Plot signal`
|`hf tune                `|N       |`Continuously measure HF antenna tuning`
|`hf search              `|Y       |`Search for known HF tags`
|`hf sniff               `|N       |`Generic HF Sniff`


### hf 14a

 { ISO14443A RFIDs...                  }

|command                  |offline |description
|-------                  |------- |-----------
|`hf 14a help            `|Y       |`This help`
|`hf 14a list            `|Y       |`List ISO 14443-a history`
|`hf 14a antifuzz        `|N       |`Fuzzing the anticollision phase.  Warning! Readers may react strange`
|`hf 14a config          `|N       |`Configure 14a settings (use with caution)`
|`hf 14a cuids           `|N       |`Collect n>0 ISO14443-a UIDs in one go`
|`hf 14a info            `|N       |`Tag information`
|`hf 14a sim             `|N       |`Simulate ISO 14443-a tag`
|`hf 14a sniff           `|N       |`sniff ISO 14443-a traffic`
|`hf 14a raw             `|N       |`Send raw hex data to tag`
|`hf 14a reader          `|N       |`Act like an ISO14443-a reader`
|`hf 14a apdu            `|N       |`Send ISO 14443-4 APDU to tag`
|`hf 14a apdufind        `|N       |`Enumerate APDUs - CLA/INS/P1P2`
|`hf 14a chaining        `|N       |`Control ISO 14443-4 input chaining`
|`hf 14a ndefformat      `|N       |`Format ISO 14443-A as NFC Type 4 tag`
|`hf 14a ndefread        `|N       |`Read an NDEF file from ISO 14443-A Type 4 tag`
|`hf 14a ndefwrite       `|N       |`Write NDEF records to ISO 14443-A tag`


### hf 14b

 { ISO14443B RFIDs...                  }

|command                  |offline |description
|-------                  |------- |-----------
|`hf 14b help            `|Y       |`This help`
|`hf 14b apdu            `|N       |`Send ISO 14443-4 APDU to tag`
|`hf 14b dump            `|N       |`Read all memory pages of an ISO-14443-B tag, save to file`
|`hf 14b info            `|N       |`Tag information`
|`hf 14b list            `|Y       |`List ISO-14443-B history`
|`hf 14b ndefread        `|N       |`Read NDEF file on tag`
|`hf 14b raw             `|N       |`Send raw hex data to tag`
|`hf 14b reader          `|N       |`Act as a ISO-14443-B reader to identify a tag`
|`hf 14b sim             `|N       |`Fake ISO ISO-14443-B tag`
|`hf 14b sniff           `|N       |`Eavesdrop ISO-14443-B`
|`hf 14b rdbl            `|N       |`Read SRI512/SRIX4x block`
|`hf 14b sriwrite        `|N       |`Write data to a SRI512 or SRIX4K tag`
|`hf 14b view            `|Y       |`Display content from tag dump file`


### hf 15

 { ISO15693 RFIDs...                   }

|command                  |offline |description
|-------                  |------- |-----------
|`hf 15 help             `|Y       |`This help`
|`hf 15 list             `|Y       |`List ISO-15693 history`
|`hf 15 demod            `|Y       |`Demodulate ISO-15693 from tag`
|`hf 15 dump             `|N       |`Read all memory pages of an ISO-15693 tag, save to file`
|`hf 15 info             `|N       |`Tag information`
|`hf 15 sniff            `|N       |`Sniff ISO-15693 traffic`
|`hf 15 raw              `|N       |`Send raw hex data to tag`
|`hf 15 rdbl             `|N       |`Read a block`
|`hf 15 rdmulti          `|N       |`Reads multiple blocks`
|`hf 15 reader           `|N       |`Act like an ISO-15693 reader`
|`hf 15 restore          `|N       |`Restore from file to all memory pages of an ISO-15693 tag`
|`hf 15 samples          `|N       |`Acquire samples as reader (enables carrier, sends inquiry)`
|`hf 15 view             `|Y       |`Display content from tag dump file`
|`hf 15 wrbl             `|N       |`Write a block`
|`hf 15 sim              `|N       |`Fake an ISO-15693 tag`
|`hf 15 eload            `|N       |`Load image file into emulator to be used by 'sim' command`
|`hf 15 esave            `|N       |`Save emulator memory into image file`
|`hf 15 eview            `|N       |`View emulator memory`
|`hf 15 slixwritepwd     `|N       |`Writes a password on a SLIX ISO-15693 tag`
|`hf 15 slixeasdisable   `|N       |`Disable EAS mode on SLIX ISO-15693 tag`
|`hf 15 slixeasenable    `|N       |`Enable EAS mode on SLIX ISO-15693 tag`
|`hf 15 slixprivacydisable`|N       |`Disable privacy mode on SLIX ISO-15693 tag`
|`hf 15 slixprivacyenable`|N       |`Enable privacy mode on SLIX ISO-15693 tag`
|`hf 15 passprotectafi   `|N       |`Password protect AFI - Cannot be undone`
|`hf 15 passprotecteas   `|N       |`Password protect EAS - Cannot be undone`
|`hf 15 findafi          `|N       |`Brute force AFI of an ISO-15693 tag`
|`hf 15 writeafi         `|N       |`Writes the AFI on an ISO-15693 tag`
|`hf 15 writedsfid       `|N       |`Writes the DSFID on an ISO-15693 tag`
|`hf 15 csetuid          `|N       |`Set UID for magic card`


### hf cipurse

 { Cipurse transport Cards...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf cipurse help        `|Y       |`This help.`
|`hf cipurse info        `|N       |`Get info about CIPURSE tag`
|`hf cipurse select      `|N       |`Select CIPURSE application or file`
|`hf cipurse auth        `|N       |`Authenticate CIPURSE tag`
|`hf cipurse read        `|N       |`Read binary file`
|`hf cipurse write       `|N       |`Write binary file`
|`hf cipurse aread       `|N       |`Read file attributes`
|`hf cipurse awrite      `|N       |`Write file attributes`
|`hf cipurse formatall   `|N       |`Erase all the data from chip`
|`hf cipurse create      `|N       |`Create file, application, key via DGI record`
|`hf cipurse delete      `|N       |`Delete file`
|`hf cipurse updkey      `|N       |`Update key`
|`hf cipurse updakey     `|N       |`Update key attributes`
|`hf cipurse default     `|N       |`Set default key and file id for all the other commands`
|`hf cipurse test        `|Y       |`Regression tests`


### hf epa

 { German Identification Card...       }

|command                  |offline |description
|-------                  |------- |-----------
|`hf epa help            `|Y       |`This help`
|`hf epa cnonces         `|N       |`Acquire encrypted PACE nonces of specific size`
|`hf epa replay          `|N       |`Perform PACE protocol by replaying given APDUs`
|`hf epa sim             `|N       |`Simulate PACE protocol`


### hf emrtd

 { Machine Readable Travel Document... }

|command                  |offline |description
|-------                  |------- |-----------
|`hf emrtd help          `|Y       |`This help`
|`hf emrtd dump          `|N       |`Dump eMRTD files to binary files`
|`hf emrtd info          `|Y       |`Display info about an eMRTD`
|`hf emrtd list          `|Y       |`List ISO 14443A/7816 history`


### hf felica

 { ISO18092 / FeliCa RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf felica help         `|Y       |`This help`
|`hf felica list         `|Y       |`List ISO 18092/FeliCa history`
|`hf felica reader       `|N       |`Act like an ISO18092/FeliCa reader`
|`hf felica info         `|N       |`Tag information`
|`hf felica sniff        `|N       |`Sniff ISO 18092/FeliCa traffic`
|`hf felica raw          `|N       |`Send raw hex data to tag`
|`hf felica rdbl         `|N       |`read block data from authentication-not-required Service.`
|`hf felica wrbl         `|N       |`write block data to an authentication-not-required Service.`
|`hf felica rqservice    `|N       |`verify the existence of Area and Service, and to acquire Key Version.`
|`hf felica rqresponse   `|N       |`verify the existence of a card and its Mode.`
|`hf felica scsvcode     `|N       |`acquire Area Code and Service Code.`
|`hf felica rqsyscode    `|N       |`acquire System Code registered to the card.`
|`hf felica auth1        `|N       |`authenticate a card. Start mutual authentication with Auth1`
|`hf felica auth2        `|N       |`allow a card to authenticate a Reader/Writer. Complete mutual authentication`
|`hf felica rqspecver    `|N       |`acquire the version of card OS.`
|`hf felica resetmode    `|N       |`reset Mode to Mode 0.`
|`hf felica litesim      `|N       |`Emulating ISO/18092 FeliCa Lite tag`
|`hf felica litedump     `|N       |`Wait for and try dumping FelicaLite`


### hf fido

 { FIDO and FIDO2 authenticators...    }

|command                  |offline |description
|-------                  |------- |-----------
|`hf fido help           `|Y       |`This help.`
|`hf fido list           `|Y       |`List ISO 14443A history`
|`hf fido info           `|N       |`Info about FIDO tag.`
|`hf fido reg            `|N       |`FIDO U2F Registration Message.`
|`hf fido auth           `|N       |`FIDO U2F Authentication Message.`
|`hf fido make           `|N       |`FIDO2 MakeCredential command.`
|`hf fido assert         `|N       |`FIDO2 GetAssertion command.`


### hf fudan

 { Fudan RFIDs...                      }

|command                  |offline |description
|-------                  |------- |-----------
|`hf fudan help          `|Y       |`This help`
|`hf fudan reader        `|N       |`Act like a fudan reader`
|`hf fudan dump          `|N       |`Dump FUDAN tag to binary file`
|`hf fudan rdbl          `|N       |`Read a fudan tag`
|`hf fudan view          `|Y       |`Display content from tag dump file`
|`hf fudan wrbl          `|N       |`Write a fudan tag`


### hf gallagher

 { Gallagher DESFire RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf gallagher help      `|Y       |`This help`
|`hf gallagher reader    `|N       |`Read & decode all Gallagher credentials on a DESFire card`
|`hf gallagher clone     `|N       |`Add Gallagher credentials to a DESFire card`
|`hf gallagher delete    `|N       |`Delete Gallagher credentials from a DESFire card`
|`hf gallagher diversifykey`|Y       |`Diversify Gallagher key`
|`hf gallagher decode    `|Y       |`Decode Gallagher credential block`


### hf ksx6924

 { KS X 6924 (T-Money, Snapper+) RFIDs }

|command                  |offline |description
|-------                  |------- |-----------
|`hf ksx6924 help        `|Y       |`This help`
|`hf ksx6924 select      `|N       |`Select application, and leave field up`
|`hf ksx6924 info        `|N       |`Get info about a KS X 6924 (T-Money, Snapper+) transit card`
|`hf ksx6924 balance     `|N       |`Get current purse balance`
|`hf ksx6924 init        `|N       |`Perform transaction initialization with Mpda`
|`hf ksx6924 prec        `|N       |`Send proprietary get record command (CLA=90, INS=4C)`


### hf jooki

 { Jooki RFIDs...                      }

|command                  |offline |description
|-------                  |------- |-----------
|`hf jooki help          `|Y       |`This help`
|`hf jooki clone         `|N       |`Write a Jooki token`
|`hf jooki decode        `|Y       |`Decode Jooki token`
|`hf jooki encode        `|Y       |`Encode Jooki token`
|`hf jooki sim           `|N       |`Simulate Jooki token`


### hf iclass

 { ICLASS RFIDs...                     }

|command                  |offline |description
|-------                  |------- |-----------
|`hf iclass help         `|Y       |`This help`
|`hf iclass list         `|Y       |`List iclass history`
|`hf iclass dump         `|N       |`Dump Picopass / iCLASS tag to file`
|`hf iclass info         `|Y       |`Tag information`
|`hf iclass rdbl         `|N       |`Read Picopass / iCLASS block`
|`hf iclass reader       `|N       |`Act like a Picopass / iCLASS reader`
|`hf iclass restore      `|N       |`Restore a dump file onto a Picopass / iCLASS tag`
|`hf iclass sniff        `|N       |`Eavesdrop Picopass / iCLASS communication`
|`hf iclass view         `|Y       |`Display content from tag dump file`
|`hf iclass wrbl         `|N       |`Write Picopass / iCLASS block`
|`hf iclass chk          `|N       |`Check keys`
|`hf iclass loclass      `|Y       |`Use loclass to perform bruteforce reader attack`
|`hf iclass lookup       `|Y       |`Uses authentication trace to check for key in dictionary file`
|`hf iclass sim          `|N       |`Simulate iCLASS tag`
|`hf iclass eload        `|N       |`Load Picopass / iCLASS dump file into emulator memory`
|`hf iclass esave        `|N       |`Save emulator memory to file`
|`hf iclass esetblk      `|N       |`Set emulator memory block data`
|`hf iclass eview        `|N       |`View emulator memory`
|`hf iclass configcard   `|Y       |`Reader configuration card`
|`hf iclass calcnewkey   `|Y       |`Calc diversified keys (blocks 3 & 4) to write new keys`
|`hf iclass encode       `|Y       |`Encode binary wiegand to block 7`
|`hf iclass encrypt      `|Y       |`Encrypt given block data`
|`hf iclass decrypt      `|Y       |`Decrypt given block data or tag dump file`
|`hf iclass managekeys   `|Y       |`Manage keys to use with iclass commands`
|`hf iclass permutekey   `|Y       |`Permute function from 'heart of darkness' paper`
|`hf iclass sam          `|N       |`SAM tests`


### hf legic

 { LEGIC RFIDs...                      }

|command                  |offline |description
|-------                  |------- |-----------
|`hf legic help          `|Y       |`This help`
|`hf legic dump          `|N       |`Dump LEGIC Prime tag to binary file`
|`hf legic info          `|N       |`Display deobfuscated and decoded LEGIC Prime tag data`
|`hf legic list          `|Y       |`List LEGIC history`
|`hf legic rdbl          `|N       |`Read bytes from a LEGIC Prime tag`
|`hf legic reader        `|N       |`LEGIC Prime Reader UID and tag info`
|`hf legic restore       `|N       |`Restore a dump file onto a LEGIC Prime tag`
|`hf legic wipe          `|N       |`Wipe a LEGIC Prime tag`
|`hf legic wrbl          `|N       |`Write data to a LEGIC Prime tag`
|`hf legic sim           `|N       |`Start tag simulator`
|`hf legic eload         `|N       |`Load binary dump to emulator memory`
|`hf legic esave         `|N       |`Save emulator memory to binary file`
|`hf legic eview         `|N       |`View emulator memory`
|`hf legic einfo         `|N       |`Display deobfuscated and decoded emulator memory`
|`hf legic crc           `|Y       |`Calculate Legic CRC over given bytes`
|`hf legic view          `|Y       |`Display deobfuscated and decoded content from tag dump file`


### hf lto

 { LTO Cartridge Memory RFIDs...       }

|command                  |offline |description
|-------                  |------- |-----------
|`hf lto help            `|Y       |`This help`
|`hf lto dump            `|N       |`Dump LTO-CM tag to file`
|`hf lto info            `|N       |`Tag information`
|`hf lto list            `|Y       |`List LTO-CM history`
|`hf lto rdbl            `|N       |`Read block`
|`hf lto reader          `|N       |`Act like a LTO-CM reader`
|`hf lto restore         `|N       |`Restore dump file to LTO-CM tag`
|`hf lto wrbl            `|N       |`Write block`


### hf mf

 { MIFARE RFIDs...                     }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mf help             `|Y       |`This help`
|`hf mf list             `|Y       |`List MIFARE history`
|`hf mf darkside         `|N       |`Darkside attack`
|`hf mf nested           `|N       |`Nested attack`
|`hf mf hardnested       `|Y       |`Nested attack for hardened MIFARE Classic cards`
|`hf mf staticnested     `|N       |`Nested attack against static nonce MIFARE Classic cards`
|`hf mf autopwn          `|N       |`Automatic key recovery tool for MIFARE Classic`
|`hf mf nack             `|N       |`Test for MIFARE NACK bug`
|`hf mf chk              `|N       |`Check keys`
|`hf mf fchk             `|N       |`Check keys fast, targets all keys on card`
|`hf mf decrypt          `|Y       |`Decrypt Crypto1 data from sniff or trace`
|`hf mf supercard        `|N       |`Extract info from a `super card``
|`hf mf auth4            `|N       |`ISO14443-4 AES authentication`
|`hf mf acl              `|Y       |`Decode and print MIFARE Classic access rights bytes`
|`hf mf dump             `|N       |`Dump MIFARE Classic tag to binary file`
|`hf mf mad              `|Y       |`Checks and prints MAD`
|`hf mf personalize      `|N       |`Personalize UID (MIFARE Classic EV1 only)`
|`hf mf rdbl             `|N       |`Read MIFARE Classic block`
|`hf mf rdsc             `|N       |`Read MIFARE Classic sector`
|`hf mf restore          `|N       |`Restore MIFARE Classic binary file to tag`
|`hf mf setmod           `|N       |`Set MIFARE Classic EV1 load modulation strength`
|`hf mf value            `|Y       |`Value blocks`
|`hf mf view             `|Y       |`Display content from tag dump file`
|`hf mf wipe             `|N       |`Wipe card to zeros and default keys/acc`
|`hf mf wrbl             `|N       |`Write MIFARE Classic block`
|`hf mf sim              `|N       |`Simulate MIFARE card`
|`hf mf ecfill           `|N       |`Fill emulator memory with help of keys from emulator`
|`hf mf eclr             `|N       |`Clear emulator memory`
|`hf mf egetblk          `|N       |`Get emulator memory block`
|`hf mf egetsc           `|N       |`Get emulator memory sector`
|`hf mf ekeyprn          `|N       |`Print keys from emulator memory`
|`hf mf eload            `|N       |`Load from file emul dump`
|`hf mf esave            `|N       |`Save to file emul dump`
|`hf mf esetblk          `|N       |`Set emulator memory block`
|`hf mf eview            `|N       |`View emulator memory`
|`hf mf cgetblk          `|N       |`Read block from card`
|`hf mf cgetsc           `|N       |`Read sector from card`
|`hf mf cload            `|N       |`Load dump to card`
|`hf mf csave            `|N       |`Save dump from card into file or emulator`
|`hf mf csetblk          `|N       |`Write block to card`
|`hf mf csetuid          `|N       |`Set UID on card`
|`hf mf cview            `|N       |`View card`
|`hf mf cwipe            `|N       |`Wipe card to default UID/Sectors/Keys`
|`hf mf gen3uid          `|N       |`Set UID without changing manufacturer block`
|`hf mf gen3blk          `|N       |`Overwrite manufacturer block`
|`hf mf gen3freeze       `|N       |`Perma lock UID changes. irreversible`
|`hf mf ggetblk          `|N       |`Read block from card`
|`hf mf gload            `|N       |`Load dump to card`
|`hf mf gsave            `|N       |`Save dump from card into file or emulator`
|`hf mf gsetblk          `|N       |`Write block to card`
|`hf mf gview            `|N       |`View card`
|`hf mf gdmcfg           `|N       |`Read config block from card`
|`hf mf gdmsetcfg        `|N       |`Write config block to card`
|`hf mf gdmsetblk        `|N       |`Write block to card`
|`hf mf ndefformat       `|N       |`Format MIFARE Classic Tag as NFC Tag`
|`hf mf ndefread         `|N       |`Read and print NDEF records from card`
|`hf mf ndefwrite        `|N       |`Write NDEF records to card`


### hf mfp

 { MIFARE Plus RFIDs...                }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mfp help            `|Y       |`This help`
|`hf mfp list            `|Y       |`List MIFARE Plus history`
|`hf mfp auth            `|N       |`Authentication`
|`hf mfp chk             `|N       |`Check keys`
|`hf mfp dump            `|N       |`Dump MIFARE Plus tag to binary file`
|`hf mfp info            `|N       |`Info about MIFARE Plus tag`
|`hf mfp mad             `|N       |`Check and print MAD`
|`hf mfp rdbl            `|N       |`Read blocks from card`
|`hf mfp rdsc            `|N       |`Read sectors from card`
|`hf mfp wrbl            `|N       |`Write block to card`
|`hf mfp commitp         `|N       |`Configure security layer (SL1/SL3 mode)`
|`hf mfp initp           `|N       |`Fill all the card's keys in SL0 mode`
|`hf mfp wrp             `|N       |`Write Perso command`
|`hf mfp ndefformat      `|N       |`Format MIFARE Plus Tag as NFC Tag`
|`hf mfp ndefread        `|N       |`Read and print NDEF records from card`
|`hf mfp ndefwrite       `|N       |`Write NDEF records to card`


### hf mfu

 { MIFARE Ultralight RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mfu help            `|Y       |`This help`
|`hf mfu list            `|Y       |`List MIFARE Ultralight / NTAG history`
|`hf mfu keygen          `|Y       |`Generate 3DES MIFARE diversified keys`
|`hf mfu pwdgen          `|Y       |`Generate pwd from known algos`
|`hf mfu otptear         `|N       |`Tear-off test on OTP bits`
|`hf mfu cauth           `|N       |`Authentication - Ultralight-C`
|`hf mfu dump            `|N       |`Dump MIFARE Ultralight family tag to binary file`
|`hf mfu info            `|N       |`Tag information`
|`hf mfu ndefread        `|N       |`Prints NDEF records from card`
|`hf mfu rdbl            `|N       |`Read block`
|`hf mfu restore         `|N       |`Restore a dump onto a MFU MAGIC tag`
|`hf mfu view            `|Y       |`Display content from tag dump file`
|`hf mfu wrbl            `|N       |`Write block`
|`hf mfu tamper          `|N       |`Configure the tamper feature on an NTAG 213TT`
|`hf mfu eload           `|N       |`Load Ultralight dump file into emulator memory`
|`hf mfu esave           `|N       |`Save Ultralight dump file from emulator memory`
|`hf mfu eview           `|N       |`View emulator memory`
|`hf mfu sim             `|N       |`Simulate MIFARE Ultralight from emulator memory`
|`hf mfu setpwd          `|N       |`Set 3DES key - Ultralight-C`
|`hf mfu setuid          `|N       |`Set UID - MAGIC tags only`


### hf mfdes

 { MIFARE Desfire RFIDs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mfdes help          `|Y       |`This help`
|`hf mfdes info          `|N       |`Tag information`
|`hf mfdes getuid        `|N       |`Get uid from card`
|`hf mfdes default       `|N       |`Set defaults for all the commands`
|`hf mfdes auth          `|N       |`MIFARE DesFire Authentication`
|`hf mfdes chk           `|N       |`Check keys`
|`hf mfdes detect        `|N       |`Detect key type and tries to find one from the list`
|`hf mfdes freemem       `|N       |`Get free memory size`
|`hf mfdes setconfig     `|N       |`Set card configuration`
|`hf mfdes formatpicc    `|N       |`Format PICC`
|`hf mfdes list          `|Y       |`List DESFire (ISO 14443A) history`
|`hf mfdes mad           `|N       |`Prints MAD records / files from the card`
|`hf mfdes lsapp         `|N       |`Show all applications with files list`
|`hf mfdes getaids       `|N       |`Get Application IDs list`
|`hf mfdes getappnames   `|N       |`Get Applications list`
|`hf mfdes bruteaid      `|N       |`Recover AIDs by bruteforce`
|`hf mfdes createapp     `|N       |`Create Application`
|`hf mfdes deleteapp     `|N       |`Delete Application`
|`hf mfdes selectapp     `|N       |`Select Application ID`
|`hf mfdes changekey     `|N       |`Change Key`
|`hf mfdes chkeysettings `|N       |`Change Key Settings`
|`hf mfdes getkeysettings`|N       |`Get Key Settings`
|`hf mfdes getkeyversions`|N       |`Get Key Versions`
|`hf mfdes getfileids    `|N       |`Get File IDs list`
|`hf mfdes getfileisoids `|N       |`Get File ISO IDs list`
|`hf mfdes lsfiles       `|N       |`Show all files list`
|`hf mfdes dump          `|N       |`Dump all files`
|`hf mfdes createfile    `|N       |`Create Standard/Backup File`
|`hf mfdes createvaluefile`|N       |`Create Value File`
|`hf mfdes createrecordfile`|N       |`Create Linear/Cyclic Record File`
|`hf mfdes createmacfile `|N       |`Create Transaction MAC File`
|`hf mfdes deletefile    `|N       |`Delete File`
|`hf mfdes getfilesettings`|N       |`Get file settings`
|`hf mfdes chfilesettings`|N       |`Change file settings`
|`hf mfdes read          `|N       |`Read data from standard/backup/record/value/mac file`
|`hf mfdes write         `|N       |`Write data to standard/backup/record/value file`
|`hf mfdes value         `|N       |`Operations with value file (get/credit/limited credit/debit/clear)`
|`hf mfdes clearrecfile  `|N       |`Clear record File`
|`hf mfdes test          `|Y       |`Regression crypto tests`


### hf ntag424

 { NXP NTAG 4242 DNA RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf ntag424 help        `|Y       |`This help`
|`hf ntag424 info        `|N       |`Tag information`
|`hf ntag424 sdm         `|N       |`Prints NDEF records from card`
|`hf ntag424 view        `|Y       |`Display content from tag dump file`


### hf seos

 { SEOS RFIDs...                       }

|command                  |offline |description
|-------                  |------- |-----------
|`hf seos help           `|Y       |`This help`
|`hf seos info           `|N       |`Tag information`
|`hf seos list           `|Y       |`List SEOS history`


### hf st25ta

 { ST25TA RFIDs...                     }

|command                  |offline |description
|-------                  |------- |-----------
|`hf st25ta help         `|Y       |`This help`
|`hf st25ta info         `|N       |`Tag information`
|`hf st25ta list         `|Y       |`List ISO 14443A/7816 history`
|`hf st25ta ndefread     `|Y       |`read NDEF file on tag`
|`hf st25ta protect      `|N       |`change protection on tag`
|`hf st25ta pwd          `|N       |`change password on tag`
|`hf st25ta sim          `|N       |`Fake ISO 14443A/ST tag`


### hf tesla

 { TESLA Cards...                      }

|command                  |offline |description
|-------                  |------- |-----------
|`hf tesla help          `|Y       |`This help`
|`hf tesla info          `|N       |`Tag information`
|`hf tesla list          `|Y       |`List ISO 14443A/7816 history`


### hf texkom

 { Texkom RFIDs...                     }

|command                  |offline |description
|-------                  |------- |-----------
|`hf texkom help         `|Y       |`This help`
|`hf texkom reader       `|N       |`Act like a Texkom reader`
|`hf texkom sim          `|N       |`Simulate a Texkom tag`


### hf thinfilm

 { Thinfilm RFIDs...                   }

|command                  |offline |description
|-------                  |------- |-----------
|`hf thinfilm help       `|Y       |`This help`
|`hf thinfilm info       `|N       |`Tag information`
|`hf thinfilm list       `|Y       |`List NFC Barcode / Thinfilm history - not correct`
|`hf thinfilm sim        `|N       |`Fake Thinfilm tag`


### hf topaz

 { TOPAZ (NFC Type 1) RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`hf topaz help          `|Y       |`This help`
|`hf topaz list          `|Y       |`List Topaz history`
|`hf topaz dump          `|N       |`Dump TOPAZ family tag to file`
|`hf topaz info          `|N       |`Tag information`
|`hf topaz raw           `|N       |`Send raw hex data to tag`
|`hf topaz rdbl          `|N       |`Read block`
|`hf topaz reader        `|N       |`Act like a Topaz reader`
|`hf topaz sim           `|N       |`Simulate Topaz tag`
|`hf topaz sniff         `|N       |`Sniff Topaz reader-tag communication`
|`hf topaz view          `|Y       |`Display content from tag dump file`
|`hf topaz wrbl          `|N       |`Write block`


### hf vas

 { Apple Value Added Service           }

|command                  |offline |description
|-------                  |------- |-----------
|`hf vas help            `|Y       |`This help`
|`hf vas reader          `|N       |`Read and decrypt VAS message`
|`hf vas decrypt         `|Y       |`Decrypt a previously captured VAS cryptogram`


### hf waveshare

 { Waveshare NFC ePaper...             }

|command                  |offline |description
|-------                  |------- |-----------
|`hf waveshare help      `|Y       |`This help`
|`hf waveshare loadbmp   `|N       |`Load BMP file to Waveshare NFC ePaper`


### hf xerox

 { Fuji/Xerox cartridge RFIDs...       }

|command                  |offline |description
|-------                  |------- |-----------
|`hf xerox help          `|Y       |`This help`
|`hf xerox info          `|N       |`Short info on Fuji/Xerox tag`
|`hf xerox reader        `|N       |`Act like a Fuji/Xerox reader`
|`hf xerox dump          `|N       |`Read all memory pages of an Fuji/Xerox tag, save to file`


### hw

 { Hardware commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`hw help                `|Y       |`This help`
|`hw break               `|N       |`Send break loop usb command`
|`hw connect             `|Y       |`Connect Proxmark3 to serial port`
|`hw dbg                 `|N       |`Set Proxmark3 debug level`
|`hw detectreader        `|N       |`Detect external reader field`
|`hw fpgaoff             `|N       |`Set FPGA off`
|`hw lcd                 `|N       |`Send command/data to LCD`
|`hw lcdreset            `|N       |`Hardware reset LCD`
|`hw ping                `|N       |`Test if the Proxmark3 is responsive`
|`hw readmem             `|N       |`Read memory at decimal address from flash`
|`hw reset               `|N       |`Reset the Proxmark3`
|`hw setlfdivisor        `|N       |`Drive LF antenna at 12MHz / (divisor + 1)`
|`hw setmux              `|N       |`Set the ADC mux to a specific value`
|`hw standalone          `|N       |`Jump to the standalone mode`
|`hw status              `|N       |`Show runtime status information about the connected Proxmark3`
|`hw tearoff             `|N       |`Program a tearoff hook for the next command supporting tearoff`
|`hw tia                 `|N       |`Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider`
|`hw timeout             `|Y       |`Set the communication timeout on the client side`
|`hw tune                `|N       |`Measure antenna tuning`
|`hw version             `|Y       |`Show version information about the client and the connected Proxmark3, if any`


### lf

 { Low frequency commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf help                `|Y       |`This help`
|`lf config              `|N       |`Get/Set config for LF sampling, bit/sample, decimation, frequency`
|`lf cmdread             `|N       |`Modulate LF reader field to send command before read`
|`lf read                `|N       |`Read LF tag`
|`lf search              `|Y       |`Read and Search for valid known tag`
|`lf sim                 `|N       |`Simulate LF tag from buffer`
|`lf simask              `|N       |`Simulate ASK tag`
|`lf simfsk              `|N       |`Simulate FSK tag`
|`lf simpsk              `|N       |`Simulate PSK tag`
|`lf simbidir            `|N       |`Simulate LF tag (with bidirectional data transmission between reader and tag)`
|`lf sniff               `|N       |`Sniff LF traffic between reader and tag`
|`lf tune                `|N       |`Continuously measure LF antenna tuning`


### lf awid

 { AWID RFIDs...              }

|command                  |offline |description
|-------                  |------- |-----------
|`lf awid help           `|Y       |`this help`
|`lf awid demod          `|Y       |`demodulate an AWID FSK tag from the GraphBuffer`
|`lf awid reader         `|N       |`attempt to read and extract tag data`
|`lf awid clone          `|N       |`clone AWID tag to T55x7 or Q5/T5555`
|`lf awid sim            `|N       |`simulate AWID tag`
|`lf awid brute          `|N       |`bruteforce card number against reader`
|`lf awid watch          `|N       |`continuously watch for cards.  Reader mode`


### lf cotag

 { COTAG CHIPs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf cotag help          `|Y       |`This help`
|`lf cotag demod         `|Y       |`demodulate an COTAG tag`
|`lf cotag reader        `|N       |`attempt to read and extract tag data`


### lf destron

 { FDX-A Destron RFIDs...     }

|command                  |offline |description
|-------                  |------- |-----------
|`lf destron help        `|Y       |`This help`
|`lf destron demod       `|Y       |`demodulate an Destron tag from the GraphBuffer`
|`lf destron reader      `|N       |`attempt to read and extract tag data`
|`lf destron clone       `|N       |`clone Destron tag to T55x7`
|`lf destron sim         `|N       |`simulate Destron tag`


### lf em

 { EM CHIPs & RFIDs...        }

|command                  |offline |description
|-------                  |------- |-----------
|`lf em help             `|Y       |`This help`


### lf em 410x

 { EM 4102 commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf em 410x help        `|Y       |`This help`
|`lf em 410x demod       `|Y       |`demodulate a EM410x tag from the GraphBuffer`
|`lf em 410x reader      `|N       |`attempt to read and extract tag data`
|`lf em 410x sim         `|N       |`simulate EM410x tag`
|`lf em 410x brute       `|N       |`reader bruteforce attack by simulating EM410x tags`
|`lf em 410x watch       `|N       |`watches for EM410x 125/134 kHz tags`
|`lf em 410x spoof       `|N       |`watches for EM410x 125/134 kHz tags, and replays them`
|`lf em 410x clone       `|N       |`write EM410x Tag ID to T55x7 or Q5/T5555 tag`


### lf em 4x05

 { EM 4205 / 4305 / 4369 / 4469 commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf em 4x05 help        `|Y       |`This help`
|`lf em 4x05 brute       `|N       |`Bruteforce password`
|`lf em 4x05 chk         `|N       |`Check passwords from dictionary`
|`lf em 4x05 demod       `|Y       |`Demodulate a EM4x05/EM4x69 tag from the GraphBuffer`
|`lf em 4x05 dump        `|N       |`Dump EM4x05/EM4x69 tag`
|`lf em 4x05 info        `|N       |`Tag information`
|`lf em 4x05 read        `|N       |`Read word data from EM4x05/EM4x69`
|`lf em 4x05 sniff       `|Y       |`Attempt to recover em4x05 commands from sample buffer`
|`lf em 4x05 unlock      `|N       |`Execute tear off against EM4x05/EM4x69`
|`lf em 4x05 wipe        `|N       |`Wipe EM4x05/EM4x69 tag`
|`lf em 4x05 write       `|N       |`Write word data to EM4x05/EM4x69`


### lf em 4x50

 { EM 4350 / 4450 commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf em 4x50 help        `|Y       |`This help`
|`lf em 4x50 brute       `|N       |`Bruteforce attack to find password`
|`lf em 4x50 chk         `|N       |`Check passwords from dictionary`
|`lf em 4x50 dump        `|N       |`Dump EM4x50 tag`
|`lf em 4x50 info        `|N       |`Tag information`
|`lf em 4x50 login       `|N       |`Login into EM4x50 tag`
|`lf em 4x50 rdbl        `|N       |`Read EM4x50 word data`
|`lf em 4x50 reader      `|N       |`Show standard read mode data`
|`lf em 4x50 restore     `|N       |`Restore EM4x50 dump to tag`
|`lf em 4x50 wrbl        `|N       |`Write EM4x50 word data`
|`lf em 4x50 wrpwd       `|N       |`Change EM4x50 password`
|`lf em 4x50 wipe        `|N       |`Wipe EM4x50 tag`
|`lf em 4x50 eload       `|N       |`Upload EM4x50 dump to emulator memory`
|`lf em 4x50 esave       `|N       |`Save emulator memory to file`
|`lf em 4x50 eview       `|N       |`View EM4x50 content in emulator memory`
|`lf em 4x50 sim         `|N       |`Simulate EM4x50 tag`


### lf em 4x70

 { EM 4070 / 4170 commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf em 4x70 help        `|Y       |`This help`
|`lf em 4x70 brute       `|N       |`Bruteforce EM4X70 to find partial Crypt Key`
|`lf em 4x70 info        `|N       |`Tag information EM4x70`
|`lf em 4x70 write       `|N       |`Write EM4x70`
|`lf em 4x70 unlock      `|N       |`Unlock EM4x70 for writing`
|`lf em 4x70 auth        `|N       |`Authenticate EM4x70`
|`lf em 4x70 writepin    `|N       |`Write PIN`
|`lf em 4x70 writekey    `|N       |`Write Crypt Key`


### lf fdxb

 { FDX-B RFIDs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf fdxb help           `|Y       |`this help`
|`lf fdxb demod          `|Y       |`demodulate a FDX-B ISO11784/85 tag from the GraphBuffer`
|`lf fdxb reader         `|N       |`attempt to read at 134kHz and extract tag data`
|`lf fdxb clone          `|N       |`clone animal ID tag to T55x7 or Q5/T5555`
|`lf fdxb sim            `|N       |`simulate Animal ID tag`


### lf gallagher

 { GALLAGHER RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`lf gallagher help      `|Y       |`This help`
|`lf gallagher demod     `|Y       |`demodulate an GALLAGHER tag from the GraphBuffer`
|`lf gallagher reader    `|N       |`attempt to read and extract tag data`
|`lf gallagher clone     `|N       |`clone GALLAGHER tag to T55x7`
|`lf gallagher sim       `|N       |`simulate GALLAGHER tag`


### lf gproxii

 { Guardall Prox II RFIDs...  }

|command                  |offline |description
|-------                  |------- |-----------
|`lf gproxii help        `|Y       |`this help`
|`lf gproxii demod       `|Y       |`demodulate a G Prox II tag from the GraphBuffer`
|`lf gproxii reader      `|N       |`attempt to read and extract tag data`
|`lf gproxii clone       `|N       |`clone Guardall tag to T55x7 or Q5/T5555`
|`lf gproxii sim         `|N       |`simulate Guardall tag`


### lf hid

 { HID Prox RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf hid help            `|Y       |`this help`
|`lf hid demod           `|Y       |`demodulate HID Prox tag from the GraphBuffer`
|`lf hid reader          `|N       |`attempt to read and extract tag data`
|`lf hid clone           `|N       |`clone HID tag to T55x7`
|`lf hid sim             `|N       |`simulate HID tag`
|`lf hid brute           `|N       |`bruteforce facility code or card number against reader`
|`lf hid watch           `|N       |`continuously watch for cards.  Reader mode`


### lf hitag

 { Hitag CHIPs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf hitag help          `|Y       |`This help`
|`lf hitag list          `|Y       |`List Hitag trace history`
|`lf hitag info          `|N       |`Hitag 2 tag information`
|`lf hitag dump          `|N       |`Dump Hitag 2 tag`
|`lf hitag read          `|N       |`Read Hitag memory`
|`lf hitag wrbl          `|N       |`Write a block (page) in Hitag memory`
|`lf hitag sniff         `|N       |`Eavesdrop Hitag communication`
|`lf hitag cc            `|N       |`Hitag S: test all provided challenges`
|`lf hitag ta            `|N       |`Hitag 2: test all recorded authentications`
|`lf hitag eload         `|N       |`Load Hitag dump file into emulator memory`
|`lf hitag sim           `|N       |`Simulate Hitag transponder`


### lf idteck

 { Idteck RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf idteck help         `|Y       |`This help`
|`lf idteck demod        `|Y       |`demodulate an Idteck tag from the GraphBuffer`
|`lf idteck reader       `|N       |`attempt to read and extract tag data`
|`lf idteck clone        `|N       |`clone Idteck tag to T55x7 or Q5/T5555`
|`lf idteck sim          `|N       |`simulate Idteck tag`


### lf indala

 { Indala RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf indala help         `|Y       |`This help`
|`lf indala brute        `|N       |`Demodulate an Indala tag (PSK1) from the GraphBuffer`
|`lf indala demod        `|Y       |`Demodulate an Indala tag (PSK1) from the GraphBuffer`
|`lf indala altdemod     `|Y       |`Alternative method to demodulate samples for Indala 64 bit UID (option '224' for 224 bit)`
|`lf indala reader       `|N       |`Read an Indala tag from the antenna`
|`lf indala clone        `|N       |`Clone Indala tag to T55x7 or Q5/T5555`
|`lf indala sim          `|N       |`Simulate Indala tag`


### lf io

 { ioProx RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf io help             `|Y       |`this help`
|`lf io demod            `|Y       |`demodulate an ioProx tag from the GraphBuffer`
|`lf io reader           `|N       |`attempt to read and extract tag data`
|`lf io clone            `|N       |`clone ioProx tag to T55x7 or Q5/T5555`
|`lf io sim              `|N       |`simulate ioProx tag`
|`lf io watch            `|N       |`continuously watch for cards. Reader mode`


### lf jablotron

 { Jablotron RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`lf jablotron help      `|Y       |`This help`
|`lf jablotron demod     `|Y       |`demodulate an Jablotron tag from the GraphBuffer`
|`lf jablotron reader    `|N       |`attempt to read and extract tag data`
|`lf jablotron clone     `|N       |`clone jablotron tag to T55x7 or Q5/T5555`
|`lf jablotron sim       `|N       |`simulate jablotron tag`


### lf keri

 { KERI RFIDs...              }

|command                  |offline |description
|-------                  |------- |-----------
|`lf keri help           `|Y       |`This help`
|`lf keri demod          `|Y       |`demodulate an KERI tag from the GraphBuffer`
|`lf keri reader         `|N       |`attempt to read and extract tag data`
|`lf keri clone          `|N       |`clone KERI tag to T55x7 or Q5/T5555`
|`lf keri sim            `|N       |`simulate KERI tag`


### lf motorola

 { Motorola Flexpass RFIDs... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf motorola help       `|Y       |`This help`
|`lf motorola demod      `|Y       |`demodulate an MOTOROLA tag from the GraphBuffer`
|`lf motorola reader     `|N       |`attempt to read and extract tag data`
|`lf motorola clone      `|N       |`clone MOTOROLA tag to T55x7`
|`lf motorola sim        `|N       |`simulate MOTOROLA tag`


### lf nedap

 { Nedap RFIDs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf nedap help          `|Y       |`This help`
|`lf nedap demod         `|Y       |`demodulate Nedap tag from the GraphBuffer`
|`lf nedap reader        `|N       |`attempt to read and extract tag data`
|`lf nedap clone         `|N       |`clone Nedap tag to T55x7 or Q5/T5555`
|`lf nedap sim           `|N       |`simulate Nedap tag`


### lf nexwatch

 { NexWatch RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf nexwatch help       `|Y       |`This help`
|`lf nexwatch demod      `|Y       |`demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer`
|`lf nexwatch reader     `|N       |`attempt to read and extract tag data`
|`lf nexwatch clone      `|N       |`clone NexWatch tag to T55x7`
|`lf nexwatch sim        `|N       |`simulate NexWatch tag`


### lf noralsy

 { Noralsy RFIDs...           }

|command                  |offline |description
|-------                  |------- |-----------
|`lf noralsy help        `|Y       |`This help`
|`lf noralsy demod       `|Y       |`demodulate an Noralsy tag from the GraphBuffer`
|`lf noralsy reader      `|N       |`attempt to read and extract tag data`
|`lf noralsy clone       `|N       |`clone Noralsy tag to T55x7 or Q5/T5555`
|`lf noralsy sim         `|N       |`simulate Noralsy tag`


### lf pac

 { PAC/Stanley RFIDs...       }

|command                  |offline |description
|-------                  |------- |-----------
|`lf pac help            `|Y       |`This help`
|`lf pac demod           `|Y       |`demodulate a PAC tag from the GraphBuffer`
|`lf pac reader          `|N       |`attempt to read and extract tag data`
|`lf pac clone           `|N       |`clone PAC tag to T55x7`
|`lf pac sim             `|N       |`simulate PAC tag`


### lf paradox

 { Paradox RFIDs...           }

|command                  |offline |description
|-------                  |------- |-----------
|`lf paradox help        `|Y       |`This help`
|`lf paradox demod       `|Y       |`demodulate a Paradox FSK tag from the GraphBuffer`
|`lf paradox reader      `|N       |`attempt to read and extract tag data`
|`lf paradox clone       `|N       |`clone paradox tag`
|`lf paradox sim         `|N       |`simulate paradox tag`


### lf pcf7931

 { PCF7931 CHIPs...           }

|command                  |offline |description
|-------                  |------- |-----------
|`lf pcf7931 help        `|Y       |`This help`
|`lf pcf7931 reader      `|N       |`Read content of a PCF7931 transponder`
|`lf pcf7931 write       `|N       |`Write data on a PCF7931 transponder.`
|`lf pcf7931 config      `|Y       |`Configure the password, the tags initialization delay and time offsets (optional)`


### lf presco

 { Presco RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf presco help         `|Y       |`This help`
|`lf presco demod        `|Y       |`demodulate Presco tag from the GraphBuffer`
|`lf presco reader       `|N       |`attempt to read and extract tag data`
|`lf presco clone        `|N       |`clone presco tag to T55x7 or Q5/T5555`
|`lf presco sim          `|N       |`simulate presco tag`


### lf pyramid

 { Farpointe/Pyramid RFIDs... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf pyramid help        `|Y       |`this help`
|`lf pyramid demod       `|Y       |`demodulate a Pyramid FSK tag from the GraphBuffer`
|`lf pyramid reader      `|N       |`attempt to read and extract tag data`
|`lf pyramid clone       `|N       |`clone pyramid tag to T55x7 or Q5/T5555`
|`lf pyramid sim         `|N       |`simulate pyramid tag`


### lf securakey

 { Securakey RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`lf securakey help      `|Y       |`This help`
|`lf securakey demod     `|Y       |`demodulate an Securakey tag from the GraphBuffer`
|`lf securakey reader    `|N       |`attempt to read and extract tag data`
|`lf securakey clone     `|N       |`clone Securakey tag to T55x7`
|`lf securakey sim       `|N       |`simulate Securakey tag`


### lf ti

 { TI CHIPs...                }

|command                  |offline |description
|-------                  |------- |-----------
|`lf ti help             `|Y       |`This help`
|`lf ti demod            `|Y       |`Demodulate raw bits for TI LF tag from the GraphBuffer`
|`lf ti reader           `|N       |`Read and decode a TI 134 kHz tag`
|`lf ti write            `|N       |`Write new data to a r/w TI 134 kHz tag`


### lf t55xx

 { T55xx CHIPs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf t55xx help          `|Y       |`This help`
|`lf t55xx clonehelp     `|N       |`Shows the available clone commands`
|`lf t55xx config        `|Y       |`Set/Get T55XX configuration (modulation, inverted, offset, rate)`
|`lf t55xx dangerraw     `|N       |`Sends raw bitstream. Dangerous, do not use!!`
|`lf t55xx detect        `|Y       |`Try detecting the tag modulation from reading the configuration block`
|`lf t55xx deviceconfig  `|N       |`Set/Get T55XX device configuration`
|`lf t55xx dump          `|N       |`Dump T55xx card Page 0 block 0-7`
|`lf t55xx info          `|Y       |`Show T55x7 configuration data (page 0/ blk 0)`
|`lf t55xx p1detect      `|N       |`Try detecting if this is a t55xx tag by reading page 1`
|`lf t55xx read          `|N       |`Read T55xx block data`
|`lf t55xx resetread     `|N       |`Send Reset Cmd then lf read the stream to attempt to identify the start of it`
|`lf t55xx restore       `|N       |`Restore T55xx card Page 0 / Page 1 blocks`
|`lf t55xx trace         `|Y       |`Show T55x7 traceability data (page 1/ blk 0-1)`
|`lf t55xx wakeup        `|N       |`Send AOR wakeup command`
|`lf t55xx write         `|N       |`Write T55xx block data`
|`lf t55xx bruteforce    `|N       |`Simple bruteforce attack to find password`
|`lf t55xx chk           `|N       |`Check passwords from dictionary/flash`
|`lf t55xx protect       `|N       |`Password protect tag`
|`lf t55xx recoverpw     `|N       |`Try to recover from bad password write from a cloner`
|`lf t55xx sniff         `|Y       |`Attempt to recover T55xx commands from sample buffer`
|`lf t55xx special       `|N       |`Show block changes with 64 different offsets`
|`lf t55xx wipe          `|N       |`Wipe a T55xx tag and set defaults (will destroy any data on tag)`


### lf viking

 { Viking RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf viking help         `|Y       |`This help`
|`lf viking demod        `|Y       |`demodulate a Viking tag from the GraphBuffer`
|`lf viking reader       `|N       |`attempt to read and extract tag data`
|`lf viking clone        `|N       |`clone Viking tag to T55x7 or Q5/T5555`
|`lf viking sim          `|N       |`simulate Viking tag`


### lf visa2000

 { Visa2000 RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf visa2000 help       `|Y       |`This help`
|`lf visa2000 demod      `|Y       |`demodulate an VISA2000 tag from the GraphBuffer`
|`lf visa2000 reader     `|N       |`attempt to read and extract tag data`
|`lf visa2000 clone      `|N       |`clone Visa2000 tag to T55x7 or Q5/T5555`
|`lf visa2000 sim        `|N       |`simulate Visa2000 tag`


### mem

 { Flash memory manipulation... }

|command                  |offline |description
|-------                  |------- |-----------
|`mem help               `|Y       |`This help`
|`mem baudrate           `|N       |`Set Flash memory Spi baudrate`
|`mem dump               `|N       |`Dump data from flash memory`
|`mem info               `|N       |`Flash memory information`
|`mem load               `|N       |`Load data to flash memory`
|`mem wipe               `|N       |`Wipe data from flash memory`


### mem spiffs

 { SPI File system }

|command                  |offline |description
|-------                  |------- |-----------
|`mem spiffs help        `|Y       |`This help`
|`mem spiffs copy        `|N       |`Copy a file to another (destructively) in SPIFFS file system`
|`mem spiffs check       `|N       |`Check/try to defrag faulty/fragmented file system`
|`mem spiffs dump        `|N       |`Dump a file from SPIFFS file system`
|`mem spiffs info        `|N       |`Print file system info and usage statistics`
|`mem spiffs mount       `|N       |`Mount the SPIFFS file system if not already mounted`
|`mem spiffs remove      `|N       |`Remove a file from SPIFFS file system`
|`mem spiffs rename      `|N       |`Rename/move a file in SPIFFS file system`
|`mem spiffs test        `|N       |`Test SPIFFS Operations`
|`mem spiffs tree        `|N       |`Print the Flash memory file system tree`
|`mem spiffs unmount     `|N       |`Un-mount the SPIFFS file system`
|`mem spiffs upload      `|N       |`Upload file into SPIFFS file system`
|`mem spiffs view        `|N       |`View file on SPIFFS file system`
|`mem spiffs wipe        `|N       |`Wipe all files from SPIFFS file system   * dangerous *`


### nfc

 { NFC commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc help               `|Y       |`This help`
|`nfc decode             `|Y       |`Decode NDEF records`


### nfc type1

 { NFC Forum Tag Type 1...             }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc type1 read         `|N       |`read NFC Forum Tag Type 1`
|`nfc type1 help         `|Y       |`This help`


### nfc type2

 { NFC Forum Tag Type 2...             }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc type2 read         `|N       |`read NFC Forum Tag Type 2`
|`nfc type2 help         `|Y       |`This help`


### nfc type4a

 { NFC Forum Tag Type 4 ISO14443A...   }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc type4a format      `|N       |`format ISO-14443-a tag as NFC Tag`
|`nfc type4a read        `|N       |`read NFC Forum Tag Type 4 A`
|`nfc type4a write       `|N       |`write NFC Forum Tag Type 4 A`
|`nfc type4a st25taread  `|N       |`read ST25TA as NFC Forum Tag Type 4`
|`nfc type4a help        `|Y       |`This help`


### nfc type4b

 { NFC Forum Tag Type 4 ISO14443B...   }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc type4b read        `|N       |`read NFC Forum Tag Type 4 B`
|`nfc type4b help        `|Y       |`This help`


### nfc mf

 { NFC Type MIFARE Classic/Plus Tag... }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc mf cformat         `|N       |`format MIFARE Classic Tag as NFC Tag`
|`nfc mf cread           `|N       |`read NFC Type MIFARE Classic Tag`
|`nfc mf cwrite          `|N       |`write NFC Type MIFARE Classic Tag`
|`nfc mf pread           `|N       |`read NFC Type MIFARE Plus Tag`
|`nfc mf help            `|Y       |`This help`


### nfc barcode

 { NFC Barcode Tag...                  }

|command                  |offline |description
|-------                  |------- |-----------
|`nfc barcode read       `|N       |`read NFC Barcode`
|`nfc barcode sim        `|N       |`simulate NFC Barcode`
|`nfc barcode help       `|Y       |`This help`


### piv

 { PIV commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`piv help               `|Y       |`This help`
|`piv select             `|N       |`Select the PIV applet`
|`piv getdata            `|N       |`Gets a container on a PIV card`
|`piv authsign           `|N       |`Authenticate with the card`
|`piv scan               `|N       |`Scan PIV card for known containers`
|`piv list               `|Y       |`List ISO7816 history`


### reveng

 { CRC calculations from RevEng software... }

[=] reveng: no mode switch specified. Use reveng -h for help.

### smart

 { Smart card ISO-7816 commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`smart help             `|Y       |`This help`
|`smart list             `|Y       |`List ISO 7816 history`
|`smart info             `|N       |`Tag information`
|`smart reader           `|N       |`Act like an IS07816 reader`
|`smart raw              `|N       |`Send raw hex data to tag`
|`smart upgrade          `|Y       |`Upgrade sim module firmware`
|`smart setclock         `|N       |`Set clock speed`
|`smart brute            `|N       |`Bruteforce SFI`


### script

 { Scripting commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`script help            `|Y       |`This help`
|`script list            `|Y       |`List available scripts`
|`script run             `|Y       |`<name> - execute a script`


### trace

 { Trace manipulation... }

|command                  |offline |description
|-------                  |------- |-----------
|`trace help             `|Y       |`This help`
|`trace extract          `|Y       |`Extract authentication challenges found in trace`
|`trace list             `|Y       |`List protocol data in trace buffer`
|`trace load             `|Y       |`Load trace from file`
|`trace save             `|Y       |`Save trace buffer to file`


### usart

 { USART commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`usart help             `|Y       |`This help`
|`usart btpin            `|N       |`Change BT add-on PIN`
|`usart btfactory        `|N       |`Reset BT add-on to factory settings`
|`usart tx               `|N       |`Send string over USART`
|`usart rx               `|N       |`Receive string over USART`
|`usart txrx             `|N       |`Send string over USART and wait for response`
|`usart txhex            `|N       |`Send bytes over USART`
|`usart rxhex            `|N       |`Receive bytes over USART`
|`usart config           `|N       |`Configure USART`


### wiegand

 { Wiegand format manipulation... }

|command                  |offline |description
|-------                  |------- |-----------
|`wiegand help           `|Y       |`This help`
|`wiegand list           `|Y       |`List available wiegand formats`
|`wiegand encode         `|Y       |`Encode to wiegand raw hex (currently for HID Prox)`
|`wiegand decode         `|Y       |`Convert raw hex to decoded wiegand format (currently for HID Prox)`


Full help dump done.
