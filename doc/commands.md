
# Proxmark3 command dump


Some commands are available only if a Proxmark3 is actually connected.  

Check column "offline" for their availability.



|command                  |offline |description
|-------                  |------- |-----------
|`auto                   `|N       |`Automated detection process for unknown tags`
|`clear                  `|Y       |`Clear screen`
|`help                   `|Y       |`This help. Use '<command> help' for details of a particular command.`
|`hints                  `|Y       |`Turn hints on / off`
|`msleep                 `|Y       |`Add a pause in milliseconds`
|`pref                   `|Y       |`Edit preferences`
|`rem                    `|Y       |`Add a text line in log file`
|`quit                   `|Y       |``
|`exit                   `|Y       |`Exit program`


### analyse

 { Analyse utils... }

|command                  |offline |description
|-------                  |------- |-----------
|`analyse help           `|Y       |`This help`
|`analyse lcr            `|Y       |`Generate final byte for XOR LRC`
|`analyse crc            `|Y       |`Stub method for CRC evaluations`
|`analyse chksum         `|Y       |`Checksum with adding, masking and one's complement`
|`analyse dates          `|Y       |`Look for datestamps in a given array of bytes`
|`analyse tea            `|Y       |`Crypto TEA test`
|`analyse lfsr           `|Y       |`LFSR tests`
|`analyse a              `|Y       |`Num bits test`
|`analyse nuid           `|Y       |`Create NUID from 7byte UID`
|`analyse demodbuff      `|Y       |`Load binary string to demodbuffer`
|`analyse freq           `|Y       |`Calc wave lengths`


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
|`data askedgedetect     `|Y       |`[threshold] Adjust Graph for manual ASK demod using the length of sample differences to detect the edge of a wave (use 20-45, def:25)`
|`data autocorr          `|Y       |`Autocorrelation over window`
|`data dirthreshold      `|Y       |`<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev.`
|`data decimate          `|Y       |`Decimate samples`
|`data undecimate        `|Y       |`Un-decimate samples`
|`data hide              `|Y       |`Hide graph window`
|`data hpf               `|Y       |`Remove DC offset from trace`
|`data iir               `|Y       |`Apply IIR buttersworth filter on plotdata`
|`data grid              `|Y       |`<x> <y> -- overlay grid on graph window, use zero value to turn off either`
|`data ltrim             `|Y       |`<samples> -- Trim samples from left of trace`
|`data mtrim             `|Y       |`<start> <stop> -- Trim out samples from the specified start to the specified stop`
|`data norm              `|Y       |`Normalize max/min to +/-128`
|`data plot              `|Y       |`Show graph window (hit 'h' in window for keystroke help)`
|`data rtrim             `|Y       |`<location to end trace> -- Trim samples from right of trace`
|`data setgraphmarkers   `|Y       |`[orange_marker] [blue_marker] (in graph window)`
|`data shiftgraphzero    `|Y       |`<shift> -- Shift 0 for Graphed wave + or - shift value`
|`data timescale         `|Y       |`Set a timescale to get a differential reading between the yellow and purple markers as time duration
`
|`data zerocrossings     `|Y       |`Count time between zero-crossings`
|`data convertbitstream  `|Y       |`Convert GraphBuffer's 0/1 values to 127 / -127`
|`data getbitstream      `|Y       |`Convert GraphBuffer's >=1 values to 1 and <1 to 0`
|`data bin2hex           `|Y       |`Converts binary to hexadecimal`
|`data bitsamples        `|N       |`Get raw samples as bitstring`
|`data clear             `|Y       |`Clears bigbuf on deviceside and graph window`
|`data hexsamples        `|N       |`<bytes> [<offset>] -- Dump big buffer as hex bytes`
|`data hex2bin           `|Y       |`Converts hexadecimal to binary`
|`data load              `|Y       |`Load contents of file into graph window`
|`data ndef              `|Y       |`Decode NDEF records`
|`data print             `|Y       |`Print the data in the DemodBuffer`
|`data samples           `|N       |`[512 - 40000] -- Get raw samples for graph window (GraphBuffer)`
|`data save              `|Y       |`Save signal trace data  (from graph window)`
|`data setdebugmode      `|Y       |`<0|1|2> -- Set Debugging Level on client side`
|`data tune              `|N       |`Measure tuning of device antenna. Results shown in graph window`


### emv

 { EMV ISO-14443 / ISO-7816... }

|command                  |offline |description
|-------                  |------- |-----------
|`emv help               `|Y       |`This help`
|`emv exec               `|N       |`Executes EMV contactless transaction.`
|`emv pse                `|N       |`Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory.`
|`emv search             `|N       |`Try to select all applets from applets list and print installed applets.`
|`emv select             `|N       |`Select applet.`
|`emv gpo                `|N       |`Execute GetProcessingOptions.`
|`emv readrec            `|N       |`Read files from card.`
|`emv genac              `|N       |`Generate ApplicationCryptogram.`
|`emv challenge          `|N       |`Generate challenge.`
|`emv intauth            `|N       |`Internal authentication.`
|`emv scan               `|N       |`Scan EMV card and save it contents to json file for emulator.`
|`emv test               `|Y       |`Crypto logic test.`
|`emv list               `|Y       |`List ISO7816 history`
|`emv roca               `|N       |`Extract public keys and run ROCA test`


### hf

 { High frequency commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`hf help                `|Y       |`This help`
|`hf list                `|Y       |`List protocol data in trace buffer`
|`hf plot                `|N       |`Plot signal`
|`hf tune                `|N       |`Continuously measure HF antenna tuning`
|`hf search              `|Y       |`Search for known HF tags`
|`hf sniff               `|N       |`<samples to skip (10000)> <triggers to skip (1)> Generic HF Sniff`


### hf 14a

 { ISO14443A RFIDs...               }

|command                  |offline |description
|-------                  |------- |-----------
|`hf 14a help            `|Y       |`This help`
|`hf 14a list            `|Y       |`List ISO 14443-a history`
|`hf 14a info            `|N       |`Tag information`
|`hf 14a reader          `|N       |`Act like an ISO14443-a reader`
|`hf 14a cuids           `|N       |`<n> Collect n>0 ISO14443-a UIDs in one go`
|`hf 14a sim             `|N       |`<UID> -- Simulate ISO 14443-a tag`
|`hf 14a sniff           `|N       |`Sniff ISO 14443-a traffic`
|`hf 14a apdu            `|N       |`Send ISO 14443-4 APDU to tag`
|`hf 14a chaining        `|N       |`Control ISO 14443-4 input chaining`
|`hf 14a raw             `|N       |`Send raw hex data to tag`
|`hf 14a antifuzz        `|N       |`Fuzzing the anticollision phase.  Warning! Readers may react strange`
|`hf 14a config          `|N       |`Configure 14a settings (use with caution)`


### hf 14b

 { ISO14443B RFIDs...               }

|command                  |offline |description
|-------                  |------- |-----------
|`hf 14b help            `|Y       |`This help`
|`hf 14b apdu            `|N       |`Send ISO 14443-4 APDU to tag`
|`hf 14b dump            `|N       |`Read all memory pages of an ISO14443-B tag, save to file`
|`hf 14b info            `|N       |`Tag information`
|`hf 14b list            `|Y       |`List ISO 14443B history`
|`hf 14b ndef            `|N       |`Read NDEF file on tag`
|`hf 14b raw             `|N       |`Send raw hex data to tag`
|`hf 14b reader          `|N       |`Act as a 14443B reader to identify a tag`
|`hf 14b sim             `|N       |`Fake ISO 14443B tag`
|`hf 14b sniff           `|N       |`Eavesdrop ISO 14443B`
|`hf 14b rdbl            `|N       |`Read SRI512/SRIX4x block`
|`hf 14b sriwrite        `|N       |`Write data to a SRI512 | SRIX4K tag`


### hf 15

 { ISO15693 RFIDs...                }

|command                  |offline |description
|-------                  |------- |-----------
|`hf 15 help             `|Y       |`This help`
|`hf 15 list             `|Y       |`List ISO15693 history`
|`hf 15 demod            `|Y       |`Demodulate ISO15693 from tag`
|`hf 15 dump             `|N       |`Read all memory pages of an ISO15693 tag, save to file`
|`hf 15 info             `|N       |`Tag information`
|`hf 15 sniff            `|N       |`Sniff ISO15693 traffic`
|`hf 15 raw              `|N       |`Send raw hex data to tag`
|`hf 15 rdbl             `|N       |`Read a block`
|`hf 15 reader           `|N       |`Act like an ISO15693 reader`
|`hf 15 readmulti        `|N       |`Reads multiple Blocks`
|`hf 15 restore          `|N       |`Restore from file to all memory pages of an ISO15693 tag`
|`hf 15 samples          `|N       |`Acquire Samples as Reader (enables carrier, sends inquiry)`
|`hf 15 sim              `|N       |`Fake an ISO15693 tag`
|`hf 15 wrbl             `|N       |`Write a block`
|`hf 15 findafi          `|N       |`Brute force AFI of an ISO15693 tag`
|`hf 15 writeafi         `|N       |`Writes the AFI on an ISO15693 tag`
|`hf 15 writedsfid       `|N       |`Writes the DSFID on an ISO15693 tag`
|`hf 15 csetuid          `|N       |`Set UID for magic Chinese card`


### hf epa

 { German Identification Card...    }

|command                  |offline |description
|-------                  |------- |-----------
|`hf epa help            `|Y       |`This help`
|`hf epa cnonces         `|N       |`<m> <n> <d> Acquire n>0 encrypted PACE nonces of size m>0 with d sec pauses`
|`hf epa preplay         `|N       |`<mse> <get> <map> <pka> <ma> Perform PACE protocol by replaying given APDUs`


### hf felica

 { ISO18092 / FeliCa RFIDs...       }

|command                  |offline |description
|-------                  |------- |-----------
|`hf felica help         `|Y       |`This help`
|`hf felica list         `|Y       |`List ISO 18092/FeliCa history`
|`hf felica reader       `|N       |`Act like an ISO18092/FeliCa reader`
|`hf felica sniff        `|N       |`Sniff ISO 18092/FeliCa traffic`
|`hf felica raw          `|N       |`Send raw hex data to tag`
|`hf felica rdunencrypted`|N       |`Read Block Data from authentication-not-required Service.`
|`hf felica wrunencrypted`|N       |`Write Block Data to an authentication-not-required Service.`
|`hf felica rqservice    `|N       |`Verify the existence of Area and Service, and to acquire Key Version.`
|`hf felica rqresponse   `|N       |`Verify the existence of a card and its Mode.`
|`hf felica scsvcode     `|N       |`Acquire Area Code and Service Code.`
|`hf felica rqsyscode    `|N       |`Acquire System Code registered to the card.`
|`hf felica auth1        `|N       |`Authenticate a card. Start mutual authentication with Auth1`
|`hf felica auth2        `|N       |`Allow a card to authenticate a Reader/Writer. Complete mutual authentication`
|`hf felica rqspecver    `|N       |`Acquire the version of card OS.`
|`hf felica resetmode    `|N       |`Reset Mode to Mode 0.`
|`hf felica litesim      `|N       |`<NDEF2> - only reply to poll request`
|`hf felica litedump     `|N       |`Wait for and try dumping FelicaLite`


### hf fido

 { FIDO and FIDO2 authenticators... }

|command                  |offline |description
|-------                  |------- |-----------
|`hf fido help           `|Y       |`This help.`
|`hf fido list           `|N       |`List ISO 14443A history`
|`hf fido info           `|N       |`Info about FIDO tag.`
|`hf fido reg            `|N       |`FIDO U2F Registration Message.`
|`hf fido auth           `|N       |`FIDO U2F Authentication Message.`
|`hf fido make           `|N       |`FIDO2 MakeCredential command.`
|`hf fido assert         `|N       |`FIDO2 GetAssertion command.`


### hf iclass

 { ICLASS RFIDs...                  }

|command                  |offline |description
|-------                  |------- |-----------
|`hf iclass help         `|Y       |`This help`
|`hf iclass dump         `|N       |`[options..] Dump Picopass / iCLASS tag to file`
|`hf iclass info         `|Y       |`            Tag information`
|`hf iclass list         `|Y       |`            List iclass history`
|`hf iclass rdbl         `|N       |`[options..] Read Picopass / iCLASS block`
|`hf iclass reader       `|N       |`            Act like an Picopass / iCLASS reader`
|`hf iclass restore      `|N       |`[options..] Restore a dump file onto a Picopass / iCLASS tag`
|`hf iclass sniff        `|N       |`            Eavesdrop Picopass / iCLASS communication`
|`hf iclass wrbl         `|N       |`[options..] Write Picopass / iCLASS block`
|`hf iclass autopwn      `|N       |`[options..] Automatic key recovery tool for iCLASS`
|`hf iclass chk          `|N       |`[options..] Check keys`
|`hf iclass loclass      `|Y       |`[options..] Use loclass to perform bruteforce reader attack`
|`hf iclass lookup       `|Y       |`[options..] Uses authentication trace to check for key in dictionary file`
|`hf iclass sim          `|N       |`[options..] Simulate iCLASS tag`
|`hf iclass eload        `|N       |`[f <fn>   ] Load Picopass / iCLASS dump file into emulator memory`
|`hf iclass esave        `|N       |`[f <fn>   ] Save emulator memory to file`
|`hf iclass eview        `|N       |`[options..] View emulator memory`
|`hf iclass calcnewkey   `|Y       |`[options..] Calc diversified keys (blocks 3 & 4) to write new keys`
|`hf iclass encrypt      `|Y       |`[options..] Encrypt given block data`
|`hf iclass decrypt      `|Y       |`[options..] Decrypt given block data or tag dump file`
|`hf iclass managekeys   `|Y       |`[options..] Manage keys to use with iclass commands`
|`hf iclass permute      `|N       |`            Permute function from 'heart of darkness' paper`
|`hf iclass view         `|Y       |`[options..] Display content from tag dump file`


### hf legic

 { LEGIC RFIDs...                   }

|command                  |offline |description
|-------                  |------- |-----------
|`hf legic help          `|Y       |`This help`
|`hf legic list          `|Y       |`List LEGIC history`
|`hf legic reader        `|N       |`LEGIC Prime Reader UID and tag info`
|`hf legic info          `|N       |`Display deobfuscated and decoded LEGIC Prime tag data`
|`hf legic dump          `|N       |`Dump LEGIC Prime tag to binary file`
|`hf legic restore       `|N       |`Restore a dump file onto a LEGIC Prime tag`
|`hf legic rdbl          `|N       |`Read bytes from a LEGIC Prime tag`
|`hf legic sim           `|N       |`Start tag simulator`
|`hf legic wrbl          `|N       |`Write data to a LEGIC Prime tag`
|`hf legic crc           `|Y       |`Calculate Legic CRC over given bytes`
|`hf legic eload         `|Y       |`Load binary dump to emulator memory`
|`hf legic esave         `|Y       |`Save emulator memory to binary file`
|`hf legic wipe          `|N       |`Wipe a LEGIC Prime tag`


### hf lto

 { LTO Cartridge Memory RFIDs...    }

|command                  |offline |description
|-------                  |------- |-----------
|`hf lto help            `|Y       |`This help`
|`hf lto dump            `|N       |`Dump LTO-CM tag to file`
|`hf lto restore         `|N       |`Restore dump file to LTO-CM tag`
|`hf lto info            `|N       |`Tag information`
|`hf lto rdbl            `|N       |`Read block`
|`hf lto wrbl            `|N       |`Write block`
|`hf lto list            `|Y       |`List LTO-CM history`


### hf mf

 { MIFARE RFIDs...                  }

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
|`hf mf decrypt          `|Y       |`[nt] [ar_enc] [at_enc] [data] - to decrypt sniff or trace`
|`hf mf supercard        `|N       |`Extract info from a `super card``
|`hf mf auth4            `|N       |`ISO14443-4 AES authentication`
|`hf mf dump             `|N       |`Dump MIFARE Classic tag to binary file`
|`hf mf mad              `|N       |`Checks and prints MAD`
|`hf mf ndef             `|N       |`Prints NDEF records from card`
|`hf mf personalize      `|N       |`Personalize UID (MIFARE Classic EV1 only)`
|`hf mf rdbl             `|N       |`Read MIFARE Classic block`
|`hf mf rdsc             `|N       |`Read MIFARE Classic sector`
|`hf mf restore          `|N       |`Restore MIFARE Classic binary file to BLANK tag`
|`hf mf setmod           `|N       |`Set MIFARE Classic EV1 load modulation strength`
|`hf mf wrbl             `|N       |`Write MIFARE Classic block`
|`hf mf sim              `|N       |`Simulate MIFARE card`
|`hf mf ecfill           `|N       |`Fill simulator memory with help of keys from simulator`
|`hf mf eclr             `|N       |`Clear simulator memory`
|`hf mf egetblk          `|N       |`Get simulator memory block`
|`hf mf egetsc           `|N       |`Get simulator memory sector`
|`hf mf ekeyprn          `|N       |`Print keys from simulator memory`
|`hf mf eload            `|N       |`Load from file emul dump`
|`hf mf esave            `|N       |`Save to file emul dump`
|`hf mf eset             `|N       |`Set simulator memory block`
|`hf mf eview            `|N       |`View emul memory`
|`hf mf cgetblk          `|N       |`Read block`
|`hf mf cgetsc           `|N       |`Read sector`
|`hf mf cload            `|N       |`Load dump`
|`hf mf csave            `|N       |`Save dump from card into file or emulator`
|`hf mf csetblk          `|N       |`Write block`
|`hf mf csetuid          `|N       |`Set UID`
|`hf mf cview            `|N       |`View card`
|`hf mf cwipe            `|N       |`Wipe card to default UID/Sectors/Keys`
|`hf mf gen3uid          `|N       |`Set UID without manufacturer block`
|`hf mf gen3blk          `|N       |`Overwrite full manufacturer block`
|`hf mf gen3freeze       `|N       |`Perma lock further UID changes`
|`hf mf ice              `|N       |`Collect MIFARE Classic nonces to file`


### hf mfp

 { MIFARE Plus RFIDs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mfp help            `|Y       |`This help`
|`hf mfp info            `|N       |`Info about Mifare Plus tag`
|`hf mfp wrp             `|N       |`Write Perso command`
|`hf mfp initp           `|N       |`Fills all the card's keys`
|`hf mfp commitp         `|N       |`Move card to SL1 or SL3 mode`
|`hf mfp auth            `|N       |`Authentication`
|`hf mfp rdbl            `|N       |`Read blocks`
|`hf mfp rdsc            `|N       |`Read sectors`
|`hf mfp wrbl            `|N       |`Write blocks`
|`hf mfp chk             `|N       |`Check keys`
|`hf mfp mad             `|N       |`Checks and prints MAD`
|`hf mfp ndef            `|N       |`Prints NDEF records from card`


### hf mfu

 { MIFARE Ultralight RFIDs...       }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mfu help            `|Y       |`This help`
|`hf mfu info            `|N       |`Tag information`
|`hf mfu dump            `|N       |`Dump Ultralight / Ultralight-C / NTAG tag to binary file`
|`hf mfu restore         `|N       |`Restore a dump onto a MFU MAGIC tag`
|`hf mfu eload           `|N       |`Load Ultralight .eml dump file into emulator memory`
|`hf mfu rdbl            `|N       |`Read block`
|`hf mfu wrbl            `|N       |`Write block`
|`hf mfu cauth           `|N       |`Authentication    - Ultralight C`
|`hf mfu setpwd          `|N       |`Set 3des password - Ultralight-C`
|`hf mfu setuid          `|N       |`Set UID - MAGIC tags only`
|`hf mfu sim             `|N       |`Simulate Ultralight from emulator memory`
|`hf mfu gen             `|Y       |`Generate 3des mifare diversified keys`
|`hf mfu pwdgen          `|Y       |`Generate pwd from known algos`
|`hf mfu otptear         `|N       |`Tear-off test on OTP bits`
|`hf mfu ndef            `|N       |`Prints NDEF records from card`


### hf mfdes

 { MIFARE Desfire RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf mfdes help          `|Y       |`This help`
|`hf mfdes info          `|N       |`Tag information`
|`hf mfdes list          `|Y       |`List DESFire (ISO 14443A) history`
|`hf mfdes enum          `|N       |`Tries enumerate all applications`
|`hf mfdes auth          `|N       |`Tries a MIFARE DesFire Authentication`
|`hf mfdes getuid        `|N       |`Get random uid`
|`hf mfdes selectaid     `|N       |`Select Application ID`
|`hf mfdes createaid     `|N       |`Create Application ID`
|`hf mfdes deleteaid     `|N       |`Delete Application ID`
|`hf mfdes createfile    `|N       |`Create Standard/Backup File`
|`hf mfdes createvaluefile`|N       |`Create Value File`
|`hf mfdes createrecordfile`|N       |`Create Linear/Cyclic Record File`
|`hf mfdes deletefile    `|N       |`Create Delete File`
|`hf mfdes clearfile     `|N       |`Clear record File`
|`hf mfdes readdata      `|N       |`Read data from standard/backup/record file`
|`hf mfdes writedata     `|N       |`Write data to standard/backup/record file`
|`hf mfdes getvalue      `|N       |`Get value of file`
|`hf mfdes changevalue   `|N       |`Write value of a value file (credit/debit/clear)`
|`hf mfdes changekey     `|N       |`Change Key`
|`hf mfdes formatpicc    `|N       |`Format PICC`
|`hf mfdes dump          `|N       |`Dump all files`
|`hf mfdes chk           `|N       |`Check keys`


### hf st

 { ST Rothult RFIDs...              }

|command                  |offline |description
|-------                  |------- |-----------
|`hf st help             `|Y       |`This help`
|`hf st info             `|N       |`Tag information`
|`hf st list             `|Y       |`List ISO 14443A/7816 history`
|`hf st ndef             `|Y       |`Read NDEF file on tag`
|`hf st protect          `|N       |`Change protection on tag`
|`hf st pwd              `|N       |`Change password on tag`
|`hf st sim              `|N       |`Fake ISO 14443A/ST tag`


### hf thinfilm

 { Thinfilm RFIDs...                }

|command                  |offline |description
|-------                  |------- |-----------
|`hf thinfilm help       `|Y       |`This help`
|`hf thinfilm info       `|N       |`Tag information`
|`hf thinfilm list       `|Y       |`List NFC Barcode / Thinfilm history - not correct`
|`hf thinfilm sim        `|N       |`Fake Thinfilm tag`


### hf topaz

 { TOPAZ (NFC Type 1) RFIDs...      }

|command                  |offline |description
|-------                  |------- |-----------
|`hf topaz help          `|Y       |`This help`
|`hf topaz list          `|Y       |`List Topaz history`
|`hf topaz info          `|N       |`Tag information`
|`hf topaz reader        `|N       |`Act like a Topaz reader`
|`hf topaz sim           `|N       |`<UID> -- Simulate Topaz tag`
|`hf topaz sniff         `|N       |`Sniff Topaz reader-tag communication`
|`hf topaz raw           `|N       |`Send raw hex data to tag`


### hf waveshare

 { Waveshare NFC ePaper...          }

|command                  |offline |description
|-------                  |------- |-----------
|`hf waveshare help      `|Y       |`This help`
|`hf waveshare loadbmp   `|N       |`Load BMP file to Waveshare NFC ePaper`


### hw

 { Hardware commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`hw help                `|Y       |`This help`
|`hw connect             `|Y       |`Connect Proxmark3 to serial port`
|`hw dbg                 `|N       |`Set Proxmark3 debug level`
|`hw detectreader        `|N       |`['l'|'h'] -- Detect external reader field (option 'l' or 'h' to limit to LF or HF)`
|`hw fpgaoff             `|N       |`Set FPGA off`
|`hw lcd                 `|N       |`<HEX command> <count> -- Send command/data to LCD`
|`hw lcdreset            `|N       |`Hardware reset LCD`
|`hw ping                `|N       |`Test if the Proxmark3 is responsive`
|`hw readmem             `|N       |`[address] -- Read memory at decimal address from flash`
|`hw reset               `|N       |`Reset the Proxmark3`
|`hw setlfdivisor        `|N       |`<19 - 255> -- Drive LF antenna at 12MHz/(divisor+1)`
|`hw setmux              `|N       |`Set the ADC mux to a specific value`
|`hw standalone          `|N       |`Jump to the standalone mode`
|`hw status              `|N       |`Show runtime status information about the connected Proxmark3`
|`hw tearoff             `|N       |`Program a tearoff hook for the next command supporting tearoff`
|`hw tia                 `|N       |`Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider`
|`hw tune                `|N       |`Measure antenna tuning`
|`hw version             `|N       |`Show version information about the connected Proxmark3`


### lf

 { Low frequency commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf help                `|Y       |`This help`
|`lf config              `|N       |`Get/Set config for LF sampling, bit/sample, decimation, frequency`
|`lf cmdread             `|N       |`Modulate LF reader field to send command before read (all periods in microseconds)`
|`lf read                `|N       |`Read LF tag`
|`lf search              `|Y       |`Read and Search for valid known tag (in offline mode it you can load first then search)`
|`lf sim                 `|N       |`Simulate LF tag from buffer with optional GAP (in microseconds)`
|`lf simask              `|N       |`Simulate LF ASK tag from demodbuffer or input`
|`lf simfsk              `|N       |`Simulate LF FSK tag from demodbuffer or input`
|`lf simpsk              `|N       |`Simulate LF PSK tag from demodbuffer or input`
|`lf simbidir            `|N       |`Simulate LF tag (with bidirectional data transmission between reader and tag)`
|`lf sniff               `|N       |`Sniff LF traffic between reader and tag`
|`lf tune                `|N       |`Continuously measure LF antenna tuning`


### lf awid

 { AWID RFIDs...              }

|command                  |offline |description
|-------                  |------- |-----------
|`lf awid help           `|Y       |`This help`
|`lf awid demod          `|Y       |`Demodulate an AWID FSK tag from the GraphBuffer`
|`lf awid read           `|N       |`Attempt to read and extract tag data`
|`lf awid clone          `|N       |`Clone AWID tag to T55x7 or Q5/T5555`
|`lf awid sim            `|N       |`Simulate AWID tag`
|`lf awid brute          `|N       |`Bruteforce card number against reader`
|`lf awid watch          `|N       |`Continuously watch for cards.  Reader mode`


### lf cotag

 { COTAG CHIPs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf cotag help          `|Y       |`This help`
|`lf cotag demod         `|Y       |`Tries to decode a COTAG signal`
|`lf cotag read          `|N       |`Attempt to read and extract tag data`


### lf destron

 { FDX-A Destron RFIDs...     }

|command                  |offline |description
|-------                  |------- |-----------
|`lf destron help        `|Y       |`This help`
|`lf destron demod       `|Y       |`Demodulate an Destron tag from the GraphBuffer`
|`lf destron read        `|N       |`Attempt to read and extract tag data from the antenna`
|`lf destron clone       `|N       |`Clone Destron tag to T55x7`
|`lf destron sim         `|N       |`Simulate Destron tag`


### lf em

 { EM4X CHIPs & RFIDs...      }

|command                  |offline |description
|-------                  |------- |-----------
|`lf em help             `|Y       |`This help`
|`lf em 410x_demod       `|Y       |`Demodulate a EM410x tag from the GraphBuffer`
|`lf em 410x_read        `|N       |`Attempt to read and extract tag data`
|`lf em 410x_sim         `|N       |`Simulate EM410x tag`
|`lf em 410x_brute       `|N       |`Reader bruteforce attack by simulating EM410x tags`
|`lf em 410x_watch       `|N       |`Watches for EM410x 125/134 kHz tags (option 'h' for 134)`
|`lf em 410x_spoof       `|N       |`Watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)`
|`lf em 410x_clone       `|N       |`Write EM410x UID to T55x7 or Q5/T5555 tag`
|`lf em 4x05_chk         `|N       |`Check passwords from dictionary`
|`lf em 4x05_demod       `|Y       |`Demodulate a EM4x05/EM4x69 tag from the GraphBuffer`
|`lf em 4x05_dump        `|N       |`Dump EM4x05/EM4x69 tag`
|`lf em 4x05_wipe        `|N       |`Wipe EM4x05/EM4x69 tag`
|`lf em 4x05_info        `|N       |`Tag information EM4x05/EM4x69`
|`lf em 4x05_read        `|N       |`Read word data from EM4x05/EM4x69`
|`lf em 4x05_write       `|N       |`Write word data to EM4x05/EM4x69`
|`lf em 4x05_unlock      `|N       |`Execute tear off against EM4x05/EM4x69`
|`lf em 4x05_sniff       `|Y       |`Attempt to recover em4x05 commands from sample buffer`
|`lf em 4x05_brute       `|N       |`Bruteforce password`
|`lf em 4x50_dump        `|N       |`Dump EM4x50 tag`
|`lf em 4x50_info        `|N       |`Tag information EM4x50`
|`lf em 4x50_write       `|N       |`Write word data to EM4x50`
|`lf em 4x50_write_password`|N       |`Change password of EM4x50 tag`
|`lf em 4x50_read        `|N       |`Read word data from EM4x50`
|`lf em 4x50_wipe        `|N       |`Wipe data from EM4x50`


### lf fdxb

 { FDX-B RFIDs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf fdxb help           `|Y       |`This help`
|`lf fdxb demod          `|Y       |`Demodulate a FDX-B ISO11784/85 tag from the GraphBuffer`
|`lf fdxb read           `|N       |`Attempt to read at 134kHz and extract tag data`
|`lf fdxb clone          `|N       |`Clone animal ID tag to T55x7 or Q5/T5555`
|`lf fdxb sim            `|N       |`Simulate Animal ID tag`


### lf gallagher

 { GALLAGHER RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`lf gallagher help      `|Y       |`This help`
|`lf gallagher demod     `|Y       |`Demodulate an GALLAGHER tag from the GraphBuffer`
|`lf gallagher read      `|N       |`Attempt to read and extract tag data from the antenna`
|`lf gallagher clone     `|N       |`Clone GALLAGHER tag to T55x7`
|`lf gallagher sim       `|N       |`Simulate GALLAGHER tag`


### lf gproxii

 { Guardall Prox II RFIDs...  }

|command                  |offline |description
|-------                  |------- |-----------
|`lf gproxii help        `|Y       |`This help`
|`lf gproxii demod       `|Y       |`Demodulate a G Prox II tag from the GraphBuffer`
|`lf gproxii read        `|N       |`Attempt to read and extract tag data from the antenna`
|`lf gproxii clone       `|N       |`Clone Guardall tag to T55x7 or Q5/T5555`
|`lf gproxii sim         `|N       |`Simulate Guardall tag`


### lf hid

 { HID Prox RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf hid help            `|Y       |`This help`
|`lf hid demod           `|Y       |`Demodulate HID Prox tag from the GraphBuffer`
|`lf hid read            `|N       |`Attempt to read and extract tag data`
|`lf hid clone           `|N       |`Clone HID tag to T55x7`
|`lf hid sim             `|N       |`Simulate HID tag`
|`lf hid brute           `|N       |`Bruteforce card number against reader`
|`lf hid watch           `|N       |`Continuously watch for cards.  Reader mode`


### lf hitag

 { Hitag CHIPs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf hitag help          `|Y       |`This help`
|`lf hitag list          `|N       |`List Hitag trace history`
|`lf hitag info          `|N       |`Tag information`
|`lf hitag reader        `|N       |`Act like a Hitag Reader`
|`lf hitag sim           `|N       |`Simulate Hitag transponder`
|`lf hitag sniff         `|N       |`Eavesdrop Hitag communication`
|`lf hitag writer        `|N       |`Act like a Hitag Writer`
|`lf hitag dump          `|N       |`Dump Hitag2 tag`
|`lf hitag cc            `|N       |`Test all challenges`


### lf idteck

 { Idteck RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf idteck help         `|Y       |`This help`
|`lf idteck demod        `|Y       |`Demodulate an Idteck tag from the GraphBuffer`
|`lf idteck read         `|N       |`Attempt to read and Extract tag data from the antenna`


### lf indala

 { Indala RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf indala help         `|Y       |`This help`
|`lf indala demod        `|Y       |`Demodulate an indala tag (PSK1) from GraphBuffer`
|`lf indala altdemod     `|Y       |`Alternative method to Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)`
|`lf indala read         `|N       |`Read an Indala Prox tag from the antenna`
|`lf indala clone        `|N       |`Clone Indala tag to T55x7 or Q5/T5555`
|`lf indala sim          `|N       |`Simulate Indala tag`


### lf io

 { ioProx RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf io help             `|Y       |`This help`
|`lf io demod            `|Y       |`Demodulate an IOProx tag from the GraphBuffer`
|`lf io read             `|N       |`Attempt to read and extract tag data`
|`lf io clone            `|N       |`Clone IOProx tag to T55x7 or Q5/T5555`
|`lf io sim              `|N       |`Simulate IOProx tag`
|`lf io watch            `|N       |`Continuously watch for cards. Reader mode`


### lf jablotron

 { Jablotron RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`lf jablotron help      `|Y       |`This help`
|`lf jablotron demod     `|Y       |`Demodulate an Jablotron tag from the GraphBuffer`
|`lf jablotron read      `|N       |`Attempt to read and extract tag data from the antenna`
|`lf jablotron clone     `|N       |`Clone jablotron tag to T55x7 or Q5/T5555`
|`lf jablotron sim       `|N       |`Simulate jablotron tag`


### lf keri

 { KERI RFIDs...              }

|command                  |offline |description
|-------                  |------- |-----------
|`lf keri help           `|Y       |`This help`
|`lf keri demod          `|Y       |`Demodulate an KERI tag from the GraphBuffer`
|`lf keri read           `|N       |`Attempt to read and extract tag data from the antenna`
|`lf keri clone          `|N       |`Clone KERI tag to T55x7 or Q5/T5555`
|`lf keri sim            `|N       |`Simulate KERI tag`


### lf motorola

 { Motorola RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf motorola help       `|Y       |`This help`
|`lf motorola demod      `|Y       |`Demodulate an MOTOROLA tag from the GraphBuffer`
|`lf motorola read       `|N       |`Attempt to read and extract tag data from the antenna`
|`lf motorola clone      `|N       |`Clone MOTOROLA tag to T55x7`
|`lf motorola sim        `|N       |`Simulate MOTOROLA tag`


### lf nedap

 { Nedap RFIDs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf nedap help          `|Y       |`This help`
|`lf nedap demod         `|Y       |`Demodulate Nedap tag from the GraphBuffer`
|`lf nedap generate      `|Y       |`Generate Nedap bitstream in DemodBuffer`
|`lf nedap read          `|N       |`Attempt to read and extract tag data from the antenna`
|`lf nedap clone         `|N       |`Clone Nedap tag to T55x7 or Q5/T5555`
|`lf nedap sim           `|N       |`Simulate Nedap tag`


### lf nexwatch

 { NexWatch RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf nexwatch help       `|Y       |`This help`
|`lf nexwatch demod      `|Y       |`Demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer`
|`lf nexwatch read       `|N       |`Attempt to Read and Extract tag data from the antenna`
|`lf nexwatch clone      `|N       |`Clone NexWatch tag to T55x7`
|`lf nexwatch sim        `|N       |`Simulate NexWatch tag`


### lf noralsy

 { Noralsy RFIDs...           }

|command                  |offline |description
|-------                  |------- |-----------
|`lf noralsy help        `|Y       |`This help`
|`lf noralsy demod       `|Y       |`Demodulate an Noralsy tag from the GraphBuffer`
|`lf noralsy read        `|N       |`Attempt to read and extract tag data from the antenna`
|`lf noralsy clone       `|N       |`Clone Noralsy tag to T55x7 or Q5/T5555`
|`lf noralsy sim         `|N       |`Simulate Noralsy tag`


### lf pac

 { PAC/Stanley RFIDs...       }

|command                  |offline |description
|-------                  |------- |-----------
|`lf pac help            `|Y       |`This help`
|`lf pac demod           `|Y       |`Demodulate a PAC tag from the GraphBuffer`
|`lf pac read            `|N       |`Attempt to read and extract tag data from the antenna`
|`lf pac clone           `|N       |`Clone PAC tag to T55x7`
|`lf pac sim             `|N       |`Simulate PAC tag`


### lf paradox

 { Paradox RFIDs...           }

|command                  |offline |description
|-------                  |------- |-----------
|`lf paradox help        `|Y       |`This help`
|`lf paradox demod       `|Y       |`Demodulate a Paradox FSK tag from the GraphBuffer`
|`lf paradox read        `|N       |`Attempt to read and Extract tag data from the antenna`
|`lf paradox clone       `|N       |`Clone paradox tag to T55x7`
|`lf paradox sim         `|N       |`Simulate paradox tag`


### lf pcf7931

 { PCF7931 CHIPs...           }

|command                  |offline |description
|-------                  |------- |-----------
|`lf pcf7931 help        `|Y       |`This help`
|`lf pcf7931 read        `|N       |`Read content of a PCF7931 transponder`
|`lf pcf7931 write       `|N       |`Write data on a PCF7931 transponder.`
|`lf pcf7931 config      `|Y       |`Configure the password, the tags initialization delay and time offsets (optional)`


### lf presco

 { Presco RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf presco help         `|Y       |`This help`
|`lf presco demod        `|Y       |`Demodulate Presco tag from the GraphBuffer`
|`lf presco read         `|N       |`Attempt to read and Extract tag data`
|`lf presco clone        `|N       |`Clone presco tag to T55x7 or Q5/T5555`
|`lf presco sim          `|N       |`Simulate presco tag`


### lf pyramid

 { Farpointe/Pyramid RFIDs... }

|command                  |offline |description
|-------                  |------- |-----------
|`lf pyramid help        `|Y       |`This help`
|`lf pyramid demod       `|Y       |`Demodulate a Pyramid FSK tag from the GraphBuffer`
|`lf pyramid read        `|N       |`Attempt to read and extract tag data`
|`lf pyramid clone       `|N       |`Clone pyramid tag to T55x7 or Q5/T5555`
|`lf pyramid sim         `|N       |`Simulate pyramid tag`


### lf securakey

 { Securakey RFIDs...         }

|command                  |offline |description
|-------                  |------- |-----------
|`lf securakey help      `|Y       |`This help`
|`lf securakey demod     `|Y       |`Demodulate an Securakey tag from the GraphBuffer`
|`lf securakey read      `|N       |`Attempt to read and extract tag data from the antenna`
|`lf securakey clone     `|N       |`Clone Securakey tag to T55x7`
|`lf securakey sim       `|N       |`Simulate Securakey tag`


### lf ti

 { TI CHIPs...                }

|command                  |offline |description
|-------                  |------- |-----------
|`lf ti help             `|Y       |`This help`
|`lf ti demod            `|Y       |`Demodulate raw bits for TI-type LF tag from the GraphBuffer`
|`lf ti read             `|N       |`Read and decode a TI 134 kHz tag`
|`lf ti write            `|N       |`Write new data to a r/w TI 134 kHz tag`


### lf t55xx

 { T55xx CHIPs...             }

|command                  |offline |description
|-------                  |------- |-----------
|`lf t55xx help          `|Y       |`This help`
|`lf t55xx clonehelp     `|N       |`Shows the available clone commands`
|`lf t55xx config        `|Y       |`Set/Get T55XX configuration (modulation, inverted, offset, rate)`
|`lf t55xx dangerraw     `|N       |`Sends raw bitstream. Dangerous, do not use!! b <bitstream> t <timing>`
|`lf t55xx detect        `|Y       |`[1] Try detecting the tag modulation from reading the configuration block.`
|`lf t55xx deviceconfig  `|N       |`Set/Get T55XX device configuration (startgap, writegap, write0, write1, readgap`
|`lf t55xx dump          `|N       |`[password] [o] Dump T55xx card Page 0 block 0-7. Optional [password], [override]`
|`lf t55xx info          `|Y       |`[1] Show T55x7 configuration data (page 0/ blk 0)`
|`lf t55xx p1detect      `|N       |`[1] Try detecting if this is a t55xx tag by reading page 1`
|`lf t55xx read          `|N       |`b <block> p [password] [o] [1] -- Read T55xx block data. Optional [p password], [override], [page1]`
|`lf t55xx resetread     `|N       |`Send Reset Cmd then lf read the stream to attempt to identify the start of it (needs a demod and/or plot after)`
|`lf t55xx restore       `|N       |`f <filename> [p <password>] Restore T55xx card Page 0 / Page 1 blocks`
|`lf t55xx trace         `|Y       |`[1] Show T55x7 traceability data (page 1/ blk 0-1)`
|`lf t55xx wakeup        `|N       |`Send AOR wakeup command`
|`lf t55xx write         `|N       |`b <block> d <data> p [password] [1] -- Write T55xx block data. Optional [p password], [page1]`
|`lf t55xx bruteforce    `|N       |`<start password> <end password> Simple bruteforce attack to find password`
|`lf t55xx chk           `|N       |`Check passwords from dictionary/flash`
|`lf t55xx protect       `|N       |`Password protect tag`
|`lf t55xx recoverpw     `|N       |`[password] Try to recover from bad password write from a cloner. Only use on PW protected chips!`
|`lf t55xx sniff         `|Y       |`Attempt to recover T55xx commands from sample buffer`
|`lf t55xx special       `|N       |`Show block changes with 64 different offsets`
|`lf t55xx wipe          `|N       |`[q] Wipe a T55xx tag and set defaults (will destroy any data on tag)`


### lf viking

 { Viking RFIDs...            }

|command                  |offline |description
|-------                  |------- |-----------
|`lf viking help         `|Y       |`This help`
|`lf viking demod        `|Y       |`Demodulate a Viking tag from the GraphBuffer`
|`lf viking read         `|N       |`Attempt to read and Extract tag data from the antenna`
|`lf viking clone        `|N       |`Clone Viking tag to T55x7 or Q5/T5555`
|`lf viking sim          `|N       |`Simulate Viking tag`


### lf visa2000

 { Visa2000 RFIDs...          }

|command                  |offline |description
|-------                  |------- |-----------
|`lf visa2000 help       `|Y       |`This help`
|`lf visa2000 demod      `|Y       |`Demodulate an VISA2000 tag from the GraphBuffer`
|`lf visa2000 read       `|N       |`Attempt to read and extract tag data from the antenna`
|`lf visa2000 clone      `|N       |`Clone Visa2000 tag to T55x7 or Q5/T5555`
|`lf visa2000 sim        `|N       |`Simulate Visa2000 tag`


### mem

 { Flash memory manipulation... }

|command                  |offline |description
|-------                  |------- |-----------
|`mem help               `|Y       |`This help`
|`mem baudrate           `|N       |`Set Flash memory Spi baudrate`
|`mem spiffs             `|N       |`High level SPI FileSystem Flash manipulation`
|`mem info               `|N       |`Flash memory information`
|`mem load               `|N       |`Load data into flash memory`
|`mem dump               `|N       |`Dump data from flash memory`
|`mem wipe               `|N       |`Wipe data from flash memory`


### reveng

 { CRC calculations from RevEng software }

[=] reveng: no mode switch specified. Use reveng -h for help.

### smart

 { Smart card ISO-7816 commands... }

|command                  |offline |description
|-------                  |------- |-----------
|`smart help             `|Y       |`This help`
|`smart list             `|N       |`List ISO 7816 history`
|`smart info             `|N       |`Tag information`
|`smart reader           `|N       |`Act like an IS07816 reader`
|`smart raw              `|N       |`Send raw hex data to tag`
|`smart upgrade          `|Y       |`Upgrade sim module firmware`
|`smart setclock         `|N       |`Set clock speed`
|`smart brute            `|N       |`Bruteforce SFI`


### script

 { Scripting commands }

|command                  |offline |description
|-------                  |------- |-----------
|`script help            `|Y       |`Usage info`
|`script list            `|Y       |`List available scripts`
|`script run             `|Y       |`<name> -- execute a script`


### trace

 { Trace manipulation... }

|command                  |offline |description
|-------                  |------- |-----------
|`trace help             `|Y       |`This help`
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
|`wiegand encode         `|Y       |`Encode to wiegand raw hex`
|`wiegand decode         `|Y       |`Convert raw hex to decoded wiegand format`


