    
|command                  |offline |description          
|-------                  |------- |-----------          
|`help                   `|Y       |`This help. Use '<command> help' for details of a particular command.`          
|`auto                   `|Y       |`Automated detection process for unknown tags`          
|`msleep                 `|Y       |`Add a pause in milliseconds`          
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
|`analyse a              `|Y       |`num bits test`          
|`analyse nuid           `|Y       |`create NUID from 7byte UID`          
|`analyse demodbuff      `|Y       |`Load binary string to demodbuffer`          

          
### data

 { Plot window / data buffer manipulation... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`data help              `|Y       |`This help`          
|`data askedgedetect     `|Y       |`[threshold] Adjust Graph for manual ASK demod using the length of sample differences to detect the edge of a wave (use 20-45, def:25)`          
|`data autocorr          `|Y       |`[window length] [g] -- Autocorrelation over window - g to save back to GraphBuffer (overwrite)`          
|`data biphaserawdecode  `|Y       |`[offset] [invert<0|1>] [maxErr] -- Biphase decode bin stream in DemodBuffer (offset = 0|1 bits to shift the decode start)`          
|`data bin2hex           `|Y       |`<digits> -- Converts binary to hexadecimal`          
|`data bitsamples        `|Y       |`Get raw samples as bitstring`          
|`data buffclear         `|Y       |`Clears bigbuff on deviceside and graph window`          
|`data convertbitstream  `|Y       |`Convert GraphBuffer's 0/1 values to 127 / -127`          
|`data dec               `|Y       |`Decimate samples`          
|`data detectclock       `|Y       |`[<a|f|n|p>] Detect ASK, FSK, NRZ, PSK clock rate of wave in GraphBuffer`          
|`data fsktonrz          `|Y       |`Convert fsk2 to nrz wave for alternate fsk demodulating (for weak fsk)`          
|`data getbitstream      `|Y       |`Convert GraphBuffer's >=1 values to 1 and <1 to 0`          
|`data grid              `|Y       |`<x> <y> -- overlay grid on graph window, use zero value to turn off either`          
|`data hexsamples        `|Y       |`<bytes> [<offset>] -- Dump big buffer as hex bytes`          
|`data hex2bin           `|Y       |`<hexadecimal> -- Converts hexadecimal to binary`          
|`data hide              `|Y       |`Hide graph window`          
|`data hpf               `|Y       |`Remove DC offset from trace`          
|`data load              `|Y       |`<filename> -- Load trace (to graph window`          
|`data ltrim             `|Y       |`<samples> -- Trim samples from left of trace`          
|`data rtrim             `|Y       |`<location to end trace> -- Trim samples from right of trace`          
|`data mtrim             `|Y       |`<start> <stop> -- Trim out samples from the specified start to the specified stop`          
|`data manrawdecode      `|Y       |`[invert] [maxErr] -- Manchester decode binary stream in DemodBuffer`          
|`data norm              `|Y       |`Normalize max/min to +/-128`          
|`data plot              `|Y       |`Show graph window (hit 'h' in window for keystroke help)`          
|`data printdemodbuffer  `|Y       |`[x] [o] <offset> [l] <length> -- print the data in the DemodBuffer - 'x' for hex output`          
|`data rawdemod          `|Y       |`[modulation] ... <options> -see help (h option) -- Demodulate the data in the GraphBuffer and output binary`          
|`data samples           `|Y       |`[512 - 40000] -- Get raw samples for graph window (GraphBuffer)`          
|`data save              `|Y       |`Save trace (from graph window)`          
|`data setgraphmarkers   `|Y       |`[orange_marker] [blue_marker] (in graph window)`          
|`data scale             `|Y       |`<int> -- Set cursor display scale in carrier frequency expressed in kHz`          
|`data setdebugmode      `|Y       |`<0|1|2> -- Set Debugging Level on client side`          
|`data shiftgraphzero    `|Y       |`<shift> -- Shift 0 for Graphed wave + or - shift value`          
|`data dirthreshold      `|Y       |`<thres up> <thres down> -- Max rising higher up-thres/ Min falling lower down-thres, keep rest as prev.`          
|`data tune              `|Y       |`Get hw tune samples for graph window`          
|`data undec             `|Y       |`Un-decimate samples by 2`          
|`data zerocrossings     `|Y       |`Count time between zero-crossings`          
|`data iir               `|Y       |`apply IIR buttersworth filter on plotdata`          

          
### emv

 { EMV ISO-14443 / ISO-7816... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`emv help               `|Y       |`This help`          
|`emv exec               `|Y       |`Executes EMV contactless transaction.`          
|`emv pse                `|Y       |`Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory.`          
|`emv search             `|Y       |`Try to select all applets from applets list and print installed applets.`          
|`emv select             `|Y       |`Select applet.`          
|`emv gpo                `|Y       |`Execute GetProcessingOptions.`          
|`emv readrec            `|Y       |`Read files from card.`          
|`emv genac              `|Y       |`Generate ApplicationCryptogram.`          
|`emv challenge          `|Y       |`Generate challenge.`          
|`emv intauth            `|Y       |`Internal authentication.`          
|`emv scan               `|Y       |`Scan EMV card and save it contents to json file for emulator.`          
|`emv test               `|Y       |`Crypto logic test.`          
|`emv list               `|Y       |`List ISO7816 history`          
|`emv roca               `|Y       |`Extract public keys and run ROCA test`          

          
### hf

 { High frequency commands... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf help                `|Y       |`This help`          
|`hf list                `|Y       |`List protocol data in trace buffer`          
|`hf tune                `|Y       |`Continuously measure HF antenna tuning`          
|`hf search              `|Y       |`Search for known HF tags`          
|`hf sniff               `|Y       |`<samples to skip (10000)> <triggers to skip (1)> Generic HF Sniff`          

          
### hf 14a

 { ISO14443A RFIDs...               }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf 14a help            `|Y       |`This help`          
|`hf 14a list            `|Y       |`List ISO 14443-a history`          
|`hf 14a info            `|Y       |`Tag information`          
|`hf 14a reader          `|Y       |`Act like an ISO14443-a reader`          
|`hf 14a cuids           `|Y       |`<n> Collect n>0 ISO14443-a UIDs in one go`          
|`hf 14a sim             `|Y       |`<UID> -- Simulate ISO 14443-a tag`          
|`hf 14a sniff           `|Y       |`sniff ISO 14443-a traffic`          
|`hf 14a apdu            `|Y       |`Send ISO 14443-4 APDU to tag`          
|`hf 14a chaining        `|Y       |`Control ISO 14443-4 input chaining`          
|`hf 14a raw             `|Y       |`Send raw hex data to tag`          
|`hf 14a antifuzz        `|Y       |`Fuzzing the anticollision phase.  Warning! Readers may react strange`          

          
### hf 14b

 { ISO14443B RFIDs...               }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf 14b help            `|Y       |`This help`          
|`hf 14b dump            `|Y       |`Read all memory pages of an ISO14443-B tag, save to file`          
|`hf 14b info            `|Y       |`Tag information`          
|`hf 14b list            `|Y       |`List ISO 14443B history`          
|`hf 14b raw             `|Y       |`Send raw hex data to tag`          
|`hf 14b reader          `|Y       |`Act as a 14443B reader to identify a tag`          
|`hf 14b sim             `|Y       |`Fake ISO 14443B tag`          
|`hf 14b sniff           `|Y       |`Eavesdrop ISO 14443B`          
|`hf 14b sriread         `|Y       |`Read contents of a SRI512 | SRIX4K tag`          
|`hf 14b sriwrite        `|Y       |`Write data to a SRI512 | SRIX4K tag`          

          
### hf 15

 { ISO15693 RFIDs...                }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf 15 help             `|Y       |`This help`          
|`hf 15 demod            `|Y       |`Demodulate ISO15693 from tag`          
|`hf 15 dump             `|Y       |`Read all memory pages of an ISO15693 tag, save to file`          
|`hf 15 findafi          `|Y       |`Brute force AFI of an ISO15693 tag`          
|`hf 15 writeafi         `|Y       |`Writes the AFI on an ISO15693 tag`          
|`hf 15 writedsfid       `|Y       |`Writes the DSFID on an ISO15693 tag`          
|`hf 15 info             `|Y       |`Tag information`          
|`hf 15 list             `|Y       |`List ISO15693 history`          
|`hf 15 raw              `|Y       |`Send raw hex data to tag`          
|`hf 15 reader           `|Y       |`Act like an ISO15693 reader`          
|`hf 15 record           `|Y       |`Record Samples (ISO15693)`          
|`hf 15 restore          `|Y       |`Restore from file to all memory pages of an ISO15693 tag`          
|`hf 15 sim              `|Y       |`Fake an ISO15693 tag`          
|`hf 15 samples          `|Y       |`Acquire Samples as Reader (enables carrier, sends inquiry)`          
|`hf 15 read             `|Y       |`Read a block`          
|`hf 15 write            `|Y       |`Write a block`          
|`hf 15 readmulti        `|Y       |`Reads multiple Blocks`          
|`hf 15 csetuid          `|Y       |`Set UID for magic Chinese card`          

          
### hf epa

 { German Identification Card...    }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf epa help            `|Y       |`This help`          
|`hf epa cnonces         `|Y       |`<m> <n> <d> Acquire n>0 encrypted PACE nonces of size m>0 with d sec pauses`          
|`hf epa preplay         `|Y       |`<mse> <get> <map> <pka> <ma> Perform PACE protocol by replaying given APDUs`          

          
### hf felica

 { ISO18092 / Felica RFIDs...       }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf felica help         `|Y       |`This help`          
|`hf felica list         `|Y       |`List ISO 18092/FeliCa history`          
|`hf felica reader       `|Y       |`Act like an ISO18092/FeliCa reader`          
|`hf felica sniff        `|Y       |`Sniff ISO 18092/FeliCa traffic`          
|`hf felica raw          `|Y       |`Send raw hex data to tag`          
|`hf felica rqservice    `|Y       |`verify the existence of Area and Service, and to acquire Key Version.`          
|`hf felica rqresponse   `|Y       |`verify the existence of a card and its Mode.`          
|`hf felica rdunencrypted`|Y       |`read Block Data from authentication-not-required Service.`          
|`hf felica wrunencrypted`|Y       |`write Block Data to an authentication-not-required Service.`          
|`hf felica scsvcode     `|Y       |`acquire Area Code and Service Code.`          
|`hf felica rqsyscode    `|Y       |`acquire System Code registered to the card.`          
|`hf felica auth1        `|Y       |`authenticate a card. Start mutual authentication with Auth1`          
|`hf felica auth2        `|Y       |`allow a card to authenticate a Reader/Writer. Complete mutual authentication`          
|`hf felica read         `|Y       |`read Block Data from authentication-required Service.`          
|`hf felica rqspecver    `|Y       |`acquire the version of card OS.`          
|`hf felica resetmode    `|Y       |`reset Mode to Mode 0.`          
|`hf felica litesim      `|Y       |`<NDEF2> - only reply to poll request`          
|`hf felica litedump     `|Y       |`Wait for and try dumping FelicaLite`          

          
### hf legic

 { LEGIC RFIDs...                   }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf legic help          `|Y       |`This help`          
|`hf legic reader        `|Y       |`LEGIC Prime Reader UID and tag info`          
|`hf legic info          `|Y       |`Display deobfuscated and decoded LEGIC Prime tag data`          
|`hf legic dump          `|Y       |`Dump LEGIC Prime tag to binary file`          
|`hf legic restore       `|Y       |`Restore a dump file onto a LEGIC Prime tag`          
|`hf legic rdmem         `|Y       |`Read bytes from a LEGIC Prime tag`          
|`hf legic sim           `|Y       |`Start tag simulator`          
|`hf legic write         `|Y       |`Write data to a LEGIC Prime tag`          
|`hf legic crc           `|Y       |`Calculate Legic CRC over given bytes`          
|`hf legic eload         `|Y       |`Load binary dump to emulator memory`          
|`hf legic esave         `|Y       |`Save emulator memory to binary file`          
|`hf legic list          `|Y       |`List LEGIC history`          
|`hf legic wipe          `|Y       |`Wipe a LEGIC Prime tag`          

          
### hf iclass

 { ICLASS RFIDs...                  }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf iclass help         `|Y       |`This help`          
|`hf iclass calcnewkey   `|Y       |`[options..] Calc diversified keys (blocks 3 & 4) to write new keys`          
|`hf iclass chk          `|Y       |`[options..] Check keys`          
|`hf iclass clone        `|Y       |`[options..] Restore a dump file onto a iClass tag`          
|`hf iclass decrypt      `|Y       |`[options..] Decrypt given block data or tag dump file`          
|`hf iclass dump         `|Y       |`[options..] Dump iClass tag to file`          
|`hf iclass eload        `|Y       |`[f <fname>] Load iClass dump file into emulator memory`          
|`hf iclass encrypt      `|Y       |`[options..] Encrypt given block data`          
|`hf iclass info         `|Y       |`            Tag information`          
|`hf iclass list         `|Y       |`            List iClass history`          
|`hf iclass loclass      `|Y       |`[options..] Use loclass to perform bruteforce reader attack`          
|`hf iclass lookup       `|Y       |`[options..] Uses authentication trace to check for key in dictionary file`          
|`hf iclass managekeys   `|Y       |`[options..] Manage keys to use with iClass`          
|`hf iclass permutekey   `|Y       |`            Permute function from 'heart of darkness' paper`          
|`hf iclass rdbl         `|Y       |`[options..] Read iClass block`          
|`hf iclass reader       `|Y       |`            Act like an iClass reader`          
|`hf iclass readtagfile  `|Y       |`[options..] Display content from tag dump file`          
|`hf iclass replay       `|Y       |`<mac>       Read iClass tag via replay attack`          
|`hf iclass sim          `|Y       |`[options..] Simulate iClass tag`          
|`hf iclass sniff        `|Y       |`            Eavesdrop iClass communication`          
|`hf iclass wrbl         `|Y       |`[options..] Write iClass block`          

          
### hf mf

 { MIFARE RFIDs...                  }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf mf help             `|Y       |`This help`          
|`hf mf list             `|Y       |`List MIFARE history`          
|`hf mf darkside         `|Y       |`Darkside attack`          
|`hf mf nested           `|Y       |`Nested attack`          
|`hf mf hardnested       `|Y       |`Nested attack for hardened MIFARE Classic cards`          
|`hf mf autopwn          `|Y       |`Automatic key recovery tool for MIFARE Classic`          
|`hf mf nack             `|Y       |`Test for MIFARE NACK bug`          
|`hf mf chk              `|Y       |`Check keys`          
|`hf mf fchk             `|Y       |`Check keys fast, targets all keys on card`          
|`hf mf decrypt          `|Y       |`[nt] [ar_enc] [at_enc] [data] - to decrypt sniff or trace`          
|`hf mf rdbl             `|Y       |`Read MIFARE classic block`          
|`hf mf rdsc             `|Y       |`Read MIFARE classic sector`          
|`hf mf dump             `|Y       |`Dump MIFARE classic tag to binary file`          
|`hf mf restore          `|Y       |`Restore MIFARE classic binary file to BLANK tag`          
|`hf mf wrbl             `|Y       |`Write MIFARE classic block`          
|`hf mf setmod           `|Y       |`Set MIFARE Classic EV1 load modulation strength`          
|`hf mf auth4            `|Y       |`ISO14443-4 AES authentication`          
|`hf mf sim              `|Y       |`Simulate MIFARE card`          
|`hf mf eclr             `|Y       |`Clear simulator memory`          
|`hf mf eget             `|Y       |`Get simulator memory block`          
|`hf mf eset             `|Y       |`Set simulator memory block`          
|`hf mf eload            `|Y       |`Load from file emul dump`          
|`hf mf esave            `|Y       |`Save to file emul dump`          
|`hf mf ecfill           `|Y       |`Fill simulator memory with help of keys from simulator`          
|`hf mf ekeyprn          `|Y       |`Print keys from simulator memory`          
|`hf mf csetuid          `|Y       |`Set UID     (magic chinese card)`          
|`hf mf cwipe            `|Y       |`Wipe card to default UID/Sectors/Keys`          
|`hf mf csetblk          `|Y       |`Write block (magic chinese card)`          
|`hf mf cgetblk          `|Y       |`Read block  (magic chinese card)`          
|`hf mf cgetsc           `|Y       |`Read sector (magic chinese card)`          
|`hf mf cload            `|Y       |`Load dump   (magic chinese card)`          
|`hf mf csave            `|Y       |`Save dump from magic chinese card into file or emulator`          
|`hf mf mad              `|Y       |`Checks and prints MAD`          
|`hf mf ndef             `|Y       |`Prints NDEF records from card`          
|`hf mf ice              `|Y       |`collect MIFARE Classic nonces to file`          

          
### hf mfp

 { MIFARE Plus RFIDs...             }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf mfp help            `|Y       |`This help`          
|`hf mfp info            `|Y       |`Info about Mifare Plus tag`          
|`hf mfp wrp             `|Y       |`Write Perso command`          
|`hf mfp initp           `|Y       |`Fills all the card's keys`          
|`hf mfp commitp         `|Y       |`Move card to SL1 or SL3 mode`          
|`hf mfp auth            `|Y       |`Authentication`          
|`hf mfp rdbl            `|Y       |`Read blocks`          
|`hf mfp rdsc            `|Y       |`Read sectors`          
|`hf mfp wrbl            `|Y       |`Write blocks`          
|`hf mfp chk             `|Y       |`Check keys`          
|`hf mfp mad             `|Y       |`Checks and prints MAD`          
|`hf mfp ndef            `|Y       |`Prints NDEF records from card`          

          
### hf mfu

 { MIFARE Ultralight RFIDs...       }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf mfu help            `|Y       |`This help`          
|`hf mfu info            `|Y       |`Tag information`          
|`hf mfu dump            `|Y       |`Dump Ultralight / Ultralight-C / NTAG tag to binary file`          
|`hf mfu restore         `|Y       |`Restore a dump onto a MFU MAGIC tag`          
|`hf mfu eload           `|Y       |`load Ultralight .eml dump file into emulator memory`          
|`hf mfu rdbl            `|Y       |`Read block`          
|`hf mfu wrbl            `|Y       |`Write block`          
|`hf mfu cauth           `|Y       |`Authentication    - Ultralight C`          
|`hf mfu setpwd          `|Y       |`Set 3des password - Ultralight-C`          
|`hf mfu setuid          `|Y       |`Set UID - MAGIC tags only`          
|`hf mfu sim             `|Y       |`Simulate Ultralight from emulator memory`          
|`hf mfu gen             `|Y       |`Generate 3des mifare diversified keys`          
|`hf mfu pwdgen          `|Y       |`Generate pwd from known algos`          
|`hf mfu otptear         `|Y       |`Tear-off test on OTP bits`          

          
### hf mfdes

 { MIFARE Desfire RFIDs...          }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf mfdes help          `|Y       |`This help`          
|`hf mfdes info          `|Y       |`Tag information`          
|`hf mfdes enum          `|Y       |`Tries enumerate all applications`          
|`hf mfdes auth          `|Y       |`Tries a MIFARE DesFire Authentication`          

          
### hf topaz

 { TOPAZ (NFC Type 1) RFIDs...      }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf topaz help          `|Y       |`This help`          
|`hf topaz reader        `|Y       |`Act like a Topaz reader`          
|`hf topaz sim           `|Y       |`<UID> -- Simulate Topaz tag`          
|`hf topaz sniff         `|Y       |`Sniff Topaz reader-tag communication`          
|`hf topaz raw           `|Y       |`Send raw hex data to tag`          
|`hf topaz list          `|Y       |`List Topaz history`          

          
### hf fido

 { FIDO and FIDO2 authenticators... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf fido help           `|Y       |`This help.`          
|`hf fido info           `|Y       |`Info about FIDO tag.`          
|`hf fido reg            `|Y       |`FIDO U2F Registration Message.`          
|`hf fido auth           `|Y       |`FIDO U2F Authentication Message.`          
|`hf fido make           `|Y       |`FIDO2 MakeCredential command.`          
|`hf fido assert         `|Y       |`FIDO2 GetAssertion command.`          

          
### hf thinfilm

 { Thinfilm RFIDs...                }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hf thinfilm help       `|Y       |`This help`          
|`hf thinfilm info       `|Y       |`Tag information`          
|`hf thinfilm list       `|Y       |`List NFC Barcode / Thinfilm history - not correct`          
|`hf thinfilm sim        `|Y       |`Fake Thinfilm tag`          

          
### hw

 { Hardware commands... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`hw help                `|Y       |`This help`          
|`hw connect             `|Y       |`connect Proxmark3 to serial port`          
|`hw dbg                 `|Y       |`Set Proxmark3 debug level`          
|`hw detectreader        `|Y       |`['l'|'h'] -- Detect external reader field (option 'l' or 'h' to limit to LF or HF)`          
|`hw fpgaoff             `|Y       |`Set FPGA off`          
|`hw lcd                 `|N       |`<HEX command> <count> -- Send command/data to LCD`          
|`hw lcdreset            `|N       |`Hardware reset LCD`          
|`hw ping                `|Y       |`Test if the Proxmark3 is responsive`          
|`hw readmem             `|Y       |`[address] -- Read memory at decimal address from flash`          
|`hw reset               `|Y       |`Reset the Proxmark3`          
|`hw setlfdivisor        `|Y       |`<19 - 255> -- Drive LF antenna at 12MHz/(divisor+1)`          
|`hw setmux              `|Y       |`Set the ADC mux to a specific value`          
|`hw standalone          `|Y       |`Jump to the standalone mode`          
|`hw status              `|Y       |`Show runtime status information about the connected Proxmark3`          
|`hw tia                 `|Y       |`Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider`          
|`hw tune                `|Y       |`Measure antenna tuning`          
|`hw version             `|Y       |`Show version information about the connected Proxmark3`          

          
### lf

 { Low frequency commands... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf help                `|Y       |`This help`          
|`lf config              `|Y       |`Get/Set config for LF sampling, bit/sample, decimation, frequency`          
|`lf cmdread             `|Y       |`<off period> <'0' period> <'1' period> <command> ['h' 134] 
		-- Modulate LF reader field to send command before read (all periods in microseconds)`          
|`lf read                `|Y       |`['s' silent] Read 125/134 kHz LF ID-only tag. Do 'lf read h' for help`          
|`lf search              `|Y       |`[offline] ['u'] Read and Search for valid known tag (in offline mode it you can load first then search) 
		-- 'u' to search for unknown tags`          
|`lf sim                 `|Y       |`[GAP] -- Simulate LF tag from buffer with optional GAP (in microseconds)`          
|`lf simask              `|Y       |`[clock] [invert <1|0>] [biphase/manchester/raw <'b'|'m'|'r'>] [msg separator 's'] [d <hexdata>] 
		-- Simulate LF ASK tag from demodbuffer or input`          
|`lf simfsk              `|Y       |`[c <clock>] [i] [H <fcHigh>] [L <fcLow>] [d <hexdata>] 
		-- Simulate LF FSK tag from demodbuffer or input`          
|`lf simpsk              `|Y       |`[1|2|3] [c <clock>] [i] [r <carrier>] [d <raw hex to sim>] 
		-- Simulate LF PSK tag from demodbuffer or input`          
|`lf simbidir            `|Y       |`Simulate LF tag (with bidirectional data transmission between reader and tag)`          
|`lf sniff               `|Y       |`Sniff LF traffic between reader and tag`          
|`lf tune                `|Y       |`Continuously measure LF antenna tuning`          

          
### lf awid

 { AWID RFIDs...              }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf awid help           `|Y       |`this help`          
|`lf awid demod          `|Y       |`demodulate an AWID FSK tag from the GraphBuffer`          
|`lf awid read           `|Y       |`attempt to read and extract tag data`          
|`lf awid clone          `|Y       |`clone AWID tag to T55x7 (or to q5/T5555)`          
|`lf awid sim            `|Y       |`simulate AWID tag`          
|`lf awid brute          `|Y       |`Bruteforce card number against reader`          
|`lf awid watch          `|Y       |`continuously watch for cards.  Reader mode`          

          
### lf cotag

 { COTAG CHIPs...             }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf cotag help          `|Y       |`This help`          
|`lf cotag demod         `|Y       |`Tries to decode a COTAG signal`          
|`lf cotag read          `|Y       |`Attempt to read and extract tag data`          

          
### lf em

 { EM4X CHIPs & RFIDs...      }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf em help             `|Y       |`This help`          
|`lf em 410x_demod       `|Y       |`demodulate a EM410x tag from the GraphBuffer`          
|`lf em 410x_read        `|Y       |`attempt to read and extract tag data`          
|`lf em 410x_sim         `|Y       |`simulate EM410x tag`          
|`lf em 410x_brute       `|Y       |`reader bruteforce attack by simulating EM410x tags`          
|`lf em 410x_watch       `|Y       |`watches for EM410x 125/134 kHz tags (option 'h' for 134)`          
|`lf em 410x_spoof       `|Y       |`watches for EM410x 125/134 kHz tags, and replays them. (option 'h' for 134)`          
|`lf em 410x_write       `|Y       |`write EM410x UID to T5555(Q5) or T55x7 tag`          
|`lf em 4x05_demod       `|Y       |`demodulate a EM4x05/EM4x69 tag from the GraphBuffer`          
|`lf em 4x05_dump        `|Y       |`dump EM4x05/EM4x69 tag`          
|`lf em 4x05_wipe        `|Y       |`wipe EM4x05/EM4x69 tag`          
|`lf em 4x05_info        `|Y       |`tag information EM4x05/EM4x69`          
|`lf em 4x05_read        `|Y       |`read word data from EM4x05/EM4x69`          
|`lf em 4x05_write       `|Y       |`write word data to EM4x05/EM4x69`          
|`lf em 4x50_demod       `|Y       |`demodulate a EM4x50 tag from the GraphBuffer`          
|`lf em 4x50_dump        `|Y       |`dump EM4x50 tag`          
|`lf em 4x50_read        `|Y       |`read word data from EM4x50`          
|`lf em 4x50_write       `|Y       |`write word data to EM4x50`          

          
### lf fdx

 { FDX-B RFIDs...             }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf fdx help            `|Y       |`this help`          
|`lf fdx demod           `|Y       |`demodulate a FDX-B ISO11784/85 tag from the GraphBuffer`          
|`lf fdx read            `|Y       |`attempt to read and extract tag data`          
|`lf fdx clone           `|Y       |`clone animal ID tag to T55x7 (or to q5/T5555)`          
|`lf fdx sim             `|Y       |`simulate Animal ID tag`          

          
### lf gallagher

 { GALLAGHER RFIDs...         }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf gallagher help      `|Y       |`This help`          
|`lf gallagher demod     `|Y       |`Demodulate an GALLAGHER tag from the GraphBuffer`          
|`lf gallagher read      `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf gallagher clone     `|Y       |`clone GALLAGHER tag to T55x7`          
|`lf gallagher sim       `|Y       |`simulate GALLAGHER tag`          

          
### lf gproxii

 { Guardall Prox II RFIDs...  }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf gproxii help        `|Y       |`this help`          
|`lf gproxii demod       `|Y       |`demodulate a G Prox II tag from the GraphBuffer`          
|`lf gproxii read        `|Y       |`attempt to read and extract tag data from the antenna`          
|`lf gproxii clone       `|Y       |`clone Guardall tag to T55x7`          
|`lf gproxii sim         `|Y       |`simulate Guardall tag`          

          
### lf hid

 { HID RFIDs...               }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf hid help            `|Y       |`this help`          
|`lf hid demod           `|Y       |`demodulate HID Prox tag from the GraphBuffer`          
|`lf hid read            `|Y       |`attempt to read and extract tag data`          
|`lf hid clone           `|Y       |`clone HID tag to T55x7`          
|`lf hid sim             `|Y       |`simulate HID tag`          
|`lf hid brute           `|Y       |`bruteforce card number against reader`          
|`lf hid watch           `|Y       |`continuously watch for cards.  Reader mode`          

          
### lf hitag

 { Hitag CHIPs...             }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf hitag help          `|Y       |`This help`          
|`lf hitag list          `|Y       |`List Hitag trace history`          
|`lf hitag info          `|Y       |`Tag information`          
|`lf hitag reader        `|Y       |`Act like a Hitag Reader`          
|`lf hitag sim           `|Y       |`Simulate Hitag transponder`          
|`lf hitag sniff         `|Y       |`Eavesdrop Hitag communication`          
|`lf hitag writer        `|Y       |`Act like a Hitag Writer`          
|`lf hitag cc            `|Y       |`Test all challenges`          

          
### lf indala

 { Indala RFIDs...            }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf indala help         `|Y       |`this help`          
|`lf indala demod        `|Y       |`demodulate an indala tag (PSK1) from GraphBuffer`          
|`lf indala altdemod     `|Y       |`alternative method to Demodulate samples for Indala 64 bit UID (option '224' for 224 bit)`          
|`lf indala read         `|Y       |`read an Indala Prox tag from the antenna`          
|`lf indala clone        `|Y       |`clone Indala tag to T55x7`          
|`lf indala sim          `|Y       |`simulate Indala tag`          

          
### lf io

 { ioProx RFIDs...            }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf io help             `|Y       |`this help`          
|`lf io demod            `|Y       |`demodulate an IOProx tag from the GraphBuffer`          
|`lf io read             `|Y       |`attempt to read and extract tag data`          
|`lf io clone            `|Y       |`clone IOProx tag to T55x7 (or to q5/T5555)`          
|`lf io sim              `|Y       |`simulate IOProx tag`          
|`lf io watch            `|Y       |`continuously watch for cards. Reader mode`          

          
### lf jablotron

 { Jablotron RFIDs...         }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf jablotron help      `|Y       |`This help`          
|`lf jablotron slurdge   `|Y       |`Demod slurdge ..`          
|`lf jablotron demod     `|Y       |`Demodulate an Jablotron tag from the GraphBuffer`          
|`lf jablotron read      `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf jablotron clone     `|Y       |`clone jablotron tag to T55x7 (or to q5/T5555)`          
|`lf jablotron sim       `|Y       |`simulate jablotron tag`          

          
### lf keri

 { KERI RFIDs...              }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf keri help           `|Y       |`This help`          
|`lf keri demod          `|Y       |`Demodulate an KERI tag from the GraphBuffer`          
|`lf keri read           `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf keri clone          `|Y       |`clone KERI tag to T55x7 (or to q5/T5555)`          
|`lf keri sim            `|Y       |`simulate KERI tag`          

          
### lf nedap

 { Nedap RFIDs...             }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf nedap help          `|Y       |`This help`          
|`lf nedap demod         `|Y       |`Demodulate Nedap tag from the GraphBuffer`          
|`lf nedap generate      `|Y       |`Generate Nedap bitstream in DemodBuffer`          
|`lf nedap read          `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf nedap clone         `|Y       |`Clone Nedap tag to T55x7`          
|`lf nedap sim           `|Y       |`Simulate Nedap tag`          

          
### lf nexwatch

 { NexWatch RFIDs...          }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf nexwatch help       `|Y       |`This help`          
|`lf nexwatch demod      `|Y       |`Demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer`          
|`lf nexwatch read       `|Y       |`Attempt to Read and Extract tag data from the antenna`          
|`lf nexwatch clone      `|Y       |`clone NexWatch tag to T55x7`          
|`lf nexwatch sim        `|Y       |`simulate NexWatch tag`          

          
### lf noralsy

 { Noralsy RFIDs...           }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf noralsy help        `|Y       |`This help`          
|`lf noralsy demod       `|Y       |`Demodulate an Noralsy tag from the GraphBuffer`          
|`lf noralsy read        `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf noralsy clone       `|Y       |`clone Noralsy tag to T55x7 (or to q5/T5555)`          
|`lf noralsy sim         `|Y       |`simulate Noralsy tag`          

          
### lf motorola

 { Motorola RFIDs...          }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf motorola help       `|Y       |`This help`          
|`lf motorola demod      `|Y       |`Demodulate an MOTOROLA tag from the GraphBuffer`          
|`lf motorola read       `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf motorola clone      `|Y       |`clone MOTOROLA tag to T55x7`          
|`lf motorola sim        `|Y       |`simulate MOTOROLA tag`          

          
### lf pac

 { PAC/Stanley RFIDs...       }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf pac help            `|Y       |`This help`          
|`lf pac demod           `|Y       |`Demodulate a PAC tag from the GraphBuffer`          
|`lf pac read            `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf pac clone           `|Y       |`clone PAC tag to T55x7`          
|`lf pac sim             `|Y       |`simulate PAC tag`          

          
### lf paradox

 { Paradox RFIDs...           }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf paradox help        `|Y       |`This help`          
|`lf paradox demod       `|Y       |`Demodulate a Paradox FSK tag from the GraphBuffer`          
|`lf paradox read        `|Y       |`Attempt to read and Extract tag data from the antenna`          
|`lf paradox clone       `|Y       |`clone paradox tag to T55x7`          
|`lf paradox sim         `|Y       |`simulate paradox tag`          

          
### lf pcf7931

 { PCF7931 CHIPs...           }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf pcf7931 help        `|Y       |`This help`          
|`lf pcf7931 read        `|Y       |`Read content of a PCF7931 transponder`          
|`lf pcf7931 write       `|Y       |`Write data on a PCF7931 transponder.`          
|`lf pcf7931 config      `|Y       |`Configure the password, the tags initialization delay and time offsets (optional)`          

          
### lf presco

 { Presco RFIDs...            }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf presco help         `|Y       |`This help`          
|`lf presco read         `|Y       |`Attempt to read and Extract tag data`          
|`lf presco clone        `|Y       |`clone presco tag to T55x7 (or to q5/T5555)`          
|`lf presco sim          `|Y       |`simulate presco tag`          

          
### lf pyramid

 { Farpointe/Pyramid RFIDs... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf pyramid help        `|Y       |`this help`          
|`lf pyramid demod       `|Y       |`demodulate a Pyramid FSK tag from the GraphBuffer`          
|`lf pyramid read        `|Y       |`attempt to read and extract tag data`          
|`lf pyramid clone       `|Y       |`clone pyramid tag to T55x7 (or to q5/T5555)`          
|`lf pyramid sim         `|Y       |`simulate pyramid tag`          

          
### lf securakey

 { Securakey RFIDs...         }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf securakey help      `|Y       |`This help`          
|`lf securakey demod     `|Y       |`Demodulate an Securakey tag from the GraphBuffer`          
|`lf securakey read      `|Y       |`Attempt to read and extract tag data from the antenna`          
|`lf securakey clone     `|Y       |`clone Securakey tag to T55x7`          
|`lf securakey sim       `|Y       |`simulate Securakey tag`          

          
### lf ti

 { TI CHIPs...                }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf ti help             `|Y       |`This help`          
|`lf ti demod            `|Y       |`Demodulate raw bits for TI-type LF tag from the GraphBuffer`          
|`lf ti read             `|Y       |`Read and decode a TI 134 kHz tag`          
|`lf ti write            `|Y       |`Write new data to a r/w TI 134 kHz tag`          

          
### lf t55xx

 { T55xx CHIPs...             }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf t55xx help          `|Y       |`This help`          
|`lf t55xx bruteforce    `|Y       |`<start password> <end password> Simple bruteforce attack to find password`          
|`lf t55xx config        `|Y       |`Set/Get T55XX configuration (modulation, inverted, offset, rate)`          
|`lf t55xx chk           `|Y       |`Check passwords from dictionary/flash`          
|`lf t55xx clonehelp     `|Y       |`Shows the available clone commands`          
|`lf t55xx dangerraw     `|Y       |`Sends raw bitstream. Dangerous, do not use!! b <bitstream> t <timing>`          
|`lf t55xx detect        `|Y       |`[1] Try detecting the tag modulation from reading the configuration block.`          
|`lf t55xx deviceconfig  `|Y       |`Set/Get T55XX device configuration (startgap, writegap, write0, write1, readgap`          
|`lf t55xx dump          `|Y       |`[password] [o] Dump T55xx card Page 0 block 0-7. Optional [password], [override]`          
|`lf t55xx restore       `|Y       |`f <filename> [p <password>] Restore T55xx card Page 0 / Page 1 blocks`          
|`lf t55xx info          `|Y       |`[1] Show T55x7 configuration data (page 0/ blk 0)`          
|`lf t55xx p1detect      `|Y       |`[1] Try detecting if this is a t55xx tag by reading page 1`          
|`lf t55xx protect       `|Y       |`Password protect tag`          
|`lf t55xx read          `|Y       |`b <block> p [password] [o] [1] -- Read T55xx block data. Optional [p password], [override], [page1]`          
|`lf t55xx resetread     `|Y       |`Send Reset Cmd then lf read the stream to attempt to identify the start of it (needs a demod and/or plot after)`          
|`lf t55xx recoverpw     `|Y       |`[password] Try to recover from bad password write from a cloner. Only use on PW protected chips!`          
|`lf t55xx special       `|Y       |`Show block changes with 64 different offsets`          
|`lf t55xx trace         `|Y       |`[1] Show T55x7 traceability data (page 1/ blk 0-1)`          
|`lf t55xx wakeup        `|Y       |`Send AOR wakeup command`          
|`lf t55xx wipe          `|Y       |`[q] Wipe a T55xx tag and set defaults (will destroy any data on tag)`          
|`lf t55xx write         `|Y       |`b <block> d <data> p [password] [1] -- Write T55xx block data. Optional [p password], [page1]`          

          
### lf viking

 { Viking RFIDs...            }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf viking help         `|Y       |`This help`          
|`lf viking demod        `|Y       |`Demodulate a Viking tag from the GraphBuffer`          
|`lf viking read         `|Y       |`Attempt to read and Extract tag data from the antenna`          
|`lf viking clone        `|Y       |`clone Viking tag to T55x7 (or to q5/T5555)`          
|`lf viking sim          `|Y       |`simulate Viking tag`          

          
### lf visa2000

 { Visa2000 RFIDs...          }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`lf visa2000 help       `|Y       |`This help`          
|`lf visa2000 demod      `|Y       |`demodulate an VISA2000 tag from the GraphBuffer`          
|`lf visa2000 read       `|Y       |`attempt to read and extract tag data from the antenna`          
|`lf visa2000 clone      `|Y       |`clone Visa2000 tag to T55x7 (or to q5/T5555)`          
|`lf visa2000 sim        `|Y       |`simulate Visa2000 tag`          

          
### mem

 { Flash Memory manipulation... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`mem help               `|Y       |`This help`          
|`mem spiffs             `|Y       |`High level SPI FileSystem Flash manipulation [rdv40]`          
|`mem spibaud            `|Y       |`Set Flash memory Spi baudrate [rdv40]`          
|`mem info               `|Y       |`Flash memory information [rdv40]`          
|`mem load               `|Y       |`Load data into flash memory [rdv40]`          
|`mem dump               `|Y       |`Dump data from flash memory [rdv40]`          
|`mem wipe               `|Y       |`Wipe data from flash memory [rdv40]`          

          
### reveng

 { CRC calculations from RevEng software }
          
### sc

 { Smart card ISO-7816 commands... }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`sc help                `|Y       |`This help`          
|`sc list                `|Y       |`List ISO 7816 history`          
|`sc info                `|Y       |`Tag information`          
|`sc reader              `|Y       |`Act like an IS07816 reader`          
|`sc raw                 `|Y       |`Send raw hex data to tag`          
|`sc upgrade             `|Y       |`Upgrade sim module firmware`          
|`sc setclock            `|Y       |`Set clock speed`          
|`sc brute               `|Y       |`Bruteforce SFI`          

          
### script

 { Scripting commands }
          
|command                  |offline |description          
|-------                  |------- |-----------          
|`script help            `|Y       |`This help`          
|`script list            `|Y       |`List available scripts`          
|`script run             `|Y       |`<name> -- Execute a script`          

          
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
|`wiegand encode         `|Y       |`Convert `          
|`wiegand decode         `|Y       |`Convert raw hex to wiegand format`          

          
