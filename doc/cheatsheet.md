# Cheatsheet

## Generic

Identify High Frequency cards
```
pm3 --> hf search
```

Identify Low Frequency cards
```
pm3 --> lf search
```

Measure antenna characteristics, LF/HF voltage should be around 20-45+ V
```
pm3 --> hw tune
```

Check versioning
```
pm3 --> hw version
```

## iClass

Reverse permute iClass master key
```
Options
---
r          reverse permuted key 

pm3 --> hf iclass permute r 3F90EBF0910F7B6F
```

iClass Reader
```
pm3 --> hf iclass reader
```

Dump iClass card contents
```
Options
---
k <Key>      : *Access Key as 16 hex symbols or 1 hex to select key from memory

pm3 --> hf iclass dump k AFA785A7DAB33378
```

Read iClass Block
```
Options
---
b <Block>  : The block number as 2 hex symbols
k <Key>    : Access Key as 16 hex symbols or 1 hex to select key from memory

pm3 --> hf iclass readblk b 7 k AFA785A7DAB33378
```

Write to iClass Block
```
Options
---
b <Block>  : The block number as 2 hex symbols
d <data>   : Set the Data to write as 16 hex symbols
k <Key>    : Access Key as 16 hex symbols or 1 hex to select key from memory

pm3 --> hf iclass writeblk b 07 d 6ce099fe7e614fd0 k AFA785A7DAB33378
```

Print keystore
```
Options
---
p           : print keys loaded into memory

pm3 --> hf iclass managekeys p
```

Add key to keystore [0-7]
```
Options
---
n <keynbr>    : specify the keyNbr to set in memory
k <key>       : set a key in memory

pm3 --> hf iclass managekeys n 0 k AFA785A7DAB33378
```

Encrypt iClass Block
```
pm3 --> hf iclass encryptblk 0000000f2aa3dba8
```

Load iClass dump into memory for simulation
```
Options
---
f <filename>     : load iclass tag-dump filename

pm3 --> hf iclass eload f iclass_tagdump-db883702f8ff12e0.bin
```

Simulate iClass
```
Options
---
0 <CSN>     simulate the given CSN
1           simulate default CSN
3           Full simulation using emulator memory (see 'hf iclass eload')

pm3 --> hf iclass sim 3
```

Clone iClass Legacy Sequence
```
pm3 --> hf iclass readblk b 7 k AFA785A7DAB33378
pm3 --> hf iclass writeblk b 07 d 6ce099fe7e614fd0 k AFA785A7DAB33378
```

Simulate iClass Sequence
```
pm3 --> hf iclass dump k AFA785A7DAB33378
pm3 --> hf iclass eload f iclass_tagdump-db883702f8ff12e0.bin
pm3 --> hf iclass sim 3
```

Extract custom iClass key (loclass attack)
```
Options
---
f <filename>   : specify a filename to clone from
k <Key>        : Access Key as 16 hex symbols or 1 hex to select key from memory
e              : If 'e' is specified, elite computations applied to key

pm3 --> hf iclass sim 2
pm3 --> hf iclass loclass f iclass_mac_attack.bin
pm3 --> hf iclass dump k <Kcus> e
```

Verify custom iClass key
```
Options
---
f <filename> : Dictionary file with default iclass keys
u            : CSN
p            : EPURSE
m            : macs
e            : elite

pm3 --> hf iclass lookup u 010a0ffff7ff12e0 p feffffffffffffff m 66348979153c41b9 f default_iclass_keys.dic e
```

## Mifare

Check for default keys
```
Options
---
<*card memory> <key type (A/B/?)> [t|d|s|ss] <dic (*.dic)>
* - all sectors
card memory - 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K
d - write keys to binary file

pm3 --> hf mf chk *1 ? d default_keys.dic
```

Dump Mifare card contents
```
Options
---
<card memory>: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K
k <name>     : key filename, if no <name> given, UID will be used as filename"
f <name>     : data filename, if no <name> given, UID will be used as filename

pm3 --> hf mf dump 1
pm3 --> hf mf dump 1 k hf-mf-A29558E4-key.bin f hf-mf-A29558E4-data.bin
```

Convert .bin to .eml
```
Options
---
i ?????????????

pm3 --> script run dumptoemul -i dumpdata.bin
```

Write to Mifare block
```
Options
---
<block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>

pm3 --> hf mf wrbl 0 A FFFFFFFFFFFF d3a2859f6b880400c801002000000016
```

Run Hardnested attack
```
Options
---
<block number> <key A|B> <key (12 hex symbols)> <target block number> <target key A|B> [known target key (12 hex symbols)] [w] [s]
w          : Acquire nonces and write them to binary file nonces.bin

pm3 --> hf mf hardnested 0 A 8829da9daf76 0 A w
```

Load Mifare emul dump file into memory for simulation
```
Options
---
<card memory> <file name w/o `.eml`>
[card memory]: 0 = 320 bytes (Mifare Mini), 1 = 1K (default), 2 = 2K, 4 = 4K, u = UL

pm3 --> hf mf eload 353C2AA6
pm3 --> hf mf eload 1 353C2AA6
```

Simulate Mifare 
```
u     : (Optional) UID 4,7 or 10 bytes. If not specified, the UID 4B from emulator memory will be used

pm3 --> hf mf sim u 353c2aa6
```

Simulate Mifare Sequence
```
pm3 --> hf mf chk *1 ? d default_keys.dic
pm3 --> hf mf dump 1
pm3 --> script run dumptoemul -i dumpdata.bin
pm3 --> hf mf eload 353C2AA6
pm3 --> hf mf sim u 353c2aa6
```

Clone Mifare 1K Sequence
```
pm3 --> hf mf chk *1 ? d default_keys.dic
pm3 --> hf mf dump
pm3 --> hf mf restore 1 u 4A6CE843 k hf-mf-A29558E4-key.bin f hf-mf-A29558E4-data.bin
```

## HID Prox

Read HID Prox card
```
pm3 --> lf hid read
```

Demodulate HID Prox card
```
pm3 --> lf hid demod
```

Convert Site & Facility code to Wiegand
```
Options
---
<OEM> <FC> <CN> 
OEM           : OEM number / site code          
FC            : facility code          
CN            : card number  

pm3 --> lf hid wiegand 0 56 150
```

Simulate Prox card
```

pm3 --> lf hid sim 200670012d
```

Clone Prox to T5577 card
```
pm3 --> lf hid clone 200670012d
```

Brute force HID reader
```
Options
---
a <format>        :  26|33|34|35|37|40|44|84");
f <facility-code> :  8-bit value HID facility code");
c <cardnumber>    :  (optional) cardnumber to start with, max 65535");
d <delay>         :  delay betweens attempts in ms. Default 1000ms");
v                 :  verbose logging, show all tries");

pm3 --> lf hid brute a 26 f 224
pm3 --> lf hid brute v a 26 f 21 c 200 d 2000
```

## Indala

Read Indala card
```
pm3 --> lf indala read
```

Demodulate Indala card
```
pm3 --> lf indala demod
```

Simulate Indala card
```
Options
---
<uid> :  64/224 UID

pm3 --> lf indala sim a0000000c2c436c1
```

Clone to T55x7 card
```
Options
---
<uid> :  64/224 UID

pm3 --> lf indala clone a0000000c2c436c1
```

## Hitag

Read Hitag information
```
pm3 --> lf hitag info
```

Act as Hitag reader
```
Options
---
HitagS:
01 <nr> <ar>    : Read all pages, challenge mode
02 <key>        : Read all pages, crypto mode. Set key=0 for no auth

Hitag2:
21 <password>   : Read all pages, password mode. Default: 4D494B52 (\"MIKR\")
22 <nr> <ar>    : Read all pages, challenge mode
23 <key>        : Read all pages, crypto mode. Key format: ISK high + ISK low. Default: 4F4E4D494B52 ("ONMIKR")
25              : Test recorded authentications
26              : Just read UID

pm3 --> lf hitag 26
pm3 --> lf hitag 21 4D494B52
```

Sniff Hitag traffic 
```
pm3 --> lf hitag sniff
pm3 --> lf hitag list
```

Simulate Hitag
```
pm3 --> lf hitag sim c378181c_a8f7.ht2 
```

Write to Hitag block
```
Options
---
HitagS:
03 <nr,ar> <page> <byte0...byte3>     : Write page, challenge mode
04 <key> <page> <byte0...byte3>       : Write page, crypto mode. Set key=0 for no auth

Hitag2:
24  <key> <page> <byte0...byte3>      : Write page, crypto mode. Key format: ISK high + ISK low.
27  <password> <page> <byte0...byte3> : Write page, password mode. Default: 4D494B52 ("MIKR")

pm3 --> lf hitag writer 24 499602D2 1 00000000
```

Simulate Hitag2 sequence
```
pm3 --> lf hitag reader 21 56713368
pm3 --> lf hitag sim c378181c_a8f7.ht2 
```

## T55XX

Detect T55XX card
```
pm3 --> lf t55xx detect
```

Configure demodulation
```
Options
---
<FSK|FSK1|FSK1a|FSK2|FSK2a|ASK|PSK1|PSK2|NRZ|BI|BIa>  : Set demodulation
EM is ASK
HID Prox is FSK
Indala is PSK

pm3 --> lf t55xx config FSK
```

Write to T55xx block
```
b <block>    : block number to write. Between 0-7          
d <data>     : 4 bytes of data to write (8 hex characters) 

pm3 --> lf t55xx wr b 0 d 00081040
```

Wipe a T55xx tag and set defaults
```
lf t55xx wipe
```

## Data

Get raw samples [512-40000]
```
data samples <size>
```

Save samples to file
```
data save <filename>
```

Load samples from file
```
data load <filename>
```

## Lua Scripts

List Lua Scripts

```
script list
```

Convert .bin to .eml
```
Options
---
i <file>	: Specifies the dump-file (input). If omitted, 'dumpdata.bin' is used

script run dumptoemul -i xxxxxxxxxxxxxx.bin
```

Format Mifare card
```
Options
---
k <key>       : the current six byte key with write access
n <key>       : the new key that will be written to the card
a <access>    : the new access bytes that will be written to the card
x             : execute the commands aswell.

script run formatMifare -k FFFFFFFFFFFF -n FFFFFFFFFFFF -x
```
