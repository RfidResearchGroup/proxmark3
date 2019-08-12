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
