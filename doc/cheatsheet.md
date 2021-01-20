<a id="Top"></a>
# Command Cheat Sheet

|Generic|Low Frequency 125 kHz|High Frequency 13.56 MHz|
|---|---|---|
|[Generic](#Generic)|[T55XX](#T55XX)|[MIFARE](#MIFARE)|
|[Data](#Data)|[HID Prox](#HID-Prox)|[iCLASS](#iCLASS)|
|[Memory](#Memory)|[Indala](#Indala)||
|[Sim Module](#Sim-Module)|[Hitag](#Hitag)||
|[Lua Scripts](#Lua-Scripts)|||
|[Smart Card](#Smart-Card)|||
|[Wiegand convertion](#Wiegand-manipulation)|||

## Generic
^[Top](#top)

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

Check overall status
```
pm3 --> hw status
```

## iCLASS
^[Top](#top)

Reverse permute iCLASS master key
```
Options
---
-r  --reverse      : reverse permuted key
    --key <bytes>  : input key

pm3 --> hf iclass permute --reverse --key 3F90EBF0910F7B6F
```

iCLASS Reader

```
pm3 --> hf iclass reader
```

Dump iCLASS card contents
```
Options
---
-f, --file <filename>          filename to save dump to
-k, --key <hex>                debit key as 16 hex symbols OR NR/MAC for replay
    --ki <dec>                 debit key index to select key from memory 'hf iclass managekeys'
    --credit <hex>             credit key as 16 hex symbols
    --ci <dec>                 credit key index to select key from memory 'hf iclass managekeys'
    --elite                    elite computations applied to key
    --raw                      raw, the key is interpreted as raw block 3/4
    --nr                       replay of NR/MAC

pm3 --> hf iclass dump --ki 0
```

Read iCLASS Block
```
Options
---
-k, --key <hex>                Access key as 16 hex symbols
-b, --block <dec>              The block number to read as an integer
    --ki <dec>                 Key index to select key from memory 'hf iclass managekeys'
    --credit                   key is assumed to be the credit key
    --elite                    elite computations applied to key
    --raw                      no computations applied to key (raw)
    --nr                       replay of NR/MAC

pm3 --> hf iclass rdbl -b 7 --ki 0
```

Write to iCLASS Block
```
Options
---
-k, --key <hex>                Access key as 16 hex symbols
-b, --block <dec>              The block number to read as an integer
-d, --data <hex>               data to write as 16 hex symbols
    --ki <dec>                 Key index to select key from memory 'hf iclass managekeys'
    --credit                   key is assumed to be the credit key
    --elite                    elite computations applied to key
    --raw                      no computations applied to key (raw)
    --nr                       replay of NR/MAC

pm3 --> hf iclass wrbl -b 7 -d 6ce099fe7e614fd0 --ki 0
```

Print keystore
```
Options
---
-p, --print                    Print keys loaded into memory


pm3 --> hf iclass managekeys -p
```

Add key to keystore [0-7]
```
Options
---
-f, --file <filename>          Specify a filename to use with load or save operations
    --ki <dec>                 Specify key index to set key in memory

pm3 --> hf iclass managekeys --ki 3 -k AFA785A7DAB33378
```

Encrypt iCLASS Block
```
Options
---
-d, --data <hex>               data to encrypt
-k, --key <hex>                3DES transport key
-v, --verbose                  verbose output

pm3 --> hf iclass encrypt -d 0000000f2aa3dba8
```

Decrypt iCLASS Block / file
```
Options
---
-f, --file <filename>          filename of dumpfile
-d, --data <hex>               3DES encrypted data
-k, --key <hex>                3DES transport key
-v, --verbose                  verbose output

pm3 --> hf iclass decrypt -d 2AD4C8211F996871
pm3 --> hf iclass decrypt -f hf-iclass-db883702f8ff12e0.bin
```

Load iCLASS dump into memory for simulation
```
Options
---
-f, --file <filename>          filename of dump
    --json                     load JSON type dump
    --eml                      load EML type dump

pm3 --> hf iclass eload -f hf-iclass-db883702f8ff12e0.bin
```

Clone iCLASS Legacy Sequence
```
pm3 --> hf iclass rdbl -b 7 --ki 0
pm3 --> hf iclass wrbl -b 7 -d 6ce099fe7e614fd0 --ki 0
```

Simulate iCLASS
```
Options
---
-t, --type <int>               Simulation type to use
    --csn <hex>                Specify CSN as 8 bytes (16 hex symbols) to use with sim type 0
Types:
0           simulate the given CSN
1           simulate default CSN
2           Runs online part of LOCLASS attack
3           Full simulation using emulator memory (see 'hf iclass eload')
4           Runs online part of LOCLASS attack against reader in keyroll mode

pm3 --> hf iclass sim -t 3
```

Simulate iCLASS Sequence
```
pm3 --> hf iclass dump --ki 0
pm3 --> hf iclass eload -f hf-iclass-db883702f8ff12e0.bin
pm3 --> hf iclass sim -t 3
```

Extract custom iCLASS key (loclass attack)
```
Options
---
-f <filename>                  specify a filename to clone from
-k <key>                       Access Key as 16 hex symbols or 1 hex to select key from memory
    --elite                    Elite computations applied to key

pm3 --> hf iclass sim -t 2
pm3 --> hf iclass loclass -f iclass_mac_attack.bin
pm3 --> hf iclass managekeys --ki 7 -k <Kcus>
pm3 --> hf iclass dump --ki 7 --elite
```

Verify custom iCLASS key
```
Options
---
-f, --file <filename>          Dictionary file with default iclass keys
    --csn <hex>                Specify CSN as 8 bytes (16 hex symbols)
    --epurse <hex>             Specify ePurse as 8 bytes (16 hex symbols)
    --macs <hex>               MACs
    --raw                      no computations applied to key (raw)
    --elite                    Elite computations applied to key

pm3 --> hf iclass lookup --csn 010a0ffff7ff12e0 --epurse feffffffffffffff --macs 66348979153c41b9 -f iclass_default_keys --elite
```

## MIFARE
^[Top](#top)

Check for default keys
```
Options
---
<*card memory> <key type (A/B/?)> [t|d|s|ss] <dic (*.dic)>
*              : all sectors
card memory    : 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K
d              : write keys to binary file

pm3 --> hf mf chk *1 ? d mfc_default_keys
```

Check for default keys from local memory
```
Options
---
card memory   : 0 - MINI(320 bytes), 1 - 1K, 2 - 2K, 4 - 4K
m             : use dictionary from flashmemory

pm3 --> hf mf fchk 1 m
```

Dump MIFARE card contents
```
Options
---
<card memory> : 0 = 320 bytes (MIFARE Mini), 1 = 1K (default), 2 = 2K, 4 = 4K
k <name>      : key filename, if no <name> given, UID will be used as filename"
f <name>      : data filename, if no <name> given, UID will be used as filename

pm3 --> hf mf dump 1
pm3 --> hf mf dump 1 k hf-mf-A29558E4-key.bin f hf-mf-A29558E4-dump.bin
```

Convert .bin to .eml
```
Options
---
i <file>     : Specifies the dump-file (input). If omitted, 'dumpdata.bin' is used

pm3 --> script run data_mf_bin2eml -i dumpdata.bin
```

Write to MIFARE block
```
Options
---
<block number> <key A/B> <key (12 hex symbols)> <block data (32 hex symbols)>

pm3 --> hf mf wrbl 0 A FFFFFFFFFFFF d3a2859f6b880400c801002000000016
```

Run autopwn, to backup a MIFARE tag
```
Options
---

pm3 --> hf mf autopwn
```

Run hardnested attack
```
Options
---
<block number> <key A|B> <key (12 hex symbols)> <target block number> <target key A|B> [known target key (12 hex symbols)] [w] [s]
w          : Acquire nonces and write them to binary file nonces.bin

pm3 --> hf mf hardnested 0 A 8829da9daf76 0 A w
```

Load MIFARE emul dump file into memory for simulation
```
Options
---
<card memory> <file name w/o `.eml`>
[card memory]: 0 = 320 bytes (MIFARE Mini), 1 = 1K (default), 2 = 2K, 4 = 4K, u = UL

pm3 --> hf mf eload hf-mf-353C2AA6
pm3 --> hf mf eload 1 hf-mf-353C2AA6
```

Simulate MIFARE
```
u     : (Optional) UID 4,7 or 10 bytes. If not specified, the UID 4B from emulator memory will be used

pm3 --> hf mf sim u 353c2aa6
```

Simulate MIFARE Sequence
```
pm3 --> hf mf chk *1 ? d mfc_default_keys
pm3 --> hf mf dump 1
pm3 --> script run data_mf_bin2eml -i dumpdata.bin
pm3 --> hf mf eload 353C2AA6
pm3 --> hf mf sim u 353c2aa6
```

Clone MIFARE 1K Sequence
```
pm3 --> hf mf chk *1 ? d mfc_default_keys
pm3 --> hf mf dump
pm3 --> hf mf restore 1 u 4A6CE843 k hf-mf-A29558E4-key.bin f hf-mf-A29558E4-dump.bin
```

Read MIFARE Ultralight EV1
```
pm3 --> hf mfu info
```

Clone MIFARE Ultralight EV1 Sequence
```
pm3 --> hf mfu dump -k FFFFFFFF
pm3 --> script run hf_mfu_dumptoemulator -i hf-mfu-XXXX-dump.bin -o hf-mfu-XXXX-dump.eml
pm3 --> hf mfu eload -u -f hf-mfu-XXXX-dump.eml
pm3 --> hf mfu sim -t 7 -f hf-mfu-XXXX-dump.eml
```

Bruteforce MIFARE Classic card numbers from 11223344 to 11223346
```
pm3 --> script run hf_mf_uidbruteforce -s 0x11223344 -e 0x11223346 -t 1000 -x mfc
```

Bruteforce MIFARE Ultralight EV1 card numbers from 11223344556677 to 11223344556679
```
pm3 --> script run hf_mf_uidbruteforce -s 0x11223344556677 -e 0x11223344556679 -t 1000 -x mfu
```

## Wiegand manipulation
^[Top](#top)

List all available wiegand formats in client
```
pm3 --> wiegand list
```

Convert Site & Facility code to Wiegand raw hex
```
Options
---
-w <format> --oem <OEM> --fc <FC> --cn <CN> --issue <issuelevel>

-w                             wiegand format to use
    --oem                      OEM number / site code
    --fc                       facility code
    --cn                       card number
    --issue                    issue level

pm3 --> wiegand encode -w H10301 --oem 0 --fc 56  --cn 150
```

Convert Site & Facility code from Wiegand raw hex to numbers
```
Options
---
-p                             ignore parity errors
    --raw                      raw hex to be decoded

pm3 --> wiegand decode --raw 2006f623ae
```

## HID Prox
^[Top](#top)

Read HID Prox card
```
pm3 --> lf hid read
```

Demodulate HID Prox card
```
pm3 --> lf hid demod
```

Simulate Prox card
```

pm3 --> lf hid sim -r 200670012d
pm3 --> lf hid sim -w H10301 --fc 10 --cn 1337
```

Clone Prox to T5577 card
```
pm3 --> lf hid clone -r 200670012d
pm3 --> lf hid clone -w H10301 --fc 10 --cn 1337
```

Brute force HID reader
```
Options
---
-v, --verbose                  verbose logging, show all tries
-w, --wiegand format           see `wiegand list` for available formats
-f, --fn dec                   facility code
-c, --cn dec                   card number to start with
-i dec                         issue level
-o, --oem dec                  OEM code
-d, --delay dec                delay betweens attempts in ms. Default 1000ms
    --up                       direction to increment card number. (default is both directions)
    --down                     direction to decrement card number. (default is both directions)

pm3 --> lf hid brute -w H10301 -f 224
pm3 --> lf hid brute -v -w H10301 -f 21 -c 200 -d 2000
```

## Indala
^[Top](#top)

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
-r, --raw <hex>                raw bytes
    --heden <decimal>          Cardnumber for Heden 2L format

pm3 --> lf indala sim -r a0000000c2c436c1
```

Clone to T55x7 card
```
Options
---
-r, --raw <hex>                raw bytes
    --heden <decimal>          Cardnumber for Heden 2L format
    --fc <decimal>             Facility Code (26 bit H10301 format)
    --cn <decimal>             Cardnumber (26 bit H10301 format)
    --q5                       specify writing to Q5/T5555 tag
    --em                       specify writing to EM4305/4469 tag

pm3 --> lf indala clone -r a0000000c2c436c1
```

## Hitag
^[Top](#top)

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
21 <password>   : Read all pages, password mode. Default: 4D494B52 ("MIKR")
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
^[Top](#top)

Detect T55XX card
```
pm3 --> lf t55xx detect
```

Configure modulation
```
Options
---
<FSK|FSK1|FSK1a|FSK2|FSK2a|ASK|PSK1|PSK2|NRZ|BI|BIa>  : Set modulation
EM is ASK
HID Prox is FSK
Indala is PSK

pm3 --> lf t55xx config FSK
```

Set timings to default
```
Options
---
-p            : persist to flash memory (RDV4)
-z            : Set default t55x7 timings (use `-p` to save if required)

pm3 --> lf t55xx deviceconfig -z -p
```

Write to T55xx block
```
b <block>    : block number to write. Between 0-7
d <data>     : 4 bytes of data to write (8 hex characters)

pm3 --> lf t55xx wr b 0 d 00081040
```

Wipe a T55xx tag and set defaults
```
pm3 --> lf t55xx wipe
```

## Data
^[Top](#top)

Get raw samples [512-40000]
```
pm3 --> data samples <size>
```

Save samples to file
```
pm3 --> data save -f <filename>
```

Load samples from file
```
pm3 --> data load -f <filename>
```

## Lua Scripts
^[Top](#top)

List lua Scripts

```
pm3 --> script list
```

View lua helptext

```
pm3 --> script run <nameofscript> -h
```


Convert .bin to .eml
```
Options
---
-i <file>       Specifies the dump-file (input). If omitted, 'dumpdata.bin' is used
-o <filename>   Specifies the output file. If omitted, <uid>.eml is used

pm3 --> script run data_mf_bin2eml -i xxxxxxxxxxxxxx.bin
```

Convert .eml to .bin
```
Options
---
-i <filename>   Specifies the dump-file (input). If omitted, 'dumpdata.eml' is used
-o <filename>   Specifies the output file. If omitted, <currdate>.bin is used

pm3 --> script run data_mf_eml2bin -i myfile.eml -o myfile.bin
```

Format Mifare card
```
Options
---
-k <key>        The current six byte key with write access
-n <key>        The new key that will be written to the card
-a <access>     The new access bytes that will be written to the card
-x              Execute the commands as well

pm3 --> script run hf_mf_format -k FFFFFFFFFFFF -n FFFFFFFFFFFF -x
```

## Memory
^[Top](#top)

Load default keys into flash memory (RDV4 only)
```
Options
---
-o <offset>                    offset in memory
-f <filename>                  file name
    --mfc                      upload 6 bytes keys (mifare key dictionary)
    --iclass                   upload 8 bytes keys (iClass key dictionary)
    --t55xx                    upload 4 bytes keys (pwd dictionary)

pm3 --> mem load -f mfc_default_keys --mfc
pm3 --> mem load -f t55xx_default_pwds --t5xx
pm3 --> mem load -f iclass_default_keys --iclass
```

## Sim Module
^[Top](#top)

Upgrade Sim Module firmware
```
pm3 --> smart upgrade -f sim011.bin
```

## Smart Card
^[Top](#top)

Get Smart Card Information
```
pm3 --> smart info
```

Act like an IS07816 reader
```
pm3 --> smart reader
```

Set clock speed for smart card interface
```
Options
---
    --16mhz                    16 MHz clock speed
    --8mhz                     8 MHz clock speed
    --4mhz                     4 MHz clock speed


pm3 --> smart setclock --8mhz
```

Send raw hex data
```
Options
---
-r                             do not read response
-a                             active smartcard without select (reset sc module)
-s                             active smartcard with select (get ATR)
-t, --tlv                      executes TLV decoder if it possible
-0                             use protocol T=0
-d, --data <hex>               bytes to send

pm3 --> smart raw -s -0 -d 00a404000e315041592e5359532e4444463031
pm3 --> smart raw -0 -d 00a404000e325041592e5359532e4444463031
pm3 --> smart raw -0 -t -d 00a4040007a0000000041010
pm3 --> smart raw -0 -t -d 00a4040007a0000000031010
````

Bruteforce SPI
```
Options
---
-t, --tlv                      executes TLV decoder if it possible

pm3 --> smart brute
pm3 --> smart brute --tlv
```
