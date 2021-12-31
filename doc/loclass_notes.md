# Notes about the LOCLASS attack
<a id="top"></a>

# Table of Contents
- [Notes about the LOCLASS attack](#notes-about-the-loclass-attack)
- [Table of Contents](#table-of-contents)
- [Unit testing](#unit-testing)


This document is primarily intended for understanding `hf iclass loclass` and files used with it.

LOCLASS aim is to recover the used masterkey for that specific reader configured in Elite mode / High Security mode.

LOCLASS, is a two part attack. First is the online part where you gather needed information from the reader by presenting a carefully selected CSN and save the responses to file.  For the first part you run `hf iclass sim -t 2` and take notice of the saved filename.

The second part is offline,  where the information gathered from the first step is used in a series of DES operations to figure out the used 
masterkey.
   run `hf iclass loclass -f abc.bin`

If you don't have access to a iClass SE reader configured in Elite mode there is a test file which you can use.
   `hf iclass loclass -f iclass_dump.bin` 


# Unit testing
^[Top](#top)

In order to verify that loclass is actually working, there is a "unit" test mode.
run `hf iclass loclass --test`.

This test mode uses two files. 

- `iclass_dump.bin`
   this is a sample file from `hf iclass sim -t 2`, with complete keytable recovery, using 128 carefully selected CSN and the file contains the MAC results from reader. 
- `iclass_key.bin`
   this is file shall contain the legacy masterkey, AA1 key. loclass uses it to verify that permutation / reversing / generation of key is correct.