mf_nonce_brute
==============

Nested auntenticated sector key recovery tool
-----------------------------------------------

Compatible tags:
* Mifare Classic 1k (4k)
* Mifare Plus in SL1 mode

To recover keys to nested auntenticated sectors you need a reader-card communication log. To get it use 
hardware tools that able to sniff communication (for example Proxmark3 or HydraNFC).

This enhanced version:  
First 2 bytes should be bruteforced in phase 2 with mf_key_brute tool that interacts with a card.

Sample trace:
```
    93 70 fd ac f6 d8 7f 21 4f                            // select card with UID fdacf6d8
TAG 08 b6 dd                                              // sak
    60 04 d1 3d                                           // wanna auth block 0x04 with A key
TAG ed 12 9c 74                                           // 1st auth clear text nt
    55 53 9f cc 41 8d e8 f3                               // nr', ar'  (nr^ks1, ar^ks2 )
TAG 05 49 e1 65                                           // at' ( at^ks3 )
    03 24 26 56                                           // wanna read block 0x04
TAG ac 69 ef 58 45 e1 c2 1d a9 47 a5 94 54 ef 5d c7 1e a9 // block 0x04 content
    d4 3e a8 aa 
TAG 8e 8e e3 e6 e9 e2 5f dd f6 08 ce fb 02 6a db 75 94 2f 
    79 77 68 3c 
TAG e0 00 00 80 80 08 cc 80 08 9c 82 e0 68 64 60 30 91 60  // 18 bytes = 16 byte content + 2 bytes crc
    ea 88 c3 c2                                            // 4 byte read cmd
TAG a3 76 dc df c1 42 e0 ee c6 75 a4 ca eb 0c da eb 46 a0  // 18 bytes = 16 byte content + 2 bytes crc ks8 + crc
    2d 27 ab 6f                                            // wanna auth to 0x04 block with key B

-------Until this line we can recover key or decrypt communication with no troubles (see mfkey64 tool)--------------------------------

TAG 52 6e af 8b                                            // nested auth encrypted tag nonce that we don't know
    8e 21 3a 29 a4 80 7e 02                                // nr_enc = nr^ks1, ar_enc = ar^ks2
TAG b9 43 74 8d                                            // at_enc = at^ks3
    e2 25 f8 32                                            // probably next command (actually is read block cmd, but we don't know it yet)
TAG 1f 26 82 8d 12 21 dd 42 c2 84 3e d0 26 7f 6b 2a 81 a9  // probably data
    ba 85 1d 36                                            // probably read cmd
TAG 62 a8 78 69 ee 36 22 16 1c ff 4b 4e 69 cb 27 c2 e8 7e  // probably data
    a7 b1 c8 da                                            // probably read cmd
TAG b2 fc 6c 65 60 ec 35 83 87 56 e3 7e 3c bf 38 b8 73 21  // probably data
    99 92 13 55                                            // probably read cmd
TAG 93 5b 65 a3 1d 8c 75 b8 3a 63 e2 31 f0 d0 a9 24 9a f6  // probably data
```


Phase 1
-------

Syntax:  
`mf_nonce_brute <uid> <{nt}> <nt_par_err> <{nr}> <{ar}> <ar_par_err> <{at}> <at_par_err> [<{next_command}>]`

Example: if `nt` in trace is `8c!  42 e6! 4e!`, then `nt` is `8c42e64e` and `nt_par_err` is `1011`

Example with parity (from this trace http://www.proxmark.org/forum/viewtopic.php?pid=550#p550) :

```
 + 561882:  1 :     26
 +     64:  2 : TAG 04  00
 +  10217:  2 :     93  20
 +     64:  5 : TAG 9c  59  9b  32  6c                        UID
 +  12313:  9 :     93  70  9c  59  9b  32  6c  6b  30
 +     64:  3 : TAG 08  b6  dd
 + 923318:  4 :     60  00  f5  7b                            AUTH Block 0
 +    112:  4 : TAG 82  a4  16  6c                            Nonce Tag (NT)
 +   6985:  8 :     a1  e4! 58  ce! 6e  ea! 41  e0!           NR , AR
 +     64:  4 : TAG 5c! ad  f4  39!                           AT
 + 811513:  4 :     8e  0e! 5d! b9                            AUTH Block 0 (nested)
 +    112:  4 : TAG 5a! 92  0d! 85!                           Nonce Tag (NT)
 +   6946:  8 :     98! d7  6b! 77  d6  c6  e8  70            NR , AR
 +     64:  4 : TAG ca  7e! 0b! 63!                           AT
 + 670868:  4 :     3e! 70  9c! 8a
 +    112:  4 : TAG 36! 41  24! 79
 +   9505:  8 :     1b! 8c  3a! 48! 83  5a  4a! 27
 +     64:  4 : TAG 40! 6a! 99! 4b
 + 905612:  4 :     c9  7c  64! 13!                           !crc
 +    112:  4 : TAG b5! ab! 1d! 2b
 +   6936:  8 :     7e! d2  5c! ca! 4b! 50! 88! c4            !crc
 +     64:  4 : TAG bf  dd  01  be!
 + 987853:  4 :     56  98  49  d6!                           !crc
```
=>
```
./mf_nonce_brute 9c599b32 82a4166c 0000 a1e458ce 6eea41e0 0101 5cadf439 1001 8e0e5db9  
                 |        |        |    |        |        |    |        |    |
                 +UID     +nt_enc  |    +nr_enc  +ar_enc  |    +at_enc  |    +encrypted next cmd
                                   +nt_par_err            +at_par_err   +at_par_err
```

These two taken from above use the plaintext tagnonce `nt`=`82a4166c`,  they still find a possible key candidate.
```
./mf_nonce_brute 9c599b32 82a4166c 0000 a1e458ce 6eea41e0 0101 5cadf439 1001 
./mf_nonce_brute 9c599b32 82a4166c 0000 98d76b77 d6c6e870 0000 ca7e0b63 0111
```

This one uses the encrypted tagnonce `nt`=`5a920d85`, it finds a valid key.
```
./mf_nonce_brute 9c599b32 5a920d85 1011 98d76b77 d6c6e870 0000 ca7e0b63 0111
```

This one uses the encrypted tagnonce `nt`=`5a920d85` and the encrypted cmd `3e709c8a` to validate , it finds a valid key.
```
./mf_nonce_brute 9c599b32 5a920d85 1011 98d76b77 d6c6e870 0000 ca7e0b63 0111 3e709c8a
```
Full output:
```
$ ./mf_nonce_brute 9c599b32 5a920d85 1011 98d76b77 d6c6e870 0000 ca7e0b63 0111 3e709c8a
Mifare classic nested auth key recovery. Phase 1.
-------------------------------------------------
uid:            9c599b32
nt encrypted:   5a920d85
nt parity err:  1011
nr encrypted:   98d76b77
ar encrypted:   d6c6e870
ar parity err:  0000
at encrypted:   ca7e0b63
at parity err:  0111
next cmd enc:   3e709c8a


Starting 4 threads to bruteforce encrypted tag nonce last bytes
CMD enc(3e709c8a)
    dec(6000f57b)       <-- Valid cmd

Valid Key found: [ffffffffffff]

Time in mf_nonce_brute (Phase 1): 1763 ticks 2.0 seconds
```
