ht2crack4



Build
-----

make clean
make


Run
---

You'll need a file consisting of 16 (or more) nR aR pairs.  These are the
encrypted nonces and challenge response values.  They should be in hex with
one pair per line, e.g.:
0x12345678 0x9abcdef0

./ht2crack4 -u UID -n NRARFILE [-N nonces to use] [-t table size]

UID is the UID of the tag that you used to gather the nR aR values.
NRARFILE is the file containing the nR aR values.
The number of nonces to use allows you to use less than 32 nonces to increase
speed.
The table size can be tweaked for speed.  Start with 500000 and double it each
time it fails to find the key.


