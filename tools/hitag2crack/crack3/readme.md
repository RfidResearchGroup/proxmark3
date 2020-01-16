ht2crack3



Build
-----

make clean
make


Run
---

You'll need a file consisting of 136 (or more) nR aR pairs.  These are the
encrypted nonces and challenge response values.  They should be in hex with
one pair per line, e.g.:
0x12345678 0x9abcdef0

./ht2crack3 UID NRARFILE

UID is the UID of the tag that you used to gather the nR aR values.
NRARFILE is the file containing the nR aR values.


Tests
-----

If you happen to know the key and want to check that all your nR aR values
are valid (for high-powered demonstrations only, really) then you can use
the ht2test program to check them.  It's otherwise massively pointless and a
complete waste of space.

./ht2test NRARFILE KEY UID

