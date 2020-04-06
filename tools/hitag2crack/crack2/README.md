ht2crack2 suite



Build
-----

Edit ht2crack2buildtable.c and set the DATAMAX, NUM_BUILD_THREADS and NUM_SORT_THREADS values.
These are important if you want it to run quickly.  Ideally set DATAMAX to the largest value
that you can get away with and set NUM_BUILD_THREADS and NUM_SORT_THREADS to the number of
virtual cores you have available, which MUST be a power of 2.  NUM_BUILD_THREADS MUST be >=
NUM_SORT_THREADS.

Calculate DATAMAX = free RAM available / 65536, and then round down to a power of 10.

The Makefile is configured for linux.  To compile on Mac, edit it and swap the LIBS= lines.

```
make clean
make
```

Run ht2crack2buildtable
-----------------------

Make sure you are in a directory on a disk with at least 1.5TB of space.

```
./ht2crack2buildtable
```

Wait a very long time.  Maybe a few days.

This will create a directory tree called table/ while it is working that will contain
files that will slowly build up in size to approx 20MB each.  Once it has finished making
these unsorted files, it will sort them into the directory tree sorted/ and remove the
original files.  It will then exit and you'll have your shiny table.


Test with ht2crack2gentests
---------------------------

```
./ht2crack2gentests NUMBER_OF_TESTS
```

to generate NUMBER_OF_TESTS test files.  These will all be named
keystream.key-KEYVALUE.uid-UIDVALUE.nR-NRVALUE

Test a single test with

```
./runtest.sh KEYSTREAMFILE
```
or manually with

```
./ht2crack2search KEYSTREAMFILE UIDVALUE NRVALUE
```

or run all tests with
```
./runalltests.sh
```

Feel free to edit the shell scripts to find your tools.  You might want to create a
symbolic link to your sorted/ directory called 'sorted' to help ht2crack2seach find the
table.

If the tests work, then the table is sound.


Search for key in real keystream
--------------------------------

Recover 2048 bits of keystream from the target RFID tag with the RFIDler.  You will have had
to supply an NR value and you should know the tag's UID (you can get this using the RFIDler).

```
./ht2crack2search KEYSTREAMFILE UIDVALUE NRVALUE
```
