HiTag2 Cracking Suite
---------------------

Authors:

* Attacks 1, 2, 3, 4 : Kevin Sheldrake <kev@headhacking.com>
* Attacks 5, 5gpu : anonymous, based on https://github.com/factoritbv/hitag2hell by FactorIT B.V.
* Attack  5opencl : Gabriele Gristina <gabriele.gristina@gmail.com>, based on 5gpu

Introduction
------------

These tools are implementations of the four attacks detailed in the papers,
Gone In 360 Seconds - Hijacking With HiTag 2 by Roel Verdult, Flavio Garcia
and Josep Balasch, and Lock It And Still Lose It - on the (In)Security of
Automotive Remote Keyless Entry Systems by Flavio Garcia, David Oswald,
Timo Kasper and Pierre Pavlides.  The first three attacks come from the first
paper and the fourth attack comes from the second paper.


_note_
There are no Proxmark3 client implemented commands for these attacks. Only separate executables to be compiled and run on your own system.
No guarantees of working binaries on all systems.  Some work on linux only. 
There is no easy way to extract the needed data from a live system and use with these tools.
You can use the `RFIdler` device but the Proxmark3 client needs some more love.  Feel free to contribute.

Attack 1
--------

Attack 1 is a nonce replay and length extension attack.  This is an attack on
a single HiTag2 RFID tag, given a single encrypted nonce and challenge
response value pair (nR, aR) for the tag's UID.  The attack runs entirely on
the Proxmark3 with it acting like a RWD that replays the same encrypted nonce
and challenge response pair for every interaction; this fixes the key stream
that the tag's PRNG outputs to the same stream for every interaction.

By brute forcing a subset of the encrypted command space, the Proxmark3 finds a
single valid encrypted command - invalid commands return a known unencrypted
error response so finding a valid one is simply a case of trying different
values until a response other than the error response is received.

It then bit flips the valid encrypted command to find the other 15 valid
encrypted commands.  By knowing the contents of page 0 - it's the UID that
is presented in clear at the start of each interaction - it tries each
encrypted response in turn, assuming each to be the encrypted version of
'read page 0 non-inverted' and each response to be the encrypted version of
page 0.

For each attempted command, it calculates the key stream that would have
correctly generated the encrypted command and response:
command ++ response XOR key stream = encrypted command ++ encrypted response
therefore:
key stream = command ++ response XOR encrypted command ++ encrypted response

It then tests the potentially recovered key stream by creating an encrypted
command that consumes as much of it as possible, re-initialising with the same
encrypted nonce and challenge response pair (to set the key stream to the
same stream as that which produced the encrypted command response it is
testing), and then sending this extended encrypted command.  If the response
is not the error response, then the key stream is valid and the response is
the encryption of the page 0 contents (the UID).

When one of the valid encrypted commands satisfies this situation, the
recovered key stream must be the output of the PRNG for the given encrypted
nonce and challenge response pair.

The Proxmark3 then uses this key stream to encrypt commands and decrypt the
responses, and therefore requests the contents of all 8 pages.  Pages 1 and 2
contain the encryption key.

Attack 2
--------

Attack 2 is a time/space trade off to recover the key for situations where the
tag has been configured to prevent reading of pages 1 and 2.  This attack uses
a pre-computed table of 2^37 PRNG states and resultant PRNG output, sorted on
the PRNG output.  The Proxmark3 is used to recover 2048 bits of key stream using
a modification of attack 1 and this is used to search the table for matching
PRNG output.  When the output is found, it is tested for validity (by testing
previous or following PRNG output) and then the PRNG state is rolled back to
the initialisation state, from which the unencrypted nonce and key can be
recovered.

Attack 3
--------

Attack 3 is a cryptanalytic attack that focuses on the RWD and a bias in the
PRNG output.  By capturing 136 encrypted nonce and challenge response pairs,
candidates for the first 34 bits of the key can be identified, and for each
the remaining 14 bits can be brute forced.

Attack 4
--------

Attack 4 is a fast correlative attack on the key based on a number of captured
encrypted nonce and challenge response pairs (up to 32, but 16 usually
sufficient).  It starts by guessing the first 16 bits of the key and scores
all these guesses against how likely they are to be the correct key, given the
encrypted nonces and the keystream they should produce.  Each guess is then
expanded by 1 bit and the process iterates, with only the best guesses taken
forward to the next iteration.

Attack 5
--------

Attack 5 is heavily based on the HiTag2 Hell CPU implementation from https://github.com/factoritbv/hitag2hell by FactorIT B.V.,
with the following changes:

* Main takes a UID and 2 {nR},{aR} pairs as arguments and searches for states producing the first aR sample, reconstructs the corresponding key candidates and tests them against the second nR,aR pair;
* Reuses the Hitag helping functions of the other attacks.

Attack 5gpu
-----------

Attack 5gpu is identical to attack 5, simply the code has been ported to OpenCL
to run on GPUs and is therefore much faster than attack 5.

Attack 5opencl
--------------

Attack 5opencl is an optimized OpenCL version based on 5gpu.
It runs on multi GPUs/CPUs and is faster than 5gpu.

Usage details: Attack 1
-----------------------

Attack 1 requires a valid tag and a valid encrypted nonce and challenge
response pair.  The attacker needs to obtain a valid tag and then use this to
obtain a valid encrypted nonce and challenge response pair.  This can be
achieved by using the Proxmark3 `lf hitag sniff` command, placing the coil on the RWD and
presenting the valid tag.  The encrypted nonce and challenge response pairs
can then be read out.   

_note_  the Proxmark3 hitag sniff command isn't good enough yet to collect the needed data.

**TODO** example


Usage details: Attack 2
-----------------------

Attack 2 requires the same resources as attack 1, plus a pre-computed table.
The table can be generated on a disk with >1.5TB of storage, although it takes
some time (allow a couple of days, privilege SSD). This can be
achieved by using the Proxmark3 `lf hitag sniff` command, placing the coil on the RWD and
presenting the valid tag.  The encrypted nonce and challenge response pairs
can then be read out.  

_note_  the Proxmark3 hitag sniff command isn't good enough yet to collect the needed data.

**TODO** example


Usage details: Attack 3
-----------------------

Attack 3 requires only interaction with the RWD and does not require a valid
tag, although it does require a HiTag2 tag that the RWD will initially respond
to; e.g. you could potentially use any HiTag2 tag as long as the RWD starts
the crypto handshake with it.  It requires >=136 encrypted nonce and challenge
response pairs for the same tag UID.

_note_  the Proxmark3 hitag sniff command isn't good enough yet to collect the needed data.

**TODO** will be ht2 sim or sniff with actual tag ?


Usage details: Attack 4
-----------------------

Attack 4 requires the same information as attack 3, but only 16-32 encrypted
nonce and challenge response pairs are required.

_note_  the Proxmark3 hitag sniff command isn't good enough yet to collect the needed data.

**TODO** example

Usage details: Attack 5
-----------------------

Attack 5 requires two encrypted nonce and challenge
response value pairs (nR, aR) for the tag's UID.

**TODO** example


Usage details: Attack 5gpu/5opencl
----------------------------------

Attacks 5gpu and 5opencl require two encrypted nonce and challenge
response value pairs (nR, aR) for the tag's UID.

**TODO** example

5opencl supports a number of additional parameters, see [crack5opencl/README.md](/tools/hitag2crack/crack5opencl/README.md) for details.

Usage details: Next steps
-------------------------

Once the key has been recovered using one of these attacks, the Proxmark3 can
be configured to operate as a RWD and will capture tags using that key.

**TODO** example

Tags can be copied with standard Proxmark3 commands.

**TODO** example
