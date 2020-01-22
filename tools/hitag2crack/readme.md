HiTag2 Cracking Suite
---------------------

Author: Kevin Sheldrake <kev@headhacking.com>

Introduction
------------

These tools are implementations of the four attacks detailed in the papers,
Gone In 360 Seconds - Hijacking With HiTag 2 by Roel Verdult, Flavio Garcia
and Josep Balasch, and Lock It And Still Lose It - on the (In)Security of
Automotive Remote Keyless Entry Systems by Flavio Garcia, David Oswald,
Timo Kasper and Pierre Pavlides.  The first three attacks come from the first
paper and the fourth attack comes from the second paper.

Attack 1
--------

Attack 1 is a nonce replay and length extension attack.  This is an attack on
a single HiTag2 RFID tag, given a single encrypted nonce and challenge
response value pair (nR, aR) for the tag's UID.  The attack runs entirely on
the RFIDler with it acting like a RWD that replays the same encrypted nonce
and challenge response pair for every interaction; this fixes the key stream
that the tag's PRNG outputs to the same stream for every interaction.

By brute forcing a subset of the encrypted command space, the RFIDler finds a
single valid encrypted command - invalid commands return a known unencrypted
error response so finding a valid one is simply a case of trying different
values until a response other than the error response is received.

It then bit flips the valid encrypted command to find the other 15 valid
encrypted commands.  By knowing the contents of page 0 - it's the UID that
is presented in clear at the start of each interaction - it tries each
encrypyted response in turn, assuming each to be the encrypted version of
'read page 0 non-inverted' and each response to be the encrypted version of
page 0.

For each attempted command, it calculates the key stream that would have
correctly generated the encrypted command and response:
command ++ response XOR key stream = encrypted command ++ encrypted response
therefore:
key stream = command ++ response XOR encrypted command ++ encrypted response

It then tests the potentially recovered key stream by creating an encrypted
command that consumes as much of it as possible, re-initialising with the same
encrypyted nonce and challenge response pair (to set the key stream to the
same stream as that which produced the encrypted command response it is
testing), and then sending this extended encrypted command.  If the response
is not the error response, then the key stream is valid and the response is
the encryption of the page 0 contents (the UID).

When one of the valid encrypted commands satisfies this situation, the
recovered key stream must be the output of the PRNG for the given encrypted
nonce and challenge response pair.

The RFIDler then uses this key stream to encrypt commands and decrypt the
responses, and therefore requests the contents of all 8 pages.  Pages 1 and 2
contain the encryption key.

Attack 2
--------

Attack 2 is a time/space trade off to recover the key for situations where the
tag has been configured to prevent reading of pages 1 and 2.  This attack uses
a pre-computed table of 2^37 PRNG states and resultant PRNG output, sorted on
the PRNG output.  The RFIDler is used to recover 2048 bits of key stream using
a modification of attack 1 and this is used to search the table for matching
PRNG output.  When the output is found, it is tested for validity (by testing
previous or following PRNG output) and then the PRNG state is rolled back to
the initialisation state, from which the unecrypted nonce and key can be
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

Usage details
-------------

Attack 1 requires a valid tag and a valid encrypted nonce and challenge
response pair.  The attacker needs to obtain a valid tag and then use this to
obtain a valid encrypted nonce and challenge response pair.  This can be
acheived by using the RFIDler 'SNIFF-PWM S' command (having previously cleared
the nonce storage with 'SNIFF-PWM C'), placing the coil on the RWD and
presenting the valid tag.  The encrypted nonce and challenge response pairs
can then be read out with the 'SNIFF-PWM L' command.  These values can then
be used to attack the tag with 'HITAG2-CRACK <nR> <aR>'.

RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM C
RFIDler: SNIFF-PWM S
Capture encrypted nonce and challenge response pair (nR, aR).
RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM L
RFIDler: HITAG2-CRACK <nR> <aR>

Attack 2 requires the same resources as attack 1, plus a pre-computed table.
The table can be generated on a disk with >1.5TB of storage, although it takes
some time (allow a couple of days).
./ht2crack2buildtable
RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM C
RFIDler: SNIFF-PWM S
Capture encrypted nonce and challenge response pair (nR, aR).
RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM L
RFIDler: UID
RFIDler: HITAG2-KEYSTREAM <nR> <aR>
Copy/paste the key stream to a file.
./ht2crack2search <key stream file> <tag UID> <nR>

Attack 3 requires only interaction with the RWD and does not require a valid
tag, although it does require a HiTag2 tag that the RWD will initially respond
to; e.g. you could potentially use any HiTag2 tag as long as the RWD starts
the crypto handshake with it.  It requires >=136 encrypted nonce and challenge
response pairs for the same tag UID.

RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM C
RFIDler: SNIFF-PWM S
Capture >=136 encrypted nonce and challenge response pairs (nR, aR).
RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM L
RFIDler: UID
Copy/paste the encrypted nonce and challenge response pairs into a file.
./ht2crack3 <tag UID> <nR aR file>

Attack 4 requires the same information as attack 3, but only 16-32 encrypted
nonce and challenge response pairs are required.
./ht2crack4 -u <tag UID> -n <nR aR file> [-N <number of nonces to use>]
   [-t <table size>]

Start with -N 16 and -t 500000.  If the attack fails to find the key, double
the table size and try again, repeating if it still fails.

Once the key has been recovered using one of these attacks, the RFIDler can
be configured to operate as a RWD and will capture tags using that key.
RFIDler: SET TAG HITAG2
RFIDler: HITAG2-READER <KEY>

Both the SNIFF-PWM and HITAG2-READER commands can be used as AUTORUN commands
for when the RFIDler is powered from a USB power supply without interaction.

RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM C
RFIDler: AUTORUN SNIFF-PWM S
RFIDler: SAVE
Capture encrypted nonce and challenge response pairs.
RFIDler: SET TAG HITAG2
RFIDler: SNIFF-PWM L


RFIDler: SET TAG HITAG2
RFIDler: HITAG2-CLEARSTOREDTAGS
RFIDler: AUTORUN HITAG2-READER <KEY> S
RFIDler: SAVE
Capture tags.
RFIDler: HITAG2-COUNTSTOREDTAGS
RFIDler: HITAG2-LISTSTOREDTAGS [START] [END]


Tags can be copied with standard RFIDler commands.

RFIDler: SET TAG HITAG2
RFIDler: COPY
RFIDler: VTAG
Replace original tag with a blank tag.
RFIDler: CLONE <blank tag password/key - defaults to 4d494b52>

OR:

RFIDler: SET TAG HITAG2
RFIDler: SET VTAG HITAG2
RFIDler: VWRITE 0 <page 0 contents>
RFIDler: VWRITE 1 <page 1 contents>
...
RFIDler: VWRITE 7 <page 7 contents>
RFIDler: VTAG
Place blank tag on coil.
RFIDler: CLONE <blank tag password/key - defaults to 4d494b52>

OR:

RFIDler: SET TAG HITAG2
RFIDler: SET VTAG HITAG2
RFIDler: VWRITE 0 <all 8 page contents with no spaces>
RFIDler: VTAG
Place blank tag on coil.
RFIDler: CLONE <blank tag password/key - defaults to 4d494b52>


