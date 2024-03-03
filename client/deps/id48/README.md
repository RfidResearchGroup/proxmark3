# ID48LIB

## Purpose

Enable reliable and repeatable key-writing and verification
on ID48 RFID tags.  Improve key recovery when the tag is
present and writable.

### Why this is needed.

Have you ever lost data when a computer shutdown unexpectedly?
This occurs when the program believes the data was written,
but the device did not actually store the data before power
was lost.

With RFID tags, the same problem exists, except the power is
wirelessly provided, and may be only enough to read data
(writing takes more power).  Thus, it's even more critical
for RFID tags to validate what was written.

If you are bothered by unreliable processes, and enjoy a measure
of certainty, and need to write a new key to an ID48 tag,
then read on.

### Problem background

The ProxMark3 RFID research tool has had basic support for
reading and writing ID48-based RFID tags (aka em4x70).  However,
although the code existed to write new 96-bit keys, there was no
way to verify that the keys were actually written to the tag.

This is because the keys are not directly readable from the tag
(by design).  The *only* way to verify that the key was successfully
stored on the tag is to perform an authentication against the tag,
using the new key that you had attempted to write, and verify that
the tag's response to the nonce and challenge matches.

Obviously, this requires the ability to calculate, given a known
key and nonce, the challenge to send to the tag, and the expected
response from the tag.  Without this, folks simply could not know
if the key was safely stored on the tag or not.

## Capabilities

This library provides the ability to calculate the challenge and
expected response for a known key and nonce.  In addition, if
provided the first half of the key, and at least one successful
authentication trio of nonce, challenge, and response, then
the library can recover all potentially valid values for the
second half of the key.
