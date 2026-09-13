#!/usr/bin/env python3
#-----------------------------------------------------------------------------
# Copyright (C) 2026 Iceman. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# See LICENSE.txt for the text of the license.
#-------
#
# Recover the RSA public modulus a VIGIK service signs its cards with, from the cards alone. as described in 
# "A common weakness in RSA signatures: extracting public keys from communications and embedded devices",
# Renaud Lifchitz, Hackito Ergo Sum 2014.
#

import sys
from math import gcd

PI = [0x0E, 0x03, 0x05, 0x08, 0x09, 0x04, 0x02, 0x0F,
      0x00, 0x0D, 0x0B, 0x06, 0x07, 0x0A, 0x0C, 0x01]

SIG_LEN = 128       # RSA 1024
MSG_SLOTS = 64      # message byte slots in the block
VIGIK_AIDS = (0x4910, 0x4916)


def shadow(b):
    return (PI[b >> 4] << 4) | PI[b & 0x0F]

def vigik_struct(dump):
    if len(dump) < 1024:
        return None

    mad = dump[16:32]
    secs = [i + 1 for i in range(7)
            if int.from_bytes(mad[2 + 2 * i:4 + 2 * i], 'little') in VIGIK_AIDS]

    if not secs:
        return None

    buf = dump[0:48] + b''.join(dump[s * 64:s * 64 + 48] for s in secs)

    return buf if len(buf) >= 224 else None

def signed_message(buf):
    return (bytes(8) + buf[0:4] + buf[64:68] + buf[69:70] + buf[88:89] + buf[73:78] + buf[78:80])

def iso9796_1_block(msg, clear_top_bit):
    z = len(msg)
    rev = msg[::-1]
    stream = bytes(rev[(i - 1) % z] for i in range(MSG_SLOTS))
    f = bytearray(SIG_LEN)
    for i in range(MSG_SLOTS):
        f[2 * i] = shadow(stream[i])
        f[2 * i + 1] = stream[i]
    f[2 * (MSG_SLOTS - z)] ^= 0x01
    f[SIG_LEN - 1] = ((stream[MSG_SLOTS - 1] & 0x0F) << 4) | 0x06
    if clear_top_bit:
        f[0] ^= 0x80
    return int.from_bytes(bytes(f), 'big')

def card_multiple(buf):
    s = int.from_bytes(buf[96:96 + SIG_LEN][::-1], 'big')
    msg = signed_message(buf)
    out = 1
    for top in (False, True):
        f = iso9796_1_block(msg, top)
        for v in (s * s - f, s * s + f, 2 * s * s - f, 2 * s * s + f):
            if v:
                out *= v
    return abs(out)

def strip_small_factors(g, keep_bits=1024):
    for p in range(2, 200000):
        while g % p == 0 and (g // p).bit_length() >= keep_bits:
            g //= p
    return g

def recover(bufs, keep_bits=1024, verbose=False):
    g = 0
    for i, buf in enumerate(bufs):
        m = card_multiple(buf)
        g = m if g == 0 else gcd(g, m)
        if verbose:
            print("  after card %d: %d bits" % (i + 1, g.bit_length()))
        if g.bit_length() < keep_bits:
            return None
    g = strip_small_factors(g, keep_bits)
    return g if g.bit_length() == keep_bits else None

def main():

    if len(sys.argv) < 3:
        print("Recover the RSA public modulus of a VIGIK service from its cards.")
        print("")
        print("Usage:   %s <dump> <dump> [...]" % sys.argv[0])
        print("")
        print("Dumps are MIFARE Classic 1K binaries.")
        print("Two cards of the same service are usually enough")
        return 1

    bufs = []
    for fn in sys.argv[1:]:
        with open(fn, 'rb') as fd:
            buf = vigik_struct(fd.read())
        if buf is None:
            print("%s: no VIGIK application in the MAD, skipped" % fn)
            continue
        svc = int.from_bytes(buf[64:68], 'little') & 0xFFFF
        print("%s: service 0x%04X, uid %s" % (fn, svc, buf[0:4].hex()))
        bufs.append(buf)

    if len(bufs) < 2:
        print("\nNeed at least two cards signed by the same service.")
        return 1

    print("")
    n = recover(bufs, verbose=True)
    if n is None:
        print("\nNo 1024 bit modulus came out. Are these all the same service?")
        return 1

    print("\nPublic modulus (%d bits):" % n.bit_length())
    h = "%X" % n
    for i in range(0, len(h), 64):
        print("  %s" % h[i:i + 64])
    return 0


if __name__ == "__main__":
    sys.exit(main())
