#  xorcheck.py - find xor values for 8-bit LRC
#
#  Adam Laurie <adam@algroup.co.uk>
#  http://rfidiot.org/
#
#  This code is copyright (c) Adam Laurie, 2009, All rights reserved.
#  For non-commercial use only, the following terms apply - for all other
#  uses, please contact the author:
#
#    This code is free software; you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation; either version 2 of the License, or
#    (at your option) any later version.
#
#    This code is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
# 2020, Modified (@iceman1001)

import sys

def main():
    if(len(sys.argv) < 3):
        print("""
    \t{0} - Generate final byte for XOR LRC

    Usage: {0} <ID Byte1> <ID Byte2> ... <LRC>

    \tSpecifying the bytes of a UID with a known LRC will find the last byte value
    \tneeded to generate that LRC with a rolling XOR. All bytes should be specified in HEX.

    Example:

    \t{0} 04 00 80 64 ba

    Should produce the output:

    \tTarget (BA) requires final LRC XOR byte value: 5A\n""".format(sys.argv[0]))
        return 1

    target= int(sys.argv[len(sys.argv) - 1],16)

    lrc= 0x00
    for i in range(len(sys.argv) - 1):
        lrc ^= int(sys.argv[i + 1],16)
    print('\nTarget (%02X) requires final LRC XOR byte value: %02X\n' % (target,lrc))

if __name__ == "__main__":
    sys.exit(main())
