#!/usr/bin/env python3

#  findbits.py - find Binary, Octal, Decimal or Hex number in bitstream
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

import sys
import os

# invert binary string
def invert(data):
    return ''.join('0' if c == '1' else '1' for c in data)

# do the actual search
def search(target,data):
    location = data.find(target)
    if location >= 0:
        print('*** Match at bit {:d}: {}<{}>{}'.format(location, data[:location],target,data[location+len(target):]))
    else:
        print('Not found')

# convert integer to binary string
def binstring(number):
    return bin(number)[2:] if number > 0 else ''

# reverse string order
def stringreverse(data):
    return data[::-1]

# match forward, backward and inverted
def domatch(binary,number):
    reversed= stringreverse(number)
    inverted= invert(binary)

    print('  Forward: (%s) ' % number, end = '')
    search(binary,number)
    print('  Reverse: (%s) ' % reversed, end = '')
    search(binary,reversed)
    print('  Inverse: (%s) ' % inverted)
    print('    Forward: (%s) ' % number, end = '')
    search(inverted,number)
    print('    Reverse: (%s) ' % reversed, end = '')
    search(inverted,reversed)

def main():
    if(len(sys.argv) < 3):
        print("""
\t{0} - Search bitstream for a known number

Usage: {0} <NUMBER> <BITSTREAM>

\tNUMBER will be converted to its BINARY equivalent for all valid
\tinstances of BINARY, OCTAL, DECIMAL and HEX, and the bitstream
\tand its inverse will be searched for a pattern match. Note that
\tNUMBER must be specified in BINARY to match leading zeros.

Example:

\t{0} 73 0110010101110011
""".format(sys.argv[0]))
        os._exit(True)

    bases=    {
        2:'BINARY',
        8:'OCTAL',
        10:'DECIMAL',
        16:'HEX',
            }

    for base, base_name in sorted(bases.items()):
        try:
            number= int(sys.argv[1],base)
            print('\nTrying ' + base_name)
            # do BINARY as specified to preserve leading zeros
            if base == 2:
                domatch(sys.argv[1],sys.argv[2])
            else:
                domatch(binstring(number),sys.argv[2])
        except:
            continue

if __name__ == '__main__':
    main()
