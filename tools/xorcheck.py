#!/usr/bin/python

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

import sys
import os

if(len(sys.argv) < 3):
	print
	print '\t'+sys.argv[0] + ' - Generate final byte for XOR LRC'
	print
	print 'Usage: ' + sys.argv[0] + ' <ID Byte1> <ID Byte2> ... <LRC>'
	print
	print '\tSpecifying the bytes of a UID with a known LRC will find the last byte value'
	print '\tneeded to generate that LRC with a rolling XOR. All bytes should be specified in HEX.'
	print
	print 'Example:'
	print
	print '\txorcheck.py 04 00 80 64 ba'
	print
	print 'Should produce the output:'
	print
	print '\tTarget (BA) requires final LRC XOR byte value: 5A'
	print
	os._exit(True)

target= int(sys.argv[len(sys.argv) - 1],16)

lrc= 0x00
for i in range(len(sys.argv) - 1):
	lrc ^= int(sys.argv[i + 1],16)
print
print 'Target (%02X) requires final LRC XOR byte value: %02X' % (target,lrc)
print
