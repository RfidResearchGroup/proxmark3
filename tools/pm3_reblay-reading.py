#!/usr/bin/env python3

"""
//-----------------------------------------------------------------------------
// Salvador Mendoza (salmg.net), 2021
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Code to test Proxmark3 Standalone mode aka reblay by Salvador Mendoza
//-----------------------------------------------------------------------------
"""

import serial
from smartcard.util import toHexString

ser = serial.Serial('/dev/rfcomm0')  # open Proxmark3 Bluetooth port

def pd(data):
        rapdu = map(ord, data)
        return rapdu

apdu = [
        [0x00, 0xA4, 0x04, 0x00, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0x00], # PPSE
        [0x00, 0xA4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00], # Visa card
        [0x80, 0xA8, 0x00, 0x00, 0x02, 0x83, 0x00, 0x00], # GET PROCESSING
        [0x00, 0xb2, 0x01, 0x0c, 0x00] # SFI
]

print('Testing code: bluetooth has to be connected with the right rfcomm port!')
print('Waiting for data...')
initd = ser.read(1)

bufferlen = pd(initd)[0]
rping = ser.read(bufferlen)

ping = pd(rping)
if (len(ping) == 7):
        print('UID:'),
        print(toHexString(ping[:4]))
        print('ATQA:'),
        print(toHexString(ping[4:-1]))
        print('SAK:'),
        print(toHexString(ping[-1:]))
elif (len(ping) == 10):
        print('UID:'),
        print(toHexString(ping[:7]))
        print('ATQA:'),
        print(toHexString(ping[7:-1]))
        print('SAK:'),
        print(toHexString(ping[-1:]))
else:
        print('got ping, no sure what it means: '),
        print(ping)

for x in apdu:
        print('Sending cmd: '),
        ser.write(x)
        print(toHexString(x))

        lenpk = ser.read(1) #first byte is the buffer length
        bufferlen = pd(lenpk)[0]

        buffer = pd(ser.read(bufferlen))
        print('Card Response:'),
        print(toHexString(buffer))
        print('--')

ser.write(b'1') #tell Proxmark3 that we finish the communication
ser.close()
