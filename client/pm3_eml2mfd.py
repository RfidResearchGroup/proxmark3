#!/usr/bin/python

'''
# Andrei Costin <zveriu@gmail.com>, 2011
# pm3_eml2mfd.py
# Converts PM3 Mifare Classic emulator EML text file to MFD binary dump file
'''

import sys
import binascii

def main(argv):
    argc = len(argv)
    if argc < 3:
        print 'Usage:', argv[0], 'input.eml output.mfd'
        sys.exit(1)

    try:
        file_inp = open(argv[1], "r")
        file_out = open(argv[2], "wb")
        line = file_inp.readline()
        while line:
            line = line.rstrip('\n')
            line = line.rstrip('\r')
            print line
            data = binascii.unhexlify(line)
            file_out.write(data)
            line = file_inp.readline()

    finally:
        file_inp.close()
        file_out.close()

main(sys.argv)
