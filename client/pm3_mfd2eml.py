#!/usr/bin/python

'''
# Andrei Costin <zveriu@gmail.com>, 2011
# pm3_eml2mfd.py
# Converts PM3 Mifare Classic MFD binary dump file to emulator EML text file
'''

import sys
import binascii

def main(argv):
    argc = len(argv)
    if argc < 3:
        print 'Usage:', argv[0], 'input.mfd output.eml'
        sys.exit(1)

    try:
        file_inp = open(argv[1], "rb")
        file_out = open(argv[2], "w")
        
        while 1:
            # TODO: need to use defines instead of hardcoded 16, 64, etc.
            byte_s = file_inp.read(16)
            if not byte_s:
                break
            hex_char_repr = binascii.hexlify(byte_s)
            file_out.write(hex_char_repr)
            file_out.write("\n")
    
    finally:
        file_inp.close()
        file_out.close()

main(sys.argv)
