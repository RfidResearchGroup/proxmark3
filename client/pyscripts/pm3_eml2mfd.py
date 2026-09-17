#!/usr/bin/env python3

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
        print('Usage:', argv[0], 'input.eml output.mfd')
        return 1

    with open(argv[1], "r") as file_inp, open(argv[2], "wb") as file_out:
        for line in file_inp:
            line = line.rstrip('\n').rstrip('\r')
            print(line)
            data = binascii.unhexlify(line)
            file_out.write(data)

if __name__ == '__main__':
    sys.exit(main(sys.argv))
