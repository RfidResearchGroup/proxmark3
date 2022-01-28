#!/usr/bin/env python3

'''
# Andrei Costin <zveriu@gmail.com>, 2011
# pm3_eml2mfd.py
# Converts PM3 Mifare Classic MFD binary dump file to emulator EML text file
'''
import sys

READ_BLOCKSIZE = 16

def main(argv):
    argc = len(argv)
    if argc < 3:
        print('Usage:', argv[0], 'input.mfd output.eml')
        return 1

    with open(argv[1], "rb") as file_inp, open(argv[2], "w") as file_out:
        while True:
            byte_s = file_inp.read(READ_BLOCKSIZE)
            if not byte_s:
                break
            hex_char_repr = byte_s.hex()
            file_out.write(hex_char_repr)
            file_out.write("\n")

if __name__ == '__main__':
    sys.exit(main(sys.argv))
