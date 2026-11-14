#!/usr/bin/env python3

# Print the footer 0x0A word of a Gowin bitstream (.bin), the value to compare
# with the "usercode" line of `hw status` on a PM5 running that image.
#
# usage: gowin_usercode.py <file.bin>

import sys

TAIL = 64


def main(path):
    data = open(path, "rb").read()[-TAIL:]
    pos = data.rfind(b"\x0a\x00\x00\x00")
    if pos < 0 or pos + 8 > len(data):
        sys.exit("no 0x0A footer entry in the last {} bytes of {}".format(TAIL, path))
    print("0x{:08X}".format(int.from_bytes(data[pos + 4:pos + 8], "big")))


if __name__ == "__main__":
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-1])
    main(sys.argv[1])
