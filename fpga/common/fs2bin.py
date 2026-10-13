#!/usr/bin/env python3

# Pack an ASCII Gowin bitstream (.fs from apycula's gowin_pack) into the binary
# form the ARM JTAG loader shifts out for `hw fpga config`.
# Every byte in the .fs is 8 ASCII '0'/'1' characters, most significant bit
# first; the inverse of apycula's bslib.bytearr(), which is reused here so the
# two cannot drift apart.
#
# usage: fs2bin.py <in.fs> <out.bin>

import sys

from apycula.bslib import bytearr


def main(infile, outfile):
    data = bytearray()
    with open(infile) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            if len(line) % 8:
                sys.exit("{}: line of {} characters is not a multiple of 8".format(infile, len(line)))
            data += bytearr(line)

    with open(outfile, "wb") as f:
        f.write(data)

    print("[=] PACK {} ({} bytes)".format(outfile, len(data)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: fs2bin.py <in.fs> <out.bin>")
    main(sys.argv[1], sys.argv[2])
