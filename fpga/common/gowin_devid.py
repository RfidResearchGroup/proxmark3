#!/usr/bin/env python3

# Stamp the real device IDCODE into a Gowin bitstream (.fs from apycula's
# gowin_pack), in place, and repair the CRC that depends on it.
#
# apycula's GW1N-4 database writes 0x0100381B, the plain GW1N-4, but the
# GW1N-4B/4D silicon on a PM5 reports 0x1100381B. The device compares that
# field with its own IDCODE and refuses an image that disagrees: the FPGA stays
# unconfigured (Gowin status register done_final = 0), so nothing drives the
# antenna and `hw tune` reads a couple of volts instead of tens. `hw fpga
# config` prints the value to use here as "gowin_jtag OK: idcode = ...".
#
# Only the IDCODE changes. The running CRC that apycula's write_bitstream()
# carries into the first row covers the header entries, so that one CRC is
# recomputed. Every other row is verified rather than rewritten, so a change to
# the apycula bitstream layout is reported instead of silently producing an
# image that will not configure.
#
# usage: gowin_devid.py <file.fs> <idcode>

import sys

PREAMBLE = 3   # write_bitstream() starts folding header entries into the CRC after these
SKIP = 0xd2    # ... and leaves the SPI address entry out


def crc16_arc(data):
    """CRC-16/ARC: poly 0x8005 reflected, init 0, xorout 0, as apycula computes it."""
    crc = 0
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def to_bytes(line):
    """8 ASCII '0'/'1' characters per byte, most significant bit first"""
    return bytearray(int(line[i:i + 8], 2) for i in range(0, len(line), 8))


def to_line(data):
    return "".join("{:08b}".format(b) for b in data)


def split(blocks):
    """header, rows, footer: the rows are the repeated long lines in the middle"""
    lengths = [len(b) for b in blocks]
    row_len = max(set(lengths), key=lengths.count)
    first = next(n for n, b in enumerate(blocks) if len(b) == row_len)
    last = len(blocks) - 1 - next(n for n, b in enumerate(reversed(blocks)) if len(b) == row_len)
    head, rows, foot = blocks[:first], blocks[first:last + 1], blocks[last + 1:]
    if len(head) <= PREAMBLE or not rows or not foot:
        sys.exit("unexpected .fs layout: {} header, {} row(s), {} footer entries".format(
            len(head), len(rows), len(foot)))
    for row in rows:
        if row[-6:] != b"\xff" * 6:
            sys.exit("unexpected .fs row: not terminated by {} CRC + 6 padding bytes".format(2))
    return head, rows, foot


def main(path, idcode):
    blocks = [to_bytes(l) for l in open(path).read().splitlines() if l]
    head, rows, foot = split(blocks)

    # the first entry write_bitstream() folds into the CRC, right after the preamble
    chip = head[PREAMBLE]
    old = int.from_bytes(chip[-4:], "big")
    if old == idcode:
        print("[=] DEVID {} already 0x{:08X}".format(path, idcode))
        return
    chip[-4:] = idcode.to_bytes(4, "big")

    # what write_bitstream() has accumulated once it reaches the first row
    seed = b"".join(bytes(entry) for entry in head[PREAMBLE:] if entry[0] != SKIP)

    for n, row in enumerate(rows):
        data = bytes(row[:-8])
        want = crc16_arc(seed + data if n == 0 else b"\xff" * 6 + data)
        if n == 0:
            row[-8:-6] = want.to_bytes(2, "little")
        elif row[-8:-6] != want.to_bytes(2, "little"):
            sys.exit("row {} CRC mismatch: apycula changed the bitstream layout".format(n))

    with open(path, "w") as f:
        for block in head + rows + foot:
            f.write(to_line(block) + "\n")

    print("[=] DEVID {} 0x{:08X} -> 0x{:08X}".format(path, old, idcode))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: gowin_devid.py <file.fs> <idcode>")
    main(sys.argv[1], int(sys.argv[2], 16))
