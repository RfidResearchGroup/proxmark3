#!/usr/bin/env python3
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
# SPDX-License-Identifier: GPL-3.0-or-later
"""Test USB packet boundaries and buffered commands on a connected PM3 (POSIX)."""

import argparse
import os
import select
import struct
import termios
import time
import tty


def ping(payload):
    return struct.pack('<IHH', 0x61334D50, 0x8000 | len(payload), 0x0109) + payload + b'a3'


def read_exact(port, length, deadline):
    data = bytearray()
    while len(data) < length:
        remaining = deadline - time.monotonic()
        if remaining <= 0 or not select.select([port], [], [], remaining)[0]:
            raise RuntimeError(f'reply timed out after {len(data)}/{length} bytes')
        data.extend(os.read(port, length - len(data)))
    return data


def check_pair(port, first, second):
    # One write can place both commands in one USB packet. Neither response may
    # depend on a subsequent write waking a command left in the receive buffer.
    pending = ping(first) + ping(second)
    while pending:
        if not select.select([], [port], [], 2)[1]:
            raise RuntimeError('write timed out')
        pending = pending[os.write(port, pending):]
    deadline = time.monotonic() + 2
    for expected in (first, second):
        header = read_exact(port, 10, deadline)
        magic, length, status, _, command = struct.unpack('<IHbbH', header)
        if (magic, length, status, command) != (0x62334D50, 0x8000 | len(expected), 0, 0x0109):
            raise RuntimeError(f'unexpected reply header: {header.hex()}')
        reply = read_exact(port, len(expected) + 2, deadline)
        if reply != expected + b'b3':
            raise RuntimeError(f'ping content mismatch: {reply.hex()}')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--port', required=True)
    parser.add_argument('--rounds', type=int, default=100)
    args = parser.parse_args()
    if args.rounds < 1:
        parser.error('--rounds must be positive')
    port = os.open(args.port, os.O_RDWR | os.O_NOCTTY | os.O_NONBLOCK)
    saved = termios.tcgetattr(port)
    try:
        tty.setraw(port)
        config = termios.tcgetattr(port)
        config[2] |= termios.CLOCAL | termios.CREAD
        config[2] &= ~getattr(termios, 'CRTSCTS', 0)
        config[4] = config[5] = termios.B115200
        termios.tcsetattr(port, termios.TCSANOW, config)
        termios.tcflush(port, termios.TCIOFLUSH)
        lengths = (0, 1, 53, 54, 55, 117, 118, 119, 512)
        for iteration in range(args.rounds):
            for length in lengths:
                payload = bytes((iteration + i) & 255 for i in range(length))
                check_pair(port, payload, bytes([iteration & 255]))
        print(f'PASS: {args.rounds * len(lengths) * 2} pings, including coalesced commands')
    finally:
        termios.tcsetattr(port, termios.TCSANOW, saved)
        os.close(port)


if __name__ == '__main__':
    main()
