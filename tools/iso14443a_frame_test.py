#!/usr/bin/env python3
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Compile and exercise the firmware's ISO14443A frame-completeness predicate."""

import os
from pathlib import Path
import shlex
import subprocess
import tempfile


SOURCE = r'''
#include <stdio.h>
#include "iso14443a.h"

int main(void) {
    tDemod14a frame = {0};
    frame.len = 4;
    frame.parityLen = 1;
    if (!iso14a_is_complete_frame(&frame, 4)) return 1;

    // Regression: four bytes with unfinished trailing bits are not a nonce.
    for (uint16_t bits = 1; bits <= 8; bits++) {
        frame.bitCount = bits;
        if (iso14a_is_complete_frame(&frame, 4)) return 2;
    }
    frame.bitCount = 0;
    frame.collisionPos = 1;
    if (iso14a_is_complete_frame(&frame, 4)) return 3;
    frame.collisionPos = 0;
    for (uint8_t parity_len = 0; parity_len <= 2; parity_len += 2) {
        frame.parityLen = parity_len;
        if (iso14a_is_complete_frame(&frame, 4)) return 4;
    }
    frame.parityLen = 1;
    for (uint16_t len = 0; len <= 5; len++) {
        frame.len = len;
        if (iso14a_is_complete_frame(&frame, 4) != (len == 4)) return 5;
    }
    frame.len = 0;
    frame.parityLen = 0;
    if (iso14a_is_complete_frame(&frame, 0)) return 6;
    frame.len = 9;
    frame.parityLen = 1;
    if (iso14a_is_complete_frame(&frame, 9)) return 7;
    frame.parityLen = 2;
    if (!iso14a_is_complete_frame(&frame, 9)) return 8;
    puts("ISO14443A frame test: OK");
    return 0;
}
'''


def main():
    root = Path(__file__).resolve().parent.parent
    with tempfile.TemporaryDirectory(prefix="iso14443a-frame-test-") as directory:
        executable = Path(directory) / ("frame_test.exe" if os.name == "nt" else "frame_test")
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c99", "-Wall", "-Wextra", "-Werror", "-DPM5",
            "-I" + str(root / "armsrc"), "-I" + str(root / "include"),
            "-I" + str(root / "common"), "-x", "c", "-", "-o", str(executable),
        ]
        subprocess.run(command, input=SOURCE, text=True, check=True)
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
