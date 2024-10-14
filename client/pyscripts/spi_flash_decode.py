#!/usr/bin/env python3

import re
import pm3
# optional color support
try:
    # pip install ansicolors
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

spi = {
    0x85:{
        "manufacturer": "Puya",
        0x60: {
            0x15: {
                "part": "P25Q16H",
                "size": "16mbits",
                "sizeB": "2MB",
                },
            },
        },
    0xEF:{
        "manufacturer": "Winbond",
        0x30: {
            0x11: {
                "part": "W25X10BV",
                "size": "1mbits",
                "sizeB": "128KB",
                },
            0x12: {
                "part": "W25X20BV",
                "size": "2mbits",
                "sizeB": "256KB",
                },
            0x13: {
                "part": "W25X40BV",
                "size": "4mbits",
                "sizeB": "512KB",
                },
            },
        0x40: {
            0x16: {
                "part": "W25Q32BV",
                "size": "32mbits",
                "sizeB": "4MB",
                },
            },
            0x13: {
                "part": "W25Q40BV",
                "size": "4mbits",
                "sizeB": "512KB",
                },
            },
        0x70: {
            0x22: {
                "part": "W25Q02JV-IM",
                "size": "2mbits",
                "sizeB": "256KB",
                },
            },
        },
    }

p = pm3.pm3()

p.console("hw status")

rex = re.compile("...\\s([0-9a-fA-F]{2})\\s/\\s([0-9a-fA-F]{4})")
for line in p.grabbed_output.split('\n'):
    # [#]   JEDEC Mfr ID / Dev ID... 85 / 6015
    if " JEDEC " not in line:
        continue
    match = re.findall(rex, line)
    mid = int(match[0][0], 16)
    did = int(match[0][1], 16)
    did_h = did >> 8
    did_l = did & 0xff
    t = None
    if mid in spi:
        mfr = spi[mid]['manufacturer']
        if did_h in spi[mid]:
            if did_l in spi[mid][did_h]:
                t = spi[mid][did_h][did_l]
                print("\n Manufacturer... " + color(f"{mfr}", fg="green") +
                     "\n Device......... " + color(f"{t['part']}", fg="green") +
                     "\n Size........... " + color(f"{t['size']} ({t['sizeB']})", fg="yellow")
                     )
            else:
                print("\n Manufacturer... " + color(f"{mfr}", fg="green") +
                     "\n Device ID...... " + color(f"{did:04X}h (unknown)", fg="red"))
        else:
            print("\n Manufacturer... " + color(f"{mfr}", fg="green") +
                 "\n Device ID...... " + color(f"{did:04X}h (unknown)", fg="red"))
    else:
        print("\n Manufacturer... " + color(f"{mid:02X}h (unknown)", fg="red") +
             "\n Device ID...... " + color(f"{did:04X}h (unknown)", fg="red"))
