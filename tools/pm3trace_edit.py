#!/usr/bin/env python3
"""
pm3trace_edit.py — Proxmark3 binary trace file editor

Binary record format (tracelog_hdr_t, include/pm3_cmd.h):
  [4]  timestamp  uint32 LE  — carrier periods (14a/thinfilm), ETU (hitag), etc.
  [2]  duration   uint16 LE  — frame duration in same units
  [2]  flags      uint16 LE  — bits[14:0] = data_len, bit[15] = isResponse
  [N]  data       data_len bytes
  [P]  parity     ceil(data_len/8) bytes, bit j of byte i = odd-parity of data[i*8+j]

Usage:
  python3 pm3trace_edit.py <file.trace>          # interactive editor
  python3 pm3trace_edit.py <file.trace> --dump   # dump to stdout and exit

Interactive commands:
  l / list [N]          list all frames, or frame N only
  e N HEXBYTES          replace data bytes of frame N (space-separated or run-together hex)
  t N                   toggle isResponse flag (Rdr <-> Tag) for frame N
  T N r|t               set isResponse explicitly: r=reader, t=tag
  d N [END]             delete frame N, or frames N..END inclusive
  dup N                 duplicate frame N (insert copy immediately after)
  ins N HEXBYTES [r|t]  insert new frame after N (default: same dir as N)
  ts N VALUE            set timestamp of frame N (decimal or 0xHEX)
  dur N VALUE           set duration of frame N (decimal or 0xHEX)
  save [FILENAME]       save to file (default: overwrites original)
  q / quit              quit (warns if unsaved changes)
"""

import sys
import os
import struct
import argparse
import shlex
import readline  # noqa: F401 — enables history/editing in input()


HDR_SIZE = 8  # 4 + 2 + 2


# ---------------------------------------------------------------------------
# Binary format helpers
# ---------------------------------------------------------------------------

def parity_len(data_len: int) -> int:
    """ceil(data_len/8) parity bytes; 0 for empty frames."""
    return (data_len + 7) // 8


def compute_parity(data: bytes) -> bytes:
    """
    Compute ISO14443-A style parity bytes.
    Bit j of parity byte i = odd parity of data[i*8 + j].
    Odd parity: 1 if popcount(byte) is even, 0 if popcount is odd.
    """
    n = len(data)
    p_len = parity_len(n)
    parities = bytearray(p_len)
    for idx, byte in enumerate(data):
        pop = bin(byte).count('1')
        bit = 0 if (pop % 2 == 1) else 1   # odd parity: total (data+parity) bits = odd
        word = idx // 8
        shift = idx % 8
        if bit:
            parities[word] |= (1 << shift)
    return bytes(parities)


def parity_ok(data: bytes, parity: bytes) -> bool:
    """Return True if all parity bits are correct (odd parity per byte)."""
    for idx, byte in enumerate(data):
        pop = bin(byte).count('1')
        word = idx // 8
        shift = idx % 8
        p_bit = (parity[word] >> shift) & 1 if word < len(parity) else 0
        if (pop + p_bit) % 2 != 1:
            return False
    return True


# ---------------------------------------------------------------------------
# Frame class
# ---------------------------------------------------------------------------

class Frame:
    __slots__ = ('timestamp', 'duration', 'is_response', 'data', 'parity')

    def __init__(self, timestamp: int, duration: int, is_response: bool,
                 data: bytes, parity: bytes):
        self.timestamp = timestamp
        self.duration = duration
        self.is_response = is_response
        self.data = data
        self.parity = parity

    def to_bytes(self) -> bytes:
        flags = (len(self.data) & 0x7FFF) | (0x8000 if self.is_response else 0)
        hdr = struct.pack('<IHH', self.timestamp, self.duration, flags)
        return hdr + self.data + self.parity

    @property
    def parity_status(self) -> str:
        if len(self.data) == 0:
            return '  -'
        return ' ok' if parity_ok(self.data, self.parity) else 'ERR'

    @property
    def src(self) -> str:
        return 'Tag' if self.is_response else 'Rdr'

    def data_hex(self, width: int = 48) -> str:
        h = ' '.join(f'{b:02x}' for b in self.data)
        if len(h) > width:
            h = h[:width - 3] + '...'
        return h


# ---------------------------------------------------------------------------
# Parse / serialise
# ---------------------------------------------------------------------------

def parse_trace(blob: bytes) -> list[Frame]:
    frames: list[Frame] = []
    pos = 0
    n = len(blob)
    while pos + HDR_SIZE <= n:
        ts, dur, flags = struct.unpack_from('<IHH', blob, pos)
        pos += HDR_SIZE
        data_len = flags & 0x7FFF
        is_resp = bool(flags & 0x8000)
        p_len = parity_len(data_len)
        if pos + data_len + p_len > n:
            print(f'[warn] truncated record at offset {pos - HDR_SIZE}, stopping parse')
            break
        data = blob[pos: pos + data_len]
        pos += data_len
        parity = blob[pos: pos + p_len]
        pos += p_len
        frames.append(Frame(ts, dur, is_resp, data, parity))
    return frames


def serialise_trace(frames: list[Frame]) -> bytes:
    return b''.join(f.to_bytes() for f in frames)


# ---------------------------------------------------------------------------
# Display helpers
# ---------------------------------------------------------------------------

HEADER = (
    f"{'#':>5}  {'Timestamp':>10}  {'Dur':>6}  {'Src':>3}  "
    f"{'Data (hex)':<50}  {'Par':>3}"
)
SEP = '-' * len(HEADER)


def print_frame(idx: int, f: Frame) -> None:
    print(f'{idx:>5}  {f.timestamp:>10}  {f.duration:>6}  {f.src:>3}  '
          f'{f.data_hex():<50}  {f.parity_status:>3}')


def cmd_list(frames: list[Frame], args: list[str]) -> None:
    if args:
        try:
            idx = int(args[0])
            if not 0 <= idx < len(frames):
                print(f'frame {idx} out of range (0..{len(frames)-1})')
                return
            print(HEADER)
            print(SEP)
            f = frames[idx]
            # detailed view
            print_frame(idx, f)
            print()
            print(f'  timestamp : {f.timestamp} (0x{f.timestamp:08x})')
            print(f'  duration  : {f.duration}  (0x{f.duration:04x})')
            print(f'  direction : {"Tag (response)" if f.is_response else "Rdr (command)"}')
            print(f'  data_len  : {len(f.data)}')
            if f.data:
                print(f'  data      : {" ".join(f"{b:02x}" for b in f.data)}')
                print(f'  parity    : {" ".join(f"{b:02x}" for b in f.parity)}'
                      f'  [{f.parity_status.strip()}]')
            return
        except ValueError:
            print('usage: list [frame_number]')
            return
    print(HEADER)
    print(SEP)
    for i, f in enumerate(frames):
        print_frame(i, f)
    print(SEP)
    print(f'  {len(frames)} frames total')


# ---------------------------------------------------------------------------
# Edit commands
# ---------------------------------------------------------------------------

def parse_hex_arg(token: str) -> bytes:
    """Accept '0a 1b 2c', '0a1b2c', or mixed."""
    cleaned = token.replace(' ', '').replace(':', '')
    if len(cleaned) % 2:
        raise ValueError(f'odd hex length: {token!r}')
    return bytes.fromhex(cleaned)


def parse_value(token: str) -> int:
    return int(token, 0)


def cmd_edit(frames: list[Frame], args: list[str]) -> bool:
    if len(args) < 2:
        print('usage: e N HEXBYTES')
        return False
    try:
        idx = int(args[0])
    except ValueError:
        print('N must be an integer')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False
    hex_str = ''.join(args[1:])
    try:
        new_data = parse_hex_arg(hex_str)
    except ValueError as exc:
        print(f'bad hex: {exc}')
        return False
    frames[idx].data = new_data
    frames[idx].parity = compute_parity(new_data)
    print(f'frame {idx}: data updated ({len(new_data)} bytes), parity recomputed')
    return True


def cmd_toggle(frames: list[Frame], args: list[str]) -> bool:
    if not args:
        print('usage: t N')
        return False
    try:
        idx = int(args[0])
    except ValueError:
        print('N must be an integer')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False
    frames[idx].is_response = not frames[idx].is_response
    print(f'frame {idx}: now {frames[idx].src}')
    return True


def cmd_set_dir(frames: list[Frame], args: list[str]) -> bool:
    if len(args) < 2:
        print('usage: T N r|t')
        return False
    try:
        idx = int(args[0])
    except ValueError:
        print('N must be an integer')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False
    d = args[1].lower()
    if d not in ('r', 't'):
        print('direction must be r (reader) or t (tag)')
        return False
    frames[idx].is_response = (d == 't')
    print(f'frame {idx}: set to {frames[idx].src}')
    return True


def cmd_delete(frames: list[Frame], args: list[str]) -> bool:
    if not args:
        print('usage: d N  or  d START END')
        return False
    try:
        if len(args) == 1:
            idx = int(args[0])
            if not 0 <= idx < len(frames):
                print(f'frame {idx} out of range (0..{len(frames)-1})')
                return False
            frames.pop(idx)
            print(f'frame {idx} deleted ({len(frames)} frames remain)')
        else:
            start, end = int(args[0]), int(args[1])
            if start > end:
                print(f'START {start} must be <= END {end}')
                return False
            if not 0 <= start < len(frames):
                print(f'start {start} out of range (0..{len(frames)-1})')
                return False
            if not 0 <= end < len(frames):
                print(f'end {end} out of range (0..{len(frames)-1})')
                return False
            count = end - start + 1
            del frames[start:end + 1]
            print(f'frames {start}..{end} deleted ({count} removed, {len(frames)} remain)')
    except ValueError:
        print('usage: d N  or  d START END')
        return False
    return True


def cmd_dup(frames: list[Frame], args: list[str]) -> bool:
    if not args:
        print('usage: dup N')
        return False
    try:
        idx = int(args[0])
    except ValueError:
        print('N must be an integer')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False
    f = frames[idx]
    copy = Frame(f.timestamp, f.duration, f.is_response, f.data, f.parity)
    frames.insert(idx + 1, copy)
    print(f'frame {idx} duplicated → new frame {idx + 1}')
    return True


def cmd_insert(frames: list[Frame], args: list[str]) -> bool:
    """ins N HEXBYTES [r|t]"""
    if len(args) < 2:
        print('usage: ins N HEXBYTES [r|t]')
        return False
    try:
        idx = int(args[0])
    except ValueError:
        print('N must be an integer')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False

    # last arg may be 'r' or 't'
    if args[-1].lower() in ('r', 't'):
        direction = args[-1].lower()
        hex_args = args[1:-1]
    else:
        direction = 't' if frames[idx].is_response else 'r'
        hex_args = args[1:]

    if not hex_args:
        print('HEXBYTES required')
        return False
    hex_str = ''.join(hex_args)
    try:
        data = parse_hex_arg(hex_str)
    except ValueError as exc:
        print(f'bad hex: {exc}')
        return False

    is_resp = (direction == 't')
    parity = compute_parity(data)
    # inherit timestamp from neighbour
    ref = frames[idx]
    ts = ref.timestamp + ref.duration
    new_frame = Frame(ts, 0, is_resp, data, parity)
    frames.insert(idx + 1, new_frame)
    print(f'inserted new frame at {idx + 1} ({len(data)} bytes, {"Tag" if is_resp else "Rdr"})')
    return True


def cmd_set_ts(frames: list[Frame], args: list[str]) -> bool:
    if len(args) < 2:
        print('usage: ts N VALUE')
        return False
    try:
        idx = int(args[0])
        val = parse_value(args[1])
    except ValueError as exc:
        print(f'bad argument: {exc}')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False
    if not 0 <= val <= 0xFFFFFFFF:
        print('timestamp must fit in uint32')
        return False
    frames[idx].timestamp = val
    print(f'frame {idx}: timestamp = {val} (0x{val:08x})')
    return True


def cmd_set_dur(frames: list[Frame], args: list[str]) -> bool:
    if len(args) < 2:
        print('usage: dur N VALUE')
        return False
    try:
        idx = int(args[0])
        val = parse_value(args[1])
    except ValueError as exc:
        print(f'bad argument: {exc}')
        return False
    if not 0 <= idx < len(frames):
        print(f'frame {idx} out of range')
        return False
    if not 0 <= val <= 0xFFFF:
        print('duration must fit in uint16')
        return False
    frames[idx].duration = val
    print(f'frame {idx}: duration = {val} (0x{val:04x})')
    return True


def cmd_save(frames: list[Frame], args: list[str], default_path: str) -> str:
    path = args[0] if args else default_path
    try:
        blob = serialise_trace(frames)
        with open(path, 'wb') as fh:
            fh.write(blob)
        print(f'saved {len(frames)} frames ({len(blob)} bytes) → {path}')
        return path
    except OSError as exc:
        print(f'save failed: {exc}')
        return default_path


# ---------------------------------------------------------------------------
# Dump mode
# ---------------------------------------------------------------------------

def dump_mode(frames: list[Frame], offset: int = 0) -> None:
    print(HEADER)
    print(SEP)
    for i, f in enumerate(frames):
        print_frame(offset + i, f)
    print(SEP)
    print(f'{len(frames)} frames total')


# ---------------------------------------------------------------------------
# REPL
# ---------------------------------------------------------------------------

HELP = """
Commands:
  l / list [N]          list all frames, or show detail for frame N
  e N HEXBYTES          replace data bytes of frame N (recomputes parity)
  t N                   toggle reader/tag direction for frame N
  T N r|t               set direction explicitly
  d N [END]             delete frame N, or frames N..END inclusive
  dup N                 duplicate frame N
  ins N HEXBYTES [r|t]  insert new frame after N
  ts N VALUE            set timestamp (decimal or 0xHEX)
  dur N VALUE           set duration  (decimal or 0xHEX)
  save [FILE]           save (default: overwrite original)
  q / quit              quit
"""


def repl(frames: list[Frame], filepath: str) -> None:
    dirty = False
    saved_path = filepath
    print(f'loaded {len(frames)} frames from {filepath}')
    print('type "help" for commands, "list" to see frames')

    while True:
        try:
            line = input('pm3trace> ').strip()
        except (EOFError, KeyboardInterrupt):
            print()
            if dirty:
                print('warning: unsaved changes')
            break
        if not line:
            continue

        try:
            parts = shlex.split(line)
        except ValueError as exc:
            print(f'parse error: {exc}')
            continue

        cmd = parts[0].lower()
        args = parts[1:]

        if cmd in ('q', 'quit', 'exit'):
            if dirty:
                ans = input('unsaved changes — quit anyway? [y/N] ').strip().lower()
                if ans != 'y':
                    continue
            break

        elif cmd in ('h', 'help', '?'):
            print(HELP)

        elif cmd in ('l', 'list'):
            cmd_list(frames, args)

        elif cmd == 'e':
            if cmd_edit(frames, args):
                dirty = True

        elif cmd == 't':
            if cmd_toggle(frames, args):
                dirty = True

        elif cmd == 'T':
            if cmd_set_dir(frames, args):
                dirty = True

        elif cmd == 'd':
            if cmd_delete(frames, args):
                dirty = True

        elif cmd == 'dup':
            if cmd_dup(frames, args):
                dirty = True

        elif cmd == 'ins':
            if cmd_insert(frames, args):
                dirty = True

        elif cmd == 'ts':
            if cmd_set_ts(frames, args):
                dirty = True

        elif cmd == 'dur':
            if cmd_set_dur(frames, args):
                dirty = True

        elif cmd == 'save':
            saved_path = cmd_save(frames, args, saved_path)
            dirty = False

        else:
            print(f'unknown command: {cmd!r}  (type "help")')


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='pm3trace_edit.py',
        description=(
            'Interactive editor for Proxmark3 binary trace files (.trace).\n'
            '\n'
            'Binary record format (tracelog_hdr_t):\n'
            '  [4] timestamp  uint32 LE  — carrier periods (14a), ETU (hitag), etc.\n'
            '  [2] duration   uint16 LE\n'
            '  [2] flags      uint16 LE  — bits[14:0]=data_len, bit[15]=isResponse\n'
            '  [N] data       data_len bytes\n'
            '  [P] parity     ceil(data_len/8) bytes (odd parity per bit)\n'
            '\n'
            'pm3 commands to work with trace files:\n'
            '  trace load -f <file>           load trace from file\n'
            '  trace list -1 -t <proto>       list loaded trace  (-1 = use file, not device)\n'
            '  proto examples: 14a  14b  iclass  15  hitag2  t55xx  felica'
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            'Interactive commands (shown again at runtime with "help"):\n'
            '  l / list [N]          list all frames, or show detail for frame N\n'
            '  e N HEXBYTES          replace data bytes of frame N (recomputes parity)\n'
            '  t N                   toggle reader/tag direction for frame N\n'
            '  T N r|t               set direction explicitly (r=reader, t=tag)\n'
            '  d N [END]             delete frame N, or frames N..END inclusive\n'
            '  dup N                 duplicate frame N (insert copy after it)\n'
            '  ins N HEXBYTES [r|t]  insert new frame after N\n'
            '  ts N VALUE            set timestamp (decimal or 0xHEX)\n'
            '  dur N VALUE           set duration  (decimal or 0xHEX)\n'
            '  save [FILE]           write to file (default: overwrite original)\n'
            '  q / quit              quit\n'
            '\n'
            'examples:\n'
            '  %(prog)s capture.trace\n'
            '  %(prog)s capture.trace --dump\n'
            '  %(prog)s capture.trace --dump --range 0 49\n'
            '  %(prog)s capture.trace -o edited.trace'
        ),
    )
    parser.add_argument(
        'file',
        metavar='FILE',
        help='Proxmark3 .trace file to open',
    )
    parser.add_argument(
        '--dump', '-D',
        action='store_true',
        help='print all frames to stdout and exit (non-interactive)',
    )
    parser.add_argument(
        '--range', '-r',
        metavar=('START', 'END'),
        nargs=2,
        type=int,
        default=None,
        help='with --dump: only show frames START..END inclusive',
    )
    parser.add_argument(
        '--output', '-o',
        metavar='FILE',
        default=None,
        help='output file for save (default: overwrite input file)',
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if not os.path.isfile(args.file):
        parser.error(f'file not found: {args.file}')

    with open(args.file, 'rb') as fh:
        blob = fh.read()

    frames = parse_trace(blob)
    if not frames:
        parser.error('no frames parsed — is this a valid .trace file?')

    if args.dump:
        start = 0
        if args.range:
            start, end = args.range
            if start < 0 or end >= len(frames) or start > end:
                parser.error(f'--range {start} {end} out of bounds (0..{len(frames)-1})')
            frames = frames[start:end + 1]
        dump_mode(frames, offset=start)
    else:
        save_path = args.output or args.file
        repl(frames, save_path)


if __name__ == '__main__':
    main()
