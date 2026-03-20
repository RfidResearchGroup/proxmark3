#!/usr/bin/env python3
"""
Proxmark3 dual-wield encode/decode test harness.

One PM3 acts as the encoder/simulator while the other acts as the decoder/reader.
The current case set exercises LF HID flows, and the simulator defaults to a
finite timeout so cases can advance without pressing the simulator button between runs.
"""

from __future__ import annotations

import argparse
import os
import re
import subprocess
import sys
import time
from dataclasses import dataclass
from typing import Iterable


C_RED = "\033[0;31m"
C_GREEN = "\033[0;32m"
C_YELLOW = "\033[0;33m"
C_BLUE = "\033[0;34m"
C_NC = "\033[0m"
C_OK = "✔️"
C_FAIL = "❌"


@dataclass(frozen=True)
class HidCase:
    name: str
    sim_args: list[str]
    expected_pattern: str
    description: str


CASES: tuple[HidCase, ...] = (
    HidCase(
        name="h10301",
        sim_args=["lf", "hid", "sim", "-w", "H10301", "--fc", "118", "--cn", "1603"],
        expected_pattern=r"H10301.*FC:\s*118.*CN:\s*1603",
        description="H10301 26-bit",
    ),
    HidCase(
        name="h10302",
        sim_args=["lf", "hid", "sim", "-w", "H10302", "--cn", "1234567"],
        expected_pattern=r"raw:\s*0*25ad0f",
        description="H10302 37-bit",
    ),
    HidCase(
        name="c1k48s",
        sim_args=["lf", "hid", "sim", "-w", "C1k48s", "--fc", "42069", "--cn", "42069"],
        expected_pattern=r"(C1k48s|Corporate 1000 48-bit).*FC:\s*42069.*CN:\s*42069",
        description="Corporate 1000 48-bit",
    ),
    HidCase(
        name="bin83",
        sim_args=["lf", "hid", "sim", "--bin", "1" * 83],
        expected_pattern=r"raw:\s*[0-9a-fA-F]{8,}",
        description="Synthetic 83-bit payload",
    ),
    HidCase(
        name="raw84",
        sim_args=["lf", "hid", "sim", "--raw", "0fffffffffffffffffffff"],
        expected_pattern=r"raw:\s*[0-9a-fA-F]{8,}",
        description="Synthetic 83-bit payload plus sentinel bit",
    ),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run two-PM3 encode/decode tests with one simulator and one reader."
    )
    parser.add_argument(
        "--pm3",
        default="./pm3",
        help="Path to the pm3 helper script or proxmark3 client wrapper (default: ./pm3)",
    )
    parser.add_argument(
        "--sim-index",
        type=int,
        default=1,
        help="1-based PM3 index to use as the simulator (default: 1)",
    )
    parser.add_argument(
        "--reader-index",
        type=int,
        default=2,
        help="1-based PM3 index to use as the reader (default: 2)",
    )
    parser.add_argument(
        "--case",
        action="append",
        choices=[case.name for case in CASES],
        help="Run one or more named cases. Defaults to all cases.",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List detected PM3 devices and exit.",
    )
    parser.add_argument(
        "--settle-seconds",
        type=float,
        default=0.5,
        help="Seconds to wait after starting the simulator before reading (default: 0.5)",
    )
    parser.add_argument(
        "--sim-timeout-ms",
        type=int,
        default=1500,
        help="Simulation timeout in ms added to each lf hid sim command (default: 1500, use 0 for manual stop)",
    )
    parser.add_argument(
        "--manual",
        action="store_true",
        help="Prompt before reads and before manual stop when --sim-timeout-ms is 0",
    )
    return parser.parse_args()


def run_capture(cmd: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, capture_output=True, text=True, check=False)


def list_devices(pm3_path: str) -> list[tuple[int, str]]:
    result = run_capture([pm3_path, "--list"])
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip() or "pm3 --list failed")

    devices: list[tuple[int, str]] = []
    for line in result.stdout.splitlines():
        match = re.match(r"\s*(\d+):\s*(.+)", line)
        if match:
            devices.append((int(match.group(1)), match.group(2).strip()))
    return devices


def select_cases(selected_names: Iterable[str] | None) -> list[HidCase]:
    if not selected_names:
        return list(CASES)
    wanted = set(selected_names)
    return [case for case in CASES if case.name in wanted]


def ensure_distinct_devices(sim_index: int, reader_index: int) -> None:
    if sim_index == reader_index:
        raise ValueError("Simulator and reader indexes must be different")


def prompt(message: str) -> None:
    print()
    print(message)
    input("Press Enter when ready, or Ctrl-C to abort. ")


def print_status(name: str, status: str, color: str, emoji: str, extra: str = "") -> None:
    suffix = f" {extra}" if extra else ""
    print(f"{name:<40} [ {color}{status}{C_NC} ] {emoji}{suffix}")


def run_case(pm3_path: str, sim_port: str, reader_port: str, case: HidCase, settle_seconds: float, sim_timeout_ms: int, manual: bool) -> bool:
    sim_args = list(case.sim_args)
    if sim_timeout_ms > 0:
        sim_args.extend(["--timeout", str(sim_timeout_ms)])

    sim_cmd = [pm3_path, "-p", sim_port, "-c", " ".join(sim_args)]
    reader_cmd = [pm3_path, "-p", reader_port, "-c", "lf hid reader"]

    start = time.time()

    sim_proc = subprocess.Popen(
        sim_cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )

    try:
        time.sleep(settle_seconds)
        if sim_proc.poll() is not None:
            sim_output = sim_proc.stdout.read() if sim_proc.stdout else ""
            print_status(f"{case.name}: {case.description}", "FAIL", C_RED, C_FAIL, f"({int(time.time() - start)} s)")
            print("simulator exited before the reader ran")
            print(f"simulator: {' '.join(sim_cmd)}")
            print(f"reader:    {' '.join(reader_cmd)}")
            print(sim_output)
            return False

        if manual:
            print(f"[ {C_YELLOW}MANUAL{C_NC} ]")
            print(f"  simulator: {' '.join(sim_cmd)}")
            print(f"  reader:    {' '.join(reader_cmd)}")
            prompt("Position the two PM3s for LF HID readback.")
        reader_result = run_capture(reader_cmd)

        matched = re.search(case.expected_pattern, reader_result.stdout, re.IGNORECASE | re.DOTALL)
        if not matched:
            print_status(f"{case.name}: {case.description}", "FAIL", C_RED, C_FAIL, f"({int(time.time() - start)} s)")
            print(f"simulator: {' '.join(sim_cmd)}")
            print(f"reader:    {' '.join(reader_cmd)}")
            print(reader_result.stdout)
            print(f"reader output did not match: {case.expected_pattern}")
            return False

        if sim_timeout_ms > 0:
            try:
                sim_output, _ = sim_proc.communicate(timeout=max(20, int(settle_seconds + (sim_timeout_ms / 1000.0) + 2)))
            except subprocess.TimeoutExpired:
                print_status(f"{case.name}: {case.description}", "FAIL", C_RED, C_FAIL, f"({int(time.time() - start)} s)")
                print("simulator did not stop before the timeout window elapsed")
                print(f"simulator: {' '.join(sim_cmd)}")
                print(f"reader:    {' '.join(reader_cmd)}")
                sim_proc.kill()
                sim_output, _ = sim_proc.communicate()
                print(sim_output)
                return False
        else:
            prompt("Press the simulator PM3 button to stop emulation.")
            try:
                sim_output, _ = sim_proc.communicate(timeout=20)
            except subprocess.TimeoutExpired:
                print_status(f"{case.name}: {case.description}", "FAIL", C_RED, C_FAIL, f"({int(time.time() - start)} s)")
                print("simulator did not stop after the button prompt")
                print(f"simulator: {' '.join(sim_cmd)}")
                print(f"reader:    {' '.join(reader_cmd)}")
                sim_proc.kill()
                sim_output, _ = sim_proc.communicate()
                print(sim_output)
                return False

        if "Simulating HID tag" not in sim_output:
            print_status(f"{case.name}: {case.description}", "FAIL", C_RED, C_FAIL, f"({int(time.time() - start)} s)")
            print("simulator output did not contain the expected startup text")
            print(f"simulator: {' '.join(sim_cmd)}")
            print(f"reader:    {' '.join(reader_cmd)}")
            print(sim_output)
            return False

        elapsed = int(time.time() - start)
        print_status(f"{case.name}: {case.description}", "OK", C_GREEN, C_OK, f"({elapsed} s)")
        return True
    finally:
        if sim_proc.poll() is None:
            sim_proc.kill()
            sim_proc.communicate()


def main() -> int:
    args = parse_args()
    pm3_path = os.path.abspath(args.pm3)

    try:
        devices = list_devices(pm3_path)
    except Exception as exc:  # pylint: disable=broad-except
        print(f"failed to enumerate PM3 devices: {exc}", file=sys.stderr)
        return 2

    if args.list:
        for index, device in devices:
            print(f"{index}: {device}")
        return 0

    if len(devices) < 2:
        print("dual-wield tests require at least two detected PM3 devices", file=sys.stderr)
        return 2

    if args.sim_timeout_ms == 0 and not args.manual:
        print("--sim-timeout-ms 0 requires --manual so the simulator can be stopped explicitly", file=sys.stderr)
        return 2

    try:
        ensure_distinct_devices(args.sim_index, args.reader_index)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2

    cases = select_cases(args.case)
    failures = 0

    selected_ports = {index: device for index, device in devices}
    sim_port = selected_ports.get(args.sim_index)
    reader_port = selected_ports.get(args.reader_index)
    if sim_port is None or reader_port is None:
        print("selected PM3 index is not present in the current device list", file=sys.stderr)
        return 2

    print("Detected PM3 devices:")
    for index, device in devices:
        role = ""
        if index == args.sim_index:
            role = " [simulator]"
        elif index == args.reader_index:
            role = " [reader]"
        print(f"  {index}: {device}{role}")

    for case in cases:
        if not run_case(pm3_path, sim_port, reader_port, case, args.settle_seconds, args.sim_timeout_ms, args.manual):
            failures += 1

    if failures:
        print()
        print(f"{failures} case(s) failed {C_FAIL}")
        return 1

    print()
    print(f"{C_GREEN}All dual-wield cases passed{C_NC} {C_OK}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
