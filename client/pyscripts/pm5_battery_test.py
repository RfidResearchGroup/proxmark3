#!/usr/bin/env -S uv run pm3 -y

"""
PM5 / BWM battery discharge (or charge) logger.

Polls `hw status` at a fixed interval and logs the fuel-gauge readings to CSV
(plot with pm5_battery_test_graph.py).

If not yet done, you should set up the gauge first for meaningful numbers:
    hw bwmsetcap --cap 500  # your cell's mAh
then fully charge

Usage:
    pm5 --> script run pm5_battery_test.py
    pm5 --> script run pm5_battery_test.py --cutoff 3200 --interval 10 --scenario idle

To trigger firmware auto-shutdown:  keep the load on and let it run past the
    firmware floor for the full debounce window, e.g.
    pm5 --> script run pm5_battery_test.py --cutoff 0 --scenario hf_field_on
    (do this on battery, not USB - the shutdown bails while USB power is good.)

NOTE: this deliberately runs a Li-ion cell down under load. Don't leave it
unattended, and don't push --cutoff below ~3000 mV.
"""

import os
import re
import csv
import time
import argparse
import pm3


scenarios = {
    'idle': {
        "on_start": lambda _: None,
        "in_loop": lambda _, s: time.sleep(s),
        "on_stop": lambda _: None
    },
    'hf_field_on': {
        "on_start": lambda p: p.console("hf 14a raw -ak 00"),
        "in_loop": lambda _, s: time.sleep(s),
        "on_stop": lambda p: p.console("hf 14a read --drop"),
    },
    'hf_14a_polling': {
        "on_start": lambda _: None,
        "in_loop": lambda p, s: p.console(f"hf 14a read -n {7*int(s)}"),
        "on_stop": lambda _: None,
    }
}


def parse_args():
    ap = argparse.ArgumentParser(
        description="PM5/BWM battery discharge/charge logger.")
    ap.add_argument("--cutoff", type=float, default=3200.0,
                    help="stop below this battery voltage in mV "
                         "(0 disables the voltage stop). default: 3200")
    ap.add_argument("--interval", type=float, default=10.0,
                    help="seconds between polls. default: 10")
    ap.add_argument("--scenario", default="idle", choices=scenarios.keys(),
                    help="scenario to run. default: idle")
    ap.add_argument("--limit", type=int, default=0,
                    help="stop after N samples (0 = unlimited). default: 0")
    ap.add_argument("--csv", default=None,
                    help="output CSV path "
                         "(default: battery_log_<timestamp>.csv)")
    # ignore anything the pm3 wrapper may inject into argv
    args, _ = ap.parse_known_args()
    return args


# `hw status` prints one "Label..... <num> <unit>" line per field. Pull the
# first number out, tolerating a missing/garbled line (comms hiccup) by
# returning None instead of crashing the run.
def grab(output, label, unit):
    for line in output.split("\n"):
        if label in line:
            m = re.search(r"([-\d.]+)\s*" + re.escape(unit), line)
            if m:
                return float(m.group(1)), line
    return None, None


def fmt(v):
    return f"{v:g}" if v is not None else "?"


def main():

    args = parse_args()

    csv_path = args.csv or f"battery_log_{time.strftime('%Y-%m-%d_%H-%M-%S')}.csv"

    p = pm3.pm3()

    print(f"Logging to {csv_path}")
    print(f"cutoff={args.cutoff:g} mV  interval={args.interval:g}s  "
          f"scenario={args.scenario}  limit={args.limit or 'none'}")

    try:
        # `with` + per-row flush() keeps the CSV valid even if the run is
        # interrupted or the device drops off mid-log.
        with open(csv_path, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["timestamp", "elapsed_s", "voltage_mV", "current_mA",
                             "temp_C", "capacity_mAh", "soc_percent"])

            scenario = scenarios[args.scenario]
            scenario["on_start"](p)
            t0 = time.monotonic()
            n = 0
            while True:
                p.console("hw status --ms 0")
                out = p.grabbed_output

                voltage, _ = grab(out, "Battery voltage", "mV")
                current, cline = grab(out, "Battery current", "mA")
                soc, _ = grab(out, "Battery SoC", "%")
                temp, _ = grab(out, "Temp (gauge)", "C")
                capacity, _ = grab(out, "Remaining capacity", "mAh")

                elapsed = time.monotonic() - t0
                ts = time.strftime("%Y-%m-%d %H:%M:%S")

                print(f"[{ts}] +{elapsed:8.1f}s  "
                      f"V={fmt(voltage)} mV  I={fmt(current)} mA  "
                      f"T={fmt(temp)} C  Cap={fmt(capacity)} mAh  "
                      f"SoC={fmt(soc)} %")

                writer.writerow([
                    ts, f"{elapsed:.1f}",
                    voltage if voltage is not None else "",
                    current if current is not None else "",
                    temp if temp is not None else "",
                    capacity if capacity is not None else "",
                    soc if soc is not None else "",
                ])
                csv_file.flush()

                os.fsync(csv_file.fileno())

                # --- stop conditions ---
                if args.cutoff > 0 and voltage is not None and voltage < args.cutoff:
                    print(f"Voltage {voltage:g} mV below cutoff "
                          f"{args.cutoff:g} mV, stopping.")
                    break
                # gauge marks the current line "idle" when neither charging nor
                # discharging - nothing more to log
                if cline is not None and "idle" in cline:
                    print("Gauge current idle, stopping.")
                    break
                n += 1
                if args.limit > 0 and n >= args.limit:
                    break
                scenario["in_loop"](p, max(args.interval - 1, 1))

    except KeyboardInterrupt:
        print("\nInterrupted, stopping.")
    except Exception as e:  # e.g. device powered off / comms dropped mid-run
        print(f"\nStopped: {e}")
    finally:
        try:
            scenario["on_stop"](p)
        except Exception as e:
            print(f"(Error: {e})")
        print(f"CSV saved: {csv_path}")


if __name__ == '__main__':
    main()