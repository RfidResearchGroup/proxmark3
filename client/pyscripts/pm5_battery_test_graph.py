#!/usr/bin/env python3
"""
Plot battery log CSV (timestamp, voltage_mV, current_mA, temp_C, capacity_mAh).

Since the logging script didn't sleep between iterations, rows can be much
closer together than 10s apart. This script keeps only one row per 10-second
window (the first row seen in each window) before plotting, so the graphs
aren't overcrowded with near-duplicate points.

The X axis shows elapsed time in minutes, starting at 0 for the first
sample, rather than absolute clock time.

Usage:
    python plot_battery_log.py [input_csv] [output_png]

Defaults:
    input_csv  = battery_log.csv
    output_png = battery_log.png
"""

import sys
import csv
from datetime import datetime

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
from PIL import Image


def load_and_downsample(csv_path, min_interval_s=10):
    rows = []
    with open(csv_path, newline="") as f:
        reader = csv.DictReader(f)
        for row in reader:
            try:
                ts = datetime.strptime(row["timestamp"], "%Y-%m-%d %H:%M:%S")
            except (KeyError, ValueError):
                continue
            rows.append({
                "timestamp": ts,
                "voltage_mV": float(row["voltage_mV"]) if row["voltage_mV"] else None,
                "current_mA": float(row["current_mA"]) if row["current_mA"] else None,
                "temp_C": float(row["temp_C"]) if row["temp_C"] else None,
                "capacity_mAh": float(row["capacity_mAh"]) if row["capacity_mAh"] else None,
                "soc_percent": float(row["soc_percent"]) if row["soc_percent"] else None,
            })

    rows.sort(key=lambda r: r["timestamp"])

    if min_interval_s > 0:
        downsampled = []
        last_ts = None
        for r in rows:
            if last_ts is None or (r["timestamp"] - last_ts).total_seconds() >= min_interval_s:
                downsampled.append(r)
                last_ts = r["timestamp"]
        return downsampled
    else:
        return rows


def plot(rows, output_path):
    t0 = rows[0]["timestamp"]
    elapsed_min = [(r["timestamp"] - t0).total_seconds() / 60.0 for r in rows]

    fields = [
        ("voltage_mV", "Voltage (mV)"),
        ("current_mA", "Current (mA)"),
        ("temp_C", "Temperature (C)"),
        ("capacity_mAh", "Remaining capacity (mAh)"),
        ("soc_percent", "Battery SoC (%)"),
    ]

    fig, axes = plt.subplots(len(fields), 1, figsize=(10, 12), sharex=True)

    for ax, (key, label) in zip(axes, fields):
        values = [r[key] for r in rows]
        ax.plot(elapsed_min, values, marker="o", markersize=3, linewidth=1)
        ax.set_ylabel(label)
        ax.grid(True, alpha=0.3)

    axes[-1].set_xlabel("Elapsed time (minutes)")
    fig.suptitle("Battery status over time")
    fig.tight_layout(rect=(0.0, 0.0, 1.0, 0.97))
    fig.savefig(output_path, dpi=150)
    print(f"Saved plot to {output_path}")
    return output_path


def main():
    input_csv = sys.argv[1] if len(sys.argv) > 1 else "battery_log.csv"
    output_png = sys.argv[2] if len(sys.argv) > 2 else "battery_log.png"

    min_interval_s = 10
    rows = load_and_downsample(input_csv, min_interval_s=min_interval_s)
    if not rows:
        print("No valid rows found in CSV.")
        return
    if min_interval_s > 0:
        print(f"{len(rows)} points after downsampling")

    output_path = plot(rows, output_png)
    img = Image.open(output_path)
    img.show()


if __name__ == "__main__":
    main()