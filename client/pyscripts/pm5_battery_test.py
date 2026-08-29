#!/usr/bin/env -S uv run pm3 -y

import re
import time
import csv
import os
import pm3


# Limit the number of loops
DEBUG_LIMIT = 0
# DEBUG_LIMIT = 5

# To test fast discharge, you can activate the HF field before running this script
# hf 14a raw -ak 00


def main():
    p = pm3.pm3()

    voltage = current = temp = capacity = soc = 0
    stop = False

    csv_path = f"battery_log_{time.strftime('%Y-%m-%d_%H-%M-%S')}.csv"
    csv_file = open(csv_path, "w", newline="")
    writer = csv.writer(csv_file)
    writer.writerow(["timestamp", "voltage_mV", "current_mA", "temp_C", "capacity_mAh", "soc_percent"])

    n = 0
    while DEBUG_LIMIT == 0 or n < DEBUG_LIMIT:
        p.console("hw status")
        for line in p.grabbed_output.split('\n'):
            if "Battery voltage" in line:
                # print(line)
                voltage = float(re.search(r"([\d.]+)\s*mV", line).group(1))
                if voltage < 3200:
                    print(f"Voltage {voltage} mV is below 3200 mV, stopping test.")
                    stop = True
            if "Battery current" in line:
                # print(line)
                current = float(re.search(r"([\d.]+)\s*mA", line).group(1))
                if "idle" in line:
                    stop = True
            if "Battery SoC" in line:
                # print(line)
                soc = float(re.search(r"([\d.]+)\s*%", line).group(1))
            if "Temp (gauge)" in line:
                # print(line)
                temp = float(re.search(r"([\d.]+)\s*C", line).group(1))
            if "Remaining capacity" in line:
                # print(line)
                capacity = float(re.search(r"([\d.]+)\s*mAh", line).group(1))
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] Voltage: {voltage} mV, Current: {current} mA, "
              f"Temp: {temp} C, Capacity: {capacity} mAh, SoC: {soc} %")
        writer.writerow([timestamp, voltage, current, temp, capacity, soc])
        csv_file.flush()
        os.fsync(csv_file.fileno())
        if stop or (DEBUG_LIMIT != 0 and n >= DEBUG_LIMIT):
            break

        time.sleep(10)
        # if current > 0:
        #     # Charging
        #     time.sleep(10)
        # else:
        #     # Discharging
        #     p.console("hf 14a read -n 20")
        #     p.console("hf 14a raw -ak 00")
        n += 1

    csv_file.close()
    p.console("hf 14a read --drop")


if __name__ == '__main__':
    main()