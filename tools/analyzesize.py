#! /usr/bin/env python3

import json
import subprocess
import sys

def print_increase(x, y, name):
    if x > y:
        print("{} increase by: {} (0x{:08X}) bytes ({}%)".format(name, x-y, x-y, (x-y)*100/y))
    else:
        print("{} decrease by: {} (0x{:08X}) bytes ({}%)".format(name, y-x, y-x, (y-x)*100/x))
dbname = "tools/data.json"
try:
    db = json.load(open(dbname,"r"))
except FileNotFoundError:
    db = dict()

if len(sys.argv) < 3:
    print("Usage: analyzesize.py <info|add|diff> <datasetname>")
    exit(2)
action, name = sys.argv[1:3]
currentdata = subprocess.run(["arm-none-eabi-size","armsrc/obj/fullimage.stage1.elf"], stdout=subprocess.PIPE).stdout
currentdata = currentdata.split(b"\n")[1].strip()
text,data,bss = [int(x) for x in currentdata.split(b"\t")[:3]]
if action.lower() == "add":
    db[name] = [text, data, bss]
    json.dump(db, open(dbname, "w"))
elif action.lower() == "diff":
    text_ref, data_ref, bss_ref = db[name]
    flash_ref = text_ref+data_ref
    flash = text+data
    print_increase(flash, flash_ref, "Flash")
    print_increase(bss, bss_ref, "RAM")
