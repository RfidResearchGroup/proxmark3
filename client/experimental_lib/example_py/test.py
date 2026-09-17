#!/usr/bin/env python3

import pm3
p=pm3.pm3("/dev/ttyACM0")

p.console("hw status")
p.console("hw version")
for line in p.grabbed_output.split('\n'):
    if "Unique ID" in line:
        print(line)
    if "uC:" in line:
        print(line)
print("Device:", p.name)
p.console("Rem passthru remark! :coffee:", capture=False, quiet=False)

import json
print("Fetching prefs:")
p.console("prefs show --json")
prefs = json.loads(p.grabbed_output)
print("Save path: ", prefs['file.default.savepath'])
print("Dump path: ", prefs['file.default.dumppath'])
print("Trace path:", prefs['file.default.tracepath'])
