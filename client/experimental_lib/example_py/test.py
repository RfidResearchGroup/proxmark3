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
p.console("Rem passthru remark! :coffee:", True)
