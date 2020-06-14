#!/usr/bin/env python3

import pm3
p=pm3.device()
p.console("hw status")
print("Device:", p.get_name())
