#!/usr/bin/env python3

import pm3

p=pm3.open("/dev/ttyACM0")
pm3.console(p, "hw status")
pm3.close(p)
