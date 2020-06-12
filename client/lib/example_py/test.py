#!/usr/bin/env python3

import pm3

ctx=pm3.init()
p=pm3.open(ctx, "/dev/ttyACM0")
pm3.console(p, "hw status")
pm3.close(p)
pm3.exit(ctx)
