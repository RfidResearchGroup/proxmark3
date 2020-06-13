#!/usr/bin/env lua

local pm3 = require("pm3")
p=pm3.open("/dev/ttyACM0")
pm3.console(p, "hw status")
pm3.close(p)
