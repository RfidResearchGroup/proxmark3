#!/usr/bin/env lua

local pm3 = require("pm3")
p=pm3.device("/dev/ttyACM0")
--p.console("hw status") ??
p.console(p, "hw status")
