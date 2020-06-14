#!/usr/bin/env lua

local pm3 = require("pm3")
p=pm3.pm3("/dev/ttyACM0")
p:console("hw status")
print(p.name)
