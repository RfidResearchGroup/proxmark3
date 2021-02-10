#!/usr/bin/env python3

import pm3
p=pm3.pm3()

# PyConsoleHandler class is defined and derived from C++ class ConsoleHandler
class PyConsoleHandler(pm3.ConsoleHandler):
    def __init__(self):
        pm3.ConsoleHandler.__init__(self)
    def handle_output(self, c):
        print("PY>>", c, end='')
        # don't let original print routine pursuing:
        return 0

#p.console("hw status")

handler = PyConsoleHandler()
result = p.console_async_wrapper("hw status", handler)
print(result)

print("Device:", p.name)
