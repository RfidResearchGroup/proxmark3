local pm3 = require("pm3")
ctx=pm3.get_current_context()
p=pm3.get_dev(ctx, 0)
pm3.console(p, "hw status")
