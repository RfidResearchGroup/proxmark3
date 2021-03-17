#!/usr/bin/env -S pm3 -s

mem load -f mfc_default_keys --mfc
mem load -f t55xx_default_pwds --t55xx
mem load -f iclass_default_keys --iclass
lf t55xx deviceconfig -z -p
