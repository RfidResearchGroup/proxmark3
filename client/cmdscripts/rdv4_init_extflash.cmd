#!/usr/bin/env -S pm3 -s

mem load -f mfc_default_keys --mfc
mem load -f t55xx_default_pwds --t55xx
mem load -f iclass_default_keys --iclass
mem load -f mfulc_default_keys --ulc
mem load -f mfulaes_default_keys --aes
lf t55xx deviceconfig --r0 -a 29 -b 17 -c 15 -d 47 -e 15 -p
lf t55xx deviceconfig --r1 -a 29 -b 17 -c 18 -d 50 -e 15 -p
lf t55xx deviceconfig --r2 -a 29 -b 17 -c 18 -d 40 -e 15 -p
lf t55xx deviceconfig --r3 -a 29 -b 17 -c 15 -d 31 -e 15 -f 47 -g 63 -p
