#!/bin/sh

# harder test
time ./sma c2fa94a5231d14e1 d291eeef5f76e6df 586385693a9b0f2c ec9aba404505b0fa
time ./sma_multi c2fa94a5231d14e1 d291eeef5f76e6df 586385693a9b0f2c ec9aba404505b0fa

# simpler
time ./sma ffffffffffffffff 1234567812345678 88c9d4466a501a87 dec2ee1b1c9276e9
time ./sma_multi ffffffffffffffff 1234567812345678 88c9d4466a501a87 dec2ee1b1c9276e9
