#!/usr/bin/env python3
#-----------------------------------------------------------------------------
# Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
#
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------

import sys
try:
    import numpy
except ModuleNotFoundError:
    print("Please install numpy module first.")
    sys.exit(1)

try:
    import matplotlib.pyplot as plt
except ModuleNotFoundError:
    print("Please install matplotlib module first.")
    sys.exit(1)

if len(sys.argv) != 2:
    print("Usage: %s <basename>" % sys.argv[0])
    sys.exit(1)

BASENAME = sys.argv[1]

nx = numpy.fromfile(BASENAME + ".time")

def plot_time(dat1):
    plt.plot(nx, dat1)

sig = bytearray(open(BASENAME + ".filtered", 'rb').read())
min_vals = bytearray(open(BASENAME + ".min", 'rb').read())
max_vals = bytearray(open(BASENAME + ".max", 'rb').read())
states = bytearray(open(BASENAME + ".state", 'rb').read())
toggles = bytearray(open(BASENAME+ ".toggle", 'rb').read())
high = bytearray(open(BASENAME + ".high", 'rb').read())
highz = bytearray(open(BASENAME + ".highz", 'rb').read())
lowz = bytearray(open(BASENAME + ".lowz", 'rb').read())
low = bytearray(open(BASENAME + ".low", 'rb').read())

plot_time(sig)
plot_time(min_vals)
plot_time(max_vals)
plot_time(states)
plot_time(toggles)
plot_time(high)
plot_time(highz)
plot_time(lowz)
plot_time(low)

plt.show()
