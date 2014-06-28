#!/usr/bin/env python
#-----------------------------------------------------------------------------
# Copyright (C) 2014 iZsh <izsh at fail0verflow.com>
#
# This code is licensed to you under the terms of the GNU GPL, version 2 or,
# at your option, any later version. See the LICENSE.txt file for the text of
# the license.
#-----------------------------------------------------------------------------
import numpy
import matplotlib.pyplot as plt
import sys

if len(sys.argv) != 2:
	print "Usage: %s <basename>" % sys.argv[0]
	sys.exit(1)

BASENAME = sys.argv[1]

nx = numpy.fromfile(BASENAME + ".time")

def plot_time(dat1):
    plt.plot(nx, dat1)

sig = open(BASENAME + ".filtered").read()
sig = map(lambda x: ord(x), sig)

min_vals = open(BASENAME + ".min").read()
min_vals = map(lambda x: ord(x), min_vals)

max_vals = open(BASENAME + ".max").read()
max_vals = map(lambda x: ord(x), max_vals)

states = open(BASENAME + ".state").read()
states = map(lambda x: ord(x) * 10 + 65, states)

toggles = open(BASENAME+ ".toggle").read()
toggles = map(lambda x: ord(x) * 10 + 80, toggles)

high = open(BASENAME + ".high").read()
high = map(lambda x: ord(x), high)
highz = open(BASENAME + ".highz").read()
highz = map(lambda x: ord(x), highz)
lowz = open(BASENAME + ".lowz").read()
lowz = map(lambda x: ord(x), lowz)
low = open(BASENAME + ".low").read()
low = map(lambda x: ord(x), low)

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
