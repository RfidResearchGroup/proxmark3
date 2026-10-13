#!/usr/bin/env python3

# Rewrite a Gowin IDE timing constraint file into the subset of SDC that
# nextpnr-himbaechel understands: create_clock and set_false_path, both taking
# [get_ports {...}]. The // comments, the create_clock -waveform arguments and
# the closing report_timing are dropped, and each set_clock_groups
# -asynchronous is expanded into pairwise false paths between the ports the
# clocks were declared on, since nextpnr has no notion of clock names.
#
# usage: gowin_sdc_clean.py <in.sdc> <out.sdc>

import re
import sys

WAVEFORM = re.compile(r"-waveform\s*\{[^}]*\}")
CLOCK = re.compile(r"create_clock\s+(?:.*?-name\s+(\S+))?.*?\[get_ports\s*\{([^}]*)\}\]")
CLOCK_GROUP = re.compile(r"\[get_clocks\s*\{([^}]*)\}\]")


def read_clocks(lines):
    """"clock name -> port it is declared on" for the create_clock entries"""
    ports = {}
    for line in lines:
        m = CLOCK.match(line.strip())
        if m and m.group(1):
            ports[m.group(1)] = m.group(2)
    return ports


def clean(line, clocks):
    if line.startswith("//") or not line.strip():
        return []
    if re.match(r"\s*report_timing\b", line):
        return []
    if re.match(r"\s*set_clock_groups\b", line):
        if "-asynchronous" not in line:
            return [line]
        # every pair of groups is asynchronous, not just the neighbours
        ports = [clocks.get(name, name) for name in CLOCK_GROUP.findall(line)]
        return ["set_false_path -from [get_ports {%s}] -to [get_ports {%s}]" % (a, b)
                for i, a in enumerate(ports) for b in ports[i + 1:]]
    return [WAVEFORM.sub("", line).rstrip()]


def main(infile, outfile):
    with open(infile) as f:
        lines = f.read().splitlines()
    clocks = read_clocks(lines)
    rules = [out for line in lines for out in clean(line, clocks)]
    with open(outfile, "w") as f:
        f.write("\n".join(rules) + "\n")

    print("[=] SDC {} ({} rules, {} clocks)".format(outfile, len(rules), len(clocks)))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit("usage: gowin_sdc_clean.py <in.sdc> <out.sdc>")
    main(sys.argv[1], sys.argv[2])
