#!/usr/bin/env python3
# Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.

"""Test the actual PM5 tick getter with the AN0047 section 2.4 shadow-lock model."""

import argparse
import os
from pathlib import Path
import shlex
import subprocess
import tempfile


PREAMBLE = r'''
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#define RAMFUNC

typedef struct { int year, month, day, hour, min, sec; } ertc_time_type;
typedef struct { volatile uint32_t sbs; } fake_ertc_t;
static fake_ertc_t registers;
static ertc_time_type live_calendar, frozen_calendar, next_calendar;
static uint32_t live_sbs;
static bool locked;
static volatile uint64_t tick_start_val;
static unsigned sbs_reads, time_reads, date_reads;
static int rollover;
enum { NEVER, AFTER_SBS, AFTER_TIME, AFTER_DATE };

static void advance(int position) {
    if (rollover == position) {
        live_calendar = next_calendar;
        live_sbs = 3124;
        rollover = NEVER;
    }
}

static void read_date(void) {
    date_reads++;
    locked = false;
    advance(AFTER_DATE);
}

fake_ertc_t *read_subsecond(void) {
    sbs_reads++;
    registers.sbs = live_sbs;
    if (!locked) frozen_calendar = live_calendar;
    locked = true;
    advance(AFTER_SBS);
    return &registers;
}
#define ERTC read_subsecond()

void ertc_calendar_get(ertc_time_type *time) {
    time_reads++;
    if (!locked) frozen_calendar = live_calendar;
    locked = true;
    *time = frozen_calendar;
    advance(AFTER_TIME);
    read_date();
}

uint32_t ertc_sub_second_get(void) {
    uint32_t value = ERTC->sbs;
    read_date(); // Vendor helper releases the shadow lock before returning.
    return value;
}
'''

TEST = r'''
typedef struct {
    const char *name;
    ertc_time_type before, after;
} transition_t;

static const transition_t transitions[] = {
    {"second", {25, 8, 15, 13, 0, 0}, {25, 8, 15, 13, 0, 1}},
    {"minute", {25, 8, 15, 13, 0, 59}, {25, 8, 15, 13, 1, 0}},
    {"hour", {25, 8, 15, 13, 59, 59}, {25, 8, 15, 14, 0, 0}},
    {"day", {25, 8, 15, 23, 59, 59}, {25, 8, 16, 0, 0, 0}},
    {"month", {25, 8, 31, 23, 59, 59}, {25, 9, 1, 0, 0, 0}},
    {"year", {25, 12, 31, 23, 59, 59}, {26, 1, 1, 0, 0, 0}},
    {"leap-day-start", {28, 2, 28, 23, 59, 59}, {28, 2, 29, 0, 0, 0}},
    {"leap-day-end", {28, 2, 29, 23, 59, 59}, {28, 3, 1, 0, 0, 0}},
};

static void setup(const transition_t *transition, uint32_t sbs, int position) {
    live_calendar = transition->before;
    next_calendar = transition->after;
    live_sbs = sbs;
    locked = false;
    rollover = position;
    sbs_reads = time_reads = date_reads = 0;
    ertc_time_type t = transition->before;
    tick_start_val = mktime_utc_fast(t.year + 2000, t.month, t.day, t.hour, t.min, t.sec, 0);
}

static int test_transition(const transition_t *transition, int position) {
    setup(transition, 0, NEVER);
    uint32_t before = GetTickCount();
    rollover = position;
    uint32_t after = GetTickCount();

    setup(transition, 0, position);
    uint32_t delta = GetTickCountDelta(before);
    // Existing rounding maps the final subsecond tick to 1000 ms.
    if (before != 1000 || after != 1000 || delta != 0 || locked) {
        printf("RED %s position=%d before=%u after=%u delta=%u\n",
               transition->name, position, before, after, delta);
        return 1;
    }
    return 0;
}

int main(void) {
    int failures = 0;
    unsigned cases = 0;
    for (unsigned i = 0; i < sizeof(transitions) / sizeof(transitions[0]); i++) {
        for (int position = AFTER_SBS; position <= AFTER_DATE; position++) {
            failures += test_transition(&transitions[i], position);
            cases++;
        }
    }

    for (uint32_t sbs = 0; sbs <= 3124; sbs++) {
        setup(&transitions[0], sbs, NEVER);
        uint32_t count = GetTickCount();
        uint32_t expected = (3125 - sbs) * 1000 / 3125;
        if (count != expected || locked) failures++;
    }

    setup(&transitions[0], 2500, NEVER);
    uint32_t before = GetTickCount();
    live_sbs = 2497;
    uint32_t after = GetTickCount();
    if (after < before || after - before > 1) failures++;

    // A coherent snapshot needs one read of each register, ending with DATE.
    setup(&transitions[0], 1000, NEVER);
    (void)GetTickCount();
    if (sbs_reads != 1 || time_reads != 1 || date_reads != 1 || locked) {
        printf("RED register reads SBS=%u TIME=%u DATE=%u\n", sbs_reads, time_reads, date_reads);
        failures++;
    }
    printf("RTC tick snapshot test: %s; %u rollover cases, 3125 subsecond values\n",
           failures ? "RED" : "OK", cases);
    return failures ? 1 : 0;
}
'''


def function(text, marker):
    start = text.index(marker)
    brace = text.index("{", start)
    depth = 1
    end = brace + 1
    while depth:
        if text[end] == "{":
            depth += 1
        elif text[end] == "}":
            depth -= 1
        end += 1
    return text[start:end] + "\n"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, help="alternate getter source for a negative control")
    parser.add_argument("--optimization", choices=("0", "2", "s"), default="2")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    hardware = (args.source or root / "common_arm/ticks/ticks_hw_at32.c").read_text()
    core = (root / "common_arm/ticks/ticks_core.c").read_text()
    calendar_math = function(hardware, "static uint64_t mktime_utc_fast(")
    getter = function(hardware, "uint32_t RAMFUNC GetTickCount(void)")
    delta = function(core, "uint32_t RAMFUNC GetTickCountDelta(")
    with tempfile.TemporaryDirectory(prefix="rtc-tick-test-") as directory:
        executable = Path(directory) / ("rtc_tick_test.exe" if os.name == "nt" else "rtc_tick_test")
        command = shlex.split(os.environ.get("CC", "cc")) + ["-std=c99", "-O" + args.optimization, "-Wall", "-Wextra", "-Werror", "-x", "c", "-", "-o", str(executable)]
        subprocess.run(command, input=PREAMBLE + calendar_math + getter + delta + TEST, text=True, check=True)
        result = subprocess.run([str(executable)])
        raise SystemExit(result.returncode)


if __name__ == "__main__":
    main()
