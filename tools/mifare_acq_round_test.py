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

"""Exercise the actual nonce-acquisition loop with controlled attempt timings."""

import argparse
import os
from pathlib import Path
import re
import shlex
import subprocess
import tempfile

PREAMBLE = r'''
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include "pm3_cmd.h"
#include "protocols.h"
// Native stubs do not use ARM RAM placement.
#undef RAMFUNC
#define RAMFUNC
#include "iso14443a.h"
#include "crapto1/crapto1.h"
#define MAX_MIFARE_FRAME_SIZE 32
#define FPGA_HF_ISO14443A_READER_LISTEN 0
#define FPGA_MAJOR_MODE_OFF 0
#define AUTH_FIRST 0
#define AUTH_NESTED 2
#define CHK_TIMEOUT() ((void)0)
#define LED_A_ON() ((void)0)
#define LED_C_OFF() ((void)0)
#define LED_C_ON() ((void)0)
#define LED_B_ON() ((void)0)
#define LED_B_OFF() ((void)0)
#define DBG_ERROR 1
#define DBG_DEBUG 3
#define DBG_EXTENDED 4

static uint32_t ticks, attempt_ms, attempts, watchdog_hits;
static bool cancelled;
static bool client_cancelled;
static bool initialize_request = true;
static int mode, returned_status;
static size_t returned_length;
static uint8_t returned_data[PM3_CMD_DATA_SIZE];
static tDemod14a demod;
int g_dbglevel;
enum { VALID, AUTH_FAIL, PARTIAL, STATIC_REPLY, SELECT_FAIL, FAST_SELECT_FAIL };

uint32_t GetTickCount(void) { return ticks; }
uint32_t GetTickCountDelta(uint32_t start) { return ticks - start; }
static bool BUTTON_PRESS(void) { return cancelled; }
static bool data_available(void) { return client_cancelled; }
#define WDT_HIT() (watchdog_hits++)
static void BigBuf_free(void) {}
static void BigBuf_Clear_ext(bool value) { (void)value; }
static void set_tracing(bool value) { (void)value; }
static void LEDsoff(void) {}
static void FpgaWriteConfWord(int value) { (void)value; }
static void SpinDelayUs(unsigned value) { (void)value; }
#define HARDNESTED_PRE_AUTHENTICATION_LEADTIME 400
static void Dbprintf(const char *format, ...) { (void)format; }
static void DbpString(const char *text) { (void)text; }
static uint64_t bytes_to_num(const uint8_t *data, unsigned length) {
    (void)data; (void)length; return 0;
}
void iso14443a_setup(uint8_t mode_value) { (void)mode_value; }
int iso14443a_select_card(uint8_t *uid, iso14a_card_select_t *card, uint32_t *cuid, bool anti, uint8_t cascades, bool no_rats) {
    (void)uid; (void)anti; (void)cascades; (void)no_rats;
    if (mode == SELECT_FAIL) {
        ticks += attempt_ms;
        attempts++;
        return 0;
    }
    card->uidlen = 4;
    *cuid = 1;
    return 1;
}
int iso14443a_fast_select_card(const uint8_t *uid, uint8_t cascades) {
    (void)uid; (void)cascades;
    if (mode == FAST_SELECT_FAIL) {
        ticks += attempt_ms;
        attempts++;
        return 0;
    }
    return 1;
}
static int mifare_classic_authex(struct Crypto1State *pcs, uint32_t uid, uint8_t block, uint8_t type, uint64_t key, uint8_t nested, uint32_t *nt, uint32_t *timing) {
    (void)pcs; (void)uid; (void)block; (void)type; (void)key;
    (void)nested; (void)nt; (void)timing;
    ticks += attempt_ms;
    attempts++;
    return mode == AUTH_FAIL;
}
static uint16_t mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t block, uint8_t *out, size_t size, uint8_t *parity, uint32_t *timing) {
    (void)pcs; (void)crypted; (void)cmd; (void)block; (void)size; (void)timing;
    out[0] = mode == STATIC_REPLY ? 1 : (uint8_t)attempts;
    out[1] = 1; out[2] = 2; out[3] = 3;
    parity[0] = 0x5a;
    demod = (tDemod14a){0};
    demod.len = 4;
    demod.parityLen = 1;
    demod.bitCount = mode == PARTIAL ? 7 : 0;
    return 4;
}
tDemod14a *GetDemod14a(void) { return &demod; }
void crypto1_deinit(struct Crypto1State *pcs) { (void)pcs; }
static int reply_ng(uint16_t command, int8_t status, const uint8_t *data, size_t length) {
    (void)command;
    returned_status = status;
    returned_length = length;
    memcpy(returned_data, data, length);
    return PM3_SUCCESS;
}
'''

TESTS = r'''
#define CHECK(value) do { if (!(value)) { fprintf(stderr, "line %d: %s (ticks=%u attempts=%u)\n", __LINE__, #value, ticks, attempts); return 1; } } while (0)
static void acquire(int scenario, uint32_t duration, bool cancel, uint32_t start) {
    ticks = start;
    attempts = 0;
    watchdog_hits = 0;
    attempt_ms = duration;
    mode = scenario;
    cancelled = cancel;
    mf_acquire_nonces_t payload = {0};
    payload.flags = initialize_request ? 1 : 0;
    MifareAcquireEncryptedNonces(&payload);
}
static uint16_t returned_nonces(void) {
    return ((mf_nonces_resp_t *)returned_data)->num_nonces;
}
int main(void) {
    // Hit the budget before filling even the smaller PM3 buffer.
    acquire(VALID, 30, false, 0);
    CHECK(ticks == 2910 && attempts == 97 && watchdog_hits == attempts);
    CHECK(returned_status == PM3_SUCCESS && returned_nonces() == 96);
    CHECK(returned_length == sizeof(mf_nonces_resp_t) + 48 * MFC_NONCE_PAIR_SIZE);

    acquire(AUTH_FAIL, 20, false, 0);
    CHECK(ticks == 2900 && attempts == 145 && returned_nonces() == 0);
    CHECK(returned_status == PM3_SUCCESS && returned_length == sizeof(mf_nonces_resp_t));

    acquire(SELECT_FAIL, 20, false, 0);
    CHECK(ticks == 2900 && attempts == 145 && returned_nonces() == 0);

    acquire(FAST_SELECT_FAIL, 20, false, 0);
    CHECK(ticks == 2900 && attempts == 145 && returned_nonces() == 0);

    acquire(VALID, 1, false, 0);
    CHECK(attempts == 2 * MFC_MAX_NONCE_PAIRS && returned_nonces() == attempts && ticks == attempts);
    CHECK(returned_length == sizeof(mf_nonces_resp_t) + MFC_MAX_NONCE_PAIRS * MFC_NONCE_PAIR_SIZE);

    acquire(VALID, 3100, false, 0);
    CHECK(attempts == 1 && ticks == 3100 && returned_nonces() == 0);

    acquire(VALID, 20, true, 0);
    CHECK(attempts == 0 && returned_status == PM3_EOPABORTED);

    client_cancelled = true;
    acquire(VALID, 20, false, 0);
    CHECK(attempts == 0 && watchdog_hits == 0 && returned_status == PM3_EOPABORTED);
    client_cancelled = false;

    acquire(STATIC_REPLY, 20, false, 0);
    CHECK(attempts == 6 && returned_status == PM3_ESTATIC_NONCE && returned_nonces() == 6);

    acquire(VALID, 30, false, UINT32_MAX - 99);
    CHECK(attempts == 97 && returned_nonces() == 96);

    initialize_request = false;
    acquire(VALID, 30, false, 123);
    CHECK(ticks == 3033 && attempts == 97 && returned_nonces() == 96);
    puts("Actual nonce round-budget test: OK");
    return 0;
}
'''


def function(text, marker):
    start = text.index(marker)
    position = text.index("{", start) + 1
    depth = 1
    while depth:
        if text[position] == "{":
            depth += 1
        elif text[position] == "}":
            depth -= 1
        position += 1
    return text[start:position]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path)
    parser.add_argument("--platform", choices=("PM5",
                        "PM3RDV4", "PM3GENERIC"), default="PM5")
    parser.add_argument("--optimization", choices=("0", "2", "s"), default="2")
    args = parser.parse_args()
    root = Path(__file__).resolve().parent.parent
    source = (args.source or root / "armsrc/mifarecmd.c").read_text()
    actual = function(source, "void MifareAcquireEncryptedNonces(")
    settings = "\n".join(re.findall(
        r"#ifndef (?:MFC_ACQ_ROUND_(?:BUDGET_MS|MAX_PAIRS)|HARDNESTED_NESTED_TURNAROUND_DELAY_US)\b.*?#endif",
        source, re.S))
    with tempfile.TemporaryDirectory(prefix="round-budget-test-") as directory:
        executable = Path(
            directory) / ("round_budget_test.exe" if os.name == "nt" else "round_budget_test")
        command = shlex.split(os.environ.get("CC", "cc")) + [
            "-std=c99", "-Wall", "-Wextra", "-Werror", "-DON_DEVICE", "-D" + args.platform,
            "-O" + args.optimization,
            "-iquote" + str(root / "armsrc"), "-I" + str(root / "include"),
            "-I" + str(root / "common"), "-x", "c", "-", "-o", str(executable),
        ]
        subprocess.run(command, input=PREAMBLE + settings +
                       "\n" + actual + TESTS, text=True, check=True)
        subprocess.run([str(executable)], check=True)


if __name__ == "__main__":
    main()
