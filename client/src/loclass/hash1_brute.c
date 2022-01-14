//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
#include "hash1_brute.h"
#include <stdio.h>
#include "cipherutils.h"
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <ctype.h>
#include "elite_crack.h"
#include "ui.h"

static void calc_score(uint8_t *csn, uint8_t *k) {
    uint8_t score = 0 ;
    uint8_t i;
    uint8_t goodvals[16] = {0};
    uint8_t uniq_vals[8] = {0};
    memset(goodvals, 0x00, 16);
    memset(uniq_vals, 0x00, 8);
    uint8_t badval = 0;
    int badscore = 0;
    for (i = 0; i < 8 ; i++) {
        if (k[i] == 0x01) continue;
        if (k[i] == 0x00) continue;
        if (k[i] == 0x45) continue;
        if (k[i] < 16) {
            goodvals[k[i]] = 1;
        }
//        if(k[i] ==9 || k[i]==2){
//            goodvals[k[i]] = 1;
//        }

//        else if (k[i] >= 16) {
        else {
            badscore++;
            badval = k[i];
        }
    }
    for (i = 0; i < 16; i++) {
        if (goodvals[i]) {
            uniq_vals[score] = i;
            score += 1;
        }
    }

    if (score >= 2 && badscore < 2) {
        PrintAndLogEx(NORMAL, "CSN\t%02x%02x%02x%02x%02x%02x%02x%02x\t%02x %02x %02x %02x %02x %02x %02x %02x\t" NOLF
                      , csn[0], csn[1], csn[2], csn[3], csn[4], csn[5], csn[6], csn[7]
                      , k[0], k[1], k[2], k[3], k[4], k[5], k[6], k[7]
                     );

        for (i = 0 ; i < score; i++) {
            PrintAndLogEx(NORMAL, "%d," NOLF, uniq_vals[i]);
        }
        PrintAndLogEx(NORMAL, "\tbadscore: %d (%02x)" NOLF, badscore, badval);
        PrintAndLogEx(NORMAL, "");
    }
}

void brute_hash1(void) {

    uint8_t csn[8] = {0, 0, 0, 0, 0xf7, 0xff, 0x12, 0xe0};
    uint8_t k[8] = {0, 0, 0, 0, 0, 0, 0, 0};
    uint8_t testcsn[8] = {0x00, 0x0d, 0x0f, 0xfd, 0xf7, 0xff, 0x12, 0xe0} ;
    uint8_t testkey[8] = {0x05, 0x01, 0x00, 0x10, 0x45, 0x08, 0x45, 0x56} ;
    calc_score(testcsn, testkey);

    PrintAndLogEx(INFO, "Brute forcing hashones");

    for (uint16_t a = 0; a < 256; a++) {
        for (uint16_t b = 0; b < 256; b++) {
            for (uint16_t c = 0; c < 256; c++) {
                for (uint16_t d = 0; d < 256; d++) {
                    csn[0] = a;
                    csn[1] = b;
                    csn[2] = c;
                    csn[3] = d;
                    csn[4] = 0xf7;
                    csn[5] = 0xff;
                    csn[6] = 0x12;
                    csn[7] = 0xe0;
                    hash1(csn, k);
                    calc_score(csn, k);
                }
            }
        }
    }
}

