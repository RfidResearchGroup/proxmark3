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
// ATR information lookup
//-----------------------------------------------------------------------------
#include "atrs.h"
#include <string.h>
#include <stdlib.h>
#include "commonutil.h" // ARRAYLEN
#include "ui.h"         // PrintAndLogEx

// get a ATR description based on the atr bytes
// returns description of the best match
const char *getAtrInfo(const char *atr_str) {

    size_t slen = strlen(atr_str);
    int match = -1;

    // skip last element of AtrTable
    for (size_t i = 0; i < ARRAYLEN(AtrTable) - 1; ++i) {

        if (strlen(AtrTable[i].bytes) != slen) {
            continue;
        }

        if (strstr(AtrTable[i].bytes, ".") != NULL) {

            char *tmp_atr = calloc(slen, sizeof(uint8_t));
            if (tmp_atr == NULL) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                return NULL;
            }

            for (size_t j = 0; j < slen; j++) {
                tmp_atr[j] = (AtrTable[i].bytes[j] == '.') ? '.' : atr_str[j];
            }

            if (strncmp(tmp_atr, AtrTable[i].bytes, slen) == 0) {
                // record partial match but continue looking for full match
                match = i;
            }
            free(tmp_atr);

        } else {
            if (strncmp(atr_str, AtrTable[i].bytes, slen) == 0) {
                return AtrTable[i].desc;
            }
        }
    }

    if (match >= 0) {
        return AtrTable[match].desc;
    } else {
        //No match, return default = last element of AtrTable
        return AtrTable[ARRAYLEN(AtrTable) - 1].desc;
    }
}

void atsToEmulatedAtr(uint8_t *ats, uint8_t *atr, int *atrLen) {
    uint8_t historicalLen = 0;
    uint8_t offset = 2;

    if (ats[0] < 2) {
        historicalLen = 0;
    } else {

        if ((ats[1] & 64) != 0) {
            offset++;
        }
        if ((ats[1] & 32) != 0) {
            offset++;
        }
        if ((ats[1] & 16) != 0) {
            offset++;
        }

        if (offset >= ats[0]) {
            historicalLen = 0;
        } else {
            historicalLen = ats[0] - offset;
        }
    }

    atr[0] = 0x3B;
    atr[1] = 0x80 | historicalLen;
    atr[2] = 0x80;
    atr[3] = 0x01;

    uint8_t tck = atr[1] ^ atr[2] ^ atr[3];
    for (uint8_t i = 0; i < historicalLen; ++i) {
        atr[4 + i] = ats[offset + i];
        tck = tck ^ ats[offset + i];
    }
    atr[4 + historicalLen] = tck;

    *atrLen = 5 + historicalLen;
}

void atqbToEmulatedAtr(uint8_t *atqb, uint8_t cid, uint8_t *atr, int *atrLen) {
    atr[0] = 0x3B;
    atr[1] = 0x80 | 8;
    atr[2] = 0x80;
    atr[3] = 0x01;

    memcpy(atr + 4, atqb, 7);
    atr[11] = cid >> 4;

    uint8_t tck = 0;
    for (int i = 1; i < 12; ++i) {
        tck = tck ^ atr[i];
    }
    atr[12] = tck;

    *atrLen = 13;
}

