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
    for (int i = 0; i < ARRAYLEN(AtrTable) - 1; ++i) {

        if (strlen(AtrTable[i].bytes) != slen)
            continue;

        if (strstr(AtrTable[i].bytes, ".") != NULL) {
            char *tmp_atr = calloc(slen, sizeof(uint8_t));
            if (tmp_atr == NULL) {
                PrintAndLogEx(FAILED, "failed to allocate memory");
                return NULL;
            }

            for (int j = 0; j < slen; j++) {
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
