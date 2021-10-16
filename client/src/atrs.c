//-----------------------------------------------------------------------------
// Copyright (C) Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// ATR information lookup
//-----------------------------------------------------------------------------
#include "atrs.h"
#include <string.h>
#include <stdlib.h>
#include "commonutil.h"   // ARRAYLEN
#include "ui.h" // PrintAndLogEx

// get a ATR description based on the atr bytes
// returns description of the best match
const char *getAtrInfo(const char *atr_str) {
    size_t slen = strlen(atr_str);
    int match = -1;
    // skip last element of AtrTable
    for (int i = 0; i < ARRAYLEN(AtrTable) - 1; ++i) {

        if (strlen(AtrTable[i].bytes) != slen)
            continue;

        if (strstr(AtrTable[i].bytes, "..") != NULL) {
            char *tmp_atr = calloc(slen, sizeof(uint8_t));
            if (tmp_atr == NULL) {
                PrintAndLogEx(FAILED, "failed to allocate memory");
                return NULL;
            }

            for (int j = 0; j < slen; j++) {
                tmp_atr[j] = AtrTable[i].bytes[j] == '.' ? '.' : atr_str[j];
            }

            if (strncmp(tmp_atr, AtrTable[i].bytes, slen) == 0) {
                // record partial match but continue looking for full match
                match = i;
            }
            free(tmp_atr);

        } else {
            if (strncmp(atr_str, AtrTable[i].bytes, slen) == 0) return AtrTable[i].desc;
        }
    }
    if (match >= 0) {
        return AtrTable[match].desc;
    } else {
        //No match, return default = last element of AtrTable
        return AtrTable[ARRAYLEN(AtrTable) - 1].desc;
    }
}
