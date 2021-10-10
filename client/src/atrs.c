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
#include <ctype.h>
#include <string.h>
#include "commonutil.h"   // ARRAYLEN
#include "util.h"         // startswith

// get a ATR description based on the atr bytes
// returns description of the best match
const char *getAtrInfo(const char *atr_str) {

    for (int i = 0; i < ARRAYLEN(AtrTable); ++i) {

        // check for dots in atr table. 
        // dots indicate those bytes at those positions are optional.
        // need a special case for them
        if (strstr(AtrTable[i].bytes, "..") != NULL) {

            // need to loop
            const char *foo = atr_str;
            int j = 0;
            while (foo++, j++) {
                
                char c = foo[0];
                if (c == '.') {
                    continue;
                }

                // mismatch,  return default message
                if (c != AtrTable[i].bytes[j]) {
                    return AtrTable[ARRAYLEN(AtrTable) - 1].desc;
                }

            }

            return AtrTable[i].desc;

        } else {
            if (str_startswith(atr_str, AtrTable[i].bytes)) {
                return AtrTable[i].desc;
            }
        }
    }

    //No match, return default
    return AtrTable[ARRAYLEN(AtrTable) - 1].desc;
}
