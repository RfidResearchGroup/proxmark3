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
#include <regex.h>        // regex?
#include "commonutil.h"   // ARRAYLEN
#include "ui.h"           // get PrintAndLogEx
#include "util.h"         // startswith

// get a ATR description based on the atr bytes
// returns description of the best match
const char *getAtrInfo(const char *atr_str) {

    for (int i = 0; i < ARRAYLEN(AtrTable); ++i) {

        // check for dots in atr table. 
        // dots indicate those bytes at those positions are optional.
        // need a special case for them
        if (strstr(AtrTable[i].bytes, ".") != NULL) {

            regex_t r;
            int ret = regcomp(&r, AtrTable[i].bytes, 0);
            if (ret) {
                // take next ATR value.
                PrintAndLogEx(DEBUG, "can't compile regex");
                continue;
            }

            /* Execute regular expression */
            ret = regexec(&r, atr_str, 0, NULL, 0);
            regfree(&r);

            if (!ret) {
                return AtrTable[i].desc;
            }
            else if (ret == REG_NOMATCH) {
                continue;
            }
            else {
                PrintAndLogEx(DEBUG, "regex failed");
                continue;
            }

        } else {
            if (str_startswith(atr_str, AtrTable[i].bytes)) {
                return AtrTable[i].desc;
            }
        }
    }

    //No match, return default
    return AtrTable[ARRAYLEN(AtrTable) - 1].desc;
}
