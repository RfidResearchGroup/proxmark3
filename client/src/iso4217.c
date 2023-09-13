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
// ISO4217 Currency information lookup
//-----------------------------------------------------------------------------
#include "iso4217.h"
#include <string.h>
#include <stdlib.h>
#include "commonutil.h"   // ARRAYLEN
#include "ui.h"           // PrintAndLogEx

// get a Currency description based on the currency number string
const char *getCurrencyInfo(const char *cn_str) {
    size_t slen = strlen(cn_str);

    // skip last element of AtrTable
    for (int i = 0; i < ARRAYLEN(Iso4217Table) - 1; ++i) {
        if (strncmp(cn_str, Iso4217Table[i].code, slen) == 0)
            return Iso4217Table[i].desc;
    }
    return Iso4217Table[ARRAYLEN(Iso4217Table) - 1].desc;
}

