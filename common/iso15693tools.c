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
// ISO15693 other commons
//-----------------------------------------------------------------------------
#include "iso15693tools.h"

#include <stdio.h>

// returns a string representation of the UID
// UID is transmitted and stored LSB first, displayed MSB first
// dest    char* buffer, where to put the UID, if NULL a static buffer is returned
// uid[]     the UID in transmission order
// return: ptr to string
char *iso15693_sprintUID(char *dest, uint8_t *uid) {
    static char tempbuf[3 * 8 + 1] = {0};
    if (dest == NULL)
        dest = tempbuf;

    if (uid) {
        sprintf(dest, "%02X %02X %02X %02X %02X %02X %02X %02X",
                uid[7], uid[6], uid[5], uid[4],
                uid[3], uid[2], uid[1], uid[0]
               );
    }
    return dest;
}
