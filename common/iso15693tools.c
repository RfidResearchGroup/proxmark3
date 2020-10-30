//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

    sprintf(dest, "%02X %02X %02X %02X %02X %02X %02X %02X",
            uid[7], uid[6], uid[5], uid[4],
            uid[3], uid[2], uid[1], uid[0]
           );
    return dest;
}
