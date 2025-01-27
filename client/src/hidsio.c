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
// HID Global SIO utilities
//-----------------------------------------------------------------------------
#include "commonutil.h"
#include "hidsio.h"

// structure and database for uid -> tagtype lookups
typedef struct {
    uint8_t uid;
    const char *desc;
} sioMediaTypeName_t;

static const sioMediaTypeName_t sioMediaTypeMapping[] = {
    { 0x00, "Unknown"},
    { 0x01, "DESFire"},
    { 0x02, "MIFARE"},
    { 0x03, "iCLASS (PicoPass)"},
    { 0x04, "ISO14443AL4"},
    { 0x06, "MIFARE Plus"},
    { 0x07, "Seos"},
    { 0xFF, "INVALID VALUE"}
};

// get a SIO media type based on the UID
//  uid[8] tag uid
// returns description of the best match
const char *getSioMediaTypeInfo(uint8_t uid) {

    for (int i = 0; i < ARRAYLEN(sioMediaTypeMapping); ++i) {
        if (uid == sioMediaTypeMapping[i].uid) {
            return sioMediaTypeMapping[i].desc;
        }
    }

    //No match, return default
    return sioMediaTypeMapping[ARRAYLEN(sioMediaTypeMapping) - 1].desc;
}
