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
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------
#ifndef CMDHFMFP_H__
#define CMDHFMFP_H__

#include "common.h"

typedef enum {
    MFP_UNKNOWN = 0,
    DESFIRE_MF3ICD40,
    DESFIRE_EV1,
    DESFIRE_EV2,
    DESFIRE_EV3,
    DESFIRE_LIGHT,
    PLUS_EV1,
} nxp_cardtype_t;

typedef struct mfp_key_item {
    uint8_t a[16];
    uint8_t b[16];
} mfp_key_item_t;

typedef struct mfp_keys {
    uint8_t success;
    mfp_key_item_t *keys;
} mfp_keys_t;

int CmdHFMFP(const char *Cmd);
int CmdHFMFPNDEFRead(const char *Cmd);

#endif
