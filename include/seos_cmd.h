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
// Seos type prototyping
//-----------------------------------------------------------------------------

#ifndef _SEOS_CMD_H_
#define _SEOS_CMD_H_

#include "common.h"

#define SEOS_ENCRYPTION_2K3DES      0x02
#define SEOS_ENCRYPTION_3K3DES      0x03
#define SEOS_ENCRYPTION_AES         0x09

#define SEOS_HASHING_SHA1           0x06
#define SEOS_HASHING_SHA256         0x07

// Seos emulate request data structure
typedef struct {
    uint8_t encr_alg;
    uint8_t hash_alg;

    uint8_t uid[10];
    uint8_t uid_len;

    uint8_t privenc[16];
    uint8_t privmac[16];
    uint8_t authkey[16];

    uint8_t diversifier_len;
    uint8_t diversifier[16];
    
    uint8_t data_tag_len;
    uint8_t data_tag[8];
    
    uint8_t data_len;
    uint8_t data[128];
    
    uint8_t oid_len;
    uint8_t oid[32];
} PACKED seos_emulate_req_t;

#endif // _SEOS_H_
