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
#ifndef __DESFIRE_H
#define __DESFIRE_H

#include "common.h"

#define DESFIRE_MAX_CRYPTO_BLOCK_SIZE 16
#define DESFIRE_MAX_KEY_SIZE  24
#define DESFIRE_MAC_LENGTH 4
#define DESFIRE_CMAC_LENGTH 8

typedef enum {
    T_DES = 0x00,
    T_3DES = 0x01, //aka 2K3DES
    T_3K3DES = 0x02,
    T_AES = 0x03
} DesfireCryptoAlgorithm;

#define DESFIRE_MAX_ALGO_COUNT  4       // T_DES ... T_AES
#define DESFIRE_MAX_KEY_COUNT   0x0E    // key numbers 0x00 ... 0x0D
#define DESFIRE_MAX_APP_COUNT   64      // applications we keep track of per PICC

// Keys recovered for one application.
// keys[algo][keyno][0] is the found flag,  keys[algo][keyno][1..] the key itself.
// `algo` is a DesfireCryptoAlgorithm,  `keyno` the DESFire key number.
typedef struct {
    uint32_t aid;
    uint8_t keys[DESFIRE_MAX_ALGO_COUNT][DESFIRE_MAX_KEY_COUNT][DESFIRE_MAX_KEY_SIZE + 1];
} desfire_app_keys_t;

#endif
