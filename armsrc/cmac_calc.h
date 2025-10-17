//-----------------------------------------------------------------------------
// Copyright (C) Christian Herrmman, Iceman - October 2025
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
// Calculate CMAC AES
//-----------------------------------------------------------------------------

#ifndef __CMAC_CALC_H
#define __CMAC_CALC_H


#include "common.h"

typedef struct {
    bool use_schann;
    uint8_t cmac_sk1[16];
    uint8_t cmac_sk2[16];
    uint8_t sessionkey[16];
    uint16_t counter;
} ulaes_key_t;

ulaes_key_t *get_secure_session_obj(void);

void init_secure_session(void);
void increase_session_counter(void);
void set_session_channel(bool use_schann);

void ulaes_cmac(const uint8_t *key, size_t key_len, const uint8_t *input, size_t ilen, uint8_t output[16]);
void ulaes_cmac8(uint8_t *cmac, uint8_t *mac);
void append_cmac(uint8_t *d, size_t n);

#endif
