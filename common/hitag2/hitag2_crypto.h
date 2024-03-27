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
#ifndef __HITAG2_CRYPTO_H
#define __HITAG2_CRYPTO_H

#include "common.h"

typedef struct {
    uint32_t uid;
    enum {
        TAG_STATE_RESET      = 0x01,       // Just powered up, awaiting GetSnr
        TAG_STATE_ACTIVATING = 0x02,       // In activation phase (password mode), sent UID, awaiting reader password
        TAG_STATE_ACTIVATED  = 0x03,       // Activation complete, awaiting read/write commands
        TAG_STATE_WRITING    = 0x04,       // In write command, awaiting sector contents to be written
    } state;
    uint16_t active_sector;
    uint8_t crypto_active;
    uint64_t cs;
    uint8_t sectors[12][4];
} hitag2_t;

uint64_t ht2_hitag2_init(const uint64_t key, const uint32_t serial, const uint32_t IV);
uint64_t ht2_hitag2_round(uint64_t *state);
uint32_t ht2_hitag2_byte(uint64_t *x);
void ht2_hitag2_cipher_reset(hitag2_t *tag, const uint8_t *iv);
int ht2_hitag2_cipher_authenticate(uint64_t *cs, const uint8_t *authenticator_is);
int ht2_hitag2_cipher_transcrypt(uint64_t *cs, uint8_t *data, uint16_t bytes, uint16_t bits) ;

#endif
