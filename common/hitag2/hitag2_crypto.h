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
#include <stdbool.h>

#ifndef LFSR_INV
#define LFSR_INV(state) (((state) << 1) | (__builtin_parityll((state) & ((0xce0044c101cd >> 1) | (1ull << 47)))))
#endif


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

typedef struct {
    uint64_t shiftreg; // naive shift register, required for nonlinear fn input
    uint64_t lfsr;     // fast lfsr, used to make software faster
} hitag_state_t;

void ht2_hitag2_init_ex(hitag_state_t *hstate, uint64_t sharedkey, uint32_t serialnum, const uint32_t iv);
void ht2_rollback(hitag_state_t *hstate, uint32_t steps);
uint64_t ht2_recoverkey(hitag_state_t *hstate, uint32_t uid, uint32_t nRenc);
uint32_t ht2_hitag2_nstep(hitag_state_t *hstate, uint32_t steps);
uint32_t ht2_hitag_acid(hitag_state_t *hstate, uint32_t steps);

int ht2_try_state(uint64_t s, uint32_t uid, uint32_t aR2, uint32_t nR1, uint32_t nR2, uint64_t *key);

uint32_t ht2_hitag2_word(uint64_t *state, uint32_t steps);
uint64_t ht2_hitag2_init(const uint64_t key, const uint32_t serial, const uint32_t iv);
uint64_t ht2_hitag2_bit(uint64_t *state);
uint32_t ht2_hitag2_byte(uint64_t *state);
void ht2_hitag2_cipher_reset(hitag2_t *tag, const uint8_t *iv);
int ht2_hitag2_cipher_authenticate(uint64_t *state, const uint8_t *authenticator_is);
void ht2_hitag2_cipher_transcrypt(uint64_t *state, uint8_t *data, uint16_t bytes, uint16_t bits) ;

int ht2_fnf(uint64_t state);
int ht2_fnR(uint64_t state);
#endif
