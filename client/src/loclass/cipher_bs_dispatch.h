//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Runtime dispatcher for the legbrute bitslice backends. Returns the widest
// bitslice implementation the CPU supports: AVX-512 (512 lanes) > AVX2 (256)
// > NEON (128) > portable u64 (64).
//
// Buffers in the returned backend must be sized for backend->words uint64_t
// per logical bit; callers can stack-allocate using BS_MAX_WORDS to cover
// every backend.
//-----------------------------------------------------------------------------

#ifndef CIPHER_BS_DISPATCH_H
#define CIPHER_BS_DISPATCH_H

#include <stdint.h>

#define BS_MAX_WORDS 8  // AVX-512

typedef struct bs_backend_s {
    int width;   // 64, 128, 256, or 512
    int words;   // width / 64
    const char *name;
    void (*prepare_ccnr)(const uint8_t *cc_nr, uint64_t *y_bits_bs);
    void (*prepare_mac)(const uint8_t target_mac[4], uint64_t *target_mac_bs);
    void (*build_key)(const uint8_t partial_key[8], uint64_t index_start, uint64_t *kb);
    void (*match)(const uint64_t *y_bits_bs, const uint64_t *kb, const uint64_t *target_mac_bs, uint64_t *match_out);
} bs_backend_t;

// Returns the widest backend the current CPU supports. Never NULL (u64 is
// the universal fallback). Cached after first call; safe to call repeatedly.
const bs_backend_t *bs_best_backend(void);

#endif // CIPHER_BS_DISPATCH_H
