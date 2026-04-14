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

#include "cipher_bs_dispatch.h"
#include "cipher_bs.h"
#include "cipher_bs_avx2.h"
#include "cipher_bs_avx512.h"
#include "cipher_bs_neon.h"

// The u64 match function returns its mask instead of writing through a
// pointer; wrap it to match the uniform backend signature.
static void u64_match_adapter(const uint64_t *y, const uint64_t *kb,
                              const uint64_t *tgt, uint64_t *out) {
    out[0] = doMAC_brute_match64(y, kb, tgt);
}

static const bs_backend_t backend_u64 = {
    .width        = 64,
    .words        = 1,
    .name         = "u64",
    .prepare_ccnr = prepare_ccnr_bits_bs,
    .prepare_mac  = prepare_target_mac_bs,
    .build_key    = build_bitslice_key_64,
    .match        = u64_match_adapter,
};

static const bs_backend_t backend_neon = {
    .width        = 128,
    .words        = 2,
    .name         = "NEON",
    .prepare_ccnr = prepare_ccnr_bits_bs128,
    .prepare_mac  = prepare_target_mac_bs128,
    .build_key    = build_bitslice_key_128,
    .match        = doMAC_brute_match128,
};

static const bs_backend_t backend_avx2 = {
    .width        = 256,
    .words        = 4,
    .name         = "AVX2",
    .prepare_ccnr = prepare_ccnr_bits_bs256,
    .prepare_mac  = prepare_target_mac_bs256,
    .build_key    = build_bitslice_key_256,
    .match        = doMAC_brute_match256,
};

static const bs_backend_t backend_avx512 = {
    .width        = 512,
    .words        = 8,
    .name         = "AVX-512",
    .prepare_ccnr = prepare_ccnr_bits_bs512,
    .prepare_mac  = prepare_target_mac_bs512,
    .build_key    = build_bitslice_key_512,
    .match        = doMAC_brute_match512,
};

const bs_backend_t *bs_best_backend(void) {
    static const bs_backend_t *cached = NULL;
    if (cached != NULL) return cached;

    if (bs_avx512_supported()) {
        cached = &backend_avx512;
    } else if (bs_avx2_supported()) {
        cached = &backend_avx2;
    } else if (bs_neon_supported()) {
        cached = &backend_neon;
    } else {
        cached = &backend_u64;
    }
    return cached;
}
