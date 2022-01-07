//-----------------------------------------------------------------------------
// Copyright (C) Roel Verdult 2009
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
// MIFARE Darkside hack
//-----------------------------------------------------------------------------
#include "mfkey.h"

#include "crapto1/crapto1.h"

// MIFARE
int inline compare_uint64(const void *a, const void *b) {
    if (*(uint64_t *)b == *(uint64_t *)a) return 0;
    if (*(uint64_t *)b < * (uint64_t *)a) return 1;
    return -1;
}

// create the intersection (common members) of two sorted lists. Lists are terminated by -1. Result will be in list1. Number of elements is returned.
uint32_t intersection(uint64_t *listA, uint64_t *listB) {
    if (listA == NULL || listB == NULL)
        return 0;

    uint64_t *p1, *p2, *p3;
    p1 = p3 = listA;
    p2 = listB;

    while (*p1 != UINT64_C(-1) && *p2 != UINT64_C(-1)) {
        if (compare_uint64(p1, p2) == 0) {
            *p3++ = *p1++;
            p2++;
        } else {
            while (compare_uint64(p1, p2) < 0) ++p1;
            while (compare_uint64(p1, p2) > 0) ++p2;
        }
    }
    *p3 = UINT64_C(-1);
    return p3 - listA;
}

// Darkside attack (hf mf mifare)
// if successful it will return a list of keys, not just one.
uint32_t nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint32_t ar, uint64_t par_info, uint64_t ks_info, uint64_t **keys) {
    union {
        struct Crypto1State *states;
        uint64_t *keylist;
    } unionstate;

    uint32_t i, pos;
    uint8_t ks3x[8], par[8][8];
    uint64_t key_recovered;

    // Reset the last three significant bits of the reader nonce
    nr &= 0xFFFFFF1F;

    for (pos = 0; pos < 8; pos++) {
        ks3x[7 - pos] = (ks_info >> (pos * 8)) & 0x0F;
        uint8_t bt = (par_info >> (pos * 8)) & 0xFF;

        par[7 - pos][0] = (bt >> 0) & 1;
        par[7 - pos][1] = (bt >> 1) & 1;
        par[7 - pos][2] = (bt >> 2) & 1;
        par[7 - pos][3] = (bt >> 3) & 1;
        par[7 - pos][4] = (bt >> 4) & 1;
        par[7 - pos][5] = (bt >> 5) & 1;
        par[7 - pos][6] = (bt >> 6) & 1;
        par[7 - pos][7] = (bt >> 7) & 1;
    }

    unionstate.states = lfsr_common_prefix(nr, ar, ks3x, par, (par_info == 0));

    if (!unionstate.states) {
        *keys = NULL;
        return 0;
    }

    for (i = 0; unionstate.keylist[i]; i++) {
        lfsr_rollback_word(unionstate.states + i, uid ^ nt, 0);
        crypto1_get_lfsr(unionstate.states + i, &key_recovered);
        unionstate.keylist[i] = key_recovered;
    }
    unionstate.keylist[i] = -1;

    *keys = unionstate.keylist;
    return i;
}

// recover key from 2 different reader responses on same tag challenge
bool mfkey32(nonces_t *data, uint64_t *outputkey) {
    struct Crypto1State *s, *t;
    uint64_t outkey = 0;
    uint64_t key = 0;     // recovered key
    bool isSuccess = false;
    uint8_t counter = 0;

    uint32_t p640 = prng_successor(data->nonce, 64);

    s = lfsr_recovery32(data->ar ^ p640, 0);

    for (t = s; t->odd | t->even; ++t) {
        lfsr_rollback_word(t, 0, 0);
        lfsr_rollback_word(t, data->nr, 1);
        lfsr_rollback_word(t, data->cuid ^ data->nonce, 0);
        crypto1_get_lfsr(t, &key);
        crypto1_word(t, data->cuid ^ data->nonce, 0);
        crypto1_word(t, data->nr2, 1);
        if (data->ar2 == (crypto1_word(t, 0, 0) ^ p640)) {
            outkey = key;
            counter++;
            if (counter == 20) break;
        }
    }
    isSuccess = (counter == 1);
    *outputkey = (isSuccess) ? outkey : 0;
    crypto1_destroy(s);
    return isSuccess;
}

// recover key from 2 reader responses on 2 different tag challenges
// skip "several found keys".  Only return true if ONE key is found
bool mfkey32_moebius(nonces_t *data, uint64_t *outputkey) {
    struct Crypto1State *s, *t;
    uint64_t outkey  = 0;
    uint64_t key     = 0; // recovered key
    bool isSuccess = false;
    int counter = 0;
    uint32_t p640 = prng_successor(data->nonce, 64);
    uint32_t p641 = prng_successor(data->nonce2, 64);

    s = lfsr_recovery32(data->ar ^ p640, 0);

    for (t = s; t->odd | t->even; ++t) {
        lfsr_rollback_word(t, 0, 0);
        lfsr_rollback_word(t, data->nr, 1);
        lfsr_rollback_word(t, data->cuid ^ data->nonce, 0);
        crypto1_get_lfsr(t, &key);

        crypto1_word(t, data->cuid ^ data->nonce2, 0);
        crypto1_word(t, data->nr2, 1);
        if (data->ar2 == (crypto1_word(t, 0, 0) ^ p641)) {
            outkey = key;
            ++counter;
            if (counter == 20) break;
        }
    }
    isSuccess  = (counter == 1);
    *outputkey = (isSuccess) ? outkey : 0;
    crypto1_destroy(s);
    return isSuccess;
}

// recover key from reader response and tag response of one authentication sequence
int mfkey64(nonces_t *data, uint64_t *outputkey) {
    uint64_t key = 0;  // recovered key
    uint32_t ks2;      // keystream used to encrypt reader response
    uint32_t ks3;      // keystream used to encrypt tag response
    struct Crypto1State *revstate;

    // Extract the keystream from the messages
    ks2 = data->ar ^ prng_successor(data->nonce, 64);
    ks3 = data->at ^ prng_successor(data->nonce, 96);
    revstate = lfsr_recovery64(ks2, ks3);
    lfsr_rollback_word(revstate, 0, 0);
    lfsr_rollback_word(revstate, 0, 0);
    lfsr_rollback_word(revstate, data->nr, 1);
    lfsr_rollback_word(revstate, data->cuid ^ data->nonce, 0);
    crypto1_get_lfsr(revstate, &key);
    crypto1_destroy(revstate);
    *outputkey = key;
    return 0;
}
