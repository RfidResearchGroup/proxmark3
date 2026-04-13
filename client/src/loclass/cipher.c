//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/holiman/loclass
// Copyright (C) 2014 Martin Holst Swende
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
// WARNING
//
// THIS CODE IS CREATED FOR EXPERIMENTATION AND EDUCATIONAL USE ONLY.
//
// USAGE OF THIS CODE IN OTHER WAYS MAY INFRINGE UPON THE INTELLECTUAL
// PROPERTY OF OTHER PARTIES, SUCH AS INSIDE SECURE AND HID GLOBAL,
// AND MAY EXPOSE YOU TO AN INFRINGEMENT ACTION FROM THOSE PARTIES.
//
// THIS CODE SHOULD NEVER BE USED TO INFRINGE PATENTS OR INTELLECTUAL PROPERTY RIGHTS.
//-----------------------------------------------------------------------------
// It is a reconstruction of the cipher engine used in iClass, and RFID techology.
//
// The implementation is based on the work performed by
// Flavio D. Garcia, Gerhard de Koning Gans, Roel Verdult and
// Milosch Meriac in the paper "Dismantling IClass".
//-----------------------------------------------------------------------------

#include "cipher.h"
#include "cipherutils.h"
#include "commonutil.h"
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>
#ifndef ON_DEVICE
#include "fileutils.h"
#endif


/**
* Definition 1 (Cipher state). A cipher state of iClass s is an element of F 40/2
* consisting of the following four components:
*   1. the left register l = (l 0 . . . l 7 ) ∈ F 8/2 ;
*   2. the right register r = (r 0 . . . r 7 ) ∈ F 8/2 ;
*   3. the top register t = (t 0 . . . t 15 ) ∈ F 16/2 .
*   4. the bottom register b = (b 0 . . . b 7 ) ∈ F 8/2 .
**/
typedef struct {
    uint8_t l;
    uint8_t r;
    uint8_t b;
    uint16_t t;
} State_t;

// Precomputed lookup table for the r-dependent part of select(x, y, r).
// z0 (bit2) depends only on r. z1 (bit1) = LUT_bit1 ^ x ^ y. z2 (bit0) = LUT_bit0 ^ x.
// Generated from the _select formula; x and y are folded in at call time.
static const uint8_t opt_select_LUT[256] = {
    00, 03, 02, 01, 02, 03, 00, 01, 04, 07, 07, 04, 06, 07, 05, 04,
    01, 02, 03, 00, 02, 03, 00, 01, 05, 06, 06, 05, 06, 07, 05, 04,
    06, 05, 04, 07, 04, 05, 06, 07, 06, 05, 05, 06, 04, 05, 07, 06,
    07, 04, 05, 06, 04, 05, 06, 07, 07, 04, 04, 07, 04, 05, 07, 06,
    06, 05, 04, 07, 04, 05, 06, 07, 02, 01, 01, 02, 00, 01, 03, 02,
    03, 00, 01, 02, 00, 01, 02, 03, 07, 04, 04, 07, 04, 05, 07, 06,
    00, 03, 02, 01, 02, 03, 00, 01, 00, 03, 03, 00, 02, 03, 01, 00,
    05, 06, 07, 04, 06, 07, 04, 05, 05, 06, 06, 05, 06, 07, 05, 04,
    02, 01, 00, 03, 00, 01, 02, 03, 06, 05, 05, 06, 04, 05, 07, 06,
    03, 00, 01, 02, 00, 01, 02, 03, 07, 04, 04, 07, 04, 05, 07, 06,
    02, 01, 00, 03, 00, 01, 02, 03, 02, 01, 01, 02, 00, 01, 03, 02,
    03, 00, 01, 02, 00, 01, 02, 03, 03, 00, 00, 03, 00, 01, 03, 02,
    04, 07, 06, 05, 06, 07, 04, 05, 00, 03, 03, 00, 02, 03, 01, 00,
    01, 02, 03, 00, 02, 03, 00, 01, 05, 06, 06, 05, 06, 07, 05, 04,
    04, 07, 06, 05, 06, 07, 04, 05, 04, 07, 07, 04, 06, 07, 05, 04,
    01, 02, 03, 00, 02, 03, 00, 01, 01, 02, 02, 01, 02, 03, 01, 00,
};

/**
*  Definition 4 (Successor state). Optimized in-place version.
*  T(t) computed via parallel XOR reduction on the masked t register.
*  B(b) computed via parallel XOR reduction on the b register.
*  select(x,y,r) resolved via opt_select_LUT with a single key lookup.
**/
static void successor(const uint8_t *k, State_t *s, uint8_t y) {
    // T(t) = x0^x1^x5^x7^x10^x11^x14^x15, mask selects those bits
    uint16_t Tt = s->t & 0xc533;
    Tt ^= Tt >> 1;
    Tt ^= Tt >> 4;
    Tt ^= Tt >> 10;
    Tt ^= Tt >> 8;
    // bit0 of Tt is now T(t)

    s->t = (s->t >> 1) | ((Tt ^ (s->r >> 7) ^ (s->r >> 3)) << 15);

    // B(b) = b1^b2^b3^b7; bit0 of opt_B = B(b) after the XOR reduction
    uint8_t opt_B = s->b ^ (s->b >> 6) ^ (s->b >> 5) ^ (s->b >> 4);
    s->b = (s->b >> 1) | ((opt_B ^ s->r) << 7);

    // select via LUT: z0 from LUT directly, z1/z2 fold in Tt and y
    uint8_t sel = opt_select_LUT[s->r] & 0x04;
    sel |= (opt_select_LUT[s->r] ^ ((Tt ^ y) << 1)) & 0x02;
    sel |= (opt_select_LUT[s->r] ^ Tt) & 0x01;

    uint8_t r = s->r;
    s->r = (k[sel] ^ s->b) + s->l;
    s->l = s->r + r;
}
/**
*  We define the successor function suc which takes a key k ∈ (F 82 ) 8 , a state s and
*  an input y ∈ F 2 and outputs the successor state s ′ . We overload the function suc
*  to multiple bit input x ∈ F n 2 which we define as
* @param k - array containing 8 bytes
**/
static State_t suc(uint8_t *k, State_t s, BitstreamIn_t *bitstream) {
    while (bitsLeft(bitstream) > 0) {
        successor(k, &s, headBit(bitstream));
    }
    return s;
}

/**
*  Definition 5 (Output). Define the function output which takes an internal
*  state s =< l, r, t, b > and returns the bit r 5 . We also define the function output
*  on multiple bits input which takes a key k, a state s and an input x ∈ F n 2 as
*  output(k, s, ǫ) = ǫ
*  output(k, s, x 0 . . . x n ) = output(s) · output(k, s ′ , x 1 . . . x n )
*  where s ′ = suc(k, s, x 0 ).
**/
static void output(uint8_t *k, State_t s, BitstreamIn_t *in, BitstreamOut_t *out) {
    while (bitsLeft(in) > 0) {
        pushBit(out, (s.r >> 2) & 1);
        successor(k, &s, headBit(in));
    }
}

/**
* Definition 6 (Initial state). Define the function init which takes as input a
* key k ∈ (F 82 ) 8 and outputs the initial cipher state s =< l, r, t, b >
**/

static State_t init(const uint8_t *k) {
    State_t s = {
        ((k[0] ^ 0x4c) + 0xEC) & 0xFF,// l
        ((k[0] ^ 0x4c) + 0x21) & 0xFF,// r
        0x4c, // b
        0xE012 // t
    };
    return s;
}

static void MAC(uint8_t *k, BitstreamIn_t input, BitstreamOut_t out) {
    uint8_t zeroes_32[] = {0, 0, 0, 0};
    BitstreamIn_t input_32_zeroes = {zeroes_32, sizeof(zeroes_32) * 8, 0};
    State_t initState = suc(k, init(k), &input);
    output(k, initState, &input_32_zeroes, &out);
}

void doMAC(uint8_t *cc_nr_p, uint8_t *div_key_p, uint8_t mac[4]) {
    uint8_t cc_nr[13] = { 0 };

    memcpy(cc_nr, cc_nr_p, 12);

    reverse_arraybytes(cc_nr, 12);
    BitstreamIn_t bitstream = {cc_nr, 12 * 8, 0};
    uint8_t dest [] = {0, 0, 0, 0, 0, 0, 0, 0};
    BitstreamOut_t out = { dest, sizeof(dest) * 8, 0 };
    MAC(div_key_p, bitstream, out);
    //The output MAC must also be reversed
    reverse_arraybytes(dest, sizeof(dest));
    memcpy(mac, dest, 4);
}

// Feeds `length` raw bytes into cipher state s, one bit at a time LSB-first.
// Equivalent to reflect8-then-MSB-first used by doMAC, with no intermediate buffer.
static void suc_bytes(const uint8_t *k, State_t *s, const uint8_t *in, int length) {
    for (int i = 0; i < length; i++) {
        uint8_t b = in[i];
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
        b >>= 1;
        successor(k, s, b);
    }
}

// Collects nbytes of cipher output into `out`, packing bits LSB-first per byte.
// Equivalent to output()+reflect8 used by doMAC, with no intermediate buffer or reversal.
static void output_bytes(const uint8_t *k, State_t *s, uint8_t *out, int nbytes) {
    for (int i = 0; i < nbytes; i++) {
        uint8_t bout = 0;
        bout |= (s->r & 0x4) >> 2;
        successor(k, s, 0);
        bout |= (s->r & 0x4) >> 1;
        successor(k, s, 0);
        bout |= (s->r & 0x4);
        successor(k, s, 0);
        bout |= (s->r & 0x4) << 1;
        successor(k, s, 0);
        bout |= (s->r & 0x4) << 2;
        successor(k, s, 0);
        bout |= (s->r & 0x4) << 3;
        successor(k, s, 0);
        bout |= (s->r & 0x4) << 4;
        successor(k, s, 0);
        bout |= (s->r & 0x4) << 5;
        successor(k, s, 0);
        out[i] = bout;
    }
}

// doMAC variant for the brute-force hot loop: takes raw (non-reflected) cc_nr and
// produces the same MAC as doMAC with no intermediate buffers, no reversal calls,
// and no bitstream overhead.
void doMAC_brute(const uint8_t *cc_nr, const uint8_t *div_key, uint8_t mac[4]) {
    State_t s = init(div_key);
    suc_bytes(div_key, &s, cc_nr, 12);
    output_bytes(div_key, &s, mac, 4);
}

void doMAC_N(uint8_t *address_data_p, uint8_t address_data_size, uint8_t *div_key_p, uint8_t mac[4]) {
    uint8_t *address_data;
    uint8_t div_key[8];
    address_data = (uint8_t *) calloc(address_data_size, sizeof(uint8_t));
    if (address_data == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return;
    }

    memcpy(address_data, address_data_p, address_data_size);
    memcpy(div_key, div_key_p, 8);

    reverse_arraybytes(address_data, address_data_size);
    BitstreamIn_t bitstream = {address_data, address_data_size * 8, 0};
    uint8_t dest [] = {0, 0, 0, 0, 0, 0, 0, 0};
    BitstreamOut_t out = { dest, sizeof(dest) * 8, 0 };
    MAC(div_key, bitstream, out);
    //The output MAC must also be reversed
    reverse_arraybytes(dest, sizeof(dest));
    memcpy(mac, dest, 4);
    free(address_data);
}

#ifndef ON_DEVICE
int testMAC(void) {
    PrintAndLogEx(SUCCESS, "Testing MAC calculation...");

    //From the "dismantling.IClass" paper:
    uint8_t cc_nr[] = {0xFE, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0, 0, 0, 0};
    //From the paper
    uint8_t div_key[8] = {0xE0, 0x33, 0xCA, 0x41, 0x9A, 0xEE, 0x43, 0xF9};
    uint8_t correct_MAC[4] = {0x1d, 0x49, 0xC9, 0xDA};

    uint8_t calculated_mac[4] = {0};
    doMAC(cc_nr, div_key, calculated_mac);

    if (memcmp(calculated_mac, correct_MAC, 4) == 0) {
        PrintAndLogEx(SUCCESS, "    MAC calculation ( %s )", _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "    MAC calculation ( %s )", _RED_("fail"));
        printarr("    Calculated_MAC", calculated_mac, 4);
        printarr("    Correct_MAC   ", correct_MAC, 4);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}
#endif
