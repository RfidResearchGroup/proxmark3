//-----------------------------------------------------------------------------
// Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
// and Ronny Wichers Schreur. Radboud University Nijmegen
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
// SecureMemory, CryptoMemory and CryptoRF library
//-----------------------------------------------------------------------------

#include "cryptolib.h"
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

typedef enum {
    CA_ENCRYPT = 0x01,
    CA_DECRYPT = 0x02
} CryptoAction;

int counter = 0;

static uint8_t nibbles_to_byte(nibble b0, nibble b1) {
    // Combine both nibbles
    return ((b0 << 4) | b1);
}

static uint8_t funny_mod(uint8_t a, uint8_t m) {
    // Just return the input when this is less or equal than the modular value
    if (a < m) return a;

    // Compute the modular value
    a %= m;

    // Return the funny value, when the output was now zero, return the modular value
    return (a == 0) ? m : a;
}

static uint8_t bit_rotate_left(uint8_t a, uint8_t n_bits) {
    // Rotate value a with the length of n_bits only 1 time
    uint8_t mask = (1 << n_bits) - 1;
    return ((a << 1) | (a >> (n_bits - 1))) & mask;
}

/*
static void reconstruct_nibbles(crypto_state s)
{
  uint8_t b1, b5, b8, b15, b18;
  uint8_t b0, b4, b7, b14, b17;

  // Extract the bytes that generated the "previous" nibble
  b1 = (uint8_t)((s->l >> 25) & 0x1f);
  b5 = (uint8_t)((s->l >> 5) & 0x1f);
  b8 = (uint8_t)((s->m >> 35) & 0x1f);
  b15 = (uint8_t)((s->r >> 15) & 0x1f);
  b18 = (uint8_t)(s->r & 0x1f);

  // Reconstruct the b0 nibble
  s->b0 = ((b1 ^ b5) & 0x0f) & ~(b8);
  s->b0 |= ((b15 ^ b18) & 0x0f) & b8;

  // Extract the bytes for the current nibble
  b0 = (uint8_t)((s->l >> 30) & 0x1f);
  b4 = (uint8_t)((s->l >> 10) & 0x1f);
  b7 = (uint8_t)((s->m >> 42) & 0x1f);
  b14 = (uint8_t)((s->r >> 20) & 0x1f);
  b17 = (uint8_t)((s->r >> 5) & 0x1f);

  // Construct the values for b1 generation
  s->b1l = ((b0 ^ b4) & 0x0f);
  s->b1r = ((b14 ^ b17) & 0x0f);
  s->b1s = b7;

  // Reconstruct the b1 nibble
  s->b1 = s->b1l  & ~(s->b1s);
  s->b1 |= s->b1r &  s->b1s;
}
*/
static void next_left(uint8_t in, crypto_state s) {
    uint8_t b3, b6, bx;

    // Update the left cipher state with the input byte
    s->l ^= ((in & 0x1f) << 20);

    // Extract the two (5 bits) values used for modular addtion
    b3 = (uint8_t)((s->l >> 15) & 0x1f);
    b6 = (uint8_t)(s->l & 0x1f);

    // Compute the modular addition
    bx = funny_mod(b3 + bit_rotate_left(b6, 5), 0x1f);

    // Rotate the left cipher state 5 bits
    s->l = ((s->l >> 5) | ((uint64_t)bx << 30));

    // Save the 4 left output bits used for b1
    s->b1l = ((bx ^ b3) & 0x0f);
}

static void next_right(uint8_t in, crypto_state s) {
    uint8_t b16, b18, bx;

    // Update the right cipher state with the input byte
    s->r ^= ((in & 0xf8) << 12);

    // Extract the two (5 bits) values used for modular addtion
    b16 = (uint8_t)((s->r >> 10) & 0x1f);
    b18 = (uint8_t)(s->r & 0x1f);

    // Compute the modular addition
    bx = funny_mod(b18 + b16, 0x1f);

    // Rotate the right cipher state 5 bits
    s->r = ((s->r >> 5) | ((uint64_t)bx << 20));

    // Save the 4 right output bits used for b1
    s->b1r = ((bx ^ b16) & 0x0f);
}

static void next_middle(uint8_t in, crypto_state s) {
    uint8_t b12, b13, bx;

    // Update the middle cipher state with the input byte
    s->m ^= (((((uint64_t)in << 3) & 0x7f) | (in >> 5)) << 14);

    // Extract the two (7 bits) values used for modular addtion
    b12 = (uint8_t)((s->m >> 7) & 0x7f);
    b13 = (uint8_t)(s->m & 0x7f);

    // Compute the modular addition
    bx = (funny_mod(b12 + bit_rotate_left(b13, 7), 0x7f));

    // Rotate the middle cipher state 7 bits
    s->m = ((s->m >> 7) | ((uint64_t)bx << 42));

    // Save the 4 middle selector bits used for b1
    s->b1s = bx & 0x0f;
}

static void next(const bool feedback, uint8_t in, crypto_state s) {
    // Initialize the (optional) input parameter
    uint8_t a = in;

    // Only Cryptomemory uses feedback
    if (feedback) {
        // Construct the cipher update 'a' from (input ^ feedback)
        a = in ^ nibbles_to_byte(s->b0, s->b1);
    }

    // Shift the cipher state
    next_left(a, s);
    next_middle(a, s);
    next_right(a, s);

    // For active states we can use the available (previous) 'b1' nibble,
    // otherwise use reconstruct_nibbles() to generate them
    // reconstruct_nibbles(s)

    // The nible from b1 shifts to b0
    s->b0 = s->b1;

    // Construct the new value of nible b1
    s->b1 = s->b1l  & ~(s->b1s);
    s->b1 |= s->b1r &  s->b1s;
}

static void next_n(const bool feedback, size_t n, uint8_t in, crypto_state s) {
    // While n-rounds left, shift the cipher
    while (n--) next(feedback, in, s);
}

static void initialize(const bool feedback, const uint8_t *Gc, const uint8_t *Ci, const uint8_t *Q, const size_t n, crypto_state s) {
    size_t pos;

    // Reset the cipher state
    memset(s, 0x00, sizeof(crypto_state_t));

    // Load in the ci (tag-nonce), together with the first half of Q (reader-nonce)
    for (pos = 0; pos < 4; pos++) {
        next_n(feedback, n, Ci[2 * pos  ], s);
        next_n(feedback, n, Ci[2 * pos + 1], s);
        next(feedback, Q[pos], s);
    }

    // Load in the diversified key (Gc), together with the second half of Q (reader-nonce)
    for (pos = 0; pos < 4; pos++) {
        next_n(feedback, n, Gc[2 * pos  ], s);
        next_n(feedback, n, Gc[2 * pos + 1], s);
        next(feedback, Q[pos + 4], s);
    }
}

static uint8_t cm_byte(crypto_state s) {
    // Construct keystream byte by combining both nibbles
    return nibbles_to_byte(s->b0, s->b1);
}

static uint8_t sm_byte(crypto_state s) {
    uint8_t ks;

    // Construct keystream byte by combining 2 parts from 4 nibbles
    next_n(false, 2, 0, s);
    ks = s->b1 << 4;
    next_n(false, 2, 0, s);
    ks |= s->b1;

    return ks;
}

void print_crypto_state(const char *text, crypto_state s) {
    int pos;

    printf("%s", text);
    for (pos = 6; pos >= 0; pos--)
        printf(" %02x", (uint8_t)(s->l >> (pos * 5)) & 0x1f);

    printf(" |");
    for (pos = 6; pos >= 0; pos--)
        printf(" %02x", (uint8_t)(s->m >> (pos * 7)) & 0x7f);

    printf(" |");
    for (pos = 4; pos >= 0; pos--)
        printf(" %02x", (uint8_t)(s->r >> (pos * 5)) & 0x1f);

    printf(" | %02x", cm_byte(s));
    printf("\n");
}

void sm_auth(const uint8_t *Gc, const uint8_t *Ci, const uint8_t *Q, uint8_t *Ch, uint8_t *Ci_1, crypto_state s) {
    size_t pos;

    initialize(false, Gc, Ci, Q, 1, s);

    // Generate challenge answer for Tag and Reader
    for (pos = 0; pos < 8; pos++) {
        Ci_1[pos] = sm_byte(s);
        Ch[pos] = sm_byte(s);
    }
}

void cm_auth(const uint8_t *Gc, const uint8_t *Ci, const uint8_t *Q, uint8_t *Ch, uint8_t *Ci_1, uint8_t *Ci_2, crypto_state s) {
    size_t pos;

    initialize(true, Gc, Ci, Q, 3, s);

    // Construct the reader-answer (challenge)
    next_n(true, 6, 0, s);
    Ch[0] = cm_byte(s);
    for (pos = 1; pos < 8; pos++) {
        next_n(true, 7, 0, s);
        Ch [pos] = cm_byte(s);
    }

    // Construct the tag-answer (Ci+1 = ff .. .. .. .. .. .. ..)
    Ci_1[0] = 0xff;
    for (pos = 1; pos < 8; pos++) {
        next_n(true, 2, 0, s);
        Ci_1[pos] = cm_byte(s);
    }

    // Construct the session key (Ci+2)
    for (pos = 0; pos < 8; pos++) {
        next_n(true, 2, 0, s);
        Ci_2[pos] = cm_byte(s);
    }

    // Prepare the cipher for encryption by shifting 3 more times
    next_n(true, 3, 0, s);
}

static void cm_crypt(const CryptoAction ca, const uint8_t offset, const uint8_t len, const uint8_t *in, uint8_t *out, crypto_state s) {
    size_t pos;

    next_n(true, 5, 0, s);
    next(true, offset, s);
    next_n(true, 5, 0, s);
    next(true, len, s);
    for (pos = 0; pos < len; pos++) {
        // Perform the crypto operation
        uint8_t bt = in[pos] ^ cm_byte(s);

        // Generate output
        if (out) out[pos] = bt;

        // Detect where to find the plaintext for loading into cipher state
        if (ca == CA_DECRYPT) {
            next(true, bt, s);
        } else {
            next(true, in[pos], s);
        }

        // Shift the cipher state 5 times
        next_n(true, 5, 0, s);
    }
}

void cm_encrypt(const uint8_t offset, const uint8_t len, const uint8_t *pt, uint8_t *ct, crypto_state s) {
    next_n(true, 5, 0, s);
    next(true, 0, s);
    cm_crypt(CA_ENCRYPT, offset, len, pt, ct, s);
}

void cm_decrypt(const uint8_t offset, const uint8_t len, const uint8_t *ct, uint8_t *pt, crypto_state s) {
    next_n(true, 5, 0, s);
    next(true, 0, s);
    cm_crypt(CA_DECRYPT, offset, len, ct, pt, s);
}

void cm_grind_read_system_zone(const uint8_t offset, const uint8_t len, const uint8_t *pt, crypto_state s) {
    cm_crypt(CA_ENCRYPT, offset, len, pt, NULL, s);
}

void cm_grind_set_user_zone(const uint8_t zone, crypto_state s) {
    next(true, zone, s);
}

void cm_mac(uint8_t *mac, crypto_state s) {
    next_n(true, 10, 0, s);
    if (mac)
        mac[0] = cm_byte(s);

    next_n(true, 5, 0, s);
    if (mac)
        mac[1] = cm_byte(s);
}

void cm_password(const uint8_t *pt, uint8_t *ct, crypto_state s) {
    for (size_t pos = 0; pos < 3; pos++) {
        next_n(true, 5, pt[pos], s);
        ct[pos] = cm_byte(s);
    }
}

