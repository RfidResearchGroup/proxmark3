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

/**
*  Definition 2. The feedback function for the top register T : F 16/2 → F 2
*  is defined as
*  T (x 0 x 1 . . . . . . x 15 ) = x 0 ⊕ x 1 ⊕ x 5 ⊕ x 7 ⊕ x 10 ⊕ x 11 ⊕ x 14 ⊕ x 15 .
**/
static bool T(State_t state) {
    /*
        bool x0 = state.t & 0x8000;
        bool x1 = state.t & 0x4000;
        bool x5 = state.t & 0x0400;
        bool x7 = state.t & 0x0100;
        bool x10 = state.t & 0x0020;
        bool x11 = state.t & 0x0010;
        bool x14 = state.t & 0x0002;
        bool x15 = state.t & 0x0001;
        return x0 ^ x1 ^ x5 ^ x7 ^ x10 ^ x11 ^ x14 ^ x15;
    */
#define  _x0  ((state.t & 0x8000) >> 15 )
#define  _x1  ((state.t & 0x4000) >> 14 )
#define  _x5  ((state.t & 0x0400) >> 10 )
#define  _x7  ((state.t & 0x0100) >> 8 )
#define  _x10 ((state.t & 0x0020) >> 5 )
#define  _x11 ((state.t & 0x0010) >> 4 )
#define  _x14 ((state.t & 0x0002) >> 1 )
#define  _x15 (state.t & 0x0001)
    return (_x0) ^ (_x1) ^ (_x5) ^ (_x7) ^ (_x10) ^ (_x11) ^ (_x14) ^ (_x15);
}
/**
*  Similarly, the feedback function for the bottom register B : F 8/2 → F 2 is defined as
*  B(x 0 x 1 . . . x 7 ) = x 1 ⊕ x 2 ⊕ x 3 ⊕ x 7 .
**/
/*static bool B(State_t state) {
    bool x1 = state.b & 0x40;
    bool x2 = state.b & 0x20;
    bool x3 = state.b & 0x10;
    bool x7 = state.b & 0x01;
    return x1 ^ x2 ^ x3 ^ x7;
}
*/
#define B(x) (((x.b & 0x40) >> 6)  ^ ((x.b & 0x20) >> 5) ^ ((x.b & 0x10) >> 4) ^ (x.b & 0x01))

//   12 3456
// 0100 0000

/**
*  Definition 3 (Selection function). The selection function select : F 2 × F 2 ×
*  F 8/2 → F 3/2 is defined as select(x, y, r) = z 0 z 1 z 2 where
*  z 0 = (r 0 ∧ r 2 ) ⊕ (r 1 ∧ r 3 ) ⊕ (r 2 ∨ r 4 )
*  z 1 = (r 0 ∨ r 2 ) ⊕ (r 5 ∨ r 7 ) ⊕ r 1 ⊕ r 6 ⊕ x ⊕ y
*  z 2 = (r 3 ∧ r 5 ) ⊕ (r 4 ∧ r 6 ) ⊕ r 7 ⊕ x
**/
static uint8_t _select(bool x, bool y, uint8_t r) {
#define _r0 ((r >> 7) & 0x01)
#define _r1 ((r >> 6) & 0x01)
#define _r2 ((r >> 5) & 0x01)
#define _r3 ((r >> 4) & 0x01)
#define _r4 ((r >> 3) & 0x01)
#define _r5 ((r >> 2) & 0x01)
#define _r6 ((r >> 1) & 0x01)
#define _r7 (r & 0x01)

#define _z0  ( (_r0 & _r2) ^ ( _r1 & (!_r3)) ^ (_r2 | _r4) )
#define _z1  ( (_r0 | _r2) ^ ( _r5 | _r7) ^_r1 ^ _r6 ^ (x) ^ (y) )
#define _z2  ( (_r3 & (!_r5)) ^ (_r4 & _r6) ^ _r7 ^ (x) )

    /*
        uint8_t r0 = r >> 7 & 0x1;
        uint8_t r1 = r >> 6 & 0x1;
        uint8_t r2 = r >> 5 & 0x1;
        uint8_t r3 = r >> 4 & 0x1;
        uint8_t r4 = r >> 3 & 0x1;
        uint8_t r5 = r >> 2 & 0x1;
        uint8_t r6 = r >> 1 & 0x1;
        uint8_t r7 = r & 0x1;

        bool z0 = (r0 & r2) ^ (r1 & (!r3)) ^ (r2 | r4);
        bool z1 = (r0 | r2) ^ (r5 | r7) ^ r1 ^ r6 ^ x ^ y;
        bool z2 = (r3 & (!r5)) ^ (r4 & r6) ^ r7 ^ x;

        // The three bitz z0.. z1 are packed into a uint8_t:
        // 00000ZZZ
        //Return value is a uint8_t
        return ((z0 << 2) & 4) | ((z1 << 1) & 2) | (z2 & 1);
    */
    return ((_z0 << 2) & 4) | ((_z1 << 1) & 2) | (_z2 & 1);

    /*
        uint8_t retval = 0;
        retval |= (z0 << 2) & 4;
        retval |= (z1 << 1) & 2;
        retval |= (z2) & 1;

        // Return value 0 <= retval <= 7
        return retval;
    */
}

/**
*  Definition 4 (Successor state). Let s = l, r, t, b be a cipher state, k ∈ (F 82 ) 8
*  be a key and y ∈ F 2 be the input bit. Then, the successor cipher state s ′ =
*  l ′ , r ′ , t ′ , b ′ is defined as
*  t ′ := (T (t) ⊕ r 0 ⊕ r 4 )t 0 . . . t 14 l ′ := (k [select(T (t),y,r)] ⊕ b ′ ) ⊞ l ⊞ r
*  b ′ := (B(b) ⊕ r 7 )b 0 . . . b 6 r ′ := (k [select(T (t),y,r)] ⊕ b ′ ) ⊞ l
*
* @param s - state
* @param k - array containing 8 bytes
**/
static State_t successor(const uint8_t *k, State_t s, bool y) {
    bool r0 = s.r >> 7 & 0x1;
    bool r4 = s.r >> 3 & 0x1;
    bool r7 = s.r & 0x1;

    State_t successor = {0, 0, 0, 0};

    successor.t = s.t >> 1;
    successor.t |= ((T(s)) ^ (r0) ^ (r4)) << 15;

    successor.b = s.b >> 1;
    successor.b |= ((B(s)) ^ (r7)) << 7;

    bool Tt = T(s);

    successor.l = ((k[_select(Tt, y, s.r)] ^ successor.b) + s.l + s.r) & 0xFF;
    successor.r = ((k[_select(Tt, y, s.r)] ^ successor.b) + s.l) & 0xFF;

    return successor;
}
/**
*  We define the successor function suc which takes a key k ∈ (F 82 ) 8 , a state s and
*  an input y ∈ F 2 and outputs the successor state s ′ . We overload the function suc
*  to multiple bit input x ∈ F n 2 which we define as
* @param k - array containing 8 bytes
**/
static State_t suc(uint8_t *k, State_t s, BitstreamIn_t *bitstream) {
    if (bitsLeft(bitstream) == 0) {
        return s;
    }
    bool lastbit = tailBit(bitstream);
    return successor(k, suc(k, s, bitstream), lastbit);
}

/**
*  Definition 5 (Output). Define the function output which takes an internal
*  state s =< l, r, t, b > and returns the bit r 5 . We also define the function output
*  on multiple bits input which takes a key k, a state s and an input x ∈ F n 2 as
*  output(k, s, ǫ) = ǫ
*  output(k, s, x 0 . . . x n ) = output(s) · output(k, s ′ , x 1 . . . x n )
*  where s ′ = suc(k, s, x 0 ).
**/
static void output(uint8_t *k, State_t s, BitstreamIn_t *in,  BitstreamOut_t *out) {
    if (bitsLeft(in) == 0) {
        return;
    }
    pushBit(out, (s.r >> 2) & 1);
    //Remove first bit
    uint8_t x0 = headBit(in);
    State_t ss = successor(k, s, x0);
    output(k, ss, in, out);
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
    uint8_t div_key[8];

    memcpy(cc_nr, cc_nr_p, 12);
    memcpy(div_key, div_key_p, 8);

    reverse_arraybytes(cc_nr, 12);
    BitstreamIn_t bitstream = {cc_nr, 12 * 8, 0};
    uint8_t dest [] = {0, 0, 0, 0, 0, 0, 0, 0};
    BitstreamOut_t out = { dest, sizeof(dest) * 8, 0 };
    MAC(div_key, bitstream, out);
    //The output MAC must also be reversed
    reverse_arraybytes(dest, sizeof(dest));
    memcpy(mac, dest, 4);
}

void doMAC_N(uint8_t *address_data_p, uint8_t address_data_size, uint8_t *div_key_p, uint8_t mac[4]) {
    uint8_t *address_data;
    uint8_t div_key[8];
    address_data = (uint8_t *) calloc(address_data_size, sizeof(uint8_t));

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
