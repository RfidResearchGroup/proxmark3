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
// functions for bruteforcing card keys - key generators
//-----------------------------------------------------------------------------

#ifndef BRUTEFORCE_H__
#define BRUTEFORCE_H__

#include "common.h"

#define BF_KEY_SIZE_32 4
#define BF_KEY_SIZE_48 6

// bruteforcing all keys sequentially between X and Y
#define BF_MODE_RANGE 1

// try keys based on limited charset/passphrases
// some payment systems use user-provided passphrase as system key
#define BF_MODE_CHARSET 2

// "smart" mode - try some predictable patterns
#define BF_MODE_SMART 3


// bit flags - can be used together using logical OR
#define BF_CHARSET_DIGITS 1
#define BF_CHARSET_UPPERCASE 2

#define BF_GENERATOR_END 0
#define BF_GENERATOR_NEXT 1
#define BF_GENERATOR_ERROR 2

#define BF_CHARSET_DIGITS_SIZE 10
#define BF_CHARSET_UPPERCASE_SIZE 25

extern uint8_t charset_digits[];
extern uint8_t charset_uppercase[];

typedef uint8_t bruteforce_charset_t;
typedef uint8_t bruteforce_mode_t;

// structure to hold key generator temporary data
typedef struct {
    // position of each of bytes in charset mode - used to iterate over alphabets
    // add more bytes to support larger keys
    // pos[0] is most significant byte - all maths avoid relying on little/big endian memory layout
    uint8_t pos[6]; // max supported key is now 48 bit

    uint8_t key_length; // bytes
    uint64_t current_key; // Use 64 bit and truncate when needed.
    uint8_t mode;
    uint8_t charset[
     BF_CHARSET_DIGITS_SIZE
     + BF_CHARSET_UPPERCASE_SIZE
    ];
    uint8_t charset_length;

    uint32_t range_low;
    uint32_t range_high;
    uint16_t smart_mode_stage;
    // flags to use internally by generators as they wish
    bool flag1, flag2, flag3;
    // counters to use internally by generators as they wish
    uint32_t counter1, counter2;

} generator_context_t;


void bf_generator_init(generator_context_t *ctx, uint8_t mode, uint8_t key_size);
void bf_generator_clear(generator_context_t *ctx); // clear flags and counters used by generators
int bf_generator_set_charset(generator_context_t *ctx, uint8_t charsets);
int bf_generate(generator_context_t *ctx);
int _bf_generate_mode_range(generator_context_t *ctx);
int _bf_generate_mode_charset(generator_context_t *ctx);
int _bf_generate_mode_smart(generator_context_t *ctx);
int bf_array_increment(uint8_t *data, uint8_t data_len, uint8_t modulo);
uint32_t bf_get_key32(generator_context_t *ctx);
uint64_t bf_get_key48(generator_context_t *ctx);

// smart mode
typedef int (smart_generator_t)(generator_context_t *ctx);

int bf_generate_mode_smart(generator_context_t *ctx);

int smart_generator_byte_repeat(generator_context_t *ctx);
int smart_generator_msb_byte_only(generator_context_t *ctx);
int smart_generator_nibble_sequence(generator_context_t *ctx);

extern smart_generator_t *smart_generators[]; // array of smart cracking functions

#endif // BRUTEFORCE_H__
