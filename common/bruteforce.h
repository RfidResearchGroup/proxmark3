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

typedef uint8_t bruteforce_mode_t;
// bruteforcing all keys sequentially between X and Y
#define BRUTEFORCE_MODE_RANGE 1

// try keys based on limited charset/passphrases
// some payment systems use user-provided passphrase as system key
#define BRUTEFORCE_MODE_CHARSET 2

// "smart" mode - try some predictable patterns
#define BRUTEFORCE_MODE_SMART 3


typedef uint8_t bruteforce_charset_t;
// bit flags - can be used together using logical OR
#define CHARSET_DIGITS 1
#define CHARSET_UPPERCASE 2

#define GENERATOR_END 0
#define GENERATOR_NEXT 1
#define GENERATOR_ERROR 2

#define CHARSET_DIGITS_SIZE 10
#define CHARSET_UPPERCASE_SIZE 25

extern uint8_t charset_digits[];
extern uint8_t charset_uppercase[];

// structure to hold key generator temporary data
typedef struct {
    // position of each of 4 bytes in 32 bit key in charset mode
    // add more bytes to support larger keys
    // pos[0] is most significant byte - all maths avoid relying on little/big endian memory layout
    uint8_t pos[4];
    uint32_t current_key32;
    uint8_t mode;
    uint8_t charset[
     CHARSET_DIGITS_SIZE
     + CHARSET_UPPERCASE_SIZE
    ];
    uint8_t charset_length;

    uint32_t range_low;
    uint32_t range_high;
    // flags to use internally by generators as they wish
    bool flag1, flag2, flag3;

} generator_context_t;

void bf_generator_init(generator_context_t *ctx, uint8_t mode);
int bf_generator_set_charset(generator_context_t *ctx, uint8_t charsets);
int bf_generate32(generator_context_t *ctx);
int _bf_generate_mode_range32(generator_context_t *ctx);
int _bf_generate_mode_charset32(generator_context_t *ctx);
int _bf_generate_mode_smart32(generator_context_t *ctx);
int bf_array_increment(uint8_t *data, uint8_t data_len, uint8_t modulo);
#endif // BRUTEFORCE_H__
