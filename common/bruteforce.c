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

#include "bruteforce.h"
#include <string.h>
#include <stdio.h>

uint8_t charset_digits[] = {
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9',
};

uint8_t charset_uppercase[] = {
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K',
    'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'W',
    'X', 'Y', 'Z'
};

void bf_generator_init(generator_context_t *ctx, uint8_t mode) {
    memset(ctx, 0, sizeof(generator_context_t));
    ctx->mode = mode;
}

int bf_generator_set_charset(generator_context_t *ctx, uint8_t charsets) {
    if (ctx->mode != BRUTEFORCE_MODE_CHARSET) {
        return -1;
    }

    if (charsets & CHARSET_DIGITS) {
        memcpy(ctx->charset, charset_digits, sizeof(charset_digits));
        ctx->charset_length += sizeof(charset_digits);
    }

    if (charsets & CHARSET_UPPERCASE) {
        memcpy(ctx->charset + ctx->charset_length, charset_uppercase, sizeof(charset_uppercase));
        ctx->charset_length += sizeof(charset_uppercase);
    }

    return 0;
}

int bf_generate32(generator_context_t *ctx) {

    switch (ctx->mode) {
        case BRUTEFORCE_MODE_RANGE:
            return _bf_generate_mode_range32(ctx);
        case BRUTEFORCE_MODE_CHARSET:
            return _bf_generate_mode_charset32(ctx);
    }

    return GENERATOR_ERROR;
}

int _bf_generate_mode_range32(generator_context_t *ctx) {

    if (ctx->current_key32 >= ctx->range_high) {
        return GENERATOR_END;
    }

    // we use flag1 as indicator if value of range_low was already emitted
    // so the range generated is <range_low, range_high>
    if (ctx->current_key32 <= ctx->range_low && ctx->flag1 == false) {
        ctx->current_key32 = ctx->range_low;
        ctx->pos[0] = true;
        return GENERATOR_NEXT;
    }

    ctx->current_key32++;
    return GENERATOR_NEXT;
}

int _bf_generate_mode_charset32(generator_context_t *ctx) {

    if (ctx->flag1)
        return GENERATOR_END;

    ctx->current_key32 = ctx->charset[ctx->pos[0]] << 24 | ctx->charset[ctx->pos[1]] << 16 |
                         ctx->charset[ctx->pos[2]] << 8 | ctx->charset[ctx->pos[3]];


    if (bf_array_increment(ctx->pos, 4, ctx->charset_length) == -1)
        // set flag1 to emit value last time and end generation
        ctx->flag1 = true;

    return GENERATOR_NEXT;
}

// increments values in array with carryover using modulo limit for each byte
// this is used to iterate each byte in key over charset table
// returns -1 if incrementing reaches its end
int bf_array_increment(uint8_t *data, uint8_t data_len, uint8_t modulo) {

    uint8_t prev_value;

    // check if we reached max value already
    uint8_t i;
    for (i = 0; i < data_len; i++)
        if (data[i] < modulo - 1)
            break;

    if (i == data_len)
        return -1;

    for (uint8_t pos = data_len - 1;; pos--) {
        prev_value = ++data[pos];
        data[pos] = data[pos] % modulo;
        if (prev_value == data[pos])
            return 0;
        else if (pos == 0) {
            // we cannot carryover to next byte
            // with the max value check in place before, we should not reach this place
            return -1;
        }
    }

    return 0;
}
