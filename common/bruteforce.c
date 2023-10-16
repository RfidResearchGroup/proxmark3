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

smart_generator_t *smart_generators[] = {
    smart_generator_byte_repeat,
    NULL
};


void bf_generator_init(generator_context_t *ctx, uint8_t mode, uint8_t key_length) {
    memset(ctx, 0, sizeof(generator_context_t));
    ctx->mode = mode;
    ctx->key_length = key_length;
}

int bf_generator_set_charset(generator_context_t *ctx, uint8_t charsets) {
    if (ctx->mode != BF_MODE_CHARSET) {
        return -1;
    }

    if (charsets & BF_CHARSET_DIGITS) {
        memcpy(ctx->charset, charset_digits, sizeof(charset_digits));
        ctx->charset_length += sizeof(charset_digits);
    }

    if (charsets & BF_CHARSET_UPPERCASE) {
        memcpy(ctx->charset + ctx->charset_length, charset_uppercase, sizeof(charset_uppercase));
        ctx->charset_length += sizeof(charset_uppercase);
    }

    return 0;
}

int bf_generate(generator_context_t *ctx) {

    switch (ctx->mode) {
        case BF_MODE_RANGE:
            return _bf_generate_mode_range(ctx);
        case BF_MODE_CHARSET:
            return _bf_generate_mode_charset(ctx);

        case BF_MODE_SMART:
            return _bf_generate_mode_smart(ctx);
        }

    return BF_GENERATOR_ERROR;
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

// get current key casted to 32 bit
uint32_t bf_get_key32(generator_context_t *ctx){
    return ctx->current_key & 0xFFFFFFFF;
}

// get current key casted to 48 bit
uint64_t bf_get_key48(generator_context_t *ctx){
    return ctx->current_key & 0xFFFFFFFFFFFF;
}

void bf_generator_clear(generator_context_t *ctx){
    ctx->flag1 = 0;
    ctx->flag2 = 0;
    ctx->flag3 = 0;
    ctx->counter1 = 0;
    ctx->counter2 = 0;
}

int _bf_generate_mode_range(generator_context_t *ctx) {

    if (ctx->key_length != BF_KEY_SIZE_32 && ctx->key_length != BF_KEY_SIZE_48)
            return BF_GENERATOR_ERROR;

    if (ctx->current_key >= ctx->range_high) {
        return BF_GENERATOR_END;
    }

    // we use flag1 as indicator if value of range_low was already emitted
    // so the range generated is <range_low, range_high>
    if (ctx->current_key <= ctx->range_low && ctx->flag1 == false) {
        ctx->current_key = ctx->range_low;
        ctx->flag1 = true;
        return BF_GENERATOR_NEXT;
    }

    ctx->current_key++;
    return BF_GENERATOR_NEXT;
}

int _bf_generate_mode_charset(generator_context_t *ctx) {

    if (ctx->key_length != BF_KEY_SIZE_32 && ctx->key_length != BF_KEY_SIZE_48){
        return BF_GENERATOR_ERROR;
    }

    if (ctx->flag1)
        return BF_GENERATOR_END;

    uint8_t key_byte = 0;
    ctx->current_key = 0;

    for (key_byte = 0; key_byte < ctx->key_length; key_byte++)
    {
        ctx->current_key |=  (uint64_t) ctx->charset[ctx->pos[key_byte]] << ((ctx->key_length - key_byte - 1) * 8);
    }

    if (bf_array_increment(ctx->pos, ctx->key_length, ctx->charset_length) == -1)
        // set flag1 to emit value last time and end generation on next call
        ctx->flag1 = true;

    return BF_GENERATOR_NEXT;
}

int _bf_generate_mode_smart(generator_context_t *ctx){

    int ret;

    while(1){
        if (smart_generators[ctx->smart_mode_stage] == NULL)
        return BF_GENERATOR_END;

        ret = smart_generators[ctx->smart_mode_stage](ctx);

        switch (ret){
            case BF_GENERATOR_NEXT:
                return ret;
            case BF_GENERATOR_ERROR:
                return ret;
            case BF_GENERATOR_END:
                ctx->smart_mode_stage++;
                bf_generator_clear(ctx);
                continue;
        }
    }
}


int smart_generator_byte_repeat(generator_context_t *ctx){
    // key consists of repeated single byte
    uint32_t current_byte = ctx->counter1;

    if (current_byte > 0xFF)
        return BF_GENERATOR_END;

    ctx->current_key = 0;

    for (uint8_t key_byte = 0; key_byte < ctx->key_length;key_byte++){
        ctx->current_key |=  (uint64_t)current_byte << ((ctx->key_length - key_byte - 1) * 8);
    }

    ctx->counter1++;
    return BF_GENERATOR_NEXT;
}
int smart_generator_test2(generator_context_t *ctx){
    return 0;
}
