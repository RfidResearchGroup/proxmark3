/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2024 by Henry Gabryjelski
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */
//-----------------------------------------------------------------------------
// NOTE: This file describes internal details used by the ID48 library.
//       Changes to this file are unannounced, and may break any code that
//       is relying on it.  Nothing in this file is considered part of the
//       public API.
//       The public API can be found in id48.h
//-----------------------------------------------------------------------------

#if !defined(ID48_INTERNALS_H__)
#define ID48_INTERNALS_H__

#include "id48.h"

typedef struct _ID48LIBX_STATE_REGISTERS {
    uint64_t Raw;
} ID48LIBX_STATE_REGISTERS;

typedef struct _ID48LIBX_SUCCESSOR_RESULT {
    ID48LIBX_STATE_REGISTERS state;
    bool output;
} ID48LIBX_SUCCESSOR_RESULT;

// the following are used in key recovery but implemented in id48.c
ID48LIBX_SUCCESSOR_RESULT id48libx_retro003_successor(const ID48LIBX_STATE_REGISTERS *initial_state, uint8_t input_bit);
ID48LIBX_STATE_REGISTERS  id48libx_retro003_init(const ID48LIB_KEY *key, const ID48LIB_NONCE *nonce);

bool id48libx_output_lookup(uint32_t output_index);

#endif // !defined(ID48_INTERNALS_H__)
