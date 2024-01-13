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
// Hitag2 Crypto
//-----------------------------------------------------------------------------
#include "hitag2_crypto.h"

#include "util.h"
#include "string.h"

/* Following is a modified version of cryptolib.com/ciphers/hitag2/ */
// Software optimized 48-bit Philips/NXP Mifare Hitag2 PCF7936/46/47/52 stream cipher algorithm by I.C. Wiener 2006-2007.
// For educational purposes only.
// No warranties or guarantees of any kind.
// This code is released into the public domain by its author.

// Single bit Hitag2 functions:
#ifndef i4
#define i4(x,a,b,c,d)    ((uint32_t)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))
#endif

static const uint32_t ht2_f4a = 0x2C79;     // 0010 1100 0111 1001
static const uint32_t ht2_f4b = 0x6671;     // 0110 0110 0111 0001
static const uint32_t ht2_f5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011

uint32_t _f20(const uint64_t x) {
    uint32_t i5;

    i5 = ((ht2_f4a >> i4(x, 1, 2, 4, 5)) & 1) * 1
         + ((ht2_f4b >> i4(x, 7, 11, 13, 14)) & 1) * 2
         + ((ht2_f4b >> i4(x, 16, 20, 22, 25)) & 1) * 4
         + ((ht2_f4b >> i4(x, 27, 28, 30, 32)) & 1) * 8
         + ((ht2_f4a >> i4(x, 33, 42, 43, 45)) & 1) * 16;

    return (ht2_f5c >> i5) & 1;
}

uint64_t _hitag2_init(const uint64_t key, const uint32_t serial, const uint32_t IV) {
    uint32_t i;
    uint64_t x = ((key & 0xFFFF) << 32) + serial;

    for (i = 0; i < 32; i++) {
        x >>= 1;
        x += (uint64_t)(_f20(x) ^ (((IV >> i) ^ (key >> (i + 16))) & 1)) << 47;
    }
    return x;
}

uint64_t _hitag2_round(uint64_t *state) {
    uint64_t x = *state;

    x = (x >>  1) +
        ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
           ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
           ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
           ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);

    *state = x;
    return _f20(x);
}

// "MIKRON"             =  O  N  M  I  K  R
// Key                  = 4F 4E 4D 49 4B 52             - Secret 48-bit key
// Serial               = 49 43 57 69                   - Serial number of the tag, transmitted in clear
// Random               = 65 6E 45 72                   - Random IV, transmitted in clear
//~28~DC~80~31  = D7 23 7F CE                   - Authenticator value = inverted first 4 bytes of the keystream

// The code below must print out "D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6".
// The inverse of the first 4 bytes is sent to the tag to authenticate.
// The rest is encrypted by XORing it with the subsequent keystream.

uint32_t _hitag2_byte(uint64_t *x) {
    uint32_t i, c;
    for (i = 0, c = 0; i < 8; i++) {
        c += (uint32_t) _hitag2_round(x) << (i ^ 7);
    }
    return c;
}

void hitag2_cipher_reset(struct hitag2_tag *tag, const uint8_t *iv) {
    uint64_t key = ((uint64_t)tag->sectors[2][2]) |
                   ((uint64_t)tag->sectors[2][3] <<  8) |
                   ((uint64_t)tag->sectors[1][0] << 16) |
                   ((uint64_t)tag->sectors[1][1] << 24) |
                   ((uint64_t)tag->sectors[1][2] << 32) |
                   ((uint64_t)tag->sectors[1][3] << 40);
    uint32_t uid = ((uint32_t)tag->sectors[0][0]) |
                   ((uint32_t)tag->sectors[0][1] <<  8) |
                   ((uint32_t)tag->sectors[0][2] << 16) |
                   ((uint32_t)tag->sectors[0][3] << 24);
    uint32_t iv_ = (((uint32_t)(iv[0]))) |
                   (((uint32_t)(iv[1])) <<  8) |
                   (((uint32_t)(iv[2])) << 16) |
                   (((uint32_t)(iv[3])) << 24);
    tag->cs = _hitag2_init(REV64(key), REV32(uid), REV32(iv_));
}

int hitag2_cipher_authenticate(uint64_t *cs, const uint8_t *authenticator_is) {
    uint8_t authenticator_should[4];
    authenticator_should[0] = ~_hitag2_byte(cs);
    authenticator_should[1] = ~_hitag2_byte(cs);
    authenticator_should[2] = ~_hitag2_byte(cs);
    authenticator_should[3] = ~_hitag2_byte(cs);
    return (memcmp(authenticator_should, authenticator_is, 4) == 0);
}

int hitag2_cipher_transcrypt(uint64_t *cs, uint8_t *data, uint16_t bytes, uint16_t bits) {
    int i;
    for (i = 0; i < bytes; i++) data[i] ^= _hitag2_byte(cs);
    for (i = 0; i < bits; i++) data[bytes] ^= _hitag2_round(cs) << (7 - i);
    return 0;
}

