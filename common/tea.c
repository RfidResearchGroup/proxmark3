//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Generic TEA crypto code.
// ref: http://143.53.36.235:8080/source.htm#ansi
//-----------------------------------------------------------------------------
#include "tea.h"
#define ROUNDS 32
#define DELTA  0x9E3779B9
#define SUM    0xC6EF3720

void tea_encrypt(uint8_t *v, uint8_t *key) {

    uint32_t a = 0, b = 0, c = 0, d = 0, y = 0, z = 0;
    uint32_t sum = 0;
    uint8_t n = ROUNDS;

    //key
    a = bytes_to_num(key, 4);
    b = bytes_to_num(key + 4, 4);
    c = bytes_to_num(key + 8, 4);
    d = bytes_to_num(key + 12, 4);

    //input
    y = bytes_to_num(v, 4);
    z = bytes_to_num(v + 4, 4);

    while (n-- > 0) {
        sum += DELTA;
        y += ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        z += ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
    }

    num_to_bytes(y, 4, v);
    num_to_bytes(z, 4, v + 4);
}

void tea_decrypt(uint8_t *v, uint8_t *key) {

    uint32_t a = 0, b = 0, c = 0, d = 0, y = 0, z = 0;
    uint32_t sum = SUM;
    uint8_t n = ROUNDS;

    //key
    a = bytes_to_num(key, 4);
    b = bytes_to_num(key + 4, 4);
    c = bytes_to_num(key + 8, 4);
    d = bytes_to_num(key + 12, 4);

    //input
    y = bytes_to_num(v, 4);
    z = bytes_to_num(v + 4, 4);

    /* sum = delta<<5, in general sum = delta * n */
    while (n-- > 0) {
        z -= ((y << 4) + c) ^ (y + sum) ^ ((y >> 5) + d);
        y -= ((z << 4) + a) ^ (z + sum) ^ ((z >> 5) + b);
        sum -= DELTA;
    }
    num_to_bytes(y, 4, v);
    num_to_bytes(z, 4, v + 4);
}
