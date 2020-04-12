/*-
 * Copyright (C) 2010, Romain Tartiere.
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * NIST Special Publication 800-38B
 * Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
 * May 2005
 */
#include "desfire_crypto.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include "commonutil.h"
#include "crc32.h"
#include "mbedtls/aes.h"
//#include "mbedtls/des.h"
#include "ui.h"
#include "crc.h"
#include "crc16.h"        // crc16 ccitt

const uint8_t sbox[256]  = {
        /* S-box 1 */
        0xE4, 0xD1, 0x2F, 0xB8, 0x3A, 0x6C, 0x59, 0x07,
        0x0F, 0x74, 0xE2, 0xD1, 0xA6, 0xCB, 0x95, 0x38,
        0x41, 0xE8, 0xD6, 0x2B, 0xFC, 0x97, 0x3A, 0x50,
        0xFC, 0x82, 0x49, 0x17, 0x5B, 0x3E, 0xA0, 0x6D,
        /* S-box 2 */
        0xF1, 0x8E, 0x6B, 0x34, 0x97, 0x2D, 0xC0, 0x5A,
        0x3D, 0x47, 0xF2, 0x8E, 0xC0, 0x1A, 0x69, 0xB5,
        0x0E, 0x7B, 0xA4, 0xD1, 0x58, 0xC6, 0x93, 0x2F,
        0xD8, 0xA1, 0x3F, 0x42, 0xB6, 0x7C, 0x05, 0xE9,
        /* S-box 3 */
        0xA0, 0x9E, 0x63, 0xF5, 0x1D, 0xC7, 0xB4, 0x28,
        0xD7, 0x09, 0x34, 0x6A, 0x28, 0x5E, 0xCB, 0xF1,
        0xD6, 0x49, 0x8F, 0x30, 0xB1, 0x2C, 0x5A, 0xE7,
        0x1A, 0xD0, 0x69, 0x87, 0x4F, 0xE3, 0xB5, 0x2C,
        /* S-box 4 */
        0x7D, 0xE3, 0x06, 0x9A, 0x12, 0x85, 0xBC, 0x4F,
        0xD8, 0xB5, 0x6F, 0x03, 0x47, 0x2C, 0x1A, 0xE9,
        0xA6, 0x90, 0xCB, 0x7D, 0xF1, 0x3E, 0x52, 0x84,
        0x3F, 0x06, 0xA1, 0xD8, 0x94, 0x5B, 0xC7, 0x2E,
        /* S-box 5 */
        0x2C, 0x41, 0x7A, 0xB6, 0x85, 0x3F, 0xD0, 0xE9,
        0xEB, 0x2C, 0x47, 0xD1, 0x50, 0xFA, 0x39, 0x86,
        0x42, 0x1B, 0xAD, 0x78, 0xF9, 0xC5, 0x63, 0x0E,
        0xB8, 0xC7, 0x1E, 0x2D, 0x6F, 0x09, 0xA4, 0x53,
        /* S-box 6 */
        0xC1, 0xAF, 0x92, 0x68, 0x0D, 0x34, 0xE7, 0x5B,
        0xAF, 0x42, 0x7C, 0x95, 0x61, 0xDE, 0x0B, 0x38,
        0x9E, 0xF5, 0x28, 0xC3, 0x70, 0x4A, 0x1D, 0xB6,
        0x43, 0x2C, 0x95, 0xFA, 0xBE, 0x17, 0x60, 0x8D,
        /* S-box 7 */
        0x4B, 0x2E, 0xF0, 0x8D, 0x3C, 0x97, 0x5A, 0x61,
        0xD0, 0xB7, 0x49, 0x1A, 0xE3, 0x5C, 0x2F, 0x86,
        0x14, 0xBD, 0xC3, 0x7E, 0xAF, 0x68, 0x05, 0x92,
        0x6B, 0xD8, 0x14, 0xA7, 0x95, 0x0F, 0xE2, 0x3C,
        /* S-box 8 */
        0xD2, 0x84, 0x6F, 0xB1, 0xA9, 0x3E, 0x50, 0xC7,
        0x1F, 0xD8, 0xA3, 0x74, 0xC5, 0x6B, 0x0E, 0x92,
        0x7B, 0x41, 0x9C, 0xE2, 0x06, 0xAD, 0xF3, 0x58,
        0x21, 0xE7, 0x4A, 0x8D, 0xFC, 0x90, 0x35, 0x6B
};

const uint8_t e_permtab[] = {
        4,  6,                     /* 4 bytes in 6 bytes out*/
        32,  1,  2,  3,  4,  5,
        4,  5,  6,  7,  8,  9,
        8,  9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32,  1
};

const uint8_t p_permtab[] = {
        4,  4,                     /* 32 bit -> 32 bit */
        16,  7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2,  8, 24, 14,
        32, 27,  3,  9,
        19, 13, 30,  6,
        22, 11,  4, 25
};

const uint8_t ip_permtab[] = {
        8,  8,                     /* 64 bit -> 64 bit */
        58, 50, 42, 34, 26, 18, 10, 2,
        60, 52, 44, 36, 28, 20, 12, 4,
        62, 54, 46, 38, 30, 22, 14, 6,
        64, 56, 48, 40, 32, 24, 16, 8,
        57, 49, 41, 33, 25, 17,  9, 1,
        59, 51, 43, 35, 27, 19, 11, 3,
        61, 53, 45, 37, 29, 21, 13, 5,
        63, 55, 47, 39, 31, 23, 15, 7
};

const uint8_t inv_ip_permtab[] = {
        8, 8,                      /* 64 bit -> 64 bit */
        40, 8, 48, 16, 56, 24, 64, 32,
        39, 7, 47, 15, 55, 23, 63, 31,
        38, 6, 46, 14, 54, 22, 62, 30,
        37, 5, 45, 13, 53, 21, 61, 29,
        36, 4, 44, 12, 52, 20, 60, 28,
        35, 3, 43, 11, 51, 19, 59, 27,
        34, 2, 42, 10, 50, 18, 58, 26,
        33, 1, 41,  9, 49, 17, 57, 25
};

const uint8_t pc1_permtab[] = {
        8,  7,                     /* 64 bit -> 56 bit*/
        57, 49, 41, 33, 25, 17,  9,
        1, 58, 50, 42, 34, 26, 18,
        10,  2, 59, 51, 43, 35, 27,
        19, 11,  3, 60, 52, 44, 36,
        63, 55, 47, 39, 31, 23, 15,
        7, 62, 54, 46, 38, 30, 22,
        14,  6, 61, 53, 45, 37, 29,
        21, 13,  5, 28, 20, 12,  4
};

const uint8_t pc2_permtab[] = {
        7,  6,                     /* 56 bit -> 48 bit */
        14, 17, 11, 24,  1,  5,
        3, 28, 15,  6, 21, 10,
        23, 19, 12,  4, 26,  8,
        16,  7, 27, 20, 13,  2,
        41, 52, 31, 37, 47, 55,
        30, 40, 51, 45, 33, 48,
        44, 49, 39, 56, 34, 53,
        46, 42, 50, 36, 29, 32
};

const uint8_t splitin6bitword_permtab[] = {
        8,  8,                     /* 64 bit -> 64 bit */
        64, 64,  1,  6,  2,  3,  4,  5,
        64, 64,  7, 12,  8,  9, 10, 11,
        64, 64, 13, 18, 14, 15, 16, 17,
        64, 64, 19, 24, 20, 21, 22, 23,
        64, 64, 25, 30, 26, 27, 28, 29,
        64, 64, 31, 36, 32, 33, 34, 35,
        64, 64, 37, 42, 38, 39, 40, 41,
        64, 64, 43, 48, 44, 45, 46, 47
};

const uint8_t shiftkey_permtab[] = {
        7,  7,                     /* 56 bit -> 56 bit */
        2,  3,  4,  5,  6,  7,  8,  9,
        10, 11, 12, 13, 14, 15, 16, 17,
        18, 19, 20, 21, 22, 23, 24, 25,
        26, 27, 28,  1,
        30, 31, 32, 33, 34, 35, 36, 37,
        38, 39, 40, 41, 42, 43, 44, 45,
        46, 47, 48, 49, 50, 51, 52, 53,
        54, 55, 56, 29
};

const uint8_t shiftkeyinv_permtab[] = {
        7,  7,
        28,  1,  2,  3,  4,  5,  6,  7,
        8,  9, 10, 11, 12, 13, 14, 15,
        16, 17, 18, 19, 20, 21, 22, 23,
        24, 25, 26, 27,
        56, 29, 30, 31, 32, 33, 34, 35,
        36, 37, 38, 39, 40, 41, 42, 43,
        44, 45, 46, 47, 48, 49, 50, 51,
        52, 53, 54, 55
};

/*
1 0
1 0
2 1
2 1
2 1
2 1
2 1
2 1
----
1 0
2 1
2 1
2 1
2 1
2 1
2 1
1 0
*/
#define ROTTABLE      0x7EFC
#define ROTTABLE_INV  0x3F7E
/******************************************************************************/

void permute(const uint8_t *ptable, const uint8_t *in, uint8_t *out) {
    uint8_t ob; /* in-bytes and out-bytes */
    uint8_t byte, bit; /* counter for bit and byte */
    ob = ptable[1];
    ptable = &(ptable[2]);
    for (byte = 0; byte < ob; ++byte) {
        uint8_t t = 0;
        for (bit = 0; bit < 8; ++bit) {
            uint8_t x = *ptable++ - 1;
            t <<= 1;
            if ((in[x / 8]) & (0x80 >> (x % 8))) {
                t |= 0x01;
            }
        }
        out[byte] = t;
    }
}

/******************************************************************************/

void changeendian32(uint32_t *a) {
    *a = (*a & 0x000000FF) << 24 |
         (*a & 0x0000FF00) <<  8 |
         (*a & 0x00FF0000) >>  8 |
         (*a & 0xFF000000) >> 24;
}

/******************************************************************************/
static inline
void shiftkey(uint8_t *key) {
    uint8_t k[7];
    memcpy(k, key, 7);
    permute((uint8_t *)shiftkey_permtab, k, key);
}

/******************************************************************************/
static inline
void shiftkey_inv(uint8_t *key) {
    uint8_t k[7];
    memcpy(k, key, 7);
    permute((uint8_t *)shiftkeyinv_permtab, k, key);

}

/******************************************************************************/
static inline
uint64_t splitin6bitwords(uint64_t a) {
    uint64_t ret = 0;
    a &= 0x0000ffffffffffffLL;
    permute((uint8_t *)splitin6bitword_permtab, (uint8_t *)&a, (uint8_t *)&ret);
    return ret;
}

/******************************************************************************/

static inline
uint8_t substitute(uint8_t a, uint8_t *sbp) {
    uint8_t x;
    x = sbp[a >> 1];
    x = (a & 1) ? x & 0x0F : x >> 4;
    return x;

}

/******************************************************************************/

uint32_t des_f(uint32_t r, uint8_t *kr) {
    uint8_t i;
    uint32_t t = 0, ret;
    uint64_t data = 0;
    uint8_t *sbp; /* sboxpointer */
    permute((uint8_t *)e_permtab, (uint8_t *)&r, (uint8_t *)&data);
    for (i = 0; i < 6; ++i)
        ((uint8_t *)&data)[i] ^= kr[i];

    /* Sbox substitution */
    data = splitin6bitwords(data);
    sbp = (uint8_t *)sbox;
    for (i = 0; i < 8; ++i) {
        uint8_t x;
        x = substitute(((uint8_t *)&data)[i], sbp);
        t <<= 4;
        t |= x;
        sbp += 32;
    }
    changeendian32(&t);

    permute((uint8_t *)p_permtab, (uint8_t *)&t, (uint8_t *)&ret);

    return ret;
}

/******************************************************************************/

typedef struct {
    union {
        uint8_t  v8[8];
        uint32_t v32[2];
    } d;
} des_data_t;
#define R (des_data.d.v32[1])
#define L (des_data.d.v32[0])

void des_enc(void *out, const void *in, const void *key) {

    uint8_t kr[6], k[7];
    uint8_t i;
    des_data_t des_data;

    permute((uint8_t *)ip_permtab, (uint8_t *)in, des_data.d.v8);
    permute((uint8_t *)pc1_permtab, (const uint8_t *)key, k);

    for (i = 0; i < 8; ++i) {
        shiftkey(k);
        if (ROTTABLE & ((1 << ((i << 1) + 0))))
            shiftkey(k);
        permute((uint8_t *)pc2_permtab, k, kr);
        L ^= des_f(R, kr);

        shiftkey(k);
        if (ROTTABLE & ((1 << ((i << 1) + 1))))
            shiftkey(k);
        permute((uint8_t *)pc2_permtab, k, kr);
        R ^= des_f(L, kr);

    }
    /* L <-> R*/
    R ^= L;
    L ^= R;
    R ^= L;

    permute((uint8_t *)inv_ip_permtab, des_data.d.v8, (uint8_t *)out);
}

/******************************************************************************/

void des_dec(void *out, const void *in, const void *key) {

    uint8_t kr[6], k[7];
    int8_t i;
    des_data_t des_data;

    permute((uint8_t *)ip_permtab, (uint8_t *)in, des_data.d.v8);
    permute((uint8_t *)pc1_permtab, (const uint8_t *)key, k);
    for (i = 7; i >= 0; --i) {

        permute((uint8_t *)pc2_permtab, k, kr);
        L ^= des_f(R, kr);
        shiftkey_inv(k);
        if (ROTTABLE & ((1 << ((i << 1) + 1)))) {
            shiftkey_inv(k);
        }

        permute((uint8_t *)pc2_permtab, k, kr);
        R ^= des_f(L, kr);
        shiftkey_inv(k);
        if (ROTTABLE & ((1 << ((i << 1) + 0)))) {
            shiftkey_inv(k);
        }

    }
    /* L <-> R*/
    R ^= L;
    L ^= R;
    R ^= L;

    permute((uint8_t *)inv_ip_permtab, des_data.d.v8, (uint8_t *)out);
}

#undef R
#undef L
/******************************************************************************/

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif

#define htole32(x) (x)
#define CRC32_PRESET 0xFFFFFFFF

static void crc32_byte(uint32_t *crc, const uint8_t value);

static void crc32_byte(uint32_t *crc, const uint8_t value) {
    /* x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 */
    const uint32_t poly = 0xEDB88320;

    *crc ^= value;
    for (int current_bit = 7; current_bit >= 0; current_bit--) {
        int bit_out = (*crc) & 0x00000001;
        *crc >>= 1;
        if (bit_out)
            *crc ^= poly;
    }
}

void crc32_ex(const uint8_t *data, const size_t len, uint8_t *crc) {
    uint32_t desfire_crc = CRC32_PRESET;
    for (size_t i = 0; i < len; i++) {
        crc32_byte(&desfire_crc, data[i]);
    }

    *((uint32_t *)(crc)) = htole32(desfire_crc);
}

void crc32_append(uint8_t *data, const size_t len) {
    crc32_ex(data, len, data + len);
}

static inline void update_key_schedules(desfirekey_t key);

static inline void update_key_schedules(desfirekey_t key) {
    // DES_set_key ((DES_cblock *)key->data, &(key->ks1));
    // DES_set_key ((DES_cblock *)(key->data + 8), &(key->ks2));
    // if (T_3K3DES == key->type) {
    // DES_set_key ((DES_cblock *)(key->data + 16), &(key->ks3));
    // }
}

/******************************************************************************/

/*void des_enc(void *out, const void *in, const void *key) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

void des_dec(void *out, const void *in, const void *key) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}
*/

void tdes_3key_enc(void *out, void *in, const void *key) {
    des_enc(out,  in, (uint8_t *)key + 0);
    des_dec(out, out, (uint8_t *)key + 8);
    des_enc(out, out, (uint8_t *)key + 16);
}

void tdes_3key_dec(void *out, void *in, const uint8_t *key) {
    des_dec(out,  in, (uint8_t *)key + 16);
    des_enc(out, out, (uint8_t *)key + 8);
    des_dec(out, out, (uint8_t *)key + 0);
}

void tdes_2key_enc(void *out, void *in, const void *key) {
    des_enc(out,  in, (uint8_t *)key + 0);
    des_dec(out, out, (uint8_t *)key + 8);
    des_enc(out, out, (uint8_t *)key + 0);
}

void tdes_2key_dec(void *out, void *in, const uint8_t *key) {
    des_dec(out,  in, (uint8_t *)key + 0);
    des_enc(out, out, (uint8_t *)key + 8);
    des_dec(out, out, (uint8_t *)key + 0);
}

void tdes_nxp_receive(const void *in, void *out, size_t length, const void *key, unsigned char iv[8], int keymode) {

    if (length % 8) return;

    uint8_t i;
    unsigned char temp[8];
    uint8_t *tin = (uint8_t *) in;
    uint8_t *tout = (uint8_t *) out;

    while (length > 0) {
        memcpy(temp, tin, 8);

        if (keymode==2) tdes_2key_dec(tout,tin,key);
        else if (keymode==3) tdes_3key_dec(tout,tin,key);

        for (i = 0; i < 8; i++)
            tout[i] = (unsigned char)(tout[i] ^ iv[i]);

        memcpy(iv, temp, 8);

        tin  += 8;
        tout += 8;
        length -= 8;
    }
}

void tdes_nxp_send(const void *in, void *out, size_t length, const void *key, unsigned char iv[8], int keymode) {

    if (length % 8) return;

    uint8_t i;
    uint8_t *tin = (uint8_t *) in;
    uint8_t *tout = (uint8_t *) out;

    while (length > 0) {
        for (i = 0; i < 8; i++)
            tin[i] = (unsigned char)(tin[i] ^ iv[i]);

        if (keymode==2) tdes_2key_enc(tout,tin,key);
        else if (keymode==3) tdes_3key_enc(tout,tin,key);

        memcpy(iv, tout, 8);

        tin  += 8;
        tout += 8;
        length -= 8;
    }
}



void Desfire_des_key_new(const uint8_t value[8], desfirekey_t key) {
    uint8_t data[8];
    memcpy(data, value, 8);
    for (int n = 0; n < 8; n++)
        data[n] &= 0xfe;
    Desfire_des_key_new_with_version(data, key);
}

void Desfire_des_key_new_with_version(const uint8_t value[8], desfirekey_t key) {
    if (key != NULL) {
        key->type = T_DES;
        memcpy(key->data, value, 8);
        memcpy(key->data + 8, value, 8);
        update_key_schedules(key);
    }
}

void Desfire_3des_key_new(const uint8_t value[16], desfirekey_t key) {
    uint8_t data[16];
    memcpy(data, value, 16);
    for (int n = 0; n < 8; n++)
        data[n] &= 0xfe;
    for (int n = 8; n < 16; n++)
        data[n] |= 0x01;
    Desfire_3des_key_new_with_version(data, key);
}

void Desfire_3des_key_new_with_version(const uint8_t value[16], desfirekey_t key) {
    if (key != NULL) {
        key->type = T_3DES;
        memcpy(key->data, value, 16);
        update_key_schedules(key);
    }
}

void Desfire_3k3des_key_new(const uint8_t value[24], desfirekey_t key) {
    uint8_t data[24];
    memcpy(data, value, 24);
    for (int n = 0; n < 8; n++)
        data[n] &= 0xfe;
    Desfire_3k3des_key_new_with_version(data, key);
}

void Desfire_3k3des_key_new_with_version(const uint8_t value[24], desfirekey_t key) {
    if (key != NULL) {
        key->type = T_3K3DES;
        memcpy(key->data, value, 24);
        update_key_schedules(key);
    }
}

void Desfire_aes_key_new(const uint8_t value[16], desfirekey_t key) {
    Desfire_aes_key_new_with_version(value, 0, key);
}

void Desfire_aes_key_new_with_version(const uint8_t value[16], uint8_t version, desfirekey_t key) {

    if (key != NULL) {
        memcpy(key->data, value, 16);
        key->type = T_AES;
        key->aes_version = version;
    }
}

uint8_t Desfire_key_get_version(desfirekey_t key) {
    uint8_t version = 0;

    for (int n = 0; n < 8; n++) {
        version |= ((key->data[n] & 1) << (7 - n));
    }
    return version;
}

void Desfire_key_set_version(desfirekey_t key, uint8_t version) {
    for (int n = 0; n < 8; n++) {
        uint8_t version_bit = ((version & (1 << (7 - n))) >> (7 - n));
        key->data[n] &= 0xfe;
        key->data[n] |= version_bit;
        if (key->type == T_DES) {
            key->data[n + 8] = key->data[n];
        } else {
            // Write ~version to avoid turning a 3DES key into a DES key
            key->data[n + 8] &= 0xfe;
            key->data[n + 8] |= ~version_bit;
        }
    }
}

void Desfire_session_key_new(const uint8_t rnda[], const uint8_t rndb[], desfirekey_t authkey, desfirekey_t key) {

    uint8_t buffer[24];

    switch (authkey->type) {
        case T_DES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            Desfire_des_key_new_with_version(buffer, key);
            break;
        case T_3DES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            memcpy(buffer + 8, rnda + 4, 4);
            memcpy(buffer + 12, rndb + 4, 4);
            Desfire_3des_key_new_with_version(buffer, key);
            break;
        case T_3K3DES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            memcpy(buffer + 8, rnda + 6, 4);
            memcpy(buffer + 12, rndb + 6, 4);
            memcpy(buffer + 16, rnda + 12, 4);
            memcpy(buffer + 20, rndb + 12, 4);
            Desfire_3k3des_key_new(buffer, key);
            break;
        case T_AES:
            memcpy(buffer, rnda, 4);
            memcpy(buffer + 4, rndb, 4);
            memcpy(buffer + 8, rnda + 12, 4);
            memcpy(buffer + 12, rndb + 12, 4);
            Desfire_aes_key_new(buffer, key);
            break;
    }
}

static void xor(const uint8_t *ivect, uint8_t *data, const size_t len);
static size_t key_macing_length(desfirekey_t key);

// iceman,  see memxor inside string.c, dest/src swapped..
static void xor(const uint8_t *ivect, uint8_t *data, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        data[i] ^= ivect[i];
    }
}

void cmac_generate_subkeys(desfirekey_t key) {
    int kbs = key_block_size(key);
    const uint8_t R = (kbs == 8) ? 0x1B : 0x87;

    uint8_t l[kbs];
    memset(l, 0, kbs);

    uint8_t ivect[kbs];
    memset(ivect, 0, kbs);

    mifare_cypher_blocks_chained(NULL, key, ivect, l, kbs, MCD_RECEIVE, MCO_ENCYPHER);

    bool xor = false;

    // Used to compute CMAC on complete blocks
    memcpy(key->cmac_sk1, l, kbs);
    xor = l[0] & 0x80;
    lsl(key->cmac_sk1, kbs);
    if (xor)
        key->cmac_sk1[kbs - 1] ^= R;

    // Used to compute CMAC on the last block if non-complete
    memcpy(key->cmac_sk2, key->cmac_sk1, kbs);
    xor = key->cmac_sk1[0] & 0x80;
    lsl(key->cmac_sk2, kbs);
    if (xor)
        key->cmac_sk2[kbs - 1] ^= R;
}

void cmac(const desfirekey_t key, uint8_t *ivect, const uint8_t *data, size_t len, uint8_t *cmac) {
    int kbs = key_block_size(key);
    uint8_t *buffer = malloc(padded_data_length(len, kbs));

    memcpy(buffer, data, len);

    if ((!len) || (len % kbs)) {
        buffer[len++] = 0x80;
        while (len % kbs) {
            buffer[len++] = 0x00;
        }
        xor(key->cmac_sk2, buffer + len - kbs, kbs);
    } else {
        xor(key->cmac_sk1, buffer + len - kbs, kbs);
    }

    mifare_cypher_blocks_chained(NULL, key, ivect, buffer, len, MCD_SEND, MCO_ENCYPHER);

    memcpy(cmac, ivect, kbs);
    free(buffer);
}

size_t key_block_size(const desfirekey_t key) {
    if (key == NULL)
        return 0;
    size_t block_size = 8;
    switch (key->type) {
        case T_DES:
        case T_3DES:
        case T_3K3DES:
            block_size = 8;
            break;
        case T_AES:
            block_size = 16;
            break;
    }
    return block_size;
}

/*
 * Size of MACing produced with the key.
 */
static size_t key_macing_length(const desfirekey_t key) {
    size_t mac_length = MAC_LENGTH;
    switch (key->type) {
        case T_DES:
        case T_3DES:
            mac_length = MAC_LENGTH;
            break;
        case T_3K3DES:
        case T_AES:
            mac_length = CMAC_LENGTH;
            break;
    }
    return mac_length;
}

/*
 * Size required to store nbytes of data in a buffer of size n*block_size.
 */
size_t padded_data_length(const size_t nbytes, const size_t block_size) {
    if ((!nbytes) || (nbytes % block_size))
        return ((nbytes / block_size) + 1) * block_size;
    else
        return nbytes;
}

/*
 * Buffer size required to MAC nbytes of data
 */
size_t maced_data_length(const desfirekey_t key, const size_t nbytes) {
    return nbytes + key_macing_length(key);
}
/*
 * Buffer size required to encipher nbytes of data and a two bytes CRC.
 */
size_t enciphered_data_length(const desfiretag_t tag, const size_t nbytes, int communication_settings) {
    size_t crc_length = 0;
    if (!(communication_settings & NO_CRC)) {
        switch (DESFIRE(tag)->authentication_scheme) {
            case AS_LEGACY:
                crc_length = 2;
                break;
            case AS_NEW:
                crc_length = 4;
                break;
        }
    }

    size_t block_size = DESFIRE(tag)->session_key ? key_block_size(DESFIRE(tag)->session_key) : 1;

    return padded_data_length(nbytes + crc_length, block_size);
}

void *mifare_cryto_preprocess_data(desfiretag_t tag, void *data, size_t *nbytes, size_t offset, int communication_settings) {
    uint8_t *res = data;
    uint8_t mac[4];
    size_t edl;
    bool append_mac = true;
    desfirekey_t key = DESFIRE(tag)->session_key;

    if (!key)
        return data;

    switch (communication_settings & MDCM_MASK) {
        case MDCM_PLAIN:
            if (AS_LEGACY == DESFIRE(tag)->authentication_scheme)
                break;

            /*
             * When using new authentication methods, PLAIN data transmission from
             * the PICC to the PCD are CMACed, so we have to maintain the
             * cryptographic initialisation vector up-to-date to check data
             * integrity later.
             *
             * The only difference with CMACed data transmission is that the CMAC
             * is not apended to the data send by the PCD to the PICC.
             */

            append_mac = false;

        /* pass through */
        case MDCM_MACED:
            switch (DESFIRE(tag)->authentication_scheme) {
                case AS_LEGACY:
                    if (!(communication_settings & MAC_COMMAND))
                        break;

                    /* pass through */
                    edl = padded_data_length(*nbytes - offset, key_block_size(DESFIRE(tag)->session_key)) + offset;

                    // Fill in the crypto buffer with data ...
                    memcpy(res, data, *nbytes);
                    // ... and 0 padding
                    memset(res + *nbytes, 0, edl - *nbytes);

                    mifare_cypher_blocks_chained(tag, NULL, NULL, res + offset, edl - offset, MCD_SEND, MCO_ENCYPHER);

                    memcpy(mac, res + edl - 8, 4);

                    // Copy again provided data (was overwritten by mifare_cypher_blocks_chained)
                    memcpy(res, data, *nbytes);

                    if (!(communication_settings & MAC_COMMAND))
                        break;
                    // Append MAC
                    size_t bla = maced_data_length(DESFIRE(tag)->session_key, *nbytes - offset) + offset;
                    bla++;

                    memcpy(res + *nbytes, mac, 4);

                    *nbytes += 4;
                    break;
                case AS_NEW:
                    if (!(communication_settings & CMAC_COMMAND))
                        break;
                    cmac(key, DESFIRE(tag)->ivect, res, *nbytes, DESFIRE(tag)->cmac);

                    if (append_mac) {
                        size_t len = maced_data_length(key, *nbytes);
                        ++len;
                        memcpy(res, data, *nbytes);
                        memcpy(res + *nbytes, DESFIRE(tag)->cmac, CMAC_LENGTH);
                        *nbytes += CMAC_LENGTH;
                    }
                    break;
            }

            break;
        case MDCM_ENCIPHERED:
            /*  |<-------------- data -------------->|
             *  |<--- offset -->|                    |
             *  +---------------+--------------------+-----+---------+
             *  | CMD + HEADERS | DATA TO BE SECURED | CRC | PADDING |
             *  +---------------+--------------------+-----+---------+ ----------------
             *  |               |<~~~~v~~~~~~~~~~~~~>|  ^  |         |   (DES / 3DES)
             *  |               |     `---- crc16() ----'  |         |
             *  |               |                    |  ^  |         | ----- *or* -----
             *  |<~~~~~~~~~~~~~~~~~~~~v~~~~~~~~~~~~~>|  ^  |         |  (3K3DES / AES)
             *                  |     `---- crc32() ----'  |         |
             *                  |                                    | ---- *then* ----
             *                  |<---------------------------------->|
             *                            encypher()/decypher()
             */

            if (!(communication_settings & ENC_COMMAND))
                break;
            edl = enciphered_data_length(tag, *nbytes - offset, communication_settings) + offset;

            // Fill in the crypto buffer with data ...
            memcpy(res, data, *nbytes);
            if (!(communication_settings & NO_CRC)) {
                // ... CRC ...
                switch (DESFIRE(tag)->authentication_scheme) {
                    case AS_LEGACY:
                        AddCrc14A(res + offset, *nbytes - offset);
                        *nbytes += 2;
                        break;
                    case AS_NEW:
                        crc32_append(res, *nbytes);
                        *nbytes += 4;
                        break;
                }
            }
            // ... and padding
            memset(res + *nbytes, 0, edl - *nbytes);

            *nbytes = edl;

            mifare_cypher_blocks_chained(tag, NULL, NULL, res + offset, *nbytes - offset, MCD_SEND, (AS_NEW == DESFIRE(tag)->authentication_scheme) ? MCO_ENCYPHER : MCO_DECYPHER);
            break;
        default:

            *nbytes = -1;
            res = NULL;
            break;
    }

    return res;

}

void *mifare_cryto_postprocess_data(desfiretag_t tag, void *data, size_t *nbytes, int communication_settings) {
    void *res = data;
    void *edata = NULL;
    uint8_t first_cmac_byte = 0x00;

    desfirekey_t key = DESFIRE(tag)->session_key;

    if (!key)
        return data;

    // Return directly if we just have a status code.
    if (1 == *nbytes)
        return res;

    switch (communication_settings & MDCM_MASK) {
        case MDCM_PLAIN:

            if (AS_LEGACY == DESFIRE(tag)->authentication_scheme)
                break;

        /* pass through */
        case MDCM_MACED:
            switch (DESFIRE(tag)->authentication_scheme) {
                case AS_LEGACY:
                    if (communication_settings & MAC_VERIFY) {
                        *nbytes -= key_macing_length(key);
                        if (*nbytes == 0) {
                            *nbytes = -1;
                            res = NULL;
#ifdef WITH_DEBUG
                            Dbprintf("No room for MAC!");
#endif
                            break;
                        }

                        size_t edl = enciphered_data_length(tag, *nbytes - 1, communication_settings);
                        edata = malloc(edl);

                        memcpy(edata, data, *nbytes - 1);
                        memset((uint8_t *)edata + *nbytes - 1, 0, edl - *nbytes + 1);

                        mifare_cypher_blocks_chained(tag, NULL, NULL, edata, edl, MCD_SEND, MCO_ENCYPHER);

                        if (0 != memcmp((uint8_t *)data + *nbytes - 1, (uint8_t *)edata + edl - 8, 4)) {
#ifdef WITH_DEBUG
                            Dbprintf("MACing not verified");
                            hexdump((uint8_t *)data + *nbytes - 1, key_macing_length(key), "Expect ", 0);
                            hexdump((uint8_t *)edata + edl - 8, key_macing_length(key), "Actual ", 0);
#endif
                            DESFIRE(tag)->last_pcd_error = CRYPTO_ERROR;
                            *nbytes = -1;
                            res = NULL;
                        }
                    }
                    break;
                case AS_NEW:
                    if (!(communication_settings & CMAC_COMMAND))
                        break;
                    if (communication_settings & CMAC_VERIFY) {
                        if (*nbytes < 9) {
                            *nbytes = -1;
                            res = NULL;
                            break;
                        }
                        first_cmac_byte = ((uint8_t *)data)[*nbytes - 9];
                        ((uint8_t *)data)[*nbytes - 9] = ((uint8_t *)data)[*nbytes - 1];
                    }

                    int n = (communication_settings & CMAC_VERIFY) ? 8 : 0;
                    cmac(key, DESFIRE(tag)->ivect, ((uint8_t *)data), *nbytes - n, DESFIRE(tag)->cmac);

                    if (communication_settings & CMAC_VERIFY) {
                        ((uint8_t *)data)[*nbytes - 9] = first_cmac_byte;
                        if (0 != memcmp(DESFIRE(tag)->cmac, (uint8_t *)data + *nbytes - 9, 8)) {
#ifdef WITH_DEBUG
                            Dbprintf("CMAC NOT verified :-(");
                            hexdump((uint8_t *)data + *nbytes - 9, 8, "Expect ", 0);
                            hexdump(DESFIRE(tag)->cmac, 8, "Actual ", 0);
#endif
                            DESFIRE(tag)->last_pcd_error = CRYPTO_ERROR;
                            *nbytes = -1;
                            res = NULL;
                        } else {
                            *nbytes -= 8;
                        }
                    }
                    break;
            }

            free(edata);

            break;
        case MDCM_ENCIPHERED:
            (*nbytes)--;
            bool verified = false;
            int crc_pos = 0x00;
            int end_crc_pos = 0x00;
            uint8_t x;

            /*
             * AS_LEGACY:
             * ,-----------------+-------------------------------+--------+
             * \     BLOCK n-1   |              BLOCK n          | STATUS |
             * /  PAYLOAD | CRC0 | CRC1 | 0x80? | 0x000000000000 | 0x9100 |
             * `-----------------+-------------------------------+--------+
             *
             *         <------------ DATA ------------>
             * FRAME = PAYLOAD + CRC(PAYLOAD) + PADDING
             *
             * AS_NEW:
             * ,-------------------------------+-----------------------------------------------+--------+
             * \                 BLOCK n-1     |                  BLOCK n                      | STATUS |
             * /  PAYLOAD | CRC0 | CRC1 | CRC2 | CRC3 | 0x80? | 0x0000000000000000000000000000 | 0x9100 |
             * `-------------------------------+-----------------------------------------------+--------+
             * <----------------------------------- DATA ------------------------------------->|
             *
             *         <----------------- DATA ---------------->
             * FRAME = PAYLOAD + CRC(PAYLOAD + STATUS) + PADDING + STATUS
             *                                    `------------------'
             */

            mifare_cypher_blocks_chained(tag, NULL, NULL, res, *nbytes, MCD_RECEIVE, MCO_DECYPHER);

            /*
             * Look for the CRC and ensure it is followed by NULL padding.  We
             * can't start by the end because the CRC is supposed to be 0 when
             * verified, and accumulating 0's in it should not change it.
             */
            switch (DESFIRE(tag)->authentication_scheme) {
                case AS_LEGACY:
                    crc_pos = *nbytes - 8 - 1; // The CRC can be over two blocks
                    if (crc_pos < 0) {
                        /* Single block */
                        crc_pos = 0;
                    }
                    break;
                case AS_NEW:
                    /* Move status between payload and CRC */
                    res = DESFIRE(tag)->crypto_buffer;
                    memcpy(res, data, *nbytes);

                    crc_pos = (*nbytes) - 16 - 3;
                    if (crc_pos < 0) {
                        /* Single block */
                        crc_pos = 0;
                    }
                    memcpy((uint8_t *)res + crc_pos + 1, (uint8_t *)res + crc_pos, *nbytes - crc_pos);
                    ((uint8_t *)res)[crc_pos] = 0x00;
                    crc_pos++;
                    *nbytes += 1;
                    break;
            }

            do {
                uint16_t crc_16 = 0x00;
                uint32_t crc=0x00;
                switch (DESFIRE(tag)->authentication_scheme) {
                    case AS_LEGACY:
                        AddCrc14A((uint8_t *)res, end_crc_pos);
                        end_crc_pos = crc_pos + 2;
                        //


                        crc = crc_16;
                        break;
                    case AS_NEW:
                        end_crc_pos = crc_pos + 4;
                        crc32_ex(res, end_crc_pos, (uint8_t *)&crc);
                        break;
                }
                if (!crc) {
                    verified = true;
                    for (int n = end_crc_pos; n < *nbytes - 1; n++) {
                        uint8_t byte = ((uint8_t *)res)[n];
                        if (!((0x00 == byte) || ((0x80 == byte) && (n == end_crc_pos))))
                            verified = false;
                    }
                }
                if (verified) {
                    *nbytes = crc_pos;
                    switch (DESFIRE(tag)->authentication_scheme) {
                        case AS_LEGACY:
                            ((uint8_t *)data)[(*nbytes)++] = 0x00;
                            break;
                        case AS_NEW:
                            /* The status byte was already before the CRC */
                            break;
                    }
                } else {
                    switch (DESFIRE(tag)->authentication_scheme) {
                        case AS_LEGACY:
                            break;
                        case AS_NEW:
                            x = ((uint8_t *)res)[crc_pos - 1];
                            ((uint8_t *)res)[crc_pos - 1] = ((uint8_t *)res)[crc_pos];
                            ((uint8_t *)res)[crc_pos] = x;
                            break;
                    }
                    crc_pos++;
                }
            } while (!verified && (end_crc_pos < *nbytes));

            if (!verified) {
#ifdef WITH_DEBUG
                /* FIXME In some configurations, the file is transmitted PLAIN */
                Dbprintf("CRC not verified in decyphered stream");
#endif
                DESFIRE(tag)->last_pcd_error = CRYPTO_ERROR;
                *nbytes = -1;
                res = NULL;
            }

            break;
        default:
            PrintAndLogEx(ERR,"Unknown communication settings");
            *nbytes = -1;
            res = NULL;
            break;

    }
    return res;
}


void mifare_cypher_single_block(desfirekey_t key, uint8_t *data, uint8_t *ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, size_t block_size) {
    uint8_t ovect[MAX_CRYPTO_BLOCK_SIZE];

    if (direction == MCD_SEND) {
        xor(ivect, data, block_size);
    } else {
        memcpy(ovect, data, block_size);
    }

    uint8_t edata[MAX_CRYPTO_BLOCK_SIZE];

    switch (key->type) {
        case T_DES:
            switch (operation) {
                case MCO_ENCYPHER:
                    //DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    des_enc(edata, data, key->data);
                    break;
                case MCO_DECYPHER:
                    //DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    des_dec(edata, data, key->data);
                    break;
            }
            break;
        case T_3DES:
            switch (operation) {
                case MCO_ENCYPHER:
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    tdes_2key_enc(edata, data, key->data);
                    break;
                case MCO_DECYPHER:
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    tdes_2key_dec(data, edata, key->data);
                    break;
            }
            break;
        case T_3K3DES:
            switch (operation) {
                case MCO_ENCYPHER:
                    tdes_3key_enc(edata, data, key->data);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks3), DES_ENCRYPT);
                    break;
                case MCO_DECYPHER:
                    tdes_3key_enc(data, edata, key->data);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks3), DES_DECRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
                    // DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
                    break;
            }
            break;
        case T_AES:
            switch (operation) {
                case MCO_ENCYPHER: {
                    mbedtls_aes_context ctx;
                    mbedtls_aes_init(&ctx);
                    mbedtls_aes_setkey_enc(&ctx, key->data, 128);
                    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_ENCRYPT, sizeof(edata), ivect, data, edata);
                    mbedtls_aes_free(&ctx);
                    break;
                }
                case MCO_DECYPHER: {
                    mbedtls_aes_context ctx;
                    mbedtls_aes_init(&ctx);
                    mbedtls_aes_setkey_dec(&ctx, key->data, 128);
                    mbedtls_aes_crypt_cbc(&ctx, MBEDTLS_AES_DECRYPT, sizeof(edata), ivect, edata, data);
                    mbedtls_aes_free(&ctx);
                    break;
                }
            }
            break;
    }

    memcpy(data, edata, block_size);

    if (direction == MCD_SEND) {
        memcpy(ivect, data, block_size);
    } else {
        xor(ivect, data, block_size);
        memcpy(ivect, ovect, block_size);
    }
}

/*
 * This function performs all CBC cyphering / deciphering.
 *
 * The tag argument may be NULL, in which case both key and ivect shall be set.
 * When using the tag session_key and ivect for processing data, these
 * arguments should be set to NULL.
 *
 * Because the tag may contain additional data, one may need to call this
 * function with tag, key and ivect defined.
 */
void mifare_cypher_blocks_chained(desfiretag_t tag, desfirekey_t key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareCryptoDirection direction, MifareCryptoOperation operation) {
    size_t block_size;

    if (tag) {
        if (!key)
            key = DESFIRE(tag)->session_key;
        if (!ivect)
            ivect = DESFIRE(tag)->ivect;

        switch (DESFIRE(tag)->authentication_scheme) {
            case AS_LEGACY:
                memset(ivect, 0, MAX_CRYPTO_BLOCK_SIZE);
                break;
            case AS_NEW:
                break;
        }
    }

    block_size = key_block_size(key);

    size_t offset = 0;
    while (offset < data_size) {
        mifare_cypher_single_block(key, data + offset, ivect, direction, operation, block_size);
        offset += block_size;
    }
}
