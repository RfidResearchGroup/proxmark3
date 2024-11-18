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
// Utility functions used in many places, not specific to any piece of code.
//-----------------------------------------------------------------------------
#include "commonutil.h"
#include <string.h>

/* Similar to FpgaGatherVersion this formats stored version information
 * into a string representation. It takes a pointer to the struct version_information_t,
 * verifies the magic properties, then stores a formatted string, prefixed by
 * prefix in dst.
 */
void FormatVersionInformation(char *dst, int len, const char *prefix, const void *version_info) {
    const struct version_information_t *v = (const struct version_information_t *)version_info;
    dst[0] = 0;
    strncat(dst, prefix, len - 1);
    if (v->magic != VERSION_INFORMATION_MAGIC) {
        strncat(dst, "Missing/Invalid version information", len - strlen(dst) - 1);
        return;
    }
    if (v->versionversion != 1) {
        strncat(dst, "Version information not understood", len - strlen(dst) - 1);
        return;
    }
    if (!v->present) {
        strncat(dst, "Version information not available", len - strlen(dst) - 1);
        return;
    }

    strncat(dst, v->gitversion, len - strlen(dst) - 1);
    if (v->clean == 0) {
        strncat(dst, "-unclean", len - strlen(dst) - 1);
    } else if (v->clean == 2) {
        strncat(dst, "-suspect", len - strlen(dst) - 1);
    }

    strncat(dst, " ", len - strlen(dst) - 1);
    strncat(dst, v->buildtime, len - strlen(dst) - 1);
    strncat(dst, " ", len - strlen(dst) - 1);
    strncat(dst, v->armsrc, len - strlen(dst) - 1);
}

void format_version_information_short(char *dst, int len, const void *version_info) {
    const struct version_information_t *v = (const struct version_information_t *)version_info;
    dst[0] = 0;
    if (v->magic != VERSION_INFORMATION_MAGIC) {
        strncat(dst, "Missing/Invalid version information", len - strlen(dst) - 1);
        return;
    }
    if (v->versionversion != 1) {
        strncat(dst, "Version information not understood", len - strlen(dst) - 1);
        return;
    }
    if (!v->present) {
        strncat(dst, "Version information not available", len - strlen(dst) - 1);
        return;
    }

    strncat(dst, v->gitversion, len - strlen(dst) - 1);
    strncat(dst, " ", len - strlen(dst) - 1);
    strncat(dst, v->buildtime, len - strlen(dst) - 1);
}

/*
 ref  http://www.csm.ornl.gov/~dunigan/crc.html
 Returns the value v with the bottom b [0,32] bits reflected.
 Example: reflect(0x3e23L,3) == 0x3e26
*/
uint32_t reflect(uint32_t v, int b) {
    uint32_t t = v;
    for (int i = 0; i < b; ++i) {
        if (t & 1)
            v |=  BITMASK((b - 1) - i);
        else
            v &= ~BITMASK((b - 1) - i);
        t >>= 1;
    }
    return v;
}

// https://graphics.stanford.edu/~seander/bithacks.html#BitReverseTable

// Reverse the bits in a byte with 3 operations (64-bit multiply and modulus division):
uint8_t reflect8(uint8_t b) {
    return (b * 0x0202020202ULL & 0x010884422010ULL) % 1023;
}

uint16_t reflect16(uint16_t v) {
    v = (reflect8(v) << 8) | (reflect8(v >> 8) & 0xFF);
    return v;
}

uint32_t reflect32(uint32_t v) {
    // https://graphics.stanford.edu/~seander/bithacks.html#BitReverseTable
    // swap odd and even bits
    v = ((v >> 1) & 0x55555555) | ((v & 0x55555555) << 1);
    // swap consecutive pairs
    v = ((v >> 2) & 0x33333333) | ((v & 0x33333333) << 2);
    // swap nibbles ...
    v = ((v >> 4) & 0x0F0F0F0F) | ((v & 0x0F0F0F0F) << 4);
    // swap bytes
    v = ((v >> 8) & 0x00FF00FF) | ((v & 0x00FF00FF) << 8);
    // swap 2-byte long pairs
    v = (v >> 16) | (v               << 16);
    return v;
}

uint64_t reflect48(uint64_t v) {
    uint64_t vhi = reflect16(v >> 32);
    uint64_t vlo = reflect32(v);
    v = (vlo << 32) | (vhi & 0xFFFF);
    return v;
}

uint64_t reflect64(uint64_t v) {
    // https://graphics.stanford.edu/~seander/bithacks.html#BitReverseTable
    // swap 4-byte long pairs
    uint64_t v1 = reflect32(v >> 32);
    uint64_t v2 = reflect32(v);
    v = (v2 << 32) | (v1 & 0xFFFFFFFF);
    return v;
}

void num_to_bytes(uint64_t n, size_t len, uint8_t *dest) {
    while (len--) {
        dest[len] = (uint8_t) n;
        n >>= 8;
    }
}

uint64_t bytes_to_num(const uint8_t *src, size_t len) {
    uint64_t num = 0;
    while (len--) {
        num = (num << 8) | (*src);
        src++;
    }
    return num;
}

uint16_t MemLeToUint2byte(const uint8_t *data) {
    return (uint16_t)(
               (((uint16_t)(data[1])) << 8) +
               (((uint16_t)(data[0])) << 0)
           );
}

uint32_t MemLeToUint3byte(const uint8_t *data) {
    return (uint32_t)(
               (((uint32_t)(data[2])) << 16) +
               (((uint32_t)(data[1])) << 8) +
               (((uint32_t)(data[0])) << 0)
           );
}

uint32_t MemLeToUint4byte(const uint8_t *data) {
    return (uint32_t)(
               (((uint32_t)(data[3])) << 24) +
               (((uint32_t)(data[2])) << 16) +
               (((uint32_t)(data[1])) << 8) +
               (((uint32_t)(data[0])) << 0)
           );
}

uint64_t MemLeToUint5byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[4])) << 32) +
               (((uint64_t)(data[3])) << 24) +
               (((uint64_t)(data[2])) << 16) +
               (((uint64_t)(data[1])) << 8) +
               (((uint64_t)(data[0])) << 0)
           );
}

uint64_t MemLeToUint6byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[5])) << 40) +
               (((uint64_t)(data[4])) << 32) +
               (((uint64_t)(data[3])) << 24) +
               (((uint64_t)(data[2])) << 16) +
               (((uint64_t)(data[1])) << 8) +
               (((uint64_t)(data[0])) << 0)
           );
}

uint64_t MemLeToUint7byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[6])) << 48) +
               (((uint64_t)(data[5])) << 40) +
               (((uint64_t)(data[4])) << 32) +
               (((uint64_t)(data[3])) << 24) +
               (((uint64_t)(data[2])) << 16) +
               (((uint64_t)(data[1])) << 8) +
               (((uint64_t)(data[0])) << 0)
           );
}

uint64_t MemLeToUint8byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[7])) << 56) +
               (((uint64_t)(data[6])) << 48) +
               (((uint64_t)(data[5])) << 40) +
               (((uint64_t)(data[4])) << 32) +
               (((uint64_t)(data[3])) << 24) +
               (((uint64_t)(data[2])) << 16) +
               (((uint64_t)(data[1])) << 8) +
               (((uint64_t)(data[0])) << 0)
           );
}

uint16_t MemBeToUint2byte(const uint8_t *data) {
    return (uint16_t)(
               (((uint16_t)(data[0])) << 8) +
               (((uint16_t)(data[1])) << 0)
           );
}

uint32_t MemBeToUint3byte(const uint8_t *data) {
    return (uint32_t)(
               (((uint32_t)(data[0])) << 16) +
               (((uint32_t)(data[1])) << 8) +
               (((uint32_t)(data[2])) << 0)
           );
}

uint32_t MemBeToUint4byte(const uint8_t *data) {
    return (uint32_t)(
               (((uint32_t)(data[0])) << 24) +
               (((uint32_t)(data[1])) << 16) +
               (((uint32_t)(data[2])) << 8) +
               (((uint32_t)(data[3])) << 0)
           );
}

uint64_t MemBeToUint5byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[0])) << 32) +
               (((uint64_t)(data[1])) << 24) +
               (((uint64_t)(data[2])) << 16) +
               (((uint64_t)(data[3])) << 8) +
               (((uint64_t)(data[4])) << 0)
           );
}

uint64_t MemBeToUint6byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[0])) << 40) +
               (((uint64_t)(data[1])) << 32) +
               (((uint64_t)(data[2])) << 24) +
               (((uint64_t)(data[3])) << 16) +
               (((uint64_t)(data[4])) << 8) +
               (((uint64_t)(data[5])) << 0)
           );
}

uint64_t MemBeToUint7byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[0])) << 48) +
               (((uint64_t)(data[1])) << 40) +
               (((uint64_t)(data[2])) << 32) +
               (((uint64_t)(data[3])) << 24) +
               (((uint64_t)(data[4])) << 16) +
               (((uint64_t)(data[5])) << 8) +
               (((uint64_t)(data[6])) << 0)
           );
}

uint64_t MemBeToUint8byte(const uint8_t *data) {
    return (uint64_t)(
               (((uint64_t)(data[0])) << 56) +
               (((uint64_t)(data[1])) << 48) +
               (((uint64_t)(data[2])) << 40) +
               (((uint64_t)(data[3])) << 32) +
               (((uint64_t)(data[4])) << 24) +
               (((uint64_t)(data[5])) << 16) +
               (((uint64_t)(data[6])) << 8) +
               (((uint64_t)(data[7])) << 0)
           );
}

void Uint2byteToMemLe(uint8_t *data, uint16_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
}

void Uint3byteToMemLe(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
}

void Uint4byteToMemLe(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
}

void Uint5byteToMemLe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
    data[4] = (uint8_t)((value >> 32) & 0xffu);
}

void Uint6byteToMemLe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
    data[4] = (uint8_t)((value >> 32) & 0xffu);
    data[5] = (uint8_t)((value >> 40) & 0xffu);
}

void Uint7byteToMemLe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
    data[4] = (uint8_t)((value >> 32) & 0xffu);
    data[5] = (uint8_t)((value >> 40) & 0xffu);
    data[6] = (uint8_t)((value >> 48) & 0xffu);
}

void Uint8byteToMemLe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 0) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
    data[4] = (uint8_t)((value >> 32) & 0xffu);
    data[5] = (uint8_t)((value >> 40) & 0xffu);
    data[6] = (uint8_t)((value >> 48) & 0xffu);
    data[7] = (uint8_t)((value >> 56) & 0xffu);
}

void Uint2byteToMemBe(uint8_t *data, uint16_t value) {
    data[0] = (uint8_t)((value >> 8) & 0xffu);
    data[1] = (uint8_t)((value >> 0) & 0xffu);
}

void Uint3byteToMemBe(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)((value >> 16) & 0xffu);
    data[1] = (uint8_t)((value >> 8) & 0xffu);
    data[2] = (uint8_t)((value >> 0) & 0xffu);
}

void Uint4byteToMemBe(uint8_t *data, uint32_t value) {
    data[0] = (uint8_t)((value >> 24) & 0xffu);
    data[1] = (uint8_t)((value >> 16) & 0xffu);
    data[2] = (uint8_t)((value >> 8) & 0xffu);
    data[3] = (uint8_t)((value >> 0) & 0xffu);
}

void Uint5byteToMemBe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 32) & 0xffu);
    data[1] = (uint8_t)((value >> 24) & 0xffu);
    data[2] = (uint8_t)((value >> 16) & 0xffu);
    data[3] = (uint8_t)((value >> 8) & 0xffu);
    data[4] = (uint8_t)((value >> 0) & 0xffu);
}

void Uint6byteToMemBe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 40) & 0xffu);
    data[1] = (uint8_t)((value >> 32) & 0xffu);
    data[2] = (uint8_t)((value >> 24) & 0xffu);
    data[3] = (uint8_t)((value >> 16) & 0xffu);
    data[4] = (uint8_t)((value >> 8) & 0xffu);
    data[5] = (uint8_t)((value >> 0) & 0xffu);
}

void Uint7byteToMemBe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 48) & 0xffu);
    data[1] = (uint8_t)((value >> 40) & 0xffu);
    data[2] = (uint8_t)((value >> 32) & 0xffu);
    data[3] = (uint8_t)((value >> 24) & 0xffu);
    data[4] = (uint8_t)((value >> 16) & 0xffu);
    data[5] = (uint8_t)((value >> 8) & 0xffu);
    data[6] = (uint8_t)((value >> 0) & 0xffu);
}

void Uint8byteToMemBe(uint8_t *data, uint64_t value) {
    data[0] = (uint8_t)((value >> 56) & 0xffu);
    data[1] = (uint8_t)((value >> 48) & 0xffu);
    data[2] = (uint8_t)((value >> 40) & 0xffu);
    data[3] = (uint8_t)((value >> 32) & 0xffu);
    data[4] = (uint8_t)((value >> 24) & 0xffu);
    data[5] = (uint8_t)((value >> 16) & 0xffu);
    data[6] = (uint8_t)((value >> 8) & 0xffu);
    data[7] = (uint8_t)((value >> 0) & 0xffu);
}

// Rotate Left - Ultralight, Desfire
void rol(uint8_t *data, const size_t len) {
    uint8_t first = data[0];
    for (size_t i = 0; i < len - 1; i++) {
        data[i] = data[i + 1];
    }
    data[len - 1] = first;
}

// Rotate Right - Ultralight, Desfire
void ror(uint8_t *data, const size_t len) {
    uint8_t last = data[len - 1];

    for (int i = len - 1; i > 0; i--) {
        data[i] = data[i - 1];
    }

    data[0] = last;
}


void lsl(uint8_t *data, size_t len) {
    for (size_t n = 0; n < len - 1; n++) {
        data[n] = (data[n] << 1) | (data[n + 1] >> 7);
    }
    data[len - 1] <<= 1;
}


// BSWAP24 of array[3]
uint32_t le24toh(const uint8_t data[3]) {
    return (data[2] << 16) | (data[1] << 8) | data[0];
}

// BSWAP24, take u32, output array
void htole24(uint32_t val, uint8_t data[3]) {
    data[0] = (uint8_t) val;
    data[1] = (uint8_t)(val >> 8);
    data[2] = (uint8_t)(val >> 16);
}


// ROL on u32
uint32_t rotl(uint32_t a, uint8_t n) {
    n &= 31;
    return (a << n) | (a >> (32 - n));
}

// ROR on u32
uint32_t rotr(uint32_t a, uint8_t n) {
    n &= 31;
    return (a >> n) | (a << (32 - n));
}

uint16_t get_sw(const uint8_t *d, uint16_t n) {
    if (n < 2)
        return 0;

    n -= 2;
    return (d[n] << 8 | d[n + 1]);
}

// reverse same array
void reverse_array(uint8_t *d, size_t n) {
    if (d == NULL || n < 2) {
        return;
    }

    for (int i = 0, j = n - 1; i < j; ++i, --j) {
        d[i] ^= d[j];
        d[j] ^= d[i];
        d[i] ^= d[j];
    }
}

// reverse src array into dest array
void reverse_array_copy(const uint8_t *src, int src_len, uint8_t *dest) {
    if (src == NULL || src_len == 0 || dest == NULL) {
        return;
    }

    for (int i = 0; i < src_len; i++) {
        dest[i] = src[(src_len - 1) - i];
    }
}

static int hexchar_to_dec(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return ch - 'a' + 10;
    }
    if (ch >= 'A' && ch <= 'F') {
        return ch - 'A' + 10;
    }
    return -1;
}

// no spaces allowed for input hex string
bool hexstr_to_byte_array(const char *hexstr, uint8_t *d, size_t *n) {

    size_t hexstr_len = strlen(hexstr);
    if (hexstr_len & 1) {
        return false;
    }

    *n = (hexstr_len >> 1);

    for (int i = 0; i < *n; i++) {

        char c1 = *hexstr++;
        char c2 = *hexstr++;

        if (c1 == '\0' || c2 == '\0') {
            return false;
        }

        int b = (hexchar_to_dec(c1) << 4) | hexchar_to_dec(c2);
        if (b < 0) {
            // Error: invalid hex character
            return false;
        }
        d[i] = (uint8_t) b;
    }
    return true;
}

void reverse_arraybytes(uint8_t *arr, size_t len) {
    size_t i;
    for (i = 0; i < len ; i++) {
        arr[i] = reflect8(arr[i]);
    }
}

void reverse_arraybytes_copy(uint8_t *arr, uint8_t *dest, size_t len) {
    size_t i;
    for (i = 0; i < len ; i++) {
        dest[i] = reflect8(arr[i]);
    }
}

// TODO: Boost performance by copying in chunks of 1, 2, or 4 bytes when feasible.
size_t concatbits(uint8_t *dest, int dest_offset, const uint8_t *src, int src_offset, size_t nbits) {
    int i, end, step;

    // overlap
    if ((src - dest) * 8 + src_offset - dest_offset > 0) {
        i = 0;
        end = nbits;
        step = 1;
    } else {
        i = nbits;
        end = 0;
        step = -1;
    }

    for (; i != end; i += step) {
        // equiv of dest_bits[dest_offset + i] = src_bits[src_offset + i]
        CLEAR_BIT(dest, dest_offset + i);
        if (TEST_BIT(src, src_offset + i)) SET_BIT(dest, dest_offset + i);
    }

    return dest_offset + nbits;
}
