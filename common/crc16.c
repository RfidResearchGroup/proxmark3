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
// CRC16
//-----------------------------------------------------------------------------
#include "crc16.h"

#include <string.h>
#include "commonutil.h"

static uint16_t crc_table[256];
static bool crc_table_init = false;
static CrcType_t current_crc_type = CRC_NONE;

void init_table(CrcType_t crctype) {

    // same crc algo, and initialised already
    if (crctype == current_crc_type && crc_table_init)
        return;

    // not the same crc algo. reset table.
    if (crctype != current_crc_type)
        reset_table();

    current_crc_type = crctype;

    switch (crctype) {
        case CRC_14443_A:
        case CRC_14443_B:
        case CRC_15693:
        case CRC_ICLASS:
        case CRC_CRYPTORF:
        case CRC_KERMIT:
            generate_table(CRC16_POLY_CCITT, true);
            break;
        case CRC_FELICA:
        case CRC_XMODEM:
        case CRC_CCITT:
        case CRC_11784:
        case CRC_PHILIPS:
            generate_table(CRC16_POLY_CCITT, false);
            break;
        case CRC_LEGIC:
            generate_table(CRC16_POLY_LEGIC, true);
            break;
        case CRC_LEGIC_16:
            generate_table(CRC16_POLY_LEGIC_16, true);
            break;
        case CRC_NONE:
            crc_table_init = false;
            current_crc_type = CRC_NONE;
            break;
    }
}

void generate_table(uint16_t polynomial, bool refin) {

    for (uint16_t i = 0; i < 256; i++) {
        uint16_t c, crc = 0;
        if (refin)
            c = reflect8(i) << 8;
        else
            c = i << 8;

        for (uint16_t j = 0; j < 8; j++) {

            if ((crc ^ c) & 0x8000)
                crc = (crc << 1) ^ polynomial;
            else
                crc =   crc << 1;

            c = c << 1;
        }
        if (refin)
            crc = reflect16(crc);

        crc_table[i] = crc;
    }
    crc_table_init = true;
}

void reset_table(void) {
    memset(crc_table, 0, sizeof(crc_table));
    crc_table_init = false;
    current_crc_type = CRC_NONE;
}

// table lookup LUT solution
uint16_t crc16_fast(uint8_t const *d, size_t n, uint16_t initval, bool refin, bool refout) {

    // fast lookup table algorithm without augmented zero bytes, e.g. used in pkzip.
    // only usable with polynom orders of 8, 16, 24 or 32.
    if (n == 0)
        return (~initval);

    uint16_t crc = initval;

    if (refin)
        crc = reflect16(crc);

    if (!refin)
        while (n--) crc = (crc << 8) ^ crc_table[((crc >> 8) ^ *d++) & 0xFF ];
    else
        while (n--) crc = (crc >> 8) ^ crc_table[(crc & 0xFF) ^ *d++];

    if (refout ^ refin)
        crc = reflect16(crc);

    return crc;
}

// bit looped solution  TODO REMOVED
uint16_t update_crc16_ex(uint16_t crc, uint8_t c, uint16_t polynomial) {
    uint16_t tmp = 0;
    uint16_t v = (crc ^ c) & 0xff;

    for (uint16_t i = 0; i < 8; i++) {

        if ((tmp ^ v) & 1)
            tmp = (tmp >> 1) ^ polynomial;
        else
            tmp >>= 1;

        v >>= 1;
    }
    return ((crc >> 8) ^ tmp) & 0xffff;
}
uint16_t update_crc16(uint16_t crc, uint8_t c) {
    return update_crc16_ex(crc, c, CRC16_POLY_CCITT);
}

// two ways.  msb or lsb loop.
uint16_t Crc16(uint8_t const *d, size_t length, uint16_t remainder, uint16_t polynomial, bool refin, bool refout) {
    if (length == 0)
        return (~remainder);

    for (uint32_t i = 0; i < length; ++i) {
        uint8_t c = d[i];
        if (refin) c = reflect8(c);

        // xor in at msb
        remainder ^= (c << 8);

        // 8 iteration loop
        for (uint8_t j = 8; j; --j) {
            if (remainder & 0x8000) {
                remainder = (remainder << 1) ^ polynomial;
            } else {
                remainder <<=  1;
            }
        }
    }
    if (refout)
        remainder = reflect16(remainder);

    return remainder;
}

void compute_crc(CrcType_t ct, const uint8_t *d, size_t n, uint8_t *first, uint8_t *second) {

    // can't calc a crc on less than 1 byte
    if (n == 0) return;

    init_table(ct);

    uint16_t crc = 0;
    switch (ct) {
        case CRC_14443_A:
            crc = crc16_a(d, n);
            break;
        case CRC_CRYPTORF:
        case CRC_14443_B:
        case CRC_15693:
            crc = crc16_x25(d, n);
            break;
        case CRC_ICLASS:
            crc = crc16_iclass(d, n);
            break;
        case CRC_FELICA:
        case CRC_XMODEM:
            crc = crc16_xmodem(d, n);
            break;
        case CRC_CCITT:
            crc = crc16_ccitt(d, n);
            break;
        case CRC_KERMIT:
            crc = crc16_kermit(d, n);
            break;
        case CRC_11784:
            crc = crc16_fdxb(d, n);
            break;
        case CRC_LEGIC:
        case CRC_LEGIC_16:
            // TODO
            return;
        case CRC_PHILIPS:
            crc = crc16_philips(d, n);
            break;
        case CRC_NONE:
            return;
    }
    *first = (crc & 0xFF);
    *second = ((crc >> 8) & 0xFF);
}
uint16_t Crc16ex(CrcType_t ct, const uint8_t *d, size_t n) {

    // can't calc a crc on less than 3 byte. (1byte + 2 crc bytes)
    if (n < 3) return 0;

    init_table(ct);
    switch (ct) {
        case CRC_14443_A:
            return crc16_a(d, n);
        case CRC_CRYPTORF:
        case CRC_14443_B:
        case CRC_15693:
            return crc16_x25(d, n);
        case CRC_ICLASS:
            return crc16_iclass(d, n);
        case CRC_FELICA:
        case CRC_XMODEM:
            return crc16_xmodem(d, n);
        case CRC_CCITT:
            return crc16_ccitt(d, n);
        case CRC_KERMIT:
            return crc16_kermit(d, n);
        case CRC_11784:
            return crc16_fdxb(d, n);
        case CRC_LEGIC:
        case CRC_LEGIC_16:
            // TODO
            return 0;
        case CRC_PHILIPS:
            return crc16_philips(d, n);
        case CRC_NONE:
        default:
            break;
    }
    return 0;
}

// check CRC
// ct   crc type
// d    buffer with data
// n    length (including crc)
//
//  This function uses the message + crc bytes in order to compare the "residue" afterwards.
// crc16 algos like CRC-A become 0x0000
// while CRC-15693 become 0x0F47
// If calculated with crc bytes,  the residue should be 0xF0B8
bool check_crc(CrcType_t ct, const uint8_t *d, size_t n) {

    // can't calc a crc on less than 3 byte. (1byte + 2 crc bytes)
    if (n < 3) return false;

    init_table(ct);

    switch (ct) {
        case CRC_14443_A:
            return (crc16_a(d, n) == 0);
        case CRC_CRYPTORF:
        case CRC_14443_B:
            return (crc16_x25(d, n) == X25_CRC_CHECK);
        case CRC_15693:
            return (crc16_x25(d, n) == X25_CRC_CHECK);
        case CRC_ICLASS:
            return (crc16_iclass(d, n) == 0);
        case CRC_FELICA:
        case CRC_XMODEM:
            return (crc16_xmodem(d, n) == 0);
        case CRC_CCITT:
            return (crc16_ccitt(d, n) == 0);
        case CRC_KERMIT:
            return (crc16_kermit(d, n) == 0);
        case CRC_11784:
            return (crc16_fdxb(d, n) == 0);
        case CRC_LEGIC:
        case CRC_LEGIC_16:
            // TODO
            return false;
        case CRC_PHILIPS:
            return (crc16_philips(d, n) == 0);
        case CRC_NONE:
        default:
            break;
    }
    return false;
}

// poly=0x1021  init=0xffff  refin=false  refout=false  xorout=0x0000  check=0x29b1  residue=0x0000  name="CRC-16/CCITT-FALSE"
uint16_t crc16_ccitt(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0xffff, false, false);
}

// FDX-B ISO11784/85) uses KERMIT/CCITT
// poly 0x xx  init=0x000  refin=false  refout=true  xorout=0x0000 ...
uint16_t crc16_fdxb(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0x0000, false, true);
}

// poly=0x1021  init=0x0000  refin=true  refout=true  xorout=0x0000 name="KERMIT"
uint16_t crc16_kermit(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0x0000, true, true);
}

// FeliCa uses XMODEM
// poly=0x1021  init=0x0000  refin=false  refout=false  xorout=0x0000 name="XMODEM"
uint16_t crc16_xmodem(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0x0000, false, false);
}

// Following standards uses X-25
//   ISO 15693,
//   ISO 14443 CRC-B
//   ISO/IEC 13239 (formerly ISO/IEC 3309)
// poly=0x1021  init=0xffff  refin=true  refout=true  xorout=0xffff name="X-25"
uint16_t crc16_x25(uint8_t const *d, size_t n) {
    uint16_t crc = crc16_fast(d, n, 0xffff, true, true);
    crc = ~crc;
    return crc;
}
// CRC-A (14443-3)
// poly=0x1021 init=0xc6c6 refin=true refout=true xorout=0x0000 name="CRC-A"
uint16_t crc16_a(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0xC6C6, true, true);
}

// iClass crc
// initvalue  0x4807 reflected 0xE012
// poly       0x1021 reflected 0x8408
// poly=0x1021  init=0x4807  refin=true  refout=true  xorout=0x0BC3  check=0xF0B8  name="CRC-16/ICLASS"
uint16_t crc16_iclass(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0x4807, true, true);
}

// This CRC-16 is used in Legic Advant systems.
// poly=0xB400,  init=depends  refin=true  refout=true  xorout=0x0000  check=  name="CRC-16/LEGIC"
uint16_t crc16_legic(uint8_t const *d, size_t n, uint8_t uidcrc) {
    uint16_t initial = (uidcrc << 8 | uidcrc);
    return crc16_fast(d, n, initial, true, false);
}

uint16_t crc16_philips(uint8_t const *d, size_t n) {
    return crc16_fast(d, n, 0x49A3, false, false);
}
