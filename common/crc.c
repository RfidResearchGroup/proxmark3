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
// Generic CRC calculation code.
//-----------------------------------------------------------------------------
// the Check value below in the comments is CRC of the string '123456789'
//
#include "crc.h"

#include "commonutil.h"

void crc_init_ref(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor, bool refin, bool refout) {
    crc_init(crc, order, polynom, initial_value, final_xor);
    crc->refin = refin;
    crc->refout = refout;
    crc_clear(crc);
}

void crc_init(crc_t *crc, int order, uint32_t polynom, uint32_t initial_value, uint32_t final_xor) {
    crc->order = order;
    crc->topbit = BITMASK(order - 1);
    crc->polynom = polynom;
    crc->initial_value = initial_value;
    crc->final_xor = final_xor;
    crc->mask = (1L << order) - 1;
    crc->refin = false;
    crc->refout = false;
    crc_clear(crc);
}

void crc_clear(crc_t *crc) {

    crc->state = crc->initial_value & crc->mask;
    if (crc->refin)
        crc->state = reflect(crc->state, crc->order);
}

void crc_update2(crc_t *crc, uint32_t data, int data_width) {

    if (crc->refin)
        data = reflect(data, data_width);

    // Bring the next byte into the remainder.
    crc->state ^= data << (crc->order - data_width);

    for (uint8_t bit = data_width; bit > 0; --bit) {

        if (crc->state & crc->topbit)
            crc->state = (crc->state << 1) ^ crc->polynom;
        else
            crc->state = (crc->state << 1);
    }
}

void crc_update(crc_t *crc, uint32_t data, int data_width) {
    if (crc->refin)
        data = reflect(data, data_width);

    int i;
    for (i = 0; i < data_width; i++) {
        int oldstate = crc->state;
        crc->state = crc->state >> 1;
        if ((oldstate ^ data) & 1) {
            crc->state ^= crc->polynom;
        }
        data >>= 1;
    }
}

uint32_t crc_finish(crc_t *crc) {
    uint32_t val = crc->state;
    if (crc->refout)
        val = reflect(val, crc->order);
    return (val ^ crc->final_xor) & crc->mask;
}

/*
static void print_crc(crc_t *crc) {
    printf(" Order  %d\n Poly   %x\n Init   %x\n Final  %x\n Mask   %x\n topbit %x\n RefIn  %s\n RefOut %s\n State  %x\n",
        crc->order,
        crc->polynom,
        crc->initial_value,
        crc->final_xor,
        crc->mask,
        crc->topbit,
        (crc->refin) ? "TRUE":"FALSE",
        (crc->refout) ? "TRUE":"FALSE",
        crc->state
    );
}
*/

// width=8  poly=0x31  init=0x00  refin=true  refout=true  xorout=0x00  check=0xA1  name="CRC-8/MAXIM"
uint32_t CRC8Maxim(uint8_t *buff, size_t size) {
    crc_t crc;
    crc_init_ref(&crc, 8, 0x31, 0, 0, true, true);
    for (size_t i = 0; i < size; ++i) {
        crc_update2(&crc, buff[i], 8);
    }
    return crc_finish(&crc);
}
// width=8 poly=0x1d, init=0xc7 (0xe3 - WRONG! but it mentioned in MAD datasheet) refin=false  refout=false  xorout=0x00 name="CRC-8/MIFARE-MAD"
uint32_t CRC8Mad(uint8_t *buff, size_t size) {
    crc_t crc;
    crc_init_ref(&crc, 8, 0x1d, 0xc7, 0, false, false);
    for (size_t i = 0; i < size; ++i) {
        crc_update2(&crc, buff[i], 8);
    }
    return crc_finish(&crc);
}
// width=4  poly=0xC, reversed poly=0x7  init=0x5   refin=true  refout=true  xorout=0x0000  check=  name="CRC-4/LEGIC"
uint32_t CRC4Legic(uint8_t *buff, size_t size) {
    crc_t crc;
    crc_init_ref(&crc, 4, 0x19 >> 1, 0x5, 0, true, true);
    crc_update2(&crc, 1, 1); /* CMD_READ */
    crc_update2(&crc, buff[0], 8);
    crc_update2(&crc, buff[1], 8);
    return reflect(crc_finish(&crc), 4);
}
// width=8  poly=0x63, reversed poly=0x8D  init=0x55  refin=true  refout=true  xorout=0x0000  check=0xC6  name="CRC-8/LEGIC"
// the CRC needs to be reversed before returned.
uint32_t CRC8Legic(uint8_t *buff, size_t size) {
    crc_t crc;
    crc_init_ref(&crc, 8, 0x63, 0x55, 0, true, true);
    for (size_t i = 0; i < size; ++i) {
        crc_update2(&crc, buff[i], 8);
    }
    return reflect8(crc_finish(&crc));
}
// width=8  poly=0x7, init=0x2C  refin=false  refout=false  xorout=0x0000  check=0 name="CRC-8/CARDX"
uint32_t CRC8Cardx(uint8_t *buff, size_t size) {
    crc_t crc;
    crc_init_ref(&crc, 8, 0x7, 0x2C, 0, false, false);
    for (size_t i = 0; i < size; ++i) {
        crc_update2(&crc, buff[i], 8);
    }
    return crc_finish(&crc);
}

uint32_t CRC8Hitag1(uint8_t *buff, size_t size) {
    crc_t crc;
    crc_init_ref(&crc, 8, 0x1d, 0xff, 0, false, false);
    for (size_t i = 0; i < size; i++) {
        crc_update2(&crc, buff[i], 8);
    }
    return crc_finish(&crc);
}

uint32_t CRC8Hitag1Bits(const uint8_t *buff, size_t bitsize) {
    crc_t crc;
    uint8_t data = 0;
    uint8_t n = 0;
    crc_init_ref(&crc, 8, 0x1d, 0xff, 0, false, false);
    size_t i;
    for (i = 0; i < bitsize; i++) {
        data <<= 1;
        data += (buff[i / 8] >> (7 - (i % 8))) & 1;
        n += 1;
        if (n == 8) {
            crc_update2(&crc, data, n);
            n = 0;
            data = 0;
        }
    }
    if (n > 0) {
        crc_update2(&crc, data, n);
    }
    return crc_finish(&crc);
}
