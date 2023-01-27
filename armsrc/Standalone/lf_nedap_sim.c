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
// This simple mode encode, then emulate a Nedap identificator until button pressed
// lots of code from client side, cmdlfnedap, util, etc.
//-----------------------------------------------------------------------------
#include "standalone.h" // standalone definitions
#include "proxmark3_arm.h"
#include "appmain.h"
#include "fpgaloader.h"
#include "lfops.h"
#include "util.h"
#include "dbprint.h"
#include "string.h"
#include "BigBuf.h"
#include "crc16.h"

#define MODULE_LONG_NAME    "LF Nedap simple simulator"

typedef struct _NEDAP_TAG {
    uint8_t subType;
    uint16_t customerCode;
    uint32_t id;

    uint8_t bIsLong;
} NEDAP_TAG, *PNEDAP_TAG;

const NEDAP_TAG Tag = {.subType = 0x5, .customerCode = 0x123, .id = 42424, .bIsLong = 1};

static int NedapPrepareBigBuffer(const NEDAP_TAG *pTag);
static void biphaseSimBitInverted(uint8_t c, int *n, uint8_t *phase);
static void NedapGen(uint8_t subType, uint16_t customerCode, uint32_t id, bool isLong, uint8_t *data);
static uint8_t isEven_64_63(const uint8_t *data);
static inline uint32_t bitcount32(uint32_t a);
static void bytes_to_bytebits(const void *src, const size_t srclen, void *dest);

void ModInfo(void) {
    DbpString("  " MODULE_LONG_NAME);
}

void RunMod(void) {
    int n;

    StandAloneMode();

    Dbprintf("[=] " MODULE_LONG_NAME " -- started");
    FpgaDownloadAndGo(FPGA_BITSTREAM_LF);
    Dbprintf("[=] NEDAP (%s) - ID: " _GREEN_("%05u") " subtype: " _GREEN_("%1u") " customer code: " _GREEN_("%u / 0x%03X"), Tag.bIsLong ? "128b" : "64b", Tag.id, Tag.subType, Tag.customerCode, Tag.customerCode);

    n = NedapPrepareBigBuffer(&Tag);
    do {
        WDT_HIT();

        if (data_available())
            break;

        SimulateTagLowFrequency(n, 0, true);

    } while (BUTTON_HELD(1000) == BUTTON_NO_CLICK);

    Dbprintf("[=] " MODULE_LONG_NAME " -- exiting");

    LEDsoff();
}

static int NedapPrepareBigBuffer(const NEDAP_TAG *pTag) {
    int ret = 0;
    uint8_t data[16], bitStream[sizeof(data) * 8], phase = 0;
    uint16_t i, size = pTag->bIsLong ? sizeof(data) : (sizeof(data) / 2);

    NedapGen(pTag->subType, pTag->customerCode, pTag->id, pTag->bIsLong, data);
    bytes_to_bytebits(data, size, bitStream);
    size <<= 3;

    for (i = 0; i < size; i++) {
        biphaseSimBitInverted(!bitStream[i], &ret, &phase);
    }
    if (phase == 1) { //run a second set inverted to keep phase in check
        for (i = 0; i < size; i++) {
            biphaseSimBitInverted(!bitStream[i], &ret, &phase);
        }
    }

    return ret;
}

static void biphaseSimBitInverted(uint8_t c, int *n, uint8_t *phase) {
    uint8_t *dest = BigBuf_get_addr();

    if (c) {
        memset(dest + (*n), c ^ 1 ^ *phase, 32);
        memset(dest + (*n) + 32, c ^ *phase, 32);
    } else {
        memset(dest + (*n), c ^ *phase, 64);
        *phase ^= 1;
    }
    *n += 64;
}

#define FIXED_71    0x71
#define FIXED_40    0x40
#define UNKNOWN_A   0x00
#define UNKNOWN_B   0x00
static const uint8_t translateTable[10] = {8, 2, 1, 12, 4, 5, 10, 13, 0, 9};
static void NedapGen(uint8_t subType, uint16_t customerCode, uint32_t id, bool isLong, uint8_t *data) { // 8 or 16
    uint8_t buffer[7];

    uint8_t r1 = (uint8_t)(id / 10000);
    uint8_t r2 = (uint8_t)((id % 10000) / 1000);
    uint8_t r3 = (uint8_t)((id % 1000) / 100);
    uint8_t r4 = (uint8_t)((id % 100) / 10);
    uint8_t r5 = (uint8_t)(id % 10);

    // first part
    uint8_t idxC1 = r1;
    uint8_t idxC2 = (idxC1 + 1 + r2) % 10;
    uint8_t idxC3 = (idxC2 + 1 + r3) % 10;
    uint8_t idxC4 = (idxC3 + 1 + r4) % 10;
    uint8_t idxC5 = (idxC4 + 1 + r5) % 10;

    buffer[0] = 0xc0 | (subType & 0x0F);
    buffer[1] = (customerCode & 0x0FF0) >> 4;
    buffer[2] = ((customerCode & 0x000F) << 4) | translateTable[idxC1];
    buffer[3] = (translateTable[idxC2] << 4) | translateTable[idxC3];
    buffer[4] = (translateTable[idxC4] << 4) | translateTable[idxC5];

    // checksum
    init_table(CRC_XMODEM);
    uint16_t checksum = crc16_xmodem(buffer, 5);

    buffer[6] = ((checksum & 0x000F) << 4) | (buffer[4] & 0x0F);
    buffer[5] = (checksum & 0x00F0) | ((buffer[4] & 0xF0) >> 4);
    buffer[4] = ((checksum & 0x0F00) >> 4) | (buffer[3] & 0x0F);
    buffer[3] = ((checksum & 0xF000) >> 8) | ((buffer[3] & 0xF0) >> 4);

    // carry calc
    uint8_t carry = 0;
    for (uint8_t i = 0; i < sizeof(buffer); i++) {
        uint8_t tmp = buffer[sizeof(buffer) - 1 - i];
        data[7 - i] = ((tmp & 0x7F) << 1) | carry;
        carry = (tmp & 0x80) >> 7;
    }
    data[0] = 0xFE | carry;
    data[7] |= isEven_64_63(data);

    // second part
    if (isLong) {
        uint8_t id0 = r1;
        uint8_t id1 = (r2 << 4) | r3;
        uint8_t id2 = (r4 << 4) | r5;

        data[8] = (id2 >> 1);
        data[9] = ((id2 & 0x01) << 7) | (id1 >> 2);
        data[10] = ((id1 & 0x03) << 6) | (id0 >> 3);
        data[11] = ((id0 & 0x07) << 5) | (FIXED_71 >> 4);
        data[12] = ((FIXED_71 & 0x0F) << 4) | (FIXED_40 >> 5);
        data[13] = ((FIXED_40 & 0x1F) << 3) | (UNKNOWN_A >> 6);
        data[14] = ((UNKNOWN_A & 0x3F) << 2) | (UNKNOWN_B >> 7);
        data[15] = ((UNKNOWN_B & 0x7F) << 1);
        data[15] |= isEven_64_63(data + 8);
    }
}

static uint8_t isEven_64_63(const uint8_t *data) { // 8
    uint32_t tmp[2];
    memcpy(tmp, data, 8);
    return (bitcount32(tmp[0]) + (bitcount32(tmp[1] & 0xfeffffff))) & 1;
}

static void bytes_to_bytebits(const void *src, const size_t srclen, void *dest) {
    uint8_t *s = (uint8_t *)src, *d = (uint8_t *)dest;
    size_t i = srclen * 8, j = srclen;

    while (j--) {
        uint8_t b = s[j];
        d[--i] = (b >> 0) & 1;
        d[--i] = (b >> 1) & 1;
        d[--i] = (b >> 2) & 1;
        d[--i] = (b >> 3) & 1;
        d[--i] = (b >> 4) & 1;
        d[--i] = (b >> 5) & 1;
        d[--i] = (b >> 6) & 1;
        d[--i] = (b >> 7) & 1;
    }
}

static inline uint32_t bitcount32(uint32_t a) {
#if defined __GNUC__
    return __builtin_popcountl(a);
#else
    a = a - ((a >> 1) & 0x55555555);
    a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
    return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
#endif
}
