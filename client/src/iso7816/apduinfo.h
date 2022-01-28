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
// APDU status bytes information
//-----------------------------------------------------------------------------

#ifndef APDUINFO_H__
#define APDUINFO_H__

#include "common.h"

#define APDUCODE_TYPE_NONE     0
#define APDUCODE_TYPE_INFO     1
#define APDUCODE_TYPE_WARNING  2
#define APDUCODE_TYPE_ERROR    3
#define APDUCODE_TYPE_SECURITY 4

#define APDU_INCLUDE_LE_00     0x100

typedef struct {
    const char *ID;
    const uint8_t Type;
    const char *Description;
} APDUCode_t;

const APDUCode_t *GetAPDUCode(uint8_t sw1, uint8_t sw2);
const char *GetAPDUCodeDescription(uint8_t sw1, uint8_t sw2);

typedef struct {
    const uint16_t Code;
    const char *Description;
} APDUSpcCodeDescription_t;

const char *GetSpecificAPDUCodeDesc(const APDUSpcCodeDescription_t *desc, const size_t desclen, uint16_t code);

typedef struct {
    uint8_t CLA;
    uint8_t INS;
    uint8_t P1;
    uint8_t P2;
    uint8_t Lc;
    uint8_t *data;
} PACKED sAPDU_t;

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc[3];
} PACKED ExtAPDUHeader_t;

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint16_t lc;
    uint8_t *data;
    uint32_t le;
    bool extended_apdu;
    uint8_t case_type;
} PACKED APDU_t;

extern int APDUDecode(uint8_t *data, int len, APDU_t *apdu);
extern int APDUEncode(APDU_t *apdu, uint8_t *data, int *len);
extern int APDUEncodeS(sAPDU_t *sapdu, bool extended, uint16_t le, uint8_t *data, int *len);
extern void APDUPrint(APDU_t apdu);
extern void APDUPrintEx(APDU_t apdu, size_t maxdatalen);

void SAPDUPrint(sAPDU_t apdu, size_t maxdatalen);
#endif
