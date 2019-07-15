//-----------------------------------------------------------------------------
// Copyright (C) 2017 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// APDU status bytes information
//-----------------------------------------------------------------------------

#ifndef APDUINFO_H__
#define APDUINFO_H__

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <inttypes.h>

#define APDUCODE_TYPE_NONE     0
#define APDUCODE_TYPE_INFO     1
#define APDUCODE_TYPE_WARNING  2
#define APDUCODE_TYPE_ERROR    3
#define APDUCODE_TYPE_SECURITY 4

typedef struct {
    const char *ID;
    const uint8_t Type;
    const char *Description;
} APDUCode;

const APDUCode *GetAPDUCode(uint8_t sw1, uint8_t sw2);
const char *GetAPDUCodeDescription(uint8_t sw1, uint8_t sw2);

typedef struct {
    uint8_t cla;
    uint8_t ins;
    uint8_t p1;
    uint8_t p2;
    uint8_t lc[3];
} __attribute__((packed)) ExtAPDUHeader;

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
} __attribute__((packed)) APDUStruct;

extern int APDUDecode(uint8_t *data, int len, APDUStruct *apdu);
extern int APDUEncode(APDUStruct *apdu, uint8_t *data, int *len);
extern void APDUPrint(APDUStruct apdu);

#endif
