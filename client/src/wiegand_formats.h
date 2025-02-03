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
// Wiegand format packing/unpacking routines
//-----------------------------------------------------------------------------

#ifndef WIEGAND_FORMATS_H__
#define WIEGAND_FORMATS_H__

#include <string.h>    // memset
#include <stdbool.h>
#include <stdint.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include "cmddata.h"
#include "wiegand_formatutils.h"
#include "parity.h" // for parity
#include "ui.h"

typedef struct {
    bool hasCardNumber;
    bool hasFacilityCode;
    bool hasIssueLevel;
    bool hasOEMCode;
    bool hasParity;
} cardformatdescriptor_t;

typedef struct {
    uint32_t FacilityCode;
    uint64_t CardNumber;
    uint32_t IssueLevel;
    uint32_t OEM;
} cardformatlimit_t;

// Structure for defined Wiegand card formats available for packing/unpacking
typedef struct {
    const char *Name;
    bool (*Pack)(wiegand_card_t *card, wiegand_message_t *packed, bool preamble);
    bool (*Unpack)(wiegand_message_t *packed, wiegand_card_t *card);
    const char *Descrp;
    cardformatdescriptor_t Fields;
    cardformatlimit_t FieldLimits;
} cardformat_t;

void HIDListFormats(void);
int HIDFindCardFormat(const char *format);
cardformat_t HIDGetCardFormat(int idx);
bool HIDPack(int format_idx, wiegand_card_t *card, wiegand_message_t *packed, bool preamble);
bool HIDTryUnpack(wiegand_message_t *packed);
void HIDPackTryAll(wiegand_card_t *card, bool preamble);
void HIDUnpack(int idx, wiegand_message_t *packed);
void print_wiegand_code(wiegand_message_t *packed);
void print_desc_wiegand(cardformat_t *fmt, wiegand_message_t *packed);
cardformatlimit_t get_card_format_limit(int format_idx);
#endif
