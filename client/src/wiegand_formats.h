//-----------------------------------------------------------------------------
// Copyright (C) 2018 grauerfuchs
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

// Structure for defined Wiegand card formats available for packing/unpacking
typedef struct {
    const char *Name;
    bool (*Pack)(wiegand_card_t *card, wiegand_message_t *packed);
    bool (*Unpack)(wiegand_message_t *packed, wiegand_card_t *card);
    const char *Descrp;
    cardformatdescriptor_t Fields;
} cardformat_t;

void HIDListFormats();
int HIDFindCardFormat(const char *format);
cardformat_t HIDGetCardFormat(int idx);
bool HIDPack(int format_idx, wiegand_card_t *card, wiegand_message_t *packed);
bool HIDTryUnpack(wiegand_message_t *packed, bool ignore_parity);

#endif
