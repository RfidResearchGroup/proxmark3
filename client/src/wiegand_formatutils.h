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
// Weigand card format packing/unpacking support functions
//-----------------------------------------------------------------------------

#ifndef WIEGAND_FORMATUTILS_H__
#define WIEGAND_FORMATUTILS_H__

#include <stdarg.h>
#include <stdint.h>
#include <stdbool.h>

// Structure for packed wiegand messages
// Always align lowest value (last transmitted) bit to ordinal position 0 (lowest valued bit bottom)
typedef struct {
    uint8_t Length;   // Number of encoded bits in wiegand message (excluding headers and preamble)
    uint32_t Top;     // Bits in x<<64 positions
    uint32_t Mid;     // Bits in x<<32 positions
    uint32_t Bot;     // Lowest ordinal positions
} wiegand_message_t;

// Structure for unpacked wiegand card, like HID prox
typedef struct {
    uint32_t FacilityCode;
    uint64_t CardNumber;
    uint32_t IssueLevel;
    uint32_t OEM;
    bool ParityValid; // Only valid for responses
} wiegand_card_t;

uint8_t get_bit_by_position(wiegand_message_t *data, uint8_t pos);
bool set_bit_by_position(wiegand_message_t *data, bool value, uint8_t pos);

uint64_t get_linear_field(wiegand_message_t *data, uint8_t firstBit, uint8_t length);
bool set_linear_field(wiegand_message_t *data, uint64_t value, uint8_t firstBit, uint8_t length);

uint64_t get_nonlinear_field(wiegand_message_t *data, uint8_t numBits, uint8_t *bits);
bool set_nonlinear_field(wiegand_message_t *data, uint64_t value, uint8_t numBits, uint8_t *bits);

wiegand_message_t initialize_message_object(uint32_t top, uint32_t mid, uint32_t bot, int n);

bool add_HID_header(wiegand_message_t *data);

#endif
