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
#include <stddef.h>

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

typedef struct {
    size_t bin_len;
    char binstr[145];
    bool packed_valid;        // False when the input has a valid bitstring but no packed HID transport form.
    wiegand_message_t packed; // HID transport words used by LF/HID-oriented callers.
} wiegand_input_t;

uint8_t get_bit_by_position(const wiegand_message_t *data, uint8_t pos);
bool set_bit_by_position(wiegand_message_t *data, bool value, uint8_t pos);

uint64_t get_linear_field(const wiegand_message_t *data, uint8_t firstBit, uint8_t length);
bool set_linear_field(wiegand_message_t *data, uint64_t value, uint8_t firstBit, uint8_t length);

uint64_t get_nonlinear_field(const wiegand_message_t *data, uint8_t numBits, const uint8_t *bits);
bool set_nonlinear_field(wiegand_message_t *data, uint64_t value, uint8_t numBits, const uint8_t *bits);

wiegand_message_t initialize_message_object(uint32_t top, uint32_t mid, uint32_t bot, int n);

uint8_t get_length_from_header(const wiegand_message_t *data);
bool add_HID_header(wiegand_message_t *data);

// Render a packed Wiegand message as a plain payload bitstring without HID transport framing.
bool wiegand_message_to_binstr(const wiegand_message_t *packed, char *binstr, size_t binstr_size);

// Decode raw HID transport bytes into a plain Wiegand payload bitstring.
bool wiegand_raw_to_binstr(const uint8_t *raw, size_t raw_len, char *binstr, size_t binstr_size);

// Decode the ASN.1 PACS form emitted by `wiegand encode --new` into a plain payload bitstring.
bool wiegand_new_pacs_to_binstr(const uint8_t *pacs, size_t pacs_len, char *binstr, size_t binstr_size);

// Validate and store a caller-provided binary Wiegand payload without attempting transport packing.
int wiegand_set_plain_binstr(const char *binstr, wiegand_input_t *input);

// Decode ASN.1 PACS input into the normalized binary representation used by downstream callers.
int wiegand_set_new_pacs_binstr(const uint8_t *pacs, size_t pacs_len, wiegand_input_t *input);

// Build HID transport words from a plain Wiegand payload, including sentinel placement and headers.
int wiegand_pack_bin_with_hid_header(const char *binstr, wiegand_message_t *packed);

// Encode a card-format struct through the existing HID formatter and return packed transport words.
int wiegand_pack_formatted(int format_idx, wiegand_card_t *card, bool preamble, wiegand_message_t *packed);

// Normalize ASN.1 PACS input and, when possible, also derive HID transport words for LF/HID callers.
int wiegand_pack_from_new_pacs(const uint8_t *pacs, size_t pacs_len, wiegand_input_t *input);

// Normalize plain binary input and, when possible, also derive HID transport words for LF/HID callers.
int wiegand_pack_from_plain_bin(const char *binstr, wiegand_input_t *input);

// Normalize formatted card data into both payload bits and packed transport words.
int wiegand_pack_from_formatted(int format_idx, wiegand_card_t *card, bool preamble, wiegand_input_t *input);

// Preserve legacy raw HID transport input while also exposing the decoded payload bitstring.
int wiegand_pack_from_raw_hid(const uint8_t *raw, size_t raw_len, wiegand_input_t *input);

#endif
