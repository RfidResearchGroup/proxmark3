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
// HID PACS parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#ifndef PARSEHID_H__
#define PARSEHID_H__

#include "common.h"

// MAD application id the HID Global access control scheme claims
#define HID_MAD_AID     0x484d

// True when the MAD of this dump advertises the HID application
bool is_valid_hid_card(const uint8_t *dump, size_t dumplen);

// Decode the HID PACS credential out of a whole card dump and print it
int hid_parser_parse(const uint8_t *dump, size_t dumplen);

#endif
