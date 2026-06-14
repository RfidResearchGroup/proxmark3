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
// Shared MIFARE Prime helpers for ISO-DEP based MIFARE protocols
//-----------------------------------------------------------------------------

#ifndef MIFARE_PRIME_H
#define MIFARE_PRIME_H

#include "common.h"

const char *mifare_prime_get_card_size_str(uint8_t fsize);
const char *mifare_prime_get_protocol_str(uint8_t id, bool hw);
const char *mifare_prime_get_version_str(uint8_t type, uint8_t major, uint8_t minor);
const char *mifare_prime_get_type_str(uint8_t type);

#endif // MIFARE_PRIME_H
