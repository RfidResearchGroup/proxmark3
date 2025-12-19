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
// Polling Loop Annotations (PLA) and Enhanced Contactless Polling (ECP) utilities
//-----------------------------------------------------------------------------

#ifndef PLA_H__
#define PLA_H__

#include "common.h"
#include <jansson.h>

// Load ecplist.json file
json_t *pla_load_ecplist(void);

// Search ecplist for an entry matching the given type, subtype and/or key
// If type is not NULL, only search entries with matching "type" field (supports string or array)
// If subtype is not NULL, searches in "subtype" field (supports string or array)
// If key is not NULL, searches in "key" field (supports string or array)
json_t *pla_search_ecplist_by_key(json_t *root, const char *type, const char *subtype, const char *key);

// Parse ECP (Enhanced Contactless Polling) subcommands
// Returns the length of the generated frame (without CRC), or -1 on error
int pla_parse_ecp_subcommand(const char *cmd, uint8_t *frame, size_t frame_size);

#endif
