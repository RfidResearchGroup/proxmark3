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
// hf mf hardnested command
//-----------------------------------------------------------------------------

#ifndef CMDHFMFHARD_H__
#define CMDHFMFHARD_H__

#include "common.h"

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *trgkey, bool nonce_file_read, bool nonce_file_write, bool slow, int tests, uint64_t *foundkey, char *filename);
void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force, uint64_t min_diff_print_time);

#endif

