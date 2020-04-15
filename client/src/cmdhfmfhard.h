//-----------------------------------------------------------------------------
// Copyright (C) 2015 piwi
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// hf mf hardnested command
//-----------------------------------------------------------------------------

#ifndef CMDHFMFHARD_H__
#define CMDHFMFHARD_H__

#include "common.h"

int mfnestedhard(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *trgkey, bool nonce_file_read, bool nonce_file_write, bool slow, int tests, uint64_t *foundkey, char *filename);
void hardnested_print_progress(uint32_t nonces, const char *activity, float brute_force, uint64_t min_diff_print_time);

#endif

