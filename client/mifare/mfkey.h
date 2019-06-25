//-----------------------------------------------------------------------------
// Merlok - June 2011
// Roel - Dec 2009
// Unknown author
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE Darkside hack
//-----------------------------------------------------------------------------

#ifndef MFKEY_H
#define MFKEY_H

#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include "mifare.h"
#include "crapto1/crapto1.h"

uint32_t nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint32_t ar, uint64_t par_info, uint64_t ks_info, uint64_t **keys);
bool mfkey32(nonces_t data, uint64_t *outputkey);
bool mfkey32_moebius(nonces_t data, uint64_t *outputkey);
int mfkey64(nonces_t data, uint64_t *outputkey);

int compare_uint64(const void *a, const void *b);
uint32_t intersection(uint64_t *listA, uint64_t *listB);

#endif
