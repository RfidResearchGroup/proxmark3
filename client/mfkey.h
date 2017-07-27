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

#include <stdint.h>
#include <stdbool.h>
#include "mifare.h"

extern bool mfkey32(nonces_t data, uint64_t *outputkey);
extern bool mfkey32_moebius(nonces_t data, uint64_t *outputkey);
extern int mfkey64(nonces_t data, uint64_t *outputkey);

#endif
