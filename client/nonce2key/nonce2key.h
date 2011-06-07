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

#ifndef __NONCE2KEY_H
#define __NONCE2KEY_H

#include <inttypes.h>
#include <stdio.h>
#include "crapto1.h"

typedef unsigned char byte_t;

int nonce2key(uint32_t uid, uint32_t nt, uint64_t par_info, uint64_t ks_info, uint64_t * key); 

#endif
