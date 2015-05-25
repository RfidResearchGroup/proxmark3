//-----------------------------------------------------------------------------
// Merlok - June 2011
// Roel - Dec 2009
// Unknown author
// icemane - may 2015
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE Darkside hack
//-----------------------------------------------------------------------------

#ifndef __NONCE2KEY_H
#define __NONCE2KEY_H

#include <stdio.h>
#include <stdlib.h>
#include "crapto1.h"
#include "common.h"

int nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint64_t par_info, uint64_t ks_info, uint64_t * key); 
int tryMfk32(uint64_t myuid, uint8_t *data, uint8_t *outputkey );
int tryMfk64(uint64_t myuid, uint8_t *data, uint8_t *outputkey );
#endif
