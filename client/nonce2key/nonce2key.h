//-----------------------------------------------------------------------------
// Merlok - June 2011
// Roel - Dec 2009
// Unknown author
// iceman - may 2015
// marshmellow42 - june 2016
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
#include "mifare.h" 	// nonces_t struct
#include "ui.h"			// PrintAndLog
#include "proxmark3.h"
#include "mifarehost.h"

extern int nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint64_t par_info, uint64_t ks_info, uint64_t * key); 
extern int nonce2key_ex(uint8_t blockno, uint8_t keytype, uint32_t uid, uint32_t nt, uint32_t nr, uint64_t ks_info, uint64_t * key);

//iceman, added these to be able to crack key direct from "hf 14 sim" && "hf mf sim"
bool tryMfk32(nonces_t data, uint64_t *outputkey );
bool tryMfk32_moebius(nonces_t data, uint64_t *outputkey );  // <<-- this one has best success
int tryMfk64_ex(uint8_t *data, uint64_t *outputkey );
int tryMfk64(uint32_t uid, uint32_t nt, uint32_t nr_enc, uint32_t ar_enc, uint32_t at_enc, uint64_t *outputkey);
#endif
