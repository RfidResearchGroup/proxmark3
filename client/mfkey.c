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
#include "mfkey.h"
#include "crapto1/crapto1.h"

// recover key from 2 different reader responses on same tag challenge
bool mfkey32(nonces_t data, uint64_t *outputkey) {
	struct Crypto1State *s,*t;
	uint64_t outkey = 0;
	uint64_t key = 0;     // recovered key
	bool isSuccess = false;
	uint8_t counter = 0;

	s = lfsr_recovery32(data.ar ^ prng_successor(data.nonce, 64), 0);

	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, data.nr, 1);
		lfsr_rollback_word(t, data.cuid ^ data.nonce, 0);
		crypto1_get_lfsr(t, &key);
		crypto1_word(t, data.cuid ^ data.nonce, 0);
		crypto1_word(t, data.nr2, 1);
		if (data.ar2 == (crypto1_word(t, 0, 0) ^ prng_successor(data.nonce, 64))) {
			outkey = key;
			counter++;
			if (counter == 20) break;
		}
	}
	isSuccess = (counter == 1);
	*outputkey = ( isSuccess ) ? outkey : 0;
	crypto1_destroy(s);
	return isSuccess;
}

// recover key from 2 reader responses on 2 different tag challenges
bool mfkey32_moebius(nonces_t data, uint64_t *outputkey) {
	struct Crypto1State *s, *t;
	uint64_t outkey  = 0;
	uint64_t key 	   = 0;			// recovered key
	bool isSuccess = false;
	int counter = 0;
	
	s = lfsr_recovery32(data.ar ^ prng_successor(data.nonce, 64), 0);
  
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, data.nr, 1);
		lfsr_rollback_word(t, data.cuid ^ data.nonce, 0);
		crypto1_get_lfsr(t, &key);
		
		crypto1_word(t, data.cuid ^ data.nonce2, 0);
		crypto1_word(t, data.nr2, 1);
		if (data.ar2 == (crypto1_word(t, 0, 0) ^ prng_successor(data.nonce2, 64))) {
			outkey=key;
			++counter;
			if (counter==20)
				break;
		}
	}
	isSuccess	= (counter == 1);
	*outputkey = ( isSuccess ) ? outkey : 0;
	crypto1_destroy(s);
	return isSuccess;
}

// recover key from reader response and tag response of one authentication sequence
int mfkey64(nonces_t data, uint64_t *outputkey){
	uint64_t key 	= 0;				// recovered key
	uint32_t ks2;     					// keystream used to encrypt reader response
	uint32_t ks3;     					// keystream used to encrypt tag response
	struct Crypto1State *revstate;
	
	// Extract the keystream from the messages
	ks2 = data.ar ^ prng_successor(data.nonce, 64);
	ks3 = data.at ^ prng_successor(data.nonce, 96);
	revstate = lfsr_recovery64(ks2, ks3);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, data.nr, 1);
	lfsr_rollback_word(revstate, data.cuid ^ data.nonce, 0);
	crypto1_get_lfsr(revstate, &key);
	crypto1_destroy(revstate);
	*outputkey = key;	
	return 0;
}


