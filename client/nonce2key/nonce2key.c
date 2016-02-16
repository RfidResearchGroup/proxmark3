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
#include "nonce2key.h"
#include "mifarehost.h"
#include "ui.h"
#include "proxmark3.h"

int nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint64_t par_info, uint64_t ks_info, uint64_t * key) {


	struct Crypto1State *state;
	uint32_t i, pos, rr = 0, nr_diff;
	byte_t bt, ks3x[8], par[8][8];

	// Reset the last three significant bits of the reader nonce
	nr &= 0xffffff1f;
  
	PrintAndLog("\nuid(%08x) nt(%08x) par(%016"llx") ks(%016"llx") nr(%08"llx")\n\n", uid, nt, par_info, ks_info, nr);

	for ( pos = 0; pos < 8; pos++ ) {
		ks3x[7-pos] = (ks_info >> (pos*8)) & 0x0f;
		bt = (par_info >> (pos*8)) & 0xff;

		for ( i = 0; i < 8; i++) {
			par[7-pos][i] = (bt >> i) & 0x01;
		}
	}

	printf("|diff|{nr}    |ks3|ks3^5|parity         |\n");
	printf("+----+--------+---+-----+---------------+\n");

	for ( i = 0; i < 8; i++) {
		nr_diff = nr | i << 5;
		printf("| %02x |%08x| %01x |  %01x  |", i << 5, nr_diff, ks3x[i], ks3x[i]^5);

		for (pos = 0; pos < 7; pos++) printf("%01x,", par[i][pos]);
		printf("%01x|\n", par[i][7]);
	}
	printf("+----+--------+---+-----+---------------+\n");

	clock_t t1 = clock();

	state = lfsr_common_prefix(nr, rr, ks3x, par);
	lfsr_rollback_word(state, uid^nt, 0);
	crypto1_get_lfsr(state, key);
	crypto1_destroy(state);

	t1 = clock() - t1;
	if ( t1 > 0 ) PrintAndLog("Time in nonce2key: %.0f ticks \n", (float)t1);
	return 0;
}

// *outputkey is not used...
int tryMfk32(uint64_t myuid, uint8_t *data, uint8_t *outputkey ){

	struct Crypto1State *s,*t;
	uint64_t key;     // recovered key
	uint32_t uid;     // serial number
	uint32_t nt;      // tag challenge
	uint32_t nr0_enc; // first encrypted reader challenge
	uint32_t ar0_enc; // first encrypted reader response
	uint32_t nr1_enc; // second encrypted reader challenge
	uint32_t ar1_enc; // second encrypted reader response	
	bool isSuccess = FALSE;
	int counter = 0;
	
	uid 	= myuid;//(uint32_t)bytes_to_num(data +  0, 4);
	nt 		= *(uint32_t*)(data+8);
	nr0_enc = *(uint32_t*)(data+12);
	ar0_enc = *(uint32_t*)(data+16);
	nr1_enc = *(uint32_t*)(data+32);
	ar1_enc = *(uint32_t*)(data+36);

	// PrintAndLog("recovering key for:");
	// PrintAndLog("    uid: %08x   %08x",uid, myuid);
	// PrintAndLog("     nt: %08x",nt);
	// PrintAndLog(" {nr_0}: %08x",nr0_enc);
	// PrintAndLog(" {ar_0}: %08x",ar0_enc);
	// PrintAndLog(" {nr_1}: %08x",nr1_enc);
	// PrintAndLog(" {ar_1}: %08x",ar1_enc);

	s = lfsr_recovery32(ar0_enc ^ prng_successor(nt, 64), 0);
  
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, nr0_enc, 1);
		lfsr_rollback_word(t, uid ^ nt, 0);
		crypto1_get_lfsr(t, &key);
		crypto1_word(t, uid ^ nt, 0);
		crypto1_word(t, nr1_enc, 1);
		if (ar1_enc == (crypto1_word(t, 0, 0) ^ prng_successor(nt, 64))) {
			PrintAndLog("Found Key: [%012"llx"]", key);
			isSuccess = TRUE;
			++counter;
			if (counter==20)
				break;
		}
	}
	
	num_to_bytes(key, 6, outputkey);
	crypto1_destroy(t);
	return isSuccess;
}

int tryMfk32_moebius(uint64_t myuid, uint8_t *data, uint8_t *outputkey ){

	struct Crypto1State *s, *t;
	uint64_t key;     // recovered key
	uint32_t uid;     // serial number
	uint32_t nt0;     // tag challenge first
	uint32_t nt1;     // tag challenge second
	uint32_t nr0_enc; // first encrypted reader challenge
	uint32_t ar0_enc; // first encrypted reader response
	uint32_t nr1_enc; // second encrypted reader challenge
	uint32_t ar1_enc; // second encrypted reader response	
	bool isSuccess = FALSE;
	int counter = 0;
	
	uid 	= myuid;//(uint32_t)bytes_to_num(data +  0, 4);
	nt0 	= *(uint32_t*)(data+8);
	nr0_enc = *(uint32_t*)(data+12);
	ar0_enc = *(uint32_t*)(data+16);
	nt1 	= *(uint32_t*)(data+8);
	nr1_enc = *(uint32_t*)(data+32);
	ar1_enc = *(uint32_t*)(data+36);

	s = lfsr_recovery32(ar0_enc ^ prng_successor(nt0, 64), 0);
  
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, nr0_enc, 1);
		lfsr_rollback_word(t, uid ^ nt0, 0);
		crypto1_get_lfsr(t, &key);
		
		crypto1_word(t, uid ^ nt1, 0);
		crypto1_word(t, nr1_enc, 1);
		if (ar1_enc == (crypto1_word(t, 0, 0) ^ prng_successor(nt1, 64))) {
			PrintAndLog("Found Key: [%012"llx"]",key);
			isSuccess = TRUE;
			++counter;
			if (counter==20)
				break;
		}
	}
	num_to_bytes(key, 6, outputkey);
	crypto1_destroy(t);
	return isSuccess;
}

int tryMfk64(uint64_t myuid, uint8_t *data, uint8_t *outputkey ){

	struct Crypto1State *revstate;
	uint64_t key;     // recovered key
	uint32_t uid;     // serial number
	uint32_t nt;      // tag challenge
	uint32_t nr_enc;  // encrypted reader challenge
	uint32_t ar_enc;  // encrypted reader response
	uint32_t at_enc;  // encrypted tag response
	uint32_t ks2;     // keystream used to encrypt reader response
	uint32_t ks3;     // keystream used to encrypt tag response

	struct Crypto1State mpcs = {0, 0};
	struct Crypto1State *pcs;
	pcs = &mpcs;
	
	uid 	= myuid;//(uint32_t)bytes_to_num(data +  0, 4);
	nt	= *(uint32_t*)(data+8);
	nr_enc	= *(uint32_t*)(data+12);
	ar_enc	= *(uint32_t*)(data+16);
	
	crypto1_word(pcs, nr_enc , 1);
	at_enc = prng_successor(nt, 96) ^ crypto1_word(pcs, 0, 0);

	// printf("Recovering key for:\n");
	// printf("  uid: %08x\n",uid);
	// printf("   nt: %08x\n",nt);
	// printf(" {nr}: %08x\n",nr_enc);
	// printf(" {ar}: %08x\n",ar_enc);
	// printf(" {at}: %08x\n",at_enc);

	// Extract the keystream from the messages
	ks2 = ar_enc ^ prng_successor(nt, 64);
	ks3 = at_enc ^ prng_successor(nt, 96);

	revstate = lfsr_recovery64(ks2, ks3);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, nr_enc, 1);
	lfsr_rollback_word(revstate, uid ^ nt, 0);
	crypto1_get_lfsr(revstate, &key);
	PrintAndLog("Found Key: [%012"llx"]",key);
	num_to_bytes(key, 6, outputkey);
	crypto1_destroy(revstate);
	return 0;
}
