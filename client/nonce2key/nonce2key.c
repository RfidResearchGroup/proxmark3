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
#include "ui.h"

int nonce2key(uint32_t uid, uint32_t nt, uint64_t par_info, uint64_t ks_info, uint64_t * key) {
  struct Crypto1State *state;
  uint32_t pos, nr, rr, nr_diff;//, ks1, ks2;
  byte_t bt, i, ks3x[8], par[8][8];
  uint64_t key_recovered;
  nr = rr = 0;
  
  // Reset the last three significant bits of the reader nonce
  nr &= 0xffffff1f;
  
  PrintAndLog("\nuid(%08x) nt(%08x) par(%016llx) ks(%016llx)\n\n",uid,nt,par_info,ks_info);

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
  
  state = lfsr_common_prefix(nr, rr, ks3x, par);
  lfsr_rollback_word(state, uid^nt, 0);
  crypto1_get_lfsr(state, &key_recovered);
  crypto1_destroy(state);
	
	*key = key_recovered;
  
  return 0;
}
