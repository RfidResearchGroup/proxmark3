//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEFIC's obfuscation function
//-----------------------------------------------------------------------------

#include "legic_prng.h"

struct lfsr {
  uint8_t a;
  uint8_t b;
} lfsr;

void legic_prng_init(uint8_t init) {
  lfsr.a = init;
  if(init == 0) /* hack to get a always 0 keystream */
    lfsr.b = 0;
  else
    lfsr.b = (init << 1) | 1;
}

void legic_prng_forward(int count) {
  uint8_t tmp;
  while(count--) {
    tmp  =  lfsr.a & 1;
    tmp ^= (lfsr.a & 0x40) >> 6;
    
    lfsr.a >>= 1;
    lfsr.a |= tmp << 6;
    
    tmp  =  lfsr.b & 1;
    tmp ^= (lfsr.b & 4) >> 2;
    tmp  = ~tmp;
    tmp ^= (lfsr.b & 8) >> 3;
    tmp  = ~tmp;
    tmp ^= (lfsr.b & 0x80) >> 7;
    
    lfsr.b >>= 1;
    lfsr.b |= tmp << 7;
  }
}

uint8_t legic_prng_get_bit() {
  uint8_t idx = 7-((lfsr.a & 4) | ((lfsr.a & 8) >> 2) | ((lfsr.a & 0x10) >> 4));
  return ((lfsr.b >> idx) & 1);
}
