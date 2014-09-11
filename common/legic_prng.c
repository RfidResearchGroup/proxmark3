//-----------------------------------------------------------------------------
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LEFIC's obfuscation function
//-----------------------------------------------------------------------------

#include "../include/legic_prng.h"

struct lfsr {
  uint8_t  a;
  uint8_t  b;
  uint32_t c;
} lfsr;

void legic_prng_init(uint8_t init) {
  lfsr.c = 0;
  lfsr.a = init;
  if(init == 0) /* hack to get a always 0 keystream */
    lfsr.b = 0;
  else
    lfsr.b = (init << 1) | 1;
}

void legic_prng_forward(int count) {
  lfsr.c += count;
  while(count--) {
    lfsr.a = lfsr.a >> 1 | (lfsr.a ^ lfsr.a >> 6) << 6;
    lfsr.b = lfsr.b >> 1 | (lfsr.b ^ lfsr.b >> 2 ^ lfsr.b >> 3 ^ lfsr.b >> 7) << 7;
  }
}

int legic_prng_count() {
  return lfsr.c;
}

uint8_t legic_prng_get_bit() {
  uint8_t idx = 7 - ( (lfsr.a & 4) | (lfsr.a >> 2 & 2) | (lfsr.a >> 4 & 1) );
  return lfsr.b >> idx & 1;
}
