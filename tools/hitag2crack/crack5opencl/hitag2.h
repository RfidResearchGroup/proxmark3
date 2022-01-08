#ifndef HITAG2_H
#define HITAG2_H

#include <stdint.h>
#include <stdbool.h>

// as the HITAG2 original implementation, with some minor changes

#define i4(x,a,b,c,d) ((uint32_t)((((x)>>(a))&1)<<3)|(((x)>>(b))&1)<<2|(((x)>>(c))&1)<<1|(((x)>>(d))&1))
#define f(state) ((uint32_t)((0xdd3929b >> ( (((0x3c65 >> i4(state, 2, 3, 5, 6) ) & 1) <<4) \
                                | ((( 0xee5 >> i4(state, 8,12,14,15) ) & 1) <<3) \
                                | ((( 0xee5 >> i4(state,17,21,23,26) ) & 1) <<2) \
                                | ((( 0xee5 >> i4(state,28,29,31,33) ) & 1) <<1) \
                                | (((0x3c65 >> i4(state,34,43,44,46) ) & 1) ))) & 1))

#define get_bit(n, word) ((word >> (n)) & 1)

/*
 * Hitag Crypto support macros
 * These macros reverse the bit order in a byte, or *within* each byte of a
 * 16 , 32 or 64 bit unsigned integer. (Not across the whole 16 etc bits.)
 */
#define rev8(X)   ((((X) >> 7) &1) + (((X) >> 5) &2) + (((X) >> 3) &4) \
                  + (((X) >> 1) &8) + (((X) << 1) &16) + (((X) << 3) &32) \
                  + (((X) << 5) &64) + (((X) << 7) &128) )
#define rev16(X)  (rev8 (X) + (rev8 (X >> 8) << 8))
#define rev32(X)  (rev16(X) + (rev16(X >> 16) << 16))
#define rev64(X)  (rev32(X) + (rev32(X >> 32) << 32))

typedef struct {
    uint64_t shiftreg; // naive shift register, required for nonlinear fn input
    uint64_t lfsr;     // fast lfsr, used to make software faster
} Hitag_State;

// return a single bit from a value
int bitn(uint64_t x, int bit);

// the sub-function R that rollback depends upon
int fnR(uint64_t x);

// the three filter sub-functions that feed fnf
int fa(unsigned int i);

int fb(unsigned int i);

// the filter function that generates a bit of output from the prng state
int fnf(uint64_t s);

// macros to pick out 4 bits in various patterns of 1s & 2s & make a new number
#define pickbits2_2(S, A, B)       ( ((S >> A) & 3) | ((S >> (B - 2)) & 0xC) )
#define pickbits1x4(S, A, B, C, D) ( ((S >> A) & 1) | ((S >> (B - 1)) & 2) | ((S >> (C - 2)) & 4) | ((S >> (D - 3)) & 8) )
#define pickbits1_1_2(S, A, B, C)  ( ((S >> A) & 1) | ((S >> (B - 1)) & 2) | ((S >> (C - 2)) & 0xC) )
#define pickbits2_1_1(S, A, B, C)  ( ((S >> A) & 3) | ((S >> (B - 2)) & 4) | ((S >> (C - 3)) & 8) )
#define pickbits1_2_1(S, A, B, C)  ( ((S >> A) & 1) | ((S >> (B - 1)) & 6) | ((S >> (C - 3)) & 8) )

uint32_t hitag2_crypt(uint64_t x);

/*
 * Return up to 32 crypto bits.
 * Last bit is in least significant bit, earlier bits are shifted left.
 * Note that the Hitag transmission protocol is least significant bit,
 * so we may want to change this, or add a function, that returns the
 * crypto output bits in the other order.
 *
 * Parameters:
 * Hitag_State* pstate - in/out, internal cipher state after initialisation
 * uint32_t steps      - number of bits requested, (capped at 32)
 */
uint32_t hitag2_nstep(Hitag_State *pstate, uint32_t steps);

/*
 * Parameters:
 * Hitag_State* pstate - output, internal state after initialisation
 * uint64_t sharedkey  - 48 bit key shared between reader & tag
 * uint32_t serialnum  - 32 bit tag serial number
 * uint32_t initvector - 32 bit random IV from reader, part of tag authentication
 */
void hitag2_init(Hitag_State *pstate, uint64_t sharedkey, uint32_t serialnum, uint32_t initvector);

// try_state
bool try_state(uint64_t s, uint32_t uid, uint32_t aR2, uint32_t nR1, uint32_t nR2, uint64_t *key);

#endif // HITAG2_H
