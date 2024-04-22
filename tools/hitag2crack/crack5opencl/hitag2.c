#include <stdio.h>
#include "ht2crack5opencl.h"
#include "hitag2.h"

//#if FORCE_HITAG2_FULL == 0

// return a single bit from a value
int bitn(uint64_t x, int bit) {
    const uint64_t bitmask = (uint64_t)(1) << bit;

    return (x & bitmask) ? 1 : 0;
}

// the sub-function R that rollback depends upon
int fnR(uint64_t x) {
    // renumbered bits because my state is 0-47, not 1-48
    return (bitn(x, 1) ^ bitn(x, 2) ^ bitn(x, 5) ^
            bitn(x, 6) ^ bitn(x, 7) ^ bitn(x, 15) ^
            bitn(x, 21) ^ bitn(x, 22) ^ bitn(x, 25) ^
            bitn(x, 29) ^ bitn(x, 40) ^ bitn(x, 41) ^
            bitn(x, 42) ^ bitn(x, 45) ^ bitn(x, 46) ^ bitn(x, 47));
}

// the three filter sub-functions that feed fnf
int fa(unsigned int i) {
    return bitn(0x2C79, (int)i);
}

int fb(unsigned int i) {
    return bitn(0x6671, (int)i);
}

// the filter function that generates a bit of output from the prng state
int fnf(uint64_t s) {
    const unsigned int x1 = (unsigned int)((bitn(s,  2) << 0) | (bitn(s,  3) << 1) | (bitn(s,  5) << 2) | (bitn(s,  6) << 3));
    const unsigned int x2 = (unsigned int)((bitn(s,  8) << 0) | (bitn(s, 12) << 1) | (bitn(s, 14) << 2) | (bitn(s, 15) << 3));
    const unsigned int x3 = (unsigned int)((bitn(s, 17) << 0) | (bitn(s, 21) << 1) | (bitn(s, 23) << 2) | (bitn(s, 26) << 3));
    const unsigned int x4 = (unsigned int)((bitn(s, 28) << 0) | (bitn(s, 29) << 1) | (bitn(s, 31) << 2) | (bitn(s, 33) << 3));
    const unsigned int x5 = (unsigned int)((bitn(s, 34) << 0) | (bitn(s, 43) << 1) | (bitn(s, 44) << 2) | (bitn(s, 46) << 3));

    const unsigned int x6 = (unsigned int)((fa(x1) << 0) | (fb(x2) << 1) | (fb(x3) << 2) | (fb(x4) << 3) | (fa(x5) << 4));

    return bitn(0x7907287B, (int) x6);
}

uint32_t hitag2_crypt(uint64_t x) {
    const uint32_t ht2_function4a = 0x2C79; // 0010 1100 0111 1001
    const uint32_t ht2_function4b = 0x6671; // 0110 0110 0111 0001
    const uint32_t ht2_function5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011

    uint32_t bitindex;

    bitindex = (ht2_function4a >> pickbits2_2(x, 1, 4)) & 1;
    bitindex |= ((ht2_function4b << 1) >> pickbits1_1_2(x, 7, 11, 13)) & 0x02;
    bitindex |= ((ht2_function4b << 2) >> pickbits1x4(x, 16, 20, 22, 25)) & 0x04;
    bitindex |= ((ht2_function4b << 3) >> pickbits2_1_1(x, 27, 30, 32)) & 0x08;
    bitindex |= ((ht2_function4a << 4) >> pickbits1_2_1(x, 33, 42, 45)) & 0x10;

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("hitag2_crypt bitindex = %02x\n", bitindex);
#endif

    return (ht2_function5c >> bitindex) & 1;
}

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
uint32_t hitag2_nstep(Hitag_State *pstate, uint32_t steps) {
    uint64_t cur_state = pstate->shiftreg;
    uint32_t result = 0;
    uint64_t lfsr = pstate->lfsr;

    if (steps == 0) return 0;

    do {
        // update shift registers
        if (lfsr & 1) {
            cur_state = (cur_state >> 1) | 0x800000000000;
            lfsr = (lfsr >> 1) ^ 0xB38083220073;

            // accumulate next bit of crypto
            result = (result << 1) | hitag2_crypt(cur_state);
        } else {
            cur_state >>= 1;
            lfsr >>= 1;

            result = (result << 1) | hitag2_crypt(cur_state);
        }
    } while (--steps);

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
#ifdef _ISOC99_SOURCE
    printf("hitag2_nstep cur_state = %012I64x, result %02x\n", cur_state, result);
#else
    printf("hitag2_nstep cur_state = %012" STR(OFF_FORMAT_X) ", result %02x\n", cur_state, result);
#endif
#endif // DEBUG_HITAG2

    pstate->shiftreg = cur_state;
    pstate->lfsr = lfsr;
    return result;
}

/*
 * Parameters:
 * Hitag_State* pstate - output, internal state after initialisation
 * uint64_t sharedkey  - 48 bit key shared between reader & tag
 * uint32_t serialnum  - 32 bit tag serial number
 * uint32_t initvector - 32 bit random IV from reader, part of tag authentication
 */
void hitag2_init(Hitag_State *pstate, uint64_t sharedkey, uint32_t serialnum, uint32_t initvector) {
    // init state, from serial number and lowest 16 bits of shared key
    uint64_t cur_state = ((sharedkey & 0xFFFF) << 32) | serialnum;

    // mix the initialisation vector and highest 32 bits of the shared key
    initvector ^= (uint32_t)(sharedkey >> 16);

    // move 16 bits from (IV xor Shared Key) to top of uint64_t state
    // these will be XORed in turn with output of the crypto function
    cur_state |= (uint64_t) initvector << 48;
    initvector >>= 16;

    // unrolled loop is faster on PIC32 (MIPS), do 32 times
    // shift register, then calc new bit
    cur_state >>= 1;

    int i;

    for (i = 0; i < 16; i++) {
        cur_state = (cur_state >> 1) ^ (uint64_t) hitag2_crypt(cur_state) << 46;
    }

    // highest 16 bits of IV XOR Shared Key
    cur_state |= (uint64_t) initvector << 47;

    for (i = 0; i < 15; i++) {
        cur_state = (cur_state >> 1) ^ (uint64_t) hitag2_crypt(cur_state) << 46;
    }

    cur_state ^= (uint64_t) hitag2_crypt(cur_state) << 47;

    pstate->shiftreg = cur_state;
#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
#ifdef _ISOC99_SOURCE
    printf("hitag2_init shiftreg = %012I64x\n", pstate->shiftreg);
#else
    printf("hitag2_init shiftreg = %012" STR(OFF_FORMAT_X) "\n", pstate->shiftreg);
#endif
#endif // DEBUG_HITAG2

    /* naive version for reference, LFSR has 16 taps
    pstate->lfsr = state ^ (state >>  2) ^ (state >>  3) ^ (state >>  6)
             ^ (state >>  7) ^ (state >>  8) ^ (state >> 16) ^ (state >> 22)
             ^ (state >> 23) ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
             ^ (state >> 42) ^ (state >> 43) ^ (state >> 46) ^ (state >> 47);
    */

    // optimise with one 64-bit intermediate
    uint64_t temp = cur_state ^ (cur_state >> 1);

    pstate->lfsr = cur_state ^ (cur_state >>  6) ^ (cur_state >> 16) ^
                   (cur_state >> 26) ^ (cur_state >> 30) ^ (cur_state >> 41) ^
                   (temp >>  2) ^ (temp >>  7) ^ (temp >> 22) ^ (temp >> 42) ^ (temp >> 46);

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
#ifdef _ISOC99_SOURCE
    printf("hitag2_init lfsr = %012I64x\n", pstate->lfsr);
#else
    printf("hitag2_init lfsr = %012" STR(OFF_FORMAT_X) "\n", pstate->lfsr);
#endif
#endif // DEBUG_HITAG2
}

// try state

// todo, changes arguments, only what is needed
bool try_state(uint64_t s, uint32_t uid, uint32_t aR2, uint32_t nR1, uint32_t nR2, uint64_t *key) {
#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("s : %lu, uid: %u, aR2: %u, nR1: %u, nR2: %u\n", s, uid, aR2, nR1, nR2);
    fflush(stdout);
#endif

    Hitag_State hstate;
    uint64_t keyrev, nR1xk;
    uint32_t b = 0;

    hstate.shiftreg = s;

    //rollback(&hstate, 2);
    hstate.shiftreg = (uint64_t)(((hstate.shiftreg << 1) & 0xffffffffffff) | (uint64_t)fnR(hstate.shiftreg));
    hstate.shiftreg = (uint64_t)(((hstate.shiftreg << 1) & 0xffffffffffff) | (uint64_t)fnR(hstate.shiftreg));

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("shiftreg : %lu\n", hstate.shiftreg);
    fflush(stdout);
#endif

    // recover key
    keyrev = hstate.shiftreg & 0xffff;
    nR1xk = (hstate.shiftreg >> 16) & 0xffffffff;

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("keyrev: %lu, nR1xk: %lu\n", keyrev, nR1xk);
    fflush(stdout);
#endif

    for (int i = 0; i < 32; i++) {
        hstate.shiftreg = ((hstate.shiftreg) << 1) | ((uid >> (31 - i)) & 0x1);
        b = (b << 1) | (unsigned int) fnf(hstate.shiftreg);
    }

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("shiftreg: %lu\n", hstate.shiftreg);
    fflush(stdout);
#endif

    keyrev |= (nR1xk ^ nR1 ^ b) << 16;

#if defined(DEBUG_HITAG2) && DEBUG_HITAG2 == 1
    printf("keyrev: %lu\n", keyrev);
    fflush(stdout);
#endif

    // test key
    hitag2_init(&hstate, keyrev, uid, nR2);
    if ((aR2 ^ hitag2_nstep(&hstate, 32)) == 0xffffffff) {
        *key = rev64(keyrev);

#if DEBUGME >= 2
#if ENABLE_EMOJ == 1
        printf("\nKey found ╭☞  ");
#else
        printf("\nKey found: ");
#endif
        for (int i = 0; i < 6; i++) {
            printf("%02X", (uint8_t)(*key & 0xff));
            *key = *key >> 8;
        }
        printf("\n");
#endif
        return true;
    }

    return false;
}

//#endif // FORCE_HITAG2_FULL = 0
