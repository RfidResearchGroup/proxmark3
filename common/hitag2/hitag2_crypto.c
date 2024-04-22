//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Hitag2 Crypto
//-----------------------------------------------------------------------------
#include "hitag2_crypto.h"
#include <inttypes.h>
#include "util.h"
#include "string.h"
#include "commonutil.h"
#include "pm3_cmd.h"

#ifndef ON_DEVICE
#include "ui.h"
#endif

/* Following is a modified version of cryptolib.com/ciphers/hitag2/ */
// Software optimized 48-bit Philips/NXP Mifare Hitag2 PCF7936/46/47/52 stream cipher algorithm by I.C. Wiener 2006-2007.
// For educational purposes only.
// No warranties or guarantees of any kind.
// This code is released into the public domain by its author.


// Single bit Hitag2 functions:
#ifndef i4
#define i4(x,a,b,c,d)   ((uint32_t)((((x)>>(a))&1)+(((x)>>(b))&1)*2+(((x)>>(c))&1)*4+(((x)>>(d))&1)*8))
#endif

static const uint32_t ht2_f4a = 0x2C79;     // 0010 1100 0111 1001
static const uint32_t ht2_f4b = 0x6671;     // 0110 0110 0111 0001
static const uint32_t ht2_f5c = 0x7907287B; // 0111 1001 0000 0111 0010 1000 0111 1011

static uint32_t ht2_f20(const uint64_t state) {

    uint32_t i5 = ((ht2_f4a >> i4(state, 1, 2, 4, 5)) & 1) * 1
                  + ((ht2_f4b >> i4(state, 7, 11, 13, 14)) & 1) * 2
                  + ((ht2_f4b >> i4(state, 16, 20, 22, 25)) & 1) * 4
                  + ((ht2_f4b >> i4(state, 27, 28, 30, 32)) & 1) * 8
                  + ((ht2_f4a >> i4(state, 33, 42, 43, 45)) & 1) * 16;

    return (ht2_f5c >> i5) & 1;
}

// return a single bit from a value
static int ht2_bitn(uint64_t x, int bit) {
    const uint64_t bitmask = (uint64_t)(1) << bit;
    return (x & bitmask) ? 1 : 0;
}

// the sub-function R that rollback depends upon
int ht2_fnR(uint64_t state) {
    // renumbered bits because my state is 0-47, not 1-48
    return (
               ht2_bitn(state, 1)  ^ ht2_bitn(state, 2)  ^ ht2_bitn(state, 5)  ^
               ht2_bitn(state, 6)  ^ ht2_bitn(state, 7)  ^ ht2_bitn(state, 15) ^
               ht2_bitn(state, 21) ^ ht2_bitn(state, 22) ^ ht2_bitn(state, 25) ^
               ht2_bitn(state, 29) ^ ht2_bitn(state, 40) ^ ht2_bitn(state, 41) ^
               ht2_bitn(state, 42) ^ ht2_bitn(state, 45) ^ ht2_bitn(state, 46) ^
               ht2_bitn(state, 47)
           );
}

/*
static void ht2_rollback(hitag_state_t *hstate, unsigned int steps) {
    for (int i = 0; i < steps; i++) {
        hstate->shiftreg = ((hstate->shiftreg << 1) & 0xffffffffffff) | ht2_fnR(hstate->shiftreg);
    }
}
*/
// the rollback function that lets us go backwards in time
void ht2_rollback(hitag_state_t *hstate, uint32_t steps) {
    for (uint32_t i = 0; i < steps; i++) {
        hstate->shiftreg = ((hstate->shiftreg << 1) & 0xffffffffffff) | ht2_fnR(hstate->shiftreg);
        hstate->lfsr = LFSR_INV(hstate->lfsr);
    }
}

// the three filter sub-functions that feed fnf
#define ht2_fa(x)  ht2_bitn(0x2C79, (x))
#define ht2_fb(x)  ht2_bitn(0x6671, (x))
#define ht2_fc(x)  ht2_bitn(0x7907287B, (x))

// the filter function that generates a bit of output from the prng state
int ht2_fnf(uint64_t state) {

    uint32_t x1 = (ht2_bitn(state,  2) << 0) | (ht2_bitn(state,  3) << 1) | (ht2_bitn(state,  5) << 2) | (ht2_bitn(state,  6) << 3);
    uint32_t x2 = (ht2_bitn(state,  8) << 0) | (ht2_bitn(state, 12) << 1) | (ht2_bitn(state, 14) << 2) | (ht2_bitn(state, 15) << 3);
    uint32_t x3 = (ht2_bitn(state, 17) << 0) | (ht2_bitn(state, 21) << 1) | (ht2_bitn(state, 23) << 2) | (ht2_bitn(state, 26) << 3);
    uint32_t x4 = (ht2_bitn(state, 28) << 0) | (ht2_bitn(state, 29) << 1) | (ht2_bitn(state, 31) << 2) | (ht2_bitn(state, 33) << 3);
    uint32_t x5 = (ht2_bitn(state, 34) << 0) | (ht2_bitn(state, 43) << 1) | (ht2_bitn(state, 44) << 2) | (ht2_bitn(state, 46) << 3);

    uint32_t x6 = (ht2_fa(x1) << 0) | (ht2_fb(x2) << 1) | (ht2_fb(x3) << 2) | (ht2_fb(x4) << 3) | (ht2_fa(x5) << 4);
    return ht2_fc(x6);
}

// builds the lfsr for the prng (quick calcs for hitag2_nstep())
/*
static void ht2_buildlfsr(hitag_state_t *hstate) {
    if (hstate == NULL) {
        return;
    }

    uint64_t state = hstate->shiftreg;
    uint64_t temp = state ^ (state >> 1);
    hstate->lfsr = state ^ (state >>  6) ^ (state >> 16)
                   ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
                   ^ (temp >>  2) ^ (temp >>  7) ^ (temp >> 22)
                   ^ (temp >> 42) ^ (temp >> 46);
}
*/
#ifndef ON_DEVICE
#include <stdio.h>
#endif

uint64_t ht2_recoverkey(hitag_state_t *hstate, uint32_t uid, uint32_t nRenc) {

//    hstate->shiftreg = (uint64_t)(((hstate->shiftreg << 1) & 0xffffffffffff) | (uint64_t)ht2_fnR(hstate->shiftreg));
//    hstate->shiftreg = (uint64_t)(((hstate->shiftreg << 1) & 0xffffffffffff) | (uint64_t)ht2_fnR(hstate->shiftreg));

#ifndef ON_DEVICE
    PrintAndLogEx(INFO, "shiftreg.... %" PRIx64, hstate->shiftreg);
#endif

    // key lower 16 bits are lower 16 bits of prng state
    uint64_t key = hstate->shiftreg & 0xffff;
    uint32_t nRxork = (hstate->shiftreg >> 16) & 0xffffffff;

    // rollback and extract bits b
    uint32_t b = 0;
    for (uint8_t i = 0; i < 32; i++) {
        hstate->shiftreg = ((hstate->shiftreg) << 1) | ((uid >> (31 - i)) & 0x1);
        b = (b << 1) | (unsigned int) ht2_fnf(hstate->shiftreg);
    }

    uint32_t nR = nRenc ^ b;
    uint64_t keyupper = nRxork ^ nR;
    key = key | (keyupper << 16);

#ifndef ON_DEVICE



    PrintAndLogEx(INFO, "b..... %08" PRIx32 "  %08" PRIx32 "  %012" PRIx64, b, nRenc, hstate->shiftreg);
    PrintAndLogEx(INFO, "key... %012" PRIx64 " %012" PRIx64 "\n", key, REV64(key));
#endif
    return key;
}

/*
 * Parameters:
 * Hitag_State* pstate - output, internal state after initialisation
 * uint64_t sharedkey  - 48 bit key shared between reader & tag
 * uint32_t serialnum  - 32 bit tag serial number
 * uint32_t iv         - 32 bit random IV from reader, part of tag authentication
 */
void ht2_hitag2_init_ex(hitag_state_t *hstate, uint64_t sharedkey, uint32_t serialnum, uint32_t iv) {
    // init state, from serial number and lowest 16 bits of shared key
    uint64_t state = ((sharedkey & 0xFFFF) << 32) | serialnum;

    // mix the initialisation vector and highest 32 bits of the shared key
    iv ^= (uint32_t)(sharedkey >> 16);

    // move 16 bits from (IV xor Shared Key) to top of uint64_t state
    // these will be XORed in turn with output of the crypto function
    state |= (uint64_t) iv << 48;
    iv >>= 16;

    // unrolled loop is faster on PIC32 (MIPS), do 32 times
    // shift register, then calc new bit
    state >>= 1;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;

    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;

    // highest 16 bits of IV XOR Shared Key
    state |= (uint64_t) iv << 47;

    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;

    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state = (state >> 1) ^ (uint64_t) ht2_f20(state) << 46;
    state ^= (uint64_t) ht2_f20(state) << 47;

    // LSFR

    hstate->shiftreg = state;
    /* naive version for reference, LFSR has 16 taps
    pstate->lfsr = state ^ (state >>  2) ^ (state >>  3) ^ (state >>  6)
              ^ (state >>  7) ^ (state >>  8) ^ (state >> 16) ^ (state >> 22)
              ^ (state >> 23) ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
              ^ (state >> 42) ^ (state >> 43) ^ (state >> 46) ^ (state >> 47);
    */
    {
        // optimise with one 64-bit intermediate
        uint64_t temp = state ^ (state >> 1);
        hstate->lfsr = state ^ (state >>  6) ^ (state >> 16)
                       ^ (state >> 26) ^ (state >> 30) ^ (state >> 41)
                       ^ (temp >>  2) ^ (temp >>  7) ^ (temp >> 22)
                       ^ (temp >> 42) ^ (temp >> 46);
    }
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
uint32_t ht2_hitag2_nstep(hitag_state_t *hstate, uint32_t steps) {
    uint64_t state = hstate->shiftreg;
    uint32_t result = 0;
    uint64_t lfsr = hstate->lfsr;

    if (steps == 0) {
        return 0;
    }

    do {
        // update shift registers
        if (lfsr & 1) {
            state = (state >> 1) | 0x800000000000;
            lfsr = (lfsr >> 1) ^ 0xB38083220073;
            // accumulate next bit of crypto
            result = (result << 1) | ht2_f20(state);
        } else {
            state >>= 1;
            lfsr >>= 1;
            result = (result << 1) | ht2_f20(state);
        }
    } while (--steps);

    hstate->shiftreg = state;
    hstate->lfsr = lfsr;
    return result;
}

uint64_t ht2_hitag2_init(const uint64_t key, const uint32_t serial, const uint32_t iv) {

    uint64_t x = ((key & 0xFFFF) << 32) + serial;

    for (uint32_t i = 0; i < 32; i++) {
        x >>= 1;
        x += (uint64_t)(ht2_f20(x) ^ (((iv >> i) ^ (key >> (i + 16))) & 1)) << 47;
    }
    return x;
}

int ht2_try_state(uint64_t s, uint32_t uid, uint32_t aR2, uint32_t nR1, uint32_t nR2, uint64_t *key) {

    hitag_state_t hstate;
    hstate.shiftreg = s;
    hstate.lfsr = 0;

    hstate.shiftreg = (uint64_t)(((hstate.shiftreg << 1) & 0xffffffffffff) | (uint64_t)ht2_fnR(hstate.shiftreg));
    hstate.shiftreg = (uint64_t)(((hstate.shiftreg << 1) & 0xffffffffffff) | (uint64_t)ht2_fnR(hstate.shiftreg));

#ifndef ON_DEVICE
    hitag_state_t hs2;
    hs2.shiftreg = s;
    hs2.lfsr = 0;
    ht2_rollback(&hs2, 2);

    PrintAndLogEx(INFO, "hstate shiftreg.... %" PRIx64 " lfsr... %" PRIx64, hstate.shiftreg, hstate.lfsr);
    PrintAndLogEx(INFO, "hstate shiftreg.... %" PRIx64 " lfsr... %" PRIx64, hs2.shiftreg, hs2.lfsr);
#endif

    // recover key
    uint64_t keyrev = hstate.shiftreg & 0xffff;
    uint64_t nR1xk = (hstate.shiftreg >> 16) & 0xffffffff;

#ifndef ON_DEVICE
    PrintAndLogEx(INFO, "keyrev...... %012" PRIx64 " nR1xk... %08" PRIx64, keyrev, nR1xk);
#endif

    uint32_t b = 0;
    for (uint8_t i = 0; i < 32; i++) {
        hstate.shiftreg = ((hstate.shiftreg) << 1) | ((uid >> (31 - i)) & 0x1);
        b = (b << 1) | (unsigned int) ht2_fnf(hstate.shiftreg);
    }

#ifndef ON_DEVICE
    PrintAndLogEx(INFO, "b..... %08" PRIx32 "  %08" PRIx32 "  %012" PRIx64, b, nR1, hstate.shiftreg);
#endif

    keyrev |= (nR1xk ^ nR1 ^ b) << 16;

#ifndef ON_DEVICE
    PrintAndLogEx(INFO, "key... %012" PRIx64 " %012" PRIx64, keyrev, REV64(keyrev));
#endif

    // test key
    ht2_hitag2_init_ex(&hstate, keyrev, uid, nR2);

    if ((aR2 ^ ht2_hitag2_nstep(&hstate, 32)) == 0xFFFFFFFF) {
        *key = REV64(keyrev);
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}


// "MIKRON"             =  O  N  M  I  K  R
// Key                  = 4F 4E 4D 49 4B 52             - Secret 48-bit key
// Serial               = 49 43 57 69                   - Serial number of the tag, transmitted in clear
// Random               = 65 6E 45 72                   - Random IV, transmitted in clear
//~28~DC~80~31  = D7 23 7F CE                   - Authenticator value = inverted first 4 bytes of the keystream

// The code below must print out "D7 23 7F CE 8C D0 37 A9 57 49 C1 E6 48 00 8A B6".
// The inverse of the first 4 bytes is sent to the tag to authenticate.
// The rest is encrypted by XORing it with the subsequent keystream.

/*
 * Return 8 crypto bits.
 * Last bit is in least significant bit, earlier bits are shifted left.
 * Note that the Hitag transmission protocol is least significant bit,
 * so we may want to change this, or add a function, that returns the
 * crypto output bits in the other order.
 *
 * Parameters:
 * uint64_t *state - in/out, internal cipher state after initialisation
  */
uint64_t ht2_hitag2_bit(uint64_t *state) {
    uint64_t x = *state;

    x = (x >>  1) +
        ((((x >>  0) ^ (x >>  2) ^ (x >>  3) ^ (x >>  6)
           ^ (x >>  7) ^ (x >>  8) ^ (x >> 16) ^ (x >> 22)
           ^ (x >> 23) ^ (x >> 26) ^ (x >> 30) ^ (x >> 41)
           ^ (x >> 42) ^ (x >> 43) ^ (x >> 46) ^ (x >> 47)) & 1) << 47);

    *state = x;
    return ht2_f20(x);
}

// Take a state and create one byte (8bits) of crypto
uint32_t ht2_hitag2_byte(uint64_t *state) {
    uint32_t c = 0;
    c += (uint32_t) ht2_hitag2_bit(state) << 7; // 7
    c += (uint32_t) ht2_hitag2_bit(state) << 6; // 6
    c += (uint32_t) ht2_hitag2_bit(state) << 5; // 5
    c += (uint32_t) ht2_hitag2_bit(state) << 4;
    c += (uint32_t) ht2_hitag2_bit(state) << 3;
    c += (uint32_t) ht2_hitag2_bit(state) << 2;
    c += (uint32_t) ht2_hitag2_bit(state) << 1;
    c += (uint32_t) ht2_hitag2_bit(state) << 0;
    return c;
}

uint32_t ht2_hitag2_word(uint64_t *state, uint32_t steps) {
    uint32_t c = 0;
    do {
        c += (uint32_t) ht2_hitag2_bit(state) << (steps - 1);
    } while (--steps);
    return c;
}

void ht2_hitag2_cipher_reset(hitag2_t *tag, const uint8_t *iv) {
    uint64_t key = ((uint64_t)tag->sectors[2][2]) |
                   ((uint64_t)tag->sectors[2][3] <<  8) |
                   ((uint64_t)tag->sectors[1][0] << 16) |
                   ((uint64_t)tag->sectors[1][1] << 24) |
                   ((uint64_t)tag->sectors[1][2] << 32) |
                   ((uint64_t)tag->sectors[1][3] << 40);
    uint32_t uid = ((uint32_t)tag->sectors[0][0]) |
                   ((uint32_t)tag->sectors[0][1] <<  8) |
                   ((uint32_t)tag->sectors[0][2] << 16) |
                   ((uint32_t)tag->sectors[0][3] << 24);
    uint32_t iv_ = (((uint32_t)(iv[0]))) |
                   (((uint32_t)(iv[1])) <<  8) |
                   (((uint32_t)(iv[2])) << 16) |
                   (((uint32_t)(iv[3])) << 24);
    tag->cs = ht2_hitag2_init(REV64(key), REV32(uid), REV32(iv_));
}

int ht2_hitag2_cipher_authenticate(uint64_t *state, const uint8_t *authenticator_is) {
    uint8_t authenticator_should[4];
    authenticator_should[0] = ~ht2_hitag2_byte(state);
    authenticator_should[1] = ~ht2_hitag2_byte(state);
    authenticator_should[2] = ~ht2_hitag2_byte(state);
    authenticator_should[3] = ~ht2_hitag2_byte(state);
    return (memcmp(authenticator_should, authenticator_is, 4) == 0);
}

void ht2_hitag2_cipher_transcrypt(uint64_t *state, uint8_t *data, uint16_t bytes, uint16_t bits) {
    int i;
    for (i = 0; i < bytes; i++) {
        data[i] ^= ht2_hitag2_byte(state);
    }

    for (i = 0; i < bits; i++) {
        data[bytes] ^= ht2_hitag2_bit(state) << (7 - i);
    }
}

