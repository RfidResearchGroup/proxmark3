/**
 * The MIT License (MIT)
 *
 * Copyright (c) 2024 by Henry Gabryjelski
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

#include "id48_internals.h"

#ifndef nullptr
#define nullptr ((void*)0)
#endif

#pragma region    // reverse_bits()
static inline uint8_t  reverse_bits_08(uint8_t  n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint8_t mask = (uint8_t)(~((uint8_t)(0u)));
    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap);
        n = (uint8_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap));
    }
    return n;
}
static inline uint16_t reverse_bits_16(uint16_t n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint16_t mask = (uint16_t)(~((uint16_t)(0u)));
    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap);
        n = (uint16_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap));
    }
    return n;
}
static inline uint32_t reverse_bits_32(uint32_t n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint32_t mask = (uint32_t)(~((uint32_t)(0u)));
    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap);
        n = (uint32_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap));
    }
    return n;
}
static inline uint64_t reverse_bits_64(uint64_t n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint64_t mask = (uint64_t)(~((uint64_t)(0u)));
    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap);
        n = (uint64_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap));
    }
    return n;
}
#pragma endregion // reverse_bits()

#define MAXIMUM_STATE_HISTORY (56u)

typedef struct _EXPECTED_OUTPUT_BITS {
    uint64_t Raw; // s07: 1ull << 0, s08: 1ull << 1, s09: 1ull << 2, ... s55: 1ull << 47
} EXPECTED_OUTPUT_BITS;
typedef struct _KEY_BITS_K47_TO_K00 {
    uint64_t Raw;
} KEY_BITS_K47_TO_K00;
typedef struct _RECOVERY_STATE {
    /// <summary>
    /// What are the 48 expected output bits?
    /// Stored as 0¹⁶·O₄₇..O₀₀.
    /// </summary>
    EXPECTED_OUTPUT_BITS expected_output_bits; // const once initialized
    /// <summary>
    /// The value of the low 48-bits most recently
    /// returned to the caller as a potential match.
    /// </summary>
    KEY_BITS_K47_TO_K00 last_returned_potential_key;
    /// <summary>
    /// State history.  Overwritten during testing
    /// of input bits (next bit of possible key).
    /// Storing the full history allows backtracking
    /// without re-computing the state.
    /// </summary>
    ID48LIBX_STATE_REGISTERS states[MAXIMUM_STATE_HISTORY]; // history ... avoids re-computation when backtracking
    /// <summary>
    /// The 48-bit partial key to recover the remaining 48 bits of.
    /// Constant after initialization.
    /// </summary>
    ID48LIB_KEY known_k95_to_k48;
    /// <summary>
    /// The 56-bit nonce corresponding to the frn/grn (output bits).
    /// Constant after initialization.
    /// </summary>
    ID48LIB_NONCE known_nonce;
    /// <summary>
    /// boolean to identify first run after initialization (an edge case)
    /// </summary>
    bool is_fresh_initialization;
    /// <summary>
    /// boolean to identify that all keys have been tested.
    /// If set, caller would need to call init() function again.
    /// </summary>
    bool more_keys_to_test;
} RECOVERY_STATE;

// Need equivalent of the following two function pointers:
typedef ID48LIBX_SUCCESSOR_RESULT    (*ID48LIB_SUCCESSOR_FN)(const ID48LIBX_STATE_REGISTERS* initial_state, uint8_t input_bit);
typedef ID48LIBX_STATE_REGISTERS(*ID48LIB_INIT_FN     )(const ID48LIB_KEY* key, const ID48LIB_NONCE* nonce);

static const ID48LIB_INIT_FN      init_fn      = id48libx_retro003_init;
static const ID48LIB_SUCCESSOR_FN successor_fn = id48libx_retro003_successor;

/// <summary>
/// Creates PM3-formatted key with K₉₅..K₄₈ from the provided partial key,
/// and with K₄₇..K₃₃ from bit-reversed `more_bits`.
/// </summary>
/// <param name="input_partial_key">Key with K₉₅..K₄₈, in PM3 compatible layout</param>
/// <param name="more_bits">0 K₃₃..K₄₇ (to support simple incrementing input)</param>
/// <returns>PM3-formatted key:  K₉₅..K₃₃ 0³³</returns>
static ID48LIB_KEY create_partial_key56(const ID48LIB_KEY * input_partial_key, uint8_t k47_to_k40) {
    ID48LIB_KEY result;
    result.k[ 0] = input_partial_key->k[0];   // k[ 0] :== K₉₅..K₈₈
    result.k[ 1] = input_partial_key->k[1];   // k[ 1] :== K₈₇..K₈₀
    result.k[ 2] = input_partial_key->k[2];   // k[ 2] :== K₇₉..K₇₂
    result.k[ 3] = input_partial_key->k[3];   // k[ 3] :== K₇₁..K₆₄
    result.k[ 4] = input_partial_key->k[4];   // k[ 4] :== K₆₃..K₅₆
    result.k[ 5] = input_partial_key->k[5];   // k[ 5] :== K₅₅..K₄₈
    result.k[ 6] = k47_to_k40;                // k[ 6] :== K₄₇..K₄₀
    result.k[ 7] = 0;                         // k[ 7] :== K₃₉..K₃₂
    result.k[ 8] = 0;                         // k[ 8] :== K₃₁..K₂₄
    result.k[ 9] = 0;                         // k[ 9] :== K₂₃..K₁₆
    result.k[10] = 0;                         // k[10] :== K₁₅..K₀₈
    result.k[11] = 0;                         // k[11] :== K₀₇..K₀₀
    return result;
}
/// <summary>
/// Returns 48-bit value (using 64-bits of storage): 0¹⁶ O₄₇..O₀₀.
/// This allows simple calculation of the relevant bit to review,
/// or simply shifting the value right each time a bit is used and using lsb.
/// </summary>
/// <param name="input_frn">PM3 compatible input for frn</param>
/// <param name="input_grn">PM3 compatible input for grn</param>
/// <returns></returns>
static EXPECTED_OUTPUT_BITS create_expected_output_bits(const ID48LIB_FRN* input_frn, const ID48LIB_GRN* input_grn) {
    // inputs:
    // frn[ 0] :== O₀₀..O₀₇
    // frn[ 1] :== O₀₈..O₁₅
    // frn[ 2] :== O₁₆..O₂₃
    // frn[ 3] :== O₂₄..O₂₇ 0000
    // grn[ 0] :== O₂₈  ..  O₃₅
    // grn[ 1] :== O₃₆  ..  O₄₃
    // grn[ 2] :== O₄₄..O₄₇ 0000
    EXPECTED_OUTPUT_BITS result; result.Raw = 0u;
    result.Raw <<= 4; result.Raw |= reverse_bits_08(input_grn->grn[2] & 0xF0u); // adds grn₁₉..grn₁₆ aka O₄₇..O₄₄
    result.Raw <<= 8; result.Raw |= reverse_bits_08(input_grn->grn[1] & 0xFFu); // adds grn₁₅..grn₀₈ aka O₄₃..O₃₆
    result.Raw <<= 8; result.Raw |= reverse_bits_08(input_grn->grn[0] & 0xFFu); // adds grn₀₇..grn₀₀ aka O₃₅..O₂₈

    result.Raw <<= 4; result.Raw |= reverse_bits_08(input_frn->frn[3] & 0xF0u); // adds frn₂₇..frn₂₄ aka O₂₇..O₂₄
    result.Raw <<= 8; result.Raw |= reverse_bits_08(input_frn->frn[2] & 0xFFu); // adds frn₂₃..frn₁₆ aka O₂₃..O₁₆
    result.Raw <<= 8; result.Raw |= reverse_bits_08(input_frn->frn[1] & 0xFFu); // adds frn₁₅..frn₀₈ aka O₁₅..O₀₈
    result.Raw <<= 8; result.Raw |= reverse_bits_08(input_frn->frn[0] & 0xFFu); // adds frn₀₇..frn₀₀ aka O₀₇..O₀₀
    return result;
}
/// <summary>
/// For a current state, get the expected output bit.
/// This is used to determine which value(s) the key bit
/// may be valid, allowing early pruning of the search space.
/// </summary>
/// <param name="recovery_state">A value in the range [0,55]</param>
/// <returns>Zero or non-zero (boolean) corresponding to the expected output.</returns>
static bool get_expected_output_bit(const RECOVERY_STATE* recovery_state, uint8_t current_state_index) {
    ASSERT(recovery_state != nullptr);
    ASSERT(current_state_index >= 7);
    ASSERT(current_state_index <= 55);
    uint64_t shifted = recovery_state->expected_output_bits.Raw >> (current_state_index - 7u);
    return !!(shifted & 0x1u); // return the single bit result
}

static void restart_and_calculate_s00(RECOVERY_STATE* s, const KEY_BITS_K47_TO_K00* k_low) {
    ASSERT(s != nullptr);
    ASSERT(k_low != nullptr);
    memset(&(s->states[0]), 0xAA, sizeof(ID48LIBX_STATE_REGISTERS) * MAXIMUM_STATE_HISTORY);
    uint8_t k47_to_k40 = (uint8_t)(k_low->Raw >> 40);
    const ID48LIB_KEY start_56b_key = create_partial_key56(&(s->known_k95_to_k48), k47_to_k40);
    s->states[0] = init_fn(&start_56b_key, &(s->known_nonce));
}

static bool validate_output_from_additional_fifteen_zero_bits(RECOVERY_STATE* s) {
    bool all_still_match = true;
    for (uint8_t i = 0; all_still_match && i < 15; i++) {
        const uint8_t src_idx = 40 + i;
        const ID48LIBX_STATE_REGISTERS* state = &(s->states[src_idx]);
        ID48LIBX_SUCCESSOR_RESULT r = successor_fn(state, 0);
        bool expected_result = get_expected_output_bit(s, src_idx);
        if (expected_result != (!!r.output)) {
            all_still_match = false;
        }
        s->states[src_idx + 1] = r.state;
    }
    return all_still_match;
}


// intentionally declare this global state only here, as a way
// of forcing the above functions to act on a pointer.  Ensuring
// the above routines don't inadvertently use the global state
// makes it easier to enable a multi-threaded version.
RECOVERY_STATE g_S = { 0 };

static void init(
    const ID48LIB_KEY   * input_partial_key,
    const ID48LIB_NONCE * input_nonce,
    const ID48LIB_FRN   * input_frn,
    const ID48LIB_GRN   * input_grn
    )
{
    memset(&g_S, 0, sizeof(RECOVERY_STATE));
    memset(&(g_S.states[0]), 0xAA, sizeof(ID48LIBX_STATE_REGISTERS) * MAXIMUM_STATE_HISTORY);
    g_S.known_k95_to_k48.k[0] = input_partial_key->k[0];
    g_S.known_k95_to_k48.k[1] = input_partial_key->k[1];
    g_S.known_k95_to_k48.k[2] = input_partial_key->k[2];
    g_S.known_k95_to_k48.k[3] = input_partial_key->k[3];
    g_S.known_k95_to_k48.k[4] = input_partial_key->k[4];
    g_S.known_k95_to_k48.k[5] = input_partial_key->k[5];
    g_S.known_nonce = *input_nonce;
    g_S.expected_output_bits = create_expected_output_bits(input_frn, input_grn);
    g_S.more_keys_to_test = true;
    g_S.is_fresh_initialization = true;
}
static bool get_next_potential_key(
    ID48LIB_KEY* potential_key_output
) {
    memset(potential_key_output, 0, sizeof(ID48LIB_KEY));

    // Three possible states when this function enters:
    // 1. Never initialized / finished enumerating keys
    //    --> returns false immediately
    // 2. First time after initialization
    //    --> key starts at zero, with zero current bits
    // 3. After a key was provided as a potential match
    //    --> If that last reported potential match was
    //        all one-bits, then early-exit with false
    //        because the whole keyspace was exhausted.
    //    --> Since state stores the last key reported,
    //        setup to continue search at the first
    //        bit that was zero.

    // Early exit when no more keys to test
    if (!g_S.more_keys_to_test) {
        return false;
    }

    KEY_BITS_K47_TO_K00 k_low;
    int8_t current_key_bit_shift;

    // Setup the next key to be tested.
    if (g_S.is_fresh_initialization) {
        // first-time init is easy: key is zero, and zero bits set
        g_S.is_fresh_initialization = false;
        k_low.Raw = 0ull;
        current_key_bit_shift = 47;
    }
    else {
        // by definition, a returned potential key had all the bits defined
        current_key_bit_shift = 0;
        k_low = g_S.last_returned_potential_key;

        // edge case: returned potential key 0xFFFFFFFFFFFFull, so no more keys to be tested!
        if (k_low.Raw == 0xFFFFFFFFFFFFull) {
            g_S.more_keys_to_test = false;
            return false;
        }

        // backtrack to first zero value, flipping bits...
        if (1) {
            uint64_t mask = (1ull << current_key_bit_shift);
            while ((mask & k_low.Raw) != 0) {
                k_low.Raw ^= mask;
                mask <<= 1;
                ++current_key_bit_shift;
            }
            // and flip that next bit also
            k_low.Raw ^= mask;
        }
    }

    // TODO: move above setup to re-use code in below loop ...
    //       especially since backtracking logic is duplicated?
    //       may require re-arranging the order in which things
    //       occur in the while loop?


    // Two exit conditions from this point on:
    // 1. potential key was found (and thus returned)
    // 2. no more keys to be tested (returns false)
    while (1) {
        // Currently, at loop start, ready to test the current bit vs. expected value

        ASSERT(current_key_bit_shift < 48);
        // Anytime bit shift is 40+, changes would affect s00 ...
        if (current_key_bit_shift > 39) {
            restart_and_calculate_s00(&g_S, &k_low);
            current_key_bit_shift = 39; // k47..k40 used to get to s00
        }

        ASSERT(current_key_bit_shift < 40);
        // Anytime bit shift is 33+, unconditionally calculate through s07,
        // because the output bits are not exposed, and thus cannot be validated.
        while (current_key_bit_shift > 32) { // k39..k33 used to move from s00-->s07
            uint8_t src_idx = 39 - current_key_bit_shift;
            bool input_bit = !!(((uint8_t)(k_low.Raw >> current_key_bit_shift)) & 0x1u);
            ID48LIBX_SUCCESSOR_RESULT r = successor_fn(&(g_S.states[src_idx]), input_bit);
            g_S.states[src_idx + 1] = r.state;
            --current_key_bit_shift;
        }


        ASSERT(current_key_bit_shift <= 32); // K₃₂ is used with s₀₇ to generate first output bit O₀₀
        ASSERT(current_key_bit_shift >=  0); // K₀₀ is a special case ... so negative is unexpected

        // Check if the current state + current key bit (as stored) gives expected result.
        const uint8_t src_idx = 39 - current_key_bit_shift;
        bool input_bit = !!(((uint8_t)(k_low.Raw >> current_key_bit_shift)) & 0x1u);
        ID48LIBX_SUCCESSOR_RESULT r = successor_fn(&(g_S.states[src_idx]), input_bit);
        // can unconditionally overwrite next state...
        g_S.states[src_idx + 1] = r.state;

        bool expected_result = get_expected_output_bit(&g_S, src_idx);
        bool matched = expected_result == (!!r.output);
        // when matched the last bit, actually check the next 15x inputs (all zero) as well
        if (matched && current_key_bit_shift == 0) {
            // that was the last bit to be checked in this potential key
            // but, must also test 15x additional zero bit inputs before
            // reporting that this may be a potential key
            ASSERT(src_idx == 39);
            matched = validate_output_from_additional_fifteen_zero_bits(&g_S);
        }

        // Exit point ... found a potential key!
        if (matched && current_key_bit_shift == 0) {
            g_S.last_returned_potential_key = k_low;
            potential_key_output->k[ 0] = g_S.known_k95_to_k48.k[0];
            potential_key_output->k[ 1] = g_S.known_k95_to_k48.k[1];
            potential_key_output->k[ 2] = g_S.known_k95_to_k48.k[2];
            potential_key_output->k[ 3] = g_S.known_k95_to_k48.k[3];
            potential_key_output->k[ 4] = g_S.known_k95_to_k48.k[4];
            potential_key_output->k[ 5] = g_S.known_k95_to_k48.k[5];
            potential_key_output->k[ 6] = (uint8_t)(k_low.Raw >> (8 * 5));
            potential_key_output->k[ 7] = (uint8_t)(k_low.Raw >> (8 * 4));
            potential_key_output->k[ 8] = (uint8_t)(k_low.Raw >> (8 * 3));
            potential_key_output->k[ 9] = (uint8_t)(k_low.Raw >> (8 * 2));
            potential_key_output->k[10] = (uint8_t)(k_low.Raw >> (8 * 1));
            potential_key_output->k[11] = (uint8_t)(k_low.Raw >> (8 * 0));
            return true;
        }
        // that bit of the key was OK, but there are more to check
        else if (matched) {
            --current_key_bit_shift;
        }
        // wrong output generated with that bit.
        // Backtrack to find next one to be tested.
        else {
            // not required ... but makes debugging easier
            memset(&g_S.states[src_idx + 1], 0xAA, sizeof(ID48LIBX_STATE_REGISTERS));

            // that bit of the key results in wrong output.
            // backtrack until the next zero bit, flip it to one, and
            // continue testing from there...
            if (1) {
                // This is ***NOT*** the same as simply adding 1.
                // (Consider, for example, when current_key_bit_shift == 3.)
                uint64_t mask = 1ull << current_key_bit_shift;
                while ((mask & k_low.Raw) != 0) {
                    k_low.Raw ^= mask;
                    mask <<= 1;
                    ++current_key_bit_shift;
                }
                // found a zero bit, so flip it
                // this is the next key to test
                k_low.Raw ^= mask;
            }

            // EXIT CONDITION: k_low wraps to invalid value
            if (current_key_bit_shift >= 48) {
                // no more results available ... return!
                g_S.more_keys_to_test = false;
                return 0u;
            }

        }
    } // end while(1) loop
}




//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ******************************************************************************************************************** //
// *** Everything above this line in the file is declared static,                                                   *** //
// *** which avoids polluting the global namespace.                                                                 *** //
// *** Everything below is technically visible, but not necessarily an exported API.                                *** //
// *** In C++, this separation is much more easily achieved using an anonymous namespace.  C'est la vie!            *** //
// ******************************************************************************************************************** //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////


void id48lib_key_recovery_init(
    const ID48LIB_KEY   * input_partial_key,
    const ID48LIB_NONCE * input_nonce,
    const ID48LIB_FRN   * input_frn,
    const ID48LIB_GRN   * input_grn
    )
{
    init(input_partial_key, input_nonce, input_frn, input_grn);
}
bool id48lib_key_recovery_next(
    ID48LIB_KEY* potential_key_output
) {
    return get_next_potential_key(potential_key_output);
}
