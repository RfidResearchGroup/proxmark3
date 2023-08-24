/*
 *
 * SecureMemory recovery Multithread
 *
 * Copyright (C) 2010, Flavio D. Garcia, Peter van Rossum, Roel Verdult
 * and Ronny Wichers Schreur. Radboud University Nijmegen
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Modified Iceman, 2020
 */

#include <stdio.h>
#include <string.h>
#include <inttypes.h>
#include <iostream>
#include <vector>
#include <map>
#include <algorithm>   // sort, max_element, random_shuffle, remove_if, lower_bound
#include <functional>  // greater, bind2nd
#include <thread>      // std::thread
#include <atomic>
#include <mutex>
#include "cryptolib.h"
#include "util.h"

#ifdef __cplusplus
extern "C" {
#endif

using namespace std;

#ifdef _MSC_VER
// avoid scanf warnings in Visual Studio
#define _CRT_SECURE_NO_WARNINGS
#define _CRT_SECURE_NO_DEPRECATE
#define inline __inline
#endif

/*
>./sm 4f794a463ff81d81 ffffffffffffffff 1234567812345678
SecureMemory simulator - (c) Radboud University Nijmegen

Authenticate
  Gc: 4f 79 4a 46 3f f8 1d 81
  Ci: ff ff ff ff ff ff ff ff
   Q: 12 34 56 78 12 34 56 78
  Ch: 88 c9 d4 46 6a 50 1a 87
Ci+1: de c2 ee 1b 1c 92 76 e9

  Ks: de 88 c2 c9 ee d4 1b 46 1c 6a 92 50 76 1a e9 87

   left: 1ddeac626
  right: 19aba45

  left-candidates bins:
  004df8a64 (74)
  0059ff7d5 (81)
  00d2ff4ed (80)
  032df8b12 (78)
  0337b8b7d (87)
  036f7b607 (77)
  03a6f882a (79)
  03b2ff59b (76)
  04445c715 (74)
  0452175be (80)
  0b29f2a5b (78)
  0f6c834fb (76)
  0f78aac5b (75)
  0f79c8d49 (78)
  109691f61 (70)
  159d1687e (86)
  176e73456 (77)
  1ddeac626 (92)
  1facee6e5 (78)
  2049ed469 (80)
  205078bba (74)
  31c277406 (81)
  31c2777e6 (81)
  3770cdaf3 (74)
  48916e84e (77)
  4ba9b6520 (78)
  4ba9b653f (78)
  4c51c6463 (82)
  4c9432733 (76)
  4e3d88819 (81)
  4e3d88bf9 (81)
  51c8755b5 (76)
  5b2aeb858 (76)
  5fb612b96 (80)
  60531191a (78)
  6221539d9 (92)
  68918cba9 (79)
  6c9a11672 (78)
  6f696e09e (70)
  7086372b6 (78)
  7bade8a41 (82)
  7c90849f8 (77)
  7cc847482 (87)

const uint64_t left_candidates[43] = {
    0x6221539d9ull, 0x1ddeac626ull, 0x7cc847482ull, 0x0337b8b7dull,
    0x159d1687eull, 0x7bade8a41ull, 0x4c51c6463ull, 0x4e3d88bf9ull,
    0x4e3d88819ull, 0x31c2777e6ull, 0x31c277406ull, 0x0059ff7d5ull,
    0x5fb612b96ull, 0x2049ed469ull, 0x0452175beull, 0x00d2ff4edull,
    0x68918cba9ull, 0x03a6f882aull, 0x7086372b6ull, 0x6c9a11672ull,
    0x60531191aull, 0x4ba9b653full, 0x4ba9b6520ull, 0x1facee6e5ull,
    0x0f79c8d49ull, 0x0b29f2a5bull, 0x032df8b12ull, 0x7c90849f8ull,
    0x48916e84eull, 0x176e73456ull, 0x036f7b607ull, 0x5b2aeb858ull,
    0x51c8755b5ull, 0x4c9432733ull, 0x0f6c834fbull, 0x03b2ff59bull,
    0x0f78aac5bull, 0x3770cdaf3ull, 0x205078bbaull, 0x04445c715ull,
    0x004df8a64ull, 0x6f696e09eull, 0x109691f61ull
};
*/

typedef struct {
    uint64_t l;
    uint64_t m;
    uint64_t r;
    nibble b0;
    nibble b1;
    nibble b1l;
    nibble b1r;
    nibble b1s;
    bool invalid;
    uint8_t Gc[8];
} cs_t;
typedef cs_t *pcs;

typedef struct {
    uint8_t addition;
    uint8_t out;
} lookup_entry;

enum cipher_state_side {
    CSS_LEFT,
    CSS_RIGHT
};

void print_cs(const char *text, pcs s) {
    int pos;

    printf("%s", text);

    for (pos = 6; pos >= 0; pos--)
        printf(" %02x", (uint8_t)(s->l >> (pos * 5)) & 0x1f);

    printf(" |");
    for (pos = 6; pos >= 0; pos--)
        printf(" %02x", (uint8_t)(s->m >> (pos * 7)) & 0x7f);

    printf(" |");

    for (pos = 4; pos >= 0; pos--)
        printf(" %02x", (uint8_t)(s->r >> (pos * 5)) & 0x1f);

    printf("\n");
}

static inline uint8_t mod(uint8_t a, uint8_t m) {
    if (m == 0) {
        return 0; // Actually, divide by zero error
    }

    // Just return the input when this is less or equal than the modular value
    if (a < m) return a;

    // Compute the modular value
    a %= m;

    // Return the funny value, when the output was now zero, return the modular value
    return (a == 0) ? m : a;
}

/*
static inline uint8_t bit_rotate_l(uint8_t a, uint8_t n_bits) {
  // Rotate value a with the length of n_bits only 1 time
  uint8_t mask = (1 << n_bits) - 1;
  return ((a << 1) | (a >> (n_bits - 1))) & mask;
}

static inline uint8_t bit_rotate_r(uint8_t a, uint8_t n_bits) {
  return ((a >> 1) | ((a&1) << (n_bits - 1)));
}
*/

#define BIT_ROL_MASK     ((1 << 5) - 1)
#define BIT_ROL(a)       ((((a) << 1) | ((a) >> 4)) & BIT_ROL_MASK)
#define BIT_ROR(a)       (((a) >> 1) | (((a) & 1) << 4))


static uint8_t lookup_left_subtraction[0x400];
static uint8_t lookup_right_subtraction[0x400];
static lookup_entry lookup_left[0x100000];
static lookup_entry lookup_right[0x8000];
static uint8_t left_addition[0x100000];

static inline void init_lookup_left() {
    for (int i = 0; i < 0x400; i++) {
        uint8_t b6 = i & 0x1f;
        uint8_t b3 = (i >> 5) & 0x1f;
        int index = (b3 << 15) | b6;

//      b6 = bit_rotate_l(b6, 5);
        b6 = BIT_ROL(b6);

        uint8_t temp = mod(b3 + b6, 0x1f);
        left_addition[index] = temp;
        lookup_left[index].addition = temp;
        lookup_left[index].out = ((temp ^ b3) & 0x0f);
    }
}

static inline void init_lookup_right() {
    for (int i = 0; i < 0x400; i++) {
        uint8_t b18 = i & 0x1f;
        uint8_t b16 = (i >> 5) & 0x1f;
        int index = (b16 << 10) | b18;

        uint8_t temp = mod(b18 + b16, 0x1f);
        lookup_right[index].addition = temp;
        lookup_right[index].out = ((temp ^ b16) & 0x0f);
    }
}

static void init_lookup_left_subtraction() {
    for (int index = 0; index < 0x400 ; index++) {
        uint8_t b3 = (index >> 5 & 0x1f);
        uint8_t bx = (index & 0x1f);

        //lookup_left_subtraction[index] = bit_rotate_r(mod((bx+0x1f)-b3,0x1f),5);
        lookup_left_subtraction[index] = BIT_ROR(mod((bx + 0x1F) - b3, 0x1F));
    }
}

static void init_lookup_right_subtraction() {
    for (int index = 0; index < 0x400 ; index++) {
        int b16 = (index >> 5);
        uint8_t bx = (index & 0x1f);
        lookup_right_subtraction[index] = mod((bx + 0x1F) - b16, 0x1F);
    }
}

static inline void previous_left(uint8_t in, vector<cs_t> *candidate_states) {
    pcs state;
    size_t size = candidate_states->size();
    for (size_t pos = 0; pos < size; pos++)  {
        state = &((*candidate_states)[pos]);

        uint8_t bx = (uint8_t)((state->l >> 30) & 0x1f);
        unsigned b3 = (unsigned)(state->l >> 5) & 0x3e0;
        state->l = (state->l << 5);

        //Ignore impossible states
        if (bx == 0) {
            // Are we dealing with an impossible state?
            if (b3 != 0) {
                state->invalid = true;
            } else {
                // We only need to consider b6=0
                state->l &= 0x7ffffffe0ull;
                state->l ^= (((uint64_t)in & 0x1f) << 20);
            }
        } else {
            uint8_t b6 = lookup_left_subtraction[b3 | bx];
            state->l = (state->l & 0x7ffffffe0ull) | b6;
            state->l ^= (((uint64_t)in & 0x1f) << 20);

            // Check if we have a second candidate
            if (b6 == 0x1f) {
                cs_t nstate = *state;
                nstate.l &= 0x7ffffffe0ull;
                candidate_states->push_back(nstate);
            }
        }
    }
}

static inline void previous_right(uint8_t in, vector<cs_t> *candidate_states) {
    pcs state;
    size_t size = candidate_states->size();
    for (size_t pos = 0; pos < size; pos++) {
        state = &((*candidate_states)[pos]);

        uint8_t bx = (uint8_t)((state->r >> 20) & 0x1f);
        unsigned b16 = (unsigned)(state->r & 0x3e0);//(state->buffer_r >> 10) & 0x1f;

        state->r = (state->r << 5);

        // Ignore impossible states
        if (bx == 0) {
            if (b16 != 0) {
                state->invalid = true;
            } else {
                // We only need to consider b18=0
                state->r &= 0x1ffffe0ull;
                state->r ^= (((uint64_t)in & 0xf8) << 12);
            }
        } else {
            uint8_t b18 = lookup_right_subtraction[b16 | bx];
            state->r = (state->r & 0x1ffffe0ull) | b18;
            state->r ^= (((uint64_t)in & 0xf8) << 12);
            //state->b_right  = ((b14^b17) & 0x0f);

            // Check if we have a second candidate
            if (b18 == 0x1f) {
                cs_t nstate = *state;
                nstate.r &= 0x1ffffe0ull;
                candidate_states->push_back(nstate);
            }
        }
    }
}

static inline uint8_t next_left_fast(uint8_t in, uint64_t *left) {
    if (in)
        *left ^= ((in & 0x1f) << 20);

    lookup_entry *lookup = &(lookup_left[((*left) & 0xf801f)]);
    *left = (((*left) >> 5) | ((uint64_t)lookup->addition << 30));
    return lookup->out;
}

static inline uint8_t next_left_ksbyte(uint64_t *left) {
    lookup_entry *lookup;
    uint8_t bt;

    *left = (((*left) >> 5) | ((uint64_t)left_addition[((*left) & 0xf801f)] << 30));
    lookup = &(lookup_left[((*left) & 0xf801f)]);
    *left = (((*left) >> 5) | ((uint64_t)lookup->addition << 30));
    bt = lookup->out << 4;
    *left = (((*left) >> 5) | ((uint64_t)left_addition[((*left) & 0xf801f)] << 30));
    lookup = &(lookup_left[((*left) & 0xf801f)]);
    *left = (((*left) >> 5) | ((uint64_t)lookup->addition << 30));
    bt |= lookup->out;
    return bt;
}

static inline uint8_t next_right_fast(uint8_t in, uint64_t *right) {
    if (in) *right ^= ((in & 0xf8) << 12);
    lookup_entry *lookup = &(lookup_right[((*right) & 0x7c1f)]);
    *right = (((*right) >> 5) | (lookup->addition << 20));
    return lookup->out;
}

static inline void sm_left_mask(const uint8_t *ks, uint8_t *mask, uint64_t rstate) {
    for (uint8_t pos = 0; pos < 16; pos++) {
        next_right_fast(0, &rstate);
        uint8_t bt = next_right_fast(0, &rstate) << 4;
        next_right_fast(0, &rstate);
        bt |= next_right_fast(0, &rstate);

        // xor the bits with the keystream and count the "correct" bits
        bt ^= ks[pos];

        // Save the mask for the left produced bits
        mask[pos] = bt;
    }
}


std::atomic<bool> key_found{0};
std::atomic<uint64_t> key{0};
std::atomic<size_t> g_topbits{0};
std::mutex g_ice_mtx;
static uint32_t g_num_cpus = std::thread::hardware_concurrency();

static void ice_sm_right_thread(
    uint8_t offset,
    uint8_t skips,
    const uint8_t *ks,
    map<uint64_t, uint64_t> *bincstates,
    uint8_t *mask
) {

    uint8_t tmp_mask[16];
    uint8_t bt;

    for (uint64_t counter = offset; counter < 0x2000000; counter += skips) {
        // Reset the current bitcount of correct bits
        size_t bits = 0;

        // Copy the state we are going to test
        uint64_t rstate = counter;

        for (uint8_t pos = 0; pos < 16; pos++) {

            next_right_fast(0, &rstate);

            bt = next_right_fast(0, &rstate) << 4;

            next_right_fast(0, &rstate);

            bt |= next_right_fast(0, &rstate);

            // xor the bits with the keystream and count the "correct" bits
            bt ^= ks[pos];

            // Save the mask for the left produced bits
            tmp_mask[pos] = bt;

            // When the bit is xored away (=zero), it was the same, so correct ;)
            if ((bt & 0x01) == 0) bits++;
            if (((bt >> 1) & 0x01) == 0) bits++;
            if (((bt >> 2) & 0x01) == 0) bits++;
            if (((bt >> 3) & 0x01) == 0) bits++;
            if (((bt >> 4) & 0x01) == 0) bits++;
            if (((bt >> 5) & 0x01) == 0) bits++;
            if (((bt >> 6) & 0x01) == 0) bits++;
            if (((bt >> 7) & 0x01) == 0) bits++;
        }

        g_ice_mtx.lock();
        if (bits > g_topbits.load(std::memory_order_relaxed)) {
            // Copy the winning mask
            g_topbits = bits;
            memcpy(mask, tmp_mask, 16);
        }
        g_ice_mtx.unlock();

        // Ignore states under 90
        if (bits >= 90) {
            //  Make sure the bits are used for ordering
            g_ice_mtx.lock();
            if (bincstates->find((((uint64_t)bits) << 56) | counter) != bincstates->end())
                bincstates->at((((uint64_t)bits) << 56) | counter) = counter;
            else
                bincstates->insert(std::pair<uint64_t, uint64_t>((((uint64_t)bits) << 56) | counter, counter));
            g_ice_mtx.unlock();
        }

        if ((counter & 0xfffff) == 0) {
            g_ice_mtx.lock();
            printf(".");
            fflush(stdout);
            g_ice_mtx.unlock();
        }
    }
}
static uint32_t ice_sm_right(const uint8_t *ks, uint8_t *mask, vector<uint64_t> *pcrstates) {

    map<uint64_t, uint64_t> bincstates;
    g_topbits = ATOMIC_VAR_INIT(0);

    std::vector<std::thread> threads(g_num_cpus);
    for (uint8_t m = 0; m < g_num_cpus; m++) {
        threads[m] = std::thread(ice_sm_right_thread, m, g_num_cpus, ks, &bincstates, mask);
    }
    for (auto &t : threads) {
        t.join();
    }

    printf("\n");

    // Clear the candidate state vector
    pcrstates->clear();

    // Copy the order the states from lowest-bin to highest-bin
    map<uint64_t, uint64_t>::iterator it;
    for (it = bincstates.begin(); it != bincstates.end(); ++it) {
        pcrstates->push_back(it->second);
    }

    // Reverse the vector order (so the highest bin comes first)
    reverse(pcrstates->begin(), pcrstates->end());

    return g_topbits;
}

static void ice_sm_left_thread(
    uint8_t offset,
    uint8_t skips,
    const uint8_t *ks,
    map<uint64_t, cs_t> *bincstates,
    const uint8_t *mask
) {

    size_t pos, bits;
    uint8_t correct_bits[16];
    uint8_t bt;
    lookup_entry *lookup;

    // Reset and initialize the cryptostate and vector
    cs_t state;
    memset(&state, 0x00, sizeof(cs_t));
    state.invalid = false;

    for (uint64_t counter = offset; counter < 0x800000000ull; counter += skips) {
        uint64_t lstate = counter;

        for (pos = 0; pos < 16; pos++) {

            lstate = (((lstate) >> 5) | ((uint64_t)left_addition[((lstate) & 0xf801f)] << 30));
            lookup = &(lookup_left[((lstate) & 0xf801f)]);
            lstate = (((lstate) >> 5) | ((uint64_t)lookup->addition << 30));
            bt = lookup->out << 4;
            lstate = (((lstate) >> 5) | ((uint64_t)left_addition[((lstate) & 0xf801f)] << 30));
            lookup = &(lookup_left[((lstate) & 0xf801f)]);
            lstate = (((lstate) >> 5) | ((uint64_t)lookup->addition << 30));
            bt |= lookup->out;

            // xor the bits with the keystream and count the "correct" bits
            bt ^= ks[pos];

            // When the REQUIRED bits are NOT xored away (=zero), ignore this wrong state
            if ((bt & mask[pos]) != 0) break;

            // Save the correct bits for statistical information
            correct_bits[pos] = bt;
        }

        // If we have parsed all 16 bytes of keystream, we have a valid CANDIDATE!
        if (pos == 16) {
            // Count the total correct bits
            bits = 0;
            for (pos = 0; pos < 16; pos++) {
                // Get the next byte-value with correct bits
                bt = correct_bits[pos];

                // Count all the (correct) bits
                // When the bit is xored away (=zero), it was the same, so correct ;)
                if ((bt & 0x01) == 0) bits++;
                if (((bt >> 1) & 0x01) == 0) bits++;
                if (((bt >> 2) & 0x01) == 0) bits++;
                if (((bt >> 3) & 0x01) == 0) bits++;
                if (((bt >> 4) & 0x01) == 0) bits++;
                if (((bt >> 5) & 0x01) == 0) bits++;
                if (((bt >> 6) & 0x01) == 0) bits++;
                if (((bt >> 7) & 0x01) == 0) bits++;
            }

            state.l = counter;

            //  Make sure the bits are used for ordering
            g_ice_mtx.lock();
            printf(".");
            fflush(stdout);
            if (bincstates->find((((uint64_t)bits) << 56) | counter) != bincstates->end())
                bincstates->at((((uint64_t)bits) << 56) | counter) = state;
            else
                bincstates->insert(std::pair<uint64_t, cs_t>((((uint64_t)bits) << 56) | counter, state));
            g_ice_mtx.unlock();

        }

        if ((counter & 0xffffffffull) == 0) {
            g_ice_mtx.lock();
            printf("%02.1f%%.", ((float)100 / 8) * (counter >> 32));
            fflush(stdout);
            g_ice_mtx.unlock();
        }
    }
}

static void ice_sm_left(const uint8_t *ks, uint8_t *mask, vector<cs_t> *pcstates) {

    map<uint64_t, cs_t> bincstates;
    std::vector<std::thread> threads(g_num_cpus);
    for (uint8_t m = 0; m < g_num_cpus; m++) {
        threads[m] = std::thread(ice_sm_left_thread, m, g_num_cpus, ks, &bincstates, mask);
    }

    for (auto &t : threads) {
        t.join();
    }

    printf("100%%\n");

    // Clear the candidate state vector
    pcstates->clear();

    // Copy the order the states from lowest-bin to highest-bin
    map<uint64_t, cs_t>::iterator it;
    for (it = bincstates.begin(); it != bincstates.end(); ++it) {
        pcstates->push_back(it->second);
    }
    // Reverse the vector order (so the highest bin comes first)
    reverse(pcstates->begin(), pcstates->end());
}

static inline uint32_t sm_right(const uint8_t *ks, uint8_t *mask, vector<uint64_t> *pcrstates) {
    uint8_t tmp_mask[16];
    size_t topbits = 0;
    map<uint64_t, uint64_t> bincstates;
    map<uint64_t, uint64_t>::iterator it;


    for (uint64_t counter = 0; counter < 0x2000000; counter++) {
        // Reset the current bitcount of correct bits
        size_t bits = 0;

        // Copy the state we are going to test
        uint64_t rstate = counter;

        for (size_t pos = 0; pos < 16; pos++) {
            next_right_fast(0, &rstate);
            uint8_t bt = next_right_fast(0, &rstate) << 4;
            next_right_fast(0, &rstate);
            bt |= next_right_fast(0, &rstate);

            // xor the bits with the keystream and count the "correct" bits
            bt ^= ks[pos];

            // Save the mask for the left produced bits
            tmp_mask[pos] = bt;

            for (size_t bit = 0; bit < 8; bit++) {
                // When the bit is xored away (=zero), it was the same, so correct ;)
                if ((bt & 0x01) == 0) bits++;
                bt >>= 1;
            }
        }

        if (bits > topbits) {
            topbits = bits;
            // Copy the winning mask
            memcpy(mask, tmp_mask, 16);
        }

        // Ignore states under 90
        if (bits >= 90) {
            //  Make sure the bits are used for ordering
            bincstates[(((uint64_t)bits) << 56) | counter] = counter;
        }

        if ((counter & 0xfffff) == 0) {
            printf(".");
            fflush(stdout);
        }
    }
    printf("\n");

    // Clear the candidate state vector
    pcrstates->clear();

    // Copy the order the states from lowest-bin to highest-bin
    for (it = bincstates.begin(); it != bincstates.end(); ++it) {
        pcrstates->push_back(it->second);
    }

    // Reverse the vector order (so the highest bin comes first)
    reverse(pcrstates->begin(), pcrstates->end());

    return topbits;
}

static inline void previous_all_input(vector<cs_t> *pcstates, uint32_t gc_byte_index, cipher_state_side css) {
    uint8_t btGc, in;
    vector<cs_t> ncstates;
    vector<cs_t> prev_ncstates;
    vector<cs_t>::iterator itnew;

    // Loop through the complete entryphy of 5 bits for each candidate
    // We ignore zero (xor 0x00) to avoid duplicates
    for (btGc = 0; btGc < 0x20; btGc++)  {
        // Copy the original candidates that are supplied
        ncstates = *pcstates;

        // Rollback the (candidate) cipher states with this input
        if (css == CSS_RIGHT) {
            in = btGc << 3;
            previous_right(in, &ncstates);
        } else {
            in = btGc;
            previous_left(in, &ncstates);
        }

        for (itnew = ncstates.begin(); itnew != ncstates.end(); ++itnew)  {
            // Wipe away the invalid states
            if (itnew->invalid == false) {
                itnew->Gc[gc_byte_index] = in;
                prev_ncstates.push_back(*itnew);
            }
        }
    }

    // Copy the previous states into the vector
    *pcstates = prev_ncstates;
}

static inline void search_gc_candidates_right(const uint64_t rstate_before_gc, const uint64_t rstate_after_gc, const uint8_t *Q, vector<cs_t> *pcstates) {
    vector<cs_t>::iterator it;
    vector<cs_t> csl_cand;
    map<uint64_t, uint64_t> matchbox;
    map<uint64_t, uint64_t>::iterator itmatch;
    uint64_t rstate;
    size_t counter;
    cs_t state;

    // Generate 2^20 different (5 bits) values for the first 4 Gc bytes (0,1,2,3)
    for (counter = 0; counter < 0x100000; counter++) {
        rstate  = rstate_before_gc;
        next_right_fast((counter >> 12) & 0xf8, &rstate);
        next_right_fast((counter >> 7)  & 0xf8, &rstate);
        next_right_fast(Q[4], &rstate);
        next_right_fast((counter >> 2) & 0xf8, &rstate);
        next_right_fast((counter << 3) & 0xf8, &rstate);
        next_right_fast(Q[5], &rstate);
        matchbox[rstate] = counter;
    }

    // Reset and initialize the cryptostate and vecctor
    memset(&state, 0x00, sizeof(cs_t));
    state.invalid = false;
    state.r = rstate_after_gc;
    csl_cand.clear();
    csl_cand.push_back(state);

    // Generate 2^20(+splitting) different (5 bits) values for the last 4 Gc bytes (4,5,6,7)
    previous_right(Q[7], &csl_cand);
    previous_all_input(&csl_cand, 7, CSS_RIGHT);
    previous_all_input(&csl_cand, 6, CSS_RIGHT);
    previous_right(Q[6], &csl_cand);
    previous_all_input(&csl_cand, 5, CSS_RIGHT);
    previous_all_input(&csl_cand, 4, CSS_RIGHT);

    pcstates->clear();

    // Take the intersection of the corresponding states ~2^15 values (40-25 = 15 bits)
    for (it = csl_cand.begin(); it != csl_cand.end(); ++it) {
        itmatch = matchbox.find(it->r);
        if (itmatch != matchbox.end()) {
            it->Gc[0] = (itmatch->second >> 12) & 0xf8;
            it->Gc[1] = (itmatch->second >>  7) & 0xf8;
            it->Gc[2] = (itmatch->second >>  2) & 0xf8;
            it->Gc[3] = (itmatch->second <<  3) & 0xf8;

            pcstates->push_back(*it);
        }
    }
}

static inline void sm_left(const uint8_t *ks, const uint8_t *mask, vector<cs_t> *pcstates) {
    map<uint64_t, cs_t> bincstates;
    map<uint64_t, cs_t>::iterator it;
    uint64_t counter;
    size_t pos, bits;
    uint8_t correct_bits[16];
    uint8_t bt;
    cs_t state;
    lookup_entry *lookup;

    // Reset and initialize the cryptostate and vecctor
    memset(&state, 0x00, sizeof(cs_t));
    state.invalid = false;

    for (counter = 0; counter < 0x800000000ull; counter++) {
        uint64_t lstate = counter;

        for (pos = 0; pos < 16; pos++) {

            lstate = (((lstate) >> 5) | ((uint64_t)left_addition[((lstate) & 0xf801f)] << 30));
            lookup = &(lookup_left[((lstate) & 0xf801f)]);
            lstate = (((lstate) >> 5) | ((uint64_t)lookup->addition << 30));
            bt = lookup->out << 4;
            lstate = (((lstate) >> 5) | ((uint64_t)left_addition[((lstate) & 0xf801f)] << 30));
            lookup = &(lookup_left[((lstate) & 0xf801f)]);
            lstate = (((lstate) >> 5) | ((uint64_t)lookup->addition << 30));
            bt |= lookup->out;

            // xor the bits with the keystream and count the "correct" bits
            bt ^= ks[pos];

            // When the REQUIRED bits are NOT xored away (=zero), ignore this wrong state
            if ((bt & mask[pos]) != 0) break;

            // Save the correct bits for statistical information
            correct_bits[pos] = bt;
        }

        // If we have parsed all 16 bytes of keystream, we have a valid CANDIDATE!
        if (pos == 16) {
            // Count the total correct bits
            bits = 0;
            for (pos = 0; pos < 16; pos++) {
                // Get the next byte-value with correct bits
                bt = correct_bits[pos];

                // Count all the (correct) bits
                // When the bit is xored away (=zero), it was the same, so correct ;)
                if ((bt & 0x01) == 0) bits++;
                if (((bt >> 1) & 0x01) == 0) bits++;
                if (((bt >> 2) & 0x01) == 0) bits++;
                if (((bt >> 3) & 0x01) == 0) bits++;
                if (((bt >> 4) & 0x01) == 0) bits++;
                if (((bt >> 5) & 0x01) == 0) bits++;
                if (((bt >> 6) & 0x01) == 0) bits++;
                if (((bt >> 7) & 0x01) == 0) bits++;

            }

            // Print the left candidate
            //      printf("%09llx (%d)\n",counter,bits);
            printf(".");
            fflush(stdout);

            state.l = counter;
            //  Make sure the bits are used for ordering
            bincstates[(((uint64_t)bits) << 56) | counter] = state;
        }

        if ((counter & 0xffffffffull) == 0) {
            printf("%02.1f%%.", ((float)100 / 8) * (counter >> 32));
            fflush(stdout);
        }
    }

    printf("100%%\n");

    // Clear the candidate state vector
    pcstates->clear();

    // Copy the order the states from lowest-bin to highest-bin
    for (it = bincstates.begin(); it != bincstates.end(); ++it) {
        pcstates->push_back(it->second);
    }
    // Reverse the vector order (so the highest bin comes first)
    reverse(pcstates->begin(), pcstates->end());
}

static inline void search_gc_candidates_left(const uint64_t lstate_before_gc, const uint8_t *Q, vector<cs_t> *pcstates) {
    vector<cs_t> csl_cand, csl_search;
    vector<cs_t>::iterator itsearch, itcand;
    map<uint64_t, uint64_t> matchbox;
    map<uint64_t, uint64_t>::iterator itmatch;
    uint64_t lstate;
    size_t counter;

    // Generate 2^20 different (5 bits) values for the first 4 Gc bytes (0,1,2,3)
    for (counter = 0; counter < 0x100000; counter++) {
        lstate  = lstate_before_gc;
        next_left_fast((counter >> 15) & 0x1f, &lstate);
        next_left_fast((counter >> 10) & 0x1f, &lstate);
        next_left_fast(Q[4], &lstate);
        next_left_fast((counter >> 5) & 0x1f, &lstate);
        next_left_fast(counter & 0x1f, &lstate);
        next_left_fast(Q[5], &lstate);
        matchbox[lstate] = counter;
    }

    // Copy the input candidate states and clean the output vector
    csl_cand = *pcstates;
    pcstates->clear();

    for (itcand = csl_cand.begin(); itcand != csl_cand.end(); ++itcand) {
        csl_search.clear();
        csl_search.push_back(*itcand);

        // Generate 2^20(+splitting) different (5 bits) values for the last 4 Gc bytes (4,5,6,7)
        previous_left(Q[7], &csl_search);
        previous_all_input(&csl_search, 7, CSS_LEFT);
        previous_all_input(&csl_search, 6, CSS_LEFT);
        previous_left(Q[6], &csl_search);
        previous_all_input(&csl_search, 5, CSS_LEFT);
        previous_all_input(&csl_search, 4, CSS_LEFT);

        // Take the intersection of the corresponding states ~2^15 values (40-25 = 15 bits)
        for (itsearch = csl_search.begin(); itsearch != csl_search.end(); ++itsearch) {
            itmatch = matchbox.find(itsearch->l);
            if (itmatch != matchbox.end()) {
                itsearch->Gc[0] = (itmatch->second >> 15) & 0x1f;
                itsearch->Gc[1] = (itmatch->second >> 10) & 0x1f;
                itsearch->Gc[2] = (itmatch->second >>  5) & 0x1f;
                itsearch->Gc[3] = itmatch->second & 0x1f;

                pcstates->push_back(*itsearch);
            }
        }
        printf(".");
        fflush(stdout);
    }
    printf("\n");
}

void combine_valid_left_right_states(vector<cs_t> *plcstates, vector<cs_t> *prcstates, vector<uint64_t> *pgc_candidates) {
    vector<cs_t>::iterator itl, itr;
    size_t pos, count;
    uint64_t gc;
    bool valid;

    vector<cs_t> outer, inner;
    if (plcstates->size() > prcstates->size()) {
        outer = *plcstates;
        inner = *prcstates;
    } else {
        outer = *prcstates;
        inner = *plcstates;
    }

    printf("Outer  " _YELLOW_("%zu")" , inner " _YELLOW_("%zu") "\n", outer.size(), inner.size());

    // Clean up the candidate list
    pgc_candidates->clear();
    count = 0;
    for (itl = outer.begin(); itl != outer.end(); ++itl) {
        for (itr = inner.begin(); itr != inner.end(); ++itr) {
            valid = true;
            // Check for left and right candidates that share the overlapping bits (8 x 2bits of Gc)
            for (pos = 0; pos < 8; pos++) {
                if ((itl->Gc[pos] & 0x18) != (itr->Gc[pos] & 0x18)) {
                    valid = false;
                    break;
                }
            }

            if (valid) {
                gc = 0;
                for (pos = 0; pos < 8; pos++) {
                    gc <<= 8;
                    gc |= (itl->Gc[pos] | itr->Gc[pos]);
                }

                pgc_candidates->push_back(gc);
            }
            count++;
        }
    }
    printf("Found a total of " _YELLOW_("%llu")" combinations, ", ((unsigned long long)plcstates->size()) * prcstates->size());
    printf("but only " _GREEN_("%zu")" were valid!\n", pgc_candidates->size());
}

static void ice_compare(
    uint8_t offset,
    uint8_t skips,
    vector<uint64_t> *candidates,
    crypto_state_t *ostate,
    uint8_t *Ci,
    uint8_t *Q,
    uint8_t *Ch,
    uint8_t *Ci_1
) {
    uint8_t Gc_chk[8] = {0};
    uint8_t Ch_chk[8] = {0};
    uint8_t Ci_1_chk[8] = {0};

    crypto_state_t ls;
    ls.b0 = ostate->b0;
    ls.b1 = ostate->b1;
    ls.b1l = ostate->b1l;
    ls.b1r = ostate->b1r;
    ls.b1s = ostate->b1s;
    ls.l = ostate->l;
    ls.m = ostate->m;
    ls.r = ostate->r;

    for (std::size_t i = offset; i < candidates->size(); i += skips) {
        if (key_found.load(std::memory_order_relaxed))
            break;

        uint64_t tkey = candidates->at(i);
        num_to_bytes(tkey, 8, Gc_chk);

        sm_auth(Gc_chk, Ci, Q, Ch_chk, Ci_1_chk, &ls);
        if ((memcmp(Ch_chk, Ch, 8) == 0) && (memcmp(Ci_1_chk, Ci_1, 8) == 0)) {
            g_ice_mtx.lock();
            key_found = true;
            key = tkey;
            g_ice_mtx.unlock();
            break;
        }
    }
    return;
}

int main(int argc, const char *argv[]) {
    size_t pos;
    crypto_state_t ostate;
    uint64_t rstate_before_gc, lstate_before_gc;
    vector<uint64_t> rstates, pgc_candidates;
    vector<uint64_t>::iterator itrstates;
    vector<cs_t> crstates, clstates;
    uint32_t rbits;

    //  uint8_t   Gc[ 8] = {0x4f,0x79,0x4a,0x46,0x3f,0xf8,0x1d,0x81};
    //  uint8_t   Gc[ 8] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    //  uint8_t   Ci[ 8] = {0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    //  uint8_t    Q[ 8] = {0x12,0x34,0x56,0x78,0x12,0x34,0x56,0x78};
    uint8_t   Gc[ 8];
    uint8_t   Ci[ 8];
    uint8_t    Q[ 8];
    uint8_t   Ch[ 8];
    uint8_t Ci_1[ 8];

    //  uint8_t   ks[16] = {0xde,0x88,0xc2,0xc9,0xee,0xd4,0x1b,0x46,0x1c,0x6a,0x92,0x50,0x76,0x1a,0xe9,0x87};
    //  uint8_t mask[16] = {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
    //  uint8_t mask[16] = {0x04,0xb0,0xe1,0x10,0xc0,0x33,0x44,0x20,0x20,0x00,0x70,0x8c,0x22,0x04,0x10,0x80};

    uint8_t   ks[16];
    uint8_t mask[16];

    uint64_t nCi;   // Card random
    uint64_t nQ;    // Reader random
    uint64_t nCh;   // Reader challenge
    uint64_t nCi_1; // Card answer

    if ((argc != 2) && (argc != 5)) {
        printf("SecureMemory recovery - (c) Radboud University Nijmegen\n\n");
        printf("syntax: sma_multi simulate\n");
        printf("        sma_multi <Ci> <Q> <Ch> <Ci+1>\n\n");
        return 1;
    }

    printf(_CYAN_("\nAuthentication info\n\n"));

    // Check if this is a simulation
    if (argc == 2) {
        // Generate random values for the key and randoms
        srand((uint32_t)time(NULL));
        for (pos = 0; pos < 8; pos++) {
            Gc[pos] = rand();
            Ci[pos] = rand();
            Q[pos] = rand();
        }
        sm_auth(Gc, Ci, Q, Ch, Ci_1, &ostate);
        printf("  Gc... ");
        print_bytes(Gc, 8);
    } else {
        sscanf(argv[1], "%016" SCNx64, &nCi);
        num_to_bytes(nCi, 8, Ci);
        sscanf(argv[2], "%016" SCNx64, &nQ);
        num_to_bytes(nQ, 8, Q);
        sscanf(argv[3], "%016" SCNx64, &nCh);
        num_to_bytes(nCh, 8, Ch);
        sscanf(argv[4], "%016" SCNx64, &nCi_1);
        num_to_bytes(nCi_1, 8, Ci_1);
        printf("  Gc... unknown\n");
    }

    for (pos = 0; pos < 8; pos++) {
        ks[2 * pos] = Ci_1[pos];
        ks[(2 * pos) + 1] = Ch[pos];
    }

    printf("  Ci... ");
    print_bytes(Ci, 8);
    printf("   Q... ");
    print_bytes(Q, 8);
    printf("  Ch... ");
    print_bytes(Ch, 8);
    printf("Ci+1... ");
    print_bytes(Ci_1, 8);
    printf("\n");
    printf("  Ks... ");
    print_bytes(ks, 16);
    printf("\n");

    printf("\nMultithreaded, will use " _YELLOW_("%u") " threads\n", g_num_cpus);
    printf("Initializing lookup tables for increasing cipher speed\n");

    std::thread foo_left(init_lookup_left);
    std::thread foo_right(init_lookup_right);
    std::thread foo_leftsub(init_lookup_left_subtraction);
    std::thread foo_rightsub(init_lookup_right_subtraction);

    foo_left.join();
    foo_right.join();
    foo_leftsub.join();
    foo_rightsub.join();

    // Load in the ci (tag-nonce), together with the first half of Q (reader-nonce)
    rstate_before_gc = 0;
    lstate_before_gc = 0;

    for (pos = 0; pos < 4; pos++) {
        next_right_fast(Ci[2 * pos  ], &rstate_before_gc);
        next_right_fast(Ci[2 * pos + 1], &rstate_before_gc);
        next_right_fast(Q[pos], &rstate_before_gc);

        next_left_fast(Ci[2 * pos  ], &lstate_before_gc);
        next_left_fast(Ci[2 * pos + 1], &lstate_before_gc);
        next_left_fast(Q[pos], &lstate_before_gc);
    }

    printf("Determing the right states that correspond to the keystream\n");
    //rbits = sm_right(ks, mask, &rstates);
    rbits = ice_sm_right(ks, mask, &rstates);

    printf("Top-bin for the right state contains " _GREEN_("%u")" correct bits\n", rbits);
    printf("Total count of right bins: " _YELLOW_("%zu") "\n", rstates.size());

    if (rbits < 96) {
        printf("\n" _RED_("WARNING!!!") ", better find another trace, the right top-bin is smaller than 96 bits\n\n");
    }

    for (itrstates = rstates.begin(); itrstates != rstates.end(); ++itrstates) {
        uint64_t rstate_after_gc = *itrstates;
        sm_left_mask(ks, mask, rstate_after_gc);
        printf("Using the state from the top-right bin: " _YELLOW_("0x%07" PRIx64)"\n", rstate_after_gc);

        search_gc_candidates_right(rstate_before_gc, rstate_after_gc, Q, &crstates);
        printf("Found " _YELLOW_("%zu")" right candidates using the meet-in-the-middle attack\n", crstates.size());
        if (crstates.size() == 0) continue;

        printf("Calculating left states using the (unknown bits) mask from the top-right state\n");
        //sm_left(ks, mask, &clstates);
        ice_sm_left(ks, mask, &clstates);

        printf("Found a total of " _YELLOW_("%zu")" left cipher states, recovering left candidates...\n", clstates.size());
        if (clstates.size() == 0) continue;
        search_gc_candidates_left(lstate_before_gc, Q, &clstates);


        printf("The meet-in-the-middle attack returned " _YELLOW_("%zu")" left cipher candidates\n", clstates.size());
        if (clstates.size() == 0) continue;

        printf("Combining left and right states, disposing invalid combinations\n");
        combine_valid_left_right_states(&clstates, &crstates, &pgc_candidates);

        printf("Filtering the correct one using the middle part\n");


        key_found = ATOMIC_VAR_INIT(false);
        key = ATOMIC_VAR_INIT(0);
        std::vector<std::thread> threads(g_num_cpus);
        for (uint8_t m = 0; m < g_num_cpus; m++) {
            threads[m] =  std::thread(ice_compare, m, g_num_cpus, &pgc_candidates, &ostate, ref(Ci), ref(Q), ref(Ch), ref(Ci_1));
        }

        for (auto &t : threads) {
            t.join();
        }

        if (key_found) {
            printf("\nValid key found [ " _GREEN_("%016" PRIx64)" ]\n\n", key.load());
            break;
        }

        printf(_RED_("\nCould not find key using this right cipher state.\n\n"));
    }
    return 0;
}

#if defined(__cplusplus)
}
#endif
