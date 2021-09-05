/* ht2crack5.c
 *
 * This code is heavily based on the HiTag2 Hell CPU implementation
 *  from https://github.com/factoritbv/hitag2hell by FactorIT B.V.,
 *  with the following changes:
 *  * Main takes a UID and 2 {nR},{aR} pairs as arguments
 *    and searches for states producing the first aR sample,
 *    reconstructs the corresponding key candidates
 *    and tests them against the second nR,aR pair;
 *  * Reuses the Hitag helping functions of the other attacks.
 */

#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <pthread.h>
#include "ht2crackutils.h"

const uint8_t bits[9] = {20, 14, 4, 3, 1, 1, 1, 1, 1};
#define lfsr_inv(state) (((state)<<1) | (__builtin_parityll((state) & ((0xce0044c101cd>>1)|(1ull<<(47))))))
#define i4(x,a,b,c,d) ((uint32_t)((((x)>>(a))&1)<<3)|(((x)>>(b))&1)<<2|(((x)>>(c))&1)<<1|(((x)>>(d))&1))
#define f(state) ((0xdd3929b >> ( (((0x3c65 >> i4(state, 2, 3, 5, 6) ) & 1) <<4) \
                                | ((( 0xee5 >> i4(state, 8,12,14,15) ) & 1) <<3) \
                                | ((( 0xee5 >> i4(state,17,21,23,26) ) & 1) <<2) \
                                | ((( 0xee5 >> i4(state,28,29,31,33) ) & 1) <<1) \
                                | (((0x3c65 >> i4(state,34,43,44,46) ) & 1) ))) & 1)

#define MAX_BITSLICES 256
#define VECTOR_SIZE (MAX_BITSLICES/8)

typedef unsigned int __attribute__((aligned(VECTOR_SIZE))) __attribute__((vector_size(VECTOR_SIZE))) bitslice_value_t;
typedef union {
    bitslice_value_t value;
    uint64_t bytes64[MAX_BITSLICES / 64];
    uint8_t bytes[MAX_BITSLICES / 8];
} bitslice_t;

// we never actually set or use the lowest 2 bits the initial state, so we can save 2 bitslices everywhere
__thread bitslice_t state[-2 + 32 + 48];

bitslice_t keystream[32];
bitslice_t bs_zeroes, bs_ones;

#define f_a_bs(a,b,c,d)       (~(((a|b)&c)^(a|d)^b)) // 6 ops
#define f_b_bs(a,b,c,d)       (~(((d|c)&(a^b))^(d|a|b))) // 7 ops
#define f_c_bs(a,b,c,d,e)     (~((((((c^e)|d)&a)^b)&(c^b))^(((d^e)|a)&((d^b)|c)))) // 13 ops
#define lfsr_bs(i) (state[-2+i+ 0].value ^ state[-2+i+ 2].value ^ state[-2+i+ 3].value ^ state[-2+i+ 6].value ^ \
                    state[-2+i+ 7].value ^ state[-2+i+ 8].value ^ state[-2+i+16].value ^ state[-2+i+22].value ^ \
                    state[-2+i+23].value ^ state[-2+i+26].value ^ state[-2+i+30].value ^ state[-2+i+41].value ^ \
                    state[-2+i+42].value ^ state[-2+i+43].value ^ state[-2+i+46].value ^ state[-2+i+47].value);
#define get_bit(n, word) ((word >> (n)) & 1)
#define get_vector_bit(slice, value) get_bit(slice&0x3f, value.bytes64[slice>>6])

static uint64_t expand(uint64_t mask, uint64_t value) {
    uint64_t fill = 0;
    for (uint64_t bit_index = 0; bit_index < 48; bit_index++) {
        if (mask & 1) {
            fill |= (value & 1) << bit_index;
            value >>= 1;
        }
        mask >>= 1;
    }
    return fill;
}

static void bitslice(const uint64_t value, bitslice_t *restrict bitsliced_value, const size_t bit_len, bool reverse) {
    size_t bit_idx;
    for (bit_idx = 0; bit_idx < bit_len; bit_idx++) {
        bool bit;
        if (reverse) {
            bit = get_bit(bit_len - 1 - bit_idx, value);
        } else {
            bit = get_bit(bit_idx, value);
        }
        if (bit) {
            bitsliced_value[bit_idx].value = bs_ones.value;
        } else {
            bitsliced_value[bit_idx].value = bs_zeroes.value;
        }
    }
}

static uint64_t unbitslice(const bitslice_t *restrict b, const uint8_t s, const uint8_t n) {
    uint64_t result = 0;
    for (uint8_t i = 0; i < n; ++i) {
        result <<= 1;
        result |= get_vector_bit(s, b[n - 1 - i]);
    }
    return result;
}


// determine number of logical CPU cores (use for multithreaded functions)
static int num_CPUs(void) {
#if defined(_WIN32)
#include <sysinfoapi.h>
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    return sysinfo.dwNumberOfProcessors;
#else
#include <unistd.h>
    int count = sysconf(_SC_NPROCESSORS_ONLN);
    if (count < 2)
        count = 2;
    return count;
#endif
}


uint32_t uid, nR1, aR1, nR2, aR2;

uint64_t candidates[(1 << 20)];
bitslice_t initial_bitslices[48];
size_t filter_pos[20] = {4, 7, 9, 13, 16, 18, 22, 24, 27, 30, 32, 35, 45, 47  };
size_t thread_count = 8;
uint64_t layer_0_found;
static void *find_state(void *thread_d);
static void try_state(uint64_t s);

int main(int argc, char *argv[]) {

    if (argc < 6) {
        printf("%s UID {nR1} {aR1} {nR2} {aR2}\n", argv[0]);
        exit(1);
    }

    // set constants
    memset(bs_ones.bytes, 0xff, VECTOR_SIZE);
    memset(bs_zeroes.bytes, 0x00, VECTOR_SIZE);

    uint32_t target = 0;

    thread_count = num_CPUs();

    if (!strncmp(argv[1], "0x", 2) || !strncmp(argv[1], "0X", 2)) {
        uid = rev32(hexreversetoulong(argv[1] + 2));
    } else {
        uid = rev32(hexreversetoulong(argv[1]));
    }

    if (!strncmp(argv[2], "0x", 2) || !strncmp(argv[2], "0X", 2)) {
        nR1 = rev32(hexreversetoulong(argv[2] + 2));
    } else {
        nR1 = rev32(hexreversetoulong(argv[2]));
    }

    aR1 = strtol(argv[3], NULL, 16);

    if (!strncmp(argv[4], "0x", 2) || !strncmp(argv[4], "0X", 2)) {
        nR2 = rev32(hexreversetoulong(argv[4] + 2));
    } else {
        nR2 = rev32(hexreversetoulong(argv[4]));
    }

    aR2 = strtol(argv[5], NULL, 16);

    target = ~aR1;
    // bitslice inverse target bits
    bitslice(~target, keystream, 32, true);

    // bitslice all possible 256 values in the lowest 8 bits
    memset(initial_bitslices[0].bytes, 0xaa, VECTOR_SIZE);
    memset(initial_bitslices[1].bytes, 0xcc, VECTOR_SIZE);
    memset(initial_bitslices[2].bytes, 0xf0, VECTOR_SIZE);
    size_t interval = 1;
    for (size_t bit = 3; bit < 8; bit++) {
        for (size_t byte = 0; byte < VECTOR_SIZE;) {
            for (size_t length = 0; length < interval; length++) {
                initial_bitslices[bit].bytes[byte++] = 0x00;
            }
            for (size_t length = 0; length < interval; length++) {
                initial_bitslices[bit].bytes[byte++] = 0xff;
            }
        }
        interval <<= 1;
    }

    // compute layer 0 output
    for (size_t i0 = 0; i0 < 1 << 20; i0++) {
        uint64_t state0 = expand(0x5806b4a2d16c, i0);

        if (f(state0) == target >> 31) {
            candidates[layer_0_found++] = state0;
        }
    }

    // start threads and wait on them
    pthread_t thread_handles[thread_count];
    for (size_t thread = 0; thread < thread_count; thread++) {
        pthread_create(&thread_handles[thread], NULL, find_state, (void *) thread);
    }
    for (size_t thread = 0; thread < thread_count; thread++) {
        pthread_join(thread_handles[thread], NULL);
    }

    printf("Key not found\n");
    exit(1);
}

static void *find_state(void *thread_d) {
    uint64_t thread = (uint64_t)thread_d;

    for (uint64_t index = thread; index < layer_0_found; index += thread_count) {

        if (((index / thread_count) & 0xFF) == 0)
            printf("Thread %" PRIu64 " slice %" PRIu64 "/%" PRIu64 "\n", thread, index / thread_count / 256 + 1, layer_0_found / thread_count / 256);

        uint64_t state0 = candidates[index];
        bitslice(state0 >> 2, &state[0], 46, false);

        for (size_t bit = 0; bit < 8; bit++) {
            state[-2 + filter_pos[bit]] = initial_bitslices[bit];
        }

        for (uint16_t i1 = 0; i1 < (1 << (bits[1] + 1) >> 8); i1++) {
            state[-2 + 27].value = ((bool)(i1 & 0x1)) ? bs_ones.value : bs_zeroes.value;
            state[-2 + 30].value = ((bool)(i1 & 0x2)) ? bs_ones.value : bs_zeroes.value;
            state[-2 + 32].value = ((bool)(i1 & 0x4)) ? bs_ones.value : bs_zeroes.value;
            state[-2 + 35].value = ((bool)(i1 & 0x8)) ? bs_ones.value : bs_zeroes.value;
            state[-2 + 45].value = ((bool)(i1 & 0x10)) ? bs_ones.value : bs_zeroes.value;
            state[-2 + 47].value = ((bool)(i1 & 0x20)) ? bs_ones.value : bs_zeroes.value;
            state[-2 + 48].value = ((bool)(i1 & 0x40)) ? bs_ones.value : bs_zeroes.value; // guess lfsr output 0
            // 0xfc07fef3f9fe
            const bitslice_value_t filter1_0 = f_a_bs(state[-2 + 3].value, state[-2 + 4].value, state[-2 + 6].value, state[-2 + 7].value);
            const bitslice_value_t filter1_1 = f_b_bs(state[-2 + 9].value, state[-2 + 13].value, state[-2 + 15].value, state[-2 + 16].value);
            const bitslice_value_t filter1_2 = f_b_bs(state[-2 + 18].value, state[-2 + 22].value, state[-2 + 24].value, state[-2 + 27].value);
            const bitslice_value_t filter1_3 = f_b_bs(state[-2 + 29].value, state[-2 + 30].value, state[-2 + 32].value, state[-2 + 34].value);
            const bitslice_value_t filter1_4 = f_a_bs(state[-2 + 35].value, state[-2 + 44].value, state[-2 + 45].value, state[-2 + 47].value);
            const bitslice_value_t filter1 = f_c_bs(filter1_0, filter1_1, filter1_2, filter1_3, filter1_4);
            bitslice_t results1;
            results1.value = filter1 ^ keystream[1].value;

            if (results1.bytes64[0] == 0
                    && results1.bytes64[1] == 0
                    && results1.bytes64[2] == 0
                    && results1.bytes64[3] == 0
               ) {
                continue;
            }
            const bitslice_value_t filter2_0 = f_a_bs(state[-2 + 4].value, state[-2 + 5].value, state[-2 + 7].value, state[-2 + 8].value);
            const bitslice_value_t filter2_3 = f_b_bs(state[-2 + 30].value, state[-2 + 31].value, state[-2 + 33].value, state[-2 + 35].value);
            const bitslice_value_t filter3_0 = f_a_bs(state[-2 + 5].value, state[-2 + 6].value, state[-2 + 8].value, state[-2 + 9].value);
            const bitslice_value_t filter5_2 = f_b_bs(state[-2 + 22].value, state[-2 + 26].value, state[-2 + 28].value, state[-2 + 31].value);
            const bitslice_value_t filter6_2 = f_b_bs(state[-2 + 23].value, state[-2 + 27].value, state[-2 + 29].value, state[-2 + 32].value);
            const bitslice_value_t filter7_2 = f_b_bs(state[-2 + 24].value, state[-2 + 28].value, state[-2 + 30].value, state[-2 + 33].value);
            const bitslice_value_t filter9_1 = f_b_bs(state[-2 + 17].value, state[-2 + 21].value, state[-2 + 23].value, state[-2 + 24].value);
            const bitslice_value_t filter9_2 = f_b_bs(state[-2 + 26].value, state[-2 + 30].value, state[-2 + 32].value, state[-2 + 35].value);
            const bitslice_value_t filter10_0 = f_a_bs(state[-2 + 12].value, state[-2 + 13].value, state[-2 + 15].value, state[-2 + 16].value);
            const bitslice_value_t filter11_0 = f_a_bs(state[-2 + 13].value, state[-2 + 14].value, state[-2 + 16].value, state[-2 + 17].value);
            const bitslice_value_t filter12_0 = f_a_bs(state[-2 + 14].value, state[-2 + 15].value, state[-2 + 17].value, state[-2 + 18].value);

            for (uint16_t i2 = 0; i2 < (1 << (bits[2] + 1)); i2++) {
                state[-2 + 10].value = ((bool)(i2 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                state[-2 + 19].value = ((bool)(i2 & 0x2)) ? bs_ones.value : bs_zeroes.value;
                state[-2 + 25].value = ((bool)(i2 & 0x4)) ? bs_ones.value : bs_zeroes.value;
                state[-2 + 36].value = ((bool)(i2 & 0x8)) ? bs_ones.value : bs_zeroes.value;
                state[-2 + 49].value = ((bool)(i2 & 0x10)) ? bs_ones.value : bs_zeroes.value; // guess lfsr output 1
                // 0xfe07fffbfdff
                const bitslice_value_t filter2_1 = f_b_bs(state[-2 + 10].value, state[-2 + 14].value, state[-2 + 16].value, state[-2 + 17].value);
                const bitslice_value_t filter2_2 = f_b_bs(state[-2 + 19].value, state[-2 + 23].value, state[-2 + 25].value, state[-2 + 28].value);
                const bitslice_value_t filter2_4 = f_a_bs(state[-2 + 36].value, state[-2 + 45].value, state[-2 + 46].value, state[-2 + 48].value);
                const bitslice_value_t filter2 = f_c_bs(filter2_0, filter2_1, filter2_2, filter2_3, filter2_4);
                bitslice_t results2;
                results2.value = results1.value & (filter2 ^ keystream[2].value);

                if (results2.bytes64[0] == 0
                        && results2.bytes64[1] == 0
                        && results2.bytes64[2] == 0
                        && results2.bytes64[3] == 0
                   ) {
                    continue;
                }
                state[-2 + 50].value = lfsr_bs(2);
                const bitslice_value_t filter3_3 = f_b_bs(state[-2 + 31].value, state[-2 + 32].value, state[-2 + 34].value, state[-2 + 36].value);
                const bitslice_value_t filter4_0 = f_a_bs(state[-2 + 6].value, state[-2 + 7].value, state[-2 + 9].value, state[-2 + 10].value);
                const bitslice_value_t filter4_1 = f_b_bs(state[-2 + 12].value, state[-2 + 16].value, state[-2 + 18].value, state[-2 + 19].value);
                const bitslice_value_t filter4_2 = f_b_bs(state[-2 + 21].value, state[-2 + 25].value, state[-2 + 27].value, state[-2 + 30].value);
                const bitslice_value_t filter7_0 = f_a_bs(state[-2 + 9].value, state[-2 + 10].value, state[-2 + 12].value, state[-2 + 13].value);
                const bitslice_value_t filter7_1 = f_b_bs(state[-2 + 15].value, state[-2 + 19].value, state[-2 + 21].value, state[-2 + 22].value);
                const bitslice_value_t filter8_2 = f_b_bs(state[-2 + 25].value, state[-2 + 29].value, state[-2 + 31].value, state[-2 + 34].value);
                const bitslice_value_t filter10_1 = f_b_bs(state[-2 + 18].value, state[-2 + 22].value, state[-2 + 24].value, state[-2 + 25].value);
                const bitslice_value_t filter10_2 = f_b_bs(state[-2 + 27].value, state[-2 + 31].value, state[-2 + 33].value, state[-2 + 36].value);
                const bitslice_value_t filter11_1 = f_b_bs(state[-2 + 19].value, state[-2 + 23].value, state[-2 + 25].value, state[-2 + 26].value);

                for (uint8_t i3 = 0; i3 < (1 << bits[3]); i3++) {
                    state[-2 + 11].value = ((bool)(i3 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                    state[-2 + 20].value = ((bool)(i3 & 0x2)) ? bs_ones.value : bs_zeroes.value;
                    state[-2 + 37].value = ((bool)(i3 & 0x4)) ? bs_ones.value : bs_zeroes.value;
                    // 0xff07ffffffff
                    const bitslice_value_t filter3_1 = f_b_bs(state[-2 + 11].value, state[-2 + 15].value, state[-2 + 17].value, state[-2 + 18].value);
                    const bitslice_value_t filter3_2 = f_b_bs(state[-2 + 20].value, state[-2 + 24].value, state[-2 + 26].value, state[-2 + 29].value);
                    const bitslice_value_t filter3_4 = f_a_bs(state[-2 + 37].value, state[-2 + 46].value, state[-2 + 47].value, state[-2 + 49].value);
                    const bitslice_value_t filter3 = f_c_bs(filter3_0, filter3_1, filter3_2, filter3_3, filter3_4);
                    bitslice_t results3;
                    results3.value = results2.value & (filter3 ^ keystream[3].value);

                    if (results3.bytes64[0] == 0
                            && results3.bytes64[1] == 0
                            && results3.bytes64[2] == 0
                            && results3.bytes64[3] == 0
                       ) {
                        continue;
                    }

                    state[-2 + 51].value = lfsr_bs(3);
                    state[-2 + 52].value = lfsr_bs(4);
                    state[-2 + 53].value = lfsr_bs(5);
                    state[-2 + 54].value = lfsr_bs(6);
                    state[-2 + 55].value = lfsr_bs(7);
                    const bitslice_value_t filter4_3 = f_b_bs(state[-2 + 32].value, state[-2 + 33].value, state[-2 + 35].value, state[-2 + 37].value);
                    const bitslice_value_t filter5_0 = f_a_bs(state[-2 + 7].value, state[-2 + 8].value, state[-2 + 10].value, state[-2 + 11].value);
                    const bitslice_value_t filter5_1 = f_b_bs(state[-2 + 13].value, state[-2 + 17].value, state[-2 + 19].value, state[-2 + 20].value);
                    const bitslice_value_t filter6_0 = f_a_bs(state[-2 + 8].value, state[-2 + 9].value, state[-2 + 11].value, state[-2 + 12].value);
                    const bitslice_value_t filter6_1 = f_b_bs(state[-2 + 14].value, state[-2 + 18].value, state[-2 + 20].value, state[-2 + 21].value);
                    const bitslice_value_t filter8_0 = f_a_bs(state[-2 + 10].value, state[-2 + 11].value, state[-2 + 13].value, state[-2 + 14].value);
                    const bitslice_value_t filter8_1 = f_b_bs(state[-2 + 16].value, state[-2 + 20].value, state[-2 + 22].value, state[-2 + 23].value);
                    const bitslice_value_t filter9_0 = f_a_bs(state[-2 + 11].value, state[-2 + 12].value, state[-2 + 14].value, state[-2 + 15].value);
                    const bitslice_value_t filter9_4 = f_a_bs(state[-2 + 43].value, state[-2 + 52].value, state[-2 + 53].value, state[-2 + 55].value);
                    const bitslice_value_t filter11_2 = f_b_bs(state[-2 + 28].value, state[-2 + 32].value, state[-2 + 34].value, state[-2 + 37].value);
                    const bitslice_value_t filter12_1 = f_b_bs(state[-2 + 20].value, state[-2 + 24].value, state[-2 + 26].value, state[-2 + 27].value);

                    for (uint8_t i4 = 0; i4 < (1 << bits[4]); i4++) {
                        state[-2 + 38].value = ((bool)(i4 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                        // 0xff87ffffffff
                        const bitslice_value_t filter4_4 = f_a_bs(state[-2 + 38].value, state[-2 + 47].value, state[-2 + 48].value, state[-2 + 50].value);
                        const bitslice_value_t filter4 = f_c_bs(filter4_0, filter4_1, filter4_2, filter4_3, filter4_4);
                        bitslice_t results4;
                        results4.value = results3.value & (filter4 ^ keystream[4].value);
                        if (results4.bytes64[0] == 0
                                && results4.bytes64[1] == 0
                                && results4.bytes64[2] == 0
                                && results4.bytes64[3] == 0
                           ) {
                            continue;
                        }

                        state[-2 + 56].value = lfsr_bs(8);
                        const bitslice_value_t filter5_3 = f_b_bs(state[-2 + 33].value, state[-2 + 34].value, state[-2 + 36].value, state[-2 + 38].value);
                        const bitslice_value_t filter10_4 = f_a_bs(state[-2 + 44].value, state[-2 + 53].value, state[-2 + 54].value, state[-2 + 56].value);
                        const bitslice_value_t filter12_2 = f_b_bs(state[-2 + 29].value, state[-2 + 33].value, state[-2 + 35].value, state[-2 + 38].value);

                        for (uint8_t i5 = 0; i5 < (1 << bits[5]); i5++) {
                            state[-2 + 39].value = ((bool)(i5 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                            // 0xffc7ffffffff
                            const bitslice_value_t filter5_4 = f_a_bs(state[-2 + 39].value, state[-2 + 48].value, state[-2 + 49].value, state[-2 + 51].value);
                            const bitslice_value_t filter5 = f_c_bs(filter5_0, filter5_1, filter5_2, filter5_3, filter5_4);
                            bitslice_t results5;
                            results5.value = results4.value & (filter5 ^ keystream[5].value);

                            if (results5.bytes64[0] == 0
                                    && results5.bytes64[1] == 0
                                    && results5.bytes64[2] == 0
                                    && results5.bytes64[3] == 0
                               ) {
                                continue;
                            }

                            state[-2 + 57].value = lfsr_bs(9);
                            const bitslice_value_t filter6_3 = f_b_bs(state[-2 + 34].value, state[-2 + 35].value, state[-2 + 37].value, state[-2 + 39].value);
                            const bitslice_value_t filter11_4 = f_a_bs(state[-2 + 45].value, state[-2 + 54].value, state[-2 + 55].value, state[-2 + 57].value);
                            for (uint8_t i6 = 0; i6 < (1 << bits[6]); i6++) {
                                state[-2 + 40].value = ((bool)(i6 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                                // 0xffe7ffffffff
                                const bitslice_value_t filter6_4 = f_a_bs(state[-2 + 40].value, state[-2 + 49].value, state[-2 + 50].value, state[-2 + 52].value);
                                const bitslice_value_t filter6 = f_c_bs(filter6_0, filter6_1, filter6_2, filter6_3, filter6_4);
                                bitslice_t results6;
                                results6.value = results5.value & (filter6 ^ keystream[6].value);

                                if (results6.bytes64[0] == 0
                                        && results6.bytes64[1] == 0
                                        && results6.bytes64[2] == 0
                                        && results6.bytes64[3] == 0
                                   ) {
                                    continue;
                                }

                                state[-2 + 58].value = lfsr_bs(10);
                                const bitslice_value_t filter7_3 = f_b_bs(state[-2 + 35].value, state[-2 + 36].value, state[-2 + 38].value, state[-2 + 40].value);
                                const bitslice_value_t filter12_4 = f_a_bs(state[-2 + 46].value, state[-2 + 55].value, state[-2 + 56].value, state[-2 + 58].value);
                                for (uint8_t i7 = 0; i7 < (1 << bits[7]); i7++) {
                                    state[-2 + 41].value = ((bool)(i7 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                                    // 0xfff7ffffffff
                                    const bitslice_value_t filter7_4 = f_a_bs(state[-2 + 41].value, state[-2 + 50].value, state[-2 + 51].value, state[-2 + 53].value);
                                    const bitslice_value_t filter7 = f_c_bs(filter7_0, filter7_1, filter7_2, filter7_3, filter7_4);
                                    bitslice_t results7;
                                    results7.value = results6.value & (filter7 ^ keystream[7].value);
                                    if (results7.bytes64[0] == 0
                                            && results7.bytes64[1] == 0
                                            && results7.bytes64[2] == 0
                                            && results7.bytes64[3] == 0
                                       ) {
                                        continue;
                                    }

                                    state[-2 + 59].value = lfsr_bs(11);
                                    const bitslice_value_t filter8_3 = f_b_bs(state[-2 + 36].value, state[-2 + 37].value, state[-2 + 39].value, state[-2 + 41].value);
                                    const bitslice_value_t filter10_3 = f_b_bs(state[-2 + 38].value, state[-2 + 39].value, state[-2 + 41].value, state[-2 + 43].value);
                                    const bitslice_value_t filter12_3 = f_b_bs(state[-2 + 40].value, state[-2 + 41].value, state[-2 + 43].value, state[-2 + 45].value);
                                    for (uint8_t i8 = 0; i8 < (1 << bits[8]); i8++) {
                                        state[-2 + 42].value = ((bool)(i8 & 0x1)) ? bs_ones.value : bs_zeroes.value;
                                        // 0xffffffffffff
                                        const bitslice_value_t filter8_4 = f_a_bs(state[-2 + 42].value, state[-2 + 51].value, state[-2 + 52].value, state[-2 + 54].value);
                                        const bitslice_value_t filter8 = f_c_bs(filter8_0, filter8_1, filter8_2, filter8_3, filter8_4);
                                        bitslice_t results8;
                                        results8.value = results7.value & (filter8 ^ keystream[8].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        const bitslice_value_t filter9_3 = f_b_bs(state[-2 + 37].value, state[-2 + 38].value, state[-2 + 40].value, state[-2 + 42].value);
                                        const bitslice_value_t filter9 = f_c_bs(filter9_0, filter9_1, filter9_2, filter9_3, filter9_4);
                                        results8.value &= (filter9 ^ keystream[9].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        const bitslice_value_t filter10 = f_c_bs(filter10_0, filter10_1, filter10_2, filter10_3, filter10_4);
                                        results8.value &= (filter10 ^ keystream[10].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        const bitslice_value_t filter11_3 = f_b_bs(state[-2 + 39].value, state[-2 + 40].value, state[-2 + 42].value, state[-2 + 44].value);
                                        const bitslice_value_t filter11 = f_c_bs(filter11_0, filter11_1, filter11_2, filter11_3, filter11_4);
                                        results8.value &= (filter11 ^ keystream[11].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        const bitslice_value_t filter12 = f_c_bs(filter12_0, filter12_1, filter12_2, filter12_3, filter12_4);
                                        results8.value &= (filter12 ^ keystream[12].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        const bitslice_value_t filter13_0 = f_a_bs(state[-2 + 15].value, state[-2 + 16].value, state[-2 + 18].value, state[-2 + 19].value);
                                        const bitslice_value_t filter13_1 = f_b_bs(state[-2 + 21].value, state[-2 + 25].value, state[-2 + 27].value, state[-2 + 28].value);
                                        const bitslice_value_t filter13_2 = f_b_bs(state[-2 + 30].value, state[-2 + 34].value, state[-2 + 36].value, state[-2 + 39].value);
                                        const bitslice_value_t filter13_3 = f_b_bs(state[-2 + 41].value, state[-2 + 42].value, state[-2 + 44].value, state[-2 + 46].value);
                                        const bitslice_value_t filter13_4 = f_a_bs(state[-2 + 47].value, state[-2 + 56].value, state[-2 + 57].value, state[-2 + 59].value);
                                        const bitslice_value_t filter13 = f_c_bs(filter13_0, filter13_1, filter13_2, filter13_3, filter13_4);
                                        results8.value &= (filter13 ^ keystream[13].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 60].value = lfsr_bs(12);
                                        const bitslice_value_t filter14_0 = f_a_bs(state[-2 + 16].value, state[-2 + 17].value, state[-2 + 19].value, state[-2 + 20].value);
                                        const bitslice_value_t filter14_1 = f_b_bs(state[-2 + 22].value, state[-2 + 26].value, state[-2 + 28].value, state[-2 + 29].value);
                                        const bitslice_value_t filter14_2 = f_b_bs(state[-2 + 31].value, state[-2 + 35].value, state[-2 + 37].value, state[-2 + 40].value);
                                        const bitslice_value_t filter14_3 = f_b_bs(state[-2 + 42].value, state[-2 + 43].value, state[-2 + 45].value, state[-2 + 47].value);
                                        const bitslice_value_t filter14_4 = f_a_bs(state[-2 + 48].value, state[-2 + 57].value, state[-2 + 58].value, state[-2 + 60].value);
                                        const bitslice_value_t filter14 = f_c_bs(filter14_0, filter14_1, filter14_2, filter14_3, filter14_4);
                                        results8.value &= (filter14 ^ keystream[14].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 61].value = lfsr_bs(13);
                                        const bitslice_value_t filter15_0 = f_a_bs(state[-2 + 17].value, state[-2 + 18].value, state[-2 + 20].value, state[-2 + 21].value);
                                        const bitslice_value_t filter15_1 = f_b_bs(state[-2 + 23].value, state[-2 + 27].value, state[-2 + 29].value, state[-2 + 30].value);
                                        const bitslice_value_t filter15_2 = f_b_bs(state[-2 + 32].value, state[-2 + 36].value, state[-2 + 38].value, state[-2 + 41].value);
                                        const bitslice_value_t filter15_3 = f_b_bs(state[-2 + 43].value, state[-2 + 44].value, state[-2 + 46].value, state[-2 + 48].value);
                                        const bitslice_value_t filter15_4 = f_a_bs(state[-2 + 49].value, state[-2 + 58].value, state[-2 + 59].value, state[-2 + 61].value);
                                        const bitslice_value_t filter15 = f_c_bs(filter15_0, filter15_1, filter15_2, filter15_3, filter15_4);
                                        results8.value &= (filter15 ^ keystream[15].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 62].value = lfsr_bs(14);
                                        const bitslice_value_t filter16_0 = f_a_bs(state[-2 + 18].value, state[-2 + 19].value, state[-2 + 21].value, state[-2 + 22].value);
                                        const bitslice_value_t filter16_1 = f_b_bs(state[-2 + 24].value, state[-2 + 28].value, state[-2 + 30].value, state[-2 + 31].value);
                                        const bitslice_value_t filter16_2 = f_b_bs(state[-2 + 33].value, state[-2 + 37].value, state[-2 + 39].value, state[-2 + 42].value);
                                        const bitslice_value_t filter16_3 = f_b_bs(state[-2 + 44].value, state[-2 + 45].value, state[-2 + 47].value, state[-2 + 49].value);
                                        const bitslice_value_t filter16_4 = f_a_bs(state[-2 + 50].value, state[-2 + 59].value, state[-2 + 60].value, state[-2 + 62].value);
                                        const bitslice_value_t filter16 = f_c_bs(filter16_0, filter16_1, filter16_2, filter16_3, filter16_4);
                                        results8.value &= (filter16 ^ keystream[16].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 63].value = lfsr_bs(15);
                                        const bitslice_value_t filter17_0 = f_a_bs(state[-2 + 19].value, state[-2 + 20].value, state[-2 + 22].value, state[-2 + 23].value);
                                        const bitslice_value_t filter17_1 = f_b_bs(state[-2 + 25].value, state[-2 + 29].value, state[-2 + 31].value, state[-2 + 32].value);
                                        const bitslice_value_t filter17_2 = f_b_bs(state[-2 + 34].value, state[-2 + 38].value, state[-2 + 40].value, state[-2 + 43].value);
                                        const bitslice_value_t filter17_3 = f_b_bs(state[-2 + 45].value, state[-2 + 46].value, state[-2 + 48].value, state[-2 + 50].value);
                                        const bitslice_value_t filter17_4 = f_a_bs(state[-2 + 51].value, state[-2 + 60].value, state[-2 + 61].value, state[-2 + 63].value);
                                        const bitslice_value_t filter17 = f_c_bs(filter17_0, filter17_1, filter17_2, filter17_3, filter17_4);
                                        results8.value &= (filter17 ^ keystream[17].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 64].value = lfsr_bs(16);
                                        const bitslice_value_t filter18_0 = f_a_bs(state[-2 + 20].value, state[-2 + 21].value, state[-2 + 23].value, state[-2 + 24].value);
                                        const bitslice_value_t filter18_1 = f_b_bs(state[-2 + 26].value, state[-2 + 30].value, state[-2 + 32].value, state[-2 + 33].value);
                                        const bitslice_value_t filter18_2 = f_b_bs(state[-2 + 35].value, state[-2 + 39].value, state[-2 + 41].value, state[-2 + 44].value);
                                        const bitslice_value_t filter18_3 = f_b_bs(state[-2 + 46].value, state[-2 + 47].value, state[-2 + 49].value, state[-2 + 51].value);
                                        const bitslice_value_t filter18_4 = f_a_bs(state[-2 + 52].value, state[-2 + 61].value, state[-2 + 62].value, state[-2 + 64].value);
                                        const bitslice_value_t filter18 = f_c_bs(filter18_0, filter18_1, filter18_2, filter18_3, filter18_4);
                                        results8.value &= (filter18 ^ keystream[18].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 65].value = lfsr_bs(17);
                                        const bitslice_value_t filter19_0 = f_a_bs(state[-2 + 21].value, state[-2 + 22].value, state[-2 + 24].value, state[-2 + 25].value);
                                        const bitslice_value_t filter19_1 = f_b_bs(state[-2 + 27].value, state[-2 + 31].value, state[-2 + 33].value, state[-2 + 34].value);
                                        const bitslice_value_t filter19_2 = f_b_bs(state[-2 + 36].value, state[-2 + 40].value, state[-2 + 42].value, state[-2 + 45].value);
                                        const bitslice_value_t filter19_3 = f_b_bs(state[-2 + 47].value, state[-2 + 48].value, state[-2 + 50].value, state[-2 + 52].value);
                                        const bitslice_value_t filter19_4 = f_a_bs(state[-2 + 53].value, state[-2 + 62].value, state[-2 + 63].value, state[-2 + 65].value);
                                        const bitslice_value_t filter19 = f_c_bs(filter19_0, filter19_1, filter19_2, filter19_3, filter19_4);
                                        results8.value &= (filter19 ^ keystream[19].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 66].value = lfsr_bs(18);
                                        const bitslice_value_t filter20_0 = f_a_bs(state[-2 + 22].value, state[-2 + 23].value, state[-2 + 25].value, state[-2 + 26].value);
                                        const bitslice_value_t filter20_1 = f_b_bs(state[-2 + 28].value, state[-2 + 32].value, state[-2 + 34].value, state[-2 + 35].value);
                                        const bitslice_value_t filter20_2 = f_b_bs(state[-2 + 37].value, state[-2 + 41].value, state[-2 + 43].value, state[-2 + 46].value);
                                        const bitslice_value_t filter20_3 = f_b_bs(state[-2 + 48].value, state[-2 + 49].value, state[-2 + 51].value, state[-2 + 53].value);
                                        const bitslice_value_t filter20_4 = f_a_bs(state[-2 + 54].value, state[-2 + 63].value, state[-2 + 64].value, state[-2 + 66].value);
                                        const bitslice_value_t filter20 = f_c_bs(filter20_0, filter20_1, filter20_2, filter20_3, filter20_4);
                                        results8.value &= (filter20 ^ keystream[20].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 67].value = lfsr_bs(19);
                                        const bitslice_value_t filter21_0 = f_a_bs(state[-2 + 23].value, state[-2 + 24].value, state[-2 + 26].value, state[-2 + 27].value);
                                        const bitslice_value_t filter21_1 = f_b_bs(state[-2 + 29].value, state[-2 + 33].value, state[-2 + 35].value, state[-2 + 36].value);
                                        const bitslice_value_t filter21_2 = f_b_bs(state[-2 + 38].value, state[-2 + 42].value, state[-2 + 44].value, state[-2 + 47].value);
                                        const bitslice_value_t filter21_3 = f_b_bs(state[-2 + 49].value, state[-2 + 50].value, state[-2 + 52].value, state[-2 + 54].value);
                                        const bitslice_value_t filter21_4 = f_a_bs(state[-2 + 55].value, state[-2 + 64].value, state[-2 + 65].value, state[-2 + 67].value);
                                        const bitslice_value_t filter21 = f_c_bs(filter21_0, filter21_1, filter21_2, filter21_3, filter21_4);
                                        results8.value &= (filter21 ^ keystream[21].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 68].value = lfsr_bs(20);
                                        const bitslice_value_t filter22_0 = f_a_bs(state[-2 + 24].value, state[-2 + 25].value, state[-2 + 27].value, state[-2 + 28].value);
                                        const bitslice_value_t filter22_1 = f_b_bs(state[-2 + 30].value, state[-2 + 34].value, state[-2 + 36].value, state[-2 + 37].value);
                                        const bitslice_value_t filter22_2 = f_b_bs(state[-2 + 39].value, state[-2 + 43].value, state[-2 + 45].value, state[-2 + 48].value);
                                        const bitslice_value_t filter22_3 = f_b_bs(state[-2 + 50].value, state[-2 + 51].value, state[-2 + 53].value, state[-2 + 55].value);
                                        const bitslice_value_t filter22_4 = f_a_bs(state[-2 + 56].value, state[-2 + 65].value, state[-2 + 66].value, state[-2 + 68].value);
                                        const bitslice_value_t filter22 = f_c_bs(filter22_0, filter22_1, filter22_2, filter22_3, filter22_4);
                                        results8.value &= (filter22 ^ keystream[22].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 69].value = lfsr_bs(21);
                                        const bitslice_value_t filter23_0 = f_a_bs(state[-2 + 25].value, state[-2 + 26].value, state[-2 + 28].value, state[-2 + 29].value);
                                        const bitslice_value_t filter23_1 = f_b_bs(state[-2 + 31].value, state[-2 + 35].value, state[-2 + 37].value, state[-2 + 38].value);
                                        const bitslice_value_t filter23_2 = f_b_bs(state[-2 + 40].value, state[-2 + 44].value, state[-2 + 46].value, state[-2 + 49].value);
                                        const bitslice_value_t filter23_3 = f_b_bs(state[-2 + 51].value, state[-2 + 52].value, state[-2 + 54].value, state[-2 + 56].value);
                                        const bitslice_value_t filter23_4 = f_a_bs(state[-2 + 57].value, state[-2 + 66].value, state[-2 + 67].value, state[-2 + 69].value);
                                        const bitslice_value_t filter23 = f_c_bs(filter23_0, filter23_1, filter23_2, filter23_3, filter23_4);
                                        results8.value &= (filter23 ^ keystream[23].value);
                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }
                                        state[-2 + 70].value = lfsr_bs(22);
                                        const bitslice_value_t filter24_0 = f_a_bs(state[-2 + 26].value, state[-2 + 27].value, state[-2 + 29].value, state[-2 + 30].value);
                                        const bitslice_value_t filter24_1 = f_b_bs(state[-2 + 32].value, state[-2 + 36].value, state[-2 + 38].value, state[-2 + 39].value);
                                        const bitslice_value_t filter24_2 = f_b_bs(state[-2 + 41].value, state[-2 + 45].value, state[-2 + 47].value, state[-2 + 50].value);
                                        const bitslice_value_t filter24_3 = f_b_bs(state[-2 + 52].value, state[-2 + 53].value, state[-2 + 55].value, state[-2 + 57].value);
                                        const bitslice_value_t filter24_4 = f_a_bs(state[-2 + 58].value, state[-2 + 67].value, state[-2 + 68].value, state[-2 + 70].value);
                                        const bitslice_value_t filter24 = f_c_bs(filter24_0, filter24_1, filter24_2, filter24_3, filter24_4);
                                        results8.value &= (filter24 ^ keystream[24].value);
                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }
                                        state[-2 + 71].value = lfsr_bs(23);
                                        const bitslice_value_t filter25_0 = f_a_bs(state[-2 + 27].value, state[-2 + 28].value, state[-2 + 30].value, state[-2 + 31].value);
                                        const bitslice_value_t filter25_1 = f_b_bs(state[-2 + 33].value, state[-2 + 37].value, state[-2 + 39].value, state[-2 + 40].value);
                                        const bitslice_value_t filter25_2 = f_b_bs(state[-2 + 42].value, state[-2 + 46].value, state[-2 + 48].value, state[-2 + 51].value);
                                        const bitslice_value_t filter25_3 = f_b_bs(state[-2 + 53].value, state[-2 + 54].value, state[-2 + 56].value, state[-2 + 58].value);
                                        const bitslice_value_t filter25_4 = f_a_bs(state[-2 + 59].value, state[-2 + 68].value, state[-2 + 69].value, state[-2 + 71].value);
                                        const bitslice_value_t filter25 = f_c_bs(filter25_0, filter25_1, filter25_2, filter25_3, filter25_4);
                                        results8.value &= (filter25 ^ keystream[25].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 72].value = lfsr_bs(24);
                                        const bitslice_value_t filter26_0 = f_a_bs(state[-2 + 28].value, state[-2 + 29].value, state[-2 + 31].value, state[-2 + 32].value);
                                        const bitslice_value_t filter26_1 = f_b_bs(state[-2 + 34].value, state[-2 + 38].value, state[-2 + 40].value, state[-2 + 41].value);
                                        const bitslice_value_t filter26_2 = f_b_bs(state[-2 + 43].value, state[-2 + 47].value, state[-2 + 49].value, state[-2 + 52].value);
                                        const bitslice_value_t filter26_3 = f_b_bs(state[-2 + 54].value, state[-2 + 55].value, state[-2 + 57].value, state[-2 + 59].value);
                                        const bitslice_value_t filter26_4 = f_a_bs(state[-2 + 60].value, state[-2 + 69].value, state[-2 + 70].value, state[-2 + 72].value);
                                        const bitslice_value_t filter26 = f_c_bs(filter26_0, filter26_1, filter26_2, filter26_3, filter26_4);
                                        results8.value &= (filter26 ^ keystream[26].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 73].value = lfsr_bs(25);
                                        const bitslice_value_t filter27_0 = f_a_bs(state[-2 + 29].value, state[-2 + 30].value, state[-2 + 32].value, state[-2 + 33].value);
                                        const bitslice_value_t filter27_1 = f_b_bs(state[-2 + 35].value, state[-2 + 39].value, state[-2 + 41].value, state[-2 + 42].value);
                                        const bitslice_value_t filter27_2 = f_b_bs(state[-2 + 44].value, state[-2 + 48].value, state[-2 + 50].value, state[-2 + 53].value);
                                        const bitslice_value_t filter27_3 = f_b_bs(state[-2 + 55].value, state[-2 + 56].value, state[-2 + 58].value, state[-2 + 60].value);
                                        const bitslice_value_t filter27_4 = f_a_bs(state[-2 + 61].value, state[-2 + 70].value, state[-2 + 71].value, state[-2 + 73].value);
                                        const bitslice_value_t filter27 = f_c_bs(filter27_0, filter27_1, filter27_2, filter27_3, filter27_4);
                                        results8.value &= (filter27 ^ keystream[27].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 74].value = lfsr_bs(26);
                                        const bitslice_value_t filter28_0 = f_a_bs(state[-2 + 30].value, state[-2 + 31].value, state[-2 + 33].value, state[-2 + 34].value);
                                        const bitslice_value_t filter28_1 = f_b_bs(state[-2 + 36].value, state[-2 + 40].value, state[-2 + 42].value, state[-2 + 43].value);
                                        const bitslice_value_t filter28_2 = f_b_bs(state[-2 + 45].value, state[-2 + 49].value, state[-2 + 51].value, state[-2 + 54].value);
                                        const bitslice_value_t filter28_3 = f_b_bs(state[-2 + 56].value, state[-2 + 57].value, state[-2 + 59].value, state[-2 + 61].value);
                                        const bitslice_value_t filter28_4 = f_a_bs(state[-2 + 62].value, state[-2 + 71].value, state[-2 + 72].value, state[-2 + 74].value);
                                        const bitslice_value_t filter28 = f_c_bs(filter28_0, filter28_1, filter28_2, filter28_3, filter28_4);
                                        results8.value &= (filter28 ^ keystream[28].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 75].value = lfsr_bs(27);
                                        const bitslice_value_t filter29_0 = f_a_bs(state[-2 + 31].value, state[-2 + 32].value, state[-2 + 34].value, state[-2 + 35].value);
                                        const bitslice_value_t filter29_1 = f_b_bs(state[-2 + 37].value, state[-2 + 41].value, state[-2 + 43].value, state[-2 + 44].value);
                                        const bitslice_value_t filter29_2 = f_b_bs(state[-2 + 46].value, state[-2 + 50].value, state[-2 + 52].value, state[-2 + 55].value);
                                        const bitslice_value_t filter29_3 = f_b_bs(state[-2 + 57].value, state[-2 + 58].value, state[-2 + 60].value, state[-2 + 62].value);
                                        const bitslice_value_t filter29_4 = f_a_bs(state[-2 + 63].value, state[-2 + 72].value, state[-2 + 73].value, state[-2 + 75].value);
                                        const bitslice_value_t filter29 = f_c_bs(filter29_0, filter29_1, filter29_2, filter29_3, filter29_4);
                                        results8.value &= (filter29 ^ keystream[29].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 76].value = lfsr_bs(28);
                                        const bitslice_value_t filter30_0 = f_a_bs(state[-2 + 32].value, state[-2 + 33].value, state[-2 + 35].value, state[-2 + 36].value);
                                        const bitslice_value_t filter30_1 = f_b_bs(state[-2 + 38].value, state[-2 + 42].value, state[-2 + 44].value, state[-2 + 45].value);
                                        const bitslice_value_t filter30_2 = f_b_bs(state[-2 + 47].value, state[-2 + 51].value, state[-2 + 53].value, state[-2 + 56].value);
                                        const bitslice_value_t filter30_3 = f_b_bs(state[-2 + 58].value, state[-2 + 59].value, state[-2 + 61].value, state[-2 + 63].value);
                                        const bitslice_value_t filter30_4 = f_a_bs(state[-2 + 64].value, state[-2 + 73].value, state[-2 + 74].value, state[-2 + 76].value);
                                        const bitslice_value_t filter30 = f_c_bs(filter30_0, filter30_1, filter30_2, filter30_3, filter30_4);
                                        results8.value &= (filter30 ^ keystream[30].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        state[-2 + 77].value = lfsr_bs(29);
                                        const bitslice_value_t filter31_0 = f_a_bs(state[-2 + 33].value, state[-2 + 34].value, state[-2 + 36].value, state[-2 + 37].value);
                                        const bitslice_value_t filter31_1 = f_b_bs(state[-2 + 39].value, state[-2 + 43].value, state[-2 + 45].value, state[-2 + 46].value);
                                        const bitslice_value_t filter31_2 = f_b_bs(state[-2 + 48].value, state[-2 + 52].value, state[-2 + 54].value, state[-2 + 57].value);
                                        const bitslice_value_t filter31_3 = f_b_bs(state[-2 + 59].value, state[-2 + 60].value, state[-2 + 62].value, state[-2 + 64].value);
                                        const bitslice_value_t filter31_4 = f_a_bs(state[-2 + 65].value, state[-2 + 74].value, state[-2 + 75].value, state[-2 + 77].value);
                                        const bitslice_value_t filter31 = f_c_bs(filter31_0, filter31_1, filter31_2, filter31_3, filter31_4);
                                        results8.value &= (filter31 ^ keystream[31].value);

                                        if (results8.bytes64[0] == 0
                                                && results8.bytes64[1] == 0
                                                && results8.bytes64[2] == 0
                                                && results8.bytes64[3] == 0
                                           ) {
                                            continue;
                                        }

                                        for (size_t r = 0; r < MAX_BITSLICES; r++) {
                                            if (!get_vector_bit(r, results8)) continue;
                                            // take the state from layer 2 so we can recover the lowest 2 bits by inverting the LFSR
                                            uint64_t state31 = unbitslice(&state[-2 + 2], r, 48);
                                            state31 = lfsr_inv(state31);
                                            state31 = lfsr_inv(state31);
                                            try_state(state31 & ((1ull << 48) - 1));
                                        }
                                    } // 8
                                } // 7
                            } // 6
                        } // 5
                    } // 4
                } // 3
            } // 2
        } // 1
    } // 0
    return NULL;
}

static void try_state(uint64_t s) {
    Hitag_State hstate;
    uint64_t keyrev, nR1xk;
    uint32_t b = 0;

    hstate.shiftreg = s;

    // recover key
    keyrev = hstate.shiftreg & 0xffff;
    nR1xk = (hstate.shiftreg >> 16) & 0xffffffff;
    for (int i = 0; i < 32; i++) {
        hstate.shiftreg = ((hstate.shiftreg) << 1) | ((uid >> (31 - i)) & 0x1);
        b = (b << 1) | fnf(hstate.shiftreg);
    }
    keyrev |= (nR1xk ^ nR1 ^ b) << 16;

    // test key
    hitag2_init(&hstate, keyrev, uid, nR2);
    if ((aR2 ^ hitag2_nstep(&hstate, 32)) == 0xffffffff) {

        uint64_t key = rev64(keyrev);

        printf("Key: ");
        for (int i = 0; i < 6; i++) {
            printf("%02X", (uint8_t)(key & 0xff));
            key = key >> 8;
        }
        printf("\n");
        exit(0);
    }
}
