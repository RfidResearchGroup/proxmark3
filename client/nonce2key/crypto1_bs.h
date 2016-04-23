#ifndef _CRYPTO1_BS_H
#define _CRYPTO1_BS_H
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

// bitslice type
// while AVX supports 256 bit vector floating point operations, we need integer operations for boolean logic
// same for AVX2 and 512 bit vectors
// using larger vectors works but seems to generate more register pressure
#if defined(__AVX2__)
#define MAX_BITSLICES 256
#elif defined(__AVX__)
#define MAX_BITSLICES 128
#elif defined(__SSE2__)
#define MAX_BITSLICES 128
#else
#define MAX_BITSLICES 64
#endif

#define VECTOR_SIZE (MAX_BITSLICES/8)
typedef unsigned int __attribute__((aligned(VECTOR_SIZE))) __attribute__((vector_size(VECTOR_SIZE))) bitslice_value_t;
typedef union {
        bitslice_value_t value;
        uint64_t bytes64[MAX_BITSLICES/64];
        uint8_t bytes[MAX_BITSLICES/8];
} bitslice_t;

// filter function (f20)
// sourced from ``Wirelessly Pickpocketing a Mifare Classic Card'' by Flavio Garcia, Peter van Rossum, Roel Verdult and Ronny Wichers Schreur
#define f20a(a,b,c,d) (((a|b)^(a&d))^(c&((a^b)|d)))
#define f20b(a,b,c,d) (((a&b)|c)^((a^b)&(c|d)))
#define f20c(a,b,c,d,e) ((a|((b|e)&(d^e)))^((a^(b&d))&((c^d)|(b&e))))

#define crypto1_bs_f20(s) \
f20c(f20a((s[47- 9].value), (s[47-11].value), (s[47-13].value), (s[47-15].value)), \
     f20b((s[47-17].value), (s[47-19].value), (s[47-21].value), (s[47-23].value)), \
     f20b((s[47-25].value), (s[47-27].value), (s[47-29].value), (s[47-31].value)), \
     f20a((s[47-33].value), (s[47-35].value), (s[47-37].value), (s[47-39].value)), \
     f20b((s[47-41].value), (s[47-43].value), (s[47-45].value), (s[47-47].value)))

// bit indexing
#define get_bit(n, word) ((word >> (n)) & 1)
#define get_vector_bit(slice, value) get_bit(slice&0x3f, value.bytes64[slice>>6])

// constant ones/zeroes
bitslice_t bs_ones;
bitslice_t bs_zeroes;

// size of crypto-1 state
#define STATE_SIZE 48
// size of nonce to be decrypted
#define KEYSTREAM_SIZE 32
// size of first uid^nonce byte to be rolled back to the initial key
#define ROLLBACK_SIZE 8
// number of nonces required to test to cover entire 48-bit state
// I would have said it's 12... but bla goes with 100, so I do too
#define NONCE_TESTS 100

// state pointer management
extern __thread bitslice_t states[KEYSTREAM_SIZE+STATE_SIZE];
extern __thread bitslice_t * restrict state_p;

// rewind to the point a0, at which KEYSTREAM_SIZE more bits can be generated
#define crypto1_bs_rewind_a0() (state_p = &states[KEYSTREAM_SIZE])

// bitsliced bytewise parity
#define bitsliced_byte_parity(n) (n[0].value ^ n[1].value ^ n[2].value ^ n[3].value ^ n[4].value ^ n[5].value ^ n[6].value ^ n[7].value)

// 48-bit crypto-1 states are normally represented using 64-bit values
typedef union {
    uint64_t value;
    uint8_t bytes[8];
} state_t;

// endianness conversion
#define rev32(word) (((word & 0xff) << 24) | (((word >> 8) & 0xff) << 16) | (((word >> 16) & 0xff) << 8) | (((word >> 24) & 0xff)))
#define rev64(x)  (rev32(x)<<32|(rev32((x>>32))))
#define rev_state_t rev64

// crypto-1 functions
const bitslice_value_t crypto1_bs_bit(const bitslice_value_t input, const bool is_encrypted);
const bitslice_value_t crypto1_bs_lfsr_rollback(const bitslice_value_t input, const bool is_encrypted);

// initialization functions
void crypto1_bs_init();

// conversion functions
void crypto1_bs_bitslice_value32(uint32_t value, bitslice_t bitsliced_value[], size_t bit_len);
void crypto1_bs_convert_states(bitslice_t bitsliced_states[], state_t regular_states[]);

// debug print
void crypto1_bs_print_states(bitslice_t *bitsliced_states);

#endif // _CRYPTO1_BS_H

