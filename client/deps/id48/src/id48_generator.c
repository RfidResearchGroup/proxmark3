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

typedef struct _INPUT_BITS2 {
    // least significant 55 bits are valid/used; lsb == input₀₀
    uint64_t Raw;
} INPUT_BITS2;
typedef struct _OUTPUT_BITS2 {
    // least significant 55 bits valid
    // Raw₅₄..Raw₄₈ == ignored bits to get to s₀₇
    // Raw₄₇..Raw₂₀ == 28-bit challenge value frn
    // Raw₁₉..Raw₀₀ == 20-bit response  value grn
    uint64_t Raw;
} OUTPUT_BITS2;
typedef struct _OUTPUT_INDEX2 {
    // Opaque value for use in lookup of the output bit
    // only least significant 20 bits are valid
    uint32_t Raw;
} OUTPUT_INDEX2;

#if !defined(nullptr)
#define nullptr ((void*)0)
#endif

#pragma region    // reverse_bits()
static inline uint8_t  reverse_bits_08(uint8_t  n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint8_t mask = (uint8_t)(~((uint8_t)(0u))); // equivalent to uint32_t mask = 0b11111111111111111111111111111111;

    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap); // will convert mask to 0b00000000000000001111111111111111;
        n = (uint8_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap)); // divide and conquer
    }
    return n;
}
static inline uint16_t reverse_bits_16(uint16_t n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint16_t mask = (uint16_t)(~((uint16_t)(0u))); // equivalent to uint32_t mask = 0b11111111111111111111111111111111;

    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap); // will convert mask to 0b00000000000000001111111111111111;
        n = (uint16_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap)); // divide and conquer
    }
    return n;
}
static inline uint32_t reverse_bits_32(uint32_t n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint32_t mask = (uint32_t)(~((uint32_t)(0u))); // equivalent to uint32_t mask = 0b11111111111111111111111111111111;

    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap); // will convert mask to 0b00000000000000001111111111111111;
        n = (uint32_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap)); // divide and conquer
    }
    return n;
}
static inline uint64_t reverse_bits_64(uint64_t n) {
    uint8_t bitsToSwap = sizeof(n) * 8;
    uint64_t mask = (uint64_t)(~((uint64_t)(0u))); // equivalent to uint32_t mask = 0b11111111111111111111111111111111;

    while (bitsToSwap >>= 1) {
        mask ^= mask << (bitsToSwap); // will convert mask to 0b00000000000000001111111111111111;
        n = (uint64_t)(((n & ~mask) >> bitsToSwap) | ((n & mask) << bitsToSwap)); // divide and conquer
    }
    return n;
}
#pragma endregion // reverse_bits()

#pragma region    // id48lib state register
// Bit:  ₆₃  ₆₂  ₆₁  ₆₀  ₅₉  ₅₈  ₅₇  ₅₆  ₅₅  ₅₄  ₅₃  ₅₂  ₅₁  ₅₀  ₄₉  ₄₈  ₄₇  ₄₆  ₄₅  ₄₄  ₄₃  ₄₂  ₄₁  ₄₀  ₃₉  ₃₈  ₃₇  ₃₆  ₃₅  ₃₄  ₃₃  ₃₂
// Reg:  x   x   x  r₀₆ r₀₅ r₀₄ r₀₃ r₀₂ r₀₁ r₀₀ m₀₆ m₀₅ m₀₄ m₀₃ m₀₂ m₀₁ m₀₀ l₀₆ l₀₅ l₀₄ l₀₃ l₀₂ l₀₁ l₀₀ g₂₂ g₂₁ g₂₀ g₁₉ g₁₈ g₁₇ g₁₆ g₁₅
//
// Bit:  ₃₁  ₃₀  ₂₉  ₂₈  ₂₇  ₂₆  ₂₅  ₂₄  ₂₃  ₂₂  ₂₁  ₂₀  ₁₉  ₁₈  ₁₇  ₁₆  ₁₅  ₁₄  ₁₃  ₁₂  ₁₁  ₁₀  ₀₉  ₀₈  ₀₇  ₀₆  ₀₅  ₀₄  ₀₃  ₀₂  ₀₁  ₀₀
// Reg: g₁₄ g₁₃ g₁₂ g₁₁ g₁₀ g₀₉ g₀₈ g₀₇ g₀₆ g₀₅ g₀₄ g₀₃ g₀₂ g₀₁ g₀₀ h₁₂ h₁₁ h₁₀ h₀₉ h₀₈ h₀₇ h₀₆ h₀₅ h₀₄ h₀₃ h₀₂ h₀₁ h₀₀  x   x   x   1
#pragma endregion // id48lib state register
#pragma region    // bit definitions for the (stable) id48lib state register
//                       63
// #define SSR_BIT_i        62 -- could do this ... one fewer parameter
//                       61
#define SSR_BIT_R06      60
#define SSR_BIT_R05      59
#define SSR_BIT_R04      58
#define SSR_BIT_R03      57
#define SSR_BIT_R02      56
#define SSR_BIT_R01      55
#define SSR_BIT_R00      54
#define SSR_BIT_M06      53
#define SSR_BIT_M05      52
#define SSR_BIT_M04      51
#define SSR_BIT_M03      50
#define SSR_BIT_M02      49
#define SSR_BIT_M01      48
#define SSR_BIT_M00      47
#define SSR_BIT_L06      46
#define SSR_BIT_L05      45
#define SSR_BIT_L04      44
#define SSR_BIT_L03      43
#define SSR_BIT_L02      42
#define SSR_BIT_L01      41
#define SSR_BIT_L00      40
#define SSR_BIT_G22      39
#define SSR_BIT_G21      38
#define SSR_BIT_G20      37
#define SSR_BIT_G19      36
#define SSR_BIT_G18      35
#define SSR_BIT_G17      34
#define SSR_BIT_G16      33
#define SSR_BIT_G15      32
#define SSR_BIT_G14      31
#define SSR_BIT_G13      30
#define SSR_BIT_G12      29
#define SSR_BIT_G11      28
#define SSR_BIT_G10      27
#define SSR_BIT_G09      26
#define SSR_BIT_G08      25
#define SSR_BIT_G07      24
#define SSR_BIT_G06      23
#define SSR_BIT_G05      22
#define SSR_BIT_G04      21
#define SSR_BIT_G03      20
#define SSR_BIT_G02      19
#define SSR_BIT_G01      18
#define SSR_BIT_G00      17
#define SSR_BIT_H12      16
#define SSR_BIT_H11      15
#define SSR_BIT_H10      14
#define SSR_BIT_H09      13
#define SSR_BIT_H08      12
#define SSR_BIT_H07      11
#define SSR_BIT_H06      10
#define SSR_BIT_H05       9
#define SSR_BIT_H04       8
#define SSR_BIT_H03       7
#define SSR_BIT_H02       6
#define SSR_BIT_H01       5
#define SSR_BIT_H00       4
//                        3 // used only when unstable (during calculations)
//                        2 // used only when unstable (during calculations)
//                        1 // used only when unstable (during calculations)
//                        0 // 1 == stable, 0 == unstable (during calculations)
#pragma endregion // bit definitions for the (stable) id48lib state register
#pragma region    // Unstable (during calculations) id48lib state register
// Bit:  ₆₃  ₆₂  ₆₁  ₆₀  ₅₉  ₅₈  ₅₇  ₅₆  ₅₅  ₅₄  ₅₃  ₅₂  ₅₁  ₅₀  ₄₉  ₄₈  ₄₇  ₄₆  ₄₅  ₄₄  ₄₃  ₄₂  ₄₁  ₄₀  ₃₉  ₃₈  ₃₇  ₃₆  ₃₅  ₃₄  ₃₃  ₃₂
// Reg:  i   j  r₀₆ r₀₅ r₀₄ r₀₃ r₀₂ r₀₁ r₀₀ m₀₆ m₀₅ m₀₄ m₀₃ m₀₂ m₀₁ m₀₀ l₀₆ l₀₅ l₀₄ l₀₃ l₀₂ l₀₁ l₀₀ g₂₂ g₂₁ g₂₀ g₁₉ g₁₈ g₁₇ g₁₆ g₁₅ g₁₄
//
// Bit:  ₃₁  ₃₀  ₂₉  ₂₈  ₂₇  ₂₆  ₂₅  ₂₄  ₂₃  ₂₂  ₂₁  ₂₀  ₁₉  ₁₈  ₁₇  ₁₆  ₁₅  ₁₄  ₁₃  ₁₂  ₁₁  ₁₀  ₀₉  ₀₈  ₀₇  ₀₆  ₀₅  ₀₄  ₀₃  ₀₂  ₀₁  ₀₀
// Reg:  g₁₃ g₁₂ g₁₁ g₁₀ g₀₉ g₀₈ g₀₇ g₀₆ g₀₅ g₀₄ g₀₃ g₀₂ g₀₁ g₀₀ h₁₂ h₁₁ h₁₀ h₀₉ h₀₈ h₀₇ h₀₆ h₀₅ h₀₄ h₀₃ h₀₂ h₀₁ h₀₀  _   a   b   c   0
#pragma endregion // Unstable (during calculations) id48lib state register
//
// Summary of XOR baseline that can be excluded because they are part of a single 64-bit `<< 1` operation:
//     g₀₀ <-- h₁₂
//     l₀₀ <-- g₂₂
//     m₀₀ <-- l₀₆
//     r₀₀ <-- m₀₆
//
#pragma region    // bit definitions for the (unstable) id48lib state register
#define SSR_UNSTABLE_BIT_i           63
#define SSR_UNSTABLE_BIT_j           62
#define SSR_UNSTABLE_OLD_BIT_R06     61 // valid only during calculations aka R07 ... just has to have a name... doesn't matter what
#define SSR_UNSTABLE_OLD_BIT_R05     60
#define SSR_UNSTABLE_OLD_BIT_R04     59
#define SSR_UNSTABLE_OLD_BIT_R03     58
#define SSR_UNSTABLE_OLD_BIT_R02     57
#define SSR_UNSTABLE_OLD_BIT_R01     56
#define SSR_UNSTABLE_OLD_BIT_R00     55
#define SSR_UNSTABLE_OLD_BIT_M06     54
#define SSR_UNSTABLE_OLD_BIT_M05     53
#define SSR_UNSTABLE_OLD_BIT_M04     52
#define SSR_UNSTABLE_OLD_BIT_M03     51
#define SSR_UNSTABLE_OLD_BIT_M02     50
#define SSR_UNSTABLE_OLD_BIT_M01     49
#define SSR_UNSTABLE_OLD_BIT_M00     48
#define SSR_UNSTABLE_OLD_BIT_L06     47
#define SSR_UNSTABLE_OLD_BIT_L05     46
#define SSR_UNSTABLE_OLD_BIT_L04     45
#define SSR_UNSTABLE_OLD_BIT_L03     44
#define SSR_UNSTABLE_OLD_BIT_L02     43
#define SSR_UNSTABLE_OLD_BIT_L01     42
#define SSR_UNSTABLE_OLD_BIT_L00     41
#define SSR_UNSTABLE_OLD_BIT_G22     40
#define SSR_UNSTABLE_OLD_BIT_G21     39
#define SSR_UNSTABLE_OLD_BIT_G20     38
#define SSR_UNSTABLE_OLD_BIT_G19     37
#define SSR_UNSTABLE_OLD_BIT_G18     36
#define SSR_UNSTABLE_OLD_BIT_G17     35
#define SSR_UNSTABLE_OLD_BIT_G16     34
#define SSR_UNSTABLE_OLD_BIT_G15     33
#define SSR_UNSTABLE_OLD_BIT_G14     32
#define SSR_UNSTABLE_OLD_BIT_G13     31
#define SSR_UNSTABLE_OLD_BIT_G12     30
#define SSR_UNSTABLE_OLD_BIT_G11     29
#define SSR_UNSTABLE_OLD_BIT_G10     28
#define SSR_UNSTABLE_OLD_BIT_G09     27
#define SSR_UNSTABLE_OLD_BIT_G08     26
#define SSR_UNSTABLE_OLD_BIT_G07     25
#define SSR_UNSTABLE_OLD_BIT_G06     24
#define SSR_UNSTABLE_OLD_BIT_G05     23
#define SSR_UNSTABLE_OLD_BIT_G04     22
#define SSR_UNSTABLE_OLD_BIT_G03     21
#define SSR_UNSTABLE_OLD_BIT_G02     20
#define SSR_UNSTABLE_OLD_BIT_G01     19
#define SSR_UNSTABLE_OLD_BIT_G00     18
#define SSR_UNSTABLE_OLD_BIT_H12     17
#define SSR_UNSTABLE_OLD_BIT_H11     16
#define SSR_UNSTABLE_OLD_BIT_H10     15
#define SSR_UNSTABLE_OLD_BIT_H09     14
#define SSR_UNSTABLE_OLD_BIT_H08     13
#define SSR_UNSTABLE_OLD_BIT_H07     12
#define SSR_UNSTABLE_OLD_BIT_H06     11
#define SSR_UNSTABLE_OLD_BIT_H05     10
#define SSR_UNSTABLE_OLD_BIT_H04      9
#define SSR_UNSTABLE_OLD_BIT_H03      8
#define SSR_UNSTABLE_OLD_BIT_H02      7
#define SSR_UNSTABLE_OLD_BIT_H01      6
#define SSR_UNSTABLE_OLD_BIT_H00      5
#define SSR_UNSTABLE_NEW_BIT_H00      4 // ... new value of H00 goes here ...
#define SSR_UNSTABLE_BIT_a            3 // valid only during calculations (ssr & 0b1 == 0b0), else ???
#define SSR_UNSTABLE_BIT_b            2 // valid only during calculations (ssr & 0b1 == 0b0), else ???
#define SSR_UNSTABLE_BIT_c            1 // valid only during calculations (ssr & 0b1 == 0b0), else ???
//                                    0 // == 0 value defines as unstable state
#pragma endregion // bit definitions for the (stable) id48lib state register
#pragma region    // single bit test/set/clear/flip/assign
static inline bool is_ssr_state_stable(const ID48LIBX_STATE_REGISTERS *ssr)                   { ASSERT(ssr != nullptr); return ((ssr->Raw & 1u) == 1u); }
static inline bool test_single_ssr_bit(const ID48LIBX_STATE_REGISTERS *ssr, size_t bit_index) { ASSERT(ssr != nullptr); ASSERT(bit_index < (sizeof(uint64_t) * 8)); return ((ssr->Raw) >> bit_index) & 1;         }
static inline void set_single_ssr_bit(ID48LIBX_STATE_REGISTERS *ssr, size_t bit_index) { ASSERT(ssr != nullptr); ASSERT(bit_index < (sizeof(uint64_t) * 8)); ssr->Raw |= ((uint64_t)(1ull << bit_index)); }
static inline void clear_single_ssr_bit(ID48LIBX_STATE_REGISTERS *ssr, size_t bit_index) { ASSERT(ssr != nullptr); ASSERT(bit_index < (sizeof(uint64_t) * 8)); ssr->Raw &= ~((uint64_t)(1ull << bit_index)); }
static inline void flip_single_ssr_bit(ID48LIBX_STATE_REGISTERS *ssr, size_t bit_index) { ASSERT(ssr != nullptr); ASSERT(bit_index < (sizeof(uint64_t) * 8)); ssr->Raw ^= ((uint64_t)(1ull << bit_index)); }
static inline void assign_single_ssr_bit(ID48LIBX_STATE_REGISTERS *ssr, size_t bit_index, bool value) {
    ASSERT(ssr != nullptr);
    ASSERT(bit_index < (sizeof(uint64_t) * 8));
    if (value) {
        set_single_ssr_bit(ssr, bit_index);
    } else {
        clear_single_ssr_bit(ssr, bit_index);
    }
}
#pragma endregion // single bit test/set/clear/flip/assign
#pragma region    // test/assign of temporaries a/b/c/i/j
static inline void test_temporary_a(ID48LIBX_STATE_REGISTERS *ssr) { ASSERT(!is_ssr_state_stable(ssr)); test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a); }
static inline void test_temporary_b(ID48LIBX_STATE_REGISTERS *ssr) { ASSERT(!is_ssr_state_stable(ssr)); test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b); }
static inline void test_temporary_c(ID48LIBX_STATE_REGISTERS *ssr) { ASSERT(!is_ssr_state_stable(ssr)); test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c); }
static inline void test_temporary_i(ID48LIBX_STATE_REGISTERS *ssr) { ASSERT(!is_ssr_state_stable(ssr)); test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_i); }
static inline void test_temporary_j(ID48LIBX_STATE_REGISTERS *ssr) { ASSERT(!is_ssr_state_stable(ssr)); test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_j); }

static inline void assign_temporary_a(ID48LIBX_STATE_REGISTERS *ssr, bool v) { ASSERT(!is_ssr_state_stable(ssr)); assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a, v); }
static inline void assign_temporary_b(ID48LIBX_STATE_REGISTERS *ssr, bool v) { ASSERT(!is_ssr_state_stable(ssr)); assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b, v); }
static inline void assign_temporary_c(ID48LIBX_STATE_REGISTERS *ssr, bool v) { ASSERT(!is_ssr_state_stable(ssr)); assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c, v); }
static inline void assign_temporary_i(ID48LIBX_STATE_REGISTERS *ssr, bool v) { ASSERT(!is_ssr_state_stable(ssr)); assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_i, v); }
static inline void assign_temporary_j(ID48LIBX_STATE_REGISTERS *ssr, bool v) { ASSERT(!is_ssr_state_stable(ssr)); assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_j, v); }
#pragma endregion // test/assign of temporaries a/b/c/i/j

#pragma region    // Mask & Macro to get registers (in minimal bit form)
//                       ------------------------>          60   56   52   48   44   40   36   32   28   24   20   16   12    8    4    0
//                                                           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
#define SSR_BITMASK_REG_H   (0x000000000001FFF0ull) // (0b0000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0001'1111'1111'1111'0000ull)
#define SSR_BITMASK_REG_G   (0x000000FFFFFE0000ull) // (0b0000'0000'0000'0000'0000'0000'1111'1111'1111'1111'1111'1110'0000'0000'0000'0000ull)
#define SSR_BITMASK_REG_L   (0x00007F0000000000ull) // (0b0000'0000'0000'0000'0111'1111'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000ull)
#define SSR_BITMASK_REG_M   (0x003F100000000000ull) // (0b0000'0000'0011'1111'1000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000ull)
#define SSR_BITMASK_REG_R   (0x1FC0000000000000ull) // (0b0001'1111'1100'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000'0000ull)
#define SSR_BITMASK_REG_ALL (0x1FFFFFFFFFFFFFF0ull) // (0b0001'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'1111'0000ull)
//                                                           |    |    |    |    |    |    |    |    |    |    |    |    |    |    |    |
//                       ------------------------>          60   56   52   48   44   40   36   32   28   24   20   16   12    8    4    0

#define SSR_BITMASK_WITHOUT_REG_H     (~(SSR_BITMASK_REG_H))
#define SSR_BITMASK_WITHOUT_REG_G     (~(SSR_BITMASK_REG_G))
#define SSR_BITMASK_WITHOUT_REG_L     (~(SSR_BITMASK_REG_L))
#define SSR_BITMASK_WITHOUT_REG_M     (~(SSR_BITMASK_REG_M))
#define SSR_BITMASK_WITHOUT_REG_R     (~(SSR_BITMASK_REG_R))
#define SSR_BITMASK_WITHOUT_ANY_REGS  (~(SSR_BITMASK_REG_ALL))
#define SSR_SHIFT_COUNT_REG_H         ( 4)
#define SSR_SHIFT_COUNT_REG_G         (17)
#define SSR_SHIFT_COUNT_REG_L         (40)
#define SSR_SHIFT_COUNT_REG_M         (47)
#define SSR_SHIFT_COUNT_REG_R         (54)
#define SSR_VALUE_MASK_REG_H          (0x001FFFu) // 13 bits
#define SSR_VALUE_MASK_REG_G          (0x7FFFFFu) // 23 bits
#define SSR_VALUE_MASK_REG_L          (0x00007Fu) //  7 bits
#define SSR_VALUE_MASK_REG_M          (0x00007Fu) //  7 bits
#define SSR_VALUE_MASK_REG_R          (0x00007Fu) //  7 bits

static inline uint16_t get_register_h(const ID48LIBX_STATE_REGISTERS *ssr) { return ((uint16_t)(ssr->Raw >> SSR_SHIFT_COUNT_REG_H)) & (SSR_VALUE_MASK_REG_H); }
static inline uint32_t get_register_g(const ID48LIBX_STATE_REGISTERS *ssr) { return ((uint32_t)(ssr->Raw >> SSR_SHIFT_COUNT_REG_G)) & (SSR_VALUE_MASK_REG_G); }
static inline uint8_t  get_register_l(const ID48LIBX_STATE_REGISTERS *ssr) { return ((uint8_t)(ssr->Raw >> SSR_SHIFT_COUNT_REG_L)) & (SSR_VALUE_MASK_REG_L); }
static inline uint8_t  get_register_m(const ID48LIBX_STATE_REGISTERS *ssr) { return ((uint8_t)(ssr->Raw >> SSR_SHIFT_COUNT_REG_M)) & (SSR_VALUE_MASK_REG_M); }
static inline uint8_t  get_register_r(const ID48LIBX_STATE_REGISTERS *ssr) { return ((uint8_t)(ssr->Raw >> SSR_SHIFT_COUNT_REG_R)) & (SSR_VALUE_MASK_REG_R); }

static inline void set_register_h(ID48LIBX_STATE_REGISTERS *ssr, uint16_t v) { ASSERT((v & SSR_VALUE_MASK_REG_H) == v); ssr->Raw = (ssr->Raw & SSR_BITMASK_WITHOUT_REG_H) | (((uint64_t)(v & SSR_VALUE_MASK_REG_H)) << SSR_SHIFT_COUNT_REG_H); }
static inline void set_register_g(ID48LIBX_STATE_REGISTERS *ssr, uint32_t v) { ASSERT((v & SSR_VALUE_MASK_REG_G) == v); ssr->Raw = (ssr->Raw & SSR_BITMASK_WITHOUT_REG_G) | (((uint64_t)(v & SSR_VALUE_MASK_REG_G)) << SSR_SHIFT_COUNT_REG_G); }
static inline void set_register_l(ID48LIBX_STATE_REGISTERS *ssr, uint8_t  v) { ASSERT((v & SSR_VALUE_MASK_REG_L) == v); ssr->Raw = (ssr->Raw & SSR_BITMASK_WITHOUT_REG_L) | (((uint64_t)(v & SSR_VALUE_MASK_REG_L)) << SSR_SHIFT_COUNT_REG_L); }
static inline void set_register_m(ID48LIBX_STATE_REGISTERS *ssr, uint8_t  v) { ASSERT((v & SSR_VALUE_MASK_REG_M) == v); ssr->Raw = (ssr->Raw & SSR_BITMASK_WITHOUT_REG_M) | (((uint64_t)(v & SSR_VALUE_MASK_REG_M)) << SSR_SHIFT_COUNT_REG_M); }
static inline void set_register_r(ID48LIBX_STATE_REGISTERS *ssr, uint8_t  v) { ASSERT((v & SSR_VALUE_MASK_REG_R) == v); ssr->Raw = (ssr->Raw & SSR_BITMASK_WITHOUT_REG_R) | (((uint64_t)(v & SSR_VALUE_MASK_REG_R)) << SSR_SHIFT_COUNT_REG_R); }
#pragma endregion // Mask & Macro to get registers (in minimal bit form)

/// <summary>
/// Calculates and returns 56-bit value  p₅₅..p₀₀
/// per Definition 3.11:
/// p = p₀₀..p₅₅ = ( K₄₀..K₉₅ ) + ( N₀₀..N₅₅ )
/// </summary>
/// <param name="k96">key in pm3 order</param>
/// <param name="n56">nonce in pm3 order</param>
/// <returns>56-bit value p₅₅..p₀₀</returns>
static inline uint64_t calculate__p55_p00(const ID48LIB_KEY *k96, const ID48LIB_NONCE *n56) {
    // messy ... have to reverse the bits AND shift them into position,
    // perform the addition, and then reverse bits again to return to
    // native bit order (subscript is same as bit position).
    //
    // 1. for each byte, reverse bit order and shift into 64-bit tmp
    // 2. add the two 56-bit tmp values
    // 3. keeping only low 56-bit bits... reverse the bits
    ASSERT(k96 != nullptr);
    ASSERT(n56 != nullptr);
    uint64_t k40_k95 = 0;
    uint64_t n00_n55 = 0;
    //
    //     k [ 6] :== K₄₇..K₄₀
    //     ...
    //     k [ 0] :== K₉₅..K₈₈
    //
    //     rn[ 6] :== N₀₇..N₀₀
    //     ...
    //     rn[ 0] :== N₅₅..N₄₈
    //
    for (int8_t i = 6; i >= 0; --i) {
        k40_k95 <<= 8;
        n00_n55 <<= 8;
        uint8_t t1 = reverse_bits_08(k96->k[i]);
        k40_k95 |= t1;
        uint8_t t2 = reverse_bits_08(n56->rn[i]);
        n00_n55 |= t2;
    }
    uint64_t result = k40_k95 + n00_n55;
    // shift so msb == p₀₀  (p₀₀..p₅₅0⁸)
    result <<= 8;
    // reverse the 64-bit value to get: 0⁸p₅₅..p₀₀
    result = reverse_bits_64(result);
    return result;
}
/// <summary>
/// Calculate and return q₄₃..q₀₀
/// per Definition 3.11:
/// bitstream_q = (p₀₂ ... p₄₅) ⊕ (p₀₈ ... p₅₁) ⊕ (p₁₂ ... p₅₅)
///                <-- 44b -->     <-- 44b -->     <-- 44b -->
///     q43_q00 = (p₄₅ ... p₀₂) ⊕ (p₅₁ ... p₀₈) ⊕ (p₅₅ ... p₁₂)
/// </summary>
/// <param name="p55_p00">56 bit value: p₅₅..p₀₀</param>
/// <returns>44-bit value: q₄₃..q₀₀</returns>
static inline uint64_t calculate__q43_q00(const uint64_t *p55_p00) {
    ASSERT(p55_p00 != nullptr);
    static const uint64_t C_BITMASK44 = (1ull << 44) - 1u;
    uint64_t result = (*p55_p00 >>  2);
    result         ^= (*p55_p00 >>  8);
    result         ^= (*p55_p00 >> 12);
    result         &= C_BITMASK44;
    return result;
}


/// <summary>
/// Relies on old g22 bit (now in L00).
/// May modify G00, G03, G04, G05, G06, G13, G16
/// </summary>
static inline void g_successor(ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    ASSERT(!is_ssr_state_stable(ssr));
    assign_single_ssr_bit(ssr, SSR_BIT_G00, test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_j));
    //alternatively: set to zero, because `j` includes the start bit state
    //if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_j)) {
    //    flip_single_ssr_bit(ssr, SSR_BIT_G00);
    //}
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G22)) {
        //     taps ==> [ n, 16, 13,  6,  5,  3, 0 ]
        //            0b000'0001'0010'0000'0110'1001 == 0x012069
        static const uint64_t G22_XOR_MASK = 0x0000000240D20000ull;
        // static assert is only available in C11 (or C++11) and later...
        // _Static_assert(G22_XOR_MASK == (0x012069ull << SSR_SHIFT_COUNT_REG_G), "G22 XOR Mask invalid");
        ssr->Raw ^= G22_XOR_MASK;
    }
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_i)) {
        flip_single_ssr_bit(ssr, SSR_BIT_G04);
    }
}

static inline ID48LIBX_STATE_REGISTERS init_id48libx_state_register(const ID48LIB_KEY *k96, const ID48LIB_NONCE *n56) {
    ASSERT(k96 != nullptr);
    ASSERT(n56 != nullptr);
    ID48LIBX_STATE_REGISTERS result;
    result.Raw = 0;
    ID48LIBX_STATE_REGISTERS *const ssr = &result; // the pointer is constant ... not the value it points to

    const uint64_t p55_p00 = calculate__p55_p00(k96, n56);
    // p55_p00 is used to set initial value of register l
    if (true) {
        static const uint8_t C_BITMASK7 = ((1u << 7) - 1u);
        const uint8_t l = (
                              ((uint8_t)(p55_p00 >> 55)) ^ //    0   0   0   0   0   0 p55
                              ((uint8_t)(p55_p00 >> 51)) ^ //    0   0 p55 p54 p53 p52 p51
                              ((uint8_t)(p55_p00 >> 45))   //  p51 p50 p49 p48 p47 p46 p45
                          ) & C_BITMASK7;
        set_register_l(ssr, l);
        ASSERT(l == get_register_l(ssr));
    }

    // p is used to calculate q
    const uint64_t q43_q00 = calculate__q43_q00(&p55_p00);

    // init( q₂₀..q₄₂, q₀₀..q₁₉ )
    // ===> G(q₂₀..q₄₂, 0, q₀₀..q₁₉)
    // ===> g₀₀..g₂₂ :=== q₂₀..q₄₂
    //  and j₀₀..j₁₉ :=== q₀₀..q₁₉
    //
    // But, since I'm storing the register with g₀₀ as lsb:
    // ===> g₂₂..g₀₀ :=== q₄₂..q₂₀
    if (true) {
        static const uint32_t C_BITMASK23 = ((1u << 23) - 1u);
        const uint32_t g = ((uint32_t)(q43_q00 >> 20)) & C_BITMASK23;
        set_register_g(ssr, g);
        ASSERT(g == get_register_g(ssr));
    }

    // input bits for `j` during init are q00..q19, with q19 used first
    // For ease of use, I'll generate this as q00..q19, so the loop
    // can test the lsb (and then shift it right one bit)
    uint32_t q00_q19 = reverse_bits_32(((uint32_t)q43_q00) << 12);
    uint32_t q_lsb_next = q00_q19;
    ssr->Raw |= 1u;

    // G(g,0,j) twenty times, using q19, q18, ... q00 for `j`
    for (uint8_t ix = 0; ix < 20; ++ix) {
        ASSERT(is_ssr_state_stable(ssr));
        ssr->Raw <<= 1; // starts the process ... it's now an unstable value
        ASSERT(!is_ssr_state_stable(ssr));
        assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_j, (q_lsb_next & 1u) != 0);
        assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_i, 0);
        q_lsb_next >>= 1;

        g_successor(ssr);
        // save only the register bits
        ssr->Raw &= SSR_BITMASK_REG_ALL;
        // mark this as a stable value
        ssr->Raw |= 1u;
    }

    // h00..h12 is defined as 0 p00..p11
    // but since we're storing h as h12..h00:  p11..p00 0
    if (true) {
        // NOTE: delay `h` until loops done, else low bits
        // will shift into / break calculation of g() above
        static const uint16_t C_BITMASK_H_INIT = (1u << 13) - 2u; // 0b1'1111'1111'1110
        const uint16_t h = (((uint16_t)p55_p00) << 1) & C_BITMASK_H_INIT;
        set_register_h(ssr, h);
        ASSERT(h == get_register_h(ssr));
    }
    return result;
}

/// <summary>
/// H(h) matches the research paper, definition 3.3
///
/// Reads bits H01, H08, H09, H11, H12.
/// </summary>
/// <remarks>
/// If ssr is in unstable state, caller is responsible for ensuring
/// the values have not changed.
/// </remarks>
static inline bool calculate_feedback_h(const ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    // ( h₀₁ && h₀₈ ) || ( h₀₉ && h₁₁ ) || (!h₁₂        )
    // \____ a1 ____/    \____ a2 ____/    \____ a3 ____/
    // result == xor(a1,a2,a3)
    bool a1 = is_ssr_state_stable(ssr) ?
              test_single_ssr_bit(ssr, SSR_BIT_H01)              && test_single_ssr_bit(ssr, SSR_BIT_H08) :
              test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_H01) && test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_H08);
    bool a2 = is_ssr_state_stable(ssr) ?
              test_single_ssr_bit(ssr, SSR_BIT_H09)              && test_single_ssr_bit(ssr, SSR_BIT_H11) :
              test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_H09) && test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_H11);
    bool a3 = is_ssr_state_stable(ssr) ?
              !test_single_ssr_bit(ssr, SSR_BIT_H12) :
              !test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_H12);
    bool result = false;
    if (a1) result = !result;
    if (a2) result = !result;
    if (a3) result = !result;
    return result;
}

/// <summary>
/// fₗ(...) matches the research paper, definition 3.4
/// hard-coded to use bits for calculation of 'a'
/// </summary>
static inline bool calculate_feedback_l(const ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    // a = fₗ( g00  g04  g06  g13  g18  h03  ) ⊕  g22  ⊕  r02  ⊕  r06
    //     fₗ(  x₀   x₁   x₂   x₃   x₄   x₅ )
    bool x0 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G00 : SSR_UNSTABLE_OLD_BIT_G00);
    bool x1 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G04 : SSR_UNSTABLE_OLD_BIT_G04);
    bool x2 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G06 : SSR_UNSTABLE_OLD_BIT_G06);
    bool x3 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G13 : SSR_UNSTABLE_OLD_BIT_G13);
    bool x4 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G18 : SSR_UNSTABLE_OLD_BIT_G18);
    bool x5 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_H03 : SSR_UNSTABLE_OLD_BIT_H03);

    bool line1 = !x0 && !x2 &&  x3;
    bool line2 =  x2 &&  x4 && !x5;
    bool line3 =  x0 && !x1 && !x4;
    bool line4 =  x1 && !x3 &&  x5;

    bool result = line1 || line2 || line3 || line4;
    return result;
}

/// <summary>
/// fₘ(...) matches the research paper, definition 3.5
/// hard-coded to use bits for calculation of 'b'
/// </summary>
static inline bool calculate_feedback_m(const ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    // b = fₘ( g01  g05  g10  g15  h00  h07 ) ⊕  l00  ⊕  l03  ⊕  l06
    //     fₘ( x₀   x₁   x₂   x₃   x₄   x₅ )
    bool x0 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G01 : SSR_UNSTABLE_OLD_BIT_G01);
    bool x1 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G05 : SSR_UNSTABLE_OLD_BIT_G05);
    bool x2 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G10 : SSR_UNSTABLE_OLD_BIT_G10);
    bool x3 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_G15 : SSR_UNSTABLE_OLD_BIT_G15);
    bool x4 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_H00 : SSR_UNSTABLE_OLD_BIT_H00);
    bool x5 = test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_H07 : SSR_UNSTABLE_OLD_BIT_H07);

    bool line1 =  x1 && !x2 && !x4;
    bool line2 =  x0 &&  x2 && !x3;
    bool line3 = !x1 &&  x3 &&  x5;
    bool line4 = !x0 &&  x4 && !x5;

    bool result = line1 || line2 || line3 || line4;
    return result;
}

/// <summary>
/// fᵣ(...) matches the research paper, definition 3.6
/// hard-coded to use bits for calculation of 'c'
/// </summary>
static inline bool calculate_feedback_r(const ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    ASSERT(!is_ssr_state_stable(ssr));
    // c = fᵣ( g02  g03⊕i  g09  g14  g16  h01 ) ⊕  m00  ⊕  m03  ⊕  m06
    //     fᵣ( x₀   x₁     x₂    x₃   x₄   x₅ )
    bool x0 = test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G02);
    bool x1 = test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G03);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_i)) { x1 = !x1; }
    bool x2 = test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G09);
    bool x3 = test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G14);
    bool x4 = test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G16);
    bool x5 = test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_H01);

    bool line1 =  x1 &&  x3 && !x5;
    bool line2 =  x2 && !x3 && !x4;
    bool line3 = !x0 && !x2 &&  x5;
    bool line4 =  x0 && !x1 &&  x4;
    bool result = line1 || line2 || line3 || line4;
    return result;
}

/// <summary>
/// Matches the research paper, definition 3.7
/// See also Definition 3.2, defining that parameter as `j`.
/// </summary>
static inline bool calculate_j(const ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    // g′  := G(g, i, l₀₁ ⊕ m₀₆ ⊕ h₀₂ ⊕ h₀₈ ⊕ h₁₂)
    //                ^^^^^^^^^^^^^^^^^^^^^^^^^^^------ calculates `j`
    bool result = 0;
    if (test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_L01 : SSR_UNSTABLE_OLD_BIT_L01)) result = !result;
    if (test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_M06 : SSR_UNSTABLE_OLD_BIT_M06)) result = !result;
    if (test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_H02 : SSR_UNSTABLE_OLD_BIT_H02)) result = !result;
    if (test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_H08 : SSR_UNSTABLE_OLD_BIT_H08)) result = !result;
    if (test_single_ssr_bit(ssr, is_ssr_state_stable(ssr) ? SSR_BIT_H12 : SSR_UNSTABLE_OLD_BIT_H12)) result = !result;
    return result;
}


/// <summary>
/// REQUIRES INPUT BIT `i` TO BE VALID.
/// Calculates a, b, c, j and new value for H₀₀.
/// These are the only bits changed by this function.
/// </summary>
static inline void calculate_temporaries(ID48LIBX_STATE_REGISTERS *ssr) {
    ASSERT(ssr != nullptr);
    #pragma region    // to be removed after all is validated
    static const uint64_t bits_must_remain_same_mask =
        ~(
            (1ull << SSR_UNSTABLE_BIT_a) |
            (1ull << SSR_UNSTABLE_BIT_b) |
            (1ull << SSR_UNSTABLE_BIT_c) |
            (1ull << SSR_UNSTABLE_BIT_j) |
            (1ull << SSR_UNSTABLE_NEW_BIT_H00)
        );

    const uint64_t backup = ssr->Raw & bits_must_remain_same_mask;
    (void)backup; // to avoid warning about unused variable
    #pragma endregion // to be removed after all is validated

    // Only bits that change value: H00, a, b, c, j

    ASSERT(!is_ssr_state_stable(ssr)); // assigning temp values directly in ssr, so...
    assign_single_ssr_bit(ssr, SSR_UNSTABLE_NEW_BIT_H00, calculate_feedback_h(ssr));
    assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a,       calculate_feedback_l(ssr));
    assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b,       calculate_feedback_m(ssr));
    assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c,       calculate_feedback_r(ssr));
    assign_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_j,       calculate_j(ssr));

    // NOTE: Could scramble the below nine lines into any order desired.
    // If start by setting the outputs all to zero, could also scramble the above into this mix
    //
    // a = fₗ()  ⊕  g22  ⊕  r02  ⊕  r06
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_G22)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R02)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R06)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a);
    // b = fₘ() ⊕  l00  ⊕  l03  ⊕  l06
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L00)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L03)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L06)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b);
    // c = fᵣ() ⊕  m00  ⊕  m03  ⊕  m06
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M00)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M03)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M06)) flip_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c);

    #pragma region    // to be removed after all is validated
    const uint64_t chk = ssr->Raw & bits_must_remain_same_mask;
    (void)chk; // to avoid warning about unused variable
    ASSERT(chk == backup);
    #pragma endregion // to be removed after all is validated

    return;
}


static inline OUTPUT_INDEX2 calculate_output_index(const ID48LIBX_STATE_REGISTERS *ssr) {
    //           Fₒ( abc l₀l₂l₃l₄l₅l₆ m₀m₁m₃m₅ r₀r₁r₂r₃r₄r₅r₆ )
    //     msb 19 ---^                           lsb 00 ---^^
    ASSERT(ssr != nullptr);
    ASSERT(!is_ssr_state_stable(ssr));
    OUTPUT_INDEX2 result;
    result.Raw = 0;
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a)) result.Raw |= (1u << 19);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b)) result.Raw |= (1u << 18);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c)) result.Raw |= (1u << 17);
    //bool bit17 = test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c);
    //if (test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_i)      ) bit17 = !bit17;
    //if (bit17                                              ) result.Raw |= (1u << 17);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L00)) result.Raw |= (1u << 16);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L02)) result.Raw |= (1u << 15);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L03)) result.Raw |= (1u << 14);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L04)) result.Raw |= (1u << 13);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L05)) result.Raw |= (1u << 12);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_L06)) result.Raw |= (1u << 11);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M00)) result.Raw |= (1u << 10);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M01)) result.Raw |= (1u <<  9);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M03)) result.Raw |= (1u <<  8);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_M05)) result.Raw |= (1u <<  7);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R00)) result.Raw |= (1u <<  6);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R01)) result.Raw |= (1u <<  5);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R02)) result.Raw |= (1u <<  4);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R03)) result.Raw |= (1u <<  3);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R04)) result.Raw |= (1u <<  2);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R05)) result.Raw |= (1u <<  1);
    if (test_single_ssr_bit(ssr, SSR_UNSTABLE_OLD_BIT_R06)) result.Raw |= (1u <<  0);
    return result;
}

// returns a single bit corresponding to the output bit for this transition
static inline bool calculate_successor_state(ID48LIBX_STATE_REGISTERS *ssr, bool i) {
    ASSERT(ssr != nullptr);
    ASSERT(is_ssr_state_stable(ssr));


    // HACK -- ORDER OF THESE OPERATIONS MATTERS ...
    //         to avoid overwriting bits needed for calculation of temporaries
    // Thus:
    // 1. ssr_new = ssr_old << 1;            // all prior values still available (even r₀₆)
    // 2. store input bit `i`                // required many places
    // 3. calculate and store a/b/c/j h'00   // can use SSR_UNSTABLE_OLD_BIT_... to get old values
    // 4. calculate and save output index    // relies on a/b/c AND the bits that get modified using a/b/c,
    //                                       // so must be after calculate a/b/c and before setting new L00,M00,R00 values
    // 5. G(g, i, j)                         // relies on SSR_UNSTABLE_OLD_BIT_G22, which is now L00 ... aka must do before L()
    // 6. L()                                // overwrite L00 with `a`
    // 7. M()                                // overwrite M00 with `b`
    // 8. R()                                // overwrite R00 with `c`
    //


    // 1. ssr_new = ssr_old << 1;
    ssr->Raw <<= 1; // begin!

    // 2. store input bit `i`
    assign_temporary_i(ssr, i);

    // 3. calculate and store a/b/c/j and new H00 bits
    calculate_temporaries(ssr);                               // updates new H00, stores a/c/c and j

    // 4. calculate and save output index
    OUTPUT_INDEX2 output_index = calculate_output_index(ssr); // note: does *NOT* rely on new H00 value
    bool output_result = id48libx_output_lookup(output_index.Raw);

    // 5. g --> g', aka G(g, i, j)
    g_successor(ssr);

    // 6. l --> l'
    assign_single_ssr_bit(ssr, SSR_BIT_L00, test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_a));

    // 7. m --> m'
    assign_single_ssr_bit(ssr, SSR_BIT_M00, test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_b));

    // 8. r --> r'
    assign_single_ssr_bit(ssr, SSR_BIT_R00, test_single_ssr_bit(ssr, SSR_UNSTABLE_BIT_c));

    // Done!  Clear temporaries and indicate this is a final state

    // Keep only the registers (no temporaries)
    ssr->Raw &= SSR_BITMASK_REG_ALL;

    // Mark as stable view of the SSR
    ssr->Raw |= 1u;

    return output_result;
}

/// <summary>
/// Returns a value where the least significant bit is the
/// first input bit, so that the value can be right-shifted
/// by one bit each iteration (allowing least significant bit
/// to always be the input bit).
/// </summary>
static inline INPUT_BITS2 get_key_input_bits(const ID48LIB_KEY *k) {
    ASSERT(k != nullptr);

    // Per research paper, key bit 39 is used first.
    // So, what should end up in result is: 0²⁴ k₀₀..K₃₉
    // This allows simply shifting the lsb out each cycle....

    INPUT_BITS2 result;
    result.Raw = 0;

    //     k[ 0] :== K₉₅..K₈₈
    //     ...
    //     k[ 7] :== K₃₉..K₃₂
    //     ...
    //     k[11] :== K₀₇..K₀₀
    for (uint8_t i = 0; i < 5; ++i) {
        result.Raw <<= 8;
        uint8_t tmp = k->k[11 - i]; // e.g., first loop will contain K₀₇..K₀₀
        tmp = reverse_bits_08(tmp); // e.g., first loop will contain K₀₀..K₀₇
        result.Raw |= tmp;
    }

    static const uint64_t INPUT_MASK = (1ull << 40) - 1u;
    (void)INPUT_MASK; // to avoid warning about unused variable
    ASSERT((result.Raw & (~INPUT_MASK)) == 0ull);
    return result;
}

static inline bool shift_out_next_input_bit(INPUT_BITS2 *inputs) {
    ASSERT(inputs != nullptr);
    bool result = inputs->Raw & 1ull;
    inputs->Raw >>= 1;
    return result;
}
static inline void shift_in_next_output_bit(OUTPUT_BITS2 *outputs, bool v) {
    ASSERT(outputs != nullptr);
    outputs->Raw <<= 1;
    if (v) outputs->Raw |= 1ull;
}

static inline void extract_frn(const OUTPUT_BITS2 *outputs, ID48LIB_FRN *frn28_out) {
    ASSERT(outputs   != nullptr);
    ASSERT(frn28_out != nullptr);

    static const uint64_t C_MASK28 = (1ull << 28) - 1u;
    uint64_t tmp = outputs->Raw;
    tmp >>= 20;      // remove the 20 bit grn (but still has 7 ignored bits)
    tmp &= C_MASK28; // tmp now has exactly 28 valid bits
    tmp <<=  4;      // align to 32-bits for easier assignment to output
    // tmp now :== O₀₀..O₂₇ 0000
    frn28_out->frn[0] = (uint8_t)((tmp >> (8 * 3)) & 0xFFu);
    frn28_out->frn[1] = (uint8_t)((tmp >> (8 * 2)) & 0xFFu);
    frn28_out->frn[2] = (uint8_t)((tmp >> (8 * 1)) & 0xFFu);
    frn28_out->frn[3] = (uint8_t)((tmp >> (8 * 0)) & 0xFFu);
}
static inline void extract_grn(const OUTPUT_BITS2 *outputs, ID48LIB_GRN *grn20_out) {
    ASSERT(outputs   != nullptr);
    ASSERT(grn20_out != nullptr);
    memset(grn20_out, 0, sizeof(ID48LIB_GRN));

    static const uint64_t C_MASK20 = (1ull << 20) - 1u;
    uint64_t tmp = outputs->Raw;
    tmp &= C_MASK20; // tmp now has exactly 20 valid bits
    tmp <<= 4;       // align to 24-bits for easier assignment to output
    grn20_out->grn[0] = (uint8_t)((tmp >> (8 * 2)) & 0xFFu);
    grn20_out->grn[1] = (uint8_t)((tmp >> (8 * 1)) & 0xFFu);
    grn20_out->grn[2] = (uint8_t)((tmp >> (8 * 0)) & 0xFFu);
}

static void retro_generator_impl(
    const ID48LIB_KEY *k,
    const ID48LIB_NONCE *n,
    ID48LIB_FRN *frn28_out,
    ID48LIB_GRN *grn20_out
) {
    ASSERT(k         != nullptr);
    ASSERT(n         != nullptr);
    ASSERT(frn28_out != nullptr);
    ASSERT(grn20_out != nullptr);
    memset(frn28_out, 0, sizeof(ID48LIB_FRN));
    memset(grn20_out, 0, sizeof(ID48LIB_GRN));

    ID48LIBX_STATE_REGISTERS ssr = init_id48libx_state_register(k, n);

    // get 55-bit successor state input
    INPUT_BITS2 inputs  = get_key_input_bits(k);
    OUTPUT_BITS2 outputs;
    outputs.Raw = 0ull;
    for (uint8_t ix = 0; ix < 55; ix++) {
        ASSERT(is_ssr_state_stable(&ssr));

        // input bit `i` is not valid in stable state...
        bool input_bit = shift_out_next_input_bit(&inputs);
        // calculate the next state... (note: logs calculations for this state)
        bool output_bit = calculate_successor_state(&ssr, input_bit);
        ASSERT(is_ssr_state_stable(&ssr));

        // store the output bit
        shift_in_next_output_bit(&outputs, output_bit);
    }

    // convert the output bits into frn/grn
    extract_frn(&outputs, frn28_out);
    extract_grn(&outputs, grn20_out);
    return;
}


//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ******************************************************************************************************************** //
// *** Everything above this line in the file is declared static,                                                   *** //
// *** which avoids polluting the global namespace.                                                                 *** //
// *** Everything below is technically visible, but not necessarily an exported API.                                *** //
// *** In C++, this separation is much more easily achieved using an anonymous namespace.  C'est la vie!            *** //
// ******************************************************************************************************************** //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

// internal function
ID48LIBX_SUCCESSOR_RESULT id48libx_retro003_successor(const ID48LIBX_STATE_REGISTERS *initial_state, uint8_t input_bit) {
    ASSERT(initial_state != nullptr);
    ID48LIBX_SUCCESSOR_RESULT r;
    memset(&r, 0, sizeof(ID48LIBX_SUCCESSOR_RESULT));
    ID48LIBX_STATE_REGISTERS s = *initial_state;
    bool output_bit = calculate_successor_state(&s, !!input_bit);
    r.state.Raw = s.Raw;
    r.output = output_bit;
    return r;
}
// internal function
ID48LIBX_STATE_REGISTERS  id48libx_retro003_init(const ID48LIB_KEY *key, const ID48LIB_NONCE *nonce) {
    ASSERT(key != nullptr);
    ASSERT(nonce != nullptr);

    ID48LIBX_STATE_REGISTERS ssr = init_id48libx_state_register(key, nonce);
    ID48LIBX_STATE_REGISTERS result;
    memset(&result, 0, sizeof(ID48LIBX_STATE_REGISTERS));
    result.Raw = ssr.Raw;
    return result;
}

// public API
void id48lib_generator(
    const ID48LIB_KEY *k,
    const ID48LIB_NONCE *n,
    ID48LIB_FRN *frn28_out,
    ID48LIB_GRN *grn20_out
) {
    retro_generator_impl(k, n, frn28_out, grn20_out);
}
