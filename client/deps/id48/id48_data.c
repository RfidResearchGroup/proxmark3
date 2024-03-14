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
#define COUNT_OF_POTENTIAL_INPUTS (0x100000ul) // thus the lookup parameter is uint20_t...

/// initial_idx = (l0 << 7) | (l4 << 6) | (l6 << 5) | (m1 << 4) | (m3 << 3) | (r0 << 2) | (r3 << 1) | (r5 << 0)
static const uint8_t small_lut_initial[32] = {  // aka 256 bits
    0x44, 0xff, 0x4f, 0x4f, 0x55, 0xff, 0x55, 0x55,
    0xcc, 0xff, 0xcf, 0x4f, 0xcc, 0xff, 0xcc, 0x44,
    0x00, 0x00, 0x0f, 0x0f, 0x55, 0x55, 0x55, 0x55,
    0xcc, 0x00, 0xcf, 0x0f, 0xcc, 0x00, 0xcc, 0x00,
};
/// g1_idx = (a << 4) | (l2 << 3) | (l3 << 2) | (l0 << 1) | (l6 << 0)
static const uint8_t small_lut_group1[4] = { // aka 32 bits
    0x4f, 0x92, 0xa1, 0x7c,
};
/// g2_idx = (l5 << 4) | (b << 3) | (m0 << 2) | (l4 << 1) | (m1 << 0)
static const uint8_t small_lut_group2[4] = { // aka 32 bits
    0x8f, 0x52, 0x61, 0xbc,
};
/// g3_idx = (m5 << 4) | (c << 3) | (r1 << 2) | (m3 << 1) | (r3 << 0)
static const uint8_t small_lut_group3[4] = { // aka 32 bits
    0x8f, 0x34, 0x61, 0xda,
};
/// g4_idx = (r2 << 4) | (r4 << 3) | (r6 << 2) | (r0 << 1) | (r5 << 0)
static const uint8_t small_lut_group4[4] = { // aka 32 bits
    0x8f, 0x34, 0x52, 0xe9,
};

static inline bool get_bit(const uint8_t *table_start, uint32_t bit_idx) {
    const uint32_t byte = bit_idx / 8u;
    const uint8_t  mask = 1u << (bit_idx % 8u);
    return (table_start[byte] & mask) != 0;
}

//
// NOTE: Additional optimizations possible, but not pursued.
// Could spend a lot of time to define more optimized version that directly
// takes ID48LIBX_STATE_REGISTERS as input.  These optimizations may include
// changing the order of the bits in each intermediate lookup index (indices).
// Optimizations may also include modifying where a/b/c are stored in the
// ID48LIBX_STATE_REGISTER, such as shifting a/b/c from being stored at
// bits [03,02,01] to being stored at bit [61,60,59].
//
//  Q: Maybe move a/b/c to upper 32 bits?
//     This would allow all bits and bitshifting to occur using only upper 32-bits.
//
// Note: Each set of bits for the lookup tables can be in any order,
//       so long as the lookup tables are adjusted accordingly.
//
// Which bits are used for which small lookup table indixes?
//
// Bit:  ₆₃  ₆₂  ₆₁  ₆₀  ₅₉  ₅₈  ₅₇  ₅₆  ₅₅  ₅₄  ₅₃  ₅₂  ₅₁  ₅₀  ₄₉  ₄₈  ₄₇  ₄₆  ₄₅  ₄₄  ₄₃  ₄₂  ₄₁  ₄₀  ₃₉  ₃₈  ₃₇  ₃₆  ₃₅  ₃₄  ₃₃  ₃₂
// Reg:  i   j  r₀₆ r₀₅ r₀₄ r₀₃ r₀₂ r₀₁ r₀₀ m₀₆ m₀₅ m₀₄ m₀₃ m₀₂ m₀₁ m₀₀ l₀₆ l₀₅ l₀₄ l₀₃ l₀₂ l₀₁ l₀₀ g₂₂ g₂₁ g₂₀ g₁₉ g₁₈ g₁₇ g₁₆ g₁₅ g₁₄
//                  i_v     i_v         i_v             i_v     i_v     i_v     i_v             i_v
//                                                                      AAA         AAA AAA     AAA
//                                                              BBB BBB     BBB BBB
//                          CCC     CCC         CCC     CCC
//              DDD DDD DDD     DDD     DDD
//
// Bit:  ₃₁  ₃₀  ₂₉  ₂₈  ₂₇  ₂₆  ₂₅  ₂₄  ₂₃  ₂₂  ₂₁  ₂₀  ₁₉  ₁₈  ₁₇  ₁₆  ₁₅  ₁₄  ₁₃  ₁₂  ₁₁  ₁₀  ₀₉  ₀₈  ₀₇  ₀₆  ₀₅  ₀₄  ₀₃  ₀₂  ₀₁  ₀₀
// Reg:  g₁₃ g₁₂ g₁₁ g₁₀ g₀₉ g₀₈ g₀₇ g₀₆ g₀₅ g₀₄ g₀₃ g₀₂ g₀₁ g₀₀ h₁₂ h₁₁ h₁₀ h₀₉ h₀₈ h₀₇ h₀₆ h₀₅ h₀₄ h₀₃ h₀₂ h₀₁ h₀₀  _   a   b   c   0
//                                                                                                                      AAA BBB CCC
//
// Example minor optimization of initial 8-bit lookup:
// ===================================================
// i_v depends on ==> r₀₅ ... r₀₃ ... ... r₀₀ ... ... ... m₀₃ ... m₀₁ ... l₀₆ ... ... l₀₄ ... ... ... l₀₀
// So can reduce the number of operations somewhat as follows:
//                    ... r₀₅ ... r₀₃ ... ... ... ...
//                    r₀₀ ... ... ... m₀₃ ... ... ...
//                    ... ... ... ... ... m₀₁ ... l₀₆
//                    ... ... l₀₄ ... ... ... l₀₀ ...
// Resulting in the following (slightly-improved) bit order for the lookup table index:
//                    r₀₀ r₀₅ l₀₄ r₀₃ m₀₃ m₀₁ l₀₀ l₀₆
//
// alt_initial_v = // r₀₀ r₀₅ l₀₄ r₀₃ m₀₃ m₀₁ l₀₀ l₀₆
//    ((uint8_t)((r & (R05_BIT | R03_BIT)) >> (58 - 4))) |
//    ((uint8_t)((r & (R00_BIT | M03_BIT)) >> (51 - 3))) |
//    ((uint8_t)((r & (M01_BIT | L06_BIT)) >> (47 - 0))) |
//    ((uint8_t)((r & (L04_BIT | L00_BIT)) >> (41 - 1))) ;
//

static bool output_lookup_small_lut(uint32_t output_index) {
    if (output_index >= COUNT_OF_POTENTIAL_INPUTS) { return false; }
    //     1 1 1 1  1  1  1  1  1  1
    //     9 8 7 6  5  4  3  2  1  0  9  8  7  6  5  4  3  2  1  0
    // Fₒ( a b c l₀ l₂ l₃ l₄ l₅ l₆ m₀ m₁ m₃ m₅ r₀ r₁ r₂ r₃ r₄ r₅ r₆ )

    const uint8_t initial_v = // i_v
        ((output_index >>  9) & 0x80u) | // (l0 << 7)
        ((output_index >>  7) & 0x40u) | // (l4 << 6)
        ((output_index >>  6) & 0x20u) | // (l6 << 5)
        ((output_index >>  5) & 0x10u) | // (m1 << 4)
        ((output_index >>  5) & 0x08u) | // (m3 << 3)
        ((output_index >>  4) & 0x04u) | // (r0 << 2)
        ((output_index >>  2) & 0x02u) | // (r3 << 1)
        ((output_index >>  1) & 0x01u) ; // (r5 << 0)
    const uint8_t g1_v = // AAA
        ((output_index >> 15) & 0x10u) | // ( a << 4) |
        ((output_index >> 12) & 0x08u) | // (l2 << 3) |
        ((output_index >> 12) & 0x04u) | // (l3 << 2) |
        ((output_index >> 15) & 0x02u) | // (l0 << 1) |
        ((output_index >> 11) & 0x01u) ; // (l6 << 0) ;
    const uint8_t g2_v = // BBB
        ((output_index >>  8) & 0x10u) | // (l5 << 4) |
        ((output_index >> 15) & 0x08u) | // ( b << 3) |
        ((output_index >>  8) & 0x04u) | // (m0 << 2) |
        ((output_index >> 12) & 0x02u) | // (l4 << 1) |
        ((output_index >>  9) & 0x01u) ; // (m1 << 0) ;
    const uint8_t g3_v = // CCC
        ((output_index >>  3) & 0x10u) | // (m5 << 4) |
        ((output_index >> 14) & 0x08u) | // ( c << 3) |
        ((output_index >>  3) & 0x04u) | // (r1 << 2) |
        ((output_index >>  7) & 0x02u) | // (m3 << 1) |
        ((output_index >>  3) & 0x01u) ; // (r3 << 0) ;
    const uint8_t g4_v = // DDD
        ((output_index >>  0) & 0x10u) | // (r2 << 4) |
        ((output_index <<  1) & 0x08u) | // (r4 << 3) |
        ((output_index <<  2) & 0x04u) | // (r6 << 2) |
        ((output_index >>  5) & 0x02u) | // (r0 << 1) |
        ((output_index >>  1) & 0x01u) ; // (r5 << 0) ;
    bool result = get_bit(small_lut_initial, initial_v);
    if (get_bit(small_lut_group1, g1_v)) result = !result;
    if (get_bit(small_lut_group2, g2_v)) result = !result;
    if (get_bit(small_lut_group3, g3_v)) result = !result;
    if (get_bit(small_lut_group4, g4_v)) result = !result;
    return result;
}

//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ******************************************************************************************************************** //
// *** Everything above this line in the file is declared static,                                                   *** //
// *** which avoids polluting the global namespace.                                                                 *** //
// *** Everything below is technically visible, but not necessarily an exported API.                                *** //
// *** In C++, this separation is much more easily achieved using an anonymous namespace.  C'est la vie!            *** //
// ******************************************************************************************************************** //
//////////////////////////////////////////////////////////////////////////////////////////////////////////////////////////

bool id48libx_output_lookup(uint32_t output_index) {
    return output_lookup_small_lut(output_index);
}
