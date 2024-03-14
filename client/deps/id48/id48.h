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
#if !defined(ID48_H__)
#define ID48_H__

// This file defines only the structs and API surface.
// There are no dependencies on any external code.
#include <stdint.h>
#include <string.h>
#include <stdbool.h>
#if defined(NDEBUG)
#define ASSERT(x) ((void)0)
#elif defined(ID48_NO_STDIO)
#define ASSERT(x) ((void)0)
#else // neither NDEBUG nor ID48_NO_STDIO defined
#include <stdio.h>
#include <assert.h>
#define ASSERT(x) assert((x))
#endif


#if defined(__cplusplus)
extern "C" {
#endif

/// <summary>
/// [0..11] stores K₉₅..K₀₀
/// </summary>
/// <remarks>
/// Big-endian, "native" bit order, when viewed linearly from k[ 0..11]
/// Mapping to the indices used in the research paper:
///     k[ 0] :== K₉₅..K₈₈
///     k[ 1] :== K₈₇..K₈₀
///     k[ 2] :== K₇₉..K₇₂
///     k[ 3] :== K₇₁..K₆₄
///     k[ 4] :== K₆₃..K₅₆
///     k[ 5] :== K₅₅..K₄₈
///     k[ 6] :== K₄₇..K₄₀
///     k[ 7] :== K₃₉..K₃₂
///     k[ 8] :== K₃₁..K₂₄
///     k[ 9] :== K₂₃..K₁₆
///     k[10] :== K₁₅..K₀₈
///     k[11] :== K₀₇..K₀₀
/// </remarks>
typedef struct _ID48LIB_KEY { // 96-bit
    uint8_t k[12];
} ID48LIB_KEY;
/// <summary>
/// [0..6] stores N₅₅..N₀₀
/// </summary>
/// <remarks>
/// Big-endian, "native" bit order, when viewed linearly from rn[0..6]
/// Mapping to the indices used in the research paper:
///     rn[ 0] :== N₅₅..N₄₈
///     rn[ 1] :== N₄₇..N₄₀
///     rn[ 2] :== N₃₉..N₃₂
///     rn[ 3] :== N₃₁..N₂₄
///     rn[ 4] :== N₂₃..N₁₆
///     rn[ 5] :== N₁₅..N₀₈
///     rn[ 6] :== N₀₇..N₀₀
/// </remarks>
typedef struct _ID48LIB_NONCE { // 56-bit
    uint8_t rn[7];
} ID48LIB_NONCE;
/// <summary>
/// [0..3] stores O₀₀..O₂₇ 0000
/// </summary>
/// <remarks>
/// Big-endian, "bitstream" bit order, when viewed linearly from frn[0..3]
/// This is the order in which the research paper typically lists the bits.
/// Mapping to the indices used in the research paper,
/// where ( O₀₀ .. O₂₇ ) :== output(s₀₇,k₃₂..k₀₅ )
/// then:
///     frn[ 0] :== O₀₀..O₀₇
///     frn[ 1] :== O₀₈..O₁₅
///     frn[ 2] :== O₁₆..O₂₃
///     frn[ 3] :== O₂₄..O₂₇ 0000
/// </remarks>
typedef struct _ID48LIB_FRN {
    uint8_t frn[4];
} ID48LIB_FRN;
/// <summary>
/// [0..3] stores O₂₈..O₄₇  (12x 0)
/// </summary>
/// <remarks>
/// Native format if viewed linearly from frn[0..6].
/// Mapping to the indices used in the research paper,
/// where ( O₂₈ .. O₅₅ ) :== output( s₃₅, k₀₄..k₀₀ (15x 0) ) == grn
///
/// then:
///     rn[ 0] :== O₂₈  ..  O₃₅
///     rn[ 1] :== O₃₆  ..  O₄₃
///     rn[ 2] :== O₄₄..O₄₇ 0000
///     rn[ 3] :==  0000    0000
/// </remarks>
typedef struct _ID48LIB_GRN {
    uint8_t grn[3];
} ID48LIB_GRN;

/// <summary>
/// When provided a key and nonce, will calculate
/// the frn and grn values and store in caller-provided
/// output parameters.
/// </summary>
/// <remarks>
/// Note: In C++, each parameter would be a reference (not pointer).
/// </remarks>
void id48lib_generator(
    const ID48LIB_KEY *key_96bit,
    const ID48LIB_NONCE *nonce_56bit,
    ID48LIB_FRN *frn28_out,
    ID48LIB_GRN *grn20_out
);

/// <summary>
/// Initializes to allow iterative recovery
/// of multiple potential keys.  After calling
/// this init() function, can repeatedly call
/// the next() function until it returns false
/// to obtain all potential keys.
/// </summary>
/// <param name="input_partial_key">
/// Top 48 bits of the key, such as those discovered
/// using the proxmark3 command `lf em 4x70 brute`.
/// Only k[0..5] are used from this parameter,
/// corresponding to K₉₅..K₄₈.
/// </param>
/// <param name="input_nonce">
/// The nonce value.
/// Typically from a sniffed authentication.
/// </param>
/// <param name="input_frn">
/// The challenge sent from the reader (e.g., car)
/// to the tag (e.g., key).
/// Typically from a sniffed authentication.
/// </param>
/// <param name="input_grn">
/// The response sent from the tag (e.g., key)
/// to the car (e.g., car).
/// Typically from a sniffed authentication.
/// </param>
/// <remarks>
/// Note: In C++, each parameter would be a reference (not pointer).
/// </remarks>
void id48lib_key_recovery_init(
    const ID48LIB_KEY *input_partial_key,
    const ID48LIB_NONCE *input_nonce,
    const ID48LIB_FRN *input_frn,
    const ID48LIB_GRN *input_grn
);
/// <summary>
/// This can be repeated called (after calling init())
/// to find the next potential key for the given
/// partial key + nonce + frn + grn values.
/// I've seen combinations that have up to six
/// potential keys available, although typically
/// there are 1-3 results.
/// Each call to this function will return a single
/// value.  Call repeatedly until the function returns
/// false to get all potential keys.
/// </summary>
/// <param name="potential_key_output">
/// When the function returns true, this caller-provided
/// value will be filled with the 96-bit key that, when
/// programmed to the tag, should authenticate against
/// the nonce+frn values, with tag returning the grn value.
/// </param>
/// <returns>
/// true when another potential key has been found.
/// false if no additional potential keys have been found.
/// </returns>
/// <remarks>
/// Note: In C++, each parameter would be a reference (not pointer).
/// </remarks>
bool id48lib_key_recovery_next(
    ID48LIB_KEY *potential_key_output
);

#if defined(__cplusplus)
}
#endif

#endif // !defined(ID48_H__)

