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
// Low frequency EM4x70 structs -- common to both ARM firmware and client
//-----------------------------------------------------------------------------

#ifndef EM4X70_H__
#define EM4X70_H__

#include <stdint.h>
#include <stdbool.h>
#include <assert.h>

#define EM4X70_NUM_BLOCKS 16

// Common word/block addresses
#define EM4X70_PIN_WORD_LOWER 10
#define EM4X70_PIN_WORD_UPPER 11

/// @brief Command transport structure for EM4x70 commands.
/// @details
///     This structure is used to transport data from the PC
///     to the proxmark3, and contain all data needed for
///     a given `lf em 4x70 ...` command to be processed
///     on the proxmark3.
///     The only requirement is that this structure remain
///     smaller than the NG buffer size (256 bytes).
typedef struct {
    bool parity;

    // Used for writing address
    uint8_t address;
    // BUGBUG: Non-portable ... presumes stored in little-endian form!
    uint16_t word;

    // PIN to unlock
    // BUGBUG: Non-portable ... presumes stored in little-endian form!
    uint32_t pin;

    // Used for authentication
    //
    // IoT safe subset of C++ would be helpful here,
    // to support variable-bit-length integer types
    // as integral integer types.
    //
    // Even C23 would work for this (GCC14+, Clang15+):
    //     _BitInt(56) rnd;
    //     _BitInt(28) frnd;
    //     _BitInt(20) grnd;
    uint8_t frnd[4];
    uint8_t grnd[3];
    uint8_t rnd[7];

    // Used to write new key
    uint8_t crypt_key[12];

    // used for bruteforce the partial key
    // BUGBUG: Non-portable ... presumes stored in little-endian form!
    uint16_t start_key;

} em4x70_data_t;
//_Static_assert(sizeof(em4x70_data_t) == 36);

// ISSUE: `bool` type does not have a standard-defined size.
//        therefore, compatibility between architectures /
//        compilers is not guaranteed.
// TODO: verify alignof(bool) == 1
//_Static_assert(sizeof(bool) == 1, "bool size mismatch");
typedef union {
    uint8_t data[32];
} em4x70_tag_t;
//_Static_assert(sizeof(em4x70_tag_t) == 32, "em4x70_tag_t size mismatch");

#endif /* EM4X70_H__ */
