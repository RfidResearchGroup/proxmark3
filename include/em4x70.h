//-----------------------------------------------------------------------------
// Copyright (C) 2020 sirloins
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x70 structs
//-----------------------------------------------------------------------------

#ifndef EM4X70_H__
#define EM4X70_H__

#define EM4X70_NUM_BLOCKS 16

// Common word/block addresses
#define EM4X70_PIN_WORD_LOWER 10
#define EM4X70_PIN_WORD_UPPER 11

typedef struct {
    bool parity;

    // Used for writing address
    uint8_t address;
    uint16_t word;

    // PIN to unlock
    uint32_t pin;

    // Used for authentication
    uint8_t rnd[7];
    uint8_t frnd[4];

    // Used to write new key
    uint8_t crypt_key[12];

} em4x70_data_t;

#endif /* EM4X70_H__ */
