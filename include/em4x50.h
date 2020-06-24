//-----------------------------------------------------------------------------
// Copyright (C) 2020 tharexde
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM4x50 structs
//-----------------------------------------------------------------------------

#ifndef EM4X50_H__
#define EM4X50_H__

typedef struct {
    bool fwr_given;
    bool lwr_given;
    bool pwd_given;
    bool newpwd_given;
    uint8_t password[4];
    uint8_t new_password[4];
    uint8_t addresses[4];
    uint8_t address;
    uint8_t word[4];
} em4x50_data_t;

typedef struct {
    uint8_t byte[4];
    uint8_t row_parity[4];
    uint8_t col_parity;
    uint8_t stopbit;
    bool rparity[4];
    bool cparity[8];
    bool stopparity;
    bool parity;
} em4x50_word_t;

#endif /* EM4X50_H__ */
