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

#define EM4X50_NO_WORDS             34

// special words
#define EM4X50_DEVICE_PASSWORD      0
#define EM4X50_PROTECTION           1
#define EM4X50_CONTROL              2
#define EM4X50_DEVICE_SERIAL        32
#define EM4X50_DEVICE_ID            33

// control word (word = 4 bytes)
#define FIRST_WORD_READ             0       // first byte
#define LAST_WORD_READ              1       // second byte
#define CONFIG_BLOCK                2       // third byte
#define PASSWORD_CHECK              0x80    // first bit in third byte
#define READ_AFTER_WRITE            0x40    // second bit in third byte

// protection word
#define FIRST_WORD_READ_PROTECTED   0       // first byte
#define LAST_WORD_READ_PROTECTED    1       // second byte
#define FIRST_WORD_WRITE_INHIBITED  2       // third byte
#define LAST_WORD_WRITE_INHIBITED   3       // fourth byte

// misc
#define STATUS_NO_WORDS             0xfc
#define STATUS_SUCCESS              0x2
#define STATUS_LOGIN                0x1
#define NO_CHARS_MAX                400
#define TIMEOUT                     2000

typedef struct {
    bool addr_given;
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
