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
// Low frequency EM4x50 structs
//-----------------------------------------------------------------------------

#ifndef EM4X50_H__
#define EM4X50_H__

#include "common.h"
#include "bruteforce.h"

#define EM4X50_NO_WORDS             34
#define EM4X50_SIZE_WORD            4

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

// commands
#define EM4X50_COMMAND_LOGIN                0x01
#define EM4X50_COMMAND_RESET                0x80
#define EM4X50_COMMAND_WRITE                0x12
#define EM4X50_COMMAND_WRITE_PASSWORD       0x11
#define EM4X50_COMMAND_SELECTIVE_READ       0x0A
#define EM4X50_COMMAND_STANDARD_READ        0x02 // virtual command

// misc
#define EM4X50_TIMEOUT_CMD                 3000
#define EM4X50_DUMP_FILESIZE               136

typedef struct {
    bool addr_given;
    bool pwd_given;
    uint32_t password1;
    uint32_t password2;
    uint32_t word;
    uint32_t addresses;
    bruteforce_mode_t bruteforce_mode;
    bruteforce_charset_t bruteforce_charset;
} PACKED em4x50_data_t;

typedef struct {
    uint8_t byte[4];
} PACKED em4x50_word_t;

// CMD_LF_EM4X50_ESET payload
typedef struct {
    uint16_t offset;
    uint16_t len;
    uint8_t data[];
} PACKED em4x50_eset_t;

typedef struct {
    uint8_t count;
    uint32_t *words;
} PACKED em4x50_read_data_response_t;

// CMD_LF_EM4X50_CONFIG payload and reply, reader timings in carrier cycles
#define EM4X50_CONFIG_GET           0
#define EM4X50_CONFIG_SET           1
#define EM4X50_CONFIG_RESET         2

typedef struct {
    uint8_t mode;           // EM4X50_CONFIG_*
    uint8_t threshold;      // envelope thresholds, percent of amplitude
    uint8_t tolerance;      // pulse length tolerance
    uint8_t gap_start;      // field gap start within a reader "0" bit
    uint8_t gap_end;        // field gap end within a reader "0" bit
    uint16_t rm_delay;      // RM start after the end of the first listen window
} PACKED em4x50_config_t;

// Global variables...
extern bool g_Login;
extern bool g_WritePasswordProcess;
extern uint32_t g_Password;

#endif /* EM4X50_H__ */
