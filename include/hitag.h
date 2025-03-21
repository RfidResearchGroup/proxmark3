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
// Hitag 2, Hitag S, Hitag µ
//-----------------------------------------------------------------------------


#ifndef HITAG_H__
#define HITAG_H__

#include "common.h"

#define HITAG_NRAR_SIZE         8
#define HITAG_CRYPTOKEY_SIZE    6
#define HITAG_PASSWORD_SIZE     4
#define HITAG_UID_SIZE          4
#define HITAG_BLOCK_SIZE        4

#define HITAG2_MAX_BLOCKS       8
#define HITAG2_MAX_BYTE_SIZE    (HITAG2_MAX_BLOCKS * HITAG_BLOCK_SIZE)

#define HITAGS_PAGE_SIZE        HITAG_BLOCK_SIZE
#define HITAGS_BLOCK_PAGES      4
#define HITAGS_BLOCK_SIZE       (HITAGS_BLOCK_PAGES * HITAGS_MAX_PAGES)
#define HITAGS_MAX_PAGES        64
#define HITAGS_MAX_BYTE_SIZE    (HITAGS_MAX_PAGES * HITAGS_PAGE_SIZE)
#define HITAGS_UID_PADR         0
#define HITAGS_CONFIG_PADR      1

// Add Hitag µ specific definitions
#define HITAGU_UID_SIZE         6
#define HITAGU_BLOCK_SIZE       HITAG_BLOCK_SIZE
#define HITAGU_MAX_BLOCKS       0x100
#define HITAGU_MAX_BYTE_SIZE    (HITAGU_MAX_BLOCKS * HITAGU_BLOCK_SIZE)
#define HITAGU_CONFIG_PADR      0xFF
#define HITAGU_PASSWORD_PADR    0xFE

// Hitag µ IC Revision (ICR) values
#define HITAGU_ICR_STANDARD      0x10  // Standard Hitag µ
#define HITAGU_ICR_ADVANCED      0x20  // Hitag µ advanced
#define HITAGU_ICR_ADVANCED_PLUS 0x30  // Hitag µ advanced+
#define HITAGU_ICR_8265          0x80  // 8265

// Hitag µ memory sizes based on ICR
#define HITAGU_MAX_PAGE_STANDARD      0x04  // 4 blocks (0x00-0x03) for standard Hitag µ
#define HITAGU_MAX_PAGE_ADVANCED      0x10  // 16 blocks (0x00-0x0F) for Hitag µ advanced
#define HITAGU_MAX_PAGE_ADVANCED_PLUS 0x37  // 56 blocks (0x00-0x36) for Hitag µ advanced+
#define HITAGU_MAX_PAGE_8265          0x0F  // 15 blocks (0x00-0x0E) for 8265

// need to see which limits these cards has
#define HITAG1_MAX_BYTE_SIZE    64
#define HITAG_MAX_BYTE_SIZE     (64 * HITAG_BLOCK_SIZE)

#define HITAG2_CONFIG_BLOCK     3

// Modulation types - used by shared code
typedef enum modulation {
    AC2K = 0,  // Amplitude modulation 2000 bits/s
    AC4K,      // Amplitude modulation 4000 bits/s
    MC4K,      // Manchester modulation 4000 bits/s
    MC8K       // Manchester modulation 8000 bits/s
} MOD;

typedef enum {
    HTSF_PLAIN,
    HTSF_82xx,
    HTSF_CHALLENGE,
    HTSF_KEY,
    HTS_LAST_CMD = HTSF_KEY,

    HT1F_PLAIN,
    HT1F_AUTHENTICATE,
    HT1_LAST_CMD = HT1F_AUTHENTICATE,

    HT2F_PASSWORD,
    HT2F_AUTHENTICATE,
    HT2F_CRYPTO,
    HT2F_TEST_AUTH_ATTEMPTS,
    HT2F_UID_ONLY,
    HT2_LAST_CMD = HT2F_UID_ONLY,

    // Add Hitag µ commands
    HTUF_PLAIN,
    HTUF_82xx,
    HTUF_PASSWORD,
    HTU_LAST_CMD = HTUF_PASSWORD,
} PACKED hitag_function;

//---------------------------------------------------------
// Hitag S
//---------------------------------------------------------
// protocol-state
typedef enum PROTO_STATE {
    HT_READY = 0,
    HT_INIT,
    HT_AUTHENTICATE,
    HT_SELECTED,
    HT_QUIET,
    HT_TTF,
    HT_FAIL
} PSTATE;

typedef enum TAG_STATE {
    HT_NO_OP = 0,
    HT_READING_PAGE,
    HT_WRITING_PAGE_ACK,
    HT_WRITING_PAGE_DATA,
    HT_WRITING_BLOCK_DATA
} TSATE;

typedef struct {
    // con0
    uint8_t MEMT : 2;
    uint8_t RES0 : 1;  // for 82xx. Enable somekind extended TTF mode in conjunction with TTFM
    uint8_t RES1 : 1;
    uint8_t RES2 : 1;
    uint8_t RES3 : 1;  // for 82xx. Enable TTF FSK mode  0=RF/10 1=RF/8
    uint8_t RES4 : 1;
    uint8_t RES5 : 1;

    // con1
    uint8_t LKP : 1;    // 0 = page2/3 read write 1 =page2/3 read only in Plain mode and no access in authenticate mode
    uint8_t LCON : 1;   // 0 = con1/2 read write  1 =con1 read only and con2 OTP
    uint8_t TTFM : 2;   // the number of pages that are sent to the RWD
    uint8_t TTFDR : 2;  // data rate in TTF Mode
    uint8_t TTFC : 1;   // Transponder Talks first coding. 0 = Manchester 1 = Biphase
    uint8_t auth : 1;   // 0 = Plain 1 = Auth
    // con2
    // 0 = read write 1 = read only
    uint8_t LCK0 : 1;  // page48-63
    uint8_t LCK1 : 1;  // page32-47
    uint8_t LCK2 : 1;  // page24-31
    uint8_t LCK3 : 1;  // page16-23
    uint8_t LCK4 : 1;  // page12-15
    uint8_t LCK5 : 1;  // page8-11
    uint8_t LCK6 : 1;  // page6/7
    uint8_t LCK7 : 1;  // page4/5
    // reserved/pwdh0
    uint8_t pwdh0;
} PACKED hitags_config_t;

struct hitagS_tag {
    PSTATE   pstate;  // protocol-state
    TSATE    tstate;    // tag-state

    int      max_page;

    union {
        uint8_t pages[HITAGS_MAX_PAGES][HITAGS_PAGE_SIZE];
        struct {
            // page 0
            uint32_t uid_le;

            hitags_config_t config;

            // page 2
            uint8_t  pwdl0;
            uint8_t  pwdl1;
            uint64_t key : 48;    // fixme: unaligned access

            // page 4
        } s;
    } data;

} PACKED;

// Configuration byte 0 bit definitions
#define HITAGU_BYTE0_DATARATE_MASK 0x03  // Bits 0-1: data rate
#define HITAGU_BYTE0_DATARATE_2K 0x00    // 00 = 2kbit/s
#define HITAGU_BYTE0_DATARATE_4K 0x01    // 01 = 4kbit/s
#define HITAGU_BYTE0_DATARATE_8K 0x02    // 10 = 8kbit/s
#define HITAGU_BYTE0_ENCODING_MASK       0x04   // Bit 2: encoding
#define HITAGU_BYTE0_ENCODING_MANCHESTER 0x00   // 0 = Manchester
#define HITAGU_BYTE0_ENCODING_BIPHASE    0x01 // 1 = Biphase

// Hitag µ configuration structure
typedef struct {
    // byte0
    uint8_t datarate: 2;
    uint8_t encoding: 1;
    uint8_t pwdW0_127: 1;
    uint8_t pwdW128_511: 1;
    uint8_t pwdW512_max: 1;
    uint8_t pwdRW512_max: 1;
} PACKED hitagu_config_t;

typedef struct {
    // byte0
    uint8_t datarate : 2;  // 00 = 2kbit/s, 01 = 4kbit/s, 10 = 8kbit/s, 11 = 2kbit/s
    uint8_t datarate_override : 1;  // 0 = datarate, 1 = 2kbit/s
    uint8_t encoding : 1; // 0 = Manchester, 1 = Biphase

    uint8_t reserved : 1;
    uint8_t ttf_mode : 2;  // 00/10/11 = "Block 0, Block 1, Block 2, Block 3", 01 = "Block 0, Block 1"
    uint8_t ttf : 1;
} PACKED hitagu82xx_config_t;

// Hitag µ tag structure
struct hitagU_tag {
    PSTATE   pstate;  // protocol-state
    TSATE    tstate;  // tag-state

    int      max_page;
    uint8_t  uid[HITAGU_UID_SIZE];
    union {
        uint8_t asBytes[HITAGU_BLOCK_SIZE];
        hitagu_config_t s;
        hitagu82xx_config_t s82xx;
    } config;
    uint8_t  password[HITAG_PASSWORD_SIZE];
    uint8_t icr;  // IC Revision value - determines memory size

    union {
        uint8_t pages[HITAGU_MAX_BLOCKS][HITAGU_BLOCK_SIZE];
    } data;
} PACKED;

typedef struct {
    hitag_function cmd;
    uint8_t page;
    uint8_t page_count;
    uint8_t data[HITAG_BLOCK_SIZE];
    uint8_t NrAr[HITAG_NRAR_SIZE];
    // unaligned access to key as uint64_t will abort.
    // todo: Why does the compiler without -munaligned-access generate unaligned-access code in the first place?
    uint8_t key[HITAG_CRYPTOKEY_SIZE] __attribute__((aligned(4)));
    uint8_t pwd[HITAG_PASSWORD_SIZE];

    // Hitag 1 section.
    // will reuse pwd or key field.
    uint8_t key_no;
    uint8_t logdata_0[4];
    uint8_t logdata_1[4];
    uint8_t nonce[4];

    // Hitag S section
    uint8_t mode;

    // Hitag µ section
    uint8_t uid[HITAGU_UID_SIZE];
} PACKED lf_hitag_data_t;

typedef struct {
    int status;
    uint8_t data[256];
} PACKED lf_hitag_crack_response_t;

typedef union {
    uint8_t asBytes[HITAGS_PAGE_SIZE];
    hitags_config_t s;
} hitags_config_page_t;

typedef struct {
    hitags_config_page_t config_page;
    int8_t  pages_reason[HITAGS_MAX_PAGES];
    uint8_t pages[HITAGS_MAX_PAGES][HITAGS_PAGE_SIZE];
} PACKED lf_hts_read_response_t;

typedef union {
    uint8_t asBytes[HITAGU_BLOCK_SIZE];
    hitagu_config_t s;
    hitagu82xx_config_t s82xx;
} hitagu_config_page_t;

// Hitag µ read response structure
typedef struct {
    hitagu_config_page_t config_page;
    uint8_t uid[HITAGU_UID_SIZE];
    uint8_t icr;                                  // IC Revision value for memory size detection
    int8_t  pages_reason[HITAGU_MAX_PAGE_ADVANCED_PLUS];
    uint8_t pages[HITAGU_MAX_PAGE_ADVANCED_PLUS][HITAGU_BLOCK_SIZE];
} PACKED lf_htu_read_response_t;

#endif
