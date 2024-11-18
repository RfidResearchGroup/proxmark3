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
// Hitag 2, Hitag S
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

// need to see which limits these cards has
#define HITAG1_MAX_BYTE_SIZE    64
#define HITAGU_MAX_BYTE_SIZE    64
#define HITAG_MAX_BYTE_SIZE    (64 * HITAG_BLOCK_SIZE)

#define HITAG2_CONFIG_BLOCK     3

typedef enum {
    HTSF_PLAIN,
    HTSF_82xx,
    HTSF_CHALLENGE,
    HTSF_KEY,
    HTS_LAST_CMD              = HTSF_KEY,

    HT1F_PLAIN,
    HT1F_AUTHENTICATE,
    HT1_LAST_CMD              = HT1F_AUTHENTICATE,

    HT2F_PASSWORD,
    HT2F_AUTHENTICATE,
    HT2F_CRYPTO,
    HT2F_TEST_AUTH_ATTEMPTS,
    HT2F_UID_ONLY,
    HT2_LAST_CMD              = HT2F_UID_ONLY,
} PACKED hitag_function;

typedef struct {
    hitag_function cmd;
    uint8_t page;
    uint8_t page_count;
    uint8_t data[HITAGS_PAGE_SIZE];
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
} PACKED lf_hitag_data_t;

typedef struct {
    int status;
    uint8_t data[256];
} PACKED lf_hitag_crack_response_t;

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

//number of start-of-frame bits
typedef enum SOF_TYPE {
    HT_STANDARD = 0,
    HT_ADVANCED,
    HT_FAST_ADVANCED,
    HT_ONE,
    HT_NO_BITS
} stype;

typedef struct {
    // con0
    uint8_t MEMT : 2;
    bool    RES0 : 1;  // for 82xx. Enable somekind extended TTF mode in conjunction with TTFM
    bool    RES1 : 1;
    bool    RES2 : 1;
    bool    RES3 : 1;  // for 82xx. Enable TTF FSK mode  0=RF/10 1=RF/8
    bool    RES4 : 1;
    bool    RES5 : 1;

    // con1
    bool    LKP : 1;    // 0 = page2/3 read write 1 =page2/3 read only in Plain mode and no access in authenticate mode
    bool    LCON : 1;   // 0 = con1/2 read write  1 =con1 read only and con2 OTP
    uint8_t TTFM : 2;   // the number of pages that are sent to the RWD
    uint8_t TTFDR : 2;  // data rate in TTF Mode
    bool    TTFC : 1;   // Transponder Talks first coding. 0 = Manchester 1 = Biphase
    bool    auth : 1;   // 0 = Plain 1 = Auth
    // con2
    // 0 = read write 1 = read only
    bool LCK0 : 1;  // page48-63
    bool LCK1 : 1;  // page32-47
    bool LCK2 : 1;  // page24-31
    bool LCK3 : 1;  // page16-23
    bool LCK4 : 1;  // page12-15
    bool LCK5 : 1;  // page8-11
    bool LCK6 : 1;  // page6/7
    bool LCK7 : 1;  // page4/5
    // reserved/pwdh0
    uint8_t pwdh0;
} PACKED hitags_config_t;

struct hitagS_tag {
    PSTATE   pstate;  // protocol-state
    TSATE    tstate;    // tag-state

    int      max_page;
    stype    mode;

    union {
        uint8_t pages[64][4];
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

typedef struct {
    union {
        uint8_t asBytes[HITAGS_PAGE_SIZE];
        hitags_config_t s;
    } config_page;
    int8_t  pages_reason[HITAGS_MAX_PAGES];
    uint8_t pages[HITAGS_MAX_PAGES][HITAGS_PAGE_SIZE];
} PACKED lf_hts_read_response_t;
#endif
