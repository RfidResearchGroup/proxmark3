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
// iCLASS type prototyping
//-----------------------------------------------------------------------------

#ifndef _ICLASS_CMD_H_
#define _ICLASS_CMD_H_

#include "common.h"

//-----------------------------------------------------------------------------
// iCLASS / PICOPASS
//-----------------------------------------------------------------------------


// iCLASS reader flags
#define FLAG_ICLASS_READER_INIT        0x01
#define FLAG_ICLASS_READER_CLEARTRACE  0x02
//#define FLAG_ICLASS_READER_ONLY_ONCE   0x04
#define FLAG_ICLASS_READER_CREDITKEY   0x08
#define FLAG_ICLASS_READER_AIA         0x10
#define FLAG_ICLASS_READER_SHALLOW_MOD 0x20

// iCLASS reader status flags
#define FLAG_ICLASS_NULL               0x00
#define FLAG_ICLASS_CSN                0x01
#define FLAG_ICLASS_CC                 0x02
#define FLAG_ICLASS_CONF               0x04
#define FLAG_ICLASS_AIA                0x08

// iCLASS simulation modes
#define ICLASS_SIM_MODE_CSN                   0
#define ICLASS_SIM_MODE_CSN_DEFAULT           1
#define ICLASS_SIM_MODE_READER_ATTACK         2
#define ICLASS_SIM_MODE_FULL                  3
#define ICLASS_SIM_MODE_READER_ATTACK_KEYROLL 4
#define ICLASS_SIM_MODE_EXIT_AFTER_MAC        5  // note: device internal only
#define ICLASS_SIM_MODE_CONFIG_CARD           6


// iCLASS auth request data structure
// used with read block, dump, write block
typedef struct {
    uint8_t key[8];
    bool use_raw;
    bool use_elite;
    bool use_credit_key;
    bool use_replay;
    bool send_reply;
    bool do_auth;
    bool shallow_mod;
    uint8_t blockno;
} PACKED iclass_auth_req_t;

// iCLASS read block response data structure
typedef struct {
    bool isOK;
    uint8_t div_key[8];
    uint8_t mac[4];
    uint8_t data[8];
} PACKED iclass_readblock_resp_t;

// iCLASS dump data structure
typedef struct {
    iclass_auth_req_t req;
    uint8_t start_block;
    uint8_t end_block;
} PACKED iclass_dump_req_t;

// iCLASS write block request data structure
typedef struct {
    iclass_auth_req_t req;
    uint8_t data[8];
    uint8_t mac[4];
} PACKED iclass_writeblock_req_t;

// iCLASS dump data structure
typedef struct {
    uint8_t blockno;
    uint8_t data[8];
} PACKED iclass_restore_item_t;

typedef struct {
    iclass_auth_req_t req;
    uint8_t item_cnt;
    iclass_restore_item_t blocks[];
} PACKED iclass_restore_req_t;

typedef struct iclass_premac {
    uint8_t mac[4];
} PACKED iclass_premac_t;

typedef struct {
    bool use_credit_key;
    bool shallow_mod;
    uint8_t count;
    iclass_premac_t items[];
} PACKED iclass_chk_t;

typedef struct iclass_block {
    uint8_t d[8];
} iclass_block_t;

typedef struct iclass_prekey {
    uint8_t mac[4];
    uint8_t key[8];
} iclass_prekey_t;

typedef struct {
    char desc[70];
    uint8_t data[16];
} iclass_config_card_item_t;


// iclass / picopass chip config structures and shared routines
typedef struct {
    uint8_t app_limit;      //[8]
    uint8_t otp[2];         //[9-10]
    uint8_t block_writelock;//[11]
    uint8_t chip_config;    //[12]
    uint8_t mem_config;     //[13]
    uint8_t eas;            //[14]
    uint8_t fuses;          //[15]
} PACKED picopass_conf_block_t;

// iCLASS secure mode memory mapping
typedef struct {
    uint8_t csn[8];
    picopass_conf_block_t conf;
    uint8_t epurse[8];
    uint8_t key_d[8];
    uint8_t key_c[8];
    uint8_t app_issuer_area[8];
} PACKED picopass_hdr_t;

// iCLASS non-secure mode memory mapping
typedef struct {
    uint8_t csn[8];
    picopass_conf_block_t conf;
    uint8_t app_issuer_area[8];
} PACKED picopass_ns_hdr_t;

// reader flags
typedef struct {
    uint8_t flags;
} PACKED iclass_card_select_t;

// reader flags
typedef struct {
    uint8_t status;
    union {
        picopass_hdr_t hdr;
        picopass_ns_hdr_t ns_hdr;
    } header;
} PACKED iclass_card_select_resp_t;


#endif // _ICLASS_H_
