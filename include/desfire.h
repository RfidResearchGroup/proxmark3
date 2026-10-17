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
#ifndef __DESFIRE_H
#define __DESFIRE_H

#include "common.h"

#define DESFIRE_MAX_CRYPTO_BLOCK_SIZE 16
#define DESFIRE_MAX_KEY_SIZE  24
#define DESFIRE_MAC_LENGTH 4
#define DESFIRE_CMAC_LENGTH 8

typedef enum {
    T_DES = 0x00,
    T_3DES = 0x01, //aka 2K3DES
    T_3K3DES = 0x02,
    T_AES = 0x03
} DesfireCryptoAlgorithm;

#define DESFIRE_MAX_ALGO_COUNT  4       // T_DES ... T_AES
#define DESFIRE_MAX_KEY_COUNT   0x0E    // key numbers 0x00 ... 0x0D
#define DESFIRE_MAX_APP_COUNT   64      // applications we keep track of per PICC
#define DESFIRE_MAX_FILE_COUNT  32      // file numbers 0x00 ... 0x1F

// Optional CMD_HF_DESFIRE_SIMULATE payload. An empty payload keeps normal
// simulation unchanged. A probe stops before the final authentication answer.
#define DESFIRE_SIM_PROBE_VERSION 2
#define DESFIRE_SIM_PROBE_KEY_ANY 0xFF
typedef enum {
    DESFIRE_SIM_PROBE_DISCOVERY_FAILED = 0,
    DESFIRE_SIM_PROBE_NO_RESPONSE = 1,
    DESFIRE_SIM_PROBE_NO_MATCH = 2,
    DESFIRE_SIM_PROBE_MATCH = 3,
    DESFIRE_SIM_PROBE_UNSUPPORTED = 4,
} desfire_sim_probe_outcome_t;

typedef struct {
    uint8_t version;
    uint8_t aid[3];             // target AID in wire order
    uint8_t keyno;              // 0xFF: use the reader-requested key in the image
    uint8_t algorithm;          // DesfireCryptoAlgorithm
    uint32_t candidate_id;      // opaque host identifier, never key material
    uint8_t rndb[16];           // fresh host nonce; deterministic only in tests
    uint8_t discovery_aid[3];   // optional pre-auth application, zero disables
    uint8_t discovery_file;     // file number to observe on that application
} PACKED desfire_sim_probe_cmd_t;

#define DESFIRE_SIM_PROBE_SELECTED       (1 << 0)
#define DESFIRE_SIM_PROBE_AUTH_REQUEST   (1 << 1)
#define DESFIRE_SIM_PROBE_CHALLENGE      (1 << 2)
#define DESFIRE_SIM_PROBE_CONTINUATION   (1 << 3)
#define DESFIRE_SIM_PROBE_DECRYPTED      (1 << 4)
#define DESFIRE_SIM_PROBE_RNDB_MATCH     (1 << 5)
#define DESFIRE_SIM_PROBE_DISCOVERY_SELECTED (1 << 6)
#define DESFIRE_SIM_PROBE_DISCOVERY_READ (1 << 7)

typedef struct {
    uint8_t version;
    uint8_t outcome;            // desfire_sim_probe_outcome_t
    uint8_t flags;
    uint8_t aid[3];
    uint8_t keyno;
    uint8_t algorithm;
    uint32_t candidate_id;
    uint32_t challenge_ms;      // GetTickCount at challenge
    uint32_t continuation_ms;   // GetTickCount at continuation
    uint8_t rndb[16];
    uint8_t continuation[32];
    uint8_t continuation_len;
    uint8_t last_command;
} PACKED desfire_sim_probe_result_t;

// Keys recovered for one application.
// keys[algo][keyno][0] is the found flag,  keys[algo][keyno][1..] the key itself.
// `algo` is a DesfireCryptoAlgorithm,  `keyno` the DESFire key number.
typedef struct {
    uint32_t aid;
    uint8_t keys[DESFIRE_MAX_ALGO_COUNT][DESFIRE_MAX_KEY_COUNT][DESFIRE_MAX_KEY_SIZE + 1];
} desfire_app_keys_t;

// `hf mfdes etest`: one CMD_HF_DESFIRE_SIM_TEST packet carries one operation.
typedef enum {
    DESFIRE_SIM_TEST_BEGIN = 0, // check the image, clear the random queue       -> no data
    DESFIRE_SIM_TEST_END,       // drop the state and the random queue           -> no data
    DESFIRE_SIM_TEST_SCAN,      // RF reset and activation                       -> iso14a_card_select_t
    DESFIRE_SIM_TEST_APDU,      // data: one command, native or ISO 7816 wrapped -> the answer
    DESFIRE_SIM_TEST_RANDOM,    // data: bytes the next RndB / random id draws use
    DESFIRE_SIM_TEST_FIELDOFF,  // RF reset: session dropped, image re-read      -> no data
    DESFIRE_SIM_TEST_STATE,     //                                               -> desfire_sim_test_state_t
    DESFIRE_SIM_TEST_PROBE_CONFIG, // data: desfire_sim_probe_cmd_t             -> no data
    DESFIRE_SIM_TEST_PROBE_RESULT, //                                          -> desfire_sim_probe_result_t
} desfire_sim_test_op_t;

// bytes the random queue holds, RANDOM answers PM3_EOVFLOW past this
#define DESFIRE_SIM_TEST_RANDOM_MAX 64

typedef struct {
    uint8_t op;                 // desfire_sim_test_op_t
    uint16_t len;
    uint8_t data[];
} PACKED desfire_sim_test_cmd_t;

typedef struct {
    uint8_t ready;              // activated and answering
    uint8_t authenticated;
    uint8_t auth_keyno;
    uint8_t aid[3];             // selected application, wire order
    uint8_t random_remaining;   // queued bytes not yet drawn
    uint8_t random_underflow;   // a draw wanted more than was queued, sticky
} PACKED desfire_sim_test_state_t;

#endif
