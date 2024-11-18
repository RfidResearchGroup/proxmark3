//-----------------------------------------------------------------------------
// Borrowed initially from https://nethemba.com/tag/darkside-attack/
// Copyright (C) mifare@nethemba.com, 2010
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
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------
#ifndef __MIFARE_HOST_H
#define __MIFARE_HOST_H

#include "common.h"

#include "util.h"       // FILE_PATH_SIZE
#include "mifaredefault.h"      // consts
#include "protocol_vigik.h"

#define MIFARE_SECTOR_RETRY     10

// mifare tracer flags
#define TRACE_IDLE              0x00
#define TRACE_AUTH1             0x01
#define TRACE_AUTH2             0x02
#define TRACE_AUTH_OK           0x03
#define TRACE_READ_DATA         0x04
#define TRACE_WRITE_OK          0x05
#define TRACE_WRITE_DATA        0x06
#define TRACE_ERROR             0xFF

typedef struct {
    union {
        struct Crypto1State *slhead;
        uint64_t *keyhead;
    } head;
    union {
        struct Crypto1State *sltail;
        uint64_t *keytail;
    } tail;
    uint32_t len;
    uint32_t uid;
    uint32_t blockNo;
    uint32_t keyType;
    uint32_t nt_enc;
    uint32_t ks1;
} StateList_t;

typedef struct {
    uint64_t Key[2];
    uint8_t foundKey[2];
} sector_t;

typedef struct {
    uint8_t keyA[MIFARE_KEY_SIZE];
    uint8_t keyB[MIFARE_KEY_SIZE];
    //uint8_t foundKey[2];
} icesector_t;

#define KEYS_IN_BLOCK   ((PM3_CMD_DATA_SIZE - 5) / MIFARE_KEY_SIZE)
#define KEYBLOCK_SIZE   (KEYS_IN_BLOCK * MIFARE_KEY_SIZE)
#define CANDIDATE_SIZE  (0xFFFF * MIFARE_KEY_SIZE)

int mf_dark_side(uint8_t blockno, uint8_t key_type, uint64_t *key);
int mf_nested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey, bool calibrate);
int mf_static_nested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey);
int mf_check_keys(uint8_t blockNo, uint8_t keyType, bool clear_trace, uint8_t keycnt, uint8_t *keyBlock, uint64_t *key);
int mf_check_keys_fast(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk,
                       uint8_t strategy, uint32_t size, uint8_t *keyBlock, sector_t *e_sector,
                       bool use_flashmemory, bool verbose);
int mf_check_keys_fast_ex(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk, uint8_t strategy,
                          uint32_t size, uint8_t *keyBlock, sector_t *e_sector, bool use_flashmemory,
                          bool verbose, bool quiet, uint16_t singleSectorParams);

int mf_check_keys_file(uint8_t *destfn, uint64_t *key);

int mf_key_brute(uint8_t blockNo, uint8_t keyType, const uint8_t *key, uint64_t *resultkey);

int mf_read_sector(uint8_t sectorNo, uint8_t keyType, const uint8_t *key, uint8_t *data);
int mf_read_block(uint8_t blockNo, uint8_t keyType, const uint8_t *key, uint8_t *data);

int mf_write_block(uint8_t blockno, uint8_t keyType, const uint8_t *key, uint8_t *block);
int mf_write_sector(uint8_t sectorNo, uint8_t keyType, const uint8_t *key, uint8_t *sector);

int mf_eml_get_mem(uint8_t *data, int blockNum, int blocksCount);
int mf_elm_set_mem(uint8_t *data, int blockNum, int blocksCount);
int mf_eml_set_mem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth);

int mf_chinese_set_uid(uint8_t *uid, uint8_t uidlen, const uint8_t *atqa, const uint8_t *sak, uint8_t *old_uid, uint8_t *verifed_uid, uint8_t wipecard, uint8_t gdm);
int mf_chinese_wipe(uint8_t *uid, const uint8_t *atqa, const uint8_t *sak, uint8_t gdm);
int mf_chinese_set_block(uint8_t blockNo, uint8_t *data, uint8_t *uid, uint8_t params);
int mf_chinese_get_block(uint8_t blockNo, uint8_t *data, uint8_t params);

int mf_chinese_gen_3_uid(uint8_t *uid, uint8_t uidlen, uint8_t *oldUid);
int mf_chinese_gen_3_block(uint8_t *block, int blockLen, uint8_t *newBlock);
int mf_chinese_gen_3_freeze(void);

int try_decrypt_word(uint32_t nt, uint32_t ar_enc, uint32_t at_enc, uint8_t *data, int len);

int detect_classic_prng(void);
int detect_classic_nackbug(bool verbose);
uint16_t detect_mf_magic(bool is_mfc, uint8_t key_type, uint64_t key);
int detect_classic_static_nonce(void);
int detect_classic_static_encrypted_nonce_ex(uint8_t block_no, uint8_t key_type, uint8_t *key, uint8_t block_no_nested, uint8_t key_type_nested, uint8_t *key_nested, uint8_t nr_nested, bool reset, bool hardreset, bool addread, bool addauth, bool incblk2, bool corruptnrar, bool corruptnrarparity, bool verbose);
int detect_classic_static_encrypted_nonce(uint8_t block_no, uint8_t key_type, uint8_t *key);
bool detect_mfc_ev1_signature(void);
int read_mfc_ev1_signature(uint8_t *signature);


void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len, bool isEncrypted);

// remove all sector trailers in a MFC dump
int convert_mfc_2_arr(uint8_t *in, uint16_t ilen, uint8_t *out, uint16_t *olen);
const char *vigik_get_service(uint16_t service_code);
int vigik_verify(mfc_vigik_t *d);
int vigik_annotate(mfc_vigik_t *d);
#endif
