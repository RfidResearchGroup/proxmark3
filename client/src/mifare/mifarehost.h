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
    uint8_t keyA[6];
    uint8_t keyB[6];
    //uint8_t foundKey[2];
} icesector_t;

#define KEYS_IN_BLOCK   ((PM3_CMD_DATA_SIZE - 5) / 6)
#define KEYBLOCK_SIZE   (KEYS_IN_BLOCK * 6)
#define CANDIDATE_SIZE  (0xFFFF * 6)

int mfDarkside(uint8_t blockno, uint8_t key_type, uint64_t *key);
int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey, bool calibrate);
int mfStaticNested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey);
int mfCheckKeys(uint8_t blockNo, uint8_t keyType, bool clear_trace, uint8_t keycnt, uint8_t *keyBlock, uint64_t *key);
int mfCheckKeys_fast(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk,
                     uint8_t strategy, uint32_t size, uint8_t *keyBlock, sector_t *e_sector, bool use_flashmemory);

int mfCheckKeys_file(uint8_t *destfn, uint64_t *key);

int mfKeyBrute(uint8_t blockNo, uint8_t keyType, const uint8_t *key, uint64_t *resultkey);

int mfReadSector(uint8_t sectorNo, uint8_t keyType, const uint8_t *key, uint8_t *data);
int mfReadBlock(uint8_t blockNo, uint8_t keyType, const uint8_t *key, uint8_t *data);

int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth);

int mfCSetUID(uint8_t *uid, uint8_t uidlen, const uint8_t *atqa, const uint8_t *sak, uint8_t *old_uid, uint8_t *verifed_uid, uint8_t wipecard);
int mfCWipe(uint8_t *uid, const uint8_t *atqa, const uint8_t *sak);
int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, uint8_t params);
int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params);

int mfGen3UID(uint8_t *uid, uint8_t uidlen, uint8_t *oldUid);
int mfGen3Block(uint8_t *block, int blockLen, uint8_t *newBlock);
int mfGen3Freeze(void);

int mfG4GetBlock(uint8_t *pwd, uint8_t blockno, uint8_t *data, uint8_t workFlags);
int mfG4SetBlock(uint8_t *pwd, uint8_t blockno, uint8_t *data, uint8_t workFlags);

int tryDecryptWord(uint32_t nt, uint32_t ar_enc, uint32_t at_enc, uint8_t *data, int len);

int detect_classic_prng(void);
int detect_classic_nackbug(bool verbose);
int detect_mf_magic(bool is_mfc);
int detect_classic_static_nonce(void);
bool detect_mfc_ev1_signature(void);
int read_mfc_ev1_signature(uint8_t *signature);


void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len, bool isEncrypted);

// remove all sector trailers in a MFC dump
int convert_mfc_2_arr(uint8_t *in, uint16_t ilen, uint8_t *out, uint16_t *olen);
const char *vigik_get_service(uint16_t service_code);
int vigik_verify(mfc_vigik_t *d);
int vigik_annotate(mfc_vigik_t *d);
#endif
