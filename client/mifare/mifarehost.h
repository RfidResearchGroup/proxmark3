// Merlok, 2011, 2019
// people from mifare@nethemba.com, 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------
#ifndef __MIFARE_HOST_H
#define __MIFARE_HOST_H

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "proxmark3.h"  // time_t
#include "common.h"
#include "util.h"       // FILE_PATH_SIZE
#include "ui.h"         // PrintAndLog...
#include "crapto1/crapto1.h"
#include "crc16.h"
#include "protocols.h"
#include "mifare.h"
#include "mfkey.h"
#include "util_posix.h"  // msclock

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
    uint32_t nt;
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

extern char logHexFileName[FILE_PATH_SIZE];

extern int mfDarkside(uint8_t blockno, uint8_t key_type, uint64_t *key);
extern int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *ResultKeys, bool calibrate);
extern int mfCheckKeys(uint8_t blockNo, uint8_t keyType, bool clear_trace, uint8_t keycnt, uint8_t *keyBlock, uint64_t *key);
extern int mfCheckKeys_fast(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk,
                            uint8_t strategy, uint32_t size, uint8_t *keyBlock, sector_t *e_sector, bool use_flashmemory);
extern int mfKeyBrute(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint64_t *resultkey);

extern int mfReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *data);

extern int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount);
extern int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount);
extern int mfEmlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth);

extern int mfCSetUID(uint8_t *uid, uint8_t *atqa, uint8_t *sak, uint8_t *oldUID, uint8_t wipecard);
extern int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, uint8_t params);
extern int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params);

extern int mfTraceInit(uint8_t *tuid, uint8_t uidlen, uint8_t *atqa, uint8_t sak, bool wantSaveToEmlFile);
extern int mfTraceDecode(uint8_t *data_src, int len, bool wantSaveToEmlFile);

extern int isTraceCardEmpty(void);
extern int isBlockEmpty(int blockN);
extern int isBlockTrailer(int blockN);
extern int loadTraceCard(uint8_t *tuid, uint8_t uidlen);
extern int saveTraceCard(void);
extern int tryDecryptWord(uint32_t nt, uint32_t ar_enc, uint32_t at_enc, uint8_t *data, int len);

extern int detect_classic_prng(void);
extern int detect_classic_nackbug(bool verbose);
extern void detect_classic_magic(void);
extern void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len, bool isEncrypted);
#endif
