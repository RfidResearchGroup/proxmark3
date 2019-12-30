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

#include "common.h"

#include "util.h"       // FILE_PATH_SIZE

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

extern char logHexFileName[FILE_PATH_SIZE];
#define KEYS_IN_BLOCK   ((PM3_CMD_DATA_SIZE - 4) / 6)
#define KEYBLOCK_SIZE   (KEYS_IN_BLOCK * 6)
#define CANDIDATE_SIZE  (0xFFFF * 6)

int mfDarkside(uint8_t blockno, uint8_t key_type, uint64_t *key);
int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t *resultKey, bool calibrate);
int mfCheckKeys(uint8_t blockNo, uint8_t keyType, bool clear_trace, uint8_t keycnt, uint8_t *keyBlock, uint64_t *key);
int mfCheckKeys_fast(uint8_t sectorsCnt, uint8_t firstChunk, uint8_t lastChunk,
                     uint8_t strategy, uint32_t size, uint8_t *keyBlock, sector_t *e_sector, bool use_flashmemory);
int mfKeyBrute(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint64_t *resultkey);

int mfReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *data);

int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth);

int mfCSetUID(uint8_t *uid, uint8_t *atqa, uint8_t *sak, uint8_t *oldUID, uint8_t wipecard);
int mfCWipe(uint8_t *uid, uint8_t *atqa, uint8_t *sak);
int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, uint8_t params);
int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params);

int mfTraceInit(uint8_t *tuid, uint8_t uidlen, uint8_t *atqa, uint8_t sak, bool wantSaveToEmlFile);
int mfTraceDecode(uint8_t *data_src, int len, bool wantSaveToEmlFile);

int isTraceCardEmpty(void);
int isBlockEmpty(int blockN);
int isBlockTrailer(int blockN);
int loadTraceCard(uint8_t *tuid, uint8_t uidlen);
int saveTraceCard(void);
int tryDecryptWord(uint32_t nt, uint32_t ar_enc, uint32_t at_enc, uint8_t *data, int len);

int detect_classic_prng(void);
int detect_classic_nackbug(bool verbose);
void detect_classic_magic(void);
int detect_classic_static_nonce(void);
void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len, bool isEncrypted);
#endif
