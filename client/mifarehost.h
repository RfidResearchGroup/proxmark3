// Merlok, 2011
// people from mifare@nethemba.com, 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include "proxmark3.h"
//#include "radixsort.h"
#include <time.h>
#include "common.h"
#include "cmdmain.h"
#include "ui.h"
#include "data.h"
#include "util.h"
//#include "nonce2key/nonce2key.h"
#include "nonce2key/crapto1.h"
#include "iso14443crc.h"
#include "protocols.h"

#define NESTED_SECTOR_RETRY     10

// mifare tracer flags
#define TRACE_IDLE		 		0x00
#define TRACE_AUTH1		 		0x01
#define TRACE_AUTH2		 		0x02
#define TRACE_AUTH_OK	 		0x03
#define TRACE_READ_DATA 		0x04
#define TRACE_WRITE_OK			0x05
#define TRACE_WRITE_DATA		0x06
#define TRACE_ERROR		 		0xFF

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
	int foundKey[2];
} sector;
 
extern int compar_int(const void * a, const void * b);
extern char logHexFileName[FILE_PATH_SIZE];

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t * key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t * ResultKeys, bool calibrate);
int mfCheckKeys (uint8_t blockNo, uint8_t keyType, bool clear_trace, uint8_t keycnt, uint8_t * keyBlock, uint64_t * key);
int mfKeyBrute(uint8_t blockNo, uint8_t keyType, uint8_t *key, uint64_t *resultkey);

int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int blockBtWidth);

int mfCSetUID(uint8_t *uid, uint8_t *atqa, uint8_t *sak, uint8_t *oldUID, uint8_t wipecard);
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
