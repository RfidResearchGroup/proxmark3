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
#include "common.h"
#include "cmdmain.h"
#include "ui.h"
#include "data.h"
#include "proxusb.h"
#include "util.h"
#include "nonce2key/nonce2key.h"
#include "nonce2key/crapto1.h"
#include "iso14443crc.h"

#define MEM_CHUNK               1000000
#define NESTED_SECTOR_RETRY     10

// mfCSetBlock work flags
#define CSETBLOCK_UID 					0x01
#define CSETBLOCK_WUPC					0x02
#define CSETBLOCK_HALT					0x04
#define CSETBLOCK_INIT_FIELD		0x08
#define CSETBLOCK_RESET_FIELD		0x10
#define CSETBLOCK_SINGLE_OPER		0x1F

// mifare tracer flags
#define TRACE_IDLE		 					0x00
#define TRACE_AUTH1		 					0x01
#define TRACE_AUTH2		 					0x02
#define TRACE_AUTH_OK	 					0x03
#define TRACE_READ_DATA 				0x04
#define TRACE_WRITE_OK					0x05
#define TRACE_WRITE_DATA				0x06

#define TRACE_ERROR		 					0xFF

typedef struct fnVector { uint8_t blockNo, keyType; uint32_t uid, nt, ks1; } fnVector;

typedef struct {
	uint64_t Key[2];
	int foundKey[2];
} sector;
 
typedef struct {
        uint64_t        *possibleKeys;
        uint32_t        size;
} pKeys;

typedef struct {
        uint64_t        key;
        int             count;
} countKeys;

extern char logHexFileName[200];

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t * key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t * ResultKeys);
int mfCheckKeys (uint8_t blockNo, uint8_t keyType, uint8_t keycnt, uint8_t * keyBlock, uint64_t * key);

int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount);

int mfCSetUID(uint8_t *uid, uint8_t *oldUID, int wantWipe);
int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, int wantWipe, uint8_t params);
int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params);

int mfTraceInit(uint8_t *tuid, uint8_t *atqa, uint8_t sak, bool wantSaveToEmlFile);
int mfTraceDecode(uint8_t *data_src, int len, uint32_t parity, bool wantSaveToEmlFile);

int isTraceCardEmpty(void);
int isBlockEmpty(int blockN);
int isBlockTrailer(int blockN);
int loadTraceCard(uint8_t *tuid);
int saveTraceCard(void);
