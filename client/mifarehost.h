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

#define MEM_CHUNK               1000000
#define NESTED_SECTOR_RETRY     10

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

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t * key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t * ResultKeys);
int mfCheckKeys (uint8_t blockNo, uint8_t keyType, uint8_t keycnt, uint8_t * keyBlock, uint64_t * key);
int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount);
int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount);

