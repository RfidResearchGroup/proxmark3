// Merlok, 2011, 2012
// people from mifare@nethemba.com, 2010
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// mifare commands
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h> 
#include <string.h>
#include "mifarehost.h"

// MIFARE

int compar_int(const void * a, const void * b) {
	return (*(uint64_t*)b - *(uint64_t*)a);
}

// Compare countKeys structure
int compar_special_int(const void * a, const void * b) {
	return (((countKeys *)b)->count - ((countKeys *)a)->count);
}

countKeys * uniqsort(uint64_t * possibleKeys, uint32_t size) {
	int i, j = 0;
	int count = 0;
	countKeys *our_counts;
	
	qsort(possibleKeys, size, sizeof (uint64_t), compar_int);
	
	our_counts = calloc(size, sizeof(countKeys));
	if (our_counts == NULL) {
		PrintAndLog("Memory allocation error for our_counts");
		return NULL;
	}
	
	for (i = 0; i < size; i++) {
        if (possibleKeys[i+1] == possibleKeys[i]) { 
			count++;
		} else {
			our_counts[j].key = possibleKeys[i];
			our_counts[j].count = count;
			j++;
			count=0;
		}
	}
	qsort(our_counts, j, sizeof(countKeys), compar_special_int);
	return (our_counts);
}

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t * key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t * resultKeys) 
{
	int i, m, len;
	uint8_t isEOF;
	uint32_t uid;
	fnVector * vector = NULL;
	countKeys	*ck;
	int lenVector = 0;
	UsbCommand * resp = NULL;
	
	memset(resultKeys, 0x00, 16 * 6);

	// flush queue
	while (WaitForResponseTimeout(CMD_ACK, 500) != NULL) ;
	
  UsbCommand c = {CMD_MIFARE_NESTED, {blockNo, keyType, trgBlockNo + trgKeyType * 0x100}};
	memcpy(c.d.asBytes, key, 6);
  SendCommand(&c);

	PrintAndLog("\n");

	// wait cycle
	while (true) {
		printf(".");
		if (ukbhit()) {
			getchar();
			printf("\naborted via keyboard!\n");
			break;
		}

		resp = WaitForResponseTimeout(CMD_ACK, 1500);

		if (resp != NULL) {
			isEOF  = resp->arg[0] & 0xff;

			if (isEOF) break;
			
			len = resp->arg[1] & 0xff;
			if (len == 0) continue;
			
			memcpy(&uid, resp->d.asBytes, 4); 
			PrintAndLog("uid:%08x len=%d trgbl=%d trgkey=%x", uid, len, resp->arg[2] & 0xff, (resp->arg[2] >> 8) & 0xff);
			vector = (fnVector *) realloc((void *)vector, (lenVector + len) * sizeof(fnVector) + 200);
			if (vector == NULL) {
				PrintAndLog("Memory allocation error for fnVector. len: %d bytes: %d", lenVector + len, (lenVector + len) * sizeof(fnVector)); 
				break;
			}
			
			for (i = 0; i < len; i++) {
				vector[lenVector + i].blockNo = resp->arg[2] & 0xff;
				vector[lenVector + i].keyType = (resp->arg[2] >> 8) & 0xff;
				vector[lenVector + i].uid = uid;

				memcpy(&vector[lenVector + i].nt,  (void *)(resp->d.asBytes + 8 + i * 8 + 0), 4);
				memcpy(&vector[lenVector + i].ks1, (void *)(resp->d.asBytes + 8 + i * 8 + 4), 4);
			}

			lenVector += len;
		}
	}
	
	if (!lenVector) {
		PrintAndLog("Got 0 keys from proxmark."); 
		return 1;
	}
	printf("------------------------------------------------------------------\n");
	
	// calc keys
	struct Crypto1State* revstate = NULL;
	struct Crypto1State* revstate_start = NULL;
	uint64_t lfsr;
	int kcount = 0;
	pKeys		*pk;
	
	if ((pk = (void *) malloc(sizeof(pKeys))) == NULL) return 1;
	memset(pk, 0x00, sizeof(pKeys));
	
	for (m = 0; m < lenVector; m++) {
		// And finally recover the first 32 bits of the key
		revstate = lfsr_recovery32(vector[m].ks1, vector[m].nt ^ vector[m].uid);
		if (revstate_start == NULL) revstate_start = revstate;
	
		while ((revstate->odd != 0x0) || (revstate->even != 0x0)) {
			lfsr_rollback_word(revstate, vector[m].nt ^ vector[m].uid, 0);
			crypto1_get_lfsr(revstate, &lfsr);

			// Allocate a new space for keys
			if (((kcount % MEM_CHUNK) == 0) || (kcount >= pk->size)) {
				pk->size += MEM_CHUNK;
//fprintf(stdout, "New chunk by %d, sizeof %d\n", kcount, pk->size * sizeof(uint64_t));
				pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t));
				if (pk->possibleKeys == NULL) {
					PrintAndLog("Memory allocation error for pk->possibleKeys"); 
					return 1;
				}
			}
			pk->possibleKeys[kcount] = lfsr;
			kcount++;
			revstate++;
		}
	free(revstate_start);
	revstate_start = NULL;

	}
	
	// Truncate
	if (kcount != 0) {
		pk->size = --kcount;
		if ((pk->possibleKeys = (uint64_t *) realloc((void *)pk->possibleKeys, pk->size * sizeof(uint64_t))) == NULL) {
			PrintAndLog("Memory allocation error for pk->possibleKeys"); 
			return 1;
		}		
	}

	PrintAndLog("Total keys count:%d", kcount);
	ck = uniqsort(pk->possibleKeys, pk->size);

	// fill key array
	for (i = 0; i < 16 ; i++) {
		num_to_bytes(ck[i].key, 6, (uint8_t*)(resultKeys + i * 6));
	}

	// finalize
	free(pk->possibleKeys);
	free(pk);
	free(ck);
	free(vector);

	return 0;
}

int mfCheckKeys (uint8_t blockNo, uint8_t keyType, uint8_t keycnt, uint8_t * keyBlock, uint64_t * key){
	*key = 0;

  UsbCommand c = {CMD_MIFARE_CHKKEYS, {blockNo, keyType, keycnt}};
	memcpy(c.d.asBytes, keyBlock, 6 * keycnt);

  SendCommand(&c);

	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 3000);

	if (resp == NULL) return 1;
	if ((resp->arg[0] & 0xff) != 0x01) return 2;
	*key = bytes_to_num(resp->d.asBytes, 6);
	return 0;
}

// EMULATOR

int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMGET, {blockNum, blocksCount, 0}};
 
	SendCommand(&c);

	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);

	if (resp == NULL) return 1;
	memcpy(data, resp->d.asBytes, blocksCount * 16); 
	return 0;
}

int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMSET, {blockNum, blocksCount, 0}};
	memcpy(c.d.asBytes, data, blocksCount * 16); 
	SendCommand(&c);
	return 0;
}

// "MAGIC" CARD

int mfCSetUID(uint8_t *uid, uint8_t *oldUID, int wantWipe) {
	uint8_t block0[16];
	memset(block0, 0, 16);
	memcpy(block0, uid, 4); 
	block0[4] = block0[0]^block0[1]^block0[2]^block0[3]; // Mifare UID BCC
	// mifare classic SAK(byte 5) and ATQA(byte 6 and 7)
	block0[5] = 0x88;
	block0[6] = 0x04;
	block0[7] = 0x00;
	
	return mfCSetBlock(0, block0, oldUID, wantWipe, CSETBLOCK_SINGLE_OPER);
}

int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, int wantWipe, uint8_t params) {
	uint8_t isOK = 0;

	UsbCommand c = {CMD_MIFARE_EML_CSETBLOCK, {wantWipe, params & (0xFE | (uid == NULL ? 0:1)), blockNo}};
	memcpy(c.d.asBytes, data, 16); 
	SendCommand(&c);

	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);

	if (resp != NULL) {
		isOK  = resp->arg[0] & 0xff;
		if (uid != NULL) memcpy(uid, resp->d.asBytes, 4); 
		if (!isOK) return 2;
	} else {
		PrintAndLog("Command execute timeout");
		return 1;
	}
	return 0;
}

int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params) {
	uint8_t isOK = 0;

	UsbCommand c = {CMD_MIFARE_EML_CGETBLOCK, {params, 0, blockNo}};
	SendCommand(&c);

	UsbCommand * resp = WaitForResponseTimeout(CMD_ACK, 1500);

	if (resp != NULL) {
		isOK  = resp->arg[0] & 0xff;
		memcpy(data, resp->d.asBytes, 16); 
		if (!isOK) return 2;
	} else {
		PrintAndLog("Command execute timeout");
		return 1;
	}
	return 0;
}

// SNIFFER

// constants
static uint8_t trailerAccessBytes[4] = {0x08, 0x77, 0x8F, 0x00};

// variables
char logHexFileName[200] = {0x00};
static uint8_t traceCard[4096] = {0x00};
static char traceFileName[20];
static int traceState = TRACE_IDLE;
static uint8_t traceCurBlock = 0;
static uint8_t traceCurKey = 0;

struct Crypto1State *traceCrypto1 = NULL;

struct Crypto1State *revstate;
uint64_t lfsr;
uint32_t ks2;
uint32_t ks3;

uint32_t uid;     // serial number
uint32_t nt;      // tag challenge
uint32_t nt_par; 
uint32_t nr_enc;  // encrypted reader challenge
uint32_t ar_enc;  // encrypted reader response
uint32_t nr_ar_par; 
uint32_t at_enc;  // encrypted tag response
uint32_t at_par; 

int isTraceCardEmpty(void) {
	return ((traceCard[0] == 0) && (traceCard[1] == 0) && (traceCard[2] == 0) && (traceCard[3] == 0));
}

int isBlockEmpty(int blockN) {
	for (int i = 0; i < 16; i++) 
		if (traceCard[blockN * 16 + i] != 0) return 0;

	return 1;
}

int isBlockTrailer(int blockN) {
 return ((blockN & 0x03) == 0x03);
}

int loadTraceCard(uint8_t *tuid) {
	FILE * f;
	char buf[64];
	uint8_t buf8[64];
	int i, blockNum;
	
	if (!isTraceCardEmpty()) saveTraceCard();
	memset(traceCard, 0x00, 4096);
	memcpy(traceCard, tuid + 3, 4);
	FillFileNameByUID(traceFileName, tuid, ".eml", 7);

	f = fopen(traceFileName, "r");
	if (!f) return 1;
	
	blockNum = 0;
	while(!feof(f)){
		memset(buf, 0, sizeof(buf));
		fgets(buf, sizeof(buf), f);

		if (strlen(buf) < 32){
			if (feof(f)) break;
			PrintAndLog("File content error. Block data must include 32 HEX symbols");
			return 2;
		}
		for (i = 0; i < 32; i += 2)
			sscanf(&buf[i], "%02x", (unsigned int *)&buf8[i / 2]);

		memcpy(traceCard + blockNum * 16, buf8, 16);

		blockNum++;
	}
	fclose(f);

	return 0;
}

int saveTraceCard(void) {
	FILE * f;
	
	if ((!strlen(traceFileName)) || (isTraceCardEmpty())) return 0;
	
	f = fopen(traceFileName, "w+");
	for (int i = 0; i < 64; i++) {  // blocks
		for (int j = 0; j < 16; j++)  // bytes
			fprintf(f, "%02x", *(traceCard + i * 16 + j)); 
		fprintf(f,"\n");
	}
	fclose(f);

	return 0;
}

int mfTraceInit(uint8_t *tuid, uint8_t *atqa, uint8_t sak, bool wantSaveToEmlFile) {

	if (traceCrypto1) crypto1_destroy(traceCrypto1);
	traceCrypto1 = NULL;

	if (wantSaveToEmlFile) loadTraceCard(tuid);
	traceCard[4] = traceCard[0] ^ traceCard[1] ^ traceCard[2] ^ traceCard[3];
	traceCard[5] = sak;
	memcpy(&traceCard[6], atqa, 2);
	traceCurBlock = 0;
	uid = bytes_to_num(tuid + 3, 4);
	
	traceState = TRACE_IDLE;

	return 0;
}

void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len, bool isEncrypted){
	uint8_t	bt = 0;
	int i;
	
	if (len != 1) {
		for (i = 0; i < len; i++)
			data[i] = crypto1_byte(pcs, 0x00, isEncrypted) ^ data[i];
	} else {
		bt = 0;
		for (i = 0; i < 4; i++)
			bt |= (crypto1_bit(pcs, 0, isEncrypted) ^ BIT(data[0], i)) << i;
				
		data[0] = bt;
	}
	return;
}


int mfTraceDecode(uint8_t *data_src, int len, uint32_t parity, bool wantSaveToEmlFile) {
	uint8_t data[64];

	if (traceState == TRACE_ERROR) return 1;
	if (len > 64) {
		traceState = TRACE_ERROR;
		return 1;
	}
	
	memcpy(data, data_src, len);
	if ((traceCrypto1) && ((traceState == TRACE_IDLE) || (traceState > TRACE_AUTH_OK))) {
		mf_crypto1_decrypt(traceCrypto1, data, len, 0);
		PrintAndLog("dec> %s", sprint_hex(data, len));
		AddLogHex(logHexFileName, "dec> ", data, len); 
	}
	
	switch (traceState) {
	case TRACE_IDLE: 
		// check packet crc16!
		if ((len >= 4) && (!CheckCrc14443(CRC_14443_A, data, len))) {
			PrintAndLog("dec> CRC ERROR!!!");
			AddLogLine(logHexFileName, "dec> ", "CRC ERROR!!!"); 
			traceState = TRACE_ERROR;  // do not decrypt the next commands
			return 1;
		}
		
		// AUTHENTICATION
		if ((len ==4) && ((data[0] == 0x60) || (data[0] == 0x61))) {
			traceState = TRACE_AUTH1;
			traceCurBlock = data[1];
			traceCurKey = data[0] == 60 ? 1:0;
			return 0;
		}

		// READ
		if ((len ==4) && ((data[0] == 0x30))) {
			traceState = TRACE_READ_DATA;
			traceCurBlock = data[1];
			return 0;
		}

		// WRITE
		if ((len ==4) && ((data[0] == 0xA0))) {
			traceState = TRACE_WRITE_OK;
			traceCurBlock = data[1];
			return 0;
		}

		// HALT
		if ((len ==4) && ((data[0] == 0x50) && (data[1] == 0x00))) {
			traceState = TRACE_ERROR;  // do not decrypt the next commands
			return 0;
		}
		
		return 0;
	break;
	
	case TRACE_READ_DATA: 
		if (len == 18) {
			traceState = TRACE_IDLE;

			if (isBlockTrailer(traceCurBlock)) {
				memcpy(traceCard + traceCurBlock * 16 + 6, data + 6, 4);
			} else {
				memcpy(traceCard + traceCurBlock * 16, data, 16);
			}
			if (wantSaveToEmlFile) saveTraceCard();
			return 0;
		} else {
			traceState = TRACE_ERROR;
			return 1;
		}
	break;

	case TRACE_WRITE_OK: 
		if ((len == 1) && (data[0] = 0x0a)) {
			traceState = TRACE_WRITE_DATA;

			return 0;
		} else {
			traceState = TRACE_ERROR;
			return 1;
		}
	break;

	case TRACE_WRITE_DATA: 
		if (len == 18) {
			traceState = TRACE_IDLE;

			memcpy(traceCard + traceCurBlock * 16, data, 16);
			if (wantSaveToEmlFile) saveTraceCard();
			return 0;
		} else {
			traceState = TRACE_ERROR;
			return 1;
		}
	break;

	case TRACE_AUTH1: 
		if (len == 4) {
			traceState = TRACE_AUTH2;

			nt = bytes_to_num(data, 4);
			nt_par = parity;
			return 0;
		} else {
			traceState = TRACE_ERROR;
			return 1;
		}
	break;

	case TRACE_AUTH2: 
		if (len == 8) {
			traceState = TRACE_AUTH_OK;

			nr_enc = bytes_to_num(data, 4);
			ar_enc = bytes_to_num(data + 4, 4);
			nr_ar_par = parity;
			return 0;
		} else {
			traceState = TRACE_ERROR;
			return 1;
		}
	break;

	case TRACE_AUTH_OK: 
		if (len ==4) {
			traceState = TRACE_IDLE;

			at_enc = bytes_to_num(data, 4);
			at_par = parity;
			
			//  decode key here)
			if (!traceCrypto1) {
				ks2 = ar_enc ^ prng_successor(nt, 64);
				ks3 = at_enc ^ prng_successor(nt, 96);
				revstate = lfsr_recovery64(ks2, ks3);
				lfsr_rollback_word(revstate, 0, 0);
				lfsr_rollback_word(revstate, 0, 0);
				lfsr_rollback_word(revstate, nr_enc, 1);
				lfsr_rollback_word(revstate, uid ^ nt, 0);
			}else{
				ks2 = ar_enc ^ prng_successor(nt, 64);
				ks3 = at_enc ^ prng_successor(nt, 96);
				revstate = lfsr_recovery64(ks2, ks3);
				lfsr_rollback_word(revstate, 0, 0);
				lfsr_rollback_word(revstate, 0, 0);
				lfsr_rollback_word(revstate, nr_enc, 1);
				lfsr_rollback_word(revstate, uid ^ nt, 0);
			}
			crypto1_get_lfsr(revstate, &lfsr);
			printf("key> %x%x\n", (unsigned int)((lfsr & 0xFFFFFFFF00000000) >> 32), (unsigned int)(lfsr & 0xFFFFFFFF));
			AddLogUint64(logHexFileName, "key> ", lfsr); 
			
			int blockShift = ((traceCurBlock & 0xFC) + 3) * 16;
			if (isBlockEmpty((traceCurBlock & 0xFC) + 3)) memcpy(traceCard + blockShift + 6, trailerAccessBytes, 4);
			
			if (traceCurKey) {
				num_to_bytes(lfsr, 6, traceCard + blockShift + 10);
			} else {
				num_to_bytes(lfsr, 6, traceCard + blockShift);
			}
			if (wantSaveToEmlFile) saveTraceCard();

			if (traceCrypto1) {
				crypto1_destroy(traceCrypto1);
			}
			
			// set cryptosystem state
			traceCrypto1 = lfsr_recovery64(ks2, ks3);
			
//	nt = crypto1_word(traceCrypto1, nt ^ uid, 1) ^ nt;

	/*	traceCrypto1 = crypto1_create(lfsr); // key in lfsr
		crypto1_word(traceCrypto1, nt ^ uid, 0);
		crypto1_word(traceCrypto1, ar, 1);
		crypto1_word(traceCrypto1, 0, 0);
		crypto1_word(traceCrypto1, 0, 0);*/
	
			return 0;
		} else {
			traceState = TRACE_ERROR;
			return 1;
		}
	break;

	default: 
		traceState = TRACE_ERROR;
		return 1;
	}

	return 0;
}
