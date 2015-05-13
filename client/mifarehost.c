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
#include <pthread.h>
#include "mifarehost.h"
#include "proxmark3.h"

#define llx PRIx64

// MIFARE
int compar_int(const void * a, const void * b) {
	// didn't work: (the result is truncated to 32 bits)
	//return (*(uint64_t*)b - *(uint64_t*)a);

	// better:
	if (*(uint64_t*)b == *(uint64_t*)a) return 0;
	else if (*(uint64_t*)b > *(uint64_t*)a) return 1;
	else return -1;
}

// Compare 16 Bits out of cryptostate
int Compare16Bits(const void * a, const void * b) {
	if ((*(uint64_t*)b & 0x00ff000000ff0000) == (*(uint64_t*)a & 0x00ff000000ff0000)) return 0;
	else if ((*(uint64_t*)b & 0x00ff000000ff0000) > (*(uint64_t*)a & 0x00ff000000ff0000)) return 1;
	else return -1;
}

typedef 
	struct {
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


// wrapper function for multi-threaded lfsr_recovery32
void* nested_worker_thread(void *arg)
{
	struct Crypto1State *p1;
	StateList_t *statelist = arg;

	statelist->head.slhead = lfsr_recovery32(statelist->ks1, statelist->nt ^ statelist->uid);
	for (p1 = statelist->head.slhead; *(uint64_t *)p1 != 0; p1++);
	statelist->len = p1 - statelist->head.slhead;
	statelist->tail.sltail = --p1;
	qsort(statelist->head.slhead, statelist->len, sizeof(uint64_t), Compare16Bits);
	
	return statelist->head.slhead;
}

int mfnested(uint8_t blockNo, uint8_t keyType, uint8_t * key, uint8_t trgBlockNo, uint8_t trgKeyType, uint8_t * resultKey, bool calibrate) 
{
	uint16_t i, len;
	uint32_t uid;
	UsbCommand resp;
	StateList_t statelists[2];
	struct Crypto1State *p1, *p2, *p3, *p4;
	
	// flush queue
	WaitForResponseTimeout(CMD_ACK,NULL,100);
	
	UsbCommand c = {CMD_MIFARE_NESTED, {blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, calibrate}};
	memcpy(c.d.asBytes, key, 6);
	SendCommand(&c);

	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		len = resp.arg[1];
		if (len == 2) {	
			memcpy(&uid, resp.d.asBytes, 4);
			PrintAndLog("uid:%08x len=%d trgbl=%d trgkey=%x", uid, len, (uint16_t)resp.arg[2] & 0xff, (uint16_t)resp.arg[2] >> 8);
			
			for (i = 0; i < 2; i++) {
				statelists[i].blockNo = resp.arg[2] & 0xff;
				statelists[i].keyType = (resp.arg[2] >> 8) & 0xff;
				statelists[i].uid = uid;

				memcpy(&statelists[i].nt,  (void *)(resp.d.asBytes + 4 + i * 8 + 0), 4);
				memcpy(&statelists[i].ks1, (void *)(resp.d.asBytes + 4 + i * 8 + 4), 4);
			}
		}
		else {
			PrintAndLog("Got 0 keys from proxmark."); 
			return 1;
		}
	}
	
	// calc keys
	
	pthread_t thread_id[2];
		
	// create and run worker threads
	for (i = 0; i < 2; i++) {
		pthread_create(thread_id + i, NULL, nested_worker_thread, &statelists[i]);
	}
	
	// wait for threads to terminate:
	for (i = 0; i < 2; i++) {
		pthread_join(thread_id[i], (void*)&statelists[i].head.slhead);
	}


	// the first 16 Bits of the cryptostate already contain part of our key.
	// Create the intersection of the two lists based on these 16 Bits and
	// roll back the cryptostate
	p1 = p3 = statelists[0].head.slhead; 
	p2 = p4 = statelists[1].head.slhead;
	while (p1 <= statelists[0].tail.sltail && p2 <= statelists[1].tail.sltail) {
		if (Compare16Bits(p1, p2) == 0) {
			struct Crypto1State savestate, *savep = &savestate;
			savestate = *p1;
			while(Compare16Bits(p1, savep) == 0 && p1 <= statelists[0].tail.sltail) {
				*p3 = *p1;
				lfsr_rollback_word(p3, statelists[0].nt ^ statelists[0].uid, 0);
				p3++;
				p1++;
			}
			savestate = *p2;
			while(Compare16Bits(p2, savep) == 0 && p2 <= statelists[1].tail.sltail) {
				*p4 = *p2;
				lfsr_rollback_word(p4, statelists[1].nt ^ statelists[1].uid, 0);
				p4++;
				p2++;
			}
		}
		else {
			while (Compare16Bits(p1, p2) == -1) p1++;
			while (Compare16Bits(p1, p2) == 1) p2++;
		}
	}
	p3->even = 0; p3->odd = 0;
	p4->even = 0; p4->odd = 0;
	statelists[0].len = p3 - statelists[0].head.slhead;
	statelists[1].len = p4 - statelists[1].head.slhead;
	statelists[0].tail.sltail=--p3;
	statelists[1].tail.sltail=--p4;

	// the statelists now contain possible keys. The key we are searching for must be in the
	// intersection of both lists. Create the intersection:
	qsort(statelists[0].head.keyhead, statelists[0].len, sizeof(uint64_t), compar_int);
	qsort(statelists[1].head.keyhead, statelists[1].len, sizeof(uint64_t), compar_int);

	uint64_t *p5, *p6, *p7;
	p5 = p7 = statelists[0].head.keyhead; 
	p6 = statelists[1].head.keyhead;
	while (p5 <= statelists[0].tail.keytail && p6 <= statelists[1].tail.keytail) {
		if (compar_int(p5, p6) == 0) {
			*p7++ = *p5++;
			p6++;
		}
		else {
			while (compar_int(p5, p6) == -1) p5++;
			while (compar_int(p5, p6) == 1) p6++;
		}
	}
	statelists[0].len = p7 - statelists[0].head.keyhead;
	statelists[0].tail.keytail=--p7;

	memset(resultKey, 0, 6);
	// The list may still contain several key candidates. Test each of them with mfCheckKeys
	for (i = 0; i < statelists[0].len; i++) {
		uint8_t keyBlock[6];
		uint64_t key64;
		crypto1_get_lfsr(statelists[0].head.slhead + i, &key64);
		num_to_bytes(key64, 6, keyBlock);
		key64 = 0;
		if (!mfCheckKeys(statelists[0].blockNo, statelists[0].keyType, 1, keyBlock, &key64)) {
			num_to_bytes(key64, 6, resultKey);
			break;
		}
	}
	
	free(statelists[0].head.slhead);
	free(statelists[1].head.slhead);
	
	return 0;
}

int mfCheckKeys (uint8_t blockNo, uint8_t keyType, uint8_t keycnt, uint8_t * keyBlock, uint64_t * key){

	*key = 0;

	UsbCommand c = {CMD_MIFARE_CHKKEYS, {blockNo, keyType, keycnt}};
	memcpy(c.d.asBytes, keyBlock, 6 * keycnt);
	SendCommand(&c);

	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK,&resp,3000)) return 1;
	if ((resp.arg[0] & 0xff) != 0x01) return 2;
	*key = bytes_to_num(resp.d.asBytes, 6);
	return 0;
}

// EMULATOR

int mfEmlGetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMGET, {blockNum, blocksCount, 0}};
 	SendCommand(&c);

	UsbCommand resp;
	if (!WaitForResponseTimeout(CMD_ACK,&resp,1500)) return 1;
	memcpy(data, resp.d.asBytes, blocksCount * 16);
	return 0;
}

int mfEmlSetMem(uint8_t *data, int blockNum, int blocksCount) {
	UsbCommand c = {CMD_MIFARE_EML_MEMSET, {blockNum, blocksCount, 0}};
	memcpy(c.d.asBytes, data, blocksCount * 16); 
	SendCommand(&c);
	return 0;
}

// "MAGIC" CARD

int mfCSetUID(uint8_t *uid, uint8_t *atqa, uint8_t *sak, uint8_t *oldUID, bool wantWipe) {
	uint8_t oldblock0[16] = {0x00};
	uint8_t block0[16] = {0x00};

	int old = mfCGetBlock(0, oldblock0, CSETBLOCK_SINGLE_OPER);
	if (old == 0) {
		memcpy(block0, oldblock0, 16);
		PrintAndLog("old block 0:  %s", sprint_hex(block0,16));
	} else {
		PrintAndLog("Couldn't get old data. Will write over the last bytes of Block 0.");
	}

	// fill in the new values
	// UID
	memcpy(block0, uid, 4); 
	// Mifare UID BCC
	block0[4] = block0[0]^block0[1]^block0[2]^block0[3];
	// mifare classic SAK(byte 5) and ATQA(byte 6 and 7, reversed)
	if (sak!=NULL)
		block0[5]=sak[0];
	if (atqa!=NULL) {
		block0[6]=atqa[1];
		block0[7]=atqa[0];
	}
	PrintAndLog("new block 0:  %s", sprint_hex(block0,16));
	return mfCSetBlock(0, block0, oldUID, wantWipe, CSETBLOCK_SINGLE_OPER);
}

int mfCSetBlock(uint8_t blockNo, uint8_t *data, uint8_t *uid, bool wantWipe, uint8_t params) {

	uint8_t isOK = 0;
	UsbCommand c = {CMD_MIFARE_CSETBLOCK, {wantWipe, params & (0xFE | (uid == NULL ? 0:1)), blockNo}};
	memcpy(c.d.asBytes, data, 16); 
	SendCommand(&c);

	UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		isOK  = resp.arg[0] & 0xff;
		if (uid != NULL) 
			memcpy(uid, resp.d.asBytes, 4);
		if (!isOK) 
			return 2;
	} else {
		PrintAndLog("Command execute timeout");
		return 1;
	}
	return 0;
}

int mfCGetBlock(uint8_t blockNo, uint8_t *data, uint8_t params) {
	uint8_t isOK = 0;

	UsbCommand c = {CMD_MIFARE_CGETBLOCK, {params, 0, blockNo}};
	SendCommand(&c);

  UsbCommand resp;
	if (WaitForResponseTimeout(CMD_ACK,&resp,1500)) {
		isOK  = resp.arg[0] & 0xff;
		memcpy(data, resp.d.asBytes, 16);
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
char logHexFileName[FILE_PATH_SIZE] = {0x00};
static uint8_t traceCard[4096] = {0x00};
static char traceFileName[FILE_PATH_SIZE] = {0x00};
static int traceState = TRACE_IDLE;
static uint8_t traceCurBlock = 0;
static uint8_t traceCurKey = 0;

struct Crypto1State *traceCrypto1 = NULL;

struct Crypto1State *revstate = NULL;

uint64_t key = 0;
uint32_t ks2 = 0;
uint32_t ks3 = 0;

uint32_t uid = 0;     // serial number
uint32_t nt =0;      // tag challenge
uint32_t nr_enc =0;  // encrypted reader challenge
uint32_t ar_enc =0;  // encrypted reader response
uint32_t at_enc =0;  // encrypted tag response

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
	char buf[64] = {0x00};
	uint8_t buf8[64] = {0x00};
	int i, blockNum;
	
	if (!isTraceCardEmpty()) 
		saveTraceCard();
		
	memset(traceCard, 0x00, 4096);
	memcpy(traceCard, tuid + 3, 4);

	FillFileNameByUID(traceFileName, tuid, ".eml", 7);

	f = fopen(traceFileName, "r");
	if (!f) return 1;
	
	blockNum = 0;
		
	while(!feof(f)){
	
		memset(buf, 0, sizeof(buf));
		if (fgets(buf, sizeof(buf), f) == NULL) {
			PrintAndLog("File reading error.");
			fclose(f);
			return 2;
		}

		if (strlen(buf) < 32){
			if (feof(f)) break;
			PrintAndLog("File content error. Block data must include 32 HEX symbols");
			fclose(f);
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
	if ( !f ) return 1;
	
	for (int i = 0; i < 64; i++) {  // blocks
		for (int j = 0; j < 16; j++)  // bytes
			fprintf(f, "%02x", *(traceCard + i * 16 + j)); 
		fprintf(f,"\n");
	}
	fclose(f);
	return 0;
}

int mfTraceInit(uint8_t *tuid, uint8_t *atqa, uint8_t sak, bool wantSaveToEmlFile) {

	if (traceCrypto1) 
		crypto1_destroy(traceCrypto1);

	traceCrypto1 = NULL;

	if (wantSaveToEmlFile) 
		loadTraceCard(tuid);
		
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


int mfTraceDecode(uint8_t *data_src, int len, bool wantSaveToEmlFile) {
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
		if ((len == 4) && ((data[0] == 0x60) || (data[0] == 0x61))) {
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
		if ((len == 1) && (data[0] == 0x0a)) {
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
			
			//  decode key here)
			ks2 = ar_enc ^ prng_successor(nt, 64);
			ks3 = at_enc ^ prng_successor(nt, 96);
			revstate = lfsr_recovery64(ks2, ks3);
			lfsr_rollback_word(revstate, 0, 0);
			lfsr_rollback_word(revstate, 0, 0);
			lfsr_rollback_word(revstate, nr_enc, 1);
			lfsr_rollback_word(revstate, uid ^ nt, 0);

			crypto1_get_lfsr(revstate, &key);
			printf("Key: %012"llx"\n",key);
			AddLogUint64(logHexFileName, "key: ", key); 
			
			int blockShift = ((traceCurBlock & 0xFC) + 3) * 16;
			if (isBlockEmpty((traceCurBlock & 0xFC) + 3)) memcpy(traceCard + blockShift + 6, trailerAccessBytes, 4);
			
			if (traceCurKey) {
				num_to_bytes(key, 6, traceCard + blockShift + 10);
			} else {
				num_to_bytes(key, 6, traceCard + blockShift);
			}
			if (wantSaveToEmlFile) saveTraceCard();

			if (traceCrypto1) {
				crypto1_destroy(traceCrypto1);
			}
			
			// set cryptosystem state
			traceCrypto1 = lfsr_recovery64(ks2, ks3);
			
//	nt = crypto1_word(traceCrypto1, nt ^ uid, 1) ^ nt;

	/*	traceCrypto1 = crypto1_create(key); // key in lfsr
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
