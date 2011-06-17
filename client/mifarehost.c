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
#include "mifarehost.h"


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

