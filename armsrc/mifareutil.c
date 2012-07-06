//-----------------------------------------------------------------------------
// Merlok, May 2011, 2012
// Many authors, whom made it possible
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Work with mifare cards.
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "crapto1.h"
#include "mifareutil.h"

int MF_DBGLEVEL = MF_DBG_ALL;

// memory management
uint8_t* mifare_get_bigbufptr(void) {
	return (((uint8_t *)BigBuf) + MIFARE_BUFF_OFFSET);	// was 3560 - tied to other size changes
}
uint8_t* eml_get_bigbufptr_sendbuf(void) {
	return (((uint8_t *)BigBuf) + RECV_CMD_OFFSET);	
}
uint8_t* eml_get_bigbufptr_recbuf(void) {
	return (((uint8_t *)BigBuf) + MIFARE_BUFF_OFFSET);
}
uint8_t* eml_get_bigbufptr_cardmem(void) {
	return (((uint8_t *)BigBuf) + CARD_MEMORY);
}

// crypto1 helpers
void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len){
	uint8_t	bt = 0;
	int i;
	
	if (len != 1) {
		for (i = 0; i < len; i++)
			data[i] = crypto1_byte(pcs, 0x00, 0) ^ data[i];
	} else {
		bt = 0;
		for (i = 0; i < 4; i++)
			bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data[0], i)) << i;
				
		data[0] = bt;
	}
	return;
}

void mf_crypto1_encrypt(struct Crypto1State *pcs, uint8_t *data, int len, uint32_t *par) {
	uint8_t bt = 0;
	int i;
	uint32_t mltpl = 1 << (len - 1); // for len=18 it=0x20000
	*par = 0;
	for (i = 0; i < len; i++) {
		bt = data[i];
		data[i] = crypto1_byte(pcs, 0x00, 0) ^ data[i];
		*par = (*par >> 1) | ( ((filter(pcs->odd) ^ oddparity(bt)) & 0x01) * mltpl );
	}	
	return;
}

uint8_t mf_crypto1_encrypt4bit(struct Crypto1State *pcs, uint8_t data) {
	uint8_t bt = 0;
	int i;

	for (i = 0; i < 4; i++)
		bt |= (crypto1_bit(pcs, 0, 0) ^ BIT(data, i)) << i;
		
	return bt;
}

// send commands
int mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t* answer)
{
	return mifare_sendcmd_shortex(pcs, crypted, cmd, data, answer, NULL);
}

int mifare_sendcmd_shortex(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t* answer, uint32_t * parptr)
{
	uint8_t dcmd[4], ecmd[4];
	uint32_t pos, par, res;

	dcmd[0] = cmd;
	dcmd[1] = data;
	AppendCrc14443a(dcmd, 2);
	
	memcpy(ecmd, dcmd, sizeof(dcmd));
	
	if (crypted) {
		par = 0;
		for (pos = 0; pos < 4; pos++)
		{
			ecmd[pos] = crypto1_byte(pcs, 0x00, 0) ^ dcmd[pos];
			par = (par >> 1) | ( ((filter(pcs->odd) ^ oddparity(dcmd[pos])) & 0x01) * 0x08 );
		}	

		ReaderTransmitPar(ecmd, sizeof(ecmd), par);

	} else {
		ReaderTransmit(dcmd, sizeof(dcmd));
	}

	int len = ReaderReceivePar(answer, &par);
	
	if (parptr) *parptr = par;

	if (crypted == CRYPT_ALL) {
		if (len == 1) {
			res = 0;
			for (pos = 0; pos < 4; pos++)
				res |= (crypto1_bit(pcs, 0, 0) ^ BIT(answer[0], pos)) << pos;
				
			answer[0] = res;
			
		} else {
			for (pos = 0; pos < len; pos++)
			{
				answer[pos] = crypto1_byte(pcs, 0x00, 0) ^ answer[pos];
			}
		}
	}
	
	return len;
}

// mifare commands
int mifare_classic_auth(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint64_t isNested) 
{
	return mifare_classic_authex(pcs, uid, blockNo, keyType, ui64Key, isNested, NULL);
}

int mifare_classic_authex(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint64_t isNested, uint32_t * ntptr) 
{
	// variables
	int len;	
	uint32_t pos;
	uint8_t tmp4[4];
	byte_t par = 0;
	byte_t ar[4];
	uint32_t nt, ntpp; // Supplied tag nonce
	
	uint8_t mf_nr_ar[] = { 0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00 };
	uint8_t* receivedAnswer = mifare_get_bigbufptr();

	// Transmit MIFARE_CLASSIC_AUTH
	len = mifare_sendcmd_short(pcs, isNested, 0x60 + (keyType & 0x01), blockNo, receivedAnswer);
  if (MF_DBGLEVEL >= 4)	Dbprintf("rand nonce len: %x", len);  
	if (len != 4) return 1;
	
	ar[0] = 0x55;
	ar[1] = 0x41;
	ar[2] = 0x49;
	ar[3] = 0x92; 
	
	// Save the tag nonce (nt)
	nt = bytes_to_num(receivedAnswer, 4);

	//  ----------------------------- crypto1 create
	if (isNested)
		crypto1_destroy(pcs);

	// Init cipher with key
	crypto1_create(pcs, ui64Key);

	if (isNested == AUTH_NESTED) {
		// decrypt nt with help of new key 
		nt = crypto1_word(pcs, nt ^ uid, 1) ^ nt;
	} else {
		// Load (plain) uid^nt into the cipher
		crypto1_word(pcs, nt ^ uid, 0);
	}

	// some statistic
	if (!ntptr && (MF_DBGLEVEL >= 3))
		Dbprintf("auth uid: %08x nt: %08x", uid, nt);  
	
	// save Nt
	if (ntptr)
		*ntptr = nt;

	par = 0;
	// Generate (encrypted) nr+parity by loading it into the cipher (Nr)
	for (pos = 0; pos < 4; pos++)
	{
		mf_nr_ar[pos] = crypto1_byte(pcs, ar[pos], 0) ^ ar[pos];
		par = (par >> 1) | ( ((filter(pcs->odd) ^ oddparity(ar[pos])) & 0x01) * 0x80 );
	}	
		
	// Skip 32 bits in pseudo random generator
	nt = prng_successor(nt,32);

	//  ar+parity
	for (pos = 4; pos < 8; pos++)
	{
		nt = prng_successor(nt,8);
		mf_nr_ar[pos] = crypto1_byte(pcs,0x00,0) ^ (nt & 0xff);
		par = (par >> 1)| ( ((filter(pcs->odd) ^ oddparity(nt & 0xff)) & 0x01) * 0x80 );
	}	
		
	// Transmit reader nonce and reader answer
	ReaderTransmitPar(mf_nr_ar, sizeof(mf_nr_ar), par);

	// Receive 4 bit answer
	len = ReaderReceive(receivedAnswer);
	if (!len)
	{
		if (MF_DBGLEVEL >= 1)	Dbprintf("Authentication failed. Card timeout.");
		return 2;
	}
	
	memcpy(tmp4, receivedAnswer, 4);
	ntpp = prng_successor(nt, 32) ^ crypto1_word(pcs, 0,0);
	
	if (ntpp != bytes_to_num(tmp4, 4)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Authentication failed. Error card response.");
		return 3;
	}

	return 0;
}

int mifare_classic_readblock(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t *blockData) 
{
	// variables
	int len;	
	uint8_t	bt[2];
	
	uint8_t* receivedAnswer = mifare_get_bigbufptr();
	
	// command MIFARE_CLASSIC_READBLOCK
	len = mifare_sendcmd_short(pcs, 1, 0x30, blockNo, receivedAnswer);
	if (len == 1) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Cmd Error: %02x", receivedAnswer[0]);  
		return 1;
	}
	if (len != 18) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Cmd Error: card timeout. len: %x", len);  
		return 2;
	}

	memcpy(bt, receivedAnswer + 16, 2);
	AppendCrc14443a(receivedAnswer, 16);
	if (bt[0] != receivedAnswer[16] || bt[1] != receivedAnswer[17]) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Cmd CRC response error.");  
		return 3;
	}
	
	memcpy(blockData, receivedAnswer, 16);
	return 0;
}

int mifare_classic_writeblock(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t *blockData) 
{
	// variables
	int len, i;	
	uint32_t pos;
	uint32_t par = 0;
	byte_t res;
	
	uint8_t d_block[18], d_block_enc[18];
	uint8_t* receivedAnswer = mifare_get_bigbufptr();
	
	// command MIFARE_CLASSIC_WRITEBLOCK
	len = mifare_sendcmd_short(pcs, 1, 0xA0, blockNo, receivedAnswer);

	if ((len != 1) || (receivedAnswer[0] != 0x0A)) {   //  0x0a - ACK
		if (MF_DBGLEVEL >= 1)	Dbprintf("Cmd Error: %02x", receivedAnswer[0]);  
		return 1;
	}
	
	memcpy(d_block, blockData, 16);
	AppendCrc14443a(d_block, 16);
	
	// crypto
	par = 0;
	for (pos = 0; pos < 18; pos++)
	{
		d_block_enc[pos] = crypto1_byte(pcs, 0x00, 0) ^ d_block[pos];
		par = (par >> 1) | ( ((filter(pcs->odd) ^ oddparity(d_block[pos])) & 0x01) * 0x20000 );
	}	

	ReaderTransmitPar(d_block_enc, sizeof(d_block_enc), par);

	// Receive the response
	len = ReaderReceive(receivedAnswer);	

	res = 0;
	for (i = 0; i < 4; i++)
		res |= (crypto1_bit(pcs, 0, 0) ^ BIT(receivedAnswer[0], i)) << i;

	if ((len != 1) || (res != 0x0A)) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("Cmd send data2 Error: %02x", res);  
		return 2;
	}
	
	return 0;
}

int mifare_classic_halt(struct Crypto1State *pcs, uint32_t uid) 
{
	// variables
	int len;	
	
	// Mifare HALT
	uint8_t* receivedAnswer = mifare_get_bigbufptr();

	len = mifare_sendcmd_short(pcs, pcs == NULL ? 0:1, 0x50, 0x00, receivedAnswer);
	if (len != 0) {
		if (MF_DBGLEVEL >= 1)	Dbprintf("halt error. response len: %x", len);  
		return 1;
	}

	return 0;
}

// work with emulator memory
void emlSetMem(uint8_t *data, int blockNum, int blocksCount) {
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	
	memcpy(emCARD + blockNum * 16, data, blocksCount * 16);
}

void emlGetMem(uint8_t *data, int blockNum, int blocksCount) {
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	
	memcpy(data, emCARD + blockNum * 16, blocksCount * 16);
}

void emlGetMemBt(uint8_t *data, int bytePtr, int byteCount) {
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	
	memcpy(data, emCARD + bytePtr, byteCount);
}

int emlCheckValBl(int blockNum) {
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	uint8_t* data = emCARD + blockNum * 16;

	if ((data[0] != (data[4] ^ 0xff)) || (data[0] != data[8]) ||
			(data[1] != (data[5] ^ 0xff)) || (data[1] != data[9]) ||
			(data[2] != (data[6] ^ 0xff)) || (data[2] != data[10]) ||
			(data[3] != (data[7] ^ 0xff)) || (data[3] != data[11]) ||
			(data[12] != (data[13] ^ 0xff)) || (data[12] != data[14]) ||
			(data[12] != (data[15] ^ 0xff))
		 ) 
		return 1;
	return 0;
}

int emlGetValBl(uint32_t *blReg, uint8_t *blBlock, int blockNum) {
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	uint8_t* data = emCARD + blockNum * 16;
	
	if (emlCheckValBl(blockNum)) {
		return 1;
	}
	
	memcpy(blReg, data, 4);
	*blBlock = data[12];
	
	return 0;
}

int emlSetValBl(uint32_t blReg, uint8_t blBlock, int blockNum) {
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	uint8_t* data = emCARD + blockNum * 16;
	
	memcpy(data + 0, &blReg, 4);
	memcpy(data + 8, &blReg, 4);
	blReg = blReg ^ 0xffffffff;
	memcpy(data + 4, &blReg, 4);
	
	data[12] = blBlock;
	data[13] = blBlock ^ 0xff;
	data[14] = blBlock;
	data[15] = blBlock ^ 0xff;
	
	return 0;
}

uint64_t emlGetKey(int sectorNum, int keyType) {
	uint8_t key[6];
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	
	memcpy(key, emCARD + 3 * 16 + sectorNum * 4 * 16 + keyType * 10, 6);
	return bytes_to_num(key, 6);
}

void emlClearMem(void) {
	int b;
	
	const uint8_t trailer[] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x07, 0x80, 0x69, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	const uint8_t uid[]   =   {0xe6, 0x84, 0x87, 0xf3, 0x16, 0x88, 0x04, 0x00, 0x46, 0x8e, 0x45, 0x55, 0x4d, 0x70, 0x41, 0x04};
	uint8_t* emCARD = eml_get_bigbufptr_cardmem();
	
	memset(emCARD, 0, CARD_MEMORY_LEN);
	
	// fill sectors trailer data
	for(b = 3; b < 256; b<127?(b+=4):(b+=16)) {
		emlSetMem((uint8_t *)trailer, b , 1);
	}	

	// uid
	emlSetMem((uint8_t *)uid, 0, 1);
	return;
}
