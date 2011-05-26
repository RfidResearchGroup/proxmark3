//-----------------------------------------------------------------------------
// Merlok, May 2011
// Many authors, that makes it possible
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// code for work with mifare cards.
//-----------------------------------------------------------------------------

#include "proxmark3.h"
#include "apps.h"
#include "util.h"
#include "string.h"

#include "iso14443crc.h"
#include "iso14443a.h"
#include "crapto1.h"
#include "mifareutil.h"

uint8_t* mifare_get_bigbufptr(void) {
	return (((uint8_t *)BigBuf) + 3560);	// was 3560 - tied to other size changes
}

int mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t* answer)
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

	int len = ReaderReceive(answer);

	if (crypted) {
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

int mifare_classic_auth(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint64_t isNested) 
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
//	Dbprintf("rand nonce len: %x", len);  
  if (len != 4) return 1;
	
	ar[0] = 0x55;
	ar[1] = 0x41;
	ar[2] = 0x49;
	ar[3] = 0x92; 
	
	// Save the tag nonce (nt)
	nt = bytes_to_num(receivedAnswer, 4);
	Dbprintf("uid: %x nt: %x", uid, nt);  

	//  ----------------------------- crypto1 create
  // Init cipher with key
	crypto1_create(pcs, ui64Key);

  // Load (plain) uid^nt into the cipher
	crypto1_word(pcs, nt ^ uid, 0);

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
    Dbprintf("Authentication failed. Card timeout.");
		return 2;
  }
	
  memcpy(tmp4, receivedAnswer, 4);
	ntpp = prng_successor(nt, 32) ^ crypto1_word(pcs, 0,0);
	
	if (ntpp != bytes_to_num(tmp4, 4)) {
    Dbprintf("Authentication failed. Error card response.");
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
		Dbprintf("Cmd Error: %02x", receivedAnswer[0]);  
		return 1;
	}
	if (len != 18) {
		Dbprintf("Cmd Error: card timeout. len: %x", len);  
		return 2;
	}

	memcpy(bt, receivedAnswer + 16, 2);
  AppendCrc14443a(receivedAnswer, 16);
	if (bt[0] != receivedAnswer[16] || bt[1] != receivedAnswer[17]) {
		Dbprintf("Cmd CRC response error.");  
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
		Dbprintf("Cmd Error: %02x", receivedAnswer[0]);  
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
		Dbprintf("Cmd send data2 Error: %02x", res);  
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

	len = mifare_sendcmd_short(pcs, 1, 0x50, 0x00, receivedAnswer);
  if (len != 0) {
		Dbprintf("halt error. response len: %x", len);  
		return 1;
	}

	return 0;
}
