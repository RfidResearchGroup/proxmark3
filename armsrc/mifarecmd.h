//-----------------------------------------------------------------------------
// Jonathan Westhues, Aug 2005
// Gerhard de Koning Gans, April 2008, May 2011
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Definitions internal to the app source.
//-----------------------------------------------------------------------------
#ifndef __MIFARECMD_H
#define __MIFARECMD_H

#include "common.h"

void MifareReadBlock(uint8_t blockNo, uint8_t keyType, uint8_t *datain);

void MifareUReadBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareUC_Auth(uint8_t arg0, uint8_t *keybytes);
void MifareUReadCard(uint8_t arg0, uint16_t arg1, uint8_t arg2, uint8_t *datain);
void MifareReadSector(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);
//void MifareUWriteBlockCompat(uint8_t arg0,uint8_t *datain);

void MifareUWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareNested(uint8_t blockNo, uint8_t keyType, uint8_t targetBlockNo, uint8_t targetKeyType, bool calibrate, uint8_t *key);

void MifareAcquireEncryptedNonces(uint32_t arg0, uint32_t arg1, uint32_t flags, uint8_t *datain);
void MifareAcquireNonces(uint32_t arg0, uint32_t flags);
void MifareChkKeys(uint8_t *datain);
void MifareChkKeys_fast(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);

void MifareEMemClr(void);
void MifareEMemSet(uint8_t blockno, uint8_t blockcnt, uint8_t blockwidth, uint8_t *datain);
void MifareEMemGet(uint8_t blockno, uint8_t blockcnt);
int MifareECardLoad(uint8_t sectorcnt, uint8_t keytype);
int MifareECardLoadExt(uint8_t numSectors, uint8_t keyType);

void MifareCSetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain);  // Work with "magic Chinese" card
void MifareCGetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain);
void MifareCIdent();  // is "magic chinese" card?
void MifareHasStaticNonce();  // Has the tag a static nonce?

void MifareSetMod(uint8_t *datain);
void MifareUSetPwd(uint8_t arg0, uint8_t *datain);
void OnSuccessMagic();
void OnErrorMagic(uint8_t reason);

int32_t dist_nt(uint32_t nt1, uint32_t nt2);
void ReaderMifare(bool first_try, uint8_t block, uint8_t keytype);
//void RAMFUNC SniffMifare(uint8_t param);

void Mifare_DES_Auth1(uint8_t arg0, uint8_t *datain);
void Mifare_DES_Auth2(uint32_t arg0, uint8_t *datain);

// Tear-off test for MFU
void MifareU_Otp_Tearoff();

#endif
