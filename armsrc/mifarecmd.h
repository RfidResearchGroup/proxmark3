//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
#ifndef __MIFARECMD_H
#define __MIFARECMD_H

#include "common.h"

int16_t mifare_cmd_readblocks(uint8_t key_auth_cmd, uint8_t *key, uint8_t read_cmd, uint8_t block_no, uint8_t count, uint8_t *block_data);
int16_t mifare_cmd_writeblocks(uint8_t key_auth_cmd, uint8_t *key, uint8_t write_cmd, uint8_t block_no, uint8_t count, uint8_t *block_data);
void MifareReadSector(uint8_t sector_no, uint8_t key_type, uint8_t *key);
void MifareValue(uint8_t arg0, uint8_t arg1, uint8_t arg2, uint8_t *datain);

void MifareUReadBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareUC_Auth(uint8_t arg0, uint8_t *keybytes);
void MifareUReadCard(uint8_t arg0, uint16_t arg1, uint8_t arg2, uint8_t *datain);
void MifareUWriteBlockCompat(uint8_t arg0, uint8_t arg1, uint8_t *datain);
void MifareUWriteBlock(uint8_t arg0, uint8_t arg1, uint8_t *datain);

void MifareNested(uint8_t blockNo, uint8_t keyType, uint8_t targetBlockNo, uint8_t targetKeyType, bool calibrate, uint8_t *key);
void MifareStaticNested(uint8_t blockNo, uint8_t keyType, uint8_t targetBlockNo, uint8_t targetKeyType, uint8_t *key);

void MifareAcquireEncryptedNonces(uint32_t arg0, uint32_t arg1, uint32_t flags, uint8_t *datain);
void MifareAcquireNonces(uint32_t arg0, uint32_t flags);
void MifareChkKeys(uint8_t *datain, uint8_t reserved_mem);
void MifareChkKeys_fast(uint32_t arg0, uint32_t arg1, uint32_t arg2, uint8_t *datain);
void MifareChkKeys_file(uint8_t *fn);

void MifareEMemClr(void);
void MifareEMemGet(uint8_t blockno, uint8_t blockcnt);
int MifareECardLoad(uint8_t sectorcnt, uint8_t keytype);
int MifareECardLoadExt(uint8_t sectorcnt, uint8_t keytype);

// MFC GEN1a /1b
void MifareCSetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain);  // Work with "magic Chinese" card
void MifareCGetBlock(uint32_t arg0, uint32_t arg1, uint8_t *datain);
void MifareCIdent(bool is_mfc);  // is "magic chinese" card?
void MifareHasStaticNonce(void);  // Has the tag a static nonce?

// MFC GEN3
int DoGen3Cmd(uint8_t *cmd, uint8_t cmd_len);
void MifareGen3UID(uint8_t uidlen, uint8_t *uid); // Gen 3 magic card set UID without manufacturer block
void MifareGen3Blk(uint8_t block_len, uint8_t *block); // Gen 3 magic card overwrite manufacturer block
void MifareGen3Freez(void); // Gen 3 magic card lock further UID changes

// MFC GEN4 GTU
void MifareG4ReadBlk(uint8_t blockno, uint8_t *pwd, uint8_t workFlags);
void MifareG4WriteBlk(uint8_t blockno, uint8_t *pwd, uint8_t *data, uint8_t workFlags);

void MifareSetMod(uint8_t *datain);
void MifarePersonalizeUID(uint8_t keyType, uint8_t perso_option, uint64_t key);

void MifareUSetPwd(uint8_t arg0, uint8_t *datain);
void OnSuccessMagic(void);
void OnErrorMagic(uint8_t reason);

int32_t dist_nt(uint32_t nt1, uint32_t nt2);
//void RAMFUNC SniffMifare(uint8_t param);

void Mifare_DES_Auth1(uint8_t arg0, uint8_t *datain);
void Mifare_DES_Auth2(uint32_t arg0, uint8_t *datain);

// Tear-off test for MFU
void MifareU_Otp_Tearoff(uint8_t blno, uint32_t tearoff_time, uint8_t *data_testwrite);
void MifareU_Counter_Tearoff(uint8_t counter, uint32_t tearoff_time, uint8_t *datain);
#endif
