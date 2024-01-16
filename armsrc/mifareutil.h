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
// code for work with mifare cards.
//-----------------------------------------------------------------------------

#ifndef __MIFAREUTIL_H
#define __MIFAREUTIL_H

#include "common.h"
#include "crapto1/crapto1.h"

// mifare authentication
#define CRYPT_NONE    0
#define CRYPT_ALL     1
#define CRYPT_REQUEST 2
#define AUTH_FIRST    0
#define AUTH_NESTED   2

#define AUTHENTICATION_TIMEOUT 848      // card times out 1ms after wrong authentication (according to NXP documentation)
#define PRE_AUTHENTICATION_LEADTIME 400 // some (non standard) cards need a pause after select before they are ready for first authentication

// reader voltage field detector
#define MF_MINFIELDV      4000

// Mifare 4k/2k/1k/mini Max Block / Max Sector
#define MIFARE_4K_MAXBLOCK 256
#define MIFARE_2K_MAXBLOCK 128
#define MIFARE_1K_MAXBLOCK 64
#define MIFARE_MINI_MAXBLOCK 20

#define MIFARE_MINI_MAXSECTOR 5
#define MIFARE_1K_MAXSECTOR 16
#define MIFARE_2K_MAXSECTOR 32
#define MIFARE_4K_MAXSECTOR 40

//mifare emulator states
#define MFEMUL_NOFIELD      0
#define MFEMUL_IDLE         1
#define MFEMUL_SELECT       2
#define MFEMUL_AUTH1        3
#define MFEMUL_WORK         4
#define MFEMUL_WRITEBL2     5
#define MFEMUL_INTREG_INC   6
#define MFEMUL_INTREG_DEC   7
#define MFEMUL_INTREG_REST  8
#define MFEMUL_HALTED       9

#define cardSTATE_TO_IDLE() cardSTATE = MFEMUL_IDLE; LED_B_OFF(); LED_C_OFF();

#ifndef MifareBlockToSector
#define MifareBlockToSector(block) (block < 128 ? block / 4 : (block - 128) / 16 + 32)
#endif

//functions
uint16_t mifare_sendcmd(uint8_t cmd, uint8_t *data, uint8_t data_size, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing);
uint16_t mifare_sendcmd_short(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t data, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing);

// mifare classic
int mifare_classic_auth(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint8_t isNested);
int mifare_classic_authex(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t keyType, uint64_t ui64Key, uint8_t isNested, uint32_t *ntptr, uint32_t *timing);
int mifare_classic_authex_cmd(struct Crypto1State *pcs, uint32_t uid, uint8_t blockNo, uint8_t cmd, uint64_t ui64Key, uint8_t isNested, uint32_t *ntptr, uint32_t *timing);

int mifare_classic_readblock(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData);
int mifare_classic_readblock_ex(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData, uint8_t iso_byte);

int mifare_classic_halt(struct Crypto1State *pcs);
int mifare_classic_writeblock(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData);
int mifare_classic_writeblock_ex(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData, uint8_t cmd);
int mifare_classic_value(struct Crypto1State *pcs, uint8_t blockNo, uint8_t *blockData, uint8_t action);

// Ultralight/NTAG...
int mifare_ul_ev1_auth(uint8_t *keybytes, uint8_t *pack);
int mifare_ultra_auth(uint8_t *keybytes);
int mifare_ultra_readblock(uint8_t blockNo, uint8_t *blockData);
int mifare_ultra_writeblock_compat(uint8_t blockNo, uint8_t *blockData);
int mifare_ultra_writeblock(uint8_t blockNo, uint8_t *blockData);
int mifare_ultra_halt(void);

// desfire
int mifare_sendcmd_special(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t *data, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing);
int mifare_sendcmd_special2(struct Crypto1State *pcs, uint8_t crypted, uint8_t cmd, uint8_t *data, uint8_t *answer, uint8_t *answer_parity, uint32_t *timing);
int mifare_desfire_des_auth1(uint32_t uid, uint8_t *blockData);
int mifare_desfire_des_auth2(uint32_t uid, uint8_t *key, uint8_t *blockData);

// crypto functions
void mf_crypto1_decrypt(struct Crypto1State *pcs, uint8_t *data, int len);
void mf_crypto1_decryptEx(struct Crypto1State *pcs, const uint8_t *data_in, int len, uint8_t *data_out);
void mf_crypto1_encrypt(struct Crypto1State *pcs, uint8_t *data, uint16_t len, uint8_t *par);
void mf_crypto1_encryptEx(struct Crypto1State *pcs, const uint8_t *data_in, uint8_t *keystream,
                          uint8_t *data_out, uint16_t len, uint8_t *par);
uint8_t mf_crypto1_encrypt4bit(struct Crypto1State *pcs, uint8_t data);

// Mifare memory structure
uint8_t NumBlocksPerSector(uint8_t sectorNo);
uint8_t FirstBlockOfSector(uint8_t sectorNo);

bool IsSectorTrailer(uint8_t blockNo);
uint8_t SectorTrailer(uint8_t blockNo);

// emulator functions
void emlClearMem(void);
void emlSetMem_xt(uint8_t *data, int blockNum, int blocksCount, int block_width);
void emlGetMem(uint8_t *data, int blockNum, int blocksCount);
void emlGetMemBt(uint8_t *data, int offset, int byteCount);
uint64_t emlGetKey(int sectorNum, int keyType);
int emlGetValBl(uint32_t *blReg, uint8_t *blBlock, int blockNum);
int emlSetValBl(uint32_t blReg, uint8_t blBlock, int blockNum);
int emlCheckValBl(int blockNum);

#endif
