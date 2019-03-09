//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// Copyright (C) 2011 Gerhard de Koning Gans
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency iClass support
//-----------------------------------------------------------------------------
#ifndef CMDHFICLASS_H__
#define CMDHFICLASS_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include "iso14443crc.h" // Can also be used for iClass, using 0xE012 as CRC-type
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "comms.h"
#include "mbedtls/des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"
#include "loclass/elite_crack.h"
#include "loclass/fileutils.h"
#include "protocols.h"
#include "usb_cmd.h"
#include "cmdhfmfu.h"
#include "cmdhf.h"
#include "protocols.h" // picopass structs,
#include "usb_cdc.h" // for usb_poll_validate_length



typedef struct iclass_block {
    uint8_t d[8];
} iclass_block_t;

typedef struct iclass_premac {
    uint8_t mac[4];
} iclass_premac_t;

typedef struct iclass_prekey {
    uint8_t mac[4];
    uint8_t key[8];
} iclass_prekey_t;

int CmdHFiClass(const char *Cmd);

extern int CmdHFiClassCalcNewKey(const char *Cmd);
extern int CmdHFiClassCloneTag(const char *Cmd);
extern int CmdHFiClassDecrypt(const char *Cmd);
extern int CmdHFiClassEncryptBlk(const char *Cmd);
extern int CmdHFiClassELoad(const char *Cmd);
extern int CmdHFiClassList(const char *Cmd);
extern int HFiClassReader(const char *Cmd, bool loop, bool verbose);
extern int CmdHFiClassReader(const char *Cmd);
extern int CmdHFiClassReader_Dump(const char *Cmd);
extern int CmdHFiClassReader_Replay(const char *Cmd);
extern int CmdHFiClassReadKeyFile(const char *filename);
extern int CmdHFiClassReadTagFile(const char *Cmd);
extern int CmdHFiClass_ReadBlock(const char *Cmd);
extern int CmdHFiClass_TestMac(const char *Cmd);
extern int CmdHFiClassManageKeys(const char *Cmd);
extern int CmdHFiClass_loclass(const char *Cmd);
extern int CmdHFiClassSniff(const char *Cmd);
extern int CmdHFiClassSim(const char *Cmd);
extern int CmdHFiClassWriteKeyFile(const char *Cmd);
extern int CmdHFiClass_WriteBlock(const char *Cmd);
extern int CmdHFiClassCheckKeys(const char *Cmd);
extern int CmdHFiClassLookUp(const char *Cmd);
extern int CmdHFiClassPermuteKey(const char *Cmd);

void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize);
void HFiClassCalcDivKey(uint8_t *CSN, uint8_t *KEY, uint8_t *div_key, bool elite);

int LoadDictionaryKeyFile(char *filename, uint8_t **keys, int *keycnt);
int GenerateMacFromKeyFile(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_premac_t *list);
int GenerateFromKeyFile(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_prekey_t *list);
void PrintPreCalcMac(uint8_t *keys, int keycnt, iclass_premac_t *pre_list);
void PrintPreCalc(iclass_prekey_t *list, int itemcnt);
#endif
