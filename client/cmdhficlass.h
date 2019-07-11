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
//#include "iso14443crc.h" // Can also be used for iClass, using 0xE012 as CRC-type
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
#include "pm3_cmd.h"
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

int readIclass(bool loop, bool verbose);
void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize);
void HFiClassCalcDivKey(uint8_t *CSN, uint8_t *KEY, uint8_t *div_key, bool elite);

int LoadDictionaryKeyFile(char *filename, uint8_t **keys, int *keycnt);
int GenerateMacFromKeyFile(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_premac_t *list);
int GenerateFromKeyFile(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, int keycnt, iclass_prekey_t *list);
void PrintPreCalcMac(uint8_t *keys, int keycnt, iclass_premac_t *pre_list);
void PrintPreCalc(iclass_prekey_t *list, int itemcnt);
#endif
