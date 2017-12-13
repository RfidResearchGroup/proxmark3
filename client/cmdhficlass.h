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
#include "data.h"
#include "proxmark3.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "cmdmain.h"
#include "loclass/des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"
#include "loclass/elite_crack.h"
#include "loclass/fileutils.h"
#include "protocols.h"
#include "usb_cmd.h"
#include "cmdhfmfu.h"
#include "cmdhf.h"
#include "protocols.h"	// picopass structs,
#include "usb_cdc.h" // for usb_poll_validate_length

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
extern int CmdHF14AMfChk(const char *Cmd);
void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize);
void HFiClassCalcDivKey(uint8_t	*CSN, uint8_t	*KEY, uint8_t *div_key, bool elite);
#endif
