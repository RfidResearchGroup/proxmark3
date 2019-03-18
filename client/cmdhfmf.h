//-----------------------------------------------------------------------------
// Copyright (C) 2011 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#ifndef CMDHFMF_H__
#define CMDHFMF_H__

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <time.h>
#include <mbedtls/aes.h>
#include "proxmark3.h"
#include "iso14443crc.h"
#include "ui.h"
#include "cmdparser.h"
#include "common.h"
#include "util.h"
#include "mifare.h"                        // nonces_t struct
#include "mifare/mfkey.h"                  // mfkey32_moebious
#include "cmdhfmfhard.h"
#include "mifare/mifarehost.h"             // icesector_t,  sector_t
#include "util_posix.h"                    // msclock
#include "mifare/mifaredefault.h"          // mifare default key array
#include "cmdhf14a.h"                      // dropfield
#include "cliparser/cliparser.h"           // argtable
#include "hardnested/hardnested_bf_core.h" // SetSIMDInstr

extern int CmdHFMF(const char *Cmd);

extern int CmdHF14AMfList(const char *Cmd);
extern int CmdHF14AMfDbg(const char *Cmd);
extern int CmdHF14AMfRdBl(const char *Cmd);
extern int CmdHF14AMfURdBl(const char *Cmd);
extern int CmdHF14AMfRdSc(const char *Cmd);
extern int CmdHF14SMfURdCard(const char *Cmd);
extern int CmdHF14AMfDump(const char *Cmd);
extern int CmdHF14AMfRestore(const char *Cmd);
extern int CmdHF14AMfWrBl(const char *Cmd);
extern int CmdHF14AMfUWrBl(const char *Cmd);
extern int CmdHF14AMfChk(const char *Cmd);
extern int CmdHF14AMfDarkside(const char *Cmd);
extern int CmdHF14AMfNested(const char *Cmd);
extern int CmdHF14AMfNestedHard(const char *Cmd);
//extern int CmdHF14AMfSniff(const char* Cmd);
extern int CmdHF14AMf1kSim(const char *Cmd);
extern int CmdHF14AMfKeyBrute(const char *Cmd);
extern int CmdHF14AMfEClear(const char *Cmd);
extern int CmdHF14AMfEGet(const char *Cmd);
extern int CmdHF14AMfESet(const char *Cmd);
extern int CmdHF14AMfELoad(const char *Cmd);
extern int CmdHF14AMfESave(const char *Cmd);
extern int CmdHF14AMfECFill(const char *Cmd);
extern int CmdHF14AMfEKeyPrn(const char *Cmd);
extern int CmdHF14AMfCSetUID(const char *Cmd);
extern int CmdHF14AMfCSetBlk(const char *Cmd);
extern int CmdHF14AMfCGetBlk(const char *Cmd);
extern int CmdHF14AMfCGetSc(const char *Cmd);
extern int CmdHF14AMfCLoad(const char *Cmd);
extern int CmdHF14AMfCSave(const char *Cmd);
extern int CmdHf14MfDecryptBytes(const char *Cmd);
extern int CmdHf14AMfSetMod(const char *Cmd);
extern int CmdHf14AMfNack(const char *Cmd);

void showSectorTable(void);
void readerAttack(nonces_t data, bool setEmulatorMem, bool verbose);
void printKeyTable(uint8_t sectorscnt, sector_t *e_sector);
void printKeyTable_fast(uint8_t sectorscnt, icesector_t *e_sector, uint64_t bar, uint64_t foo);
#endif
