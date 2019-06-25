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

int CmdHFMF(const char *Cmd);
int CmdHF14AMfELoad(const char *Cmd); // used by cmd hf mfu eload
int CmdHF14AMfDbg(const char *Cmd);   // used by cmd hf mfu dbg

void showSectorTable(void);
void readerAttack(nonces_t data, bool setEmulatorMem, bool verbose);
void printKeyTable(uint8_t sectorscnt, sector_t *e_sector);
void printKeyTable_fast(uint8_t sectorscnt, icesector_t *e_sector, uint64_t bar, uint64_t foo);
#endif
