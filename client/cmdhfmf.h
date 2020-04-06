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

#include "common.h"
#include "mifare/mfkey.h"
#include "mifare/mifarehost.h" // struct

int CmdHFMF(const char *Cmd);
int CmdHF14AMfELoad(const char *Cmd); // used by cmd hf mfu eload
int CmdHF14AMfDbg(const char *Cmd);   // used by cmd hf mfu dbg

void showSectorTable(void);
void readerAttack(nonces_t data, bool setEmulatorMem, bool verbose);
void printKeyTable(uint8_t sectorscnt, sector_t *e_sector);
void printKeyTableEx(uint8_t sectorscnt, sector_t *e_sector, uint8_t start_sector);
void printKeyTable_fast(uint8_t sectorscnt, icesector_t *e_sector, uint64_t bar, uint64_t foo);
#endif
