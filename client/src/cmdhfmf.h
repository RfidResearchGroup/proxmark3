//-----------------------------------------------------------------------------
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
int CmdHFMFNDEFRead(const char *Cmd);

void showSectorTable(sector_t *k_sector, uint8_t k_sectorsCount);
void readerAttack(sector_t *k_sector, uint8_t k_sectorsCount, nonces_t data, bool setEmulatorMem, bool verbose);
void printKeyTable(uint8_t sectorscnt, sector_t *e_sector);
void printKeyTableEx(uint8_t sectorscnt, sector_t *e_sector, uint8_t start_sector);
void printKeyTable_fast(uint8_t sectorscnt, icesector_t *e_sector, uint64_t bar, uint64_t foo);

int mfc_ev1_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, int signature_len);
#endif
