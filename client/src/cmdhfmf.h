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
#include "mifare/mifarehost.h"           // structs

int CmdHFMF(const char *Cmd);
int CmdHF14AMfELoad(const char *Cmd);    // used by "hf mfu eload"
int CmdHF14AMfDbg(const char *Cmd);      // used by "hf mfu dbg"
int CmdHFMFNDEFRead(const char *Cmd);    // used by "nfc mf cread"
int CmdHFMFNDEFFormat(const char *Cmd);  // used by "nfc mf cformat"
int CmdHFMFNDEFWrite(const char *Cmd);  // used by "nfc mf cwrite"

void showSectorTable(sector_t *k_sector, size_t k_sectors_cnt);
void readerAttack(sector_t *k_sector, size_t k_sectors_cnt, nonces_t data, bool setEmulatorMem, bool verbose);
void printKeyTable(size_t sectorscnt, sector_t *e_sector);
void printKeyTableEx(size_t sectorscnt, sector_t *e_sector, uint8_t start_sector);
// void printKeyTableEx(size_t sectorscnt, sector_t *e_sector, uint8_t start_sector, bool singel_sector);

bool mfc_value(const uint8_t *d, int32_t *val);
void mf_print_sector_hdr(uint8_t sector);
void mf_print_block_one(uint8_t blockno, uint8_t *d, bool verbose);

int mfc_ev1_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, int signature_len);
#endif
