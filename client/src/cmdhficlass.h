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
// High frequency iClass support
//-----------------------------------------------------------------------------
#ifndef CMDHFICLASS_H__
#define CMDHFICLASS_H__

#include "common.h"
#include "fileutils.h"
#include "iclass_cmd.h"

int CmdHFiClass(const char *Cmd);

int info_iclass(bool shallow_mod);
int read_iclass_csn(bool loop, bool verbose, bool shallow_mod);
void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize, bool dense_output);
void HFiClassCalcDivKey(uint8_t *CSN, uint8_t *KEY, uint8_t *div_key, bool elite);

void GenerateMacFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, uint32_t keycnt, iclass_premac_t *list);
void GenerateMacKeyFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, uint32_t keycnt, iclass_prekey_t *list);
void PrintPreCalcMac(uint8_t *keys, uint32_t keycnt, iclass_premac_t *pre_list);
void PrintPreCalc(iclass_prekey_t *list, uint32_t itemcnt);

uint8_t get_pagemap(const picopass_hdr_t *hdr);
bool check_known_default(uint8_t *csn, uint8_t *epurse, uint8_t *rmac, uint8_t *tmac, uint8_t *key);
#endif
