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
// Low frequency Hitag support
//-----------------------------------------------------------------------------

#ifndef CMDLFHITAG_H__
#define CMDLFHITAG_H__

#include "common.h"
#include "hitag.h"

#define HITAG2_CONFIG_OFFSET    (HITAG_BLOCK_SIZE * HITAG2_CONFIG_BLOCK)
#define HITAG_DICTIONARY        "ht2_default"

int CmdLFHitag(const char *Cmd);

int ht2_read_uid(void);
int ht2_read_paxton(void);
void annotateHitag1(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response);
void annotateHitag2(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, uint8_t bits, bool is_response, const uint64_t *keys, uint32_t keycount, bool isdecrypted);
void annotateHitagS(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response);

void annotateHitag2_init(void);
bool hitag2_get_plain(uint8_t *plain,  uint8_t *plen);
void hitag2_annotate_plain(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, uint8_t bits);

uint8_t hitag1_CRC_check(uint8_t *d, uint32_t nbit);
#endif
