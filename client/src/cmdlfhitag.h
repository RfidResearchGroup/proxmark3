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


#define HITAG_CRYPTOKEY_SIZE    6
#define HITAG_PASSWORD_SIZE     4
#define HITAG_UID_SIZE          4
#define HITAG_BLOCK_SIZE        4
#define HITAG2_MAX_BYTE_SIZE    (12 * HITAG_BLOCK_SIZE)
// need to see which limits these cards has
#define HITAG1_MAX_BYTE_SIZE    64
#define HITAGS_MAX_BYTE_SIZE    64
#define HITAGU_MAX_BYTE_SIZE    64
#define HITAG_MAX_BYTE_SIZE    (64 * HITAG_BLOCK_SIZE)

#define HITAG2_CONFIG_BLOCK     3
#define HITAG2_CONFIG_OFFSET    (HITAG_BLOCK_SIZE * HITAG2_CONFIG_BLOCK)

int CmdLFHitag(const char *Cmd);

int readHitagUid(void);
void annotateHitag1(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response);
void annotateHitag2(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, uint8_t bits, bool is_response);
void annotateHitagS(char *exp, size_t size, const uint8_t *cmd, uint8_t cmdsize, bool is_response);

void annotateHitag2_init(void);


uint8_t hitag1_CRC_check(uint8_t *d, uint32_t nbit);
#endif
