//-----------------------------------------------------------------------------
// Copyright (C) 2012 Roel Verdult
// 2017 iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Hitag support
//-----------------------------------------------------------------------------

#ifndef CMDLFHITAG_H__
#define CMDLFHITAG_H__

#include "common.h"

int CmdLFHitag(const char *Cmd);

int readHitagUid(void);
void annotateHitag1(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_response);
void annotateHitag2(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_response);
void annotateHitagS(char *exp, size_t size, uint8_t *cmd, uint8_t cmdsize, bool is_response);
uint8_t hitag1_CRC_check(uint8_t *d, uint32_t nbit);
#endif
