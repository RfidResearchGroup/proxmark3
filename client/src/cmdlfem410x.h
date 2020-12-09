//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2016, 2017 marshmellow, iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency EM 410x commands
//-----------------------------------------------------------------------------

#ifndef CMDLFEM410X_H__
#define CMDLFEM410X_H__

#include "common.h"

int CmdLFEM410X(const char *Cmd);

int demodEM410x(bool verbose);
void printEM410x(uint32_t hi, uint64_t id, bool verbose);

int AskEm410xDecode(bool verbose, uint32_t *hi, uint64_t *lo);
int AskEm410xDemod(int clk, int invert, int maxErr, size_t maxLen, bool amplify, uint32_t *hi, uint64_t *lo, bool verbose);

#endif
