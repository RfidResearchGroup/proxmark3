//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency AWID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFAWID_H__
#define CMDLFAWID_H__

#include "common.h"

int CmdLFAWID(const char *Cmd);

int demodAWID(void);
int getAWIDBits(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *bits);

#endif
