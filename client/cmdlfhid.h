//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency HID commands
//-----------------------------------------------------------------------------

#ifndef CMDLFHID_H__
#define CMDLFHID_H__

#include "common.h"

int CmdLFHID(const char *Cmd);

int demodHID(void);
//void calc26(uint16_t fc, uint32_t cardno, uint8_t *out);
void calcWiegand(uint8_t fmtlen, uint16_t fc, uint64_t cardno, uint8_t *bits, uint8_t oem);
#endif
