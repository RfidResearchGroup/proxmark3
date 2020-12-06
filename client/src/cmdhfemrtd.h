//-----------------------------------------------------------------------------
// Copyright (C) 2020 A. Ozkal
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Electronic Machine Readable Travel Document commands
//-----------------------------------------------------------------------------

#ifndef CMDHFEMRTD_H__
#define CMDHFEMRTD_H__

#include "common.h"

int CmdHFeMRTD(const char *Cmd);

int infoHF_EMRTD(char *documentnumber, char *dob, char *expiry);
#endif
