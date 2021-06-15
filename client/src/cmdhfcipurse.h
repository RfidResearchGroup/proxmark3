//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency FIDO U2F and FIDO2 contactless authenticators
//-----------------------------------------------------------------------------
//
//  JAVA implementation here:
//
//  https://github.com/duychuongvn/cipurse-card-core
//-----------------------------------------------------------------------------

#ifndef CMDHFCIPURSE_H__
#define CMDHFCIPURSE_H__

#include "common.h"

int CmdHFCipurse(const char *Cmd);

bool CheckCardCipurse(void);

#endif
