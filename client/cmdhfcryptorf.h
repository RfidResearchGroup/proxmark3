//-----------------------------------------------------------------------------
// Copyright (C) 2020 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency CryptoRF commands (ISO14443B)
//-----------------------------------------------------------------------------

#ifndef CMDHFCRYPTORF_H__
#define CMDHFCRYPTORF_H__

#include "common.h"

int CmdHFCryptoRF(const char *Cmd);

int infoHFCryptoRF(bool verbose);
int readHFCryptoRF(bool verbose);
#endif
