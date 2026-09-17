//-----------------------------------------------------------------------------
// Borrowed initially from https://github.com/nfc-tools/libfreefare
// Copyright (C) 2010, Romain Tartiere.
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
// High frequency Desfire secure channel functions
//-----------------------------------------------------------------------------

#ifndef __DESFIRESECURECHAN_H
#define __DESFIRESECURECHAN_H

#include "common.h"
#include "mifare/desfirecore.h"
#include "mifare/desfirecrypto.h"
#include "mifare/mifare4.h"

typedef struct {
    uint8_t cmd;
    DesfireSecureChannel secureChannel;
    DesfireCommandSet cmdSet;
    DesfireCommunicationMode commMode;
} AllowedChannelModes_t;

typedef struct {
    uint8_t cmd;
    uint32_t len;
} CmdHeaderLengths_t;

void DesfireSecureChannelEncode(DesfireContext_t *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen);
void DesfireSecureChannelDecode(DesfireContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen);

bool PrintChannelModeWarning(uint8_t cmd, DesfireSecureChannel secureChannel, DesfireCommandSet cmdSet, DesfireCommunicationMode commMode);

#endif // __DESFIRESECURECHAN_H
