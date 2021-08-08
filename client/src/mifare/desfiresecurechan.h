//-----------------------------------------------------------------------------
// Copyright (C) 2010 Romain Tartiere.
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
} AllowedChannelModesS;

typedef struct {
    uint8_t cmd;
    uint32_t len;
} CmdHeaderLengthsS;

void DesfireSecureChannelEncode(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen);
void DesfireSecureChannelDecode(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen);

bool PrintChannelModeWarning(uint8_t cmd, DesfireSecureChannel secureChannel, DesfireCommandSet cmdSet, DesfireCommunicationMode commMode);

#endif // __DESFIRESECURECHAN_H
