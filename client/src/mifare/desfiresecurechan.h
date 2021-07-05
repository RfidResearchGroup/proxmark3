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
#include "mifare/desfire_crypto.h"
#include "mifare/mifare4.h"

void DesfireCryptoEncDec(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode);

void DesfireSecureChannelEncode(DesfireContext *ctx, uint8_t cmd, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen);
void DesfireSecureChannelDecode(DesfireContext *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t respcode, uint8_t *dstdata, size_t *dstdatalen);


#endif // __DESFIRESECURECHAN_H
