//-----------------------------------------------------------------------------
// Copyright (C) 2010 Romain Tartiere.
// Copyright (C) 2014 Iceman
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Desfire core functions
//-----------------------------------------------------------------------------

#ifndef __DESFIRECORE_H
#define __DESFIRECORE_H

#include "common.h"
#include "cliparser.h"
#include "mifare/desfirecrypto.h"
#include "mifare/desfire_crypto.h"
#include "mifare/mifare4.h"

extern const CLIParserOption DesfireAlgoOpts[];
extern const CLIParserOption DesfireKDFAlgoOpts[];
extern const CLIParserOption DesfireCommunicationModeOpts[];
extern const CLIParserOption DesfireCommandSetOpts[];
extern const CLIParserOption DesfireSecureChannelOpts[];

const char *DesfireGetErrorString(int res, uint16_t *sw);
uint32_t DesfireAIDByteToUint(uint8_t *data);
void DesfireAIDUintToByte(uint32_t aid, uint8_t *data);

void DesfirePrintContext(DesfireContext *ctx);

int DesfireExchange(DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen);
int DesfireExchangeEx(bool activate_field, DesfireContext *ctx, uint8_t cmd, uint8_t *data, size_t datalen, uint8_t *respcode, uint8_t *resp, size_t *resplen, bool enable_chaining, size_t splitbysize);

int DesfireSelectAID(DesfireContext *ctx, uint8_t *aid1, uint8_t *aid2);
int DesfireSelectAIDHex(DesfireContext *ctx, uint32_t aid1, bool select_two, uint32_t aid2);

int DesfireSelectAndAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel, uint32_t aid, bool verbose);
int DesfireAuthenticate(DesfireContext *dctx, DesfireSecureChannel secureChannel);

int DesfireFormatPICC(DesfireContext *dctx);
int DesfireGetUID(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetAIDList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireGetDFList(DesfireContext *dctx, uint8_t *resp, size_t *resplen);

int DesfireCreateApplication(DesfireContext *dctx, uint8_t *appdata, size_t appdatalen);
int DesfireDeleteApplication(DesfireContext *dctx, uint32_t aid);

int DesfireGetKeyVersion(DesfireContext *dctx, uint8_t *data, size_t len, uint8_t *resp, size_t *resplen);
int DesfireGetKeySettings(DesfireContext *dctx, uint8_t *resp, size_t *resplen);
int DesfireChangeKeySettings(DesfireContext *dctx, uint8_t *data, size_t len);
void PrintKeySettings(uint8_t keysettings, uint8_t numkeys, bool applevel, bool print2ndbyte);

#endif // __DESFIRECORE_H
