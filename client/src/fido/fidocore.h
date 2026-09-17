//-----------------------------------------------------------------------------
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
// FIDO2 authenticators core data and commands
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html
//-----------------------------------------------------------------------------
#ifndef __FIDOCORE_H__
#define __FIDOCORE_H__

#include "common.h"

#include <jansson.h>
#include "iso7816/apduinfo.h" // sAPDU_t

typedef enum {
    fido2CmdMakeCredential      = 0x01,
    fido2CmdGetAssertion        = 0x02,
    fido2CmdCancel              = 0x03,
    fido2CmdGetInfo             = 0x04,
    fido2CmdClientPIN           = 0x06,
    fido2CmdReset               = 0x07,
    fido2CmdGetNextAssertion    = 0x08,

    // another data
    fido2COSEKey                = 0xF0
} fido2Commands;

typedef enum  {
    ptQuery,
    ptResponse,
} fido2PacketType;

int FIDOSelect(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int FIDOExchange(sAPDU_t apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int FIDORegister(uint8_t *params, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int FIDOAuthentication(uint8_t *params, uint8_t paramslen, uint8_t controlb, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int FIDO2GetInfo(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int FIDO2MakeCredential(uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int FIDO2GetAssertion(uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);

int FIDOCheckDERAndGetKey(uint8_t *der, size_t derLen, bool verbose, uint8_t *publicKey, size_t publicKeyMaxLen);

const char *fido2GetCmdMemberDescription(uint8_t cmdCode, bool isResponse, int memberNum);
const char *fido2GetCmdErrorDescription(uint8_t errorCode);

bool CheckrpIdHash(json_t *json, uint8_t *hash);
int FIDO2CreateMakeCredentionalReq(json_t *root, uint8_t *data, size_t maxdatalen, size_t *datalen);
int FIDO2MakeCredentionalParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool verbose2, bool showCBOR, bool showDERTLV);
int FIDO2CreateGetAssertionReq(json_t *root, uint8_t *data, size_t maxdatalen, size_t *datalen, bool createAllowList);
int FIDO2GetAssertionParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool verbose2, bool showCBOR);

#endif /* __FIDOCORE_H__ */
