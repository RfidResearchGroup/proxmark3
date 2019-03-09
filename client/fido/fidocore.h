//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// FIDO2 authenticators core data and commands
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html
//-----------------------------------------------------------------------------
//
#ifndef __FIDOCORE_H__
#define __FIDOCORE_H__

#include <stddef.h>
#include <stdint.h>
#include <jansson.h>
#include "cmdhf14a.h"

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

extern int FIDOSelect(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int FIDOExchange(sAPDU apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int FIDORegister(uint8_t *params, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int FIDOAuthentication(uint8_t *params, uint8_t paramslen, uint8_t controlb, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int FIDO2GetInfo(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int FIDO2MakeCredential(uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
extern int FIDO2GetAssertion(uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);

extern int FIDOCheckDERAndGetKey(uint8_t *der, size_t derLen, bool verbose, uint8_t *publicKey, size_t publicKeyMaxLen);

extern char *fido2GetCmdMemberDescription(uint8_t cmdCode, bool isResponse, int memberNum);
extern char *fido2GetCmdErrorDescription(uint8_t errorCode);

extern bool CheckrpIdHash(json_t *json, uint8_t *hash);
extern int FIDO2CreateMakeCredentionalReq(json_t *root, uint8_t *data, size_t maxdatalen, size_t *datalen);
extern int FIDO2MakeCredentionalParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool verbose2, bool showCBOR, bool showDERTLV);
extern int FIDO2CreateGetAssertionReq(json_t *root, uint8_t *data, size_t maxdatalen, size_t *datalen, bool createAllowList);
extern int FIDO2GetAssertionParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool verbose2, bool showCBOR);

#endif /* __FIDOCORE_H__ */
