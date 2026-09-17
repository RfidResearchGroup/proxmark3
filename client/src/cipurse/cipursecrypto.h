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
// CIPURSE crypto primitives
//-----------------------------------------------------------------------------

#ifndef __CIPURSECRYPTO_H__
#define __CIPURSECRYPTO_H__

#include "common.h"
#include "iso7816/apduinfo.h"    // sAPDU_t

#define CIPURSE_KVV_LENGTH 4
#define CIPURSE_AES_KEY_LENGTH 16
#define CIPURSE_AES_BLOCK_LENGTH 16
#define CIPURSE_SECURITY_PARAM_N 6
#define CIPURSE_MAC_LENGTH 8
#define CIPURSE_MIC_LENGTH 4
#define CIPURSE_POLY 0x35b088cce172UL

#define member_size(type, member) sizeof(((type *)0)->member)

typedef enum {
    CPSNone,
    CPSPlain,
    CPSMACed,
    CPSEncrypted
} CipurseChannelSecurityLevel;

typedef struct CipurseContext_tS {
    uint8_t keyId;
    uint8_t key[CIPURSE_AES_KEY_LENGTH];

    uint8_t RP[CIPURSE_AES_KEY_LENGTH];
    uint8_t rP[CIPURSE_SECURITY_PARAM_N];
    uint8_t RT[CIPURSE_AES_KEY_LENGTH];
    uint8_t rT[CIPURSE_SECURITY_PARAM_N];

    uint8_t k0[CIPURSE_AES_KEY_LENGTH];
    uint8_t cP[CIPURSE_AES_KEY_LENGTH];
    uint8_t CT[CIPURSE_AES_KEY_LENGTH];

    uint8_t frameKey[CIPURSE_AES_KEY_LENGTH];
    uint8_t frameKeyNext[CIPURSE_AES_KEY_LENGTH];

    CipurseChannelSecurityLevel RequestSecurity;
    CipurseChannelSecurityLevel ResponseSecurity;
} CipurseContext_t;

uint8_t CipurseCSecurityLevelEnc(CipurseChannelSecurityLevel lvl);

void CipurseCClearContext(CipurseContext_t *ctx);
void CipurseCSetKey(CipurseContext_t *ctx, uint8_t keyId, uint8_t *key);
void CipurseCSetRandomFromPICC(CipurseContext_t *ctx, uint8_t *random);
void CipurseCSetRandomHost(CipurseContext_t *ctx);
uint8_t CipurseCGetSMI(CipurseContext_t *ctx, bool LePresent);

void CipurseCAuthenticateHost(CipurseContext_t *ctx, uint8_t *authdata);
bool CipurseCCheckCT(CipurseContext_t *ctx, uint8_t *CT);

void CipurseCChannelSetSecurityLevels(CipurseContext_t *ctx, CipurseChannelSecurityLevel req, CipurseChannelSecurityLevel resp);
bool isCipurseCChannelSecuritySet(CipurseContext_t *ctx);

void CipurseCGenerateMAC(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *mac);
void CipurseCCalcMACPadded(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *mac);
bool CipurseCCheckMACPadded(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *mac);
void CipurseCGenerateMIC(uint8_t *data, size_t datalen, uint8_t *mic);
bool CipurseCCheckMIC(uint8_t *data, size_t datalen, uint8_t *mic);
void CipurseCEncryptDecrypt(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *dstdata, bool isEncrypt);
void CipurseCChannelEncrypt(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *encdata, size_t *encdatalen);
void CipurseCChannelDecrypt(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *plaindata, size_t *plaindatalen);
void CipurseCGetKVV(uint8_t *key, uint8_t *kvv);

void CipurseCAPDUReqEncode(CipurseContext_t *ctx, sAPDU_t *srcapdu, sAPDU_t *dstapdu, uint8_t *dstdatabuf, bool includeLe, uint8_t Le);
void CipurseCAPDURespDecode(CipurseContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen, uint16_t *sw);


#endif /* __CIPURSECRYPTO_H__ */
