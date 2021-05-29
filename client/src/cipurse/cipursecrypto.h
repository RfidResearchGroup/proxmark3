//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CIPURSE crypto primitives
//-----------------------------------------------------------------------------

#ifndef __CIPURSECRYPTO_H__
#define __CIPURSECRYPTO_H__

#include "common.h"

#define CIPURSE_KVV_LENGTH 4
#define CIPURSE_AES_KEY_LENGTH 16
#define CIPURSE_SECURITY_PARAM_N 6
#define OSPT_MAC_LENGTH 8
#define CIPURSE_POLY 0x35b088cce172UL

#define member_size(type, member) sizeof(((type *)0)->member)

enum CipurseChannelSecurityLevel {
    CPSNone,
    CPSPlain,
    CPSMACed,
    CPSEncrypted
};

typedef struct CipurseContextS {
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
} CipurseContext;

void CipurseCClearContext(CipurseContext *ctx);
void CipurseCSetKey(CipurseContext *ctx, uint8_t keyId, uint8_t *key);
void CipurseCSetRandomFromPICC(CipurseContext *ctx, uint8_t *random);
void CipurseCSetRandomHost(CipurseContext *ctx);

void CipurseCAuthenticateHost(CipurseContext *ctx, uint8_t *authdata);


void CipurseCGetKVV(uint8_t *key, uint8_t *kvv);

#endif /* __CIPURSECRYPTO_H__ */
