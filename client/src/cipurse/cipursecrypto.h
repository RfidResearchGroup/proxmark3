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

#define member_size(type, member) sizeof(((type *)0)->member)

enum CipurseChannelSecurityLevel {
    CPSNone,
    CPSPlain,
    CPSMACed,
    CPSEncrypted
};

typedef struct CipurseContextS {
    uint8_t keyId;
    uint8_t key[16];
    
    uint8_t RP[16];
    uint8_t rP[6];
    uint8_t RT[16];
    uint8_t rT[6];
    
    uint8_t frameKey0[16];
    uint8_t cP[16];
    
    uint8_t frameKey[16];
    uint8_t frameKeyNext[16];
} CipurseContext;

void CipurseClearContext(CipurseContext *ctx);
void CipurseSetKey(CipurseContext *ctx, uint8_t keyId, uint8_t *key);
void CipurseSetRandomFromPICC(CipurseContext *ctx, uint8_t *random);
void CipurseSetRandomHost(CipurseContext *ctx);

void CipurseAuthenticateHost(CipurseContext *ctx);




#endif /* __CIPURSECRYPTO_H__ */
