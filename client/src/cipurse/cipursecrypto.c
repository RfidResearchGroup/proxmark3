//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CIPURSE crypto primitives
//-----------------------------------------------------------------------------

#include "cipursecrypto.h"

#include "commonutil.h"  // ARRAYLEN
#include "comms.h"       // DropField
#include "util_posix.h"  // msleep

#include "cmdhf14a.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "crypto/libpcrypto.h"
#include "ui.h"
#include "util.h"

uint8_t AESData0[CIPURSE_AES_KEY_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static void CipurseCGenerateK0AndGetCp(CipurseContext *ctx) {

}

static void CipurseCGenerateCT(uint8_t *RT, uint8_t *CT) {
    
}

void CipurseCGetKVV(uint8_t *key, uint8_t *kvv) {
    uint8_t res[16] = {0};
    aes_encode(NULL, key, AESData0, res, CIPURSE_AES_KEY_LENGTH);
    memcpy(kvv, res, CIPURSE_KVV_LENGTH);
}

void CipurseCClearContext(CipurseContext *ctx) {
    if (ctx == NULL)
        return;
    
    memset(ctx, 0, sizeof(CipurseContext));
}

void CipurseCSetKey(CipurseContext *ctx, uint8_t keyId, uint8_t *key) {
    if (ctx == NULL)
        return;
    
    CipurseCClearContext(ctx);
    
    ctx->keyId = keyId;
    memcpy(ctx->key, key, member_size(CipurseContext, key));
}

void CipurseCSetRandomFromPICC(CipurseContext *ctx, uint8_t *random) {
    if (ctx == NULL)
        return;
      
    memcpy(ctx->RP, random, member_size(CipurseContext, RP));
    memcpy(ctx->rP, random + member_size(CipurseContext, RP), member_size(CipurseContext, rP));
}

void CipurseCSetRandomHost(CipurseContext *ctx) {
    memset(ctx->RT, 0x10, member_size(CipurseContext, RT));
    memset(ctx->rT, 0x20, member_size(CipurseContext, rT));
}

static void CipurseCFillAuthData(CipurseContext *ctx, uint8_t *authdata) {
    memcpy(authdata, ctx->cP, member_size(CipurseContext, cP));
    memcpy(&authdata[member_size(CipurseContext, cP)], ctx->RT, member_size(CipurseContext, RT));
    memcpy(&authdata[member_size(CipurseContext, cP) + member_size(CipurseContext, RT)], ctx->rT, member_size(CipurseContext, rT));   
}

void CipurseCAuthenticateHost(CipurseContext *ctx, uint8_t *authdata) {
    if (ctx == NULL)
        return;
    
    CipurseCSetRandomHost(ctx);
    CipurseCGenerateK0AndGetCp(ctx);
    CipurseCGenerateCT(ctx->RT, ctx->CT);

    if (authdata != NULL)
        CipurseCFillAuthData(ctx, authdata);
}
