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

static void CipurseCGenerateK0AndCp(CipurseContext *ctx) {
    /*        // session key derivation function
        // kP := NLM(EXT(kID), rP)
        // k0 := AES(key=PAD2(kP) XOR PAD(rT),kID) XOR kID
        var temp1 = CryptoUtils.extFunction(kid, CIPURSE_SECURITY_PARAM_N) ?: return null
        val kp = CryptoUtils.computeNLM(rP, temp1) ?: return null
        temp1 = CryptoUtils.pad2(kp) ?: return null
        val temp2 = CryptoUtils.pad(rT) ?: return null
        temp1 = temp1 xor temp2

        // session key K0
        k0 = AesECB.aesEncrypt(temp1, kid) ?: return null
        k0 = k0 xor kid

        // first frame key k1, function to calculate k1,
        // k1 := AES(key = RP; k0 XOR RT) XOR (k0 XOR RT)
        temp1 = k0 xor RT
        val temp3: ByteArray = AesECB.aesEncrypt(RP, temp1) ?: return null
        frameKeyi = temp3 xor temp1
        Log.d(TAG, "frame key=${Utils.toHex(frameKeyi)}")

        // function to caluclate cP := AES(key=k0, RP).
        // terminal response
        return AesECB.aesEncrypt(k0, RP)*/
        
    uint8_t temp1[CIPURSE_AES_KEY_LENGTH] = {0};
    uint8_t temp2[CIPURSE_AES_KEY_LENGTH] = {0};
        
    // session key derivation function
    // kP := NLM(EXT(kID), rP)
    // k0 := AES(key=PAD2(kP) XOR PAD(rT),kID) XOR kID  
        
    // session key K0    
        
    // first frame key k1, function to calculate k1,
    // k1 := AES(key = RP; k0 XOR RT) XOR (k0 XOR RT)
        
    // function to caluclate cP := AES(key=k0, RP).
    // terminal response
    aes_encode(NULL, ctx->k0, ctx->RP, ctx->Cp, CIPURSE_AES_KEY_LENGTH);
}

static void CipurseCGenerateCT(uint8_t *k0, uint8_t *RT, uint8_t *CT) {
    aes_encode(NULL, k0, RT, CT, CIPURSE_AES_KEY_LENGTH);
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
    CipurseCGenerateK0AndCp(ctx);
    CipurseCGenerateCT(ctx->k0, ctx->RT, ctx->CT);

    if (authdata != NULL)
        CipurseCFillAuthData(ctx, authdata);
}
