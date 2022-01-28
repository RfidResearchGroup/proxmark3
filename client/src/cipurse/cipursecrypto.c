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

#include "cipursecrypto.h"

#include "commonutil.h"  // ARRAYLEN
#include "comms.h"       // DropField
#include "util_posix.h"  // msleep
#include <string.h>      // memcpy memset

#include "cmdhf14a.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "crypto/libpcrypto.h"
#include "ui.h"
#include "util.h"

uint8_t AESData0[CIPURSE_AES_KEY_LENGTH] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
uint8_t QConstant[CIPURSE_AES_KEY_LENGTH] = {0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74, 0x74};

uint8_t CipurseCSecurityLevelEnc(CipurseChannelSecurityLevel lvl) {
    switch (lvl) {
        case CPSNone:
            return 0x00;
        case CPSPlain:
            return 0x00;
        case CPSMACed:
            return 0x01;
        case CPSEncrypted:
            return 0x02;
        default:
            return 0x00;
    }
}

static void bin_ext(uint8_t *dst, size_t dstlen, uint8_t *src, size_t srclen) {
    if (srclen > dstlen)
        memcpy(dst, &src[srclen - dstlen], dstlen);
    else
        memcpy(dst, src, dstlen);
}

static void bin_pad(uint8_t *dst, size_t dstlen, uint8_t *src, size_t srclen) {
    memset(dst, 0, dstlen);
    if (srclen <= dstlen)
        memcpy(&dst[dstlen - srclen], src, srclen);
    else
        memcpy(dst, src, dstlen);
}

static void bin_pad2(uint8_t *dst, size_t dstlen, uint8_t *src, size_t srclen) {
    memset(dst, 0, dstlen);
    uint8_t dbl[srclen * 2];
    memcpy(dbl, src, srclen);
    memcpy(&dbl[srclen], src, srclen);
    bin_pad(dst, dstlen, dbl, srclen * 2);
}

static uint64_t rotateLeft48(uint64_t src) {
    uint64_t dst = src << 1;
    if (dst & 0x0001000000000000UL) {
        dst = dst | 1;
        dst = dst & 0x0000ffffffffffffUL;
    }
    return dst;
}

static uint64_t computeNLM48(uint64_t x, uint64_t y) {
    uint64_t res = 0;

    for (int i = 0; i < 48; i++) {
        res = rotateLeft48(res);
        if (res & 1)
            res = res ^ CIPURSE_POLY;
        y = rotateLeft48(y);
        if (y & 1)
            res = res ^ x;
    }
    return res;
}

static void computeNLM(uint8_t *res, const uint8_t *x, const uint8_t *y) {
    uint64_t x64 = 0;
    uint64_t y64 = 0;

    for (int i = 0; i < 6; i++) {
        x64 = (x64 << 8) | x[i];
        y64 = (y64 << 8) | y[i];
    }

    uint64_t res64 = computeNLM48(x64, y64);

    for (int i = 0; i < 6; i++) {
        res[5 - i] = res64 & 0xff;
        res64 = res64 >> 8;
    }
}

static void CipurseCGenerateK0AndCp(CipurseContext_t *ctx) {
    uint8_t temp1[CIPURSE_AES_KEY_LENGTH] = {0};
    uint8_t temp2[CIPURSE_AES_KEY_LENGTH] = {0};
    uint8_t kp[CIPURSE_SECURITY_PARAM_N] = {0};

    // session key derivation function
    // kP := NLM(EXT(kID), rP)
    // k0 := AES(key=PAD2(kP) XOR PAD(rT),kID) XOR kID
    bin_ext(temp1, CIPURSE_SECURITY_PARAM_N, ctx->key, CIPURSE_AES_KEY_LENGTH);
    computeNLM(kp, ctx->rP, temp1);  // param sizes == 6 bytes
    bin_pad2(temp1, CIPURSE_AES_KEY_LENGTH, kp, CIPURSE_SECURITY_PARAM_N);
    bin_pad(temp2, CIPURSE_AES_KEY_LENGTH, ctx->rT, CIPURSE_SECURITY_PARAM_N);
    bin_xor(temp1, temp2, CIPURSE_AES_KEY_LENGTH);

    // session key K0
    aes_encode(NULL, temp1, ctx->key, ctx->k0, CIPURSE_AES_KEY_LENGTH);
    bin_xor(ctx->k0, ctx->key, CIPURSE_AES_KEY_LENGTH);

    // first frame key k1, function to calculate k1,
    // k1 := AES(key = RP; k0 XOR RT) XOR (k0 XOR RT)
    memcpy(temp1, ctx->k0, CIPURSE_AES_KEY_LENGTH);
    bin_xor(temp1, ctx->RT, CIPURSE_AES_KEY_LENGTH);
    aes_encode(NULL, ctx->RP, temp1, temp2, CIPURSE_AES_KEY_LENGTH);
    bin_xor(temp1, temp2, CIPURSE_AES_KEY_LENGTH);
    memcpy(ctx->frameKey, temp1, CIPURSE_AES_KEY_LENGTH);

    // function to caluclate cP := AES(key=k0, RP).
    // terminal response
    aes_encode(NULL, ctx->k0, ctx->RP, ctx->cP, CIPURSE_AES_KEY_LENGTH);
}

static void CipurseCGenerateCT(uint8_t *k0, uint8_t *RT, uint8_t *CT) {
    aes_encode(NULL, k0, RT, CT, CIPURSE_AES_KEY_LENGTH);
}

// from: https://github.com/duychuongvn/cipurse-card-core/blob/master/src/main/java/com/github/duychuongvn/cirpusecard/core/security/securemessaging/CipurseSecureMessage.java#L68
void CipurseCGetKVV(uint8_t *key, uint8_t *kvv) {
    uint8_t res[16] = {0};
    aes_encode(NULL, key, AESData0, res, CIPURSE_AES_KEY_LENGTH);
    memcpy(kvv, res, CIPURSE_KVV_LENGTH);
}

void CipurseCClearContext(CipurseContext_t *ctx) {
    if (ctx == NULL)
        return;

    memset(ctx, 0, sizeof(CipurseContext_t));
}

void CipurseCSetKey(CipurseContext_t *ctx, uint8_t keyId, uint8_t *key) {
    if (ctx == NULL)
        return;

    CipurseCClearContext(ctx);

    ctx->keyId = keyId;
    memcpy(ctx->key, key, member_size(CipurseContext_t, key));
}

void CipurseCChannelSetSecurityLevels(CipurseContext_t *ctx, CipurseChannelSecurityLevel req, CipurseChannelSecurityLevel resp) {
    ctx->RequestSecurity = req;
    ctx->ResponseSecurity = resp;
}

bool isCipurseCChannelSecuritySet(CipurseContext_t *ctx) {
    return ((ctx->RequestSecurity != CPSNone) && (ctx->ResponseSecurity != CPSNone));
}

void CipurseCSetRandomFromPICC(CipurseContext_t *ctx, uint8_t *random) {
    if (ctx == NULL)
        return;

    memcpy(ctx->RP, random, member_size(CipurseContext_t, RP));
    memcpy(ctx->rP, random + member_size(CipurseContext_t, RP), member_size(CipurseContext_t, rP));
}

void CipurseCSetRandomHost(CipurseContext_t *ctx) {
    memset(ctx->RT, 0x10, member_size(CipurseContext_t, RT));
    memset(ctx->rT, 0x20, member_size(CipurseContext_t, rT));
}

uint8_t CipurseCGetSMI(CipurseContext_t *ctx, bool LePresent) {
    uint8_t res = LePresent ? 1 : 0;
    res = res | (CipurseCSecurityLevelEnc(ctx->ResponseSecurity) << 2);
    res = res | (CipurseCSecurityLevelEnc(ctx->RequestSecurity) << 6);
    return res;
}

static void CipurseCFillAuthData(CipurseContext_t *ctx, uint8_t *authdata) {
    memcpy(authdata, ctx->cP, member_size(CipurseContext_t, cP));
    memcpy(&authdata[member_size(CipurseContext_t, cP)], ctx->RT, member_size(CipurseContext_t, RT));
    memcpy(&authdata[member_size(CipurseContext_t, cP) + member_size(CipurseContext_t, RT)], ctx->rT, member_size(CipurseContext_t, rT));
}

void CipurseCAuthenticateHost(CipurseContext_t *ctx, uint8_t *authdata) {
    if (ctx == NULL)
        return;

    CipurseCSetRandomHost(ctx);
    CipurseCGenerateK0AndCp(ctx);
    CipurseCGenerateCT(ctx->k0, ctx->RT, ctx->CT);

    if (authdata != NULL)
        CipurseCFillAuthData(ctx, authdata);
}

bool CipurseCCheckCT(CipurseContext_t *ctx, uint8_t *CT) {
    return (memcmp(CT, ctx->CT, CIPURSE_AES_KEY_LENGTH) == 0);
}

static uint16_t CipurseCComputeMICCRC(const uint8_t *data, size_t len) {
    uint16_t initCRC = 0x6363;
    for (size_t i = 0; i < len; i++) {
        uint8_t ch = data[i] ^ initCRC;
        ch = ch ^ ((ch << 4) & 0xff);
        initCRC = (initCRC >> 8) ^ (ch << 8) ^ (ch << 3) ^ (ch >> 4);
    }
    return initCRC;
}

void CipurseCGenerateMIC(uint8_t *data, size_t datalen, uint8_t *mic) {
    size_t plen = 0;
    uint8_t pdata[datalen + CIPURSE_MIC_LENGTH];
    memset(pdata, 0, sizeof(pdata));

    // 0x00 padding
    memcpy(pdata, data, datalen);
    plen = datalen;
    if (datalen % CIPURSE_MIC_LENGTH)
        plen += CIPURSE_MIC_LENGTH - datalen % CIPURSE_MIC_LENGTH;

    // crc
    uint16_t crc1 = CipurseCComputeMICCRC(pdata, plen);

    for (size_t i = 0; i < datalen; i += 4) {
        uint8_t tmp1 = pdata[i + 0];
        uint8_t tmp2 = pdata[i + 1];
        pdata[i + 0] = pdata[i + 2];
        pdata[i + 1] = pdata[i + 3];
        pdata[i + 2] = tmp1;
        pdata[i + 3] = tmp2;
    }

    uint16_t crc2 = CipurseCComputeMICCRC(pdata, plen);
    if (mic != NULL) {
        mic[0] = crc2 >> 8;
        mic[1] = crc2 & 0xff;
        mic[2] = crc1 >> 8;
        mic[3] = crc1 & 0xff;
    }
}

bool CipurseCCheckMIC(uint8_t *data, size_t datalen, uint8_t *mic) {
    uint8_t xmic[CIPURSE_MIC_LENGTH] = {0};

    CipurseCGenerateMIC(data, datalen, xmic);
    return (memcmp(xmic, mic, CIPURSE_MIC_LENGTH) == 0);
}

/* from: https://github.com/duychuongvn/cipurse-card-core/blob/master/src/main/java/com/github/duychuongvn/cirpusecard/core/security/crypto/CipurseCrypto.java#L521
 *
 * Encrypt/Decrypt the given data using ciphering mechanism explained the OPST.
 * Data should be already padded.
 *
 * hx-1 := ki , hx := AES( key = hx-1 ; q) XOR q, Cx := AES( key = hx ;
 * Dx ), hx+1 := AES( key = hx ; q ) XOR q, Cx+1 := AES( key = hx+1 ;
 * Dx+1 ), ... hy := AES( key = hy-1 ; q ) XOR q, Cy := AES( key = hy ;
 * Dy ), ki+1 := hy
 */
void CipurseCEncryptDecrypt(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *dstdata, bool isEncrypt) {
    uint8_t hx[CIPURSE_AES_KEY_LENGTH] = {0};

    if (datalen == 0 || datalen % CIPURSE_AES_KEY_LENGTH != 0)
        return;

    memcpy(ctx->frameKeyNext, ctx->frameKey, CIPURSE_AES_KEY_LENGTH);
    int i = 0;
    while (datalen > i) {
        aes_encode(NULL, QConstant, ctx->frameKeyNext, hx, CIPURSE_AES_KEY_LENGTH);
        bin_xor(hx, ctx->frameKeyNext, CIPURSE_AES_KEY_LENGTH);

        if (isEncrypt)
            aes_encode(NULL, hx, &data[i], &dstdata[i], CIPURSE_AES_KEY_LENGTH);
        else
            aes_decode(NULL, hx, &data[i], &dstdata[i], CIPURSE_AES_KEY_LENGTH);

        memcpy(ctx->frameKeyNext, hx, CIPURSE_AES_KEY_LENGTH);
        i += CIPURSE_AES_KEY_LENGTH;
    }
    memcpy(ctx->frameKey, ctx->frameKeyNext, CIPURSE_AES_KEY_LENGTH);
}

void CipurseCChannelEncrypt(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *encdata, size_t *encdatalen) {
    uint8_t pdata[datalen + CIPURSE_AES_KEY_LENGTH];
    size_t pdatalen = 0;
    AddISO9797M2Padding(pdata, &pdatalen, data, datalen, CIPURSE_AES_KEY_LENGTH);

    CipurseCEncryptDecrypt(ctx, pdata, pdatalen, encdata, true);
    *encdatalen = pdatalen;
}

void CipurseCChannelDecrypt(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *plaindata, size_t *plaindatalen) {
    CipurseCEncryptDecrypt(ctx, data, datalen, plaindata, false);
    *plaindatalen = FindISO9797M2PaddingDataLen(plaindata, datalen);
}

/* from: https://github.com/duychuongvn/cipurse-card-core/blob/master/src/main/java/com/github/duychuongvn/cirpusecard/core/security/crypto/CipurseCrypto.java#L473
 *
 * Generate OSPT MAC on the given input data.
 * Data should be already padded.
 *
 * Calculation of Mi and ki+1: hx := ki , hx+1 := AES( key = hx ; Dx )
 * XOR Dx , hx+2 := AES( key = hx+1 ; Dx+1 ) XOR Dx+1, hx+3 := AES( key =
 * hx+2 ; Dx+2 ) XOR Dx+2, ... hy+1 := AES( key = hy ; Dy ) XOR Dy, ki+1 :=
 * hy+1 M'i := AES( key = ki ; ki+1 ) XOR ki+1, Mi := m LS bits of M'i = (
 * (M'i )0, (M'i )1, ..., (M'i )m-1)
 */
void CipurseCGenerateMAC(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *mac) {
    uint8_t temp[CIPURSE_AES_KEY_LENGTH] = {0};

    memcpy(ctx->frameKeyNext, ctx->frameKey, CIPURSE_AES_KEY_LENGTH);
    int i = 0;
    while (datalen > i) {
        aes_encode(NULL, ctx->frameKeyNext, &data[i], temp, CIPURSE_AES_KEY_LENGTH);
        bin_xor(temp, &data[i], CIPURSE_AES_KEY_LENGTH);
        memcpy(ctx->frameKeyNext, temp, CIPURSE_AES_KEY_LENGTH);
        i += CIPURSE_AES_KEY_LENGTH;
    }

    aes_encode(NULL, ctx->frameKey, ctx->frameKeyNext, temp, CIPURSE_AES_KEY_LENGTH);
    bin_xor(temp, ctx->frameKeyNext, CIPURSE_AES_KEY_LENGTH);
    memcpy(ctx->frameKey, ctx->frameKeyNext, CIPURSE_AES_KEY_LENGTH);
    if (mac != NULL)
        memcpy(mac, temp, CIPURSE_MAC_LENGTH);
}

void CipurseCCalcMACPadded(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *mac) {
    uint8_t pdata[datalen + CIPURSE_AES_KEY_LENGTH];
    size_t pdatalen = 0;
    AddISO9797M2Padding(pdata, &pdatalen, data, datalen, CIPURSE_AES_KEY_LENGTH);
    CipurseCGenerateMAC(ctx, pdata, pdatalen, mac);
}

bool CipurseCCheckMACPadded(CipurseContext_t *ctx, uint8_t *data, size_t datalen, uint8_t *mac) {
    uint8_t xmac[CIPURSE_MAC_LENGTH] = {0};
    CipurseCCalcMACPadded(ctx, data, datalen, xmac);
    return (memcmp(mac, xmac, CIPURSE_MAC_LENGTH) == 0);
}

static void CipurseCAPDUMACEncode(CipurseContext_t *ctx, sAPDU_t *apdu, uint8_t originalLc, uint8_t *data, size_t *datalen) {
    data[0] = apdu->CLA;
    data[1] = apdu->INS;
    data[2] = apdu->P1;
    data[3] = apdu->P2;
    data[4] = apdu->Lc;
    *datalen = 5 + apdu->Lc;

    if (ctx->RequestSecurity == CPSMACed || ctx->RequestSecurity == CPSEncrypted)
        *datalen = 5 + originalLc;
    memcpy(&data[5], apdu->data, *datalen);
}

void CipurseCAPDUReqEncode(CipurseContext_t *ctx, sAPDU_t *srcapdu, sAPDU_t *dstapdu, uint8_t *dstdatabuf, bool includeLe, uint8_t Le) {
    uint8_t mac[CIPURSE_MAC_LENGTH] = {0};
    uint8_t buf[260] = {0};
    size_t buflen = 0;

    memcpy(dstapdu, srcapdu, sizeof(sAPDU_t));

    if (isCipurseCChannelSecuritySet(ctx) == false)
        return;

    dstapdu->CLA |= 0x04;
    dstapdu->data = dstdatabuf;
    dstapdu->data[0] = CipurseCGetSMI(ctx, includeLe);
    dstapdu->Lc++;
    memcpy(&dstdatabuf[1], srcapdu->data, srcapdu->Lc);
    if (includeLe) {
        dstapdu->data[dstapdu->Lc] = Le;
        dstapdu->Lc++;
    }
    uint8_t originalLc = dstapdu->Lc;

    switch (ctx->RequestSecurity) {
        case CPSNone:
            break;
        case CPSPlain:
            CipurseCAPDUMACEncode(ctx, dstapdu, originalLc, buf, &buflen);
            CipurseCCalcMACPadded(ctx, buf, buflen, NULL);
            break;
        case CPSMACed:
            dstapdu->Lc += CIPURSE_MAC_LENGTH;
            CipurseCAPDUMACEncode(ctx, dstapdu, originalLc, buf, &buflen);
            CipurseCCalcMACPadded(ctx, buf, buflen, mac);
            memcpy(&dstdatabuf[dstapdu->Lc - CIPURSE_MAC_LENGTH], mac, CIPURSE_MAC_LENGTH);
            break;
        case CPSEncrypted:
            dstapdu->Lc = srcapdu->Lc + CIPURSE_MIC_LENGTH;
            dstapdu->Lc += CIPURSE_AES_BLOCK_LENGTH - dstapdu->Lc % CIPURSE_AES_BLOCK_LENGTH + 1; // 1 - SMI
            if (includeLe)
                dstapdu->Lc++;

            CipurseCAPDUMACEncode(ctx, dstapdu, originalLc, buf, &buflen);
            CipurseCGenerateMIC(buf, buflen, mac);
            buf[0] = dstapdu->CLA;
            buf[1] = dstapdu->INS;
            buf[2] = dstapdu->P1;
            buf[3] = dstapdu->P2;
            memcpy(&buf[4], srcapdu->data, srcapdu->Lc);
            memcpy(&buf[4 + srcapdu->Lc], mac, CIPURSE_MIC_LENGTH);
            //PrintAndLogEx(INFO, "data plain[%d]: %s", 4 + srcapdu->Lc + CIPURSE_MIC_LENGTH, sprint_hex(buf, 4 + srcapdu->Lc + CIPURSE_MIC_LENGTH));
            CipurseCChannelEncrypt(ctx, buf, 4 + srcapdu->Lc + CIPURSE_MIC_LENGTH, &dstdatabuf[1], &buflen);
            break;
        default:
            break;
    }

}

void CipurseCAPDURespDecode(CipurseContext_t *ctx, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, size_t *dstdatalen, uint16_t *sw) {
    uint8_t buf[260] = {0};
    size_t buflen = 0;
    uint8_t micdata[260] = {0};
    size_t micdatalen = 0;

    if (dstdatalen != NULL)
        *dstdatalen = 0;
    if (sw != NULL)
        *sw = 0;

    if (srcdatalen < 2)
        return;

    srcdatalen -= 2;
    uint16_t xsw = srcdata[srcdatalen] * 0x0100 + srcdata[srcdatalen + 1];
    if (sw)
        *sw = xsw;

    if (isCipurseCChannelSecuritySet(ctx) == false) {
        memcpy(dstdata, srcdata, srcdatalen);
        if (dstdatalen != NULL)
            *dstdatalen = srcdatalen;
        return;
    }

    switch (ctx->ResponseSecurity) {
        case CPSNone:
            break;
        case CPSPlain:
            memcpy(buf, srcdata, srcdatalen);
            buflen = srcdatalen;
            memcpy(&buf[buflen], &srcdata[srcdatalen], 2);
            buflen += 2;
            CipurseCCalcMACPadded(ctx, buf, buflen, NULL);

            memcpy(dstdata, srcdata, srcdatalen);
            if (dstdatalen != NULL)
                *dstdatalen = srcdatalen;
            break;
        case CPSMACed:
            if (srcdatalen < CIPURSE_MAC_LENGTH)
                return;

            buflen = srcdatalen - CIPURSE_MAC_LENGTH;
            memcpy(buf, srcdata, buflen);
            memcpy(&buf[buflen], &srcdata[srcdatalen], 2);
            buflen += 2;

            srcdatalen -= CIPURSE_MAC_LENGTH;
            if (CipurseCCheckMACPadded(ctx, buf, buflen, &srcdata[srcdatalen]) == false) {
                PrintAndLogEx(WARNING, "APDU MAC is not valid!");
            }
            memcpy(dstdata, srcdata, srcdatalen);
            if (dstdatalen != NULL)
                *dstdatalen = srcdatalen;
            break;
        case CPSEncrypted:
            CipurseCChannelDecrypt(ctx, srcdata, srcdatalen, buf, &buflen);
            //PrintAndLogEx(INFO, "data plain[%d]: %s", buflen, sprint_hex(buf, buflen));

            if (buflen == 0) {
                PrintAndLogEx(ERR, "APDU can't decode crypto stream");
                break;
            }

            micdatalen = buflen - 2 - CIPURSE_MIC_LENGTH;
            memcpy(micdata, buf, buflen);
            memcpy(&micdata[micdatalen], &buf[buflen - 2], 2);
            micdatalen += 2;

            if (CipurseCCheckMIC(micdata, micdatalen, &buf[micdatalen - 2]) == false) {
                PrintAndLogEx(ERR, "APDU response MIC is not valid!");
            }

            memcpy(dstdata, buf, micdatalen - 2);
            if (dstdatalen != NULL)
                *dstdatalen = micdatalen - 2;
            if (sw)
                *sw = micdata[micdatalen - 2] * 0x0100 + micdata[micdatalen - 1];
            break;
        default:
            break;
    }

}
