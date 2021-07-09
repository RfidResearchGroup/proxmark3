/*-
 * Copyright (C) 2010, Romain Tartiere.
 * Copyright (C) 2021 Merlok
 *
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 *
 * $Id$
 */

#include "desfirecrypto.h"

#include <stdlib.h>
#include <string.h>
#include <util.h>
#include "ui.h"
#include "aes.h"
#include "des.h"
#include <mbedtls/cmac.h>
#include "crc.h"
#include "crc16.h"        // crc16 ccitt
#include "crc32.h"
#include "commonutil.h"
#include "mifare/desfire_crypto.h"

void DesfireClearContext(DesfireContext *ctx) {
    ctx->keyNum = 0;
    ctx->keyType = T_DES;
    memset(ctx->key, 0, sizeof(ctx->key));

    ctx->secureChannel = DACNone;
    ctx->cmdSet = DCCNative;
    ctx->commMode = DCMNone;

    ctx->kdfAlgo = 0;
    ctx->kdfInputLen = 0;
    memset(ctx->kdfInput, 0, sizeof(ctx->kdfInput));

    DesfireClearSession(ctx);
}

void DesfireClearSession(DesfireContext *ctx) {
    ctx->secureChannel = DACNone; // here none - not authenticared

    memset(ctx->IV, 0, sizeof(ctx->IV));
    memset(ctx->sessionKeyMAC, 0, sizeof(ctx->sessionKeyMAC));
    memset(ctx->sessionKeyEnc, 0, sizeof(ctx->sessionKeyEnc));
    memset(ctx->lastIV, 0, sizeof(ctx->lastIV));
    ctx->lastCommand = 0;
    ctx->lastRequestZeroLen = false;
    ctx->cntrTx = 0;
    ctx->cntrRx = 0;
    memset(ctx->TI, 0, sizeof(ctx->TI));
}

void DesfireSetKey(DesfireContext *ctx, uint8_t keyNum, enum DESFIRE_CRYPTOALGO keyType, uint8_t *key) {
    DesfireClearContext(ctx);

    ctx->keyNum = keyNum;
    ctx->keyType = keyType;
    memcpy(ctx->key, key, desfire_get_key_length(keyType));
}

void DesfireSetCommandSet(DesfireContext *ctx, DesfireCommandSet cmdSet) {
    ctx->cmdSet = cmdSet;
}

void DesfireSetCommMode(DesfireContext *ctx, DesfireCommunicationMode commMode) {
    ctx->commMode = commMode;
}

void DesfireSetKdf(DesfireContext *ctx, uint8_t kdfAlgo, uint8_t *kdfInput, uint8_t kdfInputLen) {
    ctx->kdfAlgo = kdfAlgo;
    ctx->kdfInputLen = kdfInputLen;
    if (kdfInputLen)
        memcpy(ctx->kdfInput, kdfInput, kdfInputLen);
}

bool DesfireIsAuthenticated(DesfireContext *dctx) {
    return dctx->secureChannel != DACNone;
}

size_t DesfireGetMACLength(DesfireContext *ctx) {
    size_t mac_length = MAC_LENGTH;
    switch (ctx->secureChannel) {
        case DACNone:
            mac_length = 0;
            break;
        case DACd40:
            mac_length = 4;
            break;
        case DACEV1:
            mac_length = 8;
            break;
        case DACEV2:
            mac_length = 8;
            break;
    }
    return mac_length;
}

size_t DesfireSearchCRCPos(uint8_t *data, size_t datalen, uint8_t respcode, uint8_t crclen) {
    size_t crcpos = datalen - 1;
    while (crcpos > 0)
        if (data[crcpos] == 0)
            crcpos--;
        else
            break;
    crcpos++; // crc may be 0x00000000 or 0x0000
    PrintAndLogEx(INFO, "crcpos: %d", crcpos);
    if (crcpos < crclen) {
        PrintAndLogEx(WARNING, "No space for crc. pos: %d", crcpos);
        return 0;
    }

    uint8_t crcdata[1024] = {0};
    bool crcok = false;
    for (int i = 0; i < crclen + 1; i++) {
    PrintAndLogEx(INFO, "--crcpos: %d", crcpos - i);
        if (crcpos - i == 0)
            break;
        if (crcpos - i + crclen > datalen)
            continue;
    PrintAndLogEx(INFO, "--crcposcheck: %d", crcpos - i);
        
        memcpy(crcdata, data, crcpos - i);
        crcdata[crcpos - i] = respcode;
        bool res;
        if (crclen == 4)
            res = desfire_crc32_check(crcdata, crcpos - i + 1, &data[crcpos - i]);
        else
            res = iso14443a_crc_check(crcdata, crcpos - i + 1, &data[crcpos - i]);
        if (res) {
    PrintAndLogEx(INFO, "--crc OK pos: %d", crcpos - i);
            crcpos -= i;
            crcok = true;
            break;
        }
    }
    if (!crcok)
        crcpos = 0;
    
    return crcpos;
}

static void DesfireCryptoEncDecSingleBlock(uint8_t *key, DesfireCryptoAlgorythm keyType, uint8_t *data, uint8_t *dstdata, uint8_t *ivect, bool dir_to_send, bool encode) {
    size_t block_size = desfire_get_key_block_length(keyType);
    uint8_t sdata[MAX_CRYPTO_BLOCK_SIZE] = {0};
    memcpy(sdata, data, block_size);
    if (dir_to_send) {
        bin_xor(sdata, ivect, block_size);
    }

    uint8_t edata[MAX_CRYPTO_BLOCK_SIZE] = {0};

    switch (keyType) {
        case T_DES:
            if (encode)
                des_encrypt(edata, sdata, key);
            else
                des_decrypt(edata, sdata, key);
            break;
        case T_3DES:
            if (encode) {
                mbedtls_des3_context ctx3;
                mbedtls_des3_set2key_enc(&ctx3, key);
                mbedtls_des3_crypt_ecb(&ctx3, sdata, edata);
            } else {
                mbedtls_des3_context ctx3;
                mbedtls_des3_set2key_dec(&ctx3, key);
                mbedtls_des3_crypt_ecb(&ctx3, sdata, edata);
            }
            break;
        case T_3K3DES:
            if (encode) {
                mbedtls_des3_context ctx3;
                mbedtls_des3_set3key_enc(&ctx3, key);
                mbedtls_des3_crypt_ecb(&ctx3, sdata, edata);
            } else {
                mbedtls_des3_context ctx3;
                mbedtls_des3_set3key_dec(&ctx3, key);
                mbedtls_des3_crypt_ecb(&ctx3, sdata, edata);
            }
            break;
        case T_AES:
            if (encode) {
                mbedtls_aes_context actx;
                mbedtls_aes_init(&actx);
                mbedtls_aes_setkey_enc(&actx, key, 128);
                mbedtls_aes_crypt_ecb(&actx, MBEDTLS_AES_ENCRYPT, sdata, edata);
                mbedtls_aes_free(&actx);
            } else {
                mbedtls_aes_context actx;
                mbedtls_aes_init(&actx);
                mbedtls_aes_setkey_dec(&actx, key, 128);
                mbedtls_aes_crypt_ecb(&actx, MBEDTLS_AES_DECRYPT, sdata, edata);
                mbedtls_aes_free(&actx);
            }
            break;
    }

    if (dir_to_send) {
        memcpy(ivect, edata, block_size);
    } else {
        bin_xor(edata, ivect, block_size);
        memcpy(ivect, data, block_size);
    }

    memcpy(dstdata, edata, block_size);
}

void DesfireCryptoEncDecEx(DesfireContext *ctx, bool use_session_key, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode, uint8_t *iv) {
    uint8_t data[1024] = {0};
    uint8_t xiv[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};

    if (ctx->secureChannel == DACd40)
        memset(ctx->IV, 0, DESFIRE_MAX_CRYPTO_BLOCK_SIZE);

    size_t block_size = desfire_get_key_block_length(ctx->keyType);

    if (iv == NULL)
        memcpy(xiv, ctx->IV, block_size);
    else
        memcpy(xiv, iv, block_size);

    size_t offset = 0;
    while (offset < srcdatalen) {
        if (use_session_key)
            DesfireCryptoEncDecSingleBlock(ctx->sessionKeyMAC, ctx->keyType, srcdata + offset, data + offset, xiv, encode, encode);
        else
            DesfireCryptoEncDecSingleBlock(ctx->key, ctx->keyType, srcdata + offset, data + offset, xiv, encode, encode);
        offset += block_size;
    }

    if (iv == NULL)
        memcpy(ctx->IV, xiv, block_size);
    else
        memcpy(iv, xiv, block_size);

    if (dstdata)
        memcpy(dstdata, data, srcdatalen);
}

void DesfireCryptoEncDec(DesfireContext *ctx, bool use_session_key, uint8_t *srcdata, size_t srcdatalen, uint8_t *dstdata, bool encode) {
    DesfireCryptoEncDecEx(ctx, use_session_key, srcdata, srcdatalen, dstdata, encode, NULL);
}

static void DesfireCMACGenerateSubkeys(DesfireContext *ctx, uint8_t *sk1, uint8_t *sk2) {
    int kbs = desfire_get_key_block_length(ctx->keyType);
    const uint8_t R = (kbs == 8) ? 0x1B : 0x87;

    uint8_t l[kbs];
    memset(l, 0, kbs);

    uint8_t ivect[kbs];
    memset(ivect, 0, kbs);

    DesfireCryptoEncDecEx(ctx, true, l, kbs, l, true, ivect);

    bool txor = false;

    // Used to compute CMAC on complete blocks
    memcpy(sk1, l, kbs);
    txor = l[0] & 0x80;
    lsl(sk1, kbs);
    if (txor) {
        sk1[kbs - 1] ^= R;
    }

    // Used to compute CMAC on the last block if non-complete
    memcpy(sk2, sk1, kbs);
    txor = sk1[0] & 0x80;
    lsl(sk2, kbs);
    if (txor) {
        sk2[kbs - 1] ^= R;
    }
}

void DesfireCryptoCMAC(DesfireContext *ctx, uint8_t *data, size_t len, uint8_t *cmac) {
    int kbs = desfire_get_key_block_length(ctx->keyType);
    if (kbs == 0)
        return;

    uint8_t buffer[padded_data_length(len, kbs)];
    memset(buffer, 0, sizeof(buffer));

    uint8_t sk1[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    uint8_t sk2[DESFIRE_MAX_CRYPTO_BLOCK_SIZE] = {0};
    DesfireCMACGenerateSubkeys(ctx, sk1, sk2);

    memcpy(buffer, data, len);

    if ((!len) || (len % kbs)) {
        buffer[len++] = 0x80;
        while (len % kbs) {
            buffer[len++] = 0x00;
        }
        bin_xor(buffer + len - kbs, sk2, kbs);
    } else {
        bin_xor(buffer + len - kbs, sk1, kbs);
    }

    DesfireCryptoEncDec(ctx, true, buffer, len, NULL, true);

    if (cmac != NULL)
        memcpy(cmac, ctx->IV, kbs);
}

