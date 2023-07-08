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
// crypto commands
//-----------------------------------------------------------------------------

#include "crypto/libpcrypto.h"
#include "crypto/asn1utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mbedtls/asn1.h>
#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/blowfish.h>
#include "libpcrypto.h"
#include "util.h"
#include "ui.h"
#include "math.h"

void des_encrypt(void *out, const void *in, const void *key) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

void des_decrypt(void *out, const void *in, const void *key) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

void des_encrypt_ecb(void *out, const void *in, const int length, const void *key) {
    for (int i = 0; i < length; i += 8)
        des_encrypt((uint8_t *)out + i, (uint8_t *)in + i, key);
}

void des_decrypt_ecb(void *out, const void *in, const int length, const void *key) {
    for (int i = 0; i < length; i += 8)
        des_decrypt((uint8_t *)out + i, (uint8_t *)in + i, key);
}

void des_encrypt_cbc(void *out, const void *in, const int length, const void *key, uint8_t *iv) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, length, iv, in, out);
}

void des_decrypt_cbc(void *out, const void *in, const int length, const void *key, uint8_t *iv) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, length, iv, in, out);
}

void des3_encrypt(void *out, const void *in, const void *key, uint8_t keycount) {
    switch (keycount) {
        case 1:
            des_encrypt(out, in, key);
            break;
        case 2: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set2key_enc(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        case 3: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set3key_enc(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        default:
            break;
    }
}

void des3_decrypt(void *out, const void *in, const void *key, uint8_t keycount) {
    switch (keycount) {
        case 1:
            des_encrypt(out, in, key);
            break;
        case 2: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set2key_dec(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        case 3: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set3key_dec(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        default:
            break;
    }
}

// NIST Special Publication 800-38A — Recommendation for block cipher modes of operation: methods and techniques, 2001.
int aes_encode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0};
    if (iv)
        memcpy(iiv, iv, 16);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128))
        return 1;
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iiv, input, output))
        return 2;
    mbedtls_aes_free(&aes);

    return 0;
}

int aes_decode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0};
    if (iv)
        memcpy(iiv, iv, 16);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_dec(&aes, key, 128))
        return 1;
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iiv, input, output))
        return 2;
    mbedtls_aes_free(&aes);

    return 0;
}

// NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
int aes_cmac(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
    memset(mac, 0x00, 16);

    //  NIST 800-38B
    return mbedtls_aes_cmac_prf_128(key, MBEDTLS_AES_BLOCK_SIZE, input, length, mac);
}

int aes_cmac8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
    uint8_t cmac_tmp[16] = {0};
    memset(mac, 0x00, 8);

    int res = aes_cmac(iv, key, input, cmac_tmp, length);
    if (res)
        return res;

    for (int i = 0; i < 8; i++)
        mac[i] = cmac_tmp[i * 2 + 1];

    return 0;
}

static uint8_t fixed_rand_value[250] = {0};
static int fixed_rand(void *rng_state, unsigned char *output, size_t len) {
    if (len <= 250) {
        memcpy(output, fixed_rand_value, len);
    } else {
        memset(output, 0x00, len);
    }

    return 0;
}

int sha1hash(uint8_t *input, int length, uint8_t *hash) {
    if (!hash || !input)
        return 1;

    mbedtls_sha1(input, length, hash);

    return 0;
}

int sha256hash(uint8_t *input, int length, uint8_t *hash) {
    if (!hash || !input)
        return 1;

    mbedtls_sha256_context sctx;
    mbedtls_sha256_init(&sctx);
    mbedtls_sha256_starts(&sctx, 0); // SHA-256, not 224
    mbedtls_sha256_update(&sctx, input, length);
    mbedtls_sha256_finish(&sctx, hash);
    mbedtls_sha256_free(&sctx);

    return 0;
}

int sha512hash(uint8_t *input, int length, uint8_t *hash) {
    if (!hash || !input)
        return 1;

    mbedtls_sha512_context sctx;
    mbedtls_sha512_init(&sctx);
    mbedtls_sha512_starts(&sctx, 0); //SHA-512, not 384
    mbedtls_sha512_update(&sctx, input, length);
    mbedtls_sha512_finish(&sctx, hash);
    mbedtls_sha512_free(&sctx);

    return 0;
}

static int ecdsa_init_str(mbedtls_ecdsa_context *ctx,  mbedtls_ecp_group_id curveid, const char *key_d, const char *key_x, const char *key_y) {
    if (!ctx)
        return 1;

    int res;

    mbedtls_ecdsa_init(ctx);
    res = mbedtls_ecp_group_load(&ctx->grp, curveid);
    if (res)
        return res;

    if (key_d) {
        res = mbedtls_mpi_read_string(&ctx->d, 16, key_d);
        if (res)
            return res;
    }

    if (key_x && key_y) {
        res = mbedtls_ecp_point_read_string(&ctx->Q, 16, key_x, key_y);
        if (res)
            return res;
    }

    return 0;
}

static int ecdsa_init(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id curveid, uint8_t *key_d, uint8_t *key_xy) {
    if (!ctx)
        return 1;

    int res;

    mbedtls_ecdsa_init(ctx);
    res = mbedtls_ecp_group_load(&ctx->grp, curveid);
    if (res)
        return res;

    size_t keylen = (ctx->grp.nbits + 7) / 8;
    if (key_d) {
        res = mbedtls_mpi_read_binary(&ctx->d, key_d, keylen);
        if (res)
            return res;
    }

    if (key_xy) {
        res = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q, key_xy, keylen * 2 + 1);
        if (res)
            return res;
    }

    return 0;
}

int ecdsa_key_create(mbedtls_ecp_group_id curveid, uint8_t *key_d, uint8_t *key_xy) {
    int res;
    mbedtls_ecdsa_context ctx;
    res = ecdsa_init(&ctx, curveid, NULL, NULL);
    if (res)
        goto exit;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsaproxmark";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (res)
        goto exit;

    res = mbedtls_ecdsa_genkey(&ctx, curveid, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (res)
        goto exit;

    size_t keylen = (ctx.grp.nbits + 7) / 8;
    res = mbedtls_mpi_write_binary(&ctx.d, key_d, keylen);
    if (res)
        goto exit;

    size_t public_keylen = 0;
    uint8_t public_key[200] = {0};
    res = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &public_keylen, public_key, sizeof(public_key));
    if (res)
        goto exit;

    if (public_keylen != 1 + 2 * keylen) { // 0x04 <key x><key y>
        res = 1;
        goto exit;
    }
    memcpy(key_xy, public_key, public_keylen);

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ctx);
    return res;
}

char *ecdsa_get_error(int ret) {
    static char retstr[300];
    memset(retstr, 0x00, sizeof(retstr));
    mbedtls_strerror(ret, retstr, sizeof(retstr));
    return retstr;
}

int ecdsa_public_key_from_pk(mbedtls_pk_context *pk,  mbedtls_ecp_group_id curveid, uint8_t *key, size_t keylen) {
    int res = 0;
    size_t realkeylen = 0;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    res = mbedtls_ecp_group_load(&ctx.grp, curveid);
    if (res)
        goto exit;

    size_t private_keylen = (ctx.grp.nbits + 7) / 8;
    if (keylen < 1 + 2 * private_keylen) {
        res = 1;
        goto exit;
    }

    res = mbedtls_ecdsa_from_keypair(&ctx, mbedtls_pk_ec(*pk));
    if (res)
        goto exit;

    res = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &realkeylen, key, keylen);
    if (realkeylen != 1 + 2 * private_keylen)
        res = 2;
exit:
    mbedtls_ecdsa_free(&ctx);
    return res;
}

int ecdsa_signature_create(mbedtls_ecp_group_id curveid, uint8_t *key_d, uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen, bool hash) {
    int res;
    *signaturelen = 0;

    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsaproxmark";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (res)
        goto exit;

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init(&ctx, curveid, key_d, key_xy);
    if (res)
        goto exit;

    res = mbedtls_ecdsa_write_signature(
              &ctx,
              MBEDTLS_MD_SHA256,
              hash ? shahash : input,
              hash ? sizeof(shahash) : length,
              signature,
              signaturelen,
              mbedtls_ctr_drbg_random,
              &ctr_drbg
          );


exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ctx);
    return res;
}

static int ecdsa_signature_create_test(mbedtls_ecp_group_id curveid, const char *key_d, const char *key_x, const char *key_y, const char *random, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen) {
    int res;
    *signaturelen = 0;

    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    int rndlen = 0;
    param_gethex_to_eol(random, 0, fixed_rand_value, sizeof(fixed_rand_value), &rndlen);

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init_str(&ctx, curveid, key_d, key_x, key_y);
    if (res)
        return res;

    res = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, shahash, sizeof(shahash), signature, signaturelen, fixed_rand, NULL);

    mbedtls_ecdsa_free(&ctx);
    return res;
}

static int ecdsa_signature_verify_keystr(mbedtls_ecp_group_id curveid, const char *key_x, const char *key_y, uint8_t *input, int length, uint8_t *signature, size_t signaturelen, bool hash) {
    int res;
    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init_str(&ctx, curveid, NULL, key_x, key_y);
    if (res)
        return res;

    res = mbedtls_ecdsa_read_signature(
              &ctx,
              hash ? shahash : input,
              hash ? sizeof(shahash) : length,
              signature,
              signaturelen
          );

    mbedtls_ecdsa_free(&ctx);
    return res;
}

int ecdsa_signature_verify(mbedtls_ecp_group_id curveid, uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t signaturelen, bool hash) {
    int res;
    uint8_t shahash[32] = {0};
    if (hash) {
        res = sha256hash(input, length, shahash);
        if (res)
            return res;
    }

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init(&ctx, curveid, NULL, key_xy);
    if (res)
        return res;

    res = mbedtls_ecdsa_read_signature(
              &ctx,
              hash ? shahash : input,
              hash ? sizeof(shahash) : length,
              signature,
              signaturelen
          );

    mbedtls_ecdsa_free(&ctx);
    return res;
}

// take signature bytes,  converts to ASN1 signature and tries to verify
int ecdsa_signature_r_s_verify(mbedtls_ecp_group_id curveid, uint8_t *key_xy, uint8_t *input, int length, uint8_t *r_s, size_t r_s_len, bool hash) {
    uint8_t signature[MBEDTLS_ECDSA_MAX_LEN] = {0};
    size_t signature_len = 0;

    // convert r & s to ASN.1 signature
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&r, r_s, r_s_len / 2);
    mbedtls_mpi_read_binary(&s, r_s + r_s_len / 2, r_s_len / 2);

    int res = ecdsa_signature_to_asn1(&r, &s, signature, &signature_len);
    if (res < 0) {
        return res;
    }

    res = ecdsa_signature_verify(curveid, key_xy, input, length, signature, signature_len, hash);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return res;
}


#define T_PRIVATE_KEY "C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96"
#define T_Q_X         "B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19"
#define T_Q_Y         "3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09"
#define T_K           "7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE"
#define T_R           "2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F"
#define T_S           "DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1"

int ecdsa_nist_test(bool verbose) {
    int res;
    uint8_t input[] = "Example of ECDSA with P-256";
    mbedtls_ecp_group_id curveid = MBEDTLS_ECP_DP_SECP256R1;
    int length = strlen((char *)input);
    uint8_t signature[300] = {0};
    size_t siglen = 0;

    // NIST ecdsa test
    if (verbose)
        PrintAndLogEx(INFO, "  ECDSA NIST test: " NOLF);
    // make signature
    res = ecdsa_signature_create_test(curveid, T_PRIVATE_KEY, T_Q_X, T_Q_Y, T_K, input, length, signature, &siglen);
// PrintAndLogEx(INFO, "res: %x signature[%x]: %s", (res < 0)? -res : res, siglen, sprint_hex(signature, siglen));
    if (res != PM3_SUCCESS)
        goto exit;

    // check vectors
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(signature, siglen, rval, sval);
    if (res)
        goto exit;

    int slen = 0;
    uint8_t rval_s[33] = {0};
    param_gethex_to_eol(T_R, 0, rval_s, sizeof(rval_s), &slen);
    uint8_t sval_s[33] = {0};
    param_gethex_to_eol(T_S, 0, sval_s, sizeof(sval_s), &slen);
    if (strncmp((char *)rval, (char *)rval_s, 32) || strncmp((char *)sval, (char *)sval_s, 32)) {
        PrintAndLogEx(INFO, "R or S check error");
        res = 100;
        goto exit;
    }

    // verify signature
    res = ecdsa_signature_verify_keystr(curveid, T_Q_X, T_Q_Y, input, length, signature, siglen, true);
    if (res)
        goto exit;

    // verify wrong signature
    input[0] ^= 0xFF;
    res = ecdsa_signature_verify_keystr(curveid, T_Q_X, T_Q_Y, input, length, signature, siglen, true);
    if (res == false) {
        res = 1;
        goto exit;
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, _GREEN_("passed"));
        PrintAndLogEx(INFO, "  ECDSA binary signature create/check test: " NOLF);
    }

    // random ecdsa test
    uint8_t key_d[32] = {0};
    uint8_t key_xy[32 * 2 + 2] = {0};
    memset(signature, 0x00, sizeof(signature));
    siglen = 0;

    res = ecdsa_key_create(curveid, key_d, key_xy);
    if (res)
        goto exit;

    res = ecdsa_signature_create(curveid, key_d, key_xy, input, length, signature, &siglen, true);
    if (res)
        goto exit;

    res = ecdsa_signature_verify(curveid, key_xy, input, length, signature, siglen, true);
    if (res)
        goto exit;

    input[0] ^= 0xFF;
    res = ecdsa_signature_verify(curveid, key_xy, input, length, signature, siglen, true);
    if (!res)
        goto exit;

    if (verbose)
        PrintAndLogEx(NORMAL, _GREEN_("passed\n"));

    return PM3_SUCCESS;
exit:
    if (verbose)
        PrintAndLogEx(NORMAL, _RED_("failed\n"));
    return res;
}

void bin_xor(uint8_t *d1, const uint8_t *d2, size_t len) {
    for (size_t i = 0; i < len; i++)
        d1[i] = d1[i] ^ d2[i];
}

void AddISO9797M2Padding(uint8_t *ddata, size_t *ddatalen, uint8_t *sdata, size_t sdatalen, size_t blocklen) {
    *ddatalen = sdatalen + 1;
    *ddatalen += blocklen - *ddatalen % blocklen;
    memset(ddata, 0, *ddatalen);
    memcpy(ddata, sdata, sdatalen);
    ddata[sdatalen] = ISO9797_M2_PAD_BYTE;
}

size_t FindISO9797M2PaddingDataLen(const uint8_t *data, size_t datalen) {
    for (int i = datalen; i > 0; i--) {
        if (data[i - 1] == 0x80)
            return i - 1;
        if (data[i - 1] != 0x00)
            return 0;
    }
    return 0;
}


int blowfish_decrypt(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (iv)
        memcpy(iiv, iv, 16);

    mbedtls_blowfish_context blow;
    mbedtls_blowfish_init(&blow);
    if (mbedtls_blowfish_setkey(&blow, key, 64))
        return 1;
    if (mbedtls_blowfish_crypt_cbc(&blow, MBEDTLS_BLOWFISH_DECRYPT, length, iiv, input, output))
        return 2;
    mbedtls_blowfish_free(&blow);

    return 0;
}

// Implementation from http://www.secg.org/sec1-v2.pdf#subsubsection.3.6.1
int ansi_x963_sha256(uint8_t *sharedSecret, size_t sharedSecretLen, uint8_t *sharedInfo, size_t sharedInfoLen, size_t keyDataLen, uint8_t *keyData) {
    // sha256 hash has (practically) no max input len, so skipping that step

    if (keyDataLen >= 32 * (pow(2, 32) - 1)) {
        return 1;
    }

    uint32_t counter = 0x00000001;

    for (int i = 0; i < (keyDataLen / 32); ++i) {
        uint8_t *hashMaterial = malloc(4 + sharedSecretLen + sharedInfoLen);
        memcpy(hashMaterial, sharedSecret, sharedSecretLen);
        hashMaterial[sharedSecretLen] = (counter >> 24);
        hashMaterial[sharedSecretLen + 1] = (counter >> 16) & 0xFF;
        hashMaterial[sharedSecretLen + 2] = (counter >> 8) & 0xFF;
        hashMaterial[sharedSecretLen + 3] = counter & 0xFF;
        memcpy(hashMaterial + sharedSecretLen + 4, sharedInfo, sharedInfoLen);

        uint8_t hash[32] = {0};
        sha256hash(hashMaterial, 4 + sharedSecretLen + sharedInfoLen, hash);
        free(hashMaterial);

        memcpy(keyData + (32 * i), hash, 32);

        counter++;
    }

    return 0;
}
