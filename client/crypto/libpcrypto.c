//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
// Copyright (C) 2018 drHatson
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// crypto commands
//-----------------------------------------------------------------------------

#include "crypto/libpcrypto.h"
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <mbedtls/asn1.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/pk.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <crypto/asn1utils.h>
#include <util.h>

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

static int ecdsa_init_str(mbedtls_ecdsa_context *ctx, const char *key_d, const char *key_x, const char *key_y) {
    if (!ctx)
        return 1;

    int res;

    mbedtls_ecdsa_init(ctx);
    res = mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1); // secp256r1
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

static int ecdsa_init(mbedtls_ecdsa_context *ctx, uint8_t *key_d, uint8_t *key_xy) {
    if (!ctx)
        return 1;

    int res;

    mbedtls_ecdsa_init(ctx);
    res = mbedtls_ecp_group_load(&ctx->grp, MBEDTLS_ECP_DP_SECP256R1); // secp256r1
    if (res)
        return res;

    if (key_d) {
        res = mbedtls_mpi_read_binary(&ctx->d, key_d, 32);
        if (res)
            return res;
    }

    if (key_xy) {
        res = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q, key_xy, 32 * 2 + 1);
        if (res)
            return res;
    }

    return 0;
}

int ecdsa_key_create(uint8_t *key_d, uint8_t *key_xy) {
    int res;
    mbedtls_ecdsa_context ctx;
    ecdsa_init(&ctx, NULL, NULL);


    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsaproxmark";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (res)
        goto exit;

    res = mbedtls_ecdsa_genkey(&ctx, MBEDTLS_ECP_DP_SECP256R1, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (res)
        goto exit;

    res = mbedtls_mpi_write_binary(&ctx.d, key_d, 32);
    if (res)
        goto exit;

    size_t keylen = 0;
    uint8_t public_key[200] = {0};
    res = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &keylen, public_key, sizeof(public_key));
    if (res)
        goto exit;

    if (keylen != 65) { // 0x04 <key x 32b><key y 32b>
        res = 1;
        goto exit;
    }
    memcpy(key_xy, public_key, 65);

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

int ecdsa_public_key_from_pk(mbedtls_pk_context *pk, uint8_t *key, size_t keylen) {
    int res = 0;
    size_t realkeylen = 0;
    if (keylen < 65)
        return 1;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    res = mbedtls_ecp_group_load(&ctx.grp, MBEDTLS_ECP_DP_SECP256R1); // secp256r1
    if (res)
        goto exit;

    res = mbedtls_ecdsa_from_keypair(&ctx, mbedtls_pk_ec(*pk));
    if (res)
        goto exit;

    res = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &realkeylen, key, keylen);
    if (realkeylen != 65)
        res = 2;
exit:
    mbedtls_ecdsa_free(&ctx);
    return res;
}

int ecdsa_signature_create(uint8_t *key_d, uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen) {
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
    ecdsa_init(&ctx, key_d, key_xy);
    res = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, shahash, sizeof(shahash), signature, signaturelen, mbedtls_ctr_drbg_random, &ctr_drbg);

exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ctx);
    return res;
}

static int ecdsa_signature_create_test(const char *key_d, const char *key_x, const char *key_y, const char *random, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen) {
    int res;
    *signaturelen = 0;

    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    int rndlen = 0;
    param_gethex_to_eol(random, 0, fixed_rand_value, sizeof(fixed_rand_value), &rndlen);

    mbedtls_ecdsa_context ctx;
    ecdsa_init_str(&ctx, key_d, key_x, key_y);
    res = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, shahash, sizeof(shahash), signature, signaturelen, fixed_rand, NULL);

    mbedtls_ecdsa_free(&ctx);
    return res;
}

static int ecdsa_signature_verify_keystr(const char *key_x, const char *key_y, uint8_t *input, int length, uint8_t *signature, size_t signaturelen) {
    int res;
    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    mbedtls_ecdsa_context ctx;
    ecdsa_init_str(&ctx, NULL, key_x, key_y);
    res = mbedtls_ecdsa_read_signature(&ctx, shahash, sizeof(shahash), signature, signaturelen);

    mbedtls_ecdsa_free(&ctx);
    return res;
}

int ecdsa_signature_verify(uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t signaturelen) {
    int res;
    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    mbedtls_ecdsa_context ctx;
    ecdsa_init(&ctx, NULL, key_xy);
    res = mbedtls_ecdsa_read_signature(&ctx, shahash, sizeof(shahash), signature, signaturelen);

    mbedtls_ecdsa_free(&ctx);
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
    int length = strlen((char *)input);
    uint8_t signature[300] = {0};
    size_t siglen = 0;

    // NIST ecdsa test
    if (verbose)
        printf("  ECDSA NIST test: ");
    // make signature
    res = ecdsa_signature_create_test(T_PRIVATE_KEY, T_Q_X, T_Q_Y, T_K, input, length, signature, &siglen);
// printf("res: %x signature[%x]: %s\n", (res<0)?-res:res, siglen, sprint_hex(signature, siglen));
    if (res)
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
        printf("R or S check error\n");
        res = 100;
        goto exit;
    }

    // verify signature
    res = ecdsa_signature_verify_keystr(T_Q_X, T_Q_Y, input, length, signature, siglen);
    if (res)
        goto exit;

    // verify wrong signature
    input[0] ^= 0xFF;
    res = ecdsa_signature_verify_keystr(T_Q_X, T_Q_Y, input, length, signature, siglen);
    if (!res) {
        res = 1;
        goto exit;
    }

    if (verbose) {
        printf("passed\n");
        printf("  ECDSA binary signature create/check test: ");
    }

    // random ecdsa test
    uint8_t key_d[32] = {0};
    uint8_t key_xy[32 * 2 + 2] = {0};
    memset(signature, 0x00, sizeof(signature));
    siglen = 0;

    res = ecdsa_key_create(key_d, key_xy);
    if (res)
        goto exit;

    res = ecdsa_signature_create(key_d, key_xy, input, length, signature, &siglen);
    if (res)
        goto exit;

    res = ecdsa_signature_verify(key_xy, input, length, signature, siglen);
    if (res)
        goto exit;

    input[0] ^= 0xFF;
    res = ecdsa_signature_verify(key_xy, input, length, signature, siglen);
    if (!res)
        goto exit;

    if (verbose)
        printf("passed\n\n");

    return 0;
exit:
    if (verbose)
        printf("failed\n\n");
    return res;
}
