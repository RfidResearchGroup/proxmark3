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
// PACE (Password Authenticated Connection Establishment) primitives for eMRTD
//-----------------------------------------------------------------------------

#include "emrtd_pace.h"

#include <string.h>
#include <ctype.h>

#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/cipher.h>
#include <mbedtls/bignum.h>

#include "crypto/libpcrypto.h"      // sha1hash, sha256hash, des_encrypt/decrypt, pcrypto_rng_*
#include "ui.h"                     // PrintAndLogEx
#include "util.h"                   // sprint_hex_inrow
#include "commonutil.h"             // ARRAYLEN

//-----------------------------------------------------------------------------
// Tables
//-----------------------------------------------------------------------------

// TR-03110 part 3, table A.1. The OID bodies are what follows the "06 <len>"
// header, i.e. 0.4.0.127.0.7.2.2.4.x.y
static const emrtd_pacealg_t pacealg_table[] = {
//  name                                       key agreement       mapping             cipher                    keylen  oidlen  oid
    {"DH, Generic Mapping, 3DES-CBC-CBC",      EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_3DES,   16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x01}},
    {"DH, Generic Mapping, AES-CMAC-128",      EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_AES128, 16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x02}},
    {"DH, Generic Mapping, AES-CMAC-192",      EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_AES192, 24,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x03}},
    {"DH, Generic Mapping, AES-CMAC-256",      EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_AES256, 32,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01, 0x04}},
    {"ECDH, Generic Mapping, 3DES-CBC-CBC",    EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_3DES,   16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x01}},
    {"ECDH, Generic Mapping, AES-CMAC-128",    EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_AES128, 16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02}},
    {"ECDH, Generic Mapping, AES-CMAC-192",    EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_AES192, 24,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x03}},
    {"ECDH, Generic Mapping, AES-CMAC-256",    EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_GM,  EMRTD_PACE_CIPHER_AES256, 32,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x04}},
    {"DH, Integrated Mapping, 3DES-CBC-CBC",   EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_3DES,   16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x01}},
    {"DH, Integrated Mapping, AES-CMAC-128",   EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_AES128, 16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x02}},
    {"DH, Integrated Mapping, AES-CMAC-192",   EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_AES192, 24,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x03}},
    {"DH, Integrated Mapping, AES-CMAC-256",   EMRTD_PACE_KA_DH,   EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_AES256, 32,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x03, 0x04}},
    {"ECDH, Integrated Mapping, 3DES-CBC-CBC", EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_3DES,   16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x01}},
    {"ECDH, Integrated Mapping, AES-CMAC-128", EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_AES128, 16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x02}},
    {"ECDH, Integrated Mapping, AES-CMAC-192", EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_AES192, 24,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x03}},
    {"ECDH, Integrated Mapping, AES-CMAC-256", EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_IM,  EMRTD_PACE_CIPHER_AES256, 32,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x04, 0x04}},
    // Chip Authentication Mapping, TR-03110 part 3, A.1.1
    {"ECDH, CA Mapping, AES-CMAC-128",         EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_CAM, EMRTD_PACE_CIPHER_AES128, 16,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x02}},
    {"ECDH, CA Mapping, AES-CMAC-192",         EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_CAM, EMRTD_PACE_CIPHER_AES192, 24,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x03}},
    {"ECDH, CA Mapping, AES-CMAC-256",         EMRTD_PACE_KA_ECDH, EMRTD_PACE_MAP_CAM, EMRTD_PACE_CIPHER_AES256, 32,     10,     {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x06, 0x04}},
    {NULL, 0, 0, 0, 0, 0, {0}}
};

// TR-03110 part 3, table A.2.
// The curve column is MBEDTLS_ECP_DP_NONE for every curve this tree's mbedtls
// does not carry, see common/mbedtls/config.h. That must stay an explicit
// "unsupported" instead of silently picking a near neighbour.
static const emrtd_pacesdp_t pacesdp_table[] = {
//   id  name                                                     size  is_ec  mbedtls curve
    {0,  "1024-bit MODP Group with 160-bit Prime Order Subgroup", 1024, false, MBEDTLS_ECP_DP_NONE},
    {1,  "2048-bit MODP Group with 224-bit Prime Order Subgroup", 2048, false, MBEDTLS_ECP_DP_NONE},
    {2,  "2048-bit MODP Group with 256-bit Prime Order Subgroup", 2048, false, MBEDTLS_ECP_DP_NONE},
    {8,  "NIST P-192 (secp192r1)",                                192,  true,  MBEDTLS_ECP_DP_SECP192R1},
    {9,  "BrainpoolP192r1",                                       192,  true,  MBEDTLS_ECP_DP_NONE},
    {10, "NIST P-224 (secp224r1)",                                224,  true,  MBEDTLS_ECP_DP_SECP224R1},
    {11, "BrainpoolP224r1",                                       224,  true,  MBEDTLS_ECP_DP_NONE},
    {12, "NIST P-256 (secp256r1)",                                256,  true,  MBEDTLS_ECP_DP_SECP256R1},
    {13, "BrainpoolP256r1",                                       256,  true,  MBEDTLS_ECP_DP_BP256R1},
    {14, "BrainpoolP320r1",                                       320,  true,  MBEDTLS_ECP_DP_NONE},
    {15, "NIST P-384 (secp384r1)",                                384,  true,  MBEDTLS_ECP_DP_SECP384R1},
    {16, "BrainpoolP384r1",                                       384,  true,  MBEDTLS_ECP_DP_BP384R1},
    {17, "BrainpoolP512r1",                                       512,  true,  MBEDTLS_ECP_DP_BP512R1},
    {18, "NIST P-521 (secp521r1)",                                521,  true,  MBEDTLS_ECP_DP_SECP521R1},
    {32, NULL, 0, false, MBEDTLS_ECP_DP_NONE}
};

const emrtd_pacealg_t *emrtd_pace_alg_by_oid(const uint8_t *oid, size_t oidlen) {
    for (int i = 0; pacealg_table[i].name != NULL; i++) {
        if (pacealg_table[i].oidlen == oidlen && memcmp(pacealg_table[i].oid, oid, oidlen) == 0) {
            return &pacealg_table[i];
        }
    }
    return NULL;
}

const emrtd_pacesdp_t *emrtd_pace_sdp_by_id(uint8_t id) {
    for (int i = 0; pacesdp_table[i].id != 32; i++) {
        if (pacesdp_table[i].id == id) {
            return &pacesdp_table[i];
        }
    }
    return NULL;
}

const char *emrtd_pace_cipher_name(emrtd_pace_cipher_t cipher) {
    switch (cipher) {
        case EMRTD_PACE_CIPHER_3DES:
            return "3DES-CBC-CBC";
        case EMRTD_PACE_CIPHER_AES128:
            return "AES-CMAC-128";
        case EMRTD_PACE_CIPHER_AES192:
            return "AES-CMAC-192";
        case EMRTD_PACE_CIPHER_AES256:
            return "AES-CMAC-256";
    }
    return "unknown";
}

//-----------------------------------------------------------------------------
// 3DES / ISO 9797-1 helpers
//-----------------------------------------------------------------------------

void emrtd_des3_encrypt_cbc(uint8_t *iv, const uint8_t *key, const uint8_t *input, size_t inputlen, uint8_t *output) {
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, key);
    mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, inputlen, iv, input, output);
    mbedtls_des3_free(&ctx);
}

void emrtd_des3_decrypt_cbc(uint8_t *iv, const uint8_t *key, const uint8_t *input, size_t inputlen, uint8_t *output) {
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);
    mbedtls_des3_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, inputlen, iv, input, output);
    mbedtls_des3_free(&ctx);
}

size_t emrtd_pad_block(const uint8_t *input, size_t inputlen, size_t blocksize, uint8_t *output) {
    if (inputlen) {
        memmove(output, input, inputlen);
    }
    output[inputlen] = 0x80;
    size_t padded = inputlen + 1;
    while ((padded % blocksize) != 0) {
        output[padded++] = 0x00;
    }
    return padded;
}

#define EMRTD_RETAIL_MAC_MAXLEN 512
#define EMRTD_SM_MAC_MAXLEN     576

int emrtd_retail_mac(const uint8_t *key, const uint8_t *input, size_t inputlen, uint8_t *output) {
    // ISO 9797-1 MAC algorithm 3 with padding method 2, block length 8.
    // Takes inspiration from https://github.com/devinvenable/iso9797algorithm3
    uint8_t message[EMRTD_RETAIL_MAC_MAXLEN] = { 0x00 };

    if (inputlen + 8 > sizeof(message)) {
        PrintAndLogEx(ERR, "error (emrtd_retail_mac) input out-of-bounds, %zu bytes", inputlen);
        return PM3_EOUTOFBOUND;
    }

    const uint8_t *k0 = key;
    const uint8_t *k1 = key + 8;

    size_t blocksize = emrtd_pad_block(input, inputlen, 8, message);

    uint8_t intermediate[8] = { 0x00 };
    uint8_t intermediate_des[8] = { 0x00 };

    for (size_t i = 0; i < (blocksize / 8); i++) {
        for (int x = 0; x < 8; x++) {
            intermediate[x] ^= message[(i * 8) + x];
        }
        des_encrypt(intermediate_des, intermediate, k0);
        memcpy(intermediate, intermediate_des, 8);
    }

    des_decrypt(intermediate_des, intermediate, k1);
    des_encrypt(output, intermediate_des, k0);
    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// Secure messaging session
//-----------------------------------------------------------------------------

void emrtd_sm_clear(emrtd_session_t *ssn) {
    memset(ssn, 0, sizeof(emrtd_session_t));
    ssn->type = EMRTD_SM_NONE;
}

int emrtd_sm_setup(emrtd_session_t *ssn, emrtd_pace_cipher_t cipher, const uint8_t *ks_enc, const uint8_t *ks_mac) {
    size_t keylen;
    switch (cipher) {
        case EMRTD_PACE_CIPHER_3DES:
            ssn->type = EMRTD_SM_3DES;
            ssn->ssclen = 8;
            keylen = 16;
            break;
        case EMRTD_PACE_CIPHER_AES128:
            ssn->type = EMRTD_SM_AES;
            ssn->ssclen = 16;
            keylen = 16;
            break;
        case EMRTD_PACE_CIPHER_AES192:
            ssn->type = EMRTD_SM_AES;
            ssn->ssclen = 16;
            keylen = 24;
            break;
        case EMRTD_PACE_CIPHER_AES256:
            ssn->type = EMRTD_SM_AES;
            ssn->ssclen = 16;
            keylen = 32;
            break;
        default:
            return PM3_EINVARG;
    }

    ssn->keylen = keylen;
    memcpy(ssn->ks_enc, ks_enc, keylen);
    memcpy(ssn->ks_mac, ks_mac, keylen);
    memset(ssn->ssc, 0x00, sizeof(ssn->ssc));
    return PM3_SUCCESS;
}

size_t emrtd_sm_blocksize(const emrtd_session_t *ssn) {
    return (ssn->type == EMRTD_SM_AES) ? 16 : 8;
}

void emrtd_sm_bump_ssc(emrtd_session_t *ssn) {
    PrintAndLogEx(DEBUG, "ssc-b: %s", sprint_hex_inrow(ssn->ssc, ssn->ssclen));
    for (int i = (int)ssn->ssclen - 1; i >= 0; i--) {
        ssn->ssc[i]++;
        if (ssn->ssc[i] != 0x00) {
            break;
        }
    }
    PrintAndLogEx(DEBUG, "ssc-a: %s", sprint_hex_inrow(ssn->ssc, ssn->ssclen));
}

static int emrtd_aes_setkey_enc(mbedtls_aes_context *aes, const emrtd_session_t *ssn, const uint8_t *key) {
    return mbedtls_aes_setkey_enc(aes, key, ssn->keylen * 8);
}

// IV for AES secure messaging: E(KSenc, SSC) in ECB mode, ICAO 9303-11 9.8.6.1
static int emrtd_sm_aes_iv(const emrtd_session_t *ssn, uint8_t *iv) {
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int res = emrtd_aes_setkey_enc(&aes, ssn, ssn->ks_enc);
    if (res == 0) {
        res = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_ENCRYPT, ssn->ssc, iv);
    }
    mbedtls_aes_free(&aes);
    return (res == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

// The MAC algorithm that belongs to a cipher, applied to the data as given.
// 3DES is ISO 9797-1 MAC algorithm 3, which pads internally; AES is CMAC, which
// takes any length. Used directly for the PACE authentication tokens.
static int emrtd_mac_raw(emrtd_pace_cipher_t cipher, const uint8_t *key, size_t keylen,
                         const uint8_t *input, size_t inputlen, uint8_t *mac) {
    if (cipher == EMRTD_PACE_CIPHER_3DES) {
        return emrtd_retail_mac(key, input, inputlen, mac);
    }

    // Note: libpcrypto's aes_cmac()/aes_cmac8() are not usable here. The former
    // is AES-CMAC-PRF-128 (RFC 4615) and the latter truncates by taking every
    // second byte, neither of which is what ICAO 9303-11 asks for.
    mbedtls_cipher_type_t ct;
    switch (keylen) {
        case 16:
            ct = MBEDTLS_CIPHER_AES_128_ECB;
            break;
        case 24:
            ct = MBEDTLS_CIPHER_AES_192_ECB;
            break;
        case 32:
            ct = MBEDTLS_CIPHER_AES_256_ECB;
            break;
        default:
            return PM3_EINVARG;
    }

    const mbedtls_cipher_info_t *ci = mbedtls_cipher_info_from_type(ct);
    if (ci == NULL) {
        return PM3_ESOFT;
    }

    uint8_t full[16] = { 0x00 };
    if (mbedtls_cipher_cmac(ci, key, keylen * 8, input, inputlen, full) != 0) {
        return PM3_ESOFT;
    }

    // ICAO 9303-11 9.8.6 asks for a MAC length of 8 bytes
    memcpy(mac, full, 8);
    return PM3_SUCCESS;
}

int emrtd_sm_mac(const emrtd_session_t *ssn, const uint8_t *input, size_t inputlen, uint8_t *mac) {
    if (ssn->type == EMRTD_SM_3DES) {
        // the retail MAC pads the input itself, which is step e.2
        return emrtd_mac_raw(EMRTD_PACE_CIPHER_3DES, ssn->ks_mac, ssn->keylen, input, inputlen, mac);
    }

    if (ssn->type != EMRTD_SM_AES) {
        return PM3_EINVARG;
    }

    // ICAO 9303-11 9.8.6.1 step e.2: "Concatenate SSC and M and add padding".
    // CMAC does not need the padding, but the step applies to AES all the same,
    // verified against a document doing PACE with AES-CMAC-256 (a chip that is
    // sent the unpadded input answers 6988, incorrect SM data object).
    uint8_t padded[EMRTD_SM_MAC_MAXLEN] = { 0x00 };
    if ((inputlen + 16) > sizeof(padded)) {
        PrintAndLogEx(ERR, "error (emrtd_sm_mac) input out-of-bounds, %zu bytes", inputlen);
        return PM3_EOUTOFBOUND;
    }

    size_t paddedlen = emrtd_pad_block(input, inputlen, 16, padded);
    return emrtd_mac_raw(EMRTD_PACE_CIPHER_AES128, ssn->ks_mac, ssn->keylen, padded, paddedlen, mac);
}

int emrtd_sm_encrypt(const emrtd_session_t *ssn, const uint8_t *input, size_t inputlen, uint8_t *output) {
    if (ssn->type == EMRTD_SM_3DES) {
        uint8_t iv[8] = { 0x00 };
        emrtd_des3_encrypt_cbc(iv, ssn->ks_enc, input, inputlen, output);
        return PM3_SUCCESS;
    }

    if (ssn->type != EMRTD_SM_AES) {
        return PM3_EINVARG;
    }

    uint8_t iv[16] = { 0x00 };
    int res = emrtd_sm_aes_iv(ssn, iv);
    if (res != PM3_SUCCESS) {
        return res;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    res = emrtd_aes_setkey_enc(&aes, ssn, ssn->ks_enc);
    if (res == 0) {
        res = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, inputlen, iv, input, output);
    }
    mbedtls_aes_free(&aes);
    return (res == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

int emrtd_sm_decrypt(const emrtd_session_t *ssn, const uint8_t *input, size_t inputlen, uint8_t *output) {
    if (ssn->type == EMRTD_SM_3DES) {
        uint8_t iv[8] = { 0x00 };
        emrtd_des3_decrypt_cbc(iv, ssn->ks_enc, input, inputlen, output);
        return PM3_SUCCESS;
    }

    if (ssn->type != EMRTD_SM_AES) {
        return PM3_EINVARG;
    }

    uint8_t iv[16] = { 0x00 };
    int res = emrtd_sm_aes_iv(ssn, iv);
    if (res != PM3_SUCCESS) {
        return res;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    res = mbedtls_aes_setkey_dec(&aes, ssn->ks_enc, ssn->keylen * 8);
    if (res == 0) {
        res = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, inputlen, iv, input, output);
    }
    mbedtls_aes_free(&aes);
    return (res == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

//-----------------------------------------------------------------------------
// BER-TLV
//-----------------------------------------------------------------------------

bool emrtd_tlv_next(const uint8_t **cur, const uint8_t *end, uint32_t *tag, const uint8_t **value, size_t *valuelen) {
    const uint8_t *p = *cur;

    if (p >= end) {
        return false;
    }

    uint32_t t = *p++;
    if ((t & 0x1F) == 0x1F) {
        // multi byte tag
        do {
            if (p >= end || (t > 0x00FFFFFF)) {
                return false;
            }
            t = (t << 8) | *p;
        } while ((*p++ & 0x80) != 0);
    }

    if (p >= end) {
        return false;
    }

    size_t len = *p++;
    if (len > 0x80) {
        size_t lenlen = len & 0x7F;
        if ((lenlen > 4) || ((size_t)(end - p) < lenlen)) {
            return false;
        }
        len = 0;
        for (size_t i = 0; i < lenlen; i++) {
            len = (len << 8) | *p++;
        }
    } else if (len == 0x80) {
        // indefinite length, not valid in the structures we parse
        return false;
    }

    if ((size_t)(end - p) < len) {
        return false;
    }

    *tag = t;
    *value = p;
    *valuelen = len;
    *cur = p + len;
    return true;
}

size_t emrtd_tlv_write_header(uint8_t *out, size_t outlen, uint32_t tag, size_t len) {
    size_t taglen = (tag > 0xFF) ? 2 : 1;
    size_t lenlen;

    if (len < 0x80) {
        lenlen = 1;
    } else if (len <= 0xFF) {
        lenlen = 2;
    } else if (len <= 0xFFFF) {
        lenlen = 3;
    } else {
        return 0;
    }

    if (outlen < taglen + lenlen) {
        return 0;
    }

    size_t o = 0;
    if (taglen == 2) {
        out[o++] = (tag >> 8) & 0xFF;
    }
    out[o++] = tag & 0xFF;

    if (lenlen == 1) {
        out[o++] = (uint8_t)len;
    } else if (lenlen == 2) {
        out[o++] = 0x81;
        out[o++] = (uint8_t)len;
    } else {
        out[o++] = 0x82;
        out[o++] = (uint8_t)(len >> 8);
        out[o++] = (uint8_t)len;
    }
    return o;
}

//-----------------------------------------------------------------------------
// EF_CardAccess
//-----------------------------------------------------------------------------

#define ASN1_TAG_INTEGER    0x02
#define ASN1_TAG_OID        0x06
#define ASN1_TAG_SEQUENCE   0x30
#define ASN1_TAG_SET        0x31

static bool emrtd_asn1_uint(const uint8_t *value, size_t valuelen, uint32_t *out) {
    if ((valuelen == 0) || (valuelen > 5)) {
        return false;
    }
    // skip a single leading zero used to keep the value positive
    if ((valuelen == 5) && (value[0] != 0x00)) {
        return false;
    }
    uint32_t v = 0;
    for (size_t i = 0; i < valuelen; i++) {
        v = (v << 8) | value[i];
    }
    *out = v;
    return true;
}

// The PACEDomainParameterInfo protocol OIDs, TR-03110 part 3, A.1.1.
// 0.4.0.127.0.7.2.2.4.1 (DH) and .2 (ECDH)
static const uint8_t oid_pace_dh_dp[]   = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x01};
static const uint8_t oid_pace_ecdh_dp[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02};

static void emrtd_pace_classify(emrtd_paceinfo_t *info) {
    info->supported = false;

    if (info->alg == NULL) {
        info->reason = "unknown protocol OID";
        return;
    }

    if (info->alg->ka == EMRTD_PACE_KA_DH) {
        // MBEDTLS_DHM_C is deliberately left out of common/mbedtls/config.h and
        // enabling it is out of scope, so DH (MODP) mapping cannot be done here.
        info->reason = "unsupported (DH not compiled in)";
        return;
    }

    if (info->alg->mapping == EMRTD_PACE_MAP_IM) {
        info->reason = "unsupported (Integrated Mapping not implemented)";
        return;
    }

    if (info->has_param == false) {
        info->reason = "no standardized domain parameter id";
        return;
    }

    if (info->sdp == NULL) {
        info->reason = "unknown domain parameter id";
        return;
    }

    if (info->sdp->is_ec == false) {
        info->reason = "unsupported (MODP group, DH not compiled in)";
        return;
    }

    if (info->sdp->curve == MBEDTLS_ECP_DP_NONE) {
        info->reason = "unsupported curve (not compiled into mbedtls)";
        return;
    }

    info->supported = true;
    info->reason = NULL;
}

static int emrtd_pace_cipher_rank(emrtd_pace_cipher_t cipher) {
    switch (cipher) {
        case EMRTD_PACE_CIPHER_3DES:
            return 1;
        case EMRTD_PACE_CIPHER_AES128:
            return 2;
        case EMRTD_PACE_CIPHER_AES192:
            return 3;
        case EMRTD_PACE_CIPHER_AES256:
            return 4;
    }
    return 0;
}

// Chip Authentication Mapping would be the stronger choice, since it proves the
// chip is not a clone. We cannot complete that proof yet (see
// emrtd_pace_cam_verify), so a CAM session buys nothing over a Generic Mapping
// one and costs an EF_DG14 read. Prefer GM until the proof works, and fall back
// to CAM only for documents that offer nothing else.
int emrtd_pace_rank(const emrtd_paceinfo_t *info) {
    if ((info->supported == false) || (info->alg == NULL)) {
        return 0;
    }
    int rank = emrtd_pace_cipher_rank(info->alg->cipher) * 2;
    if (info->alg->mapping == EMRTD_PACE_MAP_GM) {
        rank += 1;
    }
    return rank;
}

// One SecurityInfo:  SEQUENCE { OID protocol, ... }
static void emrtd_pace_parse_securityinfo(const uint8_t *seq, size_t seqlen, emrtd_cardaccess_t *out) {
    const uint8_t *cur = seq;
    const uint8_t *end = seq + seqlen;
    uint32_t tag;
    const uint8_t *val;
    size_t vlen;

    if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
        return;
    }

    if ((tag != ASN1_TAG_OID) || (vlen == 0) || (vlen > EMRTD_PACE_OID_MAXLEN)) {
        return;
    }

    // PACEDomainParameterInfo carries the algorithm identifier instead of a
    // version number. We only report it, the parameters we act on come from
    // the PACEInfo entries.
    bool is_domain_param = ((vlen == sizeof(oid_pace_dh_dp)) &&
                            ((memcmp(val, oid_pace_dh_dp, vlen) == 0) ||
                             (memcmp(val, oid_pace_ecdh_dp, vlen) == 0)));

    if (out->count >= EMRTD_PACE_MAX_INFOS) {
        return;
    }

    emrtd_paceinfo_t *info = &out->infos[out->count];
    memset(info, 0, sizeof(emrtd_paceinfo_t));
    memcpy(info->oid, val, vlen);
    info->oidlen = vlen;
    info->alg = emrtd_pace_alg_by_oid(val, vlen);

    if (is_domain_param) {
        // SEQUENCE { OID, AlgorithmIdentifier, INTEGER parameterId OPTIONAL }
        if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
            return;
        }
        if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) && (tag == ASN1_TAG_INTEGER)) {
            uint32_t v = 0;
            if (emrtd_asn1_uint(val, vlen, &v) && (v <= 0xFF)) {
                info->has_param = true;
                info->param_id = (uint8_t)v;
                info->sdp = emrtd_pace_sdp_by_id(info->param_id);
            }
        }
        info->supported = false;
        info->reason = "domain parameter definition, informational";
        out->count++;
        return;
    }

    // PACEInfo ::= SEQUENCE { protocol OID, version INTEGER, parameterId INTEGER OPTIONAL }
    if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
        return;
    }
    if (tag != ASN1_TAG_INTEGER) {
        return;
    }
    if (emrtd_asn1_uint(val, vlen, &info->version) == false) {
        return;
    }

    if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) && (tag == ASN1_TAG_INTEGER)) {
        uint32_t v = 0;
        if (emrtd_asn1_uint(val, vlen, &v) && (v <= 0xFF)) {
            info->has_param = true;
            info->param_id = (uint8_t)v;
            info->sdp = emrtd_pace_sdp_by_id(info->param_id);
        }
    }

    emrtd_pace_classify(info);
    out->count++;
}

int emrtd_pace_parse_cardaccess(const uint8_t *data, size_t datalen, emrtd_cardaccess_t *out) {
    memset(out, 0, sizeof(emrtd_cardaccess_t));
    out->best = -1;

    if ((data == NULL) || (datalen == 0)) {
        return PM3_EINVARG;
    }

    const uint8_t *cur = data;
    const uint8_t *end = data + datalen;
    uint32_t tag;
    const uint8_t *val;
    size_t vlen;

    // EF_CardAccess is a SET OF SecurityInfo. Accept a SEQUENCE too, some
    // documents in the wild get this wrong.
    if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
        PrintAndLogEx(DEBUG, "EF_CardAccess: not a valid TLV");
        return PM3_ESOFT;
    }

    if ((tag != ASN1_TAG_SET) && (tag != ASN1_TAG_SEQUENCE)) {
        PrintAndLogEx(DEBUG, "EF_CardAccess: unexpected top level tag %02X", tag);
        return PM3_ESOFT;
    }

    const uint8_t *icur = val;
    const uint8_t *iend = val + vlen;

    while (emrtd_tlv_next(&icur, iend, &tag, &val, &vlen)) {
        if (tag != ASN1_TAG_SEQUENCE) {
            continue;
        }
        emrtd_pace_parse_securityinfo(val, vlen, out);
    }

    if (out->count == 0) {
        return PM3_ESOFT;
    }

    // Pick the strongest usable algorithm
    int bestrank = 0;
    for (size_t i = 0; i < out->count; i++) {
        int rank = emrtd_pace_rank(&out->infos[i]);
        if (rank > bestrank) {
            bestrank = rank;
            out->best = (int)i;
        }
    }

    return PM3_SUCCESS;
}

//-----------------------------------------------------------------------------
// PACE key derivation
//-----------------------------------------------------------------------------

char emrtd_calculate_check_digit(const char *data) {
    const int mrz_weight[] = {7, 3, 1};
    int value, cd = 0;

    for (size_t i = 0; i < strlen(data); i++) {
        char d = data[i];
        if ('A' <= d && d <= 'Z') {
            value = d - 55;
        } else if ('a' <= d && d <= 'z') {
            value = d - 87;
        } else if (d == '<') {
            value = 0;
        } else {  // Numbers
            value = d - 48;
        }
        cd += value * mrz_weight[i % 3];
    }
    return cd % 10;
}

int emrtd_pace_kmrz(const char *documentnumber, const char *dob, const char *expiry, char *out, size_t outlen) {
    if ((documentnumber == NULL) || (dob == NULL) || (expiry == NULL)) {
        return PM3_EINVARG;
    }

    char docnumcd = emrtd_calculate_check_digit(documentnumber);
    char dobcd = emrtd_calculate_check_digit(dob);
    char expirycd = emrtd_calculate_check_digit(expiry);

    int n = snprintf(out, outlen, "%s%i%s%i%s%i", documentnumber, docnumcd, dob, dobcd, expiry, expirycd);
    if ((n < 0) || ((size_t)n >= outlen)) {
        return PM3_EOUTOFBOUND;
    }
    return PM3_SUCCESS;
}

int emrtd_pace_password_mrz(const char *documentnumber, const char *dob, const char *expiry, uint8_t *k, size_t *klen) {
    char kmrz[25] = { 0x00 };

    int res = emrtd_pace_kmrz(documentnumber, dob, expiry, kmrz, sizeof(kmrz));
    if (res != PM3_SUCCESS) {
        return res;
    }

    PrintAndLogEx(DEBUG, "kmrz.............. %s", kmrz);
    sha1hash((uint8_t *)kmrz, strlen(kmrz), k);
    *klen = 20;
    return PM3_SUCCESS;
}

int emrtd_pace_password_can(const char *can, uint8_t *k, size_t *klen) {
    if (can == NULL) {
        return PM3_EINVARG;
    }

    size_t len = strlen(can);
    if ((len == 0) || (len > EMRTD_PACE_SECRET_MAXLEN)) {
        return PM3_EINVARG;
    }

    // The CAN is used as is, ICAO 9303-11 9.7.2
    memcpy(k, can, len);
    *klen = len;
    return PM3_SUCCESS;
}

int emrtd_pace_kdf(emrtd_pace_cipher_t cipher, const uint8_t *k, size_t klen, uint32_t counter, uint8_t *out, size_t *outlen) {
    // TR-03110 part 3, A.2.3
    uint8_t buf[EMRTD_PACE_SECRET_MAXLEN + 4] = { 0x00 };

    if (klen > EMRTD_PACE_SECRET_MAXLEN) {
        PrintAndLogEx(ERR, "error (emrtd_pace_kdf) secret out-of-bounds, %zu bytes", klen);
        return PM3_EOUTOFBOUND;
    }

    memcpy(buf, k, klen);
    buf[klen + 0] = (counter >> 24) & 0xFF;
    buf[klen + 1] = (counter >> 16) & 0xFF;
    buf[klen + 2] = (counter >> 8) & 0xFF;
    buf[klen + 3] = counter & 0xFF;

    uint8_t hash[64] = { 0x00 };
    size_t keylen;

    switch (cipher) {
        case EMRTD_PACE_CIPHER_3DES:
        case EMRTD_PACE_CIPHER_AES128:
            sha1hash(buf, klen + 4, hash);
            keylen = 16;
            break;
        case EMRTD_PACE_CIPHER_AES192:
            sha256hash(buf, klen + 4, hash);
            keylen = 24;
            break;
        case EMRTD_PACE_CIPHER_AES256:
            sha256hash(buf, klen + 4, hash);
            keylen = 32;
            break;
        default:
            return PM3_EINVARG;
    }

    memcpy(out, hash, keylen);

    if (cipher == EMRTD_PACE_CIPHER_3DES) {
        // two key 3DES, odd parity per byte
        mbedtls_des_key_set_parity(out);
        mbedtls_des_key_set_parity(out + 8);
    }

    *outlen = keylen;
    return PM3_SUCCESS;
}

int emrtd_pace_decrypt_nonce(emrtd_pace_cipher_t cipher, const uint8_t *kpi, const uint8_t *z, size_t zlen, uint8_t *s) {
    size_t blocksize = (cipher == EMRTD_PACE_CIPHER_3DES) ? 8 : 16;

    if ((zlen == 0) || ((zlen % blocksize) != 0) || (zlen > 32)) {
        PrintAndLogEx(ERR, "PACE: bad encrypted nonce length %zu", zlen);
        return PM3_EINVARG;
    }

    if (cipher == EMRTD_PACE_CIPHER_3DES) {
        uint8_t iv[8] = { 0x00 };
        emrtd_des3_decrypt_cbc(iv, kpi, z, zlen, s);
        return PM3_SUCCESS;
    }

    size_t keybits;
    switch (cipher) {
        case EMRTD_PACE_CIPHER_3DES:
            // handled above
            return PM3_EINVARG;
        case EMRTD_PACE_CIPHER_AES128:
            keybits = 128;
            break;
        case EMRTD_PACE_CIPHER_AES192:
            keybits = 192;
            break;
        case EMRTD_PACE_CIPHER_AES256:
            keybits = 256;
            break;
        default:
            return PM3_EINVARG;
    }

    uint8_t iv[16] = { 0x00 };
    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    int res = mbedtls_aes_setkey_dec(&aes, kpi, keybits);
    if (res == 0) {
        res = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, zlen, iv, z, s);
    }
    mbedtls_aes_free(&aes);
    return (res == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

//-----------------------------------------------------------------------------
// ECDH with Generic Mapping
//-----------------------------------------------------------------------------

size_t emrtd_pace_ec_pointlen(mbedtls_ecp_group_id curve) {
    mbedtls_ecp_group grp;
    mbedtls_ecp_group_init(&grp);

    size_t len = 0;
    if (mbedtls_ecp_group_load(&grp, curve) == 0) {
        len = 1 + (2 * ((grp.pbits + 7) / 8));
    }

    mbedtls_ecp_group_free(&grp);
    return len;
}

static int emrtd_ecp_write(const mbedtls_ecp_group *grp, const mbedtls_ecp_point *pt, uint8_t *out, size_t *outlen) {
    size_t written = 0;
    int res = mbedtls_ecp_point_write_binary(grp, pt, MBEDTLS_ECP_PF_UNCOMPRESSED, &written, out, EMRTD_EC_POINT_MAXLEN);
    if (res != 0) {
        return PM3_ESOFT;
    }
    *outlen = written;
    return PM3_SUCCESS;
}

// Note: mbedtls builds the standard groups out of static const MPI limbs, so
// grp->G must never be written to. A caller supplied generator is parsed into
// a point of its own and handed back through *out instead.
static int emrtd_ecp_group_with_base(mbedtls_ecp_group *grp, mbedtls_ecp_group_id curve,
                                     const uint8_t *base, size_t baselen,
                                     mbedtls_ecp_point *custom, const mbedtls_ecp_point **out) {
    if (mbedtls_ecp_group_load(grp, curve) != 0) {
        PrintAndLogEx(ERR, "PACE: failed to load curve");
        return PM3_ESOFT;
    }

    if (out == NULL) {
        return PM3_SUCCESS;
    }

    if (base == NULL) {
        *out = &grp->G;
        return PM3_SUCCESS;
    }

    if (mbedtls_ecp_point_read_binary(grp, custom, base, baselen) != 0) {
        PrintAndLogEx(ERR, "PACE: failed to parse mapped generator");
        return PM3_ESOFT;
    }

    if (mbedtls_ecp_check_pubkey(grp, custom) != 0) {
        PrintAndLogEx(ERR, "PACE: mapped generator is not on the curve");
        return PM3_ESOFT;
    }

    *out = custom;
    return PM3_SUCCESS;
}

int emrtd_pace_ec_pubkey(mbedtls_ecp_group_id curve, const uint8_t *base, size_t baselen,
                         const uint8_t *priv, size_t privlen, uint8_t *pub, size_t *publen) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q, custom;
    const mbedtls_ecp_point *G = NULL;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&custom);

    int res = emrtd_ecp_group_with_base(&grp, curve, base, baselen, &custom, &G);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = PM3_ESOFT;
    if (mbedtls_mpi_read_binary(&d, priv, privlen) != 0) {
        goto out;
    }
    if (mbedtls_ecp_mul(&grp, &Q, &d, G, NULL, NULL) != 0) {
        goto out;
    }
    res = emrtd_ecp_write(&grp, &Q, pub, publen);

out:
    mbedtls_ecp_point_free(&custom);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return res;
}

int emrtd_pace_ec_keygen(mbedtls_ecp_group_id curve, const uint8_t *base, size_t baselen,
                         uint8_t *priv, size_t *privlen, uint8_t *pub, size_t *publen) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point Q, custom;
    const mbedtls_ecp_point *G = NULL;
    pcrypto_rng_t rng = {0};

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&Q);
    mbedtls_ecp_point_init(&custom);

    int res = pcrypto_rng_init(&rng, (const uint8_t *)"emrtd-pace", 10);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = emrtd_ecp_group_with_base(&grp, curve, base, baselen, &custom, &G);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = PM3_ESOFT;
    if (mbedtls_ecp_gen_keypair_base(&grp, G, &d, &Q, mbedtls_ctr_drbg_random, &rng.ctr_drbg) != 0) {
        PrintAndLogEx(ERR, "PACE: ephemeral key generation failed");
        goto out;
    }

    *privlen = (grp.nbits + 7) / 8;
    if (mbedtls_mpi_write_binary(&d, priv, *privlen) != 0) {
        goto out;
    }

    res = emrtd_ecp_write(&grp, &Q, pub, publen);

out:
    pcrypto_rng_free(&rng);
    mbedtls_ecp_point_free(&custom);
    mbedtls_ecp_point_free(&Q);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return res;
}

int emrtd_pace_ec_gm(mbedtls_ecp_group_id curve, const uint8_t *s, size_t slen,
                     const uint8_t *priv, size_t privlen, const uint8_t *pk_ic, size_t pk_ic_len,
                     uint8_t *mapped, size_t *mappedlen) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d, sm, one;
    mbedtls_ecp_point PK, H, G;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_mpi_init(&sm);
    mbedtls_mpi_init(&one);
    mbedtls_ecp_point_init(&PK);
    mbedtls_ecp_point_init(&H);
    mbedtls_ecp_point_init(&G);

    int res = emrtd_ecp_group_with_base(&grp, curve, NULL, 0, NULL, NULL);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = PM3_ESOFT;
    if (mbedtls_ecp_point_read_binary(&grp, &PK, pk_ic, pk_ic_len) != 0) {
        PrintAndLogEx(ERR, "PACE: chip mapping key is not a valid point");
        goto out;
    }
    if (mbedtls_ecp_check_pubkey(&grp, &PK) != 0) {
        PrintAndLogEx(ERR, "PACE: chip mapping key is not on the curve");
        goto out;
    }
    if (mbedtls_mpi_read_binary(&d, priv, privlen) != 0) {
        goto out;
    }
    if (mbedtls_mpi_read_binary(&sm, s, slen) != 0) {
        goto out;
    }
    if (mbedtls_mpi_lset(&one, 1) != 0) {
        goto out;
    }

    // H = x * PK_IC
    if (mbedtls_ecp_mul(&grp, &H, &d, &PK, NULL, NULL) != 0) {
        goto out;
    }

    // G' = s*G + H
    if (mbedtls_ecp_muladd(&grp, &G, &sm, &grp.G, &one, &H) != 0) {
        goto out;
    }

    if (mbedtls_ecp_is_zero(&G)) {
        PrintAndLogEx(ERR, "PACE: mapped generator is the point at infinity");
        goto out;
    }

    res = emrtd_ecp_write(&grp, &G, mapped, mappedlen);

out:
    mbedtls_ecp_point_free(&G);
    mbedtls_ecp_point_free(&H);
    mbedtls_ecp_point_free(&PK);
    mbedtls_mpi_free(&one);
    mbedtls_mpi_free(&sm);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return res;
}

int emrtd_pace_ec_shared_x(mbedtls_ecp_group_id curve, const uint8_t *priv, size_t privlen,
                           const uint8_t *pk_ic, size_t pk_ic_len, uint8_t *out, size_t *outlen) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point PK, K;

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&PK);
    mbedtls_ecp_point_init(&K);

    int res = emrtd_ecp_group_with_base(&grp, curve, NULL, 0, NULL, NULL);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = PM3_ESOFT;
    if (mbedtls_ecp_point_read_binary(&grp, &PK, pk_ic, pk_ic_len) != 0) {
        goto out;
    }
    if (mbedtls_ecp_check_pubkey(&grp, &PK) != 0) {
        PrintAndLogEx(ERR, "PACE: chip agreement key is not on the curve");
        goto out;
    }
    if (mbedtls_mpi_read_binary(&d, priv, privlen) != 0) {
        goto out;
    }
    if (mbedtls_ecp_mul(&grp, &K, &d, &PK, NULL, NULL) != 0) {
        goto out;
    }
    if (mbedtls_ecp_is_zero(&K)) {
        PrintAndLogEx(ERR, "PACE: shared secret is the point at infinity");
        goto out;
    }

    // ICAO 9303-11 4.4.3.3, only the x coordinate is used
    *outlen = (grp.pbits + 7) / 8;
    if (mbedtls_mpi_write_binary(&K.X, out, *outlen) != 0) {
        goto out;
    }
    res = PM3_SUCCESS;

out:
    mbedtls_ecp_point_free(&K);
    mbedtls_ecp_point_free(&PK);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return res;
}

int emrtd_pace_token(const emrtd_pacealg_t *alg, const uint8_t *ks_mac,
                     const uint8_t *pubkey, size_t pubkeylen, uint8_t *token) {
    // ICAO 9303-11 4.4.3.4:
    //   T = MAC(KSmac, 7F49 || 06 <oid> || 86 <public key>)
    uint8_t inner[EMRTD_EC_POINT_MAXLEN + 32] = { 0x00 };
    size_t o = 0;

    o += emrtd_tlv_write_header(inner + o, sizeof(inner) - o, 0x06, alg->oidlen);
    memcpy(inner + o, alg->oid, alg->oidlen);
    o += alg->oidlen;

    size_t hdr = emrtd_tlv_write_header(inner + o, sizeof(inner) - o, 0x86, pubkeylen);
    if ((hdr == 0) || (o + hdr + pubkeylen > sizeof(inner))) {
        return PM3_EOUTOFBOUND;
    }
    o += hdr;
    memcpy(inner + o, pubkey, pubkeylen);
    o += pubkeylen;

    uint8_t data[sizeof(inner) + 8] = { 0x00 };
    size_t dlen = emrtd_tlv_write_header(data, sizeof(data), 0x7F49, o);
    if (dlen == 0) {
        return PM3_EOUTOFBOUND;
    }
    memcpy(data + dlen, inner, o);
    dlen += o;

    PrintAndLogEx(DEBUG, "token input....... %s", sprint_hex_inrow(data, dlen));

    // The token is the plain MAC of the data block, it carries no SSC and gets
    // none of the secure messaging padding of ICAO 9303-11 9.8.6.1 step e.2
    return emrtd_mac_raw(alg->cipher, ks_mac, alg->keylen, data, dlen, token);
}

//-----------------------------------------------------------------------------
// Chip Authentication Mapping
//-----------------------------------------------------------------------------

// TR-03110 part 3, A.1.1.1: id-PK-ECDH is 0.4.0.127.0.7.2.2.1.2
static const uint8_t oid_pk_ecdh[] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x01, 0x02};

#define ASN1_TAG_BITSTRING  0x03

int emrtd_pace_find_ca_pubkey(const uint8_t *data, size_t datalen, size_t index, uint8_t *pub, size_t *publen) {
    if ((data == NULL) || (datalen == 0)) {
        return PM3_EINVARG;
    }

    const uint8_t *cur = data;
    const uint8_t *end = data + datalen;
    uint32_t tag = 0;
    const uint8_t *val = NULL;
    size_t vlen = 0;

    if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
        return PM3_ESOFT;
    }

    // EF_DG14 wraps the SET in tag 6E, EF_CardSecurity hands us the SET directly
    if (tag == 0x6E) {
        cur = val;
        end = val + vlen;
        if (emrtd_tlv_next(&cur, end, &tag, &val, &vlen) == false) {
            return PM3_ESOFT;
        }
    }

    if ((tag != ASN1_TAG_SET) && (tag != ASN1_TAG_SEQUENCE)) {
        return PM3_ESOFT;
    }

    const uint8_t *icur = val;
    const uint8_t *iend = val + vlen;
    size_t seen = 0;

    // SET OF SecurityInfo, we want ChipAuthenticationPublicKeyInfo
    while (emrtd_tlv_next(&icur, iend, &tag, &val, &vlen)) {

        if (tag != ASN1_TAG_SEQUENCE) {
            continue;
        }

        const uint8_t *scur = val;
        const uint8_t *send = val + vlen;
        const uint8_t *sval = NULL;
        size_t svlen = 0;
        uint32_t stag = 0;

        if (emrtd_tlv_next(&scur, send, &stag, &sval, &svlen) == false) {
            continue;
        }
        if ((stag != ASN1_TAG_OID) || (svlen != sizeof(oid_pk_ecdh)) ||
                (memcmp(sval, oid_pk_ecdh, svlen) != 0)) {
            continue;
        }

        // chipAuthenticationPublicKey ::= SubjectPublicKeyInfo
        if ((emrtd_tlv_next(&scur, send, &stag, &sval, &svlen) == false) || (stag != ASN1_TAG_SEQUENCE)) {
            continue;
        }

        const uint8_t *kcur = sval;
        const uint8_t *kend = sval + svlen;

        // AlgorithmIdentifier, skipped. The curve has to match the one PACE
        // negotiated anyway, and that is what the caller checks against.
        if (emrtd_tlv_next(&kcur, kend, &stag, &sval, &svlen) == false) {
            continue;
        }

        if ((emrtd_tlv_next(&kcur, kend, &stag, &sval, &svlen) == false) || (stag != ASN1_TAG_BITSTRING)) {
            continue;
        }

        // first byte of a BIT STRING is the number of unused bits
        if ((svlen < 2) || (sval[0] != 0x00)) {
            continue;
        }

        if ((svlen - 1) > EMRTD_EC_POINT_MAXLEN) {
            PrintAndLogEx(ERR, "error (emrtd_pace_find_ca_pubkey) key out-of-bounds, %zu bytes", svlen - 1);
            return PM3_EOUTOFBOUND;
        }

        if (seen++ < index) {
            continue;
        }

        memcpy(pub, sval + 1, svlen - 1);
        *publen = svlen - 1;
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
}

static const char *cam_encnames[] = { "CBC zero IV", "ECB", "CBC IV=E(KSenc,0)", "CBC IV=E(KSenc,1)", "not encrypted" };
#define CAM_ENC_VARIANTS  5

// One candidate decryption of DO'8A'. Returns PM3_SUCCESS when it produced
// something, which says nothing about whether it is the right something.
static int emrtd_cam_decrypt(const emrtd_session_t *ssn, int variant, uint8_t *plain) {

    if (variant == 4) {
        memcpy(plain, ssn->cam.enc_data, ssn->cam.enc_datalen);
        return PM3_SUCCESS;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    int mres = mbedtls_aes_setkey_dec(&aes, ssn->ks_enc, ssn->keylen * 8);

    if ((mres == 0) && (variant == 1)) {
        for (size_t o = 0; (o < ssn->cam.enc_datalen) && (mres == 0); o += 16) {
            mres = mbedtls_aes_crypt_ecb(&aes, MBEDTLS_AES_DECRYPT, ssn->cam.enc_data + o, plain + o);
        }
    } else if (mres == 0) {
        uint8_t iv[16] = { 0x00 };

        if (variant >= 2) {
            // the secure messaging IV construction, over the first two SSC values
            uint8_t ssc[16] = { 0x00 };
            ssc[15] = (variant == 3) ? 0x01 : 0x00;

            mbedtls_aes_context ecb;
            mbedtls_aes_init(&ecb);
            if (mbedtls_aes_setkey_enc(&ecb, ssn->ks_enc, ssn->keylen * 8) == 0) {
                mbedtls_aes_crypt_ecb(&ecb, MBEDTLS_AES_ENCRYPT, ssc, iv);
            }
            mbedtls_aes_free(&ecb);
        }

        mres = mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, ssn->cam.enc_datalen, iv,
                                     ssn->cam.enc_data, plain);
    }

    mbedtls_aes_free(&aes);
    return (mres == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

// Compares the part of a CBC plaintext that does not depend on the IV.
// Decrypting block i>0 uses only ciphertext, so everything past the first block
// is fixed no matter what IV the chip used. That makes it possible to confirm
// what CA_IC contains while still not knowing how the IV is built.
static bool emrtd_cam_tail_matches(const uint8_t *a, const uint8_t *b, size_t len) {
    return (len > 16) && (memcmp(a + 16, b + 16, len - 16) == 0);
}

void emrtd_pace_cam_dump(const emrtd_session_t *ssn, const uint8_t *pk_icc, size_t pk_icc_len) {
    const emrtd_cam_t *cam = &ssn->cam;

    PrintAndLogEx(INFO, "CAM DO'8A' (%zu)... %s", cam->enc_datalen,
                  sprint_hex_inrow(cam->enc_data, cam->enc_datalen));
    PrintAndLogEx(INFO, "CAM PK.Map.IC..... %s", sprint_hex_inrow(cam->pk_map_ic, cam->pk_map_iclen));
    PrintAndLogEx(INFO, "CAM PK.DH.IC...... %s", sprint_hex_inrow(cam->pk_dh_ic, cam->pk_dh_iclen));
    PrintAndLogEx(INFO, "CAM PK.CA.IC...... %s", sprint_hex_inrow((uint8_t *)pk_icc, pk_icc_len));
    PrintAndLogEx(INFO, "CAM SK.Map.IFD.... %s", sprint_hex_inrow((uint8_t *)cam->sk_map_ifd, cam->sk_map_ifdlen));
    PrintAndLogEx(INFO, "CAM SK.DH.IFD..... %s", sprint_hex_inrow((uint8_t *)cam->sk_dh_ifd, cam->sk_dh_ifdlen));
    PrintAndLogEx(INFO, "CAM KSenc......... %s", sprint_hex_inrow((uint8_t *)ssn->ks_enc, ssn->keylen));

    uint8_t plain[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    if (emrtd_cam_decrypt(ssn, 0, plain) != PM3_SUCCESS) {
        return;
    }

    size_t content = FindISO9797M2PaddingDataLen(plain, cam->enc_datalen);
    if (content == 0) {
        content = cam->enc_datalen;
    }

    PrintAndLogEx(INFO, "CAM plaintext..... %s", sprint_hex_inrow(plain, content));
    PrintAndLogEx(INFO, "  (first block depends on the IV, the rest does not)");

    // Two readings of what the chip is proving, both testable on the tail alone
    struct {
        const char *name;
        const uint8_t *priv;
        size_t privlen;
    } guesses[] = {
        { "x( SK.Map.IFD * PK.CA.IC )", cam->sk_map_ifd, cam->sk_map_ifdlen },
        { "x( SK.DH.IFD  * PK.CA.IC )", cam->sk_dh_ifd,  cam->sk_dh_ifdlen  },
    };

    for (size_t i = 0; i < ARRAYLEN(guesses); i++) {

        if (guesses[i].privlen == 0) {
            continue;
        }

        uint8_t expected[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
        size_t expectedlen = 0;

        if (emrtd_pace_ec_shared_x(cam->curve, guesses[i].priv, guesses[i].privlen,
                                   pk_icc, pk_icc_len, expected, &expectedlen) != PM3_SUCCESS) {
            continue;
        }

        PrintAndLogEx(INFO, "CAM %s = %s", guesses[i].name, sprint_hex_inrow(expected, expectedlen));

        if ((expectedlen == content) && emrtd_cam_tail_matches(expected, plain, content)) {

            // The content is confirmed, so the only thing still wrong is the
            // IV, and it can be read straight off: with a zero IV the first
            // plaintext block is D(C1), so IV = D(C1) xor the real first block.
            uint8_t iv[16] = { 0x00 };
            for (int b = 0; b < 16; b++) {
                iv[b] = plain[b] ^ expected[b];
            }

            PrintAndLogEx(SUCCESS, "CAM " _GREEN_("content confirmed") ", the chip proves %s", guesses[i].name);
            PrintAndLogEx(SUCCESS, "CAM required IV... %s", sprint_hex_inrow(iv, sizeof(iv)));
            return;
        }
    }

    PrintAndLogEx(WARNING, "CAM neither reading matches, the content is something else");
}

// The chip's proof, US 9215230 (Kuegler / Bender) and TR-03110 part 3:
// it sends t = SK.Map.IC * SK.CA.IC^-1 mod n, so that t * PK.CA.IC reproduces
// the ephemeral PACE key it used. Only a chip holding the static Chip
// Authentication private key can produce such a t.
static int emrtd_cam_check_scalar(mbedtls_ecp_group_id curve, const uint8_t *t, size_t tlen,
                                  const uint8_t *pk_icc, size_t pk_icc_len,
                                  const uint8_t *ephemeral, size_t ephemerallen) {
    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_point PK, R, expected;

    if ((ephemerallen == 0) || (pk_icc_len == 0)) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);
    mbedtls_ecp_point_init(&PK);
    mbedtls_ecp_point_init(&R);
    mbedtls_ecp_point_init(&expected);

    int res = emrtd_ecp_group_with_base(&grp, curve, NULL, 0, NULL, NULL);
    if (res != PM3_SUCCESS) {
        goto out;
    }

    res = PM3_EWRONGANSWER;

    if (mbedtls_ecp_point_read_binary(&grp, &PK, pk_icc, pk_icc_len) != 0) {
        goto out;
    }
    if (mbedtls_ecp_point_read_binary(&grp, &expected, ephemeral, ephemerallen) != 0) {
        goto out;
    }
    if (mbedtls_mpi_read_binary(&d, t, tlen) != 0) {
        goto out;
    }
    // a t outside [1, n-1] can never be the right answer
    if (mbedtls_ecp_check_privkey(&grp, &d) != 0) {
        goto out;
    }
    if (mbedtls_ecp_mul(&grp, &R, &d, &PK, NULL, NULL) != 0) {
        goto out;
    }

    res = (mbedtls_ecp_point_cmp(&R, &expected) == 0) ? PM3_SUCCESS : PM3_EWRONGANSWER;

out:
    mbedtls_ecp_point_free(&expected);
    mbedtls_ecp_point_free(&R);
    mbedtls_ecp_point_free(&PK);
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return res;
}

int emrtd_pace_cam_verify(const emrtd_session_t *ssn, const uint8_t *pk_icc, size_t pk_icc_len,
                          const char **mode) {
    const emrtd_cam_t *cam = &ssn->cam;

    if ((cam->negotiated == false) || (cam->enc_datalen == 0)) {
        return PM3_EINVARG;
    }

    if ((cam->enc_datalen % 16) != 0) {
        PrintAndLogEx(ERR, "CAM: encrypted authentication data is not a whole number of blocks (%zu)", cam->enc_datalen);
        return PM3_ESOFT;
    }

    static char modebuf[80];
    uint8_t plain[EMRTD_EC_POINT_MAXLEN] = { 0x00 };

    // "the chip's private ephemeral key from PACE" is ambiguous: PACE generates
    // two of them, the mapping key of step 2 and the agreement key of step 3.
    struct {
        const char *name;
        const uint8_t *key;
        size_t keylen;
    } ephemerals[] = {
        { "PK.Map.IC", cam->pk_map_ic, cam->pk_map_iclen },
        { "PK.DH.IC",  cam->pk_dh_ic,  cam->pk_dh_iclen  },
    };

    for (int enc = 0; enc < CAM_ENC_VARIANTS; enc++) {

        if (emrtd_cam_decrypt(ssn, enc, plain) != PM3_SUCCESS) {
            continue;
        }

        size_t tlen = FindISO9797M2PaddingDataLen(plain, cam->enc_datalen);
        if (tlen == 0) {
            tlen = cam->enc_datalen;
        }

        PrintAndLogEx(DEBUG, "CAM candidate (%s)... %s", cam_encnames[enc], sprint_hex_inrow(plain, tlen));

        for (size_t e = 0; e < ARRAYLEN(ephemerals); e++) {

            if (emrtd_cam_check_scalar(cam->curve, plain, tlen, pk_icc, pk_icc_len,
                                       ephemerals[e].key, ephemerals[e].keylen) == PM3_SUCCESS) {
                snprintf(modebuf, sizeof(modebuf), "%s, t * PK.CA.IC == %s", cam_encnames[enc], ephemerals[e].name);
                if (mode != NULL) {
                    *mode = modebuf;
                }
                return PM3_SUCCESS;
            }
        }
    }

    return PM3_EWRONGANSWER;
}
