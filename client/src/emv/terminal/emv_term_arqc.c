//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------

#include "emv_term_arqc.h"
#include "des.h"
#include <string.h>

static void des8_ecb(const uint8_t key[8], const uint8_t in[8], uint8_t out[8], bool encrypt) {
    mbedtls_des_context ctx;
    mbedtls_des_init(&ctx);
    if (encrypt) {
        mbedtls_des_setkey_enc(&ctx, key);
    } else {
        mbedtls_des_setkey_dec(&ctx, key);
    }
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

static void des3_ecb(const uint8_t key[16], const uint8_t in[8], uint8_t out[8]) {
    mbedtls_des3_context ctx;
    mbedtls_des3_init(&ctx);
    mbedtls_des3_set2key_enc(&ctx, key);
    mbedtls_des3_crypt_ecb(&ctx, in, out);
    mbedtls_des3_free(&ctx);
}

void emv_term_sk_derive_ac(const uint8_t ac_mk[16], uint16_t atc, uint8_t sk[16]) {
    uint8_t block[8] = {0};
    block[0] = (uint8_t)(atc >> 8);
    block[1] = (uint8_t)(atc & 0xFF);
    block[6] = 0xF0;
    des3_ecb(ac_mk, block, sk);

    block[6] = 0x0F;
    block[7] = 0x00;
    des3_ecb(ac_mk, block, sk + 8);
}

static size_t pad_iso9797_m2(const uint8_t *in, size_t in_len, uint8_t *out, size_t max_out) {
    if (in_len + 1 > max_out) {
        return 0;
    }
    memcpy(out, in, in_len);
    out[in_len] = 0x80;
    size_t total = in_len + 1;
    while (total % 8) {
        if (total >= max_out) {
            return 0;
        }
        out[total++] = 0x00;
    }
    return total;
}

void emv_term_retail_mac_3des(const uint8_t sk[16], const uint8_t *data, size_t data_len, uint8_t mac[8]) {
    const uint8_t *k0 = sk;
    const uint8_t *k1 = sk + 8;

    uint8_t padded[512];
    size_t plen = pad_iso9797_m2(data, data_len, padded, sizeof(padded));
    if (plen == 0) {
        memset(mac, 0, 8);
        return;
    }

    uint8_t intermediate[8] = {0};
    uint8_t block[8];
    for (size_t i = 0; i < plen; i += 8) {
        memcpy(block, padded + i, 8);
        for (int x = 0; x < 8; x++) {
            intermediate[x] ^= block[x];
        }
        des8_ecb(k0, intermediate, intermediate, true);
    }

    uint8_t tmp[8];
    des8_ecb(k1, intermediate, tmp, false);
    des8_ecb(k0, tmp, mac, true);
}

bool emv_term_arqc_verify(const uint8_t sk[16], const uint8_t *cdol1, size_t cdol1_len,
                          const uint8_t *arqc, size_t arqc_len) {
    if (!sk || !cdol1 || !arqc || arqc_len < 8) {
        return false;
    }
    uint8_t mac[8] = {0};
    emv_term_retail_mac_3des(sk, cdol1, cdol1_len, mac);
    return memcmp(mac, arqc, 8) == 0;
}

bool emv_term_arpc_compute(emv_arpc_method_t method, const uint8_t sk[16],
                           const uint8_t *arqc, size_t arqc_len,
                           const uint8_t *arc, size_t arc_len,
                           uint8_t *arpc, size_t *arpc_len) {
    if (!sk || !arqc || arqc_len < 8 || !arpc || !arpc_len) {
        return false;
    }

    uint8_t input[8] = {0};
    memcpy(input, arqc, arqc_len > 8 ? 8 : arqc_len);

    if (method == EMV_ARPC_XOR_STUB) {
        for (size_t i = 0; i < 8 && i < arc_len; i++) {
            input[i] ^= arc[i];
        }
        memcpy(arpc, input, 8);
        *arpc_len = 8;
        return true;
    }

    if (method == EMV_ARPC_CVN10) {
        for (size_t i = 0; i < arc_len && i < 8; i++) {
            input[i] ^= arc[i];
        }
        des3_ecb(sk, input, arpc);
        *arpc_len = 8;
        return true;
    }

    // CVN18 method 1: retail MAC on (ARQC xor pad(ARC))
    uint8_t pad[8] = {0};
    if (arc_len >= 2) {
        pad[0] = arc[0];
        pad[1] = arc[1];
    }
    for (size_t i = 0; i < 8; i++) {
        input[i] ^= pad[i];
    }
    emv_term_retail_mac_3des(sk, input, 8, arpc);
    *arpc_len = 8;
    return true;
}
