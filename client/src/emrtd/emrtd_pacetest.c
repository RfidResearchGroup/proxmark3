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
// Offline regression tests for the eMRTD PACE / secure messaging primitives
//
// Unless noted otherwise every vector below is the worked example from
// ICAO Doc 9303 Part 11 (7th edition) Appendix G, "PACE-ECDH-GM-AES-CMAC-128
// with BrainpoolP256r1", which is the same example as BSI TR-SAC 1.01
// Appendix D.3. The BAC / 3DES secure messaging vectors are from
// ICAO Doc 9303 Part 11 Appendix D.4.
//-----------------------------------------------------------------------------

#include "emrtd_pacetest.h"

#include <string.h>
#include <stdio.h>

#include "emrtd/emrtd_pace.h"
#include "crypto/libpcrypto.h"
#include "ui.h"
#include "util.h"

static bool hexeq(const uint8_t *data, size_t datalen, const char *expected) {
    char buf[512] = { 0x00 };

    if ((datalen * 2) + 1 > sizeof(buf)) {
        return false;
    }

    for (size_t i = 0; i < datalen; i++) {
        snprintf(buf + (i * 2), 3, "%02X", data[i]);
    }

    return (strlen(expected) == (datalen * 2)) && (strcmp(buf, expected) == 0);
}

static size_t unhex(const char *in, uint8_t *out, size_t outlen) {
    size_t len = strlen(in) / 2;
    if (len > outlen) {
        return 0;
    }
    for (size_t i = 0; i < len; i++) {
        unsigned int v = 0;
        if (sscanf(in + (i * 2), "%2x", &v) != 1) {
            return 0;
        }
        out[i] = (uint8_t)v;
    }
    return len;
}

// ICAO 9303-11 Appendix G, the MRZ of the sample document
#define ICAO_DOCNR      "T22000129"
#define ICAO_DOB        "640812"
#define ICAO_EXPIRY     "101031"
#define ICAO_KMRZ       "T22000129364081251010318"
#define ICAO_K          "7E2D2A41C74EA0B38CD36F863939BFA8E9032AAD"

static bool test_mrz_password(void) {
    char kmrz[25] = { 0x00 };
    bool res = (emrtd_pace_kmrz(ICAO_DOCNR, ICAO_DOB, ICAO_EXPIRY, kmrz, sizeof(kmrz)) == PM3_SUCCESS);
    res = res && (strcmp(kmrz, ICAO_KMRZ) == 0);

    uint8_t k[64] = { 0x00 };
    size_t klen = 0;
    res = res && (emrtd_pace_password_mrz(ICAO_DOCNR, ICAO_DOB, ICAO_EXPIRY, k, &klen) == PM3_SUCCESS);
    res = res && (klen == 20) && hexeq(k, klen, ICAO_K);

    // Kpi = KDF(K, 3)
    uint8_t kpi[32] = { 0x00 };
    size_t kpilen = 0;
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, k, klen, 3, kpi, &kpilen) == PM3_SUCCESS);
    res = res && (kpilen == 16) && hexeq(kpi, kpilen, "89DED1B26624EC1E634C1989302849DD");

    PrintAndLogEx(SUCCESS, "MRZ password..... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_can_password(void) {
    uint8_t k[64] = { 0x00 };
    size_t klen = 0;

    // ICAO 9303-11 9.7.2, the CAN is used as its plain ASCII representation
    bool res = (emrtd_pace_password_can("123456", k, &klen) == PM3_SUCCESS);
    res = res && (klen == 6) && hexeq(k, klen, "313233343536");

    uint8_t kpi[32] = { 0x00 };
    size_t kpilen = 0;
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, k, klen, 3, kpi, &kpilen) == PM3_SUCCESS);
    // SHA-1("123456" || 00000003), first 16 bytes
    res = res && (kpilen == 16) && hexeq(kpi, kpilen, "591468CDA83D65219CCCB8560233600F");

    PrintAndLogEx(SUCCESS, "CAN password..... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_kdf(void) {
    uint8_t k[20] = { 0x00 };
    unhex(ICAO_K, k, sizeof(k));

    uint8_t out[32] = { 0x00 };
    size_t outlen = 0;
    bool res = true;

    // SHA-1 based, 16 byte keys
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, k, sizeof(k), 1, out, &outlen) == PM3_SUCCESS);
    res = res && (outlen == 16) && hexeq(out, outlen, "3CC5F8872F8B1471B47EEFDDFFC43F46");
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, k, sizeof(k), 2, out, &outlen) == PM3_SUCCESS);
    res = res && hexeq(out, outlen, "BD651C6B2FA9B4704553332007771E84");
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, k, sizeof(k), 3, out, &outlen) == PM3_SUCCESS);
    res = res && hexeq(out, outlen, "89DED1B26624EC1E634C1989302849DD");

    // Same hash, but 3DES adds odd parity to both halves (ICAO 9303-11 9.7.1.1)
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_3DES, k, sizeof(k), 3, out, &outlen) == PM3_SUCCESS);
    res = res && (outlen == 16) && hexeq(out, outlen, "89DFD0B36725EC1F624C1989312949DC");

    // SHA-256 based, truncated to 24 bytes
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES192, k, sizeof(k), 1, out, &outlen) == PM3_SUCCESS);
    res = res && (outlen == 24) && hexeq(out, outlen, "11504483F04A10A66A8FCD6D348C75A961809C54EDAA2117");
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES192, k, sizeof(k), 2, out, &outlen) == PM3_SUCCESS);
    res = res && hexeq(out, outlen, "1F35D576CE54BA775A391F9749E388C48215B7D544D62D96");
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES192, k, sizeof(k), 3, out, &outlen) == PM3_SUCCESS);
    res = res && hexeq(out, outlen, "D79A23C126202AC9051FEBFBC0E8A03B1C6645D85752B4B7");

    // SHA-256 based, full 32 bytes
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES256, k, sizeof(k), 1, out, &outlen) == PM3_SUCCESS);
    res = res && (outlen == 32) && hexeq(out, outlen, "11504483F04A10A66A8FCD6D348C75A961809C54EDAA21174726A97FB37DEF52");
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES256, k, sizeof(k), 2, out, &outlen) == PM3_SUCCESS);
    res = res && hexeq(out, outlen, "1F35D576CE54BA775A391F9749E388C48215B7D544D62D96470ABA7B19F051A3");
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES256, k, sizeof(k), 3, out, &outlen) == PM3_SUCCESS);
    res = res && hexeq(out, outlen, "D79A23C126202AC9051FEBFBC0E8A03B1C6645D85752B4B71408FA229AB6D56B");

    PrintAndLogEx(SUCCESS, "KDF.............. ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_nonce(void) {
    uint8_t kpi[16] = { 0x00 };
    uint8_t z[16] = { 0x00 };
    uint8_t s[16] = { 0x00 };

    unhex("89DED1B26624EC1E634C1989302849DD", kpi, sizeof(kpi));
    unhex("95A3A016522EE98D01E76CB6B98B42C3", z, sizeof(z));

    bool res = (emrtd_pace_decrypt_nonce(EMRTD_PACE_CIPHER_AES128, kpi, z, sizeof(z), s) == PM3_SUCCESS);
    res = res && hexeq(s, sizeof(s), "3F00C4D39D153F2B2A214A078D899B22");

    PrintAndLogEx(SUCCESS, "Nonce decrypt.... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

// ICAO 9303-11 Appendix G, PACE-ECDH-GM-AES-CMAC-128 over BrainpoolP256r1
#define ICAO_S          "3F00C4D39D153F2B2A214A078D899B22"
#define ICAO_SK_MAP_IFD "7F4EF07B9EA82FD78AD689B38D0BC78CF21F249D953BC46F4C6E19259C010F99"
#define ICAO_PK_MAP_IFD "047ACF3EFC982EC45565A4B155129EFBC74650DCBFA6362D896FC70262E0C2CC5E544552DCB6725218799115B55C9BAA6D9F6BC3A9618E70C25AF71777A9C4922D"
#define ICAO_PK_MAP_IC  "04824FBA91C9CBE26BEF53A0EBE7342A3BF178CEA9F45DE0B70AA601651FBA3F5730D8C879AAA9C9F73991E61B58F4D52EB87A0A0C709A49DC63719363CCD13C54"
#define ICAO_G_MAPPED   "048CED63C91426D4F0EB1435E7CB1D74A46723A0AF21C89634F65A9AE87A9265E28C879506743F8611AC33645C5B985C80B5F09A0B83407C1B6A4D857AE76FE522"
#define ICAO_SK_DH_IFD  "A73FB703AC1436A18E0CFA5ABB3F7BEC7A070E7A6788486BEE230C4A22762595"
#define ICAO_PK_DH_IFD  "042DB7A64C0355044EC9DF190514C625CBA2CEA48754887122F3A5EF0D5EDD301C3556F3B3B186DF10B857B58F6A7EB80F20BA5DC7BE1D43D9BF850149FBB36462"
#define ICAO_PK_DH_IC   "049E880F842905B8B3181F7AF7CAA9F0EFB743847F44A306D2D28C1D9EC65DF6DB7764B22277A2EDDC3C265A9F018F9CB852E111B768B326904B59A0193776F094"
#define ICAO_SHARED_X   "28768D20701247DAE81804C9E780EDE582A9996DB4A315020B2733197DB84925"
#define ICAO_KSENC      "F5F0E35C0D7161EE6724EE513A0D9A7F"
#define ICAO_KSMAC      "FE251C7858B356B24514B3BD5F4297D1"

static bool test_gm(void) {
    uint8_t s[16], x1[32], pk_map_ic[65], x2[32], pk_dh_ic[65];
    uint8_t pub[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    uint8_t mapped[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    uint8_t shared[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
    size_t publen = 0, mappedlen = 0, sharedlen = 0;

    unhex(ICAO_S, s, sizeof(s));
    unhex(ICAO_SK_MAP_IFD, x1, sizeof(x1));
    unhex(ICAO_PK_MAP_IC, pk_map_ic, sizeof(pk_map_ic));
    unhex(ICAO_SK_DH_IFD, x2, sizeof(x2));
    unhex(ICAO_PK_DH_IC, pk_dh_ic, sizeof(pk_dh_ic));

    const mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_BP256R1;

    bool res = (emrtd_pace_ec_pointlen(curve) == 65);

    // PK.Map.IFD = x1 * G
    res = res && (emrtd_pace_ec_pubkey(curve, NULL, 0, x1, sizeof(x1), pub, &publen) == PM3_SUCCESS);
    res = res && hexeq(pub, publen, ICAO_PK_MAP_IFD);

    // G' = s*G + x1 * PK.Map.IC
    res = res && (emrtd_pace_ec_gm(curve, s, sizeof(s), x1, sizeof(x1), pk_map_ic, sizeof(pk_map_ic),
                                   mapped, &mappedlen) == PM3_SUCCESS);
    res = res && hexeq(mapped, mappedlen, ICAO_G_MAPPED);

    // PK.DH.IFD = x2 * G'
    res = res && (emrtd_pace_ec_pubkey(curve, mapped, mappedlen, x2, sizeof(x2), pub, &publen) == PM3_SUCCESS);
    res = res && hexeq(pub, publen, ICAO_PK_DH_IFD);

    // K = x-coordinate of x2 * PK.DH.IC
    res = res && (emrtd_pace_ec_shared_x(curve, x2, sizeof(x2), pk_dh_ic, sizeof(pk_dh_ic),
                                         shared, &sharedlen) == PM3_SUCCESS);
    res = res && hexeq(shared, sharedlen, ICAO_SHARED_X);

    // KSenc = KDF(K, 1), KSmac = KDF(K, 2)
    uint8_t ks[32] = { 0x00 };
    size_t kslen = 0;
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, shared, sharedlen, 1, ks, &kslen) == PM3_SUCCESS);
    res = res && hexeq(ks, kslen, ICAO_KSENC);
    res = res && (emrtd_pace_kdf(EMRTD_PACE_CIPHER_AES128, shared, sharedlen, 2, ks, &kslen) == PM3_SUCCESS);
    res = res && hexeq(ks, kslen, ICAO_KSMAC);

    PrintAndLogEx(SUCCESS, "ECDH GM mapping.. ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_ec_keygen(void) {
    // Not a published vector, just a sanity check that the ephemeral key we
    // generate is a real key on the mapped generator and is not all zeroes.
    uint8_t mapped[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t mappedlen = unhex(ICAO_G_MAPPED, mapped, sizeof(mapped));

    uint8_t priv[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
    uint8_t pub[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    uint8_t check[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t privlen = 0, publen = 0, checklen = 0;

    bool res = (emrtd_pace_ec_keygen(MBEDTLS_ECP_DP_BP256R1, mapped, mappedlen,
                                     priv, &privlen, pub, &publen) == PM3_SUCCESS);
    res = res && (privlen == 32) && (publen == 65) && (pub[0] == 0x04);

    uint8_t zeroes[EMRTD_PACE_SECRET_MAXLEN] = { 0x00 };
    res = res && (memcmp(priv, zeroes, privlen) != 0);

    // the generated public key has to be priv * G'
    res = res && (emrtd_pace_ec_pubkey(MBEDTLS_ECP_DP_BP256R1, mapped, mappedlen,
                                       priv, privlen, check, &checklen) == PM3_SUCCESS);
    res = res && (checklen == publen) && (memcmp(check, pub, publen) == 0);

    PrintAndLogEx(SUCCESS, "Ephemeral keygen. ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_token(void) {
    uint8_t ks_mac[16] = { 0x00 };
    uint8_t pk_dh_ic[65] = { 0x00 };
    uint8_t pk_dh_ifd[65] = { 0x00 };
    uint8_t token[8] = { 0x00 };

    unhex(ICAO_KSMAC, ks_mac, sizeof(ks_mac));
    unhex(ICAO_PK_DH_IC, pk_dh_ic, sizeof(pk_dh_ic));
    unhex(ICAO_PK_DH_IFD, pk_dh_ifd, sizeof(pk_dh_ifd));

    const uint8_t oid[10] = {0x04, 0x00, 0x7F, 0x00, 0x07, 0x02, 0x02, 0x04, 0x02, 0x02};
    const emrtd_pacealg_t *alg = emrtd_pace_alg_by_oid(oid, sizeof(oid));

    bool res = (alg != NULL);
    res = res && (alg->cipher == EMRTD_PACE_CIPHER_AES128);
    res = res && (alg->mapping == EMRTD_PACE_MAP_GM);
    res = res && (alg->ka == EMRTD_PACE_KA_ECDH);

    // T_IFD is computed over the chip's key
    res = res && (emrtd_pace_token(alg, ks_mac, pk_dh_ic, sizeof(pk_dh_ic), token) == PM3_SUCCESS);
    res = res && hexeq(token, sizeof(token), "C2B0BD78D94BA866");

    // T_IC is computed over our key
    res = res && (emrtd_pace_token(alg, ks_mac, pk_dh_ifd, sizeof(pk_dh_ifd), token) == PM3_SUCCESS);
    res = res && hexeq(token, sizeof(token), "3ABB9674BCE93C08");

    PrintAndLogEx(SUCCESS, "Auth tokens...... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_ssc(void) {
    emrtd_session_t ssn;
    uint8_t ks[32] = { 0x00 };

    emrtd_sm_clear(&ssn);
    bool res = (emrtd_sm_setup(&ssn, EMRTD_PACE_CIPHER_AES128, ks, ks) == PM3_SUCCESS);
    res = res && (ssn.ssclen == 16) && (emrtd_sm_blocksize(&ssn) == 16);

    emrtd_sm_bump_ssc(&ssn);
    res = res && hexeq(ssn.ssc, ssn.ssclen, "00000000000000000000000000000001");

    // carry across the whole SSC
    memset(ssn.ssc, 0xFF, ssn.ssclen);
    ssn.ssc[ssn.ssclen - 1] = 0xFF;
    emrtd_sm_bump_ssc(&ssn);
    res = res && hexeq(ssn.ssc, ssn.ssclen, "00000000000000000000000000000000");

    memset(ssn.ssc, 0x00, ssn.ssclen);
    ssn.ssc[ssn.ssclen - 1] = 0xFF;
    emrtd_sm_bump_ssc(&ssn);
    res = res && hexeq(ssn.ssc, ssn.ssclen, "00000000000000000000000000000100");

    // 3DES sessions carry an 8 byte SSC
    emrtd_sm_clear(&ssn);
    res = res && (emrtd_sm_setup(&ssn, EMRTD_PACE_CIPHER_3DES, ks, ks) == PM3_SUCCESS);
    res = res && (ssn.ssclen == 8) && (emrtd_sm_blocksize(&ssn) == 8);
    unhex("887022120C06C2FF", ssn.ssc, sizeof(ssn.ssc));
    emrtd_sm_bump_ssc(&ssn);
    res = res && hexeq(ssn.ssc, ssn.ssclen, "887022120C06C300");

    PrintAndLogEx(SUCCESS, "SSC increment.... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_padding(void) {
    uint8_t out[32] = { 0x00 };

    bool res = (emrtd_pad_block((const uint8_t *)"\x01\x1E", 2, 8, out) == 8);
    res = res && hexeq(out, 8, "011E800000000000");

    res = res && (emrtd_pad_block((const uint8_t *)"\x01\x1E", 2, 16, out) == 16);
    res = res && hexeq(out, 16, "011E8000000000000000000000000000");

    // a full block always gets a whole block of padding added
    res = res && (emrtd_pad_block((const uint8_t *)"\x0C\xA4\x02\x0C", 4, 8, out) == 8);
    res = res && hexeq(out, 8, "0CA4020C80000000");

    uint8_t full[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    res = res && (emrtd_pad_block(full, 8, 8, out) == 16);
    res = res && hexeq(out, 16, "11223344556677888000000000000000");

    PrintAndLogEx(SUCCESS, "ISO 9797-1 pad... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

// ICAO 9303-11 Appendix D.4, the BAC secure messaging worked example.
// This is the regression test for the 3DES path, it has to keep passing
// byte for byte after any refactor of the session handling.
static bool test_sm_3des(void) {
    emrtd_session_t ssn;
    uint8_t ks_enc[16], ks_mac[16];

    unhex("979EC13B1CBFE9DCD01AB0FED307EAE5", ks_enc, sizeof(ks_enc));
    unhex("F1CB1F1FB5ADF208806B89DC579DC1F8", ks_mac, sizeof(ks_mac));

    emrtd_sm_clear(&ssn);
    bool res = (emrtd_sm_setup(&ssn, EMRTD_PACE_CIPHER_3DES, ks_enc, ks_mac) == PM3_SUCCESS);
    unhex("887022120C06C226", ssn.ssc, sizeof(ssn.ssc));

    // SELECT EF.COM, protected
    emrtd_sm_bump_ssc(&ssn);
    res = res && hexeq(ssn.ssc, ssn.ssclen, "887022120C06C227");

    uint8_t pt[16] = { 0x00 };
    uint8_t ct[16] = { 0x00 };
    size_t ptlen = emrtd_pad_block((const uint8_t *)"\x01\x1E", 2, 8, pt);
    res = res && (emrtd_sm_encrypt(&ssn, pt, ptlen, ct) == PM3_SUCCESS);
    res = res && hexeq(ct, ptlen, "6375432908C044F6");

    uint8_t n[64] = { 0x00 };
    size_t nlen = 0;
    memcpy(n, ssn.ssc, ssn.ssclen);
    nlen += ssn.ssclen;
    nlen += emrtd_pad_block((const uint8_t *)"\x0C\xA4\x02\x0C", 4, 8, n + nlen);
    memcpy(n + nlen, "\x87\x09\x01", 3);
    nlen += 3;
    memcpy(n + nlen, ct, ptlen);
    nlen += ptlen;

    uint8_t cc[8] = { 0x00 };
    res = res && (emrtd_sm_mac(&ssn, n, nlen, cc) == PM3_SUCCESS);
    res = res && hexeq(cc, sizeof(cc), "BF8B92D635FF24F8");

    // Response 99 02 90 00 8E 08 FA855A5D4C50A8ED
    emrtd_sm_bump_ssc(&ssn);
    res = res && hexeq(ssn.ssc, ssn.ssclen, "887022120C06C228");

    nlen = 0;
    memcpy(n, ssn.ssc, ssn.ssclen);
    nlen += ssn.ssclen;
    memcpy(n + nlen, "\x99\x02\x90\x00", 4);
    nlen += 4;
    res = res && (emrtd_sm_mac(&ssn, n, nlen, cc) == PM3_SUCCESS);
    res = res && hexeq(cc, sizeof(cc), "FA855A5D4C50A8ED");

    PrintAndLogEx(SUCCESS, "3DES SM.......... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

// AES secure messaging, ICAO 9303-11 9.8.6.
// The session keys are the ones the PACE example above produces. ICAO publishes
// no AES secure messaging trace, so the protected APDUs below were computed
// independently (OpenSSL / PyCryptodome) from those keys. The one judgement
// call they encode is that step e.2, "concatenate SSC and M and add padding",
// applies to AES as well as to 3DES; that was confirmed on a document doing
// PACE with AES-CMAC-256, which answers 6988 to an unpadded MAC input.
static bool test_sm_aes(void) {
    emrtd_session_t ssn;
    uint8_t ks_enc[16], ks_mac[16];

    unhex(ICAO_KSENC, ks_enc, sizeof(ks_enc));
    unhex(ICAO_KSMAC, ks_mac, sizeof(ks_mac));

    emrtd_sm_clear(&ssn);
    bool res = (emrtd_sm_setup(&ssn, EMRTD_PACE_CIPHER_AES128, ks_enc, ks_mac) == PM3_SUCCESS);
    // SSC starts at zero after PACE
    res = res && hexeq(ssn.ssc, ssn.ssclen, "00000000000000000000000000000000");

    //---------------------------------------------------------------------
    // SELECT EF.COM   ->  0CA4020C1D 871101<cryptogram> 8E08<cc> 00
    //---------------------------------------------------------------------
    emrtd_sm_bump_ssc(&ssn);

    uint8_t pt[32] = { 0x00 };
    uint8_t ct[32] = { 0x00 };
    size_t ptlen = emrtd_pad_block((const uint8_t *)"\x01\x1E", 2, 16, pt);
    res = res && (emrtd_sm_encrypt(&ssn, pt, ptlen, ct) == PM3_SUCCESS);
    res = res && hexeq(ct, ptlen, "EE0E4724F4465C1BE9C2F73ABDD73A3D");

    uint8_t n[128] = { 0x00 };
    size_t nlen = 0;
    memcpy(n, ssn.ssc, ssn.ssclen);
    nlen += ssn.ssclen;
    nlen += emrtd_pad_block((const uint8_t *)"\x0C\xA4\x02\x0C", 4, 16, n + nlen);
    memcpy(n + nlen, "\x87\x11\x01", 3);
    nlen += 3;
    memcpy(n + nlen, ct, ptlen);
    nlen += ptlen;

    uint8_t cc[8] = { 0x00 };
    res = res && (emrtd_sm_mac(&ssn, n, nlen, cc) == PM3_SUCCESS);
    res = res && hexeq(cc, sizeof(cc), "835D1B54575C955F");

    // response 99 02 90 00 8E 08 <cc>
    emrtd_sm_bump_ssc(&ssn);
    nlen = 0;
    memcpy(n, ssn.ssc, ssn.ssclen);
    nlen += ssn.ssclen;
    memcpy(n + nlen, "\x99\x02\x90\x00", 4);
    nlen += 4;
    res = res && (emrtd_sm_mac(&ssn, n, nlen, cc) == PM3_SUCCESS);
    res = res && hexeq(cc, sizeof(cc), "BEA7B381C494A079");

    //---------------------------------------------------------------------
    // READ BINARY offset 0, 4 bytes -> 0CB000000D 970104 8E08<cc> 00
    //---------------------------------------------------------------------
    emrtd_sm_bump_ssc(&ssn);
    nlen = 0;
    memcpy(n, ssn.ssc, ssn.ssclen);
    nlen += ssn.ssclen;
    nlen += emrtd_pad_block((const uint8_t *)"\x0C\xB0\x00\x00", 4, 16, n + nlen);
    memcpy(n + nlen, "\x97\x01\x04", 3);
    nlen += 3;
    res = res && (emrtd_sm_mac(&ssn, n, nlen, cc) == PM3_SUCCESS);
    res = res && hexeq(cc, sizeof(cc), "AA6BA54F44DF8364");

    // response 87 11 01 <cryptogram of 60145F01> 99 02 90 00 8E 08 <cc>
    emrtd_sm_bump_ssc(&ssn);

    uint8_t rct[16] = { 0x00 };
    unhex("645C0B1F998A088278D07942BBE94B60", rct, sizeof(rct));

    nlen = 0;
    memcpy(n, ssn.ssc, ssn.ssclen);
    nlen += ssn.ssclen;
    memcpy(n + nlen, "\x87\x11\x01", 3);
    nlen += 3;
    memcpy(n + nlen, rct, sizeof(rct));
    nlen += sizeof(rct);
    memcpy(n + nlen, "\x99\x02\x90\x00", 4);
    nlen += 4;
    res = res && (emrtd_sm_mac(&ssn, n, nlen, cc) == PM3_SUCCESS);
    res = res && hexeq(cc, sizeof(cc), "94A33C6AA2D8CCC8");

    // and the response data has to decrypt back to the start of EF_COM
    uint8_t plain[16] = { 0x00 };
    res = res && (emrtd_sm_decrypt(&ssn, rct, sizeof(rct), plain) == PM3_SUCCESS);
    res = res && hexeq(plain, sizeof(plain), "60145F01800000000000000000000000");
    res = res && hexeq(plain, 4, "60145F01");

    PrintAndLogEx(SUCCESS, "AES SM........... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_cardaccess(void) {
    // A SET of four PACEInfos:
    //   ECDH-GM-AES-CMAC-128  / BrainpoolP256r1    (supported)
    //   ECDH-GM-AES-CMAC-256  / BrainpoolP384r1    (supported)
    //   DH-GM-AES-CMAC-128    / 1024-bit MODP      (not supported, no DHM)
    //   ECDH-CAM-AES-CMAC-256 / BrainpoolP384r1    (supported, but ranked below
    //                                               GM while its proof cannot
    //                                               be checked)
    const char *blob =
        "3150"
        "3012" "060A04007F0007020204020202010202010D"
        "3012" "060A04007F00070202040204020102020110"
        "3012" "060A04007F00070202040101020102020100"
        "3012" "060A04007F00070202040604020102020110";

    uint8_t data[128] = { 0x00 };
    size_t datalen = unhex(blob, data, sizeof(data));

    emrtd_cardaccess_t ca;
    bool res = (datalen > 0);
    res = res && (emrtd_pace_parse_cardaccess(data, datalen, &ca) == PM3_SUCCESS);
    res = res && (ca.count == 4);
    // GM wins ties over CAM for now, see emrtd_pace_rank()
    res = res && (ca.best == 1);
    res = res && (ca.infos[3].supported);
    res = res && (ca.infos[3].alg != NULL) && (ca.infos[3].alg->mapping == EMRTD_PACE_MAP_CAM);
    res = res && (emrtd_pace_rank(&ca.infos[3]) < emrtd_pace_rank(&ca.infos[1]));
    // but CAM still has to be usable when it is all a document offers
    res = res && (emrtd_pace_rank(&ca.infos[3]) > 0);

    res = res && (ca.infos[0].supported) && (ca.infos[0].version == 2);
    res = res && (ca.infos[0].alg != NULL) && (ca.infos[0].alg->cipher == EMRTD_PACE_CIPHER_AES128);
    res = res && (ca.infos[0].sdp != NULL) && (ca.infos[0].sdp->curve == MBEDTLS_ECP_DP_BP256R1);

    res = res && (ca.infos[1].supported);
    res = res && (ca.infos[1].alg != NULL) && (ca.infos[1].alg->cipher == EMRTD_PACE_CIPHER_AES256);
    res = res && (ca.infos[1].sdp != NULL) && (ca.infos[1].sdp->curve == MBEDTLS_ECP_DP_BP384R1);

    res = res && (ca.infos[2].supported == false) && (ca.infos[2].reason != NULL);

    // curves that this tree's mbedtls does not carry must never resolve
    const emrtd_pacesdp_t *sdp = emrtd_pace_sdp_by_id(14);  // BrainpoolP320r1
    res = res && (sdp != NULL) && (sdp->curve == MBEDTLS_ECP_DP_NONE);
    sdp = emrtd_pace_sdp_by_id(9);                          // BrainpoolP192r1
    res = res && (sdp != NULL) && (sdp->curve == MBEDTLS_ECP_DP_NONE);
    sdp = emrtd_pace_sdp_by_id(12);                         // NIST P-256
    res = res && (sdp != NULL) && (sdp->curve == MBEDTLS_ECP_DP_SECP256R1);

    // truncated input must be rejected, not walked off the end of the buffer
    emrtd_cardaccess_t bad;
    for (size_t cut = 1; cut < datalen; cut++) {
        if (emrtd_pace_parse_cardaccess(data, cut, &bad) == PM3_SUCCESS) {
            // a shorter but still well formed prefix is only possible if it
            // parses to fewer entries than the full blob
            if (bad.count >= ca.count) {
                res = false;
                break;
            }
        }
    }

    PrintAndLogEx(SUCCESS, "EF_CardAccess.... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

// Chip Authentication Mapping.
//
// The chip sends t = SK.Map.IC * SK.CA.IC^-1 mod n encrypted with KSenc, so
// that t * PK.CA.IC reproduces the ephemeral PACE key it used. Only a chip
// holding the static Chip Authentication private key can produce such a t.
// See US 9215230 (Kuegler / Bender) and TR-03110 part 3.
//
// No published vector exists, so this one is constructed the way a genuine
// chip would: t is derived from a chosen static key and mapping key, padded
// and encrypted. t is 32 bytes here and DO'8A' is 48, mirroring a real
// BrainpoolP384r1 document where a 48 byte t arrives as 64 bytes.
#define CAM_PK_ICC     "048DF71464547FC82DCF1650BBC5B72DCD2CC3D9A71283F6E374C0958F316026DB0E1F619B0FBBD54B130E9D04B5201A0522D4CC199888B6D76C9A22BDD79F2D45"
#define CAM_PK_MAP_IC  "041D840F08CE75DDA65326277A850039892B9A399614221865EDC0DCD27DE1B4EEA5E8B3CB9560F08D09DDB3B4DE4D936FF1311A9F6D20047E94B3E458BCA5778B"
#define CAM_KSENC      "0102030405060708090A0B0C0D0E0F10"
#define CAM_DO8A       "25887095A78FA691E074800EF9B097F96EBFA89ED8350BCAEDFD309DE91878ADCE249F1253D13483C441B1A08DFD74DE"

static bool test_cam(void) {
    uint8_t pk_icc[65], ks[16];

    size_t pk_icclen = unhex(CAM_PK_ICC, pk_icc, sizeof(pk_icc));
    unhex(CAM_KSENC, ks, sizeof(ks));

    emrtd_session_t ssn;
    emrtd_sm_clear(&ssn);
    bool res = (emrtd_sm_setup(&ssn, EMRTD_PACE_CIPHER_AES128, ks, ks) == PM3_SUCCESS);

    ssn.cam.negotiated = true;
    ssn.cam.curve = MBEDTLS_ECP_DP_BP256R1;
    ssn.cam.pk_map_iclen = unhex(CAM_PK_MAP_IC, ssn.cam.pk_map_ic, sizeof(ssn.cam.pk_map_ic));
    ssn.cam.enc_datalen = unhex(CAM_DO8A, ssn.cam.enc_data, sizeof(ssn.cam.enc_data));
    res = res && (ssn.cam.enc_datalen == 48);

    const char *mode = NULL;
    res = res && (emrtd_pace_cam_verify(&ssn, pk_icc, pk_icclen, &mode) == PM3_SUCCESS);
    res = res && (mode != NULL) && (strstr(mode, "PK.Map.IC") != NULL);

    // a chip that returns the wrong blob must not verify under any encoding
    ssn.cam.enc_data[0] ^= 0x01;
    res = res && (emrtd_pace_cam_verify(&ssn, pk_icc, pk_icclen, &mode) != PM3_SUCCESS);
    ssn.cam.enc_data[0] ^= 0x01;

    // nor may a different, perfectly valid, chip authentication key pass
    uint8_t other[65] = { 0x00 };
    size_t otherlen = unhex(CAM_PK_MAP_IC, other, sizeof(other));
    res = res && (emrtd_pace_cam_verify(&ssn, other, otherlen, &mode) != PM3_SUCCESS);

    // and the chip's own public key has to come out of EF_DG14
    const char *dg14 =
        "6E5E315C305A060904007F000702020102304D300706052B8104002203420004"
        "8DF71464547FC82DCF1650BBC5B72DCD2CC3D9A71283F6E374C0958F316026DB"
        "0E1F619B0FBBD54B130E9D04B5201A0522D4CC199888B6D76C9A22BDD79F2D45";

    uint8_t dg14bin[128] = { 0x00 };
    size_t dg14len = unhex(dg14, dg14bin, sizeof(dg14bin));

    uint8_t found[EMRTD_EC_POINT_MAXLEN] = { 0x00 };
    size_t foundlen = 0;
    res = res && (emrtd_pace_find_ca_pubkey(dg14bin, dg14len, 0, found, &foundlen) == PM3_SUCCESS);
    res = res && (foundlen == pk_icclen) && hexeq(found, foundlen, CAM_PK_ICC);

    // truncated EF_DG14 must be refused, not walked off the end
    for (size_t cut = 1; cut < dg14len; cut++) {
        if (emrtd_pace_find_ca_pubkey(dg14bin, cut, 0, found, &foundlen) == PM3_SUCCESS) {
            res = false;
            break;
        }
    }

    PrintAndLogEx(SUCCESS, "CA mapping....... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

static bool test_tlv(void) {
    const uint8_t data[] = {0x7F, 0x49, 0x04, 0x06, 0x02, 0xAA, 0xBB};
    const uint8_t *cur = data;
    const uint8_t *end = data + sizeof(data);
    uint32_t tag = 0;
    const uint8_t *val = NULL;
    size_t vlen = 0;

    bool res = emrtd_tlv_next(&cur, end, &tag, &val, &vlen);
    res = res && (tag == 0x7F49) && (vlen == 4);

    const uint8_t *icur = val;
    const uint8_t *iend = val + vlen;
    res = res && emrtd_tlv_next(&icur, iend, &tag, &val, &vlen);
    res = res && (tag == 0x06) && (vlen == 2) && (val[0] == 0xAA) && (val[1] == 0xBB);
    res = res && (emrtd_tlv_next(&icur, iend, &tag, &val, &vlen) == false);

    // a length that runs past the buffer must be rejected
    const uint8_t bad[] = {0x30, 0x10, 0x01};
    cur = bad;
    res = res && (emrtd_tlv_next(&cur, bad + sizeof(bad), &tag, &val, &vlen) == false);

    uint8_t out[8] = { 0x00 };
    res = res && (emrtd_tlv_write_header(out, sizeof(out), 0x7F49, 0x4F) == 3);
    res = res && hexeq(out, 3, "7F494F");
    res = res && (emrtd_tlv_write_header(out, sizeof(out), 0x86, 0x41) == 2);
    res = res && hexeq(out, 2, "8641");
    res = res && (emrtd_tlv_write_header(out, sizeof(out), 0x87, 0x81) == 3);
    res = res && hexeq(out, 3, "878181");
    res = res && (emrtd_tlv_write_header(out, 1, 0x87, 0x81) == 0);

    PrintAndLogEx(SUCCESS, "BER-TLV.......... ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    return res;
}

bool emrtd_test(bool verbose) {
    (void)verbose;
    bool res = true;

    PrintAndLogEx(INFO, "------ " _CYAN_("eMRTD PACE tests") " ------");

    res = test_padding() && res;
    res = test_tlv() && res;
    res = test_mrz_password() && res;
    res = test_can_password() && res;
    res = test_kdf() && res;
    res = test_nonce() && res;
    res = test_cardaccess() && res;
    res = test_gm() && res;
    res = test_ec_keygen() && res;
    res = test_token() && res;
    res = test_cam() && res;
    res = test_ssc() && res;
    res = test_sm_3des() && res;
    res = test_sm_aes() && res;

    PrintAndLogEx(INFO, "---------------------------");
    PrintAndLogEx(SUCCESS, "Tests ( %s )", (res) ? _GREEN_("ok") : _RED_("fail"));
    PrintAndLogEx(NORMAL, "");
    return res;
}
