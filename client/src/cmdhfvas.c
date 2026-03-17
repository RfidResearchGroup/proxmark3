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
// An implementation of the Value Added Service protocol
//-----------------------------------------------------------------------------

#include "cmdhfvas.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "ansi.h"
#include "cmdhf14a.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "ui.h"
#include "util.h"
#include "util_posix.h"
#include "iso7816/iso7816core.h"
#include "crc16.h"
#include <stddef.h>
#include <stdbool.h>
#include <ctype.h>
#include "mifare.h"
#include <stdlib.h>
#include <string.h>
#include "crypto/libpcrypto.h"
#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/ecdh.h"
#include "mbedtls/ecc_point_compression.h"
#include "mbedtls/gcm.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

#define VAS_MAX_KEY_INPUT 8192
#define VAS_MAX_PID_ITEMS 8
#define VAS_MAX_KEY_ITEMS 16
#define VAS_MAX_MOBILE_TOKEN_LEN 32
#define VAS_MAX_CRYPTOGRAM_LEN 256

static const iso14a_polling_frame_t WUPA_FRAME = {
    .frame = { 0x52 },
    .frame_length = 1,
    .last_byte_bits = 7,
    .extra_delay = 0,
};

static const iso14a_polling_frame_t ECP_VAS_ONLY_FRAME = {
    .frame = {0x6a, 0x01, 0x00, 0x00, 0x02, 0xe4, 0xd2},
    .frame_length = 7,
    .last_byte_bits = 8,
    .extra_delay = 0,
};


enum {
    VAS_MODE_VAS_OR_PAY = 0x00,
    VAS_MODE_VAS_AND_PAY = 0x01,
    VAS_MODE_VAS_ONLY = 0x02,
};

static int vas_parse_mode(const char *mode_text, uint8_t *mode_out) {
    if (mode_out == NULL) {
        return PM3_EINVARG;
    }

    if (mode_text == NULL || *mode_text == '\0' || strcmp(mode_text, "vasonly") == 0 || strcmp(mode_text, "vas") == 0) {
        *mode_out = VAS_MODE_VAS_ONLY;
        return PM3_SUCCESS;
    }
    if (strcmp(mode_text, "vasandpay") == 0) {
        *mode_out = VAS_MODE_VAS_AND_PAY;
        return PM3_SUCCESS;
    }
    if (strcmp(mode_text, "vasorpay") == 0) {
        *mode_out = VAS_MODE_VAS_OR_PAY;
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Invalid mode '%s' (expected: vasorpay, vasandpay, vasonly)", mode_text);
    return PM3_EINVARG;
}

static void vas_build_ecp_frame(uint8_t vas_mode, iso14a_polling_frame_t *frame_out) {
    if (frame_out == NULL) {
        return;
    }

    memset(frame_out, 0, sizeof(*frame_out));
    frame_out->frame[0] = 0x6a;
    frame_out->frame[1] = 0x01;
    frame_out->frame[2] = 0x00;
    frame_out->frame[3] = 0x00;
    frame_out->frame[4] = vas_mode;
    compute_crc(CRC_14443_A, frame_out->frame, 5, &frame_out->frame[5], &frame_out->frame[6]);
    frame_out->frame_length = 7;
    frame_out->last_byte_bits = 8;
    frame_out->extra_delay = 0;
}

static const uint8_t aid[] = { 0x4f, 0x53, 0x45, 0x2e, 0x56, 0x41, 0x53, 0x2e, 0x30, 0x31 };
static const uint8_t getVasUrlOnlyP2 = 0x00;
static const uint8_t getVasFullReqP2 = 0x01;
static const uint8_t kVasEncryptedDataLabel[27] = "ApplePay encrypted VAS data";
static const uint8_t kVasAesGcmLabel[13] = "id-aes256-GCM";


static bool VASWalletTypeIsApplePay(const uint8_t *walletType, size_t walletTypeLen) {
    static const uint8_t applePayWalletType[] = "ApplePay";
    return walletType != NULL
           && walletTypeLen == (sizeof(applePayWalletType) - 1)
           && memcmp(walletType, applePayWalletType, sizeof(applePayWalletType) - 1) == 0;
}

static const uint16_t VAS_STATUS_NOT_AVAILABLE = 0xFFFF;

static void PrintVASFeatureBit(const char *bits, uint8_t mask, uint8_t bit, const char *enabled, const char *disabled) {
    const bool is_enabled = (mask & (1U << bit)) != 0;
    const int pad = 7 - bit;
    PrintAndLogEx(INFO, "   %s",
                  sprint_breakdown_bin(is_enabled ? C_GREEN : C_NONE, bits, 8, pad, 1, is_enabled ? enabled : disabled));
}

static void PrintVASCapabilitiesValue(const char *label, uint8_t mask) {
    if (label == NULL || *label == '\0') {
        label = "Capabilities";
    }

    const char *bits = sprint_bin(&mask, 1);
    PrintAndLogEx(INFO, "%s " _YELLOW_("%s") " (" _YELLOW_("0x%02X") ")", label, bits, mask);
    PrintVASFeatureBit(bits, mask, 7, "Reserved/unknown bit set", "Reserved/unknown bit clear");
    PrintVASFeatureBit(bits, mask, 6, "Reserved/unknown bit set", "Reserved/unknown bit clear");
    PrintVASFeatureBit(bits, mask, 5, "Payment may be performed", "Payment may not be performed");
    PrintVASFeatureBit(bits, mask, 4, "Payment may be skipped", "Payment may not be skipped");
    PrintVASFeatureBit(bits, mask, 3, "VAS may be performed", "VAS may not be performed");
    PrintVASFeatureBit(bits, mask, 2, "VAS may be skipped", "VAS may not be skipped");
    PrintVASFeatureBit(bits, mask, 1, "Encrypted VAS data supported", "Encrypted VAS data not supported");
    PrintVASFeatureBit(bits, mask, 0, "Plaintext VAS data supported", "Plaintext VAS data not supported");
}

static const char *vas_status_name(uint16_t sw) {
    static char unknown_status_name[20] = {0};

    switch (sw) {
        case VAS_STATUS_NOT_AVAILABLE:
            return "N/A";
        case 0x9000:
            return "OK";
        case 0x6100:
            return "WARNING_NO_DATA_RETURNED";
        case 0x6287:
            return "DATA_NOT_ACTIVATED";
        case 0x6982:
            return "SECURITY_STATUS_NOT_SATISFIED";
        case 0x6984:
            return "USER_INTERVENTION_REQUIRED";
        case 0x6A81:
            return "FUNCTION_NOT_SUPPORTED";
        case 0x6A82:
            return "FILE_NOT_FOUND";
        case 0x6700:
            return "WRONG_LC_FIELD";
        case 0x6A80:
            return "INCORRECT_DATA";
        case 0x6A83:
            return "DATA_NOT_FOUND";
        case 0x6B00:
            return "WRONG_PARAMETERS";
    }
    snprintf(unknown_status_name, sizeof(unknown_status_name), "UNKNOWN (0x%04X)", sw);
    return unknown_status_name;
}

static bool vas_status_is_success(uint16_t sw) {
    const uint8_t sw1 = (uint8_t)(sw >> 8);
    return (sw1 == 0x90) || (sw1 == 0x91);
}

static void PrintVASStatusLine(const char *label, uint16_t sw) {
    PrintAndLogEx(INFO, "%s " _YELLOW_("%04X") " (%s)", label, sw, vas_status_name(sw));
}

static const char *vas_status_meaning(uint16_t sw) {
    switch (sw) {
        case VAS_STATUS_NOT_AVAILABLE:
            return "No ISO14443-A card in field";
        case 0x6287:
            return "Data not activated (device locked or authentication required)";
        case 0x6984:
            return "User intervention/selection required";
        case 0x6A83:
            return "Data not found for this pass identifier";
        case 0x9000:
            return "Success";
        default:
            return "Request failed";
    }
}

static void PrintVASFailureReason(uint16_t select_status, uint16_t get_data_status) {
    if (select_status == VAS_STATUS_NOT_AVAILABLE && get_data_status == VAS_STATUS_NOT_AVAILABLE) {
        PrintAndLogEx(WARNING, "%s: %s", vas_status_name(VAS_STATUS_NOT_AVAILABLE), vas_status_meaning(VAS_STATUS_NOT_AVAILABLE));
    } else if (select_status != 0x9000) {
        PrintAndLogEx(FAILED, "%s: OSE/VAS applet not selected", vas_status_name(select_status));
    } else if (get_data_status != VAS_STATUS_NOT_AVAILABLE) {
        PrintAndLogEx(FAILED, "%s: %s", vas_status_name(get_data_status), vas_status_meaning(get_data_status));
    }
}

static int ParseSelectVASResponse(const uint8_t *response, size_t resLen, uint8_t *capabilitiesOut) {
    struct tlvdb *tlvRoot = tlvdb_parse_multi(response, resLen);

    const struct tlvdb *versionTlv = tlvdb_find_full(tlvRoot, 0x9F21);
    if (versionTlv == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    const struct tlv *version = tlvdb_get_tlv(versionTlv);
    if (version->len != 2) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    if (version->value[0] != 0x01 || version->value[1] != 0x00) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }

    const struct tlvdb *capabilitiesTlv = tlvdb_find_full(tlvRoot, 0x9F23);
    if (capabilitiesTlv == NULL) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    const struct tlv *capabilities = tlvdb_get_tlv(capabilitiesTlv);
    if (capabilities->len != 4
            || capabilities->value[0] != 0x00
            || capabilities->value[1] != 0x00
            || capabilities->value[2] != 0x00
            || (capabilities->value[3] & 8) == 0) {
        tlvdb_free(tlvRoot);
        return PM3_ECARDEXCHANGE;
    }
    if (capabilitiesOut != NULL) {
        *capabilitiesOut = capabilities->value[3];
    }

    tlvdb_free(tlvRoot);
    return PM3_SUCCESS;
}

static int PrintVASSelectInfo(const uint8_t *response, size_t responseLen, bool verbose) {
    struct tlvdb *tlvRoot = tlvdb_parse_multi(response, responseLen);
    if (tlvRoot == NULL) {
        return PM3_ECARDEXCHANGE;
    }

    bool skip_vas_details = false;
    const struct tlvdb *walletTypeTlv = tlvdb_find_full(tlvRoot, 0x50);
    if (walletTypeTlv != NULL) {
        const struct tlv *walletType = tlvdb_get_tlv(walletTypeTlv);
        if (VASWalletTypeIsApplePay(walletType->value, walletType->len) == false) {
            PrintAndLogEx(WARNING, "Wallet type is not ApplePay. This likely isn't Apple VAS.");
            skip_vas_details = true;
        }
    }

    if (verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogInfoHeader("OSE Information");
        if (walletTypeTlv == NULL) {
            PrintAndLogEx(WARNING, "Wallet type.......... " _YELLOW_("not present"));
        } else {
            const struct tlv *walletType = tlvdb_get_tlv(walletTypeTlv);
            PrintAndLogEx(INFO, "Wallet type.......... " _YELLOW_("%s"), sprint_ascii(walletType->value, walletType->len));
        }
    }

    if (verbose && skip_vas_details == false) {
        const struct tlvdb *versionTlv = tlvdb_find_full(tlvRoot, 0x9F21);
        if (versionTlv == NULL) {
            PrintAndLogEx(WARNING, "VAS version.......... " _YELLOW_("not present"));
        } else {
            const struct tlv *version = tlvdb_get_tlv(versionTlv);
            if (version->len == 2) {
                PrintAndLogEx(INFO, "VAS version.......... " _YELLOW_("%d.%d"), version->value[0], version->value[1]);
            } else {
                PrintAndLogEx(WARNING, "VAS version.......... " _YELLOW_("invalid length (%zu)"), version->len);
            }
        }

        const struct tlvdb *nonceTlv = tlvdb_find_full(tlvRoot, 0x9F24);
        if (nonceTlv == NULL) {
            PrintAndLogEx(WARNING, "Device nonce......... " _YELLOW_("not present"));
        } else {
            const struct tlv *nonce = tlvdb_get_tlv(nonceTlv);
            PrintAndLogEx(INFO, "Device nonce......... " _YELLOW_("%s"), sprint_hex_inrow(nonce->value, nonce->len));
            if (nonce->len != 4) {
                PrintAndLogEx(WARNING, "Device nonce......... " _YELLOW_("unexpected length (%zu)"), nonce->len);
            }
        }

        const struct tlvdb *capabilitiesTlv = tlvdb_find_full(tlvRoot, 0x9F23);
        if (capabilitiesTlv == NULL) {
            PrintAndLogEx(WARNING, "Mobile capabilities.. " _YELLOW_("not present"));
        } else {
            const struct tlv *capabilities = tlvdb_get_tlv(capabilitiesTlv);
            if (capabilities->len != 4) {
                PrintAndLogEx(WARNING, "Mobile capabilities.. " _YELLOW_("invalid length (%zu)"), capabilities->len);
            } else {
                PrintVASCapabilitiesValue("Mobile capabilities..", capabilities->value[3]);
            }
        }
    }

    tlvdb_free(tlvRoot);
    return PM3_SUCCESS;
}

static int CreateGetVASDataCommand(const uint8_t *pidHash, const char *url, size_t urlLen, uint8_t vas_mode, bool isFinalRequest, uint8_t *out, int *outLen) {
    if (pidHash == NULL && url == NULL) {
        PrintAndLogEx(FAILED, "Must provide a Pass Type ID or a URL");
        return PM3_EINVARG;
    }

    if (url != NULL && urlLen > 256) {
        PrintAndLogEx(FAILED, "URL must be less than 256 characters");
        return PM3_EINVARG;
    }

    const uint8_t p2 = pidHash == NULL ? getVasUrlOnlyP2 : getVasFullReqP2;

    size_t reqTlvLen = 19 + (pidHash != NULL ? 35 : 0) + (url != NULL ? 3 + urlLen : 0);
    uint8_t *reqTlv = calloc(reqTlvLen, sizeof(uint8_t));
    if (reqTlv == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    uint8_t version[] = {0x9F, 0x22, 0x02, 0x01, 0x00};
    memcpy(reqTlv, version, sizeof(version));

    uint8_t terminalNonce[] = {0x9F, 0x28, 0x04, 0x00, 0x00, 0x00, 0x00};
    for (size_t i = 0; i < 4; i++) {
        terminalNonce[3 + i] = (uint8_t)(rand() & 0xFF);
    }
    memcpy(reqTlv + sizeof(version), terminalNonce, sizeof(terminalNonce));

    uint8_t capabilitiesMask = (isFinalRequest ? 0x00 : 0x80) | (vas_mode & 0x03);
    uint8_t terminalCapabilities[] = {0x9F, 0x26, 0x04, 0x00, 0x80, 0x00, capabilitiesMask};
    memcpy(reqTlv + sizeof(version) + sizeof(terminalNonce), terminalCapabilities, sizeof(terminalCapabilities));

    if (pidHash != NULL) {
        size_t offset = sizeof(version) + sizeof(terminalNonce) + sizeof(terminalCapabilities);
        reqTlv[offset] = 0x9F;
        reqTlv[offset + 1] = 0x25;
        reqTlv[offset + 2] = 32;
        memcpy(reqTlv + offset + 3, pidHash, 32);
    }

    if (url != NULL) {
        size_t offset = sizeof(version) + sizeof(terminalNonce) + sizeof(terminalCapabilities) + (pidHash != NULL ? 35 : 0);
        reqTlv[offset] = 0x9F;
        reqTlv[offset + 1] = 0x29;
        reqTlv[offset + 2] = urlLen;
        memcpy(reqTlv + offset + 3, url, urlLen);
    }

    out[0] = 0x80;
    out[1] = 0xCA;
    out[2] = 0x01;
    out[3] = p2;
    out[4] = reqTlvLen;
    memcpy(out + 5, reqTlv, reqTlvLen);
    out[5 + reqTlvLen] = 0x00;

    *outLen = 6 + reqTlvLen;

    free(reqTlv);
    return PM3_SUCCESS;
}

static int ParseGetVASDataResponse(const uint8_t *res, size_t resLen,
                                   bool requireCryptogram,
                                   uint8_t *mobileToken, size_t *mobileTokenLen,
                                   uint8_t *cryptogram, size_t *cryptogramLen) {
    struct tlvdb *tlvRoot = tlvdb_parse_multi(res, resLen);
    if (tlvRoot == NULL) {
        return PM3_ECARDEXCHANGE;
    }

    bool has_payload = false;

    if (mobileTokenLen != NULL) {
        *mobileTokenLen = 0;
    }
    const struct tlvdb *mobileTokenTlvdb = tlvdb_find_full(tlvRoot, 0x9F2A);
    if (mobileTokenTlvdb != NULL && mobileToken != NULL && mobileTokenLen != NULL) {
        const struct tlv *mobileTokenTlv = tlvdb_get_tlv(mobileTokenTlvdb);
        if (mobileTokenTlv->len > VAS_MAX_MOBILE_TOKEN_LEN) {
            tlvdb_free(tlvRoot);
            return PM3_ECARDEXCHANGE;
        }
        memcpy(mobileToken, mobileTokenTlv->value, mobileTokenTlv->len);
        *mobileTokenLen = mobileTokenTlv->len;
        has_payload = true;
    }

    const struct tlvdb *cryptogramTlvdb = tlvdb_find_full(tlvRoot, 0x9F27);
    if (cryptogramTlvdb == NULL) {
        tlvdb_free(tlvRoot);
        if (requireCryptogram || !has_payload) {
            return PM3_ECARDEXCHANGE;
        }
        return PM3_SUCCESS;
    }

    if (cryptogram != NULL && cryptogramLen != NULL) {
        const struct tlv *cryptogramTlv = tlvdb_get_tlv(cryptogramTlvdb);
        if (cryptogramTlv->len > VAS_MAX_CRYPTOGRAM_LEN) {
            tlvdb_free(tlvRoot);
            return PM3_ECARDEXCHANGE;
        }
        memcpy(cryptogram, cryptogramTlv->value, cryptogramTlv->len);
        *cryptogramLen = cryptogramTlv->len;
        has_payload = true;
    }

    tlvdb_free(tlvRoot);
    if (!has_payload) {
        return PM3_ECARDEXCHANGE;
    }
    return PM3_SUCCESS;
}

static int LoadReaderPrivateKey(const char *input_or_path, mbedtls_ecp_keypair *privKey) {
    uint8_t key_d[32] = {0};
    int res = ensure_ec_private_key(input_or_path, MBEDTLS_ECP_DP_SECP256R1, key_d, sizeof(key_d));
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Invalid private key input");
        PrintAndLogEx(INFO, "Accepted formats:");
        PrintAndLogEx(INFO, "  1) PEM string with headers (BEGIN PRIVATE KEY)");
        PrintAndLogEx(INFO, "  2) DER bytes as hex or base64");
        PrintAndLogEx(INFO, "  3) Scalar as hex or base64");
        PrintAndLogEx(INFO, "  4) File path to a key in any of the formats above");
        return res;
    }

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    static const uint8_t personalization[] = "pm3-vas";
    int ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                    personalization, sizeof(personalization) - 1);
    if (ret != 0) {
        mbedtls_ctr_drbg_free(&ctr_drbg);
        mbedtls_entropy_free(&entropy);
        PrintAndLogEx(FAILED, "Unable to initialize random generator for key derivation");
        return PM3_ESOFT;
    }

    ret = mbedtls_ecp_group_load(&privKey->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret == 0) {
        ret = mbedtls_mpi_read_binary(&privKey->d, key_d, sizeof(key_d));
    }
    if (ret == 0) {
        ret = mbedtls_ecp_check_privkey(&privKey->grp, &privKey->d);
    }
    if (ret == 0) {
        ret = mbedtls_ecp_mul(&privKey->grp, &privKey->Q, &privKey->d, &privKey->grp.G,
                              mbedtls_ctr_drbg_random, &ctr_drbg);
    }
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);

    if (ret != 0 || mbedtls_ecp_check_pubkey(&privKey->grp, &privKey->Q) != 0) {
        PrintAndLogEx(FAILED, "VAS protocol requires a valid private key on curve P-256");
        return PM3_EINVARG;
    }
    return PM3_SUCCESS;
}

static int GetPrivateKeyId(mbedtls_ecp_keypair *privKey, uint8_t *keyId) {
    uint8_t xcoord[32] = {0};
    if (mbedtls_mpi_write_binary(&privKey->Q.X, xcoord, sizeof(xcoord))) {
        return PM3_EINVARG;
    }

    uint8_t hash[32] = {0};
    sha256hash(xcoord, 32, hash);

    memcpy(keyId, hash, 4);
    return PM3_SUCCESS;
}

static int LoadMobileEphemeralKey(const uint8_t *xcoordBuf, mbedtls_ecp_keypair *pubKey) {
    uint8_t compressedEcKey[33] = {0};
    compressedEcKey[0] = 0x02;
    memcpy(compressedEcKey + 1, xcoordBuf, 32);

    uint8_t decompressedEcKey[65] = {0};
    size_t decompressedEcKeyLen = 0;
    if (mbedtls_ecp_decompress(&pubKey->grp, compressedEcKey, sizeof(compressedEcKey), decompressedEcKey, &decompressedEcKeyLen, sizeof(decompressedEcKey))) {
        return PM3_EINVARG;
    }

    if (mbedtls_ecp_point_read_binary(&pubKey->grp, &pubKey->Q, decompressedEcKey, decompressedEcKeyLen)) {
        return PM3_EINVARG;
    }

    return PM3_SUCCESS;
}

static int internalVasDecrypt(uint8_t *cipherText, size_t cipherTextLen, uint8_t *sharedSecret,
                              const uint8_t *ansiSharedInfo, size_t ansiSharedInfoLen,
                              const uint8_t *gcmAad, size_t gcmAadLen, uint8_t *out, size_t *outLen) {
    uint8_t key[32] = {0};
    if (ansi_x963_sha256(sharedSecret, 32, (uint8_t *)ansiSharedInfo, ansiSharedInfoLen, sizeof(key), key)) {
        PrintAndLogEx(FAILED, "ANSI X9.63 key derivation failed");
        return PM3_EINVARG;
    }

    uint8_t iv[16] = {0};

    mbedtls_gcm_context gcmCtx;
    mbedtls_gcm_init(&gcmCtx);
    if (mbedtls_gcm_setkey(&gcmCtx, MBEDTLS_CIPHER_ID_AES, key, sizeof(key) * 8)) {
        PrintAndLogEx(FAILED, "Unable to use key in GCM context");
        return PM3_EINVARG;
    }

    if (mbedtls_gcm_auth_decrypt(&gcmCtx, cipherTextLen - 16, iv, sizeof(iv), gcmAad, gcmAadLen, cipherText + cipherTextLen - 16, 16, cipherText, out)) {
        PrintAndLogEx(FAILED, "Failed to perform GCM decryption");
        return PM3_EINVARG;
    }

    mbedtls_gcm_free(&gcmCtx);

    *outLen = cipherTextLen - 16;

    return PM3_SUCCESS;
}

static int DecryptVASCryptogram(uint8_t *pidHash, uint8_t *cryptogram, size_t cryptogramLen, mbedtls_ecp_keypair *privKey, uint8_t *out, size_t *outLen, uint32_t *timestamp) {
    uint8_t keyId[4] = {0};
    if (GetPrivateKeyId(privKey, keyId) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Unable to generate key id");
        return PM3_EINVARG;
    }

    if (memcmp(keyId, cryptogram, 4) != 0) {
        PrintAndLogEx(FAILED, "Private key does not match cryptogram");
        PrintAndLogEx(INFO, "Key identifier........... " _YELLOW_("%s"), sprint_hex_inrow(keyId, sizeof(keyId)));
        PrintAndLogEx(INFO, "Cryptogram data........ " _YELLOW_("%s"), sprint_hex_inrow(cryptogram, cryptogramLen));
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair mobilePubKey;
    mbedtls_ecp_keypair_init(&mobilePubKey);
    if (mbedtls_ecp_group_load(&mobilePubKey.grp, privKey->grp.id) != 0) {
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Unable to initialize mobile ephemeral key");
        return PM3_ESOFT;
    }

    if (LoadMobileEphemeralKey(cryptogram + 4, &mobilePubKey) != PM3_SUCCESS) {
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Unable to parse mobile ephemeral key from cryptogram");
        return PM3_EINVARG;
    }

    mbedtls_mpi sharedSecret;
    mbedtls_mpi_init(&sharedSecret);

    if (mbedtls_ecdh_compute_shared(&privKey->grp, &sharedSecret, &mobilePubKey.Q, &privKey->d, NULL, NULL)) {
        mbedtls_mpi_free(&sharedSecret);
        mbedtls_ecp_keypair_free(&mobilePubKey);
        PrintAndLogEx(FAILED, "Failed to generate ECDH shared secret");
        return PM3_EINVARG;
    }
    mbedtls_ecp_keypair_free(&mobilePubKey);

    uint8_t sharedSecretBytes[32] = {0};
    if (mbedtls_mpi_write_binary(&sharedSecret, sharedSecretBytes, sizeof(sharedSecretBytes))) {
        mbedtls_mpi_free(&sharedSecret);
        PrintAndLogEx(FAILED, "Failed to generate ECDH shared secret");
        return PM3_EINVARG;
    }
    mbedtls_mpi_free(&sharedSecret);

    uint8_t method1SharedInfo[1 + sizeof(kVasAesGcmLabel) + sizeof(kVasEncryptedDataLabel) + 32] = {0};
    method1SharedInfo[0] = sizeof(kVasAesGcmLabel);
    memcpy(method1SharedInfo + 1, kVasAesGcmLabel, sizeof(kVasAesGcmLabel));
    memcpy(method1SharedInfo + 1 + sizeof(kVasAesGcmLabel), kVasEncryptedDataLabel, sizeof(kVasEncryptedDataLabel));
    memcpy(method1SharedInfo + 1 + sizeof(kVasAesGcmLabel) + sizeof(kVasEncryptedDataLabel), pidHash, 32);

    uint8_t decryptedData[68] = {0};
    size_t decryptedDataLen = 0;
    if (internalVasDecrypt(cryptogram + 4 + 32, cryptogramLen - 4 - 32, sharedSecretBytes, method1SharedInfo, sizeof(method1SharedInfo), NULL, 0, decryptedData, &decryptedDataLen)) {
        if (internalVasDecrypt(cryptogram + 4 + 32, cryptogramLen - 4 - 32, sharedSecretBytes, kVasEncryptedDataLabel, sizeof(kVasEncryptedDataLabel), pidHash, 32, decryptedData, &decryptedDataLen)) {
            return PM3_EINVARG;
        }
    }

    memcpy(out, decryptedData + 4, decryptedDataLen - 4);
    *outLen = decryptedDataLen - 4;

    *timestamp = 0;
    for (int i = 0; i < 4; ++i) {
        *timestamp = (*timestamp << 8) | decryptedData[i];
    }

    return PM3_SUCCESS;
}

typedef struct {
    mbedtls_ecp_keypair key;
    uint8_t key_id[4];
    const char *source;
} vas_reader_key_t;

static void VasReaderCleanup(vas_reader_key_t *keys, int keys_initialized,
                                  char **key_values, int key_count,
                                  char **pid_values, int pid_count) {
    for (int i = 0; keys != NULL && i < keys_initialized; i++) {
        mbedtls_ecp_keypair_free(&keys[i].key);
    }
    for (int i = 0; i < key_count; i++) {
        free(key_values[i]);
    }
    for (int i = 0; i < pid_count; i++) {
        free(pid_values[i]);
    }
}

static void PrintVasCryptogramInfo(const char *label, const uint8_t *cryptogram, size_t clen) {
    if (clen == 0) {
        return;
    }
    PrintAndLogEx(INFO, "%s", label);
    if (clen >= 4) {
        PrintAndLogEx(INFO, "  Key id...... " _YELLOW_("%s"), sprint_hex_inrow(cryptogram, 4));
    }
    PrintAndLogEx(INFO, "  Ciphertext.. " _YELLOW_("%s"), sprint_hex_inrow(cryptogram, clen));
}


static int VASSelectOse(uint16_t *select_status_out, bool verbose) {
    if (select_status_out != NULL) {
        *select_status_out = VAS_STATUS_NOT_AVAILABLE;
    }

    uint16_t status = 0;
    size_t resLen = 0;
    uint8_t selectResponse[APDU_RES_LEN] = {0};
    Iso7816Select(CC_CONTACTLESS, false, true, (uint8_t *)aid, sizeof(aid), selectResponse, APDU_RES_LEN, &resLen, &status);

    if (select_status_out != NULL) {
        *select_status_out = status;
    }

    if (status != 0x9000) {
        return PM3_ECARDEXCHANGE;
    }

    PrintVASSelectInfo(selectResponse, resLen, verbose);
    if (ParseSelectVASResponse(selectResponse, resLen, NULL) != PM3_SUCCESS) {
        return PM3_ECARDEXCHANGE;
    }

    return PM3_SUCCESS;
}

static int VASGetData(const char *passIdentifier, const uint8_t *pidHash, bool hasPid,
                      const char *url, size_t urlLen, uint8_t vas_mode, bool isFinalRequest,
                      bool verbose, uint8_t *cryptogram, size_t *cryptogramLen,
                      uint16_t *get_data_status_out) {
    if (get_data_status_out != NULL) {
        *get_data_status_out = VAS_STATUS_NOT_AVAILABLE;
    }
    if (cryptogramLen != NULL) {
        *cryptogramLen = 0;
    }

    char pass_header[64] = {0};
    const char *displayedPassIdentifier = passIdentifier != NULL ? passIdentifier : "unknown-pass-identifier";
    snprintf(pass_header, sizeof(pass_header), "VAS Get Data %s", displayedPassIdentifier);
    PrintAndLogInfoHeader(pass_header);
    if (verbose) {
        PrintAndLogEx(INFO, "Pass type id hash...... " _YELLOW_("%s"), hasPid ? sprint_hex_inrow(pidHash, 32) : "n/a");
    }

    uint8_t getVasApdu[PM3_CMD_DATA_SIZE];
    int getVasApduLen = 0;
    int s = CreateGetVASDataCommand(pidHash, url, urlLen, vas_mode, isFinalRequest, getVasApdu, &getVasApduLen);
    if (s != PM3_SUCCESS) {
        return s;
    }

    uint8_t apduRes[APDU_RES_LEN] = {0};
    size_t apduResLen = 0;
    uint16_t getDataStatus = 0;
    sAPDU_t getVasCmd = {
        .CLA = getVasApdu[0],
        .INS = getVasApdu[1],
        .P1 = getVasApdu[2],
        .P2 = getVasApdu[3],
        .Lc = getVasApdu[4],
        .data = getVasApdu + 5,
    };
    s = Iso7816ExchangeEx(CC_CONTACTLESS, false, true, getVasCmd, false, 0x00, apduRes, APDU_RES_LEN, &apduResLen, &getDataStatus);
    if (s != PM3_SUCCESS) {
        return s;
    }

    if (get_data_status_out != NULL) {
        *get_data_status_out = getDataStatus;
    }

    if (!vas_status_is_success(getDataStatus)) {
        PrintVASStatusLine("GET VAS DATA status....", getDataStatus);
        return PM3_SUCCESS;
    }

    if (apduResLen == 0 || apduRes[0] != 0x70) {
        return PM3_ECARDEXCHANGE;
    }

    uint8_t mobileToken[VAS_MAX_MOBILE_TOKEN_LEN] = {0};
    size_t mobileTokenLen = 0;
    s = ParseGetVASDataResponse(apduRes, apduResLen, hasPid, mobileToken, &mobileTokenLen, cryptogram, cryptogramLen);
    if (s != PM3_SUCCESS) {
        return s;
    }

    if (mobileTokenLen > 0) {
        PrintAndLogEx(INFO, "Device token (9F2A)... " _YELLOW_("%s"), sprint_hex_inrow(mobileToken, mobileTokenLen));
    }

    PrintVASStatusLine("GET VAS DATA status....", getDataStatus);

    if (verbose && cryptogramLen != NULL && *cryptogramLen > 0) {
        PrintAndLogEx(INFO, "Cryptogram data........ " _YELLOW_("%s"), sprint_hex_inrow(cryptogram, *cryptogramLen));
    }
    return PM3_SUCCESS;
}

static int VASRead(bool has_pid, size_t request_count,
                          char *const *pid_values, const char *url, int urllen,
                          uint8_t vas_mode, bool verbose,
                          vas_reader_key_t *keys, int key_count) {
    uint16_t select_status = VAS_STATUS_NOT_AVAILABLE;
    if (VASSelectOse(&select_status, verbose) != PM3_SUCCESS) {
        PrintVASFailureReason(select_status, VAS_STATUS_NOT_AVAILABLE);
        return PM3_ECARDEXCHANGE;
    }

    for (size_t request_idx = 0; request_idx < request_count; request_idx++) {
        uint8_t pidhash[32] = {0};
        const char *passIdentifier = "unknown-pass-identifier";
        if (has_pid) {
            passIdentifier = pid_values[request_idx];
            sha256hash((uint8_t *)passIdentifier, strlen(passIdentifier), pidhash);
        }

        PrintAndLogEx(INFO, "");

        uint8_t cryptogram[VAS_MAX_CRYPTOGRAM_LEN] = {0};
        size_t clen = 0;
        uint16_t get_data_status = VAS_STATUS_NOT_AVAILABLE;
        bool isFinalRequest = (request_idx + 1 == request_count);
        int res = VASGetData(passIdentifier, has_pid ? pidhash : NULL, has_pid,
                             url, urllen, vas_mode, isFinalRequest, verbose,
                             cryptogram, &clen, &get_data_status);
        if (res != PM3_SUCCESS) {
            PrintVASFailureReason(select_status, get_data_status);
            break;
        }

        if (!has_pid) {
            PrintAndLogEx(SUCCESS, "Request completed");
            continue;
        }

        if (!vas_status_is_success(get_data_status)) {
            continue;
        }

        int matched_key_idx = -1;
        if (clen >= 4) {
            for (int i = 0; i < key_count; i++) {
                if (memcmp(keys[i].key_id, cryptogram, sizeof(keys[i].key_id)) == 0) {
                    matched_key_idx = i;
                    break;
                }
            }
        }

        uint8_t msg[64] = {0};
        size_t mlen = 0;
        uint32_t timestamp = 0;

        if (key_count == 0) {
            PrintVasCryptogramInfo("Cryptogram (no key provided to decrypt)", cryptogram, clen);
            continue;
        }

        if (matched_key_idx < 0) {
            PrintAndLogEx(FAILED, "No matching key identifier found, cannot decrypt VAS data");
            PrintVasCryptogramInfo("Cryptogram", cryptogram, clen);
            continue;
        }

        res = DecryptVASCryptogram(pidhash, cryptogram, clen, &keys[matched_key_idx].key, msg, &mlen, &timestamp);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Cannot decrypt VAS data");
            PrintVasCryptogramInfo("Cryptogram", cryptogram, clen);
            continue;
        }

        PrintAndLogEx(SUCCESS, "Pass data");
        PrintAndLogEx(SUCCESS, "  Timestamp... " _YELLOW_("%d") " (secs since Jan 1, 2001)", timestamp);
        PrintAndLogEx(SUCCESS, "  Message..... " _YELLOW_("%s"), sprint_ascii(msg, mlen));
    }
    return PM3_SUCCESS;
}

static int CmdVASReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf vas reader",
                  "Read and decrypt Value Added Services (VAS) message",
                  "hf vas reader --url https://example.com    -> URL Only mode\n"
                  "hf vas reader --pid pass.com.passkit.pksamples.nfcdemo -k vas.passkit.der -@\n"
                  "hf vas reader --pid pass.com.pronto.zebra-wallet-pass.demo -k vas.zebra.der -@\n"
                  "hf vas reader --pid pass.com.springcard.springblue.generic -k vas.springcard.der -@\n"
                  "hf vas reader --pid pass.id.one --pid pass.id.two -k key.one.der -k key.two.der\n"
                  "hf vas reader --mode vasandpay --pid pass.id -k key.der\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0(NULL, "pid", "<str>", "PID, pass type id (repeat --pid for multiple values)"),
        arg_strx0("k", "key,file,reader-private-key,readerprivkey,rpk", "<pem|der-b64|der-hex|scalar-b64|scalar-hex|path>", "Terminal private key (repeat --key for multiple values)"),
        arg_str0(NULL, "url", "<str>", "a URL to provide to the mobile device"),
        arg_str0(NULL, "mode", "<vasorpay|vasandpay|vasonly>", "VAS mode used in ECP and GET DATA capabilities"),
        arg_lit0("@", NULL, "continuous mode"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct arg_str *pid_args = arg_get_str(ctx, 1);
    struct arg_str *key_args = arg_get_str(ctx, 2);
    const int pid_count = pid_args->count;
    const int key_count = key_args->count;

    if (pid_count == 0 && key_count > 0) {
        PrintAndLogEx(FAILED, "--key requires at least one --pid");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (pid_count > VAS_MAX_PID_ITEMS) {
        PrintAndLogEx(FAILED, "Too many --pid values (max %d)", VAS_MAX_PID_ITEMS);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    if (key_count > VAS_MAX_KEY_ITEMS) {
        PrintAndLogEx(FAILED, "Too many --key values (max %d)", VAS_MAX_KEY_ITEMS);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    char *pid_values[VAS_MAX_PID_ITEMS] = {0};
    char *key_values[VAS_MAX_KEY_ITEMS] = {0};
    for (int i = 0; i < pid_count; i++) {
        pid_values[i] = strdup(pid_args->sval[i]);
        if (pid_values[i] == NULL) {
            VasReaderCleanup(NULL, 0, key_values, 0, pid_values, i);
            CLIParserFree(ctx);
            return PM3_EMALLOC;
        }
    }

    for (int i = 0; i < key_count; i++) {
        key_values[i] = strdup(key_args->sval[i]);
        if (key_values[i] == NULL) {
            VasReaderCleanup(NULL, 0, key_values, i, pid_values, pid_count);
            CLIParserFree(ctx);
            return PM3_EMALLOC;
        }
    }

    int urllen = 0;
    char url[512] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)url, 512, &urllen);

    char mode_text[32] = {0};
    int mode_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)mode_text, sizeof(mode_text), &mode_len);
    (void)mode_len;
    str_lower(mode_text);
    uint8_t vas_mode = VAS_MODE_VAS_ONLY;
    if (vas_parse_mode(mode_text, &vas_mode) != PM3_SUCCESS) {
        VasReaderCleanup(NULL, 0, key_values, key_count, pid_values, pid_count);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool continuous = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);

    const bool has_pid = pid_count > 0;
    const size_t request_count = has_pid ? (size_t)pid_count : 1;

    vas_reader_key_t keys[VAS_MAX_KEY_ITEMS] = {0};
    for (int i = 0; i < key_count; i++) {
        mbedtls_ecp_keypair_init(&keys[i].key);
        keys[i].source = key_values[i];
        if (LoadReaderPrivateKey(keys[i].source, &keys[i].key) != PM3_SUCCESS) {
            VasReaderCleanup(keys, i + 1, key_values, key_count, pid_values, pid_count);
            CLIParserFree(ctx);
            return PM3_ESOFT;
        }
        if (GetPrivateKeyId(&keys[i].key, keys[i].key_id) != PM3_SUCCESS) {
            VasReaderCleanup(keys, i + 1, key_values, key_count, pid_values, pid_count);
            CLIParserFree(ctx);
            return PM3_ESOFT;
        }
    }

    CLIParserFree(ctx);

    if (has_pid) {
        PrintAndLogEx(INFO, "Requesting pass type id entries... " _GREEN_("%d"), pid_count);
    } else {
        PrintAndLogEx(INFO, "Requesting VAS URL........ " _GREEN_("%s"), sprint_ascii((uint8_t *) url, urllen));
    }

    if (continuous) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    int final_res = PM3_SUCCESS;

    iso14a_polling_frame_t ecp_frame;
    vas_build_ecp_frame(vas_mode, &ecp_frame);
    iso14a_polling_parameters_t polling_parameters = {
        .frames = { WUPA_FRAME, ecp_frame },
        .frame_count = 2,
        .extra_timeout = 250
    };

    do {
        if (continuous && kbd_enter_pressed()) {
            break;
        }
        clearCommandBuffer();

        if (SelectCard14443A_4_WithParameters(false, false, NULL, &polling_parameters) != PM3_SUCCESS) {
            PrintVASFailureReason(VAS_STATUS_NOT_AVAILABLE, VAS_STATUS_NOT_AVAILABLE);
            if (final_res == PM3_SUCCESS) {
                final_res = PM3_ECARDEXCHANGE;
            }
            msleep(1000);
            continue;
        }
        int iter_res = VASRead(has_pid, request_count, pid_values,
                                        url, urllen, vas_mode, verbose,
                                        keys, key_count);
        if (iter_res != PM3_SUCCESS && final_res == PM3_SUCCESS) {
            final_res = iter_res;
        }
        
        if (continuous) {
            // Drop field so that iPhone displays the checkmark or a pass
            DropField();
            msleep(3000);
        }
        PrintAndLogEx(NORMAL, "");
        msleep(300);
    } while (continuous);

    VasReaderCleanup(keys, key_count, key_values, key_count, pid_values, pid_count);
    DropField();
    return final_res;
}

static int CmdVASInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf vas info",
                  "Select VAS applet and print capabilities.",
                  "hf vas info\n"
                  "hf vas info -a");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool apdu_logging = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    bool restore_apdu_logging = GetAPDULogging();
    SetAPDULogging(apdu_logging);

    clearCommandBuffer();

    iso14a_polling_parameters_t polling_parameters = {
        .frames = { WUPA_FRAME, ECP_VAS_ONLY_FRAME },
        .frame_count = 2,
        .extra_timeout = 250
    };

    int res = PM3_ECARDEXCHANGE;
    if (SelectCard14443A_4_WithParameters(false, false, NULL, &polling_parameters) == PM3_SUCCESS) {
        res = VASSelectOse(NULL, true);
    }

    SetAPDULogging(restore_apdu_logging);
    DropField();
    return res;
}

static int CmdVASDecrypt(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf vas decrypt",
                  "Decrypt a previously captured cryptogram",
                  "hf vas decrypt --pid pass.com.passkit.pksamples.nfcdemo -k vas.passkit.der -d c0b77375eae416b79449347f9fe838c05cdb57dc7470b97b93b806cb348771d9bfbe29d58538c7c7d7c3d015fa205b68bfccd726058a62f7f44085ac98dbf877120fd9059f1507b956e0a6d56d0a\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "pid", "<str>", "PID, pass type id"),
        arg_str0("k", "key,file,reader-private-key,readerprivkey,rpk", "<pem|der-b64|der-hex|scalar-b64|scalar-hex|path>", "Terminal private key: PEM, DER hex, scalar hex/base64, or file path"),
        arg_str0("d", "data", "<hex>", "cryptogram to decrypt"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int pidlen = 0;
    char pid[512] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)pid, 512, &pidlen);

    int key_input_len = 0;
    char key_input[VAS_MAX_KEY_INPUT] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)key_input, sizeof(key_input), &key_input_len);

    if (key_input_len == 0) {
        PrintAndLogEx(FAILED, "Must provide terminal private key input or file path");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int clen = 0;
    uint8_t cryptogram[120] = {0};
    CLIGetHexWithReturn(ctx, 3, cryptogram, &clen);
    CLIParserFree(ctx);

    mbedtls_ecp_keypair privKey;
    mbedtls_ecp_keypair_init(&privKey);

    if (LoadReaderPrivateKey(key_input, &privKey) != PM3_SUCCESS) {
        mbedtls_ecp_keypair_free(&privKey);
        return PM3_EFILE;
    }

    uint8_t pidhash[32] = {0};
    sha256hash((uint8_t *) pid, pidlen, pidhash);

    size_t mlen = 0;
    uint8_t msg[64] = {0};
    uint32_t timestamp = 0;

    int res = DecryptVASCryptogram(pidhash, cryptogram, clen, &privKey, msg, &mlen, &timestamp);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Timestamp... " _YELLOW_("%d") " (secs since Jan 1, 2001)", timestamp);
        PrintAndLogEx(SUCCESS, "Message..... " _YELLOW_("%s"), sprint_ascii(msg, mlen));
    }

    mbedtls_ecp_keypair_free(&privKey);
    return res;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"--------",  CmdHelp,        AlwaysAvailable,  "----------- " _CYAN_("Value Added Service") " -----------"},
    {"help",      CmdHelp,        AlwaysAvailable,  "This help"},
    {"--------",  CmdHelp,        AlwaysAvailable,  "----------------- " _CYAN_("General") " -----------------"},
    {"info",      CmdVASInfo,     IfPm3Iso14443a,   "Get VAS applet information"},
    {"reader",    CmdVASReader,   IfPm3Iso14443a,   "Read and decrypt VAS message"},
    {"decrypt",   CmdVASDecrypt,  AlwaysAvailable,  "Decrypt a previously captured VAS cryptogram"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFVAS(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
