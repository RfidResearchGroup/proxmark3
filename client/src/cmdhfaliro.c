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
// High frequency ALIRO commands
//-----------------------------------------------------------------------------

#include "cmdhfaliro.h"

#include <inttypes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/gcm.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <string.h>
#include "cliparser.h"
#include "cmdparser.h"
#include "comms.h"
#include "cmdtrace.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "iso7816/iso7816core.h"
#include "protocols.h"
#include "ui.h"
#include "util.h"
#include "commonutil.h"

static const uint8_t ALIRO_EXPEDITED_AID[] = {
    0xA0, 0x00, 0x00, 0x09, 0x09, 0xAC, 0xCE, 0x55, 0x01
};

static const uint8_t ALIRO_READER_CONTEXT[] = {0x41, 0x5D, 0x95, 0x69};
static const uint8_t ALIRO_DEVICE_CONTEXT[] = {0x4E, 0x88, 0x7B, 0x4C};
static const uint8_t ALIRO_AUTH0_GCM_IV[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
static const uint8_t ALIRO_EXCHANGE_MODE[] = {0, 0, 0, 0, 0, 0, 0, 1};
static const uint8_t ALIRO_NFC_INTERFACE_BYTE = 0x5E;
static const uint8_t ALIRO_AUTH0_DEFAULT_POLICY = 0x01;
static const uint8_t ALIRO_AUTH1_REQUEST_PUBLIC_KEY = 0x01;

#define ALIRO_MAX_BUFFER 2048
#define ALIRO_MAX_TLV 512

typedef struct {
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    bool seeded;
} aliro_rng_t;

typedef struct {
    uint16_t type;
    const char *name;
} aliro_application_type_t;

static const aliro_application_type_t aliro_application_type_map[] = {
    {0x0000, "CSA application"},
};

typedef enum {
    ALIRO_FLOW_FAST = 0,
    ALIRO_FLOW_STANDARD = 1,
} aliro_flow_t;

typedef struct {
    bool have_fci_aid;
    uint8_t fci_aid[APDU_AID_LEN];
    size_t fci_aid_len;
    bool have_versions;
    uint8_t versions[64];
    size_t versions_len;
    bool have_type;
    uint16_t application_type;
    bool has_max_command;
    uint32_t max_command;
    bool has_max_response;
    uint32_t max_response;
    bool have_proprietary_tlv;
    uint8_t proprietary_tlv[ALIRO_MAX_TLV];
    size_t proprietary_tlv_len;
} aliro_select_info_t;

typedef struct {
    bool have_endpoint_ephemeral_public_key;
    uint8_t endpoint_ephemeral_public_key[65];
    uint8_t endpoint_ephemeral_public_key_x[32];
    bool have_cryptogram;
    uint8_t cryptogram[64];
    bool have_auth0_response_vendor_extension;
    uint8_t auth0_response_vendor_extension_tlv[ALIRO_MAX_TLV];
    size_t auth0_response_vendor_extension_tlv_len;
} aliro_auth0_response_t;

typedef struct {
    bool have_key_slot;
    uint8_t key_slot[8];
    bool have_endpoint_public_key;
    uint8_t endpoint_public_key[65];
    uint8_t endpoint_public_key_x[32];
    bool have_signature;
    uint8_t signature[64];
    bool have_signaling_bitmap;
    uint16_t signaling_bitmap;
    bool have_credential_signed_timestamp;
    uint8_t credential_signed_timestamp[20];
    bool have_revocation_signed_timestamp;
    uint8_t revocation_signed_timestamp[20];
    bool have_mailbox_subset;
    uint8_t mailbox_subset[ALIRO_MAX_TLV];
    size_t mailbox_subset_len;
} aliro_auth1_response_t;

typedef struct {
    uint8_t kdh[32];
    uint8_t exchange_sk_reader[32];
    uint8_t exchange_sk_device[32];
    uint8_t ble_sk_reader[32];
    uint8_t ble_sk_device[32];
    uint8_t ursk[32];
    bool cryptogram_sk_present;
    uint8_t cryptogram_sk[32];
    bool step_up_keys_present;
    uint8_t step_up_sk_reader[32];
    uint8_t step_up_sk_device[32];
    bool kpersistent_present;
    uint8_t kpersistent[32];
} aliro_derived_keys_t;

typedef struct {
    bool verified;
    uint16_t signaling_bitmap;
    uint8_t credential_signed_timestamp[20];
    uint8_t revocation_signed_timestamp[20];
    aliro_derived_keys_t keys;
} aliro_fast_result_t;

typedef struct {
    bool signature_checked;
    bool signature_valid;
    aliro_derived_keys_t keys;
} aliro_standard_result_t;

typedef struct {
    aliro_select_info_t select_info;
    uint8_t protocol_version[2];
    uint8_t reader_identifier[32];
    uint8_t reader_public_key[65];
    uint8_t reader_public_key_x[32];
    uint8_t reader_ephemeral_public_key[65];
    uint8_t reader_ephemeral_public_key_x[32];
    uint8_t transaction_identifier[16];
    uint8_t auth0_command_parameters;
    uint8_t auth0_suffix[ALIRO_MAX_TLV];
    size_t auth0_suffix_len;
    aliro_auth0_response_t auth0_parsed;
    aliro_fast_result_t fast_result;
    aliro_auth1_response_t auth1_parsed;
    aliro_standard_result_t standard_result;
} aliro_read_state_t;

static int CmdHelp(const char *Cmd);

static const char *get_aliro_application_type_name(uint16_t type) {
    for (size_t i = 0; i < ARRAYLEN(aliro_application_type_map); ++i) {
        if (aliro_application_type_map[i].type == type) {
            return aliro_application_type_map[i].name;
        }
    }
    return NULL;
}

static void aliro_print_big_header(const char *title) {
    static const char dashes[] = "----------------------------------------------------------------------------------------------------";
    const size_t width = 82;
    const size_t title_len = strlen(title);

    if (title_len + 2 >= width) {
        PrintAndLogEx(INFO, _CYAN_("%s"), title);
        return;
    }

    size_t dash_count = width - (title_len + 2);
    size_t left = dash_count / 2;
    size_t right = dash_count - left;
    if (left > (sizeof(dashes) - 1)) {
        left = sizeof(dashes) - 1;
    }
    if (right > (sizeof(dashes) - 1)) {
        right = sizeof(dashes) - 1;
    }

    PrintAndLogEx(INFO, "%.*s " _CYAN_("%s") " %.*s",
                  (int)left, dashes, title, (int)right, dashes);
}

static int aliro_rng_init(aliro_rng_t *rng) {
    if (rng == NULL) {
        return PM3_EINVARG;
    }

    memset(rng, 0, sizeof(*rng));
    mbedtls_entropy_init(&rng->entropy);
    mbedtls_ctr_drbg_init(&rng->ctr_drbg);

    static const uint8_t personalization[] = "pm3-aliro";
    int ret = mbedtls_ctr_drbg_seed(&rng->ctr_drbg, mbedtls_entropy_func, &rng->entropy,
                                    personalization, sizeof(personalization) - 1);
    if (ret != 0) {
        PrintAndLogEx(ERR, "Failed to initialize random generator (mbedtls: %d)", ret);
        mbedtls_ctr_drbg_free(&rng->ctr_drbg);
        mbedtls_entropy_free(&rng->entropy);
        return PM3_ESOFT;
    }

    rng->seeded = true;
    return PM3_SUCCESS;
}

static void aliro_rng_free(aliro_rng_t *rng) {
    if (rng == NULL) {
        return;
    }

    mbedtls_ctr_drbg_free(&rng->ctr_drbg);
    mbedtls_entropy_free(&rng->entropy);
    rng->seeded = false;
}

static int aliro_ber_encode_length(size_t len, uint8_t *out, size_t out_max, size_t *out_len) {
    if (out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }

    if (len <= 0x7F) {
        if (out_max < 1) {
            return PM3_EOVFLOW;
        }
        out[0] = (uint8_t)len;
        *out_len = 1;
        return PM3_SUCCESS;
    }

    if (len <= 0xFF) {
        if (out_max < 2) {
            return PM3_EOVFLOW;
        }
        out[0] = 0x81;
        out[1] = (uint8_t)len;
        *out_len = 2;
        return PM3_SUCCESS;
    }

    if (len <= 0xFFFF) {
        if (out_max < 3) {
            return PM3_EOVFLOW;
        }
        out[0] = 0x82;
        out[1] = (uint8_t)(len >> 8);
        out[2] = (uint8_t)len;
        *out_len = 3;
        return PM3_SUCCESS;
    }

    return PM3_EOVFLOW;
}

static int aliro_append_tlv(uint8_t tag, const uint8_t *value, size_t value_len,
                            uint8_t *buf, size_t buf_max, size_t *offset) {
    if (buf == NULL || offset == NULL) {
        return PM3_EINVARG;
    }

    if (*offset >= buf_max) {
        return PM3_EOVFLOW;
    }
    buf[*offset] = tag;
    (*offset)++;

    uint8_t len_buf[3] = {0};
    size_t len_size = 0;
    int res = aliro_ber_encode_length(value_len, len_buf, sizeof(len_buf), &len_size);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if ((*offset + len_size + value_len) > buf_max) {
        return PM3_EOVFLOW;
    }

    memcpy(buf + *offset, len_buf, len_size);
    *offset += len_size;
    if (value_len > 0 && value != NULL) {
        memcpy(buf + *offset, value, value_len);
        *offset += value_len;
    }
    return PM3_SUCCESS;
}

static void parse_extended_length_info(const uint8_t *buf, size_t len,
                                       bool *has_max_command, uint32_t *max_command,
                                       bool *has_max_response, uint32_t *max_response) {
    const uint8_t *cursor = buf;
    size_t left = len;
    size_t integer_index = 0;

    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(WARNING, "Malformed tag 7F66 value");
            return;
        }

        const uint8_t *value = cursor;

        if (tlv.tag == 0x02) {
            const uint8_t *trimmed = value;
            size_t trimmed_len = tlv.len;
            while (trimmed_len > 4 && *trimmed == 0x00) {
                ++trimmed;
                --trimmed_len;
            }

            if (trimmed_len > 0 && trimmed_len <= 4) {
                uint32_t parsed = (uint32_t)bytes_to_num(trimmed, trimmed_len);
                if (integer_index == 0) {
                    *has_max_command = true;
                    *max_command = parsed;
                } else if (integer_index == 1) {
                    *has_max_response = true;
                    *max_response = parsed;
                }
                ++integer_index;
            } else {
                PrintAndLogEx(WARNING, "Could not parse INTEGER from tag 7F66");
            }
        }

        cursor += tlv.len;
        left -= tlv.len;
    }
}

static int parse_aliro_select_response(const uint8_t *buf, size_t len, aliro_select_info_t *info) {
    if (info == NULL) {
        return PM3_EINVARG;
    }
    memset(info, 0, sizeof(*info));

    const uint8_t *top_cursor = buf;
    size_t top_left = len;
    const uint8_t *fci_value = NULL;
    size_t fci_len = 0;

    while (top_left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&top_cursor, &top_left, &tlv) == false || tlv.len > top_left) {
            PrintAndLogEx(ERR, "Malformed SELECT response");
            return PM3_ECARDEXCHANGE;
        }

        if (tlv.tag == 0x6F) {
            fci_value = top_cursor;
            fci_len = tlv.len;
            break;
        }

        top_cursor += tlv.len;
        top_left -= tlv.len;
    }

    if (fci_value == NULL || fci_len == 0) {
        PrintAndLogEx(ERR, "SELECT response does not contain FCI template (tag 6F)");
        return PM3_ECARDEXCHANGE;
    }

    const uint8_t *fci_cursor = fci_value;
    size_t fci_left = fci_len;
    while (fci_left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&fci_cursor, &fci_left, &tlv) == false || tlv.len > fci_left) {
            PrintAndLogEx(ERR, "Malformed FCI template");
            return PM3_ECARDEXCHANGE;
        }

        const uint8_t *value = fci_cursor;
        if (tlv.tag == 0x84) {
            info->have_fci_aid = true;
            info->fci_aid_len = tlv.len;
            if (info->fci_aid_len > sizeof(info->fci_aid)) {
                info->fci_aid_len = sizeof(info->fci_aid);
                PrintAndLogEx(WARNING, "Returned FCI AID too long, truncating output");
            }
            memcpy(info->fci_aid, value, info->fci_aid_len);
        } else if (tlv.tag == 0xA5) {
            info->have_proprietary_tlv = true;
            size_t a5_tlv_len = 0;
            int a5_res = aliro_append_tlv(0xA5, value, tlv.len, info->proprietary_tlv, sizeof(info->proprietary_tlv), &a5_tlv_len);
            if (a5_res == PM3_SUCCESS) {
                info->proprietary_tlv_len = a5_tlv_len;
            } else {
                PrintAndLogEx(WARNING, "Proprietary information TLV too long, key derivation may fail");
                info->have_proprietary_tlv = false;
            }

            const uint8_t *a5_cursor = value;
            size_t a5_left = tlv.len;
            while (a5_left > 0) {
                struct tlv field = {0};
                if (tlv_parse_tl(&a5_cursor, &a5_left, &field) == false || field.len > a5_left) {
                    PrintAndLogEx(ERR, "Malformed proprietary information template");
                    return PM3_ECARDEXCHANGE;
                }

                const uint8_t *field_value = a5_cursor;
                switch (field.tag) {
                    case 0x80:
                        if (field.len == 2) {
                            info->application_type = (uint16_t)((field_value[0] << 8) | field_value[1]);
                            info->have_type = true;
                        } else {
                            PrintAndLogEx(WARNING, "Unexpected application type size: %zu", field.len);
                        }
                        break;
                    case 0x5C:
                        info->have_versions = true;
                        info->versions_len = field.len;
                        if (info->versions_len > sizeof(info->versions)) {
                            info->versions_len = sizeof(info->versions);
                            PrintAndLogEx(WARNING, "Supported protocol versions list too long, truncating output");
                        }
                        memcpy(info->versions, field_value, info->versions_len);
                        break;
                    case 0x7F66:
                        parse_extended_length_info(field_value, field.len,
                                                   &info->has_max_command, &info->max_command,
                                                   &info->has_max_response, &info->max_response);
                        break;
                    default:
                        break;
                }

                a5_cursor += field.len;
                a5_left -= field.len;
            }
        }

        fci_cursor += tlv.len;
        fci_left -= tlv.len;
    }

    if (info->have_proprietary_tlv == false) {
        PrintAndLogEx(ERR, "SELECT response does not contain proprietary information (tag A5)");
        return PM3_ECARDEXCHANGE;
    }

    return PM3_SUCCESS;
}

static void print_aliro_select_info(const aliro_select_info_t *info) {
    if (info->have_fci_aid) {
        PrintAndLogEx(INFO, "AID....................... %s", sprint_hex_inrow(info->fci_aid, info->fci_aid_len));
    } else {
        PrintAndLogEx(INFO, "AID....................... not present");
    }

    if (info->have_versions && info->versions_len >= 2) {
        PrintAndLogEx(INFO, "Supported protocol versions:");
        size_t pairs = info->versions_len / 2;
        for (size_t i = 0; i < pairs; ++i) {
            uint8_t major = info->versions[(i * 2)];
            uint8_t minor = info->versions[(i * 2) + 1];
            PrintAndLogEx(INFO, "  %zu) " _YELLOW_("%u.%u") " (0x%02X%02X)", i + 1, major, minor, major, minor);
        }

        if ((info->versions_len % 2) != 0) {
            PrintAndLogEx(WARNING, "Trailing protocol version byte ignored: %02X", info->versions[info->versions_len - 1]);
        }
    } else {
        PrintAndLogEx(INFO, "Supported protocol versions: not present");
    }

    if (info->have_type) {
        const char *type_name = get_aliro_application_type_name(info->application_type);
        if (type_name != NULL) {
            PrintAndLogEx(INFO, "Application type.......... " _YELLOW_("%s") " (0x%04X)", type_name, info->application_type);
        } else {
            PrintAndLogEx(INFO, "Application type.......... " _YELLOW_("Unknown") " (0x%04X)", info->application_type);
        }
    } else {
        PrintAndLogEx(INFO, "Application type.......... not present");
    }

    if (info->has_max_command || info->has_max_response) {
        if (info->has_max_command) {
            PrintAndLogEx(INFO, "Maximum command APDU...... " _GREEN_("%" PRIu32 " bytes"), info->max_command);
        }
        if (info->has_max_response) {
            PrintAndLogEx(INFO, "Maximum response APDU..... " _GREEN_("%" PRIu32 " bytes"), info->max_response);
        }
    } else {
        PrintAndLogEx(INFO, "Maximum APDU sizes........ not provided");
    }
}

static int aliro_exchange_chained(bool activate_field, bool leave_field_on,
                                  uint8_t cla, uint8_t ins, uint8_t p1, uint8_t p2,
                                  const uint8_t *data, size_t data_len,
                                  uint8_t *result, size_t max_result_len,
                                  size_t *result_len, uint16_t *sw) {
    if (result == NULL || result_len == NULL || sw == NULL) {
        return PM3_EINVARG;
    }
    if (data_len > 255) {
        PrintAndLogEx(ERR, "APDU payload too long: %zu (max 255)", data_len);
        return PM3_EINVARG;
    }

    *result_len = 0;
    *sw = 0;

    uint8_t chunk[APDU_RES_LEN] = {0};
    size_t chunk_len = 0;
    sAPDU_t apdu = {cla, ins, p1, p2, (uint8_t)data_len, (uint8_t *)data};
    int res = Iso7816ExchangeEx(CC_CONTACTLESS, activate_field, leave_field_on,
                                apdu, true, 0, chunk, sizeof(chunk), &chunk_len, sw);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if ((chunk_len + *result_len) > max_result_len) {
        return PM3_EOVFLOW;
    }
    memcpy(result + *result_len, chunk, chunk_len);
    *result_len += chunk_len;

    while (((*sw >> 8) & 0xFF) == 0x61) {
        uint16_t le = (*sw & 0xFF);
        if (le == 0) {
            le = 0x100;
        }

        chunk_len = 0;
        sAPDU_t get_response = {cla, ISO7816_GET_RESPONSE, 0x00, 0x00, 0x00, NULL};
        res = Iso7816ExchangeEx(CC_CONTACTLESS, false, leave_field_on,
                                get_response, true, le, chunk, sizeof(chunk), &chunk_len, sw);
        if (res != PM3_SUCCESS) {
            return res;
        }
        if ((chunk_len + *result_len) > max_result_len) {
            return PM3_EOVFLOW;
        }
        memcpy(result + *result_len, chunk, chunk_len);
        *result_len += chunk_len;
    }

    return PM3_SUCCESS;
}

static int aliro_select_with_info(aliro_select_info_t *info, bool keep_field_on) {
    uint8_t response[ALIRO_MAX_BUFFER] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;

    int res = aliro_exchange_chained(true, keep_field_on, 0x00, ISO7816_SELECT_FILE, 0x04, 0x00,
                                     ALIRO_EXPEDITED_AID, sizeof(ALIRO_EXPEDITED_AID),
                                     response, sizeof(response), &response_len, &sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "SELECT APDU exchange error");
        return res;
    }

    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "Aliro applet not found. APDU response: %04x - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");
        }
        return PM3_ESOFT;
    }

    return parse_aliro_select_response(response, response_len, info);
}

static bool aliro_choose_protocol_version(const aliro_select_info_t *select_info, uint8_t protocol_version[2]) {
    if (select_info == NULL || protocol_version == NULL) {
        return false;
    }
    if (select_info->have_versions == false || select_info->versions_len < 2) {
        return false;
    }

    size_t pairs = select_info->versions_len / 2;
    if (pairs == 0) {
        return false;
    }

    for (size_t i = 0; i < pairs; i++) {
        if (select_info->versions[(i * 2)] == 0x01 && select_info->versions[(i * 2) + 1] == 0x00) {
            protocol_version[0] = 0x01;
            protocol_version[1] = 0x00;
            return true;
        }
    }

    protocol_version[0] = select_info->versions[0];
    protocol_version[1] = select_info->versions[1];
    return true;
}

static int aliro_load_private_key(const uint8_t private_key_bytes[32], mbedtls_ecp_keypair *keypair, aliro_rng_t *rng) {
    if (private_key_bytes == NULL || keypair == NULL || rng == NULL || rng->seeded == false) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair_init(keypair);
    int ret = mbedtls_ecp_group_load(&keypair->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    ret = mbedtls_mpi_read_binary(&keypair->d, private_key_bytes, 32);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    ret = mbedtls_ecp_check_privkey(&keypair->grp, &keypair->d);
    if (ret != 0) {
        return PM3_ESOFT;
    }

    ret = mbedtls_ecp_mul(&keypair->grp, &keypair->Q, &keypair->d, &keypair->grp.G,
                          mbedtls_ctr_drbg_random, &rng->ctr_drbg);
    if (ret != 0) {
        return PM3_ESOFT;
    }

    ret = mbedtls_ecp_check_pubkey(&keypair->grp, &keypair->Q);
    if (ret != 0) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int aliro_generate_ephemeral_keypair(mbedtls_ecp_keypair *keypair, aliro_rng_t *rng) {
    if (keypair == NULL || rng == NULL || rng->seeded == false) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair_init(keypair);
    int ret = mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, keypair, mbedtls_ctr_drbg_random, &rng->ctr_drbg);
    if (ret != 0) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int aliro_export_uncompressed_pubkey(const mbedtls_ecp_keypair *keypair, uint8_t out[65]) {
    if (keypair == NULL || out == NULL) {
        return PM3_EINVARG;
    }
    size_t written = 0;
    int ret = mbedtls_ecp_point_write_binary(&keypair->grp, &keypair->Q,
                                             MBEDTLS_ECP_PF_UNCOMPRESSED, &written, out, 65);
    if (ret != 0 || written != 65) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int aliro_export_pubkey_x(const mbedtls_ecp_keypair *keypair, uint8_t out[32]) {
    if (keypair == NULL || out == NULL) {
        return PM3_EINVARG;
    }
    int ret = mbedtls_mpi_write_binary(&keypair->Q.X, out, 32);
    return (ret == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

static int aliro_load_public_key(const uint8_t public_key[65], mbedtls_ecp_keypair *keypair) {
    if (public_key == NULL || keypair == NULL) {
        return PM3_EINVARG;
    }
    if (public_key[0] != 0x04) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair_init(keypair);
    int ret = mbedtls_ecp_group_load(&keypair->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    ret = mbedtls_ecp_point_read_binary(&keypair->grp, &keypair->Q, public_key, 65);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    ret = mbedtls_ecp_check_pubkey(&keypair->grp, &keypair->Q);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int aliro_compute_kdh(const mbedtls_ecp_keypair *reader_ephemeral_private_key,
                             const uint8_t endpoint_ephemeral_public_key[65],
                             const uint8_t transaction_identifier[16],
                             uint8_t kdh[32],
                             aliro_rng_t *rng) {
    if (reader_ephemeral_private_key == NULL || endpoint_ephemeral_public_key == NULL ||
            transaction_identifier == NULL || kdh == NULL || rng == NULL || rng->seeded == false) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair endpoint_ephemeral_key;
    mbedtls_ecp_keypair_init(&endpoint_ephemeral_key);
    int ret = aliro_load_public_key(endpoint_ephemeral_public_key, &endpoint_ephemeral_key);
    if (ret != PM3_SUCCESS) {
        mbedtls_ecp_keypair_free(&endpoint_ephemeral_key);
        return ret;
    }

    mbedtls_mpi shared_secret;
    mbedtls_mpi_init(&shared_secret);
    ret = mbedtls_ecdh_compute_shared((mbedtls_ecp_group *)&reader_ephemeral_private_key->grp,
                                      &shared_secret,
                                      &endpoint_ephemeral_key.Q,
                                      &reader_ephemeral_private_key->d,
                                      mbedtls_ctr_drbg_random,
                                      &rng->ctr_drbg);
    if (ret != 0) {
        mbedtls_mpi_free(&shared_secret);
        mbedtls_ecp_keypair_free(&endpoint_ephemeral_key);
        return PM3_ESOFT;
    }

    uint8_t zab[32] = {0};
    ret = mbedtls_mpi_write_binary(&shared_secret, zab, sizeof(zab));
    mbedtls_mpi_free(&shared_secret);
    mbedtls_ecp_keypair_free(&endpoint_ephemeral_key);
    if (ret != 0) {
        return PM3_ESOFT;
    }

    if (ansi_x963_sha256(zab, sizeof(zab),
                         (uint8_t *)transaction_identifier, 16,
                         32, kdh) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int aliro_hkdf_sha256(const uint8_t *ikm, size_t ikm_len,
                             const uint8_t *salt, size_t salt_len,
                             const uint8_t *info, size_t info_len,
                             uint8_t *out, size_t out_len) {
    if (ikm == NULL || salt == NULL || info == NULL || out == NULL) {
        return PM3_EINVARG;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return PM3_ESOFT;
    }

    int ret = mbedtls_hkdf(md_info, salt, salt_len, ikm, ikm_len, info, info_len, out, out_len);
    return (ret == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

static int aliro_aes_gcm_decrypt(const uint8_t key[32], const uint8_t *iv, size_t iv_len,
                                 const uint8_t *ciphertext_and_tag, size_t ciphertext_and_tag_len,
                                 uint8_t *plaintext) {
    if (key == NULL || iv == NULL || ciphertext_and_tag == NULL || plaintext == NULL) {
        return PM3_EINVARG;
    }
    if (ciphertext_and_tag_len < 16) {
        return PM3_EINVARG;
    }

    size_t ciphertext_len = ciphertext_and_tag_len - 16;
    const uint8_t *tag = ciphertext_and_tag + ciphertext_len;
    mbedtls_gcm_context gcm;
    mbedtls_gcm_init(&gcm);

    int ret = mbedtls_gcm_setkey(&gcm, MBEDTLS_CIPHER_ID_AES, key, 256);
    if (ret == 0) {
        ret = mbedtls_gcm_auth_decrypt(&gcm,
                                       ciphertext_len,
                                       iv,
                                       iv_len,
                                       NULL,
                                       0,
                                       tag,
                                       16,
                                       ciphertext_and_tag,
                                       plaintext);
    }

    mbedtls_gcm_free(&gcm);
    return (ret == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

static int aliro_create_auth1_signature(const mbedtls_ecp_keypair *reader_private_key,
                                        const uint8_t *data, size_t data_len,
                                        uint8_t signature[64]) {
    if (reader_private_key == NULL || data == NULL || signature == NULL) {
        return PM3_EINVARG;
    }

    uint8_t private_key[32] = {0};
    uint8_t public_key[65] = {0};
    if (mbedtls_mpi_write_binary(&reader_private_key->d, private_key, sizeof(private_key)) != 0) {
        return PM3_ESOFT;
    }
    if (aliro_export_uncompressed_pubkey(reader_private_key, public_key) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    uint8_t der_signature[80] = {0};
    size_t der_signature_len = sizeof(der_signature);
    if (ecdsa_signature_create(MBEDTLS_ECP_DP_SECP256R1,
                               private_key,
                               public_key,
                               (uint8_t *)data,
                               (int)data_len,
                               der_signature,
                               &der_signature_len,
                               true) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    uint8_t r[32] = {0};
    uint8_t s[32] = {0};
    if (ecdsa_asn1_get_signature(der_signature, der_signature_len, r, s) != 0) {
        return PM3_ESOFT;
    }
    memcpy(signature, r, 32);
    memcpy(signature + 32, s, 32);
    return PM3_SUCCESS;
}

static int aliro_parse_auth0_response(const uint8_t *buf, size_t len, aliro_auth0_response_t *out) {
    if (buf == NULL || out == NULL) {
        return PM3_EINVARG;
    }
    memset(out, 0, sizeof(*out));

    const uint8_t *cursor = buf;
    size_t left = len;
    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(ERR, "Malformed AUTH0 response");
            return PM3_ECARDEXCHANGE;
        }

        const uint8_t *value = cursor;
        switch (tlv.tag) {
            case 0x86:
                if (tlv.len != 65 || value[0] != 0x04) {
                    PrintAndLogEx(ERR, "Invalid AUTH0 tag 0x86 length/format (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_endpoint_ephemeral_public_key = true;
                memcpy(out->endpoint_ephemeral_public_key, value, 65);
                memcpy(out->endpoint_ephemeral_public_key_x, value + 1, 32);
                break;
            case 0x9D:
                if (tlv.len != 64) {
                    PrintAndLogEx(ERR, "Invalid AUTH0 cryptogram length (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_cryptogram = true;
                memcpy(out->cryptogram, value, 64);
                break;
            case 0xB2: {
                out->have_auth0_response_vendor_extension = true;
                size_t tlv_len = 0;
                int tlv_res = aliro_append_tlv(0xB2, value, tlv.len,
                                               out->auth0_response_vendor_extension_tlv,
                                               sizeof(out->auth0_response_vendor_extension_tlv),
                                               &tlv_len);
                if (tlv_res != PM3_SUCCESS) {
                    PrintAndLogEx(WARNING, "AUTH0 vendor extension too long, ignoring");
                    out->have_auth0_response_vendor_extension = false;
                } else {
                    out->auth0_response_vendor_extension_tlv_len = tlv_len;
                }
                break;
            }
            default:
                break;
        }

        cursor += tlv.len;
        left -= tlv.len;
    }

    if (out->have_endpoint_ephemeral_public_key == false) {
        PrintAndLogEx(ERR, "AUTH0 response does not contain endpoint ephemeral public key (tag 0x86)");
        return PM3_ECARDEXCHANGE;
    }
    return PM3_SUCCESS;
}

static int aliro_parse_auth1_plaintext(const uint8_t *buf, size_t len, aliro_auth1_response_t *out) {
    if (buf == NULL || out == NULL) {
        return PM3_EINVARG;
    }
    memset(out, 0, sizeof(*out));

    const uint8_t *cursor = buf;
    size_t left = len;
    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            PrintAndLogEx(ERR, "Malformed AUTH1 plaintext response");
            return PM3_ECARDEXCHANGE;
        }

        const uint8_t *value = cursor;
        switch (tlv.tag) {
            case 0x4E:
                if (tlv.len != sizeof(out->key_slot)) {
                    PrintAndLogEx(ERR, "Invalid AUTH1 key_slot size (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_key_slot = true;
                memcpy(out->key_slot, value, sizeof(out->key_slot));
                break;
            case 0x5A:
                if (tlv.len != 65 || value[0] != 0x04) {
                    PrintAndLogEx(ERR, "Invalid AUTH1 endpoint public key size/format (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_endpoint_public_key = true;
                memcpy(out->endpoint_public_key, value, 65);
                memcpy(out->endpoint_public_key_x, value + 1, 32);
                break;
            case 0x9E:
                if (tlv.len != 64) {
                    PrintAndLogEx(ERR, "Invalid AUTH1 signature size (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_signature = true;
                memcpy(out->signature, value, 64);
                break;
            case 0x5E:
                if (tlv.len != 2) {
                    PrintAndLogEx(ERR, "Invalid AUTH1 signaling bitmap size (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_signaling_bitmap = true;
                out->signaling_bitmap = (uint16_t)((value[0] << 8) | value[1]);
                break;
            case 0x91:
                if (tlv.len != sizeof(out->credential_signed_timestamp)) {
                    PrintAndLogEx(ERR, "Invalid AUTH1 credential timestamp size (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_credential_signed_timestamp = true;
                memcpy(out->credential_signed_timestamp, value, sizeof(out->credential_signed_timestamp));
                break;
            case 0x92:
                if (tlv.len != sizeof(out->revocation_signed_timestamp)) {
                    PrintAndLogEx(ERR, "Invalid AUTH1 revocation timestamp size (%zu)", tlv.len);
                    return PM3_ECARDEXCHANGE;
                }
                out->have_revocation_signed_timestamp = true;
                memcpy(out->revocation_signed_timestamp, value, sizeof(out->revocation_signed_timestamp));
                break;
            case 0x4B:
                out->have_mailbox_subset = true;
                out->mailbox_subset_len = MIN(sizeof(out->mailbox_subset), tlv.len);
                memcpy(out->mailbox_subset, value, out->mailbox_subset_len);
                break;
            default:
                break;
        }

        cursor += tlv.len;
        left -= tlv.len;
    }

    if (out->have_signature == false) {
        PrintAndLogEx(ERR, "AUTH1 plaintext missing signature (tag 0x9E)");
        return PM3_ECARDEXCHANGE;
    }
    if (out->have_signaling_bitmap == false) {
        PrintAndLogEx(ERR, "AUTH1 plaintext missing signaling bitmap (tag 0x5E)");
        return PM3_ECARDEXCHANGE;
    }
    if (out->have_key_slot == false && out->have_endpoint_public_key == false) {
        PrintAndLogEx(ERR, "AUTH1 plaintext missing both key slot and endpoint public key");
        return PM3_ECARDEXCHANGE;
    }
    return PM3_SUCCESS;
}

static void aliro_print_signaling_bitmap(uint16_t bitmap) {
    static const char *bit_names[] = {
        "Access document can be retrieved",
        "Revocation document can be retrieved",
        "Step-up SELECT required for doc retrieval",
        "Mailbox has non-zero data",
        "Mailbox read supported",
        "Mailbox write/set supported",
        "Notify backend supported",
        "Notify bound app supported",
        "RFU (bit8)",
        "update_doc supported in expedited phase",
        "Mailbox in step-up available",
        "Notify in step-up supported",
        "update_doc in step-up supported",
    };

    PrintAndLogEx(INFO, "Signaling bitmap......... " _YELLOW_("0x%04X"), bitmap);
    for (size_t i = 0; i < ARRAYLEN(bit_names); i++) {
        if ((bitmap & (1U << i)) != 0) {
            PrintAndLogEx(INFO, "  " _YELLOW_("bit%-2zu") " set.............. %s", i, bit_names[i]);
        }
    }
}

static bool aliro_is_zeroed(const uint8_t *buf, size_t len) {
    if (buf == NULL) {
        return true;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf[i] != 0x00) {
            return false;
        }
    }
    return true;
}

static bool aliro_is_ascii(const uint8_t *buf, size_t len) {
    if (buf == NULL) {
        return false;
    }
    for (size_t i = 0; i < len; i++) {
        if (buf[i] < 0x20 || buf[i] > 0x7E) {
            return false;
        }
    }
    return true;
}

static void aliro_print_timestamp(const char *label, const uint8_t *timestamp, bool have) {
    if (have == false) {
        PrintAndLogEx(INFO, "%s not present", label);
        return;
    }
    if (aliro_is_zeroed(timestamp, 20)) {
        PrintAndLogEx(INFO, "%s all-zero", label);
        return;
    }
    if (aliro_is_ascii(timestamp, 20)) {
        PrintAndLogEx(INFO, "%s %s", label, sprint_ascii(timestamp, 20));
    } else {
        PrintAndLogEx(INFO, "%s %s", label, sprint_hex_inrow(timestamp, 20));
    }
}

static int aliro_buf_append(uint8_t *buf, size_t buf_len, size_t *offset, const uint8_t *data, size_t data_len) {
    if (buf == NULL || offset == NULL || (data_len > 0 && data == NULL)) {
        return PM3_EINVARG;
    }
    if (*offset > buf_len || data_len > (buf_len - *offset)) {
        return PM3_EOVFLOW;
    }
    if (data_len > 0) {
        memcpy(buf + *offset, data, data_len);
        *offset += data_len;
    }
    return PM3_SUCCESS;
}

static int aliro_build_kdf_info(uint8_t *info, size_t info_len, size_t *written_len,
                                const uint8_t endpoint_ephemeral_public_key_x[32],
                                const uint8_t *auth0_suffix, size_t auth0_suffix_len) {
    if (info == NULL || written_len == NULL || endpoint_ephemeral_public_key_x == NULL ||
            (auth0_suffix_len > 0 && auth0_suffix == NULL)) {
        return PM3_EINVARG;
    }

    *written_len = 0;
    int res = aliro_buf_append(info, info_len, written_len, endpoint_ephemeral_public_key_x, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    return aliro_buf_append(info, info_len, written_len, auth0_suffix, auth0_suffix_len);
}

static int aliro_build_kdf_salt(uint8_t *salt, size_t salt_len, size_t *written_len,
                                const uint8_t reader_public_key_x[32],
                                const uint8_t *mode, size_t mode_len,
                                const uint8_t reader_identifier[32],
                                const uint8_t protocol_version[2],
                                const uint8_t reader_ephemeral_public_key_x[32],
                                const uint8_t transaction_identifier[16],
                                uint8_t command_parameters,
                                uint8_t authentication_policy,
                                const uint8_t *fci_proprietary_tlv, size_t fci_proprietary_tlv_len,
                                const uint8_t endpoint_public_key_x[32]) {
    if (salt == NULL || written_len == NULL || reader_public_key_x == NULL || mode == NULL ||
            reader_identifier == NULL || protocol_version == NULL ||
            reader_ephemeral_public_key_x == NULL || transaction_identifier == NULL ||
            (fci_proprietary_tlv_len > 0 && fci_proprietary_tlv == NULL)) {
        return PM3_EINVARG;
    }

    static const uint8_t protocol_marker[] = {ALIRO_NFC_INTERFACE_BYTE, 0x5C, 0x02};
    uint8_t flag[2] = {command_parameters, authentication_policy};

    *written_len = 0;
    int res = aliro_buf_append(salt, salt_len, written_len, reader_public_key_x, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, mode, mode_len);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, reader_identifier, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, protocol_marker, sizeof(protocol_marker));
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, protocol_version, 2);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, reader_ephemeral_public_key_x, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, transaction_identifier, 16);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, flag, sizeof(flag));
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_buf_append(salt, salt_len, written_len, fci_proprietary_tlv, fci_proprietary_tlv_len);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (endpoint_public_key_x != NULL) {
        res = aliro_buf_append(salt, salt_len, written_len, endpoint_public_key_x, 32);
        if (res != PM3_SUCCESS) {
            return res;
        }
    }
    return PM3_SUCCESS;
}

static int aliro_derive_standard_keys(const uint8_t kdh[32],
                                      const uint8_t reader_public_key_x[32],
                                      const uint8_t reader_identifier[32],
                                      const uint8_t protocol_version[2],
                                      const uint8_t reader_ephemeral_public_key_x[32],
                                      const uint8_t transaction_identifier[16],
                                      uint8_t command_parameters,
                                      uint8_t authentication_policy,
                                      const uint8_t *fci_proprietary_tlv, size_t fci_proprietary_tlv_len,
                                      const uint8_t endpoint_ephemeral_public_key_x[32],
                                      const uint8_t endpoint_public_key_x[32],
                                      const uint8_t *auth0_suffix, size_t auth0_suffix_len,
                                      aliro_standard_result_t *derived) {
    if (kdh == NULL || reader_public_key_x == NULL || reader_identifier == NULL ||
            protocol_version == NULL || reader_ephemeral_public_key_x == NULL ||
            transaction_identifier == NULL || fci_proprietary_tlv == NULL ||
            endpoint_ephemeral_public_key_x == NULL || endpoint_public_key_x == NULL ||
            auth0_suffix == NULL || derived == NULL) {
        return PM3_EINVARG;
    }

    derived->keys.cryptogram_sk_present = false;
    derived->keys.step_up_keys_present = false;
    derived->keys.kpersistent_present = false;

    uint8_t volatile_salt[ALIRO_MAX_BUFFER] = {0};
    size_t volatile_salt_len = 0;
    uint8_t volatile_info[ALIRO_MAX_BUFFER] = {0};
    size_t volatile_info_len = 0;

    int res = aliro_build_kdf_salt(volatile_salt, sizeof(volatile_salt), &volatile_salt_len,
                                   reader_public_key_x,
                                   (const uint8_t *)"Volatile****", 12,
                                   reader_identifier,
                                   protocol_version,
                                   reader_ephemeral_public_key_x,
                                   transaction_identifier,
                                   command_parameters,
                                   authentication_policy,
                                   fci_proprietary_tlv, fci_proprietary_tlv_len,
                                   NULL);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_build_kdf_info(volatile_info, sizeof(volatile_info), &volatile_info_len,
                               endpoint_ephemeral_public_key_x,
                               auth0_suffix, auth0_suffix_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t volatile_material[160] = {0};
    res = aliro_hkdf_sha256(kdh, 32,
                            volatile_salt, volatile_salt_len,
                            volatile_info, volatile_info_len,
                            volatile_material, sizeof(volatile_material));
    if (res != PM3_SUCCESS) {
        return res;
    }

    memcpy(derived->keys.kdh, kdh, 32);
    memcpy(derived->keys.exchange_sk_reader, volatile_material, 32);
    memcpy(derived->keys.exchange_sk_device, volatile_material + 32, 32);

    uint8_t zeros[32] = {0};
    res = aliro_hkdf_sha256(volatile_material + 64, 32, zeros, sizeof(zeros),
                            (const uint8_t *)"SKReader", 8, derived->keys.step_up_sk_reader, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_hkdf_sha256(volatile_material + 64, 32, zeros, sizeof(zeros),
                            (const uint8_t *)"SKDevice", 8, derived->keys.step_up_sk_device, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    derived->keys.step_up_keys_present = true;
    res = aliro_hkdf_sha256(volatile_material + 96, 32, zeros, sizeof(zeros),
                            (const uint8_t *)"BleSKReader", 11, derived->keys.ble_sk_reader, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_hkdf_sha256(volatile_material + 96, 32, zeros, sizeof(zeros),
                            (const uint8_t *)"BleSKDevice", 11, derived->keys.ble_sk_device, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    memcpy(derived->keys.ursk, volatile_material + 128, 32);

    uint8_t persistent_salt[ALIRO_MAX_BUFFER] = {0};
    size_t persistent_salt_len = 0;
    res = aliro_build_kdf_salt(persistent_salt, sizeof(persistent_salt), &persistent_salt_len,
                               reader_public_key_x,
                               (const uint8_t *)"Persistent**", 12,
                               reader_identifier,
                               protocol_version,
                               reader_ephemeral_public_key_x,
                               transaction_identifier,
                               command_parameters,
                               authentication_policy,
                               fci_proprietary_tlv, fci_proprietary_tlv_len,
                               endpoint_public_key_x);
    if (res != PM3_SUCCESS) {
        return res;
    }

    res = aliro_hkdf_sha256(kdh, 32,
                            persistent_salt, persistent_salt_len,
                            volatile_info, volatile_info_len,
                            derived->keys.kpersistent, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    derived->keys.kpersistent_present = true;
    return PM3_SUCCESS;
}

static int aliro_verify_fast_cryptogram(const uint8_t kpersistent[32],
                                        const uint8_t reader_public_key_x[32],
                                        const uint8_t reader_identifier[32],
                                        const uint8_t protocol_version[2],
                                        const uint8_t reader_ephemeral_public_key_x[32],
                                        const uint8_t transaction_identifier[16],
                                        uint8_t command_parameters,
                                        uint8_t authentication_policy,
                                        const uint8_t *fci_proprietary_tlv, size_t fci_proprietary_tlv_len,
                                        const uint8_t endpoint_public_key_x[32],
                                        const uint8_t endpoint_ephemeral_public_key_x[32],
                                        const uint8_t cryptogram[64],
                                        const uint8_t *auth0_suffix, size_t auth0_suffix_len,
                                        aliro_fast_result_t *result) {
    if (kpersistent == NULL || reader_public_key_x == NULL || reader_identifier == NULL ||
            protocol_version == NULL || reader_ephemeral_public_key_x == NULL ||
            transaction_identifier == NULL || fci_proprietary_tlv == NULL ||
            endpoint_public_key_x == NULL || endpoint_ephemeral_public_key_x == NULL ||
            cryptogram == NULL || auth0_suffix == NULL || result == NULL) {
        return PM3_EINVARG;
    }
    memset(result, 0, sizeof(*result));

    uint8_t salt_fast[ALIRO_MAX_BUFFER] = {0};
    size_t salt_fast_len = 0;
    int res = aliro_build_kdf_salt(salt_fast, sizeof(salt_fast), &salt_fast_len,
                                   reader_public_key_x,
                                   (const uint8_t *)"VolatileFast", 12,
                                   reader_identifier,
                                   protocol_version,
                                   reader_ephemeral_public_key_x,
                                   transaction_identifier,
                                   command_parameters,
                                   authentication_policy,
                                   fci_proprietary_tlv, fci_proprietary_tlv_len,
                                   endpoint_public_key_x);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t info[ALIRO_MAX_BUFFER] = {0};
    size_t info_len = 0;
    res = aliro_build_kdf_info(info, sizeof(info), &info_len,
                               endpoint_ephemeral_public_key_x,
                               auth0_suffix, auth0_suffix_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t fast_material[160] = {0};
    res = aliro_hkdf_sha256(kpersistent, 32,
                            salt_fast, salt_fast_len,
                            info, info_len,
                            fast_material, sizeof(fast_material));
    if (res != PM3_SUCCESS) {
        return res;
    }

    memcpy(result->keys.cryptogram_sk, fast_material, 32);
    memcpy(result->keys.exchange_sk_reader, fast_material + 32, 32);
    memcpy(result->keys.exchange_sk_device, fast_material + 64, 32);
    memcpy(result->keys.ursk, fast_material + 128, 32);

    uint8_t zeros[32] = {0};
    res = aliro_hkdf_sha256(fast_material + 96, 32, zeros, sizeof(zeros),
                            (const uint8_t *)"BleSKReader", 11, result->keys.ble_sk_reader, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }
    res = aliro_hkdf_sha256(fast_material + 96, 32, zeros, sizeof(zeros),
                            (const uint8_t *)"BleSKDevice", 11, result->keys.ble_sk_device, 32);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t plaintext[48] = {0};
    res = aliro_aes_gcm_decrypt(result->keys.cryptogram_sk, ALIRO_AUTH0_GCM_IV, sizeof(ALIRO_AUTH0_GCM_IV),
                                cryptogram, 64, plaintext);
    if (res != PM3_SUCCESS) {
        return PM3_ECRYPTO;
    }

    const uint8_t *cursor = plaintext;
    size_t left = sizeof(plaintext);
    bool have_status = false;
    bool have_cred_ts = false;
    bool have_rev_ts = false;
    while (left > 0) {
        struct tlv tlv = {0};
        if (tlv_parse_tl(&cursor, &left, &tlv) == false || tlv.len > left) {
            return PM3_ECARDEXCHANGE;
        }

        const uint8_t *value = cursor;
        if (tlv.tag == 0x5E && tlv.len == 2) {
            result->signaling_bitmap = (uint16_t)((value[0] << 8) | value[1]);
            have_status = true;
        } else if (tlv.tag == 0x91 && tlv.len == 20) {
            memcpy(result->credential_signed_timestamp, value, 20);
            have_cred_ts = true;
        } else if (tlv.tag == 0x92 && tlv.len == 20) {
            memcpy(result->revocation_signed_timestamp, value, 20);
            have_rev_ts = true;
        }

        cursor += tlv.len;
        left -= tlv.len;
    }

    if (have_status && have_cred_ts && have_rev_ts) {
        result->keys.cryptogram_sk_present = true;
        result->verified = true;
        return PM3_SUCCESS;
    }
    return PM3_ESOFT;
}

static int info_aliro(void) {
    aliro_select_info_t select_info;
    int res = aliro_select_with_info(&select_info, false);
    DropField();
    if (res != PM3_SUCCESS) {
        return (res == PM3_ESOFT) ? PM3_SUCCESS : res;
    }

    print_aliro_select_info(&select_info);
    return PM3_SUCCESS;
}

static int aliro_read_prepare_session(aliro_read_state_t *state,
                                      mbedtls_ecp_keypair *reader_private_key,
                                      mbedtls_ecp_keypair *reader_ephemeral_key,
                                      const uint8_t reader_group_identifier[16],
                                      const uint8_t reader_group_sub_identifier[16],
                                      const uint8_t reader_private_key_raw[32],
                                      const uint8_t *transaction_identifier_in, size_t transaction_identifier_len,
                                      aliro_rng_t *rng) {
    if (state == NULL || reader_private_key == NULL || reader_ephemeral_key == NULL ||
            reader_group_identifier == NULL || reader_group_sub_identifier == NULL ||
            reader_private_key_raw == NULL || rng == NULL) {
        return PM3_EINVARG;
    }

    int res = aliro_load_private_key(reader_private_key_raw, reader_private_key, rng);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Invalid reader private key");
        return res;
    }

    res = aliro_generate_ephemeral_keypair(reader_ephemeral_key, rng);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to generate reader ephemeral key");
        return res;
    }

    res = aliro_select_with_info(&state->select_info, true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    aliro_print_big_header("Applet information");
    print_aliro_select_info(&state->select_info);

    if (state->select_info.have_proprietary_tlv == false) {
        PrintAndLogEx(ERR, "Missing proprietary information TLV in SELECT response");
        return PM3_ESOFT;
    }

    if (aliro_choose_protocol_version(&state->select_info, state->protocol_version) == false) {
        PrintAndLogEx(ERR, "Could not determine ALIRO protocol version from SELECT response");
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "Selected protocol version. 0x%02X%02X", state->protocol_version[0], state->protocol_version[1]);

    memcpy(state->reader_identifier, reader_group_identifier, 16);
    memcpy(state->reader_identifier + 16, reader_group_sub_identifier, 16);

    if (aliro_export_uncompressed_pubkey(reader_private_key, state->reader_public_key) != PM3_SUCCESS ||
            aliro_export_pubkey_x(reader_private_key, state->reader_public_key_x) != PM3_SUCCESS ||
            aliro_export_uncompressed_pubkey(reader_ephemeral_key, state->reader_ephemeral_public_key) != PM3_SUCCESS ||
            aliro_export_pubkey_x(reader_ephemeral_key, state->reader_ephemeral_public_key_x) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to export reader public keys");
        return PM3_ESOFT;
    }

    if (transaction_identifier_len == 16 && transaction_identifier_in != NULL) {
        memcpy(state->transaction_identifier, transaction_identifier_in, sizeof(state->transaction_identifier));
    } else {
        if (mbedtls_ctr_drbg_random(&rng->ctr_drbg,
                                    state->transaction_identifier,
                                    sizeof(state->transaction_identifier)) != 0) {
            PrintAndLogEx(ERR, "Failed to generate transaction identifier");
            return PM3_ESOFT;
        }
    }

    return PM3_SUCCESS;
}

static int aliro_read_do_auth0(aliro_read_state_t *state,
                               const uint8_t *kpersistent, size_t kpersistent_len,
                               const uint8_t reader_group_identifier[16],
                               const uint8_t reader_group_sub_identifier[16],
                               const uint8_t *endpoint_public_key_x_in,
                               aliro_flow_t flow,
                               bool *fast_flow_complete) {
    if (state == NULL || reader_group_identifier == NULL ||
            reader_group_sub_identifier == NULL || fast_flow_complete == NULL) {
        return PM3_EINVARG;
    }

    *fast_flow_complete = false;
    memset(&state->fast_result, 0, sizeof(state->fast_result));
    bool auth0_fast_requested = (flow == ALIRO_FLOW_FAST) || (kpersistent_len == 32);
    state->auth0_command_parameters = auth0_fast_requested ? 0x01 : 0x00;

    uint8_t auth0_data[ALIRO_MAX_BUFFER] = {0};
    size_t auth0_data_len = 0;
    if (aliro_append_tlv(0x41, &state->auth0_command_parameters, 1, auth0_data, sizeof(auth0_data), &auth0_data_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x42, (const uint8_t[]){ALIRO_AUTH0_DEFAULT_POLICY}, 1, auth0_data, sizeof(auth0_data), &auth0_data_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x5C, state->protocol_version, 2, auth0_data, sizeof(auth0_data), &auth0_data_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x87, state->reader_ephemeral_public_key, 65, auth0_data, sizeof(auth0_data), &auth0_data_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x4C, state->transaction_identifier, 16, auth0_data, sizeof(auth0_data), &auth0_data_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x4D, state->reader_identifier, 32, auth0_data, sizeof(auth0_data), &auth0_data_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to encode AUTH0 command");
        return PM3_ESOFT;
    }

    aliro_print_big_header("AUTH0");
    PrintAndLogEx(INFO, "Reader group id........... %s", sprint_hex_inrow(reader_group_identifier, 16));
    PrintAndLogEx(INFO, "Reader sub id............. %s", sprint_hex_inrow(reader_group_sub_identifier, 16));
    PrintAndLogEx(INFO, "Reader id................. %s", sprint_hex_inrow(state->reader_identifier, 32));
    PrintAndLogEx(INFO, "Reader public key......... %s", sprint_hex_inrow(state->reader_public_key, 65));
    PrintAndLogEx(INFO, "Reader ePubK.............. %s", sprint_hex_inrow(state->reader_ephemeral_public_key, 65));
    PrintAndLogEx(INFO, "Transaction identifier.... %s", sprint_hex_inrow(state->transaction_identifier, 16));
    PrintAndLogEx(INFO, "Requested AUTH0 flow...... %s", auth0_fast_requested ? "fast" : "standard");
    if (flow == ALIRO_FLOW_STANDARD && auth0_fast_requested) {
        PrintAndLogEx(INFO, "AUTH0 flow override....... fast (k-persistent provided)");
    }

    uint8_t auth0_response[ALIRO_MAX_BUFFER] = {0};
    size_t auth0_response_len = 0;
    uint16_t auth0_sw = 0;
    int res = aliro_exchange_chained(false, true, 0x80, 0x80, 0x00, 0x00,
                                     auth0_data, auth0_data_len,
                                     auth0_response, sizeof(auth0_response),
                                     &auth0_response_len, &auth0_sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "AUTH0 APDU exchange failed");
        return res;
    }
    if (auth0_sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "AUTH0 failed: %04x - %s", auth0_sw, GetAPDUCodeDescription(auth0_sw >> 8, auth0_sw & 0xff));
        return PM3_ESOFT;
    }

    res = aliro_parse_auth0_response(auth0_response, auth0_response_len, &state->auth0_parsed);
    if (res != PM3_SUCCESS) {
        return res;
    }

    state->auth0_suffix_len = 0;
    memset(state->auth0_suffix, 0, sizeof(state->auth0_suffix));
    if (state->auth0_parsed.have_auth0_response_vendor_extension &&
            state->auth0_parsed.auth0_response_vendor_extension_tlv_len > 0) {
        state->auth0_suffix_len = state->auth0_parsed.auth0_response_vendor_extension_tlv_len;
        memcpy(state->auth0_suffix, state->auth0_parsed.auth0_response_vendor_extension_tlv, state->auth0_suffix_len);
    }

    PrintAndLogEx(INFO, "AUTH0 credential ePubK.... %s", sprint_hex_inrow(state->auth0_parsed.endpoint_ephemeral_public_key, 65));
    if (state->auth0_parsed.have_cryptogram) {
        PrintAndLogEx(INFO, "AUTH0 cryptogram.......... %s", sprint_hex_inrow(state->auth0_parsed.cryptogram, 64));
    } else {
        PrintAndLogEx(INFO, "AUTH0 cryptogram.......... not present");
    }
    if (endpoint_public_key_x_in != NULL) {
        PrintAndLogEx(INFO, "Endpoint pubkey X (input). %s", sprint_hex_inrow(endpoint_public_key_x_in, 32));
    }
    if (auth0_fast_requested == false && state->auth0_parsed.have_cryptogram) {
        PrintAndLogEx(WARNING, "AUTH0 returned a cryptogram while standard flow was requested");
    }
    if (auth0_fast_requested && state->auth0_parsed.have_cryptogram == false) {
        PrintAndLogEx(WARNING, "AUTH0 fast flow requested, but cryptogram is missing");
        PrintAndLogEx(INFO, "Fast flow................. no cryptogram, continuing to standard");
    }
    if (state->auth0_suffix_len > 0) {
        PrintAndLogEx(INFO, "AUTH0 vendor extension.... %s", sprint_hex_inrow(state->auth0_suffix, state->auth0_suffix_len));
    }

    if (state->auth0_parsed.have_cryptogram) {
        if (kpersistent_len != 32) {
            PrintAndLogEx(INFO, "AUTH0 fast verify......... skipped (no --k-persistent provided)");
        } else if (endpoint_public_key_x_in == NULL) {
            PrintAndLogEx(INFO, "AUTH0 fast verify......... skipped (endpoint public key unavailable)");
            if (auth0_fast_requested) {
                PrintAndLogEx(INFO, "Fast flow................. endpoint public key unavailable, continuing to standard");
            }
        } else {
            PrintAndLogEx(INFO, "Kpersistent (input)....... " _YELLOW_("%s"), sprint_hex_inrow(kpersistent, 32));
            res = aliro_verify_fast_cryptogram(kpersistent,
                                               state->reader_public_key_x,
                                               state->reader_identifier,
                                               state->protocol_version,
                                               state->reader_ephemeral_public_key_x,
                                               state->transaction_identifier,
                                               state->auth0_command_parameters,
                                               ALIRO_AUTH0_DEFAULT_POLICY,
                                               state->select_info.proprietary_tlv,
                                               state->select_info.proprietary_tlv_len,
                                               endpoint_public_key_x_in,
                                               state->auth0_parsed.endpoint_ephemeral_public_key_x,
                                               state->auth0_parsed.cryptogram,
                                               state->auth0_suffix,
                                               state->auth0_suffix_len,
                                               &state->fast_result);
            if (res == PM3_SUCCESS && state->fast_result.verified) {
                PrintAndLogEx(INFO, "AUTH0 fast verify......... " _GREEN_("ok"));
                aliro_print_signaling_bitmap(state->fast_result.signaling_bitmap);
                aliro_print_timestamp("Fast credential timestamp..", state->fast_result.credential_signed_timestamp, true);
                aliro_print_timestamp("Fast revocation timestamp..", state->fast_result.revocation_signed_timestamp, true);
                PrintAndLogEx(INFO, "Derived keys:");
                PrintAndLogEx(INFO, "  CryptogramSK.............. %s", sprint_hex_inrow(state->fast_result.keys.cryptogram_sk, 32));
                PrintAndLogEx(INFO, "  Fast ExpeditedSKReader.... %s", sprint_hex_inrow(state->fast_result.keys.exchange_sk_reader, 32));
                PrintAndLogEx(INFO, "  Fast ExpeditedSKDevice.... %s", sprint_hex_inrow(state->fast_result.keys.exchange_sk_device, 32));
                PrintAndLogEx(INFO, "  Fast BleSKReader.......... %s", sprint_hex_inrow(state->fast_result.keys.ble_sk_reader, 32));
                PrintAndLogEx(INFO, "  Fast BleSKDevice.......... %s", sprint_hex_inrow(state->fast_result.keys.ble_sk_device, 32));
                PrintAndLogEx(INFO, "  Fast URSK................. %s", sprint_hex_inrow(state->fast_result.keys.ursk, 32));
                if (flow == ALIRO_FLOW_FAST) {
                    *fast_flow_complete = true;
                    return PM3_SUCCESS;
                }
            } else {
                if (auth0_fast_requested && res == PM3_ECRYPTO) {
                    PrintAndLogEx(INFO, "Fast flow................. unable to decrypt cryptogram, continuing to standard");
                }
                PrintAndLogEx(INFO, "AUTH0 fast verify......... " _RED_("failed"));
            }
        }
    }

    return PM3_SUCCESS;
}

static int aliro_read_prepare_auth1_keys(aliro_read_state_t *state,
                                         mbedtls_ecp_keypair *reader_ephemeral_key,
                                         aliro_rng_t *rng) {
    if (state == NULL || reader_ephemeral_key == NULL || rng == NULL) {
        return PM3_EINVARG;
    }

    uint8_t placeholder_public_key_x[32] = {0};
    memset(&state->standard_result, 0, sizeof(state->standard_result));

    int res = aliro_compute_kdh(reader_ephemeral_key, state->auth0_parsed.endpoint_ephemeral_public_key,
                                state->transaction_identifier, state->standard_result.keys.kdh, rng);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to compute Kdh");
        return res;
    }

    res = aliro_derive_standard_keys(state->standard_result.keys.kdh,
                                     state->reader_public_key_x,
                                     state->reader_identifier,
                                     state->protocol_version,
                                     state->reader_ephemeral_public_key_x,
                                     state->transaction_identifier,
                                     state->auth0_command_parameters,
                                     ALIRO_AUTH0_DEFAULT_POLICY,
                                     state->select_info.proprietary_tlv,
                                     state->select_info.proprietary_tlv_len,
                                     state->auth0_parsed.endpoint_ephemeral_public_key_x,
                                     placeholder_public_key_x,
                                     state->auth0_suffix,
                                     state->auth0_suffix_len,
                                     &state->standard_result);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to derive volatile keys for AUTH1 decryption");
        return res;
    }
    // Placeholder endpoint key was used above; do not expose kpersistent until real endpoint key is known.
    state->standard_result.keys.kpersistent_present = false;
    memset(state->standard_result.keys.kpersistent, 0, sizeof(state->standard_result.keys.kpersistent));

    return PM3_SUCCESS;
}

static int aliro_build_auth1_signed_input(const aliro_read_state_t *state,
                                          const uint8_t context[sizeof(ALIRO_READER_CONTEXT)],
                                          uint8_t *out, size_t out_size, size_t *out_len) {
    if (state == NULL || context == NULL || out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }

    *out_len = 0;
    if (aliro_append_tlv(0x4D, state->reader_identifier, 32, out, out_size, out_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x86, state->auth0_parsed.endpoint_ephemeral_public_key_x, 32, out, out_size, out_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x87, state->reader_ephemeral_public_key_x, 32, out, out_size, out_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x4C, state->transaction_identifier, 16, out, out_size, out_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x93, context, sizeof(ALIRO_READER_CONTEXT), out, out_size, out_len) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int aliro_read_do_auth1(aliro_read_state_t *state,
                               mbedtls_ecp_keypair *reader_private_key) {
    if (state == NULL || reader_private_key == NULL) {
        return PM3_EINVARG;
    }

    uint8_t auth1_hash_input[ALIRO_MAX_BUFFER] = {0};
    size_t auth1_hash_input_len = 0;
    int res = aliro_build_auth1_signed_input(state, ALIRO_READER_CONTEXT,
                                             auth1_hash_input, sizeof(auth1_hash_input), &auth1_hash_input_len);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to build AUTH1 signed data");
        return res;
    }

    uint8_t auth1_signature[64] = {0};
    res = aliro_create_auth1_signature(reader_private_key, auth1_hash_input, auth1_hash_input_len, auth1_signature);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to create AUTH1 signature");
        return res;
    }

    uint8_t auth1_data[ALIRO_MAX_BUFFER] = {0};
    size_t auth1_data_len = 0;
    if (aliro_append_tlv(0x41, (const uint8_t[]){ALIRO_AUTH1_REQUEST_PUBLIC_KEY}, 1,
                         auth1_data, sizeof(auth1_data), &auth1_data_len) != PM3_SUCCESS ||
            aliro_append_tlv(0x9E, auth1_signature, 64,
                             auth1_data, sizeof(auth1_data), &auth1_data_len) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to encode AUTH1 command");
        return PM3_ESOFT;
    }

    uint8_t auth1_response_enc[ALIRO_MAX_BUFFER] = {0};
    size_t auth1_response_enc_len = 0;
    uint16_t auth1_sw = 0;
    res = aliro_exchange_chained(false, true, 0x80, 0x81, 0x00, 0x00,
                                 auth1_data, auth1_data_len,
                                 auth1_response_enc, sizeof(auth1_response_enc),
                                 &auth1_response_enc_len, &auth1_sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "AUTH1 APDU exchange failed");
        return res;
    }
    if (auth1_sw != ISO7816_OK) {
        PrintAndLogEx(ERR, "AUTH1 failed: %04x - %s", auth1_sw, GetAPDUCodeDescription(auth1_sw >> 8, auth1_sw & 0xff));
        return PM3_ESOFT;
    }
    if (auth1_response_enc_len < 16) {
        PrintAndLogEx(ERR, "AUTH1 response too short");
        return PM3_ESOFT;
    }

    uint8_t auth1_iv[12] = {0};
    memcpy(auth1_iv, ALIRO_EXCHANGE_MODE, sizeof(ALIRO_EXCHANGE_MODE));
    auth1_iv[8] = 0x00;
    auth1_iv[9] = 0x00;
    auth1_iv[10] = 0x00;
    auth1_iv[11] = 0x01;

    uint8_t auth1_plain[ALIRO_MAX_BUFFER] = {0};
    res = aliro_aes_gcm_decrypt(state->standard_result.keys.exchange_sk_device, auth1_iv, sizeof(auth1_iv),
                                auth1_response_enc, auth1_response_enc_len, auth1_plain);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to decrypt AUTH1 response");
        return res;
    }

    size_t auth1_plain_len = auth1_response_enc_len - 16;
    res = aliro_parse_auth1_plaintext(auth1_plain, auth1_plain_len, &state->auth1_parsed);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (state->auth1_parsed.have_endpoint_public_key) {
        aliro_standard_result_t standard_result_with_persistent;
        res = aliro_derive_standard_keys(state->standard_result.keys.kdh,
                                         state->reader_public_key_x,
                                         state->reader_identifier,
                                         state->protocol_version,
                                         state->reader_ephemeral_public_key_x,
                                         state->transaction_identifier,
                                         state->auth0_command_parameters,
                                         ALIRO_AUTH0_DEFAULT_POLICY,
                                         state->select_info.proprietary_tlv,
                                         state->select_info.proprietary_tlv_len,
                                         state->auth0_parsed.endpoint_ephemeral_public_key_x,
                                         state->auth1_parsed.endpoint_public_key_x,
                                         state->auth0_suffix,
                                         state->auth0_suffix_len,
                                         &standard_result_with_persistent);
        if (res == PM3_SUCCESS) {
            state->standard_result = standard_result_with_persistent;
        }
    }

    state->standard_result.signature_checked = false;
    state->standard_result.signature_valid = false;
    if (state->auth1_parsed.have_endpoint_public_key) {
        uint8_t auth1_verify_input[ALIRO_MAX_BUFFER] = {0};
        size_t auth1_verify_input_len = 0;
        if (aliro_build_auth1_signed_input(state, ALIRO_DEVICE_CONTEXT,
                                           auth1_verify_input, sizeof(auth1_verify_input), &auth1_verify_input_len) == PM3_SUCCESS) {
            state->standard_result.signature_checked = true;
            int sig_res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_SECP256R1,
                                                     state->auth1_parsed.endpoint_public_key,
                                                     auth1_verify_input,
                                                     (int)auth1_verify_input_len,
                                                     state->auth1_parsed.signature,
                                                     sizeof(state->auth1_parsed.signature),
                                                     true);
            state->standard_result.signature_valid = (sig_res == 0);
        }
    }

    return PM3_SUCCESS;
}

static void aliro_read_print_auth1_report(const aliro_read_state_t *state,
                                          const uint8_t reader_group_identifier[16],
                                          const uint8_t reader_group_sub_identifier[16],
                                          const uint8_t reader_private_key_raw[32]) {
    if (state == NULL || reader_group_identifier == NULL ||
            reader_group_sub_identifier == NULL || reader_private_key_raw == NULL) {
        return;
    }

    aliro_print_big_header("AUTH1");
    PrintAndLogEx(INFO, "AUTH1 signature........... %s", sprint_hex_inrow(state->auth1_parsed.signature, 64));
    if (state->auth1_parsed.have_key_slot) {
        PrintAndLogEx(INFO, "AUTH1 key slot............ %s", sprint_hex_inrow(state->auth1_parsed.key_slot, 8));
    }
    if (state->auth1_parsed.have_endpoint_public_key) {
        PrintAndLogEx(INFO, "AUTH1 endpoint pubkey..... %s", sprint_hex_inrow(state->auth1_parsed.endpoint_public_key, 65));
        if (state->standard_result.signature_checked) {
            PrintAndLogEx(INFO, "AUTH1 signature valid...... %s", state->standard_result.signature_valid ? _GREEN_("yes") : _RED_("no"));
        } else {
            PrintAndLogEx(INFO, "AUTH1 signature valid...... not checked");
        }
    } else {
        PrintAndLogEx(INFO, "AUTH1 endpoint pubkey..... not present");
        PrintAndLogEx(INFO, "AUTH1 signature valid...... not checked");
    }
    aliro_print_signaling_bitmap(state->auth1_parsed.signaling_bitmap);
    aliro_print_timestamp("Credential timestamp.......", state->auth1_parsed.credential_signed_timestamp,
                          state->auth1_parsed.have_credential_signed_timestamp);
    aliro_print_timestamp("Revocation timestamp.......", state->auth1_parsed.revocation_signed_timestamp,
                          state->auth1_parsed.have_revocation_signed_timestamp);
    if (state->auth1_parsed.have_mailbox_subset) {
        PrintAndLogEx(INFO, "Mailbox subset............ %s",
                      sprint_hex_inrow(state->auth1_parsed.mailbox_subset, state->auth1_parsed.mailbox_subset_len));
    }

    PrintAndLogEx(INFO, "Derived keys:");
    PrintAndLogEx(INFO, "  Kdh....................... %s", sprint_hex_inrow(state->standard_result.keys.kdh, 32));
    PrintAndLogEx(INFO, "  ExpeditedSKReader......... %s", sprint_hex_inrow(state->standard_result.keys.exchange_sk_reader, 32));
    PrintAndLogEx(INFO, "  ExpeditedSKDevice......... %s", sprint_hex_inrow(state->standard_result.keys.exchange_sk_device, 32));
    if (state->standard_result.keys.step_up_keys_present) {
        PrintAndLogEx(INFO, "  StepUpSKReader............ %s", sprint_hex_inrow(state->standard_result.keys.step_up_sk_reader, 32));
        PrintAndLogEx(INFO, "  StepUpSKDevice............ %s", sprint_hex_inrow(state->standard_result.keys.step_up_sk_device, 32));
    }
    PrintAndLogEx(INFO, "  BleSKReader............... %s", sprint_hex_inrow(state->standard_result.keys.ble_sk_reader, 32));
    PrintAndLogEx(INFO, "  BleSKDevice............... %s", sprint_hex_inrow(state->standard_result.keys.ble_sk_device, 32));
    PrintAndLogEx(INFO, "  URSK...................... %s", sprint_hex_inrow(state->standard_result.keys.ursk, 32));
    if (state->standard_result.keys.kpersistent_present) {
        PrintAndLogEx(INFO, "  Kpersistent (derived)..... " _YELLOW_("%s"), sprint_hex_inrow(state->standard_result.keys.kpersistent, 32));

        char reader_group_hex[33] = {0};
        char reader_sub_group_hex[33] = {0};
        char reader_priv_hex[65] = {0};
        char kpersistent_hex[65] = {0};
        char endpoint_pub_hex[131] = {0};
        hex_to_buffer((uint8_t *)reader_group_hex, reader_group_identifier, 16, sizeof(reader_group_hex) - 1, 0, 0, true);
        hex_to_buffer((uint8_t *)reader_sub_group_hex, reader_group_sub_identifier, 16, sizeof(reader_sub_group_hex) - 1, 0, 0, true);
        hex_to_buffer((uint8_t *)reader_priv_hex, reader_private_key_raw, 32, sizeof(reader_priv_hex) - 1, 0, 0, true);
        hex_to_buffer((uint8_t *)kpersistent_hex, state->standard_result.keys.kpersistent, 32, sizeof(kpersistent_hex) - 1, 0, 0, true);
        hex_to_buffer((uint8_t *)endpoint_pub_hex, state->auth1_parsed.endpoint_public_key, 65, sizeof(endpoint_pub_hex) - 1, 0, 0, true);

        char fast_cmd[768] = {0};
        int fast_cmd_len = snprintf(fast_cmd, sizeof(fast_cmd),
                                    "hf aliro read --reader-group-id %s --reader-sub-group-id %s "
                                    "--reader-private-key %s --key-persistent %s "
                                    "--endpoint-public-key %s --flow fast",
                                    reader_group_hex, reader_sub_group_hex,
                                    reader_priv_hex, kpersistent_hex, endpoint_pub_hex);
        if (fast_cmd_len > 0) {
            aliro_print_big_header("Note");
            PrintAndLogEx(INFO, _GREEN_("use the following command to perform FAST authentication flow for this endpoint:"));
            if ((size_t)fast_cmd_len < sizeof(fast_cmd)) {
                PrintAndLogEx(INFO, _YELLOW_("%s"), fast_cmd);
            }
        }
    }
}

static int aliro_read_auth_flow(const uint8_t *kpersistent, size_t kpersistent_len,
                                const uint8_t reader_group_identifier[16],
                                const uint8_t reader_group_sub_identifier[16],
                                const uint8_t reader_private_key_raw[32],
                                const uint8_t *transaction_identifier_in, size_t transaction_identifier_len,
                                const uint8_t *endpoint_public_key_x_in,
                                aliro_flow_t flow) {
    int status = PM3_ESOFT;
    aliro_rng_t rng;
    int res = aliro_rng_init(&rng);
    if (res != PM3_SUCCESS) {
        return res;
    }

    mbedtls_ecp_keypair reader_private_key;
    mbedtls_ecp_keypair reader_ephemeral_key;
    mbedtls_ecp_keypair_init(&reader_private_key);
    mbedtls_ecp_keypair_init(&reader_ephemeral_key);

    aliro_read_state_t state;
    memset(&state, 0, sizeof(state));

    do {
        res = aliro_read_prepare_session(&state,
                                         &reader_private_key,
                                         &reader_ephemeral_key,
                                         reader_group_identifier,
                                         reader_group_sub_identifier,
                                         reader_private_key_raw,
                                         transaction_identifier_in, transaction_identifier_len,
                                         &rng);
        if (res != PM3_SUCCESS) {
            break;
        }

        bool fast_flow_complete = false;
        res = aliro_read_do_auth0(&state,
                                  kpersistent, kpersistent_len,
                                  reader_group_identifier, reader_group_sub_identifier,
                                  endpoint_public_key_x_in,
                                  flow,
                                  &fast_flow_complete);
        if (res != PM3_SUCCESS) {
            break;
        }
        if (fast_flow_complete) {
            status = PM3_SUCCESS;
            break;
        }

        res = aliro_read_prepare_auth1_keys(&state, &reader_ephemeral_key, &rng);
        if (res != PM3_SUCCESS) {
            break;
        }

        res = aliro_read_do_auth1(&state, &reader_private_key);
        if (res != PM3_SUCCESS) {
            break;
        }

        aliro_read_print_auth1_report(&state,
                                      reader_group_identifier,
                                      reader_group_sub_identifier,
                                      reader_private_key_raw);
        status = PM3_SUCCESS;
    } while (0);

    DropField();
    mbedtls_ecp_keypair_free(&reader_ephemeral_key);
    mbedtls_ecp_keypair_free(&reader_private_key);
    aliro_rng_free(&rng);
    return status;
}

static int CmdHFAliroInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf aliro info",
                  "Select ALIRO applet and print capabilities.",
                  "hf aliro info\n"
                  "hf aliro info -a");

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
    int res = info_aliro();
    SetAPDULogging(restore_apdu_logging);
    return res;
}

static int CmdHFAliroRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf aliro read",
                  "Execute ALIRO expedited flow (SELECT-AUTH0-AUTH1).",
                  "hf aliro read --reader-group-id 00112233445566778899AABBCCDDEEFF --reader-sub-group-id 00112233445566778899AABBCCDDEEFF --reader-private-key 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF\n"
                  "hf aliro read --reader-group-id 00112233445566778899AABBCCDDEEFF --reader-private-key 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --transaction-id 00112233445566778899AABBCCDDEEFF --k-persistent 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --endpoint-public-key 04AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --flow fast -a\n"
                  "hf aliro read --reader-group-id 00112233445566778899AABBCCDDEEFF --reader-private-key 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF --ti 00112233445566778899AABBCCDDEEFF");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "k-persistent,key-persistent,kpersistent,keypersistent,kp", "<hex>", "Kpersistent (32 bytes, optional; used for fast cryptogram verification)"),
        arg_str1("g", "reader-group-id,readergroupid,rgi", "<hex>", "Reader group identifier (16 bytes)"),
        arg_str0("s", "reader-sub-group-id,readersubid,rsi", "<hex>", "Reader subgroup identifier (16 bytes, default: all zeroes)"),
        arg_str1("p", "reader-private-key,readerprivkey,rpk", "<hex>", "Reader private key (32 bytes, P-256)"),
        arg_str0("t", "transaction-id,ti", "<hex>", "Transaction identifier (16 bytes, optional; random if omitted)"),
        arg_str0("e", "endpoint-public-key,endpointpublickey,epk", "<hex>", "Endpoint public key for AUTH0 fast verification (32-byte X or 65-byte uncompressed)"),
        arg_str0("f", "flow", "<fast|standard>", "AUTH0 flow request (default: standard)"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t kpersistent[32] = {0};
    int kpersistent_len = 0;
    CLIGetHexWithReturn(ctx, 1, kpersistent, &kpersistent_len);

    uint8_t reader_group_identifier[16] = {0};
    int reader_group_identifier_len = 0;
    CLIGetHexWithReturn(ctx, 2, reader_group_identifier, &reader_group_identifier_len);

    uint8_t reader_group_sub_identifier[16] = {0};
    int reader_group_sub_identifier_len = 0;
    CLIGetHexWithReturn(ctx, 3, reader_group_sub_identifier, &reader_group_sub_identifier_len);

    uint8_t reader_private_key[32] = {0};
    int reader_private_key_len = 0;
    CLIGetHexWithReturn(ctx, 4, reader_private_key, &reader_private_key_len);

    uint8_t transaction_identifier[16] = {0};
    int transaction_identifier_len = 0;
    CLIGetHexWithReturn(ctx, 5, transaction_identifier, &transaction_identifier_len);

    uint8_t endpoint_public_key_input[65] = {0};
    int endpoint_public_key_input_len = 0;
    CLIGetHexWithReturn(ctx, 6, endpoint_public_key_input, &endpoint_public_key_input_len);

    aliro_flow_t flow = ALIRO_FLOW_STANDARD;
    CLIParserOption flow_options[] = {
        {ALIRO_FLOW_FAST, "fast"},
        {ALIRO_FLOW_STANDARD, "standard"},
        {0, NULL}
    };
    if (CLIGetOptionList(arg_get_str(ctx, 7), flow_options, (int *)&flow) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    bool apdu_logging = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    if (reader_group_identifier_len != 16) {
        PrintAndLogEx(ERR, "readergroupid must be 16 bytes (got %d)", reader_group_identifier_len);
        return PM3_EINVARG;
    }
    if (reader_group_sub_identifier_len != 0 && reader_group_sub_identifier_len != 16) {
        PrintAndLogEx(ERR, "readersubid must be 16 bytes (got %d)", reader_group_sub_identifier_len);
        return PM3_EINVARG;
    }
    if (reader_private_key_len != 32) {
        PrintAndLogEx(ERR, "readerprivkey must be 32 bytes (got %d)", reader_private_key_len);
        return PM3_EINVARG;
    }
    if (kpersistent_len != 0 && kpersistent_len != 32) {
        PrintAndLogEx(ERR, "kpersistent must be 32 bytes when provided (got %d)", kpersistent_len);
        return PM3_EINVARG;
    }
    if (transaction_identifier_len != 0 && transaction_identifier_len != 16) {
        PrintAndLogEx(ERR, "transaction-id must be 16 bytes when provided (got %d)", transaction_identifier_len);
        return PM3_EINVARG;
    }

    uint8_t endpoint_public_key_x[32] = {0};
    const uint8_t *endpoint_public_key_x_ptr = NULL;
    if (endpoint_public_key_input_len != 0) {
        if (endpoint_public_key_input_len == 32) {
            memcpy(endpoint_public_key_x, endpoint_public_key_input, sizeof(endpoint_public_key_x));
        } else if (endpoint_public_key_input_len == 65 && endpoint_public_key_input[0] == 0x04) {
            mbedtls_ecp_keypair endpoint_public_key;
            mbedtls_ecp_keypair_init(&endpoint_public_key);
            int key_res = aliro_load_public_key(endpoint_public_key_input, &endpoint_public_key);
            if (key_res == PM3_SUCCESS) {
                key_res = aliro_export_pubkey_x(&endpoint_public_key, endpoint_public_key_x);
            }
            mbedtls_ecp_keypair_free(&endpoint_public_key);
            if (key_res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "endpoint-public-key is not a valid uncompressed P-256 key");
                return PM3_EINVARG;
            }
        } else {
            PrintAndLogEx(ERR, "endpoint-public-key must be 32 bytes (X coordinate) or 65 bytes (uncompressed) (got %d)", endpoint_public_key_input_len);
            return PM3_EINVARG;
        }
        endpoint_public_key_x_ptr = endpoint_public_key_x;
    }

    bool restore_apdu_logging = GetAPDULogging();
    SetAPDULogging(apdu_logging);
    int res = aliro_read_auth_flow(kpersistent, (size_t)kpersistent_len,
                                   reader_group_identifier,
                                   reader_group_sub_identifier,
                                   reader_private_key,
                                   transaction_identifier, (size_t)transaction_identifier_len,
                                   endpoint_public_key_x_ptr,
                                   flow);
    SetAPDULogging(restore_apdu_logging);
    return res;
}

static int CmdHFAliroList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf aliro", "7816");
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,        AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",        CmdHelp,        AlwaysAvailable, "This help"},
    {"list",        CmdHFAliroList, AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"-----------", CmdHelp,        IfPm3Iso14443a,  "--------------------- " _CYAN_("Operations") " ----------------------"},
    {"info",        CmdHFAliroInfo, IfPm3Iso14443a,  "Get Aliro applet information"},
    {"read",        CmdHFAliroRead, IfPm3Iso14443a,  "Run SELECT-AUTH0-AUTH1 and print parsed data"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFAliro(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
