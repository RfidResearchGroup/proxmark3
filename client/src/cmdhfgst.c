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
// High frequency Google Smart Tap commands
//-----------------------------------------------------------------------------

#include "cmdhfgst.h"

#include <ctype.h>
#include <inttypes.h>
#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/ecdh.h>
#include <mbedtls/ecp.h>
#include <mbedtls/entropy.h>
#include <mbedtls/hkdf.h>
#include <mbedtls/md.h>
#include <mbedtls/ecc_point_compression.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#ifdef HAVE_ZLIB
#include <zlib.h>
#endif
#include "cliparser.h"
#include "cmdhf14a.h"
#include "cmdparser.h"
#include "cmdtrace.h"
#include "commonutil.h"
#include "comms.h"
#include "crypto/libpcrypto.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "iso7816/iso7816core.h"
#include "protocols.h"
#include "ui.h"
#include "util.h"
#include "util_posix.h"

#define GST_MAX_BUFFER 4096
#define GST_MAX_NDEF_BUFFER 2048
#define GST_MAX_NONCE_LEN 64
#define GST_MAX_SIGNATURE_LEN 96
#define GST_MAX_DECOMPRESSED_PAYLOAD (256 * 1024)
#define GST_MAX_PRIVATE_KEY_ARG 8192
#define GST_MAX_WALLET_TYPE_LEN 64
#define GST_MAX_FEATURES_LEN 16
#define GST_MAX_GET_DATA_CHAINED_RETRIES 10

static const uint8_t GST_OSE_AID[] = {'O', 'S', 'E', '.', 'V', 'A', 'S', '.', '0', '1'};
static const uint8_t GST_SMART_TAP_V2_AID[] = {0xA0, 0x00, 0x00, 0x04, 0x76, 0xD0, 0x00, 0x01, 0x11};

static const uint8_t GST_TYPE_HANDSET_NONCE[] = {'m', 'd', 'n'};
static const uint8_t GST_TYPE_SESSION[] = {'s', 'e', 's'};
static const uint8_t GST_TYPE_NEGOTIATE_REQUEST[] = {'n', 'g', 'r'};
static const uint8_t GST_TYPE_NEGOTIATE_RESPONSE[] = {'n', 'r', 's'};
static const uint8_t GST_TYPE_CRYPTO_PARAMS[] = {'c', 'p', 'r'};
static const uint8_t GST_TYPE_SIGNATURE[] = {'s', 'i', 'g'};
static const uint8_t GST_TYPE_SERVICE_REQUEST[] = {'s', 'r', 'q'};
static const uint8_t GST_TYPE_SERVICE_RESPONSE[] = {'s', 'r', 's'};
static const uint8_t GST_TYPE_MERCHANT[] = {'m', 'e', 'r'};
static const uint8_t GST_TYPE_COLLECTOR_ID[] = {'c', 'l', 'd'};
static const uint8_t GST_TYPE_SERVICE_LIST[] = {'s', 'l', 'r'};
static const uint8_t GST_TYPE_SERVICE_TYPE_REQUEST[] = {'s', 't', 'r'};
static const uint8_t GST_TYPE_POS_CAPABILITIES[] = {'p', 'c', 'r'};
static const uint8_t GST_TYPE_HANDSET_EPH_PUBKEY[] = {'d', 'p', 'k'};
static const uint8_t GST_TYPE_RECORD_BUNDLE[] = {'r', 'e', 'b'};
static const uint8_t GST_TYPE_SERVICE_VALUE[] = {'a', 's', 'v'};
static const uint8_t GST_TYPE_ISSUER[] = {'i'};
static const uint8_t GST_TYPE_CUSTOMER[] = {'c', 'u', 's'};
static const uint8_t GST_TYPE_CUSTOMER_ID[] = {'c', 'i', 'd'};
static const uint8_t GST_TYPE_CUSTOMER_LANGUAGE[] = {'c', 'p', 'l'};
static const uint8_t GST_TYPE_OBJECT_ID[] = {'o', 'i', 'd'};
static const uint8_t GST_TYPE_SERVICE_NUMBER[] = {'n'};
static const uint8_t GST_OBJECT_TYPE_EVENT[] = {'e', 't'};
static const uint8_t GST_OBJECT_TYPE_FLIGHT[] = {'f', 'l'};
static const uint8_t GST_OBJECT_TYPE_GIFT_CARD[] = {'g', 'c'};
static const uint8_t GST_OBJECT_TYPE_LOYALTY[] = {'l', 'y'};
static const uint8_t GST_OBJECT_TYPE_OFFER[] = {'o', 'f'};
static const uint8_t GST_OBJECT_TYPE_PRIVATE_LABEL_CARD[] = {'p', 'l'};
static const uint8_t GST_OBJECT_TYPE_TRANSIT[] = {'t', 'r'};
static const uint8_t GST_OBJECT_TYPE_GENERIC[] = {'g', 'r'};
static const uint8_t GST_OBJECT_TYPE_GENERIC_PRIVATE[] = {'g', 'p'};
static const uint8_t GST_RNG_PERSONALIZATION[] = "pm3-gst";

typedef enum {
    GST_MODE_PASS_ONLY = 0x01,
    GST_MODE_PAYMENT_ONLY = 0x02,
    GST_MODE_PASS_AND_PAYMENT = 0x04,
    GST_MODE_PASS_OVER_PAYMENT = 0x08,
} gst_mode_t;

typedef enum {
    GST_SYSTEM_ZLIB_SUPPORTED = 0x40,
} gst_system_flag_t;

typedef enum {
    GST_SELECT_AUTO = 0,
    GST_SELECT_YES = 1,
    GST_SELECT_NO = 2,
} gst_select_behavior_t;

typedef struct {
    bool have_wallet_type;
    uint8_t wallet_type[GST_MAX_WALLET_TYPE_LEN];
    size_t wallet_type_len;
    bool have_features;
    uint8_t features[GST_MAX_FEATURES_LEN];
    size_t features_len;
    bool have_capabilities;
    uint8_t capabilities;
    bool have_ose_device_nonce;
    uint8_t ose_device_nonce[GST_MAX_NONCE_LEN];
    size_t ose_device_nonce_len;
    bool have_min_version;
    uint8_t min_version[2];
    bool have_max_version;
    uint8_t max_version[2];
    bool have_directory_smart_tap_entry;
    bool have_directory_device_nonce;
    uint8_t directory_device_nonce[GST_MAX_NONCE_LEN];
    size_t directory_device_nonce_len;
} gst_ose_info_t;

typedef struct {
    bool have_min_version;
    uint8_t min_version[2];
    bool have_max_version;
    uint8_t max_version[2];
    bool have_handset_nonce;
    uint8_t handset_nonce[GST_MAX_NONCE_LEN];
    size_t handset_nonce_len;
} gst_select_info_t;

typedef struct {
    uint8_t tnf;
    const uint8_t *type;
    size_t type_len;
    const uint8_t *id;
    size_t id_len;
    const uint8_t *payload;
    size_t payload_len;
} gst_ndef_record_t;

typedef struct {
    bool mb;
    bool me;
    uint8_t tnf;
    const uint8_t *type;
    size_t type_len;
    const uint8_t *id;
    size_t id_len;
    const uint8_t *payload;
    size_t payload_len;
} gst_ndef_record_view_t;

typedef struct {
    uint32_t collector_id;
    uint32_t key_version;
    uint8_t reader_private_key[32];
    bool have_session_id;
    uint8_t session_id[8];
    bool have_reader_nonce;
    uint8_t reader_nonce[32];
    bool have_reader_ephemeral_private_key;
    uint8_t reader_ephemeral_private_key[32];
    gst_mode_t mode;
    gst_select_behavior_t select_behavior;
    bool live_authentication;
    bool apdu_logging;
    bool verbose;
} gst_read_config_t;

typedef struct {
    const uint8_t *type;
    size_t type_len;
    const char *name;
} gst_object_type_t;

static const gst_object_type_t gst_object_types[] = {
    {GST_OBJECT_TYPE_EVENT, sizeof(GST_OBJECT_TYPE_EVENT), "event"},
    {GST_OBJECT_TYPE_FLIGHT, sizeof(GST_OBJECT_TYPE_FLIGHT), "flight"},
    {GST_OBJECT_TYPE_GIFT_CARD, sizeof(GST_OBJECT_TYPE_GIFT_CARD), "gift_card"},
    {GST_OBJECT_TYPE_LOYALTY, sizeof(GST_OBJECT_TYPE_LOYALTY), "loyalty"},
    {GST_OBJECT_TYPE_OFFER, sizeof(GST_OBJECT_TYPE_OFFER), "offer"},
    {GST_OBJECT_TYPE_PRIVATE_LABEL_CARD, sizeof(GST_OBJECT_TYPE_PRIVATE_LABEL_CARD), "private_label_card"},
    {GST_OBJECT_TYPE_TRANSIT, sizeof(GST_OBJECT_TYPE_TRANSIT), "transit"},
    {GST_OBJECT_TYPE_GENERIC, sizeof(GST_OBJECT_TYPE_GENERIC), "generic"},
    {GST_OBJECT_TYPE_GENERIC_PRIVATE, sizeof(GST_OBJECT_TYPE_GENERIC_PRIVATE), "generic_private"},
};

static int CmdHelp(const char *Cmd);

static bool gst_wallet_type_is_android_pay(const uint8_t *wallet_type, size_t wallet_type_len) {
    static const uint8_t android_pay_wallet_type[] = "AndroidPay";
    return wallet_type != NULL
           && wallet_type_len == (sizeof(android_pay_wallet_type) - 1)
           && memcmp(wallet_type, android_pay_wallet_type, sizeof(android_pay_wallet_type) - 1) == 0;
}

static bool gst_wallet_type_is_apple_pay(const uint8_t *wallet_type, size_t wallet_type_len) {
    static const uint8_t apple_pay_wallet_type[] = "ApplePay";
    return wallet_type != NULL
           && wallet_type_len == (sizeof(apple_pay_wallet_type) - 1)
           && memcmp(wallet_type, apple_pay_wallet_type, sizeof(apple_pay_wallet_type) - 1) == 0;
}

static void gst_print_wallet_type_hint(const uint8_t *wallet_type, size_t wallet_type_len) {
    if (gst_wallet_type_is_apple_pay(wallet_type, wallet_type_len)) {
        PrintAndLogEx(INFO, "Hint: detected Apple VAS flavor of OSE.VAS.01. Try " _YELLOW_("hf vas") " commands.");
    }
}

static uint32_t gst_version_value(const uint8_t version[2]) {
    return ((uint32_t)version[0] << 8) | version[1];
}

static const char *gst_issuer_type_name(uint8_t issuer_type) {
    switch (issuer_type) {
        case 0x00:
            return "unspecified";
        case 0x01:
            return "merchant";
        case 0x02:
            return "wallet";
        case 0x03:
            return "manufacturer";
        default:
            return "unknown";
    }
}

static const char *gst_status_name(uint16_t sw) {
    switch (sw) {
        case 0x9000:
            return "OK";
        case 0x9001:
            return "OK_NO_PAYLOAD";
        case 0x9002:
            return "OK_PRE_SIGNED_AUTH";
        case 0x9100:
            return "OK_MORE_PAYLOAD";
        case 0x9201:
            return "CRYPTO_FAILURE";
        case 0x9203:
            return "EXECUTION_FAILURE";
        case 0x9300:
            return "DEVICE_LOCKED";
        case 0x9302:
            return "DISAMBIGUATION_SCREEN_SHOWN";
        case 0x9400:
            return "UNKNOWN_TERMINAL_COMMAND";
        case 0x9402:
            return "PARSING_FAILURE";
        case 0x9403:
            return "INVALID_CRYPTO_INPUT";
        case 0x9404:
            return "REQUEST_MORE_NOT_APPLICABLE";
        case 0x9405:
            return "MORE_DATA_NOT_AVAILABLE";
        case 0x9406:
            return "TOO_MANY_REQUESTS";
        case 0x9407:
            return "NO_MERCHANT_SET";
        case 0x9408:
            return "INVALID_PUSHBACK_URI";
        case 0x9500:
            return "AUTH_FAILED";
        case 0x9502:
            return "VERSION_NOT_SUPPORTED";
        default:
            break;
    }
    if ((sw >> 8) == 0x92) {
        return "UNKNOWN_TRANSIENT_FAILURE";
    }
    if ((sw >> 8) == 0x93) {
        return "UNKNOWN_USER_ACTION_NEEDED";
    }
    if ((sw >> 8) == 0x94) {
        return "UNKNOWN_TERMINAL_ERROR";
    }
    if ((sw >> 8) == 0x95) {
        return "UNKNOWN_PERMANENT_ERROR";
    }
    return "UNKNOWN";
}

static bool gst_status_is_success(uint16_t sw) {
    uint8_t sw1 = (uint8_t)(sw >> 8);
    return (sw1 == 0x90) || (sw1 == 0x91);
}

static bool gst_status_is_transient_failure(uint16_t sw) {
    return ((sw >> 8) == 0x92);
}

static void gst_print_status_line(const char *label, uint16_t sw) {
    PrintAndLogEx(INFO, "%s " _YELLOW_("%04X") " (%s)", label, sw, gst_status_name(sw));
}

static int gst_ndef_encode_message(const gst_ndef_record_t *records, size_t record_count,
                                   uint8_t *out, size_t out_size, size_t *out_len) {
    if (records == NULL || out == NULL || out_len == NULL || record_count == 0) {
        return PM3_EINVARG;
    }

    size_t offset = 0;
    for (size_t i = 0; i < record_count; i++) {
        const gst_ndef_record_t *rec = &records[i];
        if (rec->type == NULL || rec->type_len == 0 || rec->type_len > 255 || rec->id_len > 255) {
            return PM3_EINVARG;
        }

        bool short_record = (rec->payload_len <= 255);
        uint8_t header = (uint8_t)(rec->tnf & 0x07);
        if (i == 0) {
            header |= 0x80;
        }
        if (i == (record_count - 1)) {
            header |= 0x40;
        }
        if (short_record) {
            header |= 0x10;
        }
        if (rec->id_len > 0) {
            header |= 0x08;
        }

        if (buffer_append_bytes_with_offset(out, out_size, &offset, &header, 1) != PM3_SUCCESS) {
            return PM3_EOVFLOW;
        }

        uint8_t type_len_u8 = (uint8_t)rec->type_len;
        if (buffer_append_bytes_with_offset(out, out_size, &offset, &type_len_u8, 1) != PM3_SUCCESS) {
            return PM3_EOVFLOW;
        }

        if (short_record) {
            uint8_t payload_len_u8 = (uint8_t)rec->payload_len;
            if (buffer_append_bytes_with_offset(out, out_size, &offset, &payload_len_u8, 1) != PM3_SUCCESS) {
                return PM3_EOVFLOW;
            }
        } else {
            uint8_t payload_len_u32[4];
            payload_len_u32[0] = (uint8_t)(rec->payload_len >> 24);
            payload_len_u32[1] = (uint8_t)(rec->payload_len >> 16);
            payload_len_u32[2] = (uint8_t)(rec->payload_len >> 8);
            payload_len_u32[3] = (uint8_t)(rec->payload_len);
            if (buffer_append_bytes_with_offset(out, out_size, &offset, payload_len_u32, sizeof(payload_len_u32)) != PM3_SUCCESS) {
                return PM3_EOVFLOW;
            }
        }

        if (rec->id_len > 0) {
            uint8_t id_len_u8 = (uint8_t)rec->id_len;
            if (buffer_append_bytes_with_offset(out, out_size, &offset, &id_len_u8, 1) != PM3_SUCCESS) {
                return PM3_EOVFLOW;
            }
        }

        if (buffer_append_bytes_with_offset(out, out_size, &offset, rec->type, rec->type_len) != PM3_SUCCESS ||
                buffer_append_bytes_with_offset(out, out_size, &offset, rec->id, rec->id_len) != PM3_SUCCESS ||
                buffer_append_bytes_with_offset(out, out_size, &offset, rec->payload, rec->payload_len) != PM3_SUCCESS) {
            return PM3_EOVFLOW;
        }
    }

    *out_len = offset;
    return PM3_SUCCESS;
}

static int gst_ndef_parse_record(const uint8_t *message, size_t message_len, size_t *offset,
                                 gst_ndef_record_view_t *out) {
    if (message == NULL || offset == NULL || out == NULL || *offset >= message_len) {
        return PM3_EINVARG;
    }

    size_t pos = *offset;
    uint8_t header = message[pos++];
    bool short_record = (header & 0x10) != 0;
    bool id_len_present = (header & 0x08) != 0;
    bool chunked = (header & 0x20) != 0;
    if (chunked) {
        return PM3_ENOTIMPL;
    }

    if (pos >= message_len) {
        return PM3_ESOFT;
    }
    size_t type_len = message[pos++];

    size_t payload_len = 0;
    if (short_record) {
        if (pos >= message_len) {
            return PM3_ESOFT;
        }
        payload_len = message[pos++];
    } else {
        if ((pos + 4) > message_len) {
            return PM3_ESOFT;
        }
        payload_len = ((size_t)message[pos] << 24) |
                      ((size_t)message[pos + 1] << 16) |
                      ((size_t)message[pos + 2] << 8) |
                      ((size_t)message[pos + 3]);
        pos += 4;
    }

    size_t id_len = 0;
    if (id_len_present) {
        if (pos >= message_len) {
            return PM3_ESOFT;
        }
        id_len = message[pos++];
    }

    size_t required = type_len + id_len + payload_len;
    if ((pos + required) > message_len) {
        return PM3_ESOFT;
    }

    out->mb = (header & 0x80) != 0;
    out->me = (header & 0x40) != 0;
    out->tnf = (uint8_t)(header & 0x07);
    out->type = message + pos;
    out->type_len = type_len;
    pos += type_len;
    out->id = message + pos;
    out->id_len = id_len;
    pos += id_len;
    out->payload = message + pos;
    out->payload_len = payload_len;
    pos += payload_len;

    *offset = pos;
    return PM3_SUCCESS;
}

static bool gst_ndef_record_matches(const gst_ndef_record_view_t *record, const uint8_t *needle, size_t needle_len) {
    if (record == NULL || needle == NULL || needle_len == 0) {
        return false;
    }
    if (bytes_equal_not_null(record->type, record->type_len, needle, needle_len)) {
        return true;
    }
    return bytes_equal_not_null(record->id, record->id_len, needle, needle_len);
}

static int gst_ndef_find_by_type_or_id(const uint8_t *message, size_t message_len,
                                       const uint8_t *needle, size_t needle_len,
                                       gst_ndef_record_view_t *out_record) {
    if (message == NULL || needle == NULL || out_record == NULL) {
        return PM3_EINVARG;
    }

    size_t offset = 0;
    while (offset < message_len) {
        gst_ndef_record_view_t record;
        int res = gst_ndef_parse_record(message, message_len, &offset, &record);
        if (res != PM3_SUCCESS) {
            return res;
        }
        if (gst_ndef_record_matches(&record, needle, needle_len)) {
            *out_record = record;
            return PM3_SUCCESS;
        }
        if (record.me) {
            break;
        }
    }

    return PM3_ENODATA;
}

static int gst_exchange_chained(bool activate_field, bool leave_field_on,
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
        res = Iso7816ExchangeEx(CC_CONTACTLESS, false, leave_field_on, get_response, true, le,
                                chunk, sizeof(chunk), &chunk_len, sw);
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

static int gst_parse_ose_response(const uint8_t *buf, size_t len, gst_ose_info_t *info) {
    if (buf == NULL || info == NULL || len == 0) {
        return PM3_EINVARG;
    }

    memset(info, 0, sizeof(*info));

    const uint8_t *cursor = buf;
    size_t left = len;

    struct tlv top = {0};
    while (left > 0) {
        if (tlv_parse_tl(&cursor, &left, &top) == false || top.len > left) {
            return PM3_ESOFT;
        }

        const uint8_t *value = cursor;
        size_t value_len = top.len;
        cursor += top.len;
        left -= top.len;

        if (top.tag != 0x6F) {
            continue;
        }

        const uint8_t *fci_cursor = value;
        size_t fci_left = value_len;
        struct tlv fci_tlv = {0};
        while (fci_left > 0) {
            if (tlv_parse_tl(&fci_cursor, &fci_left, &fci_tlv) == false || fci_tlv.len > fci_left) {
                return PM3_ESOFT;
            }
            const uint8_t *fci_value = fci_cursor;
            size_t fci_value_len = fci_tlv.len;
            fci_cursor += fci_tlv.len;
            fci_left -= fci_tlv.len;

            if (fci_tlv.tag == 0x50 && fci_value_len > 0) {
                size_t wallet_type_len = MIN(fci_value_len, sizeof(info->wallet_type));
                memcpy(info->wallet_type, fci_value, wallet_type_len);
                info->wallet_type_len = wallet_type_len;
                info->have_wallet_type = true;
            } else if (fci_tlv.tag == 0xC1 && fci_value_len > 0) {
                size_t features_len = MIN(fci_value_len, sizeof(info->features));
                memcpy(info->features, fci_value, features_len);
                info->features_len = features_len;
                info->have_features = true;
            } else if (fci_tlv.tag == 0xC2 && fci_value_len > 0) {
                size_t nonce_len = MIN(fci_value_len, sizeof(info->ose_device_nonce));
                memcpy(info->ose_device_nonce, fci_value, nonce_len);
                info->ose_device_nonce_len = nonce_len;
                info->have_ose_device_nonce = true;
            } else if (fci_tlv.tag == 0xA5) {
                const uint8_t *a5_cursor = fci_value;
                size_t a5_left = fci_value_len;
                struct tlv a5_tlv = {0};
                while (a5_left > 0) {
                    if (tlv_parse_tl(&a5_cursor, &a5_left, &a5_tlv) == false || a5_tlv.len > a5_left) {
                        return PM3_ESOFT;
                    }
                    const uint8_t *a5_value = a5_cursor;
                    size_t a5_value_len = a5_tlv.len;
                    a5_cursor += a5_tlv.len;
                    a5_left -= a5_tlv.len;

                    if (a5_tlv.tag != 0xBF0C) {
                        continue;
                    }

                    const uint8_t *dir_cursor = a5_value;
                    size_t dir_left = a5_value_len;
                    struct tlv dir_tlv = {0};
                    while (dir_left > 0) {
                        if (tlv_parse_tl(&dir_cursor, &dir_left, &dir_tlv) == false || dir_tlv.len > dir_left) {
                            return PM3_ESOFT;
                        }
                        const uint8_t *dir_value = dir_cursor;
                        size_t dir_value_len = dir_tlv.len;
                        dir_cursor += dir_tlv.len;
                        dir_left -= dir_tlv.len;

                        if (dir_tlv.tag != 0x61) {
                            continue;
                        }

                        const uint8_t *entry_cursor = dir_value;
                        size_t entry_left = dir_value_len;
                        struct tlv entry_tlv = {0};
                        const uint8_t *entry_aid = NULL;
                        size_t entry_aid_len = 0;
                        const uint8_t *entry_discretionary = NULL;
                        size_t entry_discretionary_len = 0;

                        while (entry_left > 0) {
                            if (tlv_parse_tl(&entry_cursor, &entry_left, &entry_tlv) == false || entry_tlv.len > entry_left) {
                                return PM3_ESOFT;
                            }
                            const uint8_t *entry_value = entry_cursor;
                            size_t entry_value_len = entry_tlv.len;
                            entry_cursor += entry_tlv.len;
                            entry_left -= entry_tlv.len;

                            if (entry_tlv.tag == 0x4F) {
                                entry_aid = entry_value;
                                entry_aid_len = entry_value_len;
                            } else if (entry_tlv.tag == 0x73) {
                                entry_discretionary = entry_value;
                                entry_discretionary_len = entry_value_len;
                            }
                        }

                        if (entry_aid == NULL || entry_discretionary == NULL) {
                            continue;
                        }
                        if (!bytes_equal_not_null(entry_aid, entry_aid_len, GST_SMART_TAP_V2_AID, sizeof(GST_SMART_TAP_V2_AID))) {
                            continue;
                        }

                        info->have_directory_smart_tap_entry = true;

                        const uint8_t *disc_cursor = entry_discretionary;
                        size_t disc_left = entry_discretionary_len;
                        struct tlv disc_tlv = {0};
                        while (disc_left > 0) {
                            if (tlv_parse_tl(&disc_cursor, &disc_left, &disc_tlv) == false || disc_tlv.len > disc_left) {
                                return PM3_ESOFT;
                            }
                            const uint8_t *disc_value = disc_cursor;
                            size_t disc_value_len = disc_tlv.len;
                            disc_cursor += disc_tlv.len;
                            disc_left -= disc_tlv.len;

                            if (disc_tlv.tag == 0xDF6D && disc_value_len >= 2) {
                                info->have_min_version = true;
                                info->min_version[0] = disc_value[0];
                                info->min_version[1] = disc_value[1];
                            } else if (disc_tlv.tag == 0xDF4D && disc_value_len >= 2) {
                                info->have_max_version = true;
                                info->max_version[0] = disc_value[0];
                                info->max_version[1] = disc_value[1];
                            } else if (disc_tlv.tag == 0xDF6E && disc_value_len > 0) {
                                size_t nonce_len = MIN(disc_value_len, sizeof(info->directory_device_nonce));
                                memcpy(info->directory_device_nonce, disc_value, nonce_len);
                                info->directory_device_nonce_len = nonce_len;
                                info->have_directory_device_nonce = true;
                            } else if (disc_tlv.tag == 0xDF62 && disc_value_len >= 1) {
                                info->have_capabilities = true;
                                info->capabilities = disc_value[0];
                            }
                        }
                        break;
                    }
                }
            }
        }
        break;
    }

    return PM3_SUCCESS;
}

static int gst_parse_select_smart_tap_response(const uint8_t *buf, size_t len, gst_select_info_t *info) {
    if (buf == NULL || info == NULL || len < 4) {
        return PM3_EINVARG;
    }

    memset(info, 0, sizeof(*info));
    info->have_min_version = true;
    info->min_version[0] = buf[0];
    info->min_version[1] = buf[1];
    info->have_max_version = true;
    info->max_version[0] = buf[2];
    info->max_version[1] = buf[3];

    if (len == 4) {
        return PM3_SUCCESS;
    }

    const uint8_t *ndef = buf + 4;
    size_t ndef_len = len - 4;
    gst_ndef_record_view_t handset_nonce_record;
    int res = gst_ndef_find_by_type_or_id(ndef, ndef_len,
                                          GST_TYPE_HANDSET_NONCE, sizeof(GST_TYPE_HANDSET_NONCE),
                                          &handset_nonce_record);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (handset_nonce_record.payload_len < 1) {
        return PM3_ESOFT;
    }

    size_t nonce_len = handset_nonce_record.payload_len - 1;
    nonce_len = MIN(nonce_len, sizeof(info->handset_nonce));
    memcpy(info->handset_nonce, handset_nonce_record.payload + 1, nonce_len);
    info->handset_nonce_len = nonce_len;
    info->have_handset_nonce = true;
    return PM3_SUCCESS;
}

static void gst_print_version_line(const char *label, bool have, const uint8_t version[2]) {
    if (have) {
        PrintAndLogEx(INFO, "%s " _YELLOW_("%" PRIu32 " (%u.%u)"),
                      label,
                      gst_version_value(version),
                      version[1], version[0]);
    } else {
        PrintAndLogEx(INFO, "%s not present", label);
    }
}

static void gst_print_feature_bit(const char *bits, uint8_t mask, uint8_t bit,
                                  const char *enabled, const char *disabled) {
    const bool is_enabled = (mask & (1U << bit)) != 0;
    const int pad = 7 - bit;
    PrintAndLogEx(INFO, "   %s",
                  sprint_breakdown_bin(is_enabled ? C_GREEN : C_NONE, bits, 8, pad, 1,
                                       is_enabled ? enabled : disabled));
}

static void gst_print_feature_bit_nested(const char *bits, uint8_t mask, uint8_t bit,
                                         const char *enabled, const char *disabled) {
    const bool is_enabled = (mask & (1U << bit)) != 0;
    const int pad = 7 - bit;
    PrintAndLogEx(INFO, "   %s",
                  sprint_breakdown_bin(is_enabled ? C_GREEN : C_NONE, bits, 8, pad, 1,
                                       is_enabled ? enabled : disabled));
}

static void gst_print_ose_transaction_mode(uint8_t mask) {
    const char *bits = sprint_bin(&mask, 1);
    PrintAndLogEx(INFO, "  Transaction mode........ " _YELLOW_("%s") " (" _YELLOW_("0x%02X") ")", bits, mask);
    gst_print_feature_bit_nested(bits, mask, 7, "Payment enabled", "Payment enabled not set");
    gst_print_feature_bit_nested(bits, mask, 6, "Payment requested", "Payment requested not set");
    gst_print_feature_bit_nested(bits, mask, 5, "Reserved/unknown bit set", "Reserved/unknown bit clear");
    gst_print_feature_bit_nested(bits, mask, 4, "Reserved/unknown bit set", "Reserved/unknown bit clear");
    gst_print_feature_bit_nested(bits, mask, 3, "Pass enabled", "Pass enabled not set");
    gst_print_feature_bit_nested(bits, mask, 2, "Pass requested", "Pass requested not set");
    gst_print_feature_bit_nested(bits, mask, 1, "Reserved/unknown bit set", "Reserved/unknown bit clear");
    gst_print_feature_bit_nested(bits, mask, 0, "Reserved/unknown bit set", "Reserved/unknown bit clear");
}

static void gst_print_ose_capabilities(uint8_t mask) {
    const char *bits = sprint_bin(&mask, 1);
    PrintAndLogEx(INFO, "Capabilities (DF62)....... " _YELLOW_("%s") " (" _YELLOW_("0x%02X") ")", bits, mask);
    gst_print_feature_bit(bits, mask, 1, "VAS support advertised", "VAS support not advertised");
    gst_print_feature_bit(bits, mask, 0, "Skipping second select allowed", "Skipping second select not allowed");
}

static void gst_print_bundle_flags(uint8_t mask) {
    const char *bits = sprint_bin(&mask, 1);
    PrintAndLogEx(INFO, "Bundle flags.............. " _YELLOW_("%s") " (" _YELLOW_("0x%02X") ")", bits, mask);
    gst_print_feature_bit(bits, mask, 1, "Payload compressed", "Payload not compressed");
    gst_print_feature_bit(bits, mask, 0, "Payload encrypted", "Payload not encrypted");

    const uint8_t reserved = (uint8_t)(mask & 0xFC);
    if (reserved != 0) {
        PrintAndLogEx(WARNING, "Reserved bundle bits....... " _YELLOW_("0x%02X"), reserved);
    }
}

static void gst_print_ose_info(const gst_ose_info_t *info) {
    if (info == NULL) {
        return;
    }

    PrintAndLogInfoHeader("OSE Information (6F)");
    bool skip_gst_details = false;
    if (info->have_wallet_type) {
        PrintAndLogEx(INFO, "Wallet type............... " _YELLOW_("%s"),
                      sprint_ascii(info->wallet_type, info->wallet_type_len));
        if (gst_wallet_type_is_android_pay(info->wallet_type, info->wallet_type_len) == false) {
            PrintAndLogEx(WARNING, "Wallet type is not AndroidPay. This likely isn't Google Smart Tap.");
            gst_print_wallet_type_hint(info->wallet_type, info->wallet_type_len);
            skip_gst_details = true;
        }
    } else {
        PrintAndLogEx(WARNING, "Wallet type............... " _YELLOW_("not present"));
    }
    if (skip_gst_details) {
        return;
    }

    if (info->have_features) {
        PrintAndLogEx(INFO, "Features (C1)............. " _YELLOW_("%s"),
                      sprint_hex_inrow(info->features, info->features_len));
        gst_print_ose_transaction_mode(info->features[0]);
    } else {
        PrintAndLogEx(INFO, "Features (C1)............. not present");
    }
    if (info->have_capabilities) {
        gst_print_ose_capabilities(info->capabilities);
    } else {
        PrintAndLogEx(INFO, "Capabilities.............. not present");
    }
    gst_print_version_line("Minimum version...........", info->have_min_version, info->min_version);
    gst_print_version_line("Maximum version...........", info->have_max_version, info->max_version);

    if (info->have_ose_device_nonce) {
        PrintAndLogEx(INFO, "Device nonce (C2)......... " _YELLOW_("%s"),
                      sprint_hex_inrow(info->ose_device_nonce, info->ose_device_nonce_len));
    } else {
        PrintAndLogEx(INFO, "Device nonce (C2)......... not present");
    }

    if (info->have_directory_device_nonce) {
        PrintAndLogEx(INFO, "Device nonce (DF6E)....... " _YELLOW_("%s"),
                      sprint_hex_inrow(info->directory_device_nonce, info->directory_device_nonce_len));
    } else {
        PrintAndLogEx(INFO, "Device nonce (DF6E)....... not present");
    }
}

static void gst_print_select_info(const gst_select_info_t *info) {
    if (info == NULL) {
        return;
    }
    PrintAndLogInfoHeader("Smart Tap applet information");
    gst_print_version_line("Minimum version...........", info->have_min_version, info->min_version);
    gst_print_version_line("Maximum version...........", info->have_max_version, info->max_version);
    if (info->have_handset_nonce) {
        PrintAndLogEx(INFO, "Handset nonce............. " _YELLOW_("%s"),
                      sprint_hex_inrow(info->handset_nonce, info->handset_nonce_len));
    } else {
        PrintAndLogEx(INFO, "Handset nonce............. not present");
    }
}

static bool gst_should_select_smart_tap(gst_select_behavior_t behavior, const gst_ose_info_t *ose_info) {
    if (behavior == GST_SELECT_YES) {
        return true;
    }
    if (behavior == GST_SELECT_NO) {
        return false;
    }

    if (ose_info != NULL && ose_info->have_wallet_type &&
            gst_wallet_type_is_android_pay(ose_info->wallet_type, ose_info->wallet_type_len) == false) {
        return false;
    }

    bool allow_skip = (ose_info != NULL && ose_info->have_capabilities && (ose_info->capabilities & 0x01) != 0);
    bool have_device_nonce = false;
    if (ose_info != NULL) {
        have_device_nonce = ose_info->have_directory_device_nonce || ose_info->have_ose_device_nonce;
    }
    return (!allow_skip || !have_device_nonce);
}

static int gst_select_ose(gst_ose_info_t *info, bool activate_field, bool keep_field_on) {
    uint8_t response[GST_MAX_BUFFER] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;

    int res = gst_exchange_chained(activate_field, keep_field_on, 0x00, ISO7816_SELECT_FILE, 0x04, 0x00,
                                   GST_OSE_AID, sizeof(GST_OSE_AID),
                                   response, sizeof(response), &response_len, &sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "SELECT OSE exchange error");
        return res;
    }
    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "OSE.VAS.01 not found. APDU response: %04x - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");
        }
        return PM3_ESOFT;
    }

    return gst_parse_ose_response(response, response_len, info);
}

static int gst_select_smart_tap_v2(gst_select_info_t *info, bool keep_field_on) {
    uint8_t response[GST_MAX_BUFFER] = {0};
    size_t response_len = 0;
    uint16_t sw = 0;

    int res = gst_exchange_chained(false, keep_field_on, 0x00, ISO7816_SELECT_FILE, 0x04, 0x00,
                                   GST_SMART_TAP_V2_AID, sizeof(GST_SMART_TAP_V2_AID),
                                   response, sizeof(response), &response_len, &sw);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "SELECT Smart Tap v2 exchange error");
        return res;
    }
    if (sw != ISO7816_OK) {
        if (sw) {
            PrintAndLogEx(INFO, "Smart Tap v2 applet not found. APDU response: %04x - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000");
        }
        return PM3_ESOFT;
    }

    return gst_parse_select_smart_tap_response(response, response_len, info);
}

static int gst_load_private_key_raw(const uint8_t private_key_bytes[32], mbedtls_ecp_keypair *keypair, pcrypto_rng_t *rng) {
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

static int gst_generate_ephemeral_keypair(mbedtls_ecp_keypair *keypair, pcrypto_rng_t *rng) {
    if (keypair == NULL || rng == NULL || rng->seeded == false) {
        return PM3_EINVARG;
    }
    mbedtls_ecp_keypair_init(keypair);
    return (mbedtls_ecp_gen_key(MBEDTLS_ECP_DP_SECP256R1, keypair, mbedtls_ctr_drbg_random, &rng->ctr_drbg) == 0)
           ? PM3_SUCCESS : PM3_ESOFT;
}

static int gst_export_pubkey_uncompressed(const mbedtls_ecp_keypair *keypair, uint8_t out[65]) {
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

static int gst_export_pubkey_compressed(const mbedtls_ecp_keypair *keypair, uint8_t out[33]) {
    if (keypair == NULL || out == NULL) {
        return PM3_EINVARG;
    }
    size_t written = 0;
    int ret = mbedtls_ecp_point_write_binary(&keypair->grp, &keypair->Q,
                                             MBEDTLS_ECP_PF_COMPRESSED, &written, out, 33);
    if (ret != 0 || written != 33) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int gst_load_public_key_any(const uint8_t *pubkey, size_t pubkey_len, mbedtls_ecp_keypair *keypair) {
    if (pubkey == NULL || keypair == NULL) {
        return PM3_EINVARG;
    }
    if (pubkey_len != 33 && pubkey_len != 65) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair_init(keypair);
    int ret = mbedtls_ecp_group_load(&keypair->grp, MBEDTLS_ECP_DP_SECP256R1);
    if (ret != 0) {
        return PM3_ESOFT;
    }

    uint8_t uncompressed[65] = {0};
    const uint8_t *to_read = pubkey;
    size_t to_read_len = pubkey_len;

    if (pubkey_len == 33) {
        size_t uncompressed_len = 0;
        if (mbedtls_ecp_decompress(&keypair->grp, pubkey, pubkey_len, uncompressed, &uncompressed_len, sizeof(uncompressed)) != 0 ||
                uncompressed_len != sizeof(uncompressed)) {
            return PM3_ESOFT;
        }
        to_read = uncompressed;
        to_read_len = sizeof(uncompressed);
    }

    ret = mbedtls_ecp_point_read_binary(&keypair->grp, &keypair->Q, to_read, to_read_len);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    ret = mbedtls_ecp_check_pubkey(&keypair->grp, &keypair->Q);
    if (ret != 0) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int gst_build_signature_input(const uint8_t reader_nonce[32],
                                     const uint8_t *device_nonce, size_t device_nonce_len,
                                     uint32_t collector_id,
                                     const uint8_t reader_ephemeral_public_key[33],
                                     uint8_t *out, size_t out_size, size_t *out_len) {
    if (reader_nonce == NULL || device_nonce == NULL || reader_ephemeral_public_key == NULL ||
            out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }

    size_t offset = 0;
    uint8_t collector_id_be[4];
    Uint4byteToMemBe(collector_id_be, collector_id);

    if (buffer_append_bytes_with_offset(out, out_size, &offset, reader_nonce, 32) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(out, out_size, &offset, device_nonce, device_nonce_len) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(out, out_size, &offset, collector_id_be, sizeof(collector_id_be)) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(out, out_size, &offset, reader_ephemeral_public_key, 33) != PM3_SUCCESS) {
        return PM3_EOVFLOW;
    }

    *out_len = offset;
    return PM3_SUCCESS;
}

static int gst_create_reader_signature(const uint8_t reader_private_key[32],
                                       const uint8_t reader_public_key[65],
                                       const uint8_t *signature_input,
                                       size_t signature_input_len,
                                       uint8_t *signature,
                                       size_t *signature_len) {
    if (reader_private_key == NULL || reader_public_key == NULL || signature_input == NULL ||
            signature == NULL || signature_len == NULL) {
        return PM3_EINVARG;
    }

    int res = ecdsa_signature_create(MBEDTLS_ECP_DP_SECP256R1,
                                     (uint8_t *)reader_private_key,
                                     (uint8_t *)reader_public_key,
                                     (uint8_t *)signature_input,
                                     (int)signature_input_len,
                                     signature, signature_len, true);
    return (res == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

static int gst_build_session_payload(uint64_t session_id, uint8_t sequence_number, uint8_t status,
                                     uint8_t out[10], size_t *out_len) {
    if (out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }
    Uint8byteToMemBe(out, session_id);
    out[8] = sequence_number;
    out[9] = status;
    *out_len = 10;
    return PM3_SUCCESS;
}

static int gst_build_negotiate_message(const uint8_t reader_nonce[32],
                                       const uint8_t reader_ephemeral_public_key[33],
                                       const uint8_t *signature, size_t signature_len,
                                       uint32_t collector_id,
                                       uint32_t key_version,
                                       uint64_t session_id,
                                       uint8_t sequence_number,
                                       bool live_authentication,
                                       uint8_t *out, size_t out_size, size_t *out_len) {
    if (reader_nonce == NULL || reader_ephemeral_public_key == NULL || signature == NULL ||
            out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }

    uint8_t session_payload[10] = {0};
    size_t session_payload_len = 0;
    int res = gst_build_session_payload(session_id, sequence_number, 0x01, session_payload, &session_payload_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t collector_id_be[4];
    Uint4byteToMemBe(collector_id_be, collector_id);

    uint8_t signature_record_payload[GST_MAX_SIGNATURE_LEN + 1] = {0};
    size_t signature_record_payload_len = 0;
    signature_record_payload[0] = 0x04;
    signature_record_payload_len = 1;
    if (buffer_append_bytes_with_offset(signature_record_payload, sizeof(signature_record_payload), &signature_record_payload_len, signature, signature_len) != PM3_SUCCESS) {
        return PM3_EOVFLOW;
    }

    uint8_t collector_record_payload[5] = {0x04, 0, 0, 0, 0};
    memcpy(collector_record_payload + 1, collector_id_be, 4);

    uint8_t nested_signature_msg[GST_MAX_NDEF_BUFFER] = {0};
    size_t nested_signature_msg_len = 0;
    gst_ndef_record_t nested_signature_records[] = {
        {0x04, GST_TYPE_SIGNATURE, sizeof(GST_TYPE_SIGNATURE), NULL, 0, signature_record_payload, signature_record_payload_len},
        {0x04, GST_TYPE_COLLECTOR_ID, sizeof(GST_TYPE_COLLECTOR_ID), NULL, 0, collector_record_payload, sizeof(collector_record_payload)},
    };
    res = gst_ndef_encode_message(nested_signature_records, ARRAYLEN(nested_signature_records),
                                  nested_signature_msg, sizeof(nested_signature_msg), &nested_signature_msg_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t cpr_payload[GST_MAX_NDEF_BUFFER] = {0};
    size_t cpr_payload_len = 0;
    uint8_t key_version_be[4];
    Uint4byteToMemBe(key_version_be, key_version);
    uint8_t live_auth = live_authentication ? 0x01 : 0x00;

    if (buffer_append_bytes_with_offset(cpr_payload, sizeof(cpr_payload), &cpr_payload_len, reader_nonce, 32) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(cpr_payload, sizeof(cpr_payload), &cpr_payload_len, &live_auth, 1) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(cpr_payload, sizeof(cpr_payload), &cpr_payload_len, reader_ephemeral_public_key, 33) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(cpr_payload, sizeof(cpr_payload), &cpr_payload_len, key_version_be, sizeof(key_version_be)) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(cpr_payload, sizeof(cpr_payload), &cpr_payload_len, nested_signature_msg, nested_signature_msg_len) != PM3_SUCCESS) {
        return PM3_EOVFLOW;
    }

    uint8_t nested_negotiate_msg[GST_MAX_NDEF_BUFFER] = {0};
    size_t nested_negotiate_msg_len = 0;
    gst_ndef_record_t nested_negotiate_records[] = {
        {0x04, GST_TYPE_SESSION, sizeof(GST_TYPE_SESSION), NULL, 0, session_payload, session_payload_len},
        {0x04, GST_TYPE_CRYPTO_PARAMS, sizeof(GST_TYPE_CRYPTO_PARAMS), NULL, 0, cpr_payload, cpr_payload_len},
    };
    res = gst_ndef_encode_message(nested_negotiate_records, ARRAYLEN(nested_negotiate_records),
                                  nested_negotiate_msg, sizeof(nested_negotiate_msg), &nested_negotiate_msg_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t outer_payload[GST_MAX_NDEF_BUFFER] = {0};
    size_t outer_payload_len = 0;
    const uint8_t version[2] = {0x00, 0x01};
    if (buffer_append_bytes_with_offset(outer_payload, sizeof(outer_payload), &outer_payload_len, version, sizeof(version)) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(outer_payload, sizeof(outer_payload), &outer_payload_len, nested_negotiate_msg, nested_negotiate_msg_len) != PM3_SUCCESS) {
        return PM3_EOVFLOW;
    }

    gst_ndef_record_t outer_record = {
        .tnf = 0x04,
        .type = GST_TYPE_NEGOTIATE_REQUEST,
        .type_len = sizeof(GST_TYPE_NEGOTIATE_REQUEST),
        .id = NULL,
        .id_len = 0,
        .payload = outer_payload,
        .payload_len = outer_payload_len
    };

    return gst_ndef_encode_message(&outer_record, 1, out, out_size, out_len);
}

static int gst_build_get_data_message(uint32_t collector_id,
                                      uint64_t session_id,
                                      uint8_t sequence_number,
                                      gst_mode_t mode,
                                      uint8_t system_flags,
                                      uint8_t ui_flags,
                                      uint8_t checkout_flags,
                                      uint8_t cvm_flags,
                                      uint8_t *out, size_t out_size, size_t *out_len) {
    if (out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }

    uint8_t session_payload[10] = {0};
    size_t session_payload_len = 0;
    int res = gst_build_session_payload(session_id, sequence_number, 0x01, session_payload, &session_payload_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t collector_id_be[4];
    Uint4byteToMemBe(collector_id_be, collector_id);
    uint8_t collector_record_payload[5] = {0x04, 0, 0, 0, 0};
    memcpy(collector_record_payload + 1, collector_id_be, 4);

    uint8_t merchant_payload[GST_MAX_NDEF_BUFFER] = {0};
    size_t merchant_payload_len = 0;
    gst_ndef_record_t merchant_nested[] = {
        {0x04, GST_TYPE_COLLECTOR_ID, sizeof(GST_TYPE_COLLECTOR_ID), NULL, 0, collector_record_payload, sizeof(collector_record_payload)},
    };
    res = gst_ndef_encode_message(merchant_nested, ARRAYLEN(merchant_nested),
                                  merchant_payload, sizeof(merchant_payload), &merchant_payload_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t service_type_payload[] = {0x00};
    uint8_t service_list_payload[GST_MAX_NDEF_BUFFER] = {0};
    size_t service_list_payload_len = 0;
    gst_ndef_record_t service_list_nested[] = {
        {0x04, GST_TYPE_SERVICE_TYPE_REQUEST, sizeof(GST_TYPE_SERVICE_TYPE_REQUEST), NULL, 0, service_type_payload, sizeof(service_type_payload)},
    };
    res = gst_ndef_encode_message(service_list_nested, ARRAYLEN(service_list_nested),
                                  service_list_payload, sizeof(service_list_payload), &service_list_payload_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t pos_capabilities_payload[5] = {
        system_flags,
        ui_flags,
        checkout_flags,
        cvm_flags,
        (uint8_t)mode
    };

    uint8_t nested_request[GST_MAX_NDEF_BUFFER] = {0};
    size_t nested_request_len = 0;
    gst_ndef_record_t request_records[] = {
        {0x04, GST_TYPE_SESSION, sizeof(GST_TYPE_SESSION), NULL, 0, session_payload, session_payload_len},
        {0x04, GST_TYPE_MERCHANT, sizeof(GST_TYPE_MERCHANT), NULL, 0, merchant_payload, merchant_payload_len},
        {0x04, GST_TYPE_SERVICE_LIST, sizeof(GST_TYPE_SERVICE_LIST), NULL, 0, service_list_payload, service_list_payload_len},
        {0x04, GST_TYPE_POS_CAPABILITIES, sizeof(GST_TYPE_POS_CAPABILITIES), NULL, 0, pos_capabilities_payload, sizeof(pos_capabilities_payload)},
    };
    res = gst_ndef_encode_message(request_records, ARRAYLEN(request_records),
                                  nested_request, sizeof(nested_request), &nested_request_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t outer_payload[GST_MAX_NDEF_BUFFER] = {0};
    size_t outer_payload_len = 0;
    const uint8_t version[2] = {0x00, 0x01};
    if (buffer_append_bytes_with_offset(outer_payload, sizeof(outer_payload), &outer_payload_len, version, sizeof(version)) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(outer_payload, sizeof(outer_payload), &outer_payload_len, nested_request, nested_request_len) != PM3_SUCCESS) {
        return PM3_EOVFLOW;
    }

    gst_ndef_record_t outer_record = {
        .tnf = 0x04,
        .type = GST_TYPE_SERVICE_REQUEST,
        .type_len = sizeof(GST_TYPE_SERVICE_REQUEST),
        .id = NULL,
        .id_len = 0,
        .payload = outer_payload,
        .payload_len = outer_payload_len
    };
    return gst_ndef_encode_message(&outer_record, 1, out, out_size, out_len);
}

static int gst_perform_get_data(uint32_t collector_id,
                                uint64_t session_id,
                                uint8_t sequence_number,
                                gst_mode_t mode,
                                uint8_t *out, size_t out_max_len,
                                size_t *out_len, uint16_t *sw) {
    if (out == NULL || out_len == NULL || sw == NULL) {
        return PM3_EINVARG;
    }

    uint8_t command_data[GST_MAX_NDEF_BUFFER] = {0};
    size_t command_data_len = 0;
    uint8_t system_flags = 0x00;
#ifdef HAVE_ZLIB
    system_flags |= GST_SYSTEM_ZLIB_SUPPORTED;
#endif

    int res = gst_build_get_data_message(collector_id, session_id, sequence_number, mode,
                                         system_flags, 0x00, 0x00, 0x00,
                                         command_data, sizeof(command_data), &command_data_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    size_t total = 0;
    uint16_t local_sw = 0;
    uint8_t response_chunk[GST_MAX_BUFFER] = {0};
    size_t response_chunk_len = 0;

    res = gst_exchange_chained(false, true, 0x90, 0x50, 0x00, 0x00,
                               command_data, command_data_len,
                               response_chunk, sizeof(response_chunk), &response_chunk_len, &local_sw);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if ((total + response_chunk_len) > out_max_len) {
        return PM3_EOVFLOW;
    }
    memcpy(out + total, response_chunk, response_chunk_len);
    total += response_chunk_len;

    for (uint8_t get_data_retry_count = 0; local_sw == 0x9100; get_data_retry_count++) {
        if (get_data_retry_count >= GST_MAX_GET_DATA_CHAINED_RETRIES) {
            PrintAndLogEx(ERR, "GET DATA returned chained response too many times (max=%" PRIu8 ")", GST_MAX_GET_DATA_CHAINED_RETRIES);
            return PM3_ETIMEOUT;
        }
        response_chunk_len = 0;
        res = gst_exchange_chained(false, true, 0x90, 0xC0, 0x00, 0x00,
                                   NULL, 0,
                                   response_chunk, sizeof(response_chunk), &response_chunk_len, &local_sw);
        if (res != PM3_SUCCESS) {
            return res;
        }
        if ((total + response_chunk_len) > out_max_len) {
            return PM3_EOVFLOW;
        }
        memcpy(out + total, response_chunk, response_chunk_len);
        total += response_chunk_len;
    }

    *out_len = total;
    *sw = local_sw;
    return PM3_SUCCESS;
}

static int gst_decrypt_payload(const uint8_t *encrypted_payload, size_t encrypted_payload_len,
                               uint32_t collector_id,
                               const uint8_t reader_nonce[32],
                               const uint8_t *device_nonce, size_t device_nonce_len,
                               const uint8_t *signature, size_t signature_len,
                               const mbedtls_ecp_keypair *reader_ephemeral_key,
                               const uint8_t reader_ephemeral_public_key[33],
                               const uint8_t *device_ephemeral_public_key, size_t device_ephemeral_public_key_len,
                               uint8_t *out, size_t out_max_len, size_t *out_len) {
    if (encrypted_payload == NULL || reader_nonce == NULL || device_nonce == NULL || signature == NULL ||
            reader_ephemeral_key == NULL || reader_ephemeral_public_key == NULL ||
            device_ephemeral_public_key == NULL || out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }
    if (encrypted_payload_len < 44) {
        return PM3_ESOFT;
    }

    const uint8_t *iv = encrypted_payload;
    const uint8_t *ciphertext = encrypted_payload + 12;
    size_t ciphertext_len = encrypted_payload_len - 12 - 32;
    const uint8_t *hmac = encrypted_payload + encrypted_payload_len - 32;

    mbedtls_ecp_keypair device_public_key;
    mbedtls_ecp_keypair_init(&device_public_key);
    int res = gst_load_public_key_any(device_ephemeral_public_key, device_ephemeral_public_key_len, &device_public_key);
    if (res != PM3_SUCCESS) {
        mbedtls_ecp_keypair_free(&device_public_key);
        return res;
    }

    mbedtls_mpi shared_secret;
    mbedtls_mpi_init(&shared_secret);
    int mres = mbedtls_ecdh_compute_shared((mbedtls_ecp_group *)&reader_ephemeral_key->grp,
                                           &shared_secret,
                                           &device_public_key.Q,
                                           (mbedtls_mpi *)&reader_ephemeral_key->d,
                                           NULL, NULL);
    mbedtls_ecp_keypair_free(&device_public_key);
    if (mres != 0) {
        mbedtls_mpi_free(&shared_secret);
        return PM3_ESOFT;
    }

    uint8_t shared_secret_bytes[32] = {0};
    mres = mbedtls_mpi_write_binary(&shared_secret, shared_secret_bytes, sizeof(shared_secret_bytes));
    mbedtls_mpi_free(&shared_secret);
    if (mres != 0) {
        return PM3_ESOFT;
    }

    uint8_t collector_id_be[4];
    Uint4byteToMemBe(collector_id_be, collector_id);

    uint8_t kdf_info[GST_MAX_BUFFER] = {0};
    size_t kdf_info_len = 0;
    if (buffer_append_bytes_with_offset(kdf_info, sizeof(kdf_info), &kdf_info_len, reader_nonce, 32) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(kdf_info, sizeof(kdf_info), &kdf_info_len, device_nonce, device_nonce_len) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(kdf_info, sizeof(kdf_info), &kdf_info_len, collector_id_be, sizeof(collector_id_be)) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(kdf_info, sizeof(kdf_info), &kdf_info_len, reader_ephemeral_public_key, 33) != PM3_SUCCESS ||
            buffer_append_bytes_with_offset(kdf_info, sizeof(kdf_info), &kdf_info_len, signature, signature_len) != PM3_SUCCESS) {
        return PM3_EOVFLOW;
    }

    uint8_t key_material[48] = {0};
    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(MBEDTLS_MD_SHA256);
    if (md_info == NULL) {
        return PM3_ESOFT;
    }
    mres = mbedtls_hkdf(md_info,
                        device_ephemeral_public_key, device_ephemeral_public_key_len,
                        shared_secret_bytes, sizeof(shared_secret_bytes),
                        kdf_info, kdf_info_len,
                        key_material, sizeof(key_material));
    if (mres != 0) {
        return PM3_ESOFT;
    }

    const uint8_t *aes_key = key_material;
    const uint8_t *hmac_key = key_material + 16;

    uint8_t derived_hmac[32] = {0};
    mbedtls_md_context_t md_ctx;
    mbedtls_md_init(&md_ctx);
    mres = mbedtls_md_setup(&md_ctx, md_info, 1);
    if (mres == 0) {
        mres = mbedtls_md_hmac_starts(&md_ctx, hmac_key, 32);
    }
    if (mres == 0) {
        mres = mbedtls_md_hmac_update(&md_ctx, iv, 12);
    }
    if (mres == 0) {
        mres = mbedtls_md_hmac_update(&md_ctx, ciphertext, ciphertext_len);
    }
    if (mres == 0) {
        mres = mbedtls_md_hmac_finish(&md_ctx, derived_hmac);
    }
    mbedtls_md_free(&md_ctx);
    if (mres != 0) {
        return PM3_ESOFT;
    }
    if (memcmp(derived_hmac, hmac, sizeof(derived_hmac)) != 0) {
        PrintAndLogEx(ERR, "HMAC verification failed");
        return PM3_ESOFT;
    }

    if (ciphertext_len > out_max_len) {
        return PM3_EOVFLOW;
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    mres = mbedtls_aes_setkey_enc(&aes, aes_key, 128);
    if (mres != 0) {
        mbedtls_aes_free(&aes);
        return PM3_ESOFT;
    }

    uint8_t nonce_counter[16] = {0};
    memcpy(nonce_counter, iv, 12);
    uint8_t stream_block[16] = {0};
    size_t nc_off = 0;
    mres = mbedtls_aes_crypt_ctr(&aes, ciphertext_len, &nc_off, nonce_counter, stream_block, ciphertext, out);
    mbedtls_aes_free(&aes);
    if (mres != 0) {
        return PM3_ESOFT;
    }

    *out_len = ciphertext_len;
    return PM3_SUCCESS;
}

#ifdef HAVE_ZLIB
static int gst_decompress_payload_zlib(const uint8_t *compressed_payload, size_t compressed_payload_len,
                                       uint8_t **out, size_t *out_len) {
    if (compressed_payload == NULL || out == NULL || out_len == NULL) {
        return PM3_EINVARG;
    }

    *out = NULL;
    *out_len = 0;

    if (compressed_payload_len == 0) {
        return PM3_SUCCESS;
    }

    size_t capacity = compressed_payload_len * 2;
    if (capacity < 1024) {
        capacity = 1024;
    }
    if (capacity > GST_MAX_DECOMPRESSED_PAYLOAD) {
        capacity = GST_MAX_DECOMPRESSED_PAYLOAD;
    }

    uint8_t *buffer = calloc(capacity, sizeof(uint8_t));
    if (buffer == NULL) {
        return PM3_EMALLOC;
    }

    z_stream stream;
    memset(&stream, 0, sizeof(stream));
    stream.next_in = (Bytef *)compressed_payload;
    stream.avail_in = (uInt)compressed_payload_len;
    stream.next_out = buffer;
    stream.avail_out = (uInt)capacity;

    int zret = inflateInit(&stream);
    if (zret != Z_OK) {
        free(buffer);
        return PM3_ESOFT;
    }

    int status = PM3_SUCCESS;
    while (true) {
        zret = inflate(&stream, Z_NO_FLUSH);
        if (zret == Z_STREAM_END) {
            break;
        }
        if (!(zret == Z_OK || zret == Z_BUF_ERROR)) {
            status = PM3_ESOFT;
            break;
        }

        if (stream.avail_out > 0) {
            // We have spare output space but no progress/end marker: input stream is invalid/truncated.
            if (stream.avail_in == 0 || zret == Z_BUF_ERROR) {
                status = PM3_ESOFT;
                break;
            }
            continue;
        }

        size_t produced = (size_t)(stream.next_out - buffer);
        if (capacity >= GST_MAX_DECOMPRESSED_PAYLOAD) {
            status = PM3_EOVFLOW;
            break;
        }

        size_t new_capacity = capacity * 2;
        if (new_capacity > GST_MAX_DECOMPRESSED_PAYLOAD) {
            new_capacity = GST_MAX_DECOMPRESSED_PAYLOAD;
        }

        uint8_t *new_buffer = realloc(buffer, new_capacity);
        if (new_buffer == NULL) {
            status = PM3_EMALLOC;
            break;
        }

        buffer = new_buffer;
        capacity = new_capacity;
        stream.next_out = buffer + produced;
        stream.avail_out = (uInt)(capacity - produced);
    }

    inflateEnd(&stream);

    if (status != PM3_SUCCESS) {
        free(buffer);
        return status;
    }

    *out = buffer;
    *out_len = (size_t)(stream.next_out - buffer);
    return PM3_SUCCESS;
}
#endif

static int gst_selftest_zlib(void) {
#ifdef HAVE_ZLIB
    // Captured from a compressed RECORD_BUNDLE payload produced by Google's demo pass.
    static const uint8_t compressed_payload[] = {
        0x78, 0xDA, 0x5D, 0xD4, 0xBD, 0x4A, 0x03, 0x41, 0x18, 0x85, 0xE1, 0xDD,
        0xEC, 0x22, 0x58, 0x6A, 0x67, 0x99, 0xD4, 0x0A, 0xF9, 0x7E, 0xA2, 0xC6,
        0xDA, 0x26, 0x76, 0xE2, 0x56, 0x82, 0x4A, 0x48, 0x02, 0x46, 0x82, 0x1A,
        0x93, 0x08, 0x41, 0xEC, 0x2C, 0x2D, 0x2C, 0x82, 0x8D, 0xE0, 0x05, 0x88,
        0xB5, 0xD7, 0xA0, 0x77, 0x21, 0xDE, 0x87, 0xE0, 0xA2, 0xCC, 0xD9, 0x39,
        0x4E, 0xB5, 0xF3, 0xEE, 0x34, 0x0F, 0xF3, 0x73, 0x97, 0x25, 0x49, 0xFE,
        0xDE, 0x9D, 0x5C, 0x2F, 0xD2, 0xA5, 0x61, 0x9E, 0x26, 0xE5, 0xD8, 0xAD,
        0x95, 0xE9, 0x6D, 0x34, 0x5F, 0x64, 0xCB, 0x17, 0xC3, 0x7E, 0x5E, 0xFF,
        0xD8, 0xDB, 0x4F, 0xBF, 0x8E, 0x5F, 0x3A, 0xE5, 0xCF, 0xFC, 0x39, 0x2D,
        0xCE, 0x93, 0x9B, 0x46, 0xBF, 0x3B, 0xED, 0x6E, 0x34, 0x1B, 0x3B, 0xBF,
        0x1F, 0x27, 0xA7, 0x83, 0xAB, 0x41, 0xB3, 0xB1, 0xFE, 0x57, 0x25, 0xAE,
        0x12, 0xAA, 0xC6, 0x55, 0x43, 0xB5, 0xB8, 0x5A, 0xA8, 0x1E, 0x57, 0x0F,
        0xB5, 0x15, 0xD7, 0x56, 0xA8, 0x9B, 0x71, 0xDD, 0x0C, 0x75, 0x2B, 0xAE,
        0x5B, 0xA1, 0x6E, 0xC7, 0x75, 0x3B, 0xD4, 0x76, 0x5C, 0xDB, 0x50, 0x10,
        0x4E, 0x2A, 0x1D, 0xF3, 0xE0, 0x13, 0x02, 0x0A, 0x84, 0x42, 0x44, 0x81,
        0x51, 0x08, 0x29, 0x50, 0x0A, 0x31, 0x05, 0x4E, 0x21, 0xA8, 0x40, 0x2A,
        0x44, 0x15, 0x58, 0x85, 0xB0, 0x02, 0xAD, 0x10, 0x57, 0xE0, 0x55, 0xF2,
        0x2A, 0xBC, 0x4A, 0x5E, 0xAD, 0xF6, 0x93, 0x37, 0x14, 0x5E, 0x25, 0xAF,
        0xC2, 0xAB, 0xE4, 0x55, 0x78, 0x95, 0xBC, 0x0A, 0xAF, 0x92, 0x57, 0xE1,
        0x55, 0xF2, 0x2A, 0xBC, 0x4A, 0x5E, 0x85, 0x57, 0xC9, 0xAB, 0xF0, 0x1A,
        0x79, 0x0D, 0x5E, 0x23, 0xAF, 0xC1, 0x6B, 0xE4, 0xB5, 0xEA, 0x04, 0xF3,
        0x11, 0x86, 0xD7, 0xC8, 0x6B, 0xF0, 0x1A, 0x79, 0x0D, 0x5E, 0x23, 0xAF,
        0xC1, 0x6B, 0xE4, 0x35, 0x78, 0x8D, 0xBC, 0x06, 0xAF, 0x91, 0xD7, 0xE0,
        0x75, 0xF2, 0x3A, 0xBC, 0x4E, 0x5E, 0x87, 0xD7, 0xC9, 0xEB, 0xF0, 0x3A,
        0x79, 0xBD, 0xBA, 0xB3, 0x7C, 0x69, 0xE1, 0x75, 0xF2, 0x3A, 0xBC, 0x4E,
        0x5E, 0x87, 0xD7, 0xC9, 0xEB, 0xF0, 0x3A, 0x79, 0x1D, 0x5E, 0x27, 0x6F,
        0x39, 0xBB, 0x2D, 0xB2, 0x4E, 0x78, 0xCD, 0x6A, 0xE3, 0xF9, 0x7C, 0x5C,
        0x64, 0xED, 0xDE, 0x6C, 0xB2, 0xC8, 0x56, 0x7A, 0xE5, 0x5B, 0x96, 0xFC,
        0x1B, 0x6B, 0x69, 0x96, 0x15, 0xBD, 0xCB, 0x51, 0x32, 0x38, 0x2F, 0xCA,
        0x15, 0xB3, 0x69, 0x7E, 0x7F, 0x74, 0xF8, 0x50, 0x7F, 0x3C, 0x58, 0xFD,
        0x1E, 0x7C, 0x8E, 0xC6, 0x67, 0x4F, 0xAF, 0x3F, 0xF7, 0x6A, 0x82, 0x30,
    };
    static const uint8_t loyalty_object_id[] = {0x04, 0x21, 0xC9, 0x4A, 0x51, 0x01, 0xE2, 0x5E, 0xAA};
    static const uint8_t customer_id[] = {0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                                          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    static const size_t sample_decompressed_len = 1312;
    static const size_t service_value_record_1_len = 1224;
    static const size_t loyalty_record_len = 1206;
    static const size_t service_value_record_2_len = 73;
    static const size_t customer_record_len = 57;

    uint8_t *decompressed_payload = NULL;
    size_t decompressed_payload_len = 0;
    int res = gst_decompress_payload_zlib(compressed_payload, sizeof(compressed_payload),
                                          &decompressed_payload, &decompressed_payload_len);
    bool inflate_ok = (res == PM3_SUCCESS) && (decompressed_payload_len == sample_decompressed_len);
    PrintAndLogEx(INFO, "zlib sample inflate... ( %s )", inflate_ok ? _GREEN_("ok") : _RED_("fail"));

    bool parse_ok = false;
    // Check that inflation worked properly by validating inner data
    if (inflate_ok) {
        size_t offset = 0;
        gst_ndef_record_view_t first_record;
        gst_ndef_record_view_t second_record;
        gst_ndef_record_view_t loyalty_record;
        gst_ndef_record_view_t object_id_record;
        gst_ndef_record_view_t customer_record;
        gst_ndef_record_view_t customer_id_record;

        res = gst_ndef_parse_record(decompressed_payload, decompressed_payload_len, &offset, &first_record);
        if (res == PM3_SUCCESS &&
                bytes_equal_not_null(first_record.type, first_record.type_len,
                                     GST_TYPE_SERVICE_VALUE, sizeof(GST_TYPE_SERVICE_VALUE)) &&
                first_record.payload_len == service_value_record_1_len) {
            res = gst_ndef_find_by_type_or_id(first_record.payload, first_record.payload_len,
                                              GST_OBJECT_TYPE_LOYALTY, sizeof(GST_OBJECT_TYPE_LOYALTY),
                                              &loyalty_record);
        }
        if (res == PM3_SUCCESS && loyalty_record.payload_len == loyalty_record_len) {
            res = gst_ndef_find_by_type_or_id(loyalty_record.payload, loyalty_record.payload_len,
                                              GST_TYPE_OBJECT_ID, sizeof(GST_TYPE_OBJECT_ID),
                                              &object_id_record);
        }
        if (res == PM3_SUCCESS &&
                bytes_equal_not_null(object_id_record.payload, object_id_record.payload_len,
                                     loyalty_object_id, sizeof(loyalty_object_id))) {
            res = gst_ndef_parse_record(decompressed_payload, decompressed_payload_len, &offset, &second_record);
        }
        if (res == PM3_SUCCESS &&
                bytes_equal_not_null(second_record.type, second_record.type_len,
                                     GST_TYPE_SERVICE_VALUE, sizeof(GST_TYPE_SERVICE_VALUE)) &&
                second_record.payload_len == service_value_record_2_len) {
            res = gst_ndef_find_by_type_or_id(second_record.payload, second_record.payload_len,
                                              GST_TYPE_CUSTOMER, sizeof(GST_TYPE_CUSTOMER),
                                              &customer_record);
        }
        if (res == PM3_SUCCESS && customer_record.payload_len == customer_record_len) {
            res = gst_ndef_find_by_type_or_id(customer_record.payload, customer_record.payload_len,
                                              GST_TYPE_CUSTOMER_ID, sizeof(GST_TYPE_CUSTOMER_ID),
                                              &customer_id_record);
        }
        parse_ok = (res == PM3_SUCCESS) &&
                   bytes_equal_not_null(customer_id_record.payload, customer_id_record.payload_len,
                                        customer_id, sizeof(customer_id));
    }
    PrintAndLogEx(INFO, "zlib sample parse.... ( %s )", parse_ok ? _GREEN_("ok") : _RED_("fail"));

    free(decompressed_payload);

    return (inflate_ok && parse_ok) ? PM3_SUCCESS : PM3_ESOFT;
#else
    PrintAndLogEx(INFO, "zlib support......... ( %s )", _YELLOW_("unsupported"));
    return PM3_ENOTIMPL;
#endif
}

static void gst_print_formatted_payload(const char *label, const uint8_t *payload, size_t payload_len) {
    if (payload == NULL || payload_len == 0) {
        PrintAndLogEx(INFO, "%s <empty>", label);
        return;
    }

    uint8_t format = payload[0];
    const uint8_t *value = payload + 1;
    size_t value_len = payload_len - 1;

    if (is_printable_ascii(value, value_len)) {
        PrintAndLogEx(INFO, "%s \"%.*s\" (fmt=0x%02X, ASCII)", label, (int)value_len, (const char *)value, format);
    } else {
        PrintAndLogEx(INFO, "%s %s (fmt=0x%02X)", label, sprint_hex_inrow(value, value_len), format);
    }
}

static const char *gst_get_object_name(const uint8_t *type, size_t type_len) {
    for (size_t i = 0; i < ARRAYLEN(gst_object_types); i++) {
        if (bytes_equal_not_null(type, type_len, gst_object_types[i].type, gst_object_types[i].type_len)) {
            return gst_object_types[i].name;
        }
    }
    return NULL;
}

static void gst_print_service_objects(const uint8_t *message, size_t message_len) {
    size_t offset = 0;
    size_t object_count = 0;

    while (offset < message_len) {
        gst_ndef_record_view_t top_record;
        int res = gst_ndef_parse_record(message, message_len, &offset, &top_record);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Failed to parse top-level NDEF record (err=%d)", res);
            break;
        }

        if (!bytes_equal_not_null(top_record.type, top_record.type_len, GST_TYPE_SERVICE_VALUE, sizeof(GST_TYPE_SERVICE_VALUE))) {
            if (top_record.me) {
                break;
            }
            continue;
        }

        gst_ndef_record_view_t issuer_record;
        res = gst_ndef_find_by_type_or_id(top_record.payload, top_record.payload_len,
                                          GST_TYPE_ISSUER, sizeof(GST_TYPE_ISSUER),
                                          &issuer_record);
        if (res != PM3_SUCCESS || issuer_record.payload_len < 2) {
            PrintAndLogEx(WARNING, "Service value record without valid issuer field");
            if (top_record.me) {
                break;
            }
            continue;
        }

        uint8_t issuer_type = issuer_record.payload[1];
        const uint8_t *issuer_id = issuer_record.payload + 2;
        size_t issuer_id_len = issuer_record.payload_len - 2;

        size_t nested_offset = 0;
        while (nested_offset < top_record.payload_len) {
            gst_ndef_record_view_t nested;
            res = gst_ndef_parse_record(top_record.payload, top_record.payload_len, &nested_offset, &nested);
            if (res != PM3_SUCCESS) {
                break;
            }

            bool is_customer = bytes_equal_not_null(nested.type, nested.type_len, GST_TYPE_CUSTOMER, sizeof(GST_TYPE_CUSTOMER));
            const char *object_name = gst_get_object_name(nested.type, nested.type_len);
            if (!is_customer && object_name == NULL) {
                if (nested.me) {
                    break;
                }
                continue;
            }

            object_count++;
            if (object_count > 1) {
                PrintAndLogEx(INFO, "");
            }
            PrintAndLogEx(INFO, _CYAN_("Object #%" PRIuPTR), (uintptr_t)object_count);
            PrintAndLogEx(INFO, "  kind.................... %s", is_customer ? "customer" : object_name);
            PrintAndLogEx(INFO, "  issuer_type............. %s (0x%02X)", gst_issuer_type_name(issuer_type), issuer_type);
            PrintAndLogEx(INFO, "  issuer_id............... %s", sprint_hex_inrow(issuer_id, issuer_id_len));

            if (is_customer) {
                gst_ndef_record_view_t customer_id_record;
                gst_ndef_record_view_t language_record;
                if (gst_ndef_find_by_type_or_id(nested.payload, nested.payload_len,
                                                GST_TYPE_CUSTOMER_ID, sizeof(GST_TYPE_CUSTOMER_ID),
                                                &customer_id_record) == PM3_SUCCESS) {
                    PrintAndLogEx(INFO, "  customer_id............. %s",
                                  sprint_hex_inrow(customer_id_record.payload, customer_id_record.payload_len));
                }
                if (gst_ndef_find_by_type_or_id(nested.payload, nested.payload_len,
                                                GST_TYPE_CUSTOMER_LANGUAGE, sizeof(GST_TYPE_CUSTOMER_LANGUAGE),
                                                &language_record) == PM3_SUCCESS) {
                    gst_print_formatted_payload("  language................", language_record.payload, language_record.payload_len);
                }
            } else {
                gst_ndef_record_view_t object_id_record;
                gst_ndef_record_view_t service_number_record;
                if (gst_ndef_find_by_type_or_id(nested.payload, nested.payload_len,
                                                GST_TYPE_OBJECT_ID, sizeof(GST_TYPE_OBJECT_ID),
                                                &object_id_record) == PM3_SUCCESS) {
                    PrintAndLogEx(INFO, "  object_id............... %s",
                                  sprint_hex_inrow(object_id_record.payload, object_id_record.payload_len));
                }
                if (gst_ndef_find_by_type_or_id(nested.payload, nested.payload_len,
                                                GST_TYPE_SERVICE_NUMBER, sizeof(GST_TYPE_SERVICE_NUMBER),
                                                &service_number_record) == PM3_SUCCESS) {
                    gst_print_formatted_payload("  service_number..........", service_number_record.payload, service_number_record.payload_len);
                }
            }

            if (nested.me) {
                break;
            }
        }

        if (top_record.me) {
            break;
        }
    }

    if (object_count == 0) {
        PrintAndLogEx(INFO, "(no service objects found)");
    }
}

static int gst_parse_negotiate_response(const uint8_t *response_data, size_t response_len,
                                        uint8_t *negotiate_sequence,
                                        uint8_t *device_ephemeral_public_key, size_t *device_ephemeral_public_key_len) {
    if (response_data == NULL || negotiate_sequence == NULL || device_ephemeral_public_key == NULL ||
            device_ephemeral_public_key_len == NULL) {
        return PM3_EINVARG;
    }

    gst_ndef_record_view_t negotiate_record;
    int res = gst_ndef_find_by_type_or_id(response_data, response_len,
                                          GST_TYPE_NEGOTIATE_RESPONSE, sizeof(GST_TYPE_NEGOTIATE_RESPONSE),
                                          &negotiate_record);
    if (res != PM3_SUCCESS) {
        return res;
    }

    gst_ndef_record_view_t dpk_record;
    res = gst_ndef_find_by_type_or_id(negotiate_record.payload, negotiate_record.payload_len,
                                      GST_TYPE_HANDSET_EPH_PUBKEY, sizeof(GST_TYPE_HANDSET_EPH_PUBKEY),
                                      &dpk_record);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (dpk_record.payload_len != 33 && dpk_record.payload_len != 65) {
        return PM3_ESOFT;
    }
    memcpy(device_ephemeral_public_key, dpk_record.payload, dpk_record.payload_len);
    *device_ephemeral_public_key_len = dpk_record.payload_len;

    gst_ndef_record_view_t session_record;
    res = gst_ndef_find_by_type_or_id(negotiate_record.payload, negotiate_record.payload_len,
                                      GST_TYPE_SESSION, sizeof(GST_TYPE_SESSION),
                                      &session_record);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (session_record.payload_len < 9) {
        return PM3_ESOFT;
    }

    *negotiate_sequence = session_record.payload[8];
    return PM3_SUCCESS;
}

static int gst_extract_record_bundle(const uint8_t *response_data, size_t response_len,
                                     uint8_t *flags,
                                     const uint8_t **bundle_payload, size_t *bundle_payload_len) {
    if (response_data == NULL || flags == NULL || bundle_payload == NULL || bundle_payload_len == NULL) {
        return PM3_EINVARG;
    }

    gst_ndef_record_view_t service_response_record;
    int res = gst_ndef_find_by_type_or_id(response_data, response_len,
                                          GST_TYPE_SERVICE_RESPONSE, sizeof(GST_TYPE_SERVICE_RESPONSE),
                                          &service_response_record);
    if (res != PM3_SUCCESS) {
        return res;
    }

    gst_ndef_record_view_t record_bundle_record;
    res = gst_ndef_find_by_type_or_id(service_response_record.payload, service_response_record.payload_len,
                                      GST_TYPE_RECORD_BUNDLE, sizeof(GST_TYPE_RECORD_BUNDLE),
                                      &record_bundle_record);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (record_bundle_record.payload_len < 1) {
        return PM3_ESOFT;
    }

    *flags = record_bundle_record.payload[0];
    *bundle_payload = record_bundle_record.payload + 1;
    *bundle_payload_len = record_bundle_record.payload_len - 1;
    return PM3_SUCCESS;
}

static int gst_info(gst_select_behavior_t select_behavior) {
    gst_ose_info_t ose_info;
    int res = gst_select_ose(&ose_info, true, true);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    PrintAndLogEx(INFO, "");
    gst_print_ose_info(&ose_info);

    bool should_select = gst_should_select_smart_tap(select_behavior, &ose_info);
    if (should_select) {
        gst_select_info_t select_info;
        res = gst_select_smart_tap_v2(&select_info, true);
        if (res != PM3_SUCCESS) {
            DropField();
            return res;
        }
        PrintAndLogEx(INFO, "");
        gst_print_select_info(&select_info);
    }

    PrintAndLogEx(INFO, "");
    DropField();
    return PM3_SUCCESS;
}

static int gst_read(const gst_read_config_t *cfg) {
    if (cfg == NULL) {
        return PM3_EINVARG;
    }

    int status = PM3_ESOFT;
    pcrypto_rng_t rng;

    mbedtls_ecp_keypair longterm_key;
    mbedtls_ecp_keypair reader_ephemeral_key;
    mbedtls_ecp_keypair_init(&longterm_key);
    mbedtls_ecp_keypair_init(&reader_ephemeral_key);

    uint8_t longterm_public_key[65] = {0};
    uint8_t reader_ephemeral_public_key[33] = {0};
    uint8_t reader_nonce[32] = {0};
    uint8_t session_id_be[8] = {0};
    uint64_t session_id = 0;
    uint8_t reader_signature[GST_MAX_SIGNATURE_LEN] = {0};
    size_t reader_signature_len = sizeof(reader_signature);

    uint8_t device_nonce[GST_MAX_NONCE_LEN] = {0};
    size_t device_nonce_len = 0;

    uint8_t device_ephemeral_public_key[65] = {0};
    size_t device_ephemeral_public_key_len = 0;

    uint8_t negotiate_response[GST_MAX_BUFFER] = {0};
    size_t negotiate_response_len = 0;
    uint16_t negotiate_sw = 0;

    uint8_t get_data_response[GST_MAX_BUFFER] = {0};
    size_t get_data_response_len = 0;
    uint16_t get_data_sw = 0;

    uint8_t decrypted_payload[GST_MAX_BUFFER] = {0};
    size_t decrypted_payload_len = 0;
#ifdef HAVE_ZLIB
    uint8_t *decompressed_payload = NULL;
    size_t decompressed_payload_len = 0;
#endif

    uint8_t negotiate_cmd[GST_MAX_NDEF_BUFFER] = {0};
    size_t negotiate_cmd_len = 0;

    status = pcrypto_rng_init(&rng, GST_RNG_PERSONALIZATION, sizeof(GST_RNG_PERSONALIZATION) - 1);
    if (status != PM3_SUCCESS) {
        goto out;
    }

    status = gst_load_private_key_raw(cfg->reader_private_key, &longterm_key, &rng);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Invalid reader private key");
        goto out;
    }

    status = gst_export_pubkey_uncompressed(&longterm_key, longterm_public_key);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to export reader public key");
        goto out;
    }

    if (cfg->have_reader_ephemeral_private_key) {
        status = gst_load_private_key_raw(cfg->reader_ephemeral_private_key, &reader_ephemeral_key, &rng);
    } else {
        status = gst_generate_ephemeral_keypair(&reader_ephemeral_key, &rng);
    }
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to prepare reader ephemeral key");
        goto out;
    }

    status = gst_export_pubkey_compressed(&reader_ephemeral_key, reader_ephemeral_public_key);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to export reader ephemeral public key");
        goto out;
    }

    if (cfg->have_reader_nonce) {
        memcpy(reader_nonce, cfg->reader_nonce, sizeof(reader_nonce));
    } else {
        status = pcrypto_rng_fill(&rng, reader_nonce, sizeof(reader_nonce));
        if (status != PM3_SUCCESS) {
            goto out;
        }
    }

    if (cfg->have_session_id) {
        memcpy(session_id_be, cfg->session_id, sizeof(session_id_be));
    } else {
        status = pcrypto_rng_fill(&rng, session_id_be, sizeof(session_id_be));
        if (status != PM3_SUCCESS) {
            goto out;
        }
    }
    session_id = MemBeToUint8byte(session_id_be);

    gst_ose_info_t ose_info;
    status = gst_select_ose(&ose_info, false, true);
    if (status != PM3_SUCCESS) {
        goto out;
    }

    const bool wallet_type_is_android_pay = ose_info.have_wallet_type &&
                                            gst_wallet_type_is_android_pay(ose_info.wallet_type, ose_info.wallet_type_len);
    const bool wallet_type_is_known_non_android = ose_info.have_wallet_type && !wallet_type_is_android_pay;

    if (cfg->verbose) {
        PrintAndLogEx(INFO, "");
        gst_print_ose_info(&ose_info);
    } else if (!wallet_type_is_android_pay) {
        const char *wallet_type = ose_info.have_wallet_type
                                  ? sprint_ascii(ose_info.wallet_type, ose_info.wallet_type_len)
                                  : "not present";
        PrintAndLogEx(WARNING, "Wallet type............... " _YELLOW_("%s"), wallet_type);
        PrintAndLogEx(ERR, "Wallet type is not AndroidPay. This likely isn't Google Smart Tap.");
        gst_print_wallet_type_hint(ose_info.wallet_type, ose_info.wallet_type_len);
    }

    bool should_select = gst_should_select_smart_tap(cfg->select_behavior, &ose_info);
    if (should_select) {
        gst_select_info_t select_info;
        status = gst_select_smart_tap_v2(&select_info, true);
        if (status != PM3_SUCCESS) {
            goto out;
        }
        PrintAndLogEx(INFO, "");
        gst_print_select_info(&select_info);
        if (select_info.have_handset_nonce) {
            memcpy(device_nonce, select_info.handset_nonce, select_info.handset_nonce_len);
            device_nonce_len = select_info.handset_nonce_len;
        }
    }

    if (device_nonce_len == 0) {
        if (ose_info.have_directory_device_nonce) {
            memcpy(device_nonce, ose_info.directory_device_nonce, ose_info.directory_device_nonce_len);
            device_nonce_len = ose_info.directory_device_nonce_len;
        } else if (ose_info.have_ose_device_nonce) {
            memcpy(device_nonce, ose_info.ose_device_nonce, ose_info.ose_device_nonce_len);
            device_nonce_len = ose_info.ose_device_nonce_len;
        }
    }
    if (device_nonce_len == 0) {
        if (wallet_type_is_known_non_android) {
            status = PM3_ESOFT;
            goto out;
        }
        PrintAndLogEx(ERR, "Could not obtain handset/device nonce");
        status = PM3_ESOFT;
        goto out;
    }

    uint8_t auth_device_nonce[GST_MAX_NONCE_LEN] = {0};
    memcpy(auth_device_nonce, device_nonce, device_nonce_len);
    if (!cfg->live_authentication) {
        memset(auth_device_nonce, 0, device_nonce_len);
    }

    uint8_t signature_input[GST_MAX_BUFFER] = {0};
    size_t signature_input_len = 0;
    status = gst_build_signature_input(reader_nonce,
                                       auth_device_nonce, device_nonce_len,
                                       cfg->collector_id,
                                       reader_ephemeral_public_key,
                                       signature_input, sizeof(signature_input), &signature_input_len);
    if (status != PM3_SUCCESS) {
        goto out;
    }

    status = gst_create_reader_signature(cfg->reader_private_key, longterm_public_key,
                                         signature_input, signature_input_len,
                                         reader_signature, &reader_signature_len);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to create reader signature");
        goto out;
    }

    if (cfg->verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogInfoHeader("Negotiate secure channel");
        PrintAndLogEx(INFO, "Collector ID.............. %" PRIu32 " (0x%08" PRIX32 ")", cfg->collector_id, cfg->collector_id);
        PrintAndLogEx(INFO, "Long-term key version..... %" PRIu32 " (0x%08" PRIX32 ")", cfg->key_version, cfg->key_version);
        PrintAndLogEx(INFO, "Session ID................ " _YELLOW_("%s"), sprint_hex_inrow(session_id_be, sizeof(session_id_be)));
        PrintAndLogEx(INFO, "Reader nonce.............. " _YELLOW_("%s"), sprint_hex_inrow(reader_nonce, sizeof(reader_nonce)));
        PrintAndLogEx(INFO, "Device nonce.............. " _YELLOW_("%s"), sprint_hex_inrow(device_nonce, device_nonce_len));
        PrintAndLogEx(INFO, "Reader ephemeral pubkey... " _YELLOW_("%s"), sprint_hex_inrow(reader_ephemeral_public_key, sizeof(reader_ephemeral_public_key)));
        PrintAndLogEx(INFO, "Reader signature.......... " _YELLOW_("%s"), sprint_hex_inrow(reader_signature, reader_signature_len));
        PrintAndLogEx(INFO, "Live authentication....... %s", cfg->live_authentication ? _GREEN_("yes") : "no");
    }

    status = gst_build_negotiate_message(reader_nonce, reader_ephemeral_public_key,
                                         reader_signature, reader_signature_len,
                                         cfg->collector_id, cfg->key_version,
                                         session_id, 1, cfg->live_authentication,
                                         negotiate_cmd, sizeof(negotiate_cmd), &negotiate_cmd_len);
    if (status != PM3_SUCCESS) {
        goto out;
    }

    status = gst_exchange_chained(false, true, 0x90, 0x53, 0x00, 0x00,
                                  negotiate_cmd, negotiate_cmd_len,
                                  negotiate_response, sizeof(negotiate_response), &negotiate_response_len, &negotiate_sw);
    if (status != PM3_SUCCESS) {
        goto out;
    }

    if (gst_status_is_transient_failure(negotiate_sw)) {
        PrintAndLogEx(WARNING, "Transient failure on NEGOTIATE (sequence=1), retrying with sequence=3...");
        status = gst_build_negotiate_message(reader_nonce, reader_ephemeral_public_key,
                                             reader_signature, reader_signature_len,
                                             cfg->collector_id, cfg->key_version,
                                             session_id, 3, cfg->live_authentication,
                                             negotiate_cmd, sizeof(negotiate_cmd), &negotiate_cmd_len);
        if (status != PM3_SUCCESS) {
            goto out;
        }
        status = gst_exchange_chained(false, true, 0x90, 0x53, 0x00, 0x00,
                                      negotiate_cmd, negotiate_cmd_len,
                                      negotiate_response, sizeof(negotiate_response), &negotiate_response_len, &negotiate_sw);
        if (status != PM3_SUCCESS) {
            goto out;
        }
    }

    if (cfg->verbose || negotiate_sw != 0x9000) {
        if (!cfg->verbose) {
            PrintAndLogEx(INFO, "");
        }
        gst_print_status_line("NEGOTIATE status..........", negotiate_sw);
    }
    if (!(negotiate_sw == 0x9000 || negotiate_sw == 0x9002)) {
        status = PM3_ESOFT;
        goto out;
    }

    uint8_t negotiate_sequence = 0;
    status = gst_parse_negotiate_response(negotiate_response, negotiate_response_len,
                                          &negotiate_sequence,
                                          device_ephemeral_public_key, &device_ephemeral_public_key_len);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to parse NEGOTIATE response");
        goto out;
    }

    uint8_t get_data_sequence = (uint8_t)(negotiate_sequence + 1);
    uint8_t get_data_retry_sequence = (uint8_t)(negotiate_sequence + 3);

    status = gst_perform_get_data(cfg->collector_id, session_id, get_data_sequence, cfg->mode,
                                  get_data_response, sizeof(get_data_response), &get_data_response_len, &get_data_sw);
    if (status != PM3_SUCCESS) {
        goto out;
    }
    if (gst_status_is_transient_failure(get_data_sw)) {
        PrintAndLogEx(WARNING, "Transient failure on GET DATA, retrying...");
        status = gst_perform_get_data(cfg->collector_id, session_id, get_data_retry_sequence, cfg->mode,
                                      get_data_response, sizeof(get_data_response), &get_data_response_len, &get_data_sw);
        if (status != PM3_SUCCESS) {
            goto out;
        }
    }

    if (cfg->verbose) {
        PrintAndLogEx(INFO, "");
        PrintAndLogInfoHeader("Get data");
    }
    if (cfg->verbose || get_data_sw != 0x9000) {
        if (!cfg->verbose) {
            PrintAndLogEx(INFO, "");
        }
        gst_print_status_line("GET DATA status...........", get_data_sw);
    }
    if (!gst_status_is_success(get_data_sw)) {
        status = PM3_ESOFT;
        goto out;
    }

    if (get_data_response_len == 0) {
        PrintAndLogEx(INFO, "No data returned by handset");
        status = PM3_SUCCESS;
        goto out;
    }

    uint8_t bundle_flags = 0;
    const uint8_t *bundle_payload = NULL;
    size_t bundle_payload_len = 0;
    status = gst_extract_record_bundle(get_data_response, get_data_response_len,
                                       &bundle_flags, &bundle_payload, &bundle_payload_len);
    if (status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to parse SERVICE_RESPONSE / RECORD_BUNDLE");
        goto out;
    }

    if (cfg->verbose) {
        gst_print_bundle_flags(bundle_flags);
    }

    const uint8_t *payload_to_parse = bundle_payload;
    size_t payload_to_parse_len = bundle_payload_len;

    if (bundle_flags & 0x01) {
        status = gst_decrypt_payload(bundle_payload, bundle_payload_len,
                                     cfg->collector_id,
                                     reader_nonce,
                                     device_nonce, device_nonce_len,
                                     reader_signature, reader_signature_len,
                                     &reader_ephemeral_key,
                                     reader_ephemeral_public_key,
                                     device_ephemeral_public_key, device_ephemeral_public_key_len,
                                     decrypted_payload, sizeof(decrypted_payload), &decrypted_payload_len);
        if (status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to decrypt RECORD_BUNDLE payload");
            goto out;
        }
        payload_to_parse = decrypted_payload;
        payload_to_parse_len = decrypted_payload_len;
    }

    if (bundle_flags & 0x02) {
#ifdef HAVE_ZLIB
        status = gst_decompress_payload_zlib(payload_to_parse, payload_to_parse_len,
                                             &decompressed_payload, &decompressed_payload_len);
        if (status != PM3_SUCCESS) {
            if (status == PM3_EOVFLOW) {
                PrintAndLogEx(ERR, "Compressed payload exceeds %d bytes limit", GST_MAX_DECOMPRESSED_PAYLOAD);
            } else {
                PrintAndLogEx(ERR, "Failed to decompress RECORD_BUNDLE payload (zlib)");
            }
            goto out;
        }
        payload_to_parse = decompressed_payload;
        payload_to_parse_len = decompressed_payload_len;
#else
        PrintAndLogEx(WARNING, "RECORD_BUNDLE is compressed (0x02 flag set) but zlib is unavailable. Skipping decompression.");
#endif
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogInfoHeader("Service objects");
    gst_print_service_objects(payload_to_parse, payload_to_parse_len);
    status = PM3_SUCCESS;

out:
#ifdef HAVE_ZLIB
    free(decompressed_payload);
#endif
    DropField();
    mbedtls_ecp_keypair_free(&reader_ephemeral_key);
    mbedtls_ecp_keypair_free(&longterm_key);
    pcrypto_rng_free(&rng);
    return status;
}

static int CmdHFGSTTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gst test",
                  "Perform self tests",
                  "hf gst test");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "------ " _CYAN_("Google Smart Tap tests") " ------");
    int res = gst_selftest_zlib();
    if (res == PM3_ENOTIMPL) {
        PrintAndLogEx(INFO, "Tests ( %s )", _YELLOW_("skipped"));
    } else {
        PrintAndLogEx(SUCCESS, "Tests ( %s )", (res == PM3_SUCCESS) ? _GREEN_("ok") : _RED_("fail"));
    }
    return res;
}

static int CmdHFGSTInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gst info",
                  "Select OSE / Smart Tap applet and print capabilities.",
                  "hf gst info\n"
                  "hf gst info --select-smarttap2 yes -a");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "select-smarttap2", "<auto|yes|no>", "Whether to perform Smart Tap applet select (default: auto)"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    gst_select_behavior_t select_behavior = GST_SELECT_AUTO;
    CLIParserOption select_options[] = {
        {GST_SELECT_AUTO, "auto"},
        {GST_SELECT_YES, "yes"},
        {GST_SELECT_NO, "no"},
        {0, NULL}
    };
    if (CLIGetOptionList(arg_get_str(ctx, 1), select_options, (int *)&select_behavior) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool apdu_logging = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    bool restore_apdu_logging = GetAPDULogging();
    SetAPDULogging(apdu_logging);
    int res = gst_info(select_behavior);
    SetAPDULogging(restore_apdu_logging);
    return res;
}

static int CmdHFGSTRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gst read",
                  "Execute Google Smart Tap read flow and print parsed pass objects.",
                  "hf gst read --cid 20180608 --rpk gst.google.der\n"
                  "hf gst read --cid 13380028 --rpk gst.passkit.der\n"
                  "hf gst read --cid 20180608 --rpk \"-----BEGIN EC PRIVATE KEY-----\\nMHcCAQEEIIJtF+UHZ7FlsOTZ4zL40dHiAiQoT7Ta8eUKAyRucHl9oAoGCCqGSM49\\nAwEHoUQDQgAEchyXj869zfmKhRi9xP7f2AK07kEo4lE7ZlWTN14jh4YBTny+hRGR\\nXcUzevV9zSSPJlPHpqqu5pEwlv1xyFvE1w==\\n-----END EC PRIVATE KEY-----\"\n"
                  "hf gst read --cid 20180608 --rpk MHcCAQEEIIJtF+UHZ7FlsOTZ4zL40dHiAiQoT7Ta8eUKAyRucHl9oAoGCCqGSM49AwEHoUQDQgAEchyXj869zfmKhRi9xP7f2AK07kEo4lE7ZlWTN14jh4YBTny+hRGRXcUzevV9zSSPJlPHpqqu5pEwlv1xyFvE1w==\n"
                  "hf gst read --collector-id 20180608 --reader-private-key gst.google.der\n"
                  "hf gst read --collector-id 20180608 --reader-private-key 826d17e50767b165b0e4d9e332f8d1d1e20224284fb4daf1e50a03246e70797d\n"
                  "hf gst read --cid 20180608 --rpk gst.google.der -@");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("c", "collector-id,collectorid,cid", "<hex|dec>", "Collector identifier (32-bit value)"),
        arg_str1("p", "reader-private-key,readerprivkey,rpk", "<pem|der-b64|der-hex|scalar-b64|scalar-hex|path>", "Reader private key: PEM, DER hex, scalar hex/base64, or file path"),
        arg_str0(NULL, "key-version,keyversion,kv", "<hex|dec>", "Long-term key version (default: 1)"),
        arg_str0(NULL, "session-id,sid", "<hex>", "Session id (8 bytes, random if omitted)"),
        arg_str0(NULL, "reader-nonce,nonce", "<hex>", "Reader nonce (32 bytes, random if omitted)"),
        arg_str0(NULL, "reader-ephemeral-private-key,ephemeral-privkey,epk", "<hex>", "Reader ephemeral private key (32 bytes, random if omitted)"),
        arg_str0(NULL, "mode", "<pass-only|payment-only|pass-and-payment|pass-over-payment>", "Reader mode (default: pass-over-payment)"),
        arg_str0(NULL, "select-smarttap2", "<auto|yes|no>", "Whether to perform Smart Tap applet select (default: auto)"),
        arg_lit0(NULL, "no-live-auth", "Use zeroed handset nonce for reader signature"),
        arg_lit0("@", NULL, "continuous mode"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    gst_read_config_t cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.key_version = 1;
    cfg.mode = GST_MODE_PASS_OVER_PAYMENT;
    cfg.select_behavior = GST_SELECT_AUTO;
    cfg.live_authentication = true;

    char collector_id_text[64] = {0};
    int collector_id_text_len = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)collector_id_text, sizeof(collector_id_text), &collector_id_text_len) != 0 ||
            collector_id_text_len == 0 ||
            parse_uint32_hex_or_dec(collector_id_text, &cfg.collector_id) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Invalid collector-id");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    char reader_key_text[GST_MAX_PRIVATE_KEY_ARG] = {0};
    int reader_key_text_len = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)reader_key_text, sizeof(reader_key_text), &reader_key_text_len) != 0 ||
            reader_key_text_len == 0 ||
            ensure_ec_private_key(reader_key_text, MBEDTLS_ECP_DP_SECP256R1, cfg.reader_private_key, sizeof(cfg.reader_private_key)) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Invalid reader-private-key format");
        PrintAndLogEx(INFO, "Accepted formats:");
        PrintAndLogEx(INFO, "  1) PEM string with headers (BEGIN PRIVATE KEY)");
        PrintAndLogEx(INFO, "  2) DER bytes as hex or base64");
        PrintAndLogEx(INFO, "  3) Scalar as hex or base64");
        PrintAndLogEx(INFO, "  4) File path to a key in any of the formats above");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    char key_version_text[64] = {0};
    int key_version_text_len = 0;
    if (CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)key_version_text, sizeof(key_version_text), &key_version_text_len) == 0 &&
            key_version_text_len > 0) {
        if (parse_uint32_hex_or_dec(key_version_text, &cfg.key_version) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Invalid key-version");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int session_id_len = 0;
    CLIGetHexWithReturn(ctx, 4, cfg.session_id, &session_id_len);
    if (session_id_len == 8) {
        cfg.have_session_id = true;
    } else if (session_id_len != 0) {
        PrintAndLogEx(ERR, "session-id must be 8 bytes when provided (got %d)", session_id_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int reader_nonce_len = 0;
    CLIGetHexWithReturn(ctx, 5, cfg.reader_nonce, &reader_nonce_len);
    if (reader_nonce_len == 32) {
        cfg.have_reader_nonce = true;
    } else if (reader_nonce_len != 0) {
        PrintAndLogEx(ERR, "reader-nonce must be 32 bytes when provided (got %d)", reader_nonce_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int eph_priv_len = 0;
    CLIGetHexWithReturn(ctx, 6, cfg.reader_ephemeral_private_key, &eph_priv_len);
    if (eph_priv_len == 32) {
        cfg.have_reader_ephemeral_private_key = true;
    } else if (eph_priv_len != 0) {
        PrintAndLogEx(ERR, "reader-ephemeral-private-key must be 32 bytes when provided (got %d)", eph_priv_len);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserOption mode_options[] = {
        {GST_MODE_PASS_ONLY, "pass-only"},
        {GST_MODE_PAYMENT_ONLY, "payment-only"},
        {GST_MODE_PASS_AND_PAYMENT, "pass-and-payment"},
        {GST_MODE_PASS_OVER_PAYMENT, "pass-over-payment"},
        {0, NULL}
    };
    if (CLIGetOptionList(arg_get_str(ctx, 7), mode_options, (int *)&cfg.mode) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserOption select_options[] = {
        {GST_SELECT_AUTO, "auto"},
        {GST_SELECT_YES, "yes"},
        {GST_SELECT_NO, "no"},
        {0, NULL}
    };
    if (CLIGetOptionList(arg_get_str(ctx, 8), select_options, (int *)&cfg.select_behavior) != PM3_SUCCESS) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    cfg.live_authentication = !arg_get_lit(ctx, 9);
    bool continuous = arg_get_lit(ctx, 10);
    cfg.apdu_logging = arg_get_lit(ctx, 11);
    cfg.verbose = arg_get_lit(ctx, 12);

    CLIParserFree(ctx);

    if (continuous) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    bool restore_apdu_logging = GetAPDULogging();
    SetAPDULogging(cfg.apdu_logging);

    int res = PM3_SUCCESS;
    do {
        if (continuous && kbd_enter_pressed()) {
            break;
        }
        clearCommandBuffer();

        int discovery_res = SelectCard14443A_4(false, false, NULL);
        if (discovery_res != PM3_SUCCESS) {
            if (!continuous) {
                PrintAndLogEx(WARNING, "No ISO14443-A card in field");
            }
            if (res == PM3_SUCCESS) {
                res = discovery_res;
            }
            msleep(300);
            continue;
        }

        int iter_res = gst_read(&cfg);
        if (iter_res != PM3_SUCCESS && res == PM3_SUCCESS) {
            res = iter_res;
        }

        if (continuous) {
            msleep(3000);
        }
        PrintAndLogEx(NORMAL, "");
        msleep(300);
    } while (continuous);

    SetAPDULogging(restore_apdu_logging);
    return res;
}

static int CmdHFGSTList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf gst", "7816");
}

static command_t CommandTable[] = {
    {"-----------", CmdHelp,       AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",        CmdHelp,       AlwaysAvailable, "This help"},
    {"list",        CmdHFGSTList,  AlwaysAvailable, "List ISO 14443A/7816 history"},
    {"test",        CmdHFGSTTest,  AlwaysAvailable, "Perform self tests"},
    {"-----------", CmdHelp,       IfPm3Iso14443a,  "--------------------- " _CYAN_("Operations") " ----------------------"},
    {"info",        CmdHFGSTInfo,  IfPm3Iso14443a,  "Get Google Smart Tap applet information"},
    {"read",        CmdHFGSTRead,  IfPm3Iso14443a,  "Read and decode Google Smart Tap pass objects"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFGST(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
