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
// EMV commands
//-----------------------------------------------------------------------------

#include "cmdemv.h"
#include <string.h>
#include "comms.h"          // DropField
#include "cmdsmartcard.h"   // smart_select
#include "cmdtrace.h"
#include "emvjson.h"
#include "test/cryptotest.h"
#include "cliparser.h"
#include "cmdparser.h"
#include "proxmark3.h"
#include "emv_roca.h"
#include "emvcore.h"
#include "cmdhf14a.h"
#include "dol.h"
#include "ui.h"
#include "emv_tags.h"
#include "fileutils.h"
#include "protocols.h"      // ISO7816 APDU return codes
#include "commonutil.h"     // MemBeToUint2byte
#include <mbedtls/des.h>    // DES
#include "crypto/libpcrypto.h"
#include "iso4217.h"        // currency lookup
#include "terminal/emv_term_cmd.h"
#include "terminal/emv_term_reader_session.h"
#include "terminal/phase_init.h"
#include "terminal/phase_oda.h"
#include "terminal/emv_transaction.h"

static int CmdHelp(const char *Cmd);

#define TLV_ADD(tag, value)( tlvdb_change_or_add_node(tlvRoot, tag, sizeof(value) - 1, (const unsigned char *)value) )
static void ParamLoadDefaults(struct tlvdb *tlvRoot) {
    // 9F02:(Amount, authorized (Numeric)) len:6
    TLV_ADD(0x9F02, "\x00\x00\x00\x00\x01\x00");
    // 9F1A:(Terminal Country Code) len:2
    TLV_ADD(0x9F1A, "ru");
    // 5F2A:(Transaction Currency Code) len:2
    // USD 840, EUR 978, RUR 810, RUB 643, RUR 810(old), UAH 980, AZN 031, n/a 999
    TLV_ADD(0x5F2A, "\x090\x78");
    // 9A:(Transaction Date) len:3
    TLV_ADD(0x9A,   "\x00\x00\x00");
    // 9C:(Transaction Type) len:1
    //     | 00 => Goods and Service
    //     | 01 => Cash
    TLV_ADD(0x9C,   "\x00");
    // 9F37 Unpredictable Number (UN) len:4
    TLV_ADD(0x9F37, "\x01\x02\x03\x04");
    // 9F6A Unpredictable Number (MSD for UDOL) len:4
    TLV_ADD(0x9F6A, "\x01\x02\x03\x04");
    // 9F66:(Terminal Transaction Qualifiers (TTQ)) len:4
    TLV_ADD(0x9F66, "\x26\x00\x00\x00"); // qVSDC
    // 95:(Terminal Verification Results) len:5
    // all OK TVR
    TLV_ADD(0x95,   "\x00\x00\x00\x00\x00");
    // 9F4E Merchant Name and Location len:x
    TLV_ADD(0x9F4E, "proxmark3rdv4\x00");
}

static void PrintChannel(Iso7816CommandChannel channel) {
    switch (channel) {
        case CC_CONTACTLESS:
            PrintAndLogEx(INFO, "Selected channel... " _GREEN_("CONTACTLESS (T=CL)"));
            break;
        case CC_CONTACT:
            PrintAndLogEx(INFO, "Selected channel... " _GREEN_("CONTACT"));
            break;
    }
}

/*
static int emv_calc_cvv(const uint8_t *pan, size_t panlen, const uint8_t *expiry, const uint8_t *servicecode, const uint8_t *atc) {

    uint8_t key[16] = {0};
    memset(key, 0x30, sizeof(key));

    uint8_t d[32] = {0};
    uint8_t *pd = d;

    memcpy(pd, pan, panlen);
    pd += panlen;
    memcpy(pd, expiry, 4);
    pd += 4;

    // cvv/cvc
    memcpy(pd, servicecode, 3);
    pd += 3;

    // atc
    memcpy(pd, atc, 4);

    uint8_t encrypted[16] = {0};

    // zero padding?!?

    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, d, encrypted);
    mbedtls_des_crypt_ecb(&ctx, d + 6, encrypted + 6);

    // xor
    for (size_t i = 16; i < 32; i++) {
        d[i] ^= encrypted[i - 16];
    }

    mbedtls_des_free(&ctx);

    PrintAndLogEx(INFO, "key... %s", sprint_hex_inrow(key, sizeof(key)));
    PrintAndLogEx(INFO, "d..... %s", sprint_hex_inrow(d, sizeof(d)));


    mbedtls_des3_context ctx3;
    mbedtls_des3_init(&ctx3);
    mbedtls_des3_set2key_enc(&ctx3, key);
    mbedtls_des3_set2key_dec(&ctx3, key);
    mbedtls_des3_crypt_ecb(&ctx3, d, encrypted);
    mbedtls_des3_free(&ctx3);

    PrintAndLogEx(INFO, "enc... %s", sprint_hex_inrow(encrypted, sizeof(encrypted)));

    memset(encrypted, 0, sizeof(encrypted));
    des3_encrypt(encrypted, d, key, 2);
    PrintAndLogEx(INFO, "enc... %s", sprint_hex_inrow(encrypted, sizeof(encrypted)));

    return PM3_SUCCESS;
}
*/


static size_t logtemplate_calculate_len(const struct tlv *tlv, size_t data_len) {
    if (!tlv)
        return 0;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    size_t count = 0;

    while (left) {
        struct tlv cur_tlv;
        if (!tlv_parse_tl(&buf, &left, &cur_tlv))
            return 0;

        count += cur_tlv.len;

        /* Last tag can be of variable length */
        if (cur_tlv.len == 0 && left == 0)
            count = data_len;
    }

    return count;
}

static struct tlvdb *emv_logtemplate_parse(const struct tlv *tlv, const unsigned char *data, size_t data_len) {
    if (!tlv)
        return NULL;

    const unsigned char *buf = tlv->value;
    size_t left = tlv->len;
    size_t res_len = logtemplate_calculate_len(tlv, data_len);
    size_t pos = 0;
    struct tlvdb *db = NULL;

    while (left) {
        struct tlv cur_tlv;
        if (!tlv_parse_tl(&buf, &left, &cur_tlv) || pos + cur_tlv.len > res_len) {
            tlvdb_free(db);
            return NULL;
        }

        /* Last tag can be of variable length */
        if (cur_tlv.len == 0 && left == 0)
            cur_tlv.len = res_len - pos;

        struct tlvdb *tag_db = tlvdb_fixed(cur_tlv.tag, cur_tlv.len, data + pos);
        if (!db)
            db = tag_db;
        else
            tlvdb_add(db, tag_db);

        pos += cur_tlv.len;
    }

    return db;
}

static int emv_parse_log(struct tlvdb *ttdb, const uint8_t *d, size_t n) {
    /*
        The Log Format (9F4F) is a list in tag and length format (i.e., "TL" instead of TLV) See description in Table 33 on page 141.

        In your example, "9F 27 01 9F 02 06 5F 2A 02 9A 03 9F 36 02 9F 52 06 DF 3E 01 9F 21 03 9F 7C 14" means:

        9F27 01 (Cryptogram Information Data)
        9F02 06 (Amount, Authorised)
        5F2A 02 (Transaction Currency Code)
        9A 03 (Transaction Date)
        9F36 02 (Application Transaction Counter)
        9F52 06 (Terminal Compatibility Indicator)
        DF3E 01
        9F21 03 (Transaction Time)
        9F7C 14 (Visa Customer Exclusive Data)

    */
    int pos = 0;
    struct tlvdb *tp = ttdb;
    while (tp) {
        const struct tlv *tpitem = tlvdb_get_tlv(tp);

        const char *s = emv_get_tag_name(tpitem);

        switch (tpitem->tag) {
            case 0x5F2A:
                if (tpitem->len == 2) {

                    char tmp[5] = {0};
                    snprintf(tmp, sizeof(tmp), "%x%02x", d[pos], d[pos + 1]);
                    const char *cn = getCurrencyInfo(tmp);
                    PrintAndLogEx(INFO, "%-30s... " _YELLOW_("%s") " ( %x%02x )", s, cn, d[pos], d[pos + 1]);
                }
                break;
            case 0x9A:
                if (tpitem->len == 3) {
                    PrintAndLogEx(INFO, "%-30s... " _YELLOW_("20%02x-%02x-%02x"), s, d[pos], d[pos + 1], d[pos + 2]);
                }
                break;
            case 0x9F21:
                if (tpitem->len == 3) {
                    PrintAndLogEx(INFO, "%-30s... " _YELLOW_("%02x:%02x:%02x"), s, d[pos], d[pos + 1], d[pos + 2]);
                }
                break;
            default:
                PrintAndLogEx(INFO, "%-30s... " _YELLOW_("%s"), s, sprint_hex_inrow(d + pos, tpitem->len));
                break;
        }

        pos += tpitem->len;

        tp = tlvdb_elm_get_next(tp);
    }
    return PM3_SUCCESS;
}

static int emv_extract_log_info(uint8_t *response, size_t reslen, uint8_t *lid,  uint8_t *lrecs) {

    struct tlvdb *t = tlvdb_parse_multi(response, reslen);
    if (t == NULL) {
        PrintAndLogEx(INFO, "root null");
        return PM3_EINVARG;
    }

    int res = PM3_ESOFT;
    struct tlvdb *logs = tlvdb_find_full(t, 0x9F4D);
    if (logs != NULL) {
        const struct tlv *tlv = tlvdb_get_tlv(logs);
        if (tlv->len == 2) {
            *lid = tlv->value[0];
            *lrecs = tlv->value[1];
            PrintAndLogEx(DEBUG, "Logs EMV...  SFI %u Records # %u", *lid, *lrecs);
            res = PM3_SUCCESS;
        }
    }

    tlvdb_free(t);
    return res;
}

static int emv_parse_track1(const uint8_t *d, size_t n, bool verbose) {
    if (d == NULL || n < 10) {
        return PM3_EINVARG;
    }
    if (verbose == false) {
        return PM3_SUCCESS;
    }

    // sanity checks
    if (d[0] != 'B') {
        return PM3_EINVARG;
    }

    // decoder
    char *tmp = str_ndup((const char *)d, n);
    uint8_t i = 0;
    const char delim[2] = "^";
    char *token = strtok(tmp, delim);
    while (token != NULL) {

        switch (i) {
            case 0: {
                size_t a = strlen(token);
                if (a == 16) {
                    PrintAndLogEx(INFO, "PAN...................... " _GREEN_("%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c"),
                                  token[1], token[2], token[3], token[4],
                                  token[5], token[6], token[7], token[8],
                                  token[9], token[10], token[11], token[12],
                                  token[13], token[14], token[15], token[16]
                                 );
                } else if (a == 19) {
                    PrintAndLogEx(INFO, "PAN...................... " _GREEN_("%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c %c%c%c"),
                                  token[1], token[2], token[3], token[4],
                                  token[5], token[6], token[7], token[8],
                                  token[9], token[10], token[11], token[12],
                                  token[13], token[14], token[15], token[16],
                                  token[17], token[18], token[19]
                                 );
                }
                break;
            }
            case 1:
                PrintAndLogEx(INFO, "CardHolder............... %s", token);
                break;
            case 2:
                if (strlen(token) < 14) {
                    break;
                }
                PrintAndLogEx(INFO, "Expiry date.............. %.*s ( %c%c/%c%c )", 4, token, token[2], token[3], token[0], token[1]);
                token += 4;

                PrintAndLogEx(INFO, "Service code............. %.*s", 3, token);
                token += 3;

                PrintAndLogEx(INFO, "Unknown.................. %.*s", 4, token);
                token += 4;

                PrintAndLogEx(INFO, "CVV / iCvv............... %.*s", 3, token);
                token += 3;

                PrintAndLogEx(INFO, "Trailing................. %s", token);
                break;
            default:
                break;
        }
        token = strtok(0, delim);
        i++;
    }
    free(tmp);
    return PM3_SUCCESS;
}

static int emv_parse_track2(const uint8_t *d, size_t n, bool verbose) {
    if (d == NULL || n < 10) {
        return PM3_EINVARG;
    }
    if (verbose == false) {
        return PM3_SUCCESS;
    }

    // decoder
    uint8_t s[80] = {0};
    hex_to_buffer(s, d, n, n, 0, 0, true);
    uint8_t *tmp = s;

    if (tmp[0] == ';')
        tmp++;

    PrintAndLogEx(INFO, "PAN...................... "_GREEN_("%c%c%c%c %c%c%c%c %c%c%c%c %c%c%c%c"),
                  tmp[0], tmp[1], tmp[2], tmp[3],
                  tmp[4], tmp[5], tmp[6], tmp[7],
                  tmp[8], tmp[9], tmp[10], tmp[11],
                  tmp[12], tmp[13], tmp[14], tmp[15]
                 );
    tmp += 16;

    if (tmp[0] == '=' || tmp[0] == 'D')
        tmp++;

    PrintAndLogEx(INFO, "Expiry date.............. %.*s ( %c%c/%c%c )", 4, tmp, tmp[2], tmp[3], tmp[0], tmp[1]);
    tmp += 4;

    PrintAndLogEx(INFO, "Service code............. %.*s", 3, tmp);
    tmp += 3;

    PrintAndLogEx(INFO, "Pin verification value... %.*s", 4, tmp);
    tmp += 4;

    PrintAndLogEx(INFO, "CVV / iCvv............... %.*s", 3, tmp);
    tmp += 3;

    PrintAndLogEx(INFO, "Trailing................. %s", tmp);

    return PM3_SUCCESS;
}

static int emv_parse_card_details(uint8_t *response, size_t reslen, bool verbose) {

    struct tlvdb *root = tlvdb_parse_multi(response, reslen);
    if (root == NULL) {
        return PM3_EINVARG;
    }

    // extract application preferred name
    struct tlvdb *prefname_full = tlvdb_find_full(root, 0x9F12);
    if (prefname_full != NULL) {
        const struct tlv *prefname_tlv = tlvdb_get_tlv(prefname_full);
        if (prefname_tlv->len) {
            char name[64] = {0};
            size_t n = MIN(sizeof(name), prefname_tlv->len);
            memcpy(name, prefname_tlv->value, n);
            PrintAndLogEx(INFO, "Application.......... " _YELLOW_("%s"), name);
        }
    }

    // extract application label
    struct tlvdb *alabel = tlvdb_find_full(root, 0x50);
    if (alabel != NULL) {
        const struct tlv *alabel_tlv = tlvdb_get_tlv(alabel);
        if (alabel_tlv->len) {
            char name[64] = {0};
            size_t n = MIN(sizeof(name), alabel_tlv->len);
            memcpy(name, alabel_tlv->value, n);
            PrintAndLogEx(INFO, "Label................ " _YELLOW_("%s"), name);
        }
    }

    // extract language preference
    struct tlvdb *lang_full = tlvdb_find_full(root, 0x5F2D);
    if (lang_full != NULL) {
        const struct tlv *lang_tlv = tlvdb_get_tlv(lang_full);
        if (lang_tlv->len) {
            char lang[16] = {0};
            size_t n = MIN(sizeof(lang), lang_tlv->len);
            memcpy(lang, lang_tlv->value, n);
            PrintAndLogEx(INFO, "Language............. " _YELLOW_("%s"), lang);
        }
    }

    // Application Currency Code
    struct tlvdb *acc_full = tlvdb_find_full(root, 0x9F42);
    if (acc_full != NULL) {
        const struct tlv *acc_tlv = tlvdb_get_tlv(acc_full);
        if (acc_tlv->len == 2) {
            uint16_t acc = MemBeToUint2byte((const uint8_t *)acc_tlv->value);

            char tmp[5] = {0};
            snprintf(tmp, sizeof(tmp), "%x%02x", acc_tlv->value[0], acc_tlv->value[1]);
            const char *cn = getCurrencyInfo(tmp);

            PrintAndLogEx(INFO, "Currency Code........ " _YELLOW_("%s") " ( %x )", cn, acc);
        }
    }

    // Application Effective Date
    struct tlvdb *aeffect_full = tlvdb_find_full(root, 0x5F25);
    if (aeffect_full != NULL) {
        const struct tlv *aaeffect_tlv = tlvdb_get_tlv(aeffect_full);
        if (aaeffect_tlv->len == 3) {
            PrintAndLogEx(INFO, "Effective date....... " _YELLOW_("20%02x-%02x-%02x"),
                          aaeffect_tlv->value[0],
                          aaeffect_tlv->value[1],
                          aaeffect_tlv->value[2]
                         );
        }
    }

    // Application Expiration Date
    struct tlvdb *aexd_full = tlvdb_find_full(root, 0x5F24);
    if (aexd_full != NULL) {
        const struct tlv *aexd_tlv = tlvdb_get_tlv(aexd_full);
        if (aexd_tlv->len == 3) {
            PrintAndLogEx(INFO, "Expiration date...... " _YELLOW_("20%02x-%02x-%02x"),
                          aexd_tlv->value[0],
                          aexd_tlv->value[1],
                          aexd_tlv->value[2]
                         );
        }
    }

    // Application Primary Account Number (PAN)
    struct tlvdb *apan_full = tlvdb_find_full(root, 0x5A);
    if (apan_full != NULL) {
        const struct tlv *apan_tlv = tlvdb_get_tlv(apan_full);
        if (apan_tlv->len == 8) {
            PrintAndLogEx(INFO, "PAN.................. " _GREEN_("%02x%02x %02x%02x %02x%02x %02x%02x"),
                          apan_tlv->value[0],
                          apan_tlv->value[1],
                          apan_tlv->value[2],
                          apan_tlv->value[3],
                          apan_tlv->value[4],
                          apan_tlv->value[5],
                          apan_tlv->value[6],
                          apan_tlv->value[7]
                         );
        }
    }

    // Application Primary Account Number (PAN) sequence number
    struct tlvdb *apansq_full = tlvdb_find_full(root, 0x5F34);
    if (apansq_full != NULL) {
        const struct tlv *apansq_tlv = tlvdb_get_tlv(apansq_full);
        if (apansq_tlv->len == 1) {
            PrintAndLogEx(INFO, "PAN Sequence......... " _YELLOW_("%u"), apansq_tlv->value[0]);
        }
    }

    // Cardholder Name
    struct tlvdb *chm_full = tlvdb_find_full(root, 0x5F20);
    if (chm_full != NULL) {
        const struct tlv *chm_tlv = tlvdb_get_tlv(chm_full);
        if (chm_tlv->len) {
            PrintAndLogEx(INFO, "Cardhold Name........ " _YELLOW_("%s"), sprint_ascii(chm_tlv->value, chm_tlv->len));
        }
    }

    // Track 1 Data
    struct tlvdb *track1_full = tlvdb_find_full(root, 0x56);
    if (track1_full != NULL) {
        const struct tlv *track1_tlv = tlvdb_get_tlv(track1_full);
        if (track1_tlv->len) {
            PrintAndLogEx(INFO, "Track 1.............. " _YELLOW_("%s"), sprint_ascii(track1_tlv->value, track1_tlv->len));
            emv_parse_track1(track1_tlv->value, track1_tlv->len, verbose);
        }
    }

    // Track 2 Data
    struct tlvdb *track2_full = tlvdb_find_full(root, 0x9F6B);
    if (track2_full != NULL) {
        const struct tlv *track2_tlv = tlvdb_get_tlv(track2_full);
        if (track2_tlv->len) {
            PrintAndLogEx(INFO, "Track 2.............. " _YELLOW_("%s"), sprint_hex_inrow(track2_tlv->value, track2_tlv->len));
            emv_parse_track2(track2_tlv->value, track2_tlv->len, verbose);
        }
    }

    // Track 2 Equivalent Data
    struct tlvdb *track2_eq_full = tlvdb_find_full(root, 0x57);
    if (track2_eq_full != NULL) {
        const struct tlv *track2_eq_tlv = tlvdb_get_tlv(track2_eq_full);
        if (track2_eq_tlv->len) {
            PrintAndLogEx(INFO, "Track 2 equivalent... " _YELLOW_("%s"), sprint_hex_inrow(track2_eq_tlv->value, track2_eq_tlv->len));
            emv_parse_track2(track2_eq_tlv->value, track2_eq_tlv->len, verbose);
        }
    }

    // Track 3 Data
    // to be impl.

    // Unpredicable Number (UN)
    struct tlvdb *un1_full = tlvdb_find_full(root, 0x9f37);
    if (un1_full != NULL) {
        const struct tlv *un1_tlv = tlvdb_get_tlv(un1_full);
        if (un1_tlv->len) {
            PrintAndLogEx(INFO, "9F37 Unpredicable Number... " _YELLOW_("%s"), sprint_hex_inrow(un1_tlv->value, un1_tlv->len));
        }
    }

    // Unpredicable Number (UN)
    struct tlvdb *un_full = tlvdb_find_full(root, 0x9f6a);
    if (un_full != NULL) {
        const struct tlv *un_tlv = tlvdb_get_tlv(un_full);
        if (un_tlv->len) {
            PrintAndLogEx(INFO, "9F6A Unpredicable Number... " _YELLOW_("%s"), sprint_hex_inrow(un_tlv->value, un_tlv->len));
            emv_parse_track2(un_tlv->value, un_tlv->len, verbose);
        }
    }

    struct tlvdb *merch_full = tlvdb_find_full(root, 0x9f4e);
    if (merch_full != NULL) {
        const struct tlv *merch_tlv = tlvdb_get_tlv(merch_full);
        if (merch_tlv->len) {
            PrintAndLogEx(INFO, "Merchant Name and Location... " _YELLOW_("%s"), sprint_hex_inrow(merch_tlv->value, merch_tlv->len));
        }
    }

    tlvdb_free(root);
    return PM3_SUCCESS;
}

static int CmdEMVSelect(const char *Cmd) {
    uint8_t data[APDU_AID_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv select",
                  "Executes select applet command",
                  "emv select -s a00000000101    -> select card, select applet\n"
                  "emv select -st a00000000101   -> select card, select applet, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",  "Activate field and select card"),
        arg_lit0("k",  "keep",    "Keep field for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str1(NULL, NULL, "<hex>", "Applet AID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool show_apdu = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5))
        channel = CC_CONTACT;
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 6, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVSelect(channel, activateField, leaveSignalON, data, datalen, buf, sizeof(buf), &len, &sw, NULL);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVSmartToNFC(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv smart2nfc",
                  "Executes ISO14443a payment, TX using ISO7816 interface for authentication",
                  "emv smart2nfc -t     -> test that the attached card is working (must be VISA)\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("t",  "test",    "test that the attached card is working (must be VISA)"),
        arg_str0("u", "uid", "<hex>", "optional 7 hex bytes UID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int uidlen = 0;
    uint8_t uid[7] = {0};
    CLIGetHexWithReturn(ctx, 2, uid, &uidlen);

    if (uidlen == 0) {
        PrintAndLogEx(SUCCESS, "No UID provided, using default.");
        uint8_t default_uid[7] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77};
        memcpy(uid, default_uid, sizeof(default_uid));
        uidlen = sizeof(default_uid);
    } else if (uidlen != 7) {
        PrintAndLogEx(FAILED, "UID must be 7 bytes long.");
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "UID length is %d", uidlen);

    bool testMode = arg_get_lit(ctx, 1);
    bool show_apdu = true;

    if (testMode) {
        PrintAndLogEx(SUCCESS, "Test mode enabled.");
    } else {
        PrintAndLogEx(SUCCESS, "Test mode disabled.");
    }

    CLIParserFree(ctx);

    // todo for PR: check this is relevant for us.
    SetAPDULogging(show_apdu);

    struct {
        uint16_t flags;
        uint8_t exitAfter;
        uint8_t uid[7];
        uint16_t atqa;
        uint8_t sak;
    } PACKED payload;

    memcpy(payload.uid, uid, uidlen);

    // Set up the flags for 2K mifare sim with RATS
    uint16_t flags = 0;

    FLAG_SET_UID_IN_DATA(flags, uidlen);
    if (IS_FLAG_UID_IN_EMUL(flags)) {
        PrintAndLogEx(WARNING, "Invalid parameter for UID");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    FLAG_SET_MF_SIZE(flags, MIFARE_2K_MAX_BYTES);

    flags |= FLAG_ATQA_IN_DATA;
    flags |= FLAG_SAK_IN_DATA;

    payload.flags = flags;
    payload.exitAfter = 0x1;
    payload.atqa = 0x0;
    payload.sak = 0x20;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_EMV_SIMULATE, (uint8_t *)&payload, sizeof(payload));

    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to abort simulation");

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVSearch(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv search",
                  "Tries to select all applets from applet list\n",
                  "emv search -s   -> select card and search\n"
                  "emv search -st  -> select card, search and show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",  "Activate field and select card"),
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    bool show_apdu = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 5)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    const char *al = "Applets list";
    struct tlvdb *t = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    if (EMVSearch(channel, activateField, leaveSignalON, decodeTLV, t, false)) {
        tlvdb_free(t);
        SetAPDULogging(false);
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(SUCCESS, "Search completed.");

    // print list here
    if (decodeTLV == false) {
        TLVPrintAIDlistFromSelectTLV(t);
    }

    tlvdb_free(t);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVPPSE(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv pse",
                  "Executes PSE/PPSE select command. It returns list of applet on the card:\n",
                  "emv pse -s1   -> select, get pse\n"
                  "emv pse -st2  -> select, get ppse, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",  "Activate field and select card"),
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("1",  "pse",     "PSE (1PAY.SYS.DDF01) mode"),
        arg_lit0("2",  "ppse",    "PPSE (2PAY.SYS.DDF01) mode (def)"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool activateField = arg_get_lit(ctx, 1);
    bool leaveSignalON = arg_get_lit(ctx, 2);
    uint8_t PSENum = 2;
    if (arg_get_lit(ctx, 3)) {
        PSENum = 1;
    }
    if (arg_get_lit(ctx, 4)) {
        PSENum = 2;
    }
    bool show_apdu = arg_get_lit(ctx, 5);
    bool decodeTLV = arg_get_lit(ctx, 6);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 7)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVSelectPSE(channel, activateField, leaveSignalON, PSENum, buf, sizeof(buf), &len, &sw);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVGPO(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv gpo",
                  "Executes Get Processing Options command. It returns data in TLV format (0x77 - format2)\n"
                  "or plain format (0x80 - format1). Needs a EMV applet to be selected.",
                  "emv gpo -k              -> execute GPO\n"
                  "emv gpo -t 01020304     -> execute GPO with 4-byte PDOL data, show result in TLV\n"
                  "emv gpo -pmt 9F 37 04   -> load params from file, make PDOL data from PDOL, execute GPO with PDOL, show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("p",  "params",  "Load parameters from `emv_defparams.json` file for PDOLdata making from PDOL and parameters"),
        arg_lit0("m",  "make",    "Make PDOLdata from PDOL (tag 9F38) and parameters (def: uses default parameters)"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx0(NULL,  NULL,    "<hex>", "PDOLdata/PDOL"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool paramsLoadFromFile = arg_get_lit(ctx, 2);
    bool dataMakeFromPDOL = arg_get_lit(ctx, 3);
    bool show_apdu = arg_get_lit(ctx, 4);
    bool decodeTLV = arg_get_lit(ctx, 5);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 6)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 7, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc PDOL
    struct tlv *pdol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x83,
        .len = datalen,
        .value = (uint8_t *)data,
    };
    if (dataMakeFromPDOL) {
        ParamLoadDefaults(tlvRoot);

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x9f38, datalen, data);
        pdol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x83);
        if (!pdol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create PDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain PDOL data...");
        }
        pdol_data_tlv = &data_tlv;
    }

    size_t pdol_data_tlv_data_len = 0;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data.");
        tlvdb_free(tmp_ext);
        tlvdb_free(tlvRoot);
        if (pdol_data_tlv != &data_tlv) {
            free(pdol_data_tlv);
        }
        SetAPDULogging(false);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%zu]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVGPO(channel, leaveSignalON, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (pdol_data_tlv != &data_tlv)
        free(pdol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static int CmdEMVReadRecord(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv readrec",
                  "Executes Read Record command. It returns data in TLV format.\n"
                  "Needs a bank applet to be selected and sometimes needs GPO to be executed.",
                  "emv readrec -k 0101   -> read file SFI=01, SFIrec=01\n"
                  "emv readrec -kt 0201  -> read file 0201 and show result in TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx1(NULL, NULL,     "<hex>", "<SFI 1 byte><SFIrecord 1 byte"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    bool decodeTLV = arg_get_lit(ctx, 3);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 4)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 5, data, &datalen);
    CLIParserFree(ctx);

    if (datalen != 2) {
        PrintAndLogEx(ERR, "Command needs to have 2 bytes of data");
        return PM3_EINVARG;
    }

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVReadRecord(channel, leaveSignalON, data[0], data[1], buf, sizeof(buf), &len, &sw, NULL);
    SetAPDULogging(false);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;


    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVAC(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv genac",
                  "Generate Application Cryptogram command. It returns data in TLV format.\n"
                  "Needs a EMV applet to be selected and GPO to be executed.",
                  "emv genac -k 0102         -> generate AC with 2-byte CDOLdata and keep field ON after command\n"
                  "emv genac -t 01020304     -> generate AC with 4-byte CDOL data, show result in TLV\n"
                  "emv genac -Daac 01020304  -> generate AC with 4-byte CDOL data and terminal decision 'declined'\n"
                  "emv genac -pmt 9F 37 04   -> load params from file, make CDOL data from CDOL, generate AC with CDOL, show result in TLV");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",     "Keep field ON for next command"),
        arg_lit0("c",  "cda",      "Executes CDA transaction. Needs to get SDAD in results."),
        arg_str0("d",  "decision", "<aac|tc|arqc>", "Terminal decision. aac - declined, tc - approved, arqc - online authorisation requested"),
        arg_lit0("p",  "params",   "Load parameters from `emv_defparams.json` file for CDOLdata making from CDOL and parameters"),
        arg_lit0("m",  "make",     "Make CDOLdata from CDOL (tag 8C and 8D) and parameters (def: use default parameters)"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx1(NULL, NULL,      "<hex>", "CDOLdata/CDOL"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool trTypeCDA = arg_get_lit(ctx, 2);
    uint8_t termDecision = 0xff;
    if (arg_get_str_len(ctx, 3)) {
        if (!strncmp(arg_get_str(ctx, 3)->sval[0], "aac", 4)) {
            termDecision = EMVAC_AAC;
        }
        if (!strncmp(arg_get_str(ctx, 3)->sval[0], "tc", 4)) {
            termDecision = EMVAC_TC;
        }
        if (!strncmp(arg_get_str(ctx, 3)->sval[0], "arqc", 4)) {
            termDecision = EMVAC_ARQC;
        }

        if (termDecision == 0xFF) {
            PrintAndLogEx(ERR, "ERROR: can't find terminal decision '%s'", arg_get_str(ctx, 3)->sval[0]);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else {
        termDecision = EMVAC_TC;
    }

    if (trTypeCDA) {
        termDecision = termDecision | EMVAC_CDAREQ;
    }
    bool paramsLoadFromFile = arg_get_lit(ctx, 4);
    bool dataMakeFromCDOL = arg_get_lit(ctx, 5);
    bool show_apdu = arg_get_lit(ctx, 6);
    bool decodeTLV = arg_get_lit(ctx, 7);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 8)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 9, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc CDOL
    struct tlv *cdol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x01,
        .len = datalen,
        .value = (uint8_t *)data,
    };

    if (dataMakeFromCDOL) {
        ParamLoadDefaults(tlvRoot);

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x8c, datalen, data);
        cdol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x01); // 0x01 - dummy tag
        if (!cdol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create CDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain CDOL data...");
        }
        cdol_data_tlv = &data_tlv;
    }

    PrintAndLogEx(INFO, "CDOL data[%zu]: %s", cdol_data_tlv->len, sprint_hex(cdol_data_tlv->value, cdol_data_tlv->len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVAC(channel, leaveSignalON, termDecision, (uint8_t *)cdol_data_tlv->value, cdol_data_tlv->len, buf, sizeof(buf), &len, &sw, tlvRoot);
    SetAPDULogging(false);

    if (cdol_data_tlv != &data_tlv)
        free(cdol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

static int CmdEMVGenerateChallenge(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv challenge",
                  "Executes Generate Challenge command. It returns 4 or 8-byte random number from card.\n"
                  "Needs a EMV applet to be selected and GPO to be executed.",
                  "emv challenge     -> get challenge\n"
                  "emv challenge -k  -> get challenge, keep filled ON\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool show_apdu = arg_get_lit(ctx, 2);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 3)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVGenerateChallenge(channel, leaveSignalON, buf, sizeof(buf), &len, &sw, NULL);
    SetAPDULogging(false);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    PrintAndLogEx(SUCCESS, "Challenge: %s", sprint_hex(buf, len));

    if (len != 4 && len != 8) {
        PrintAndLogEx(WARNING, "Length of challenge must be 4 or 8, got " _YELLOW_("%zu"), len);
    }

    return PM3_SUCCESS;
}

static int CmdEMVInternalAuthenticate(const char *Cmd) {
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv intauth",
                  "Generate Internal Authenticate command. Usually needs 4-byte random number. It returns data in TLV format .\n"
                  "Needs a EMV applet to be selected and GPO to be executed.",

                  "emv intauth -k 01020304   -> execute Internal Authenticate with 4-byte DDOLdata and keep field ON after command\n"
                  "emv intauth -t 01020304   -> execute Internal Authenticate with 4-byte DDOL data, show result in TLV\n"
                  "emv intauth -pmt 9F 37 04 -> load params from file, make DDOL data from DDOL, Internal Authenticate with DDOL, show result in TLV");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep",    "Keep field ON for next command"),
        arg_lit0("p",  "params",  "Load parameters from `emv_defparams.json` file for DDOLdata making from DDOL and parameters"),
        arg_lit0("m",  "make",    "Make DDOLdata from DDOL (tag 9F49) and parameters (def: use default parameters)"),
        arg_lit0("a",  "apdu",    "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",     "TLV decode results of selected applets"),
        arg_lit0("w",  "wired",   "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_strx1(NULL, NULL,     "<hex>", "DDOLdata/DDOL"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool paramsLoadFromFile = arg_get_lit(ctx, 2);
    bool dataMakeFromDDOL = arg_get_lit(ctx, 3);
    bool show_apdu = arg_get_lit(ctx, 4);
    bool decodeTLV = arg_get_lit(ctx, 5);
    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 6)) {
        channel = CC_CONTACT;
    }
    PrintChannel(channel);
    CLIGetHexWithReturn(ctx, 7, data, &datalen);
    CLIParserFree(ctx);

    SetAPDULogging(show_apdu);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // calc DDOL
    struct tlv *ddol_data_tlv = NULL;
    struct tlvdb *tmp_ext = NULL;
    struct tlv data_tlv = {
        .tag = 0x01,
        .len = datalen,
        .value = (uint8_t *)data,
    };

    if (dataMakeFromDDOL) {
        ParamLoadDefaults(tlvRoot);

        if (paramsLoadFromFile) {
            PrintAndLogEx(INFO, "Params loading from file...");
            ParamLoadFromJson(tlvRoot);
        };

        tmp_ext = tlvdb_external(0x9f49, datalen, data);
        ddol_data_tlv = dol_process((const struct tlv *)tmp_ext, tlvRoot, 0x01); // 0x01 - dummy tag
        if (!ddol_data_tlv) {
            PrintAndLogEx(ERR, "Can't create DDOL TLV.");
            tlvdb_free(tmp_ext);
            tlvdb_free(tlvRoot);
            SetAPDULogging(false);
            return PM3_ESOFT;
        }
    } else {
        if (paramsLoadFromFile) {
            PrintAndLogEx(WARNING, "Don't need to load parameters. Sending plain DDOL data...");
        }
        ddol_data_tlv = &data_tlv;
    }

    PrintAndLogEx(INFO, "DDOL data[%zu]: %s", ddol_data_tlv->len, sprint_hex(ddol_data_tlv->value, ddol_data_tlv->len));

    // exec
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = EMVInternalAuthenticate(channel, leaveSignalON, data, datalen, buf, sizeof(buf), &len, &sw, NULL);
    SetAPDULogging(false);

    if (ddol_data_tlv != &data_tlv)
        free(ddol_data_tlv);

    tlvdb_free(tmp_ext);
    tlvdb_free(tlvRoot);

    if (sw)
        PrintAndLogEx(INFO, "APDU response status: %04x - %s", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));

    if (res)
        return res;

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    return PM3_SUCCESS;
}

#define dreturn(n) { \
    free(pdol_data_tlv); \
    tlvdb_free(tlvSelect); \
    tlvdb_free(tlvRoot); \
    DropFieldEx( channel ); \
    SetAPDULogging(false); \
    return n; \
    }

static void InitTransactionParameters(struct tlvdb *tlvRoot, bool paramLoadJSON, enum TransactionType TrType, bool GenACGPO) {

    ParamLoadDefaults(tlvRoot);

    if (paramLoadJSON) {
        PrintAndLogEx(INFO, "* * Transaction parameters loading from JSON...");
        ParamLoadFromJson(tlvRoot);
    }

    //9F66:(Terminal Transaction Qualifiers (TTQ)) len:4

    switch (TrType) {
        case TT_MSD:
            TLV_ADD(0x9F66, "\x86\x00\x00\x00"); // MSD
            break;
        // not standard for contactless. just for test.
        case TT_VSDC:
            TLV_ADD(0x9F66, "\x46\x00\x00\x00"); // VSDC
            break;
        case TT_QVSDCMCHIP:
            // qVSDC
            if (GenACGPO) {
                TLV_ADD(0x9F66, "\x26\x80\x00\x00");
            } else {
                TLV_ADD(0x9F66, "\x26\x00\x00\x00");
            }
            break;
        case TT_CDA:
            // qVSDC (VISA CDA not enabled)
            if (GenACGPO) {
                TLV_ADD(0x9F66, "\x26\x80\x00\x00");
            } else {
                TLV_ADD(0x9F66, "\x26\x00\x00\x00");
            }
            break;
        case TT_END:
        default:
            break;
    }
}

static void ProcessGPOResponseFormat1(struct tlvdb *tlvRoot, uint8_t *buf, size_t len, bool decodeTLV) {
    if (buf[0] == 0x80) {
        if (decodeTLV) {
            PrintAndLogEx(SUCCESS, "GPO response format1:");
            TLVPrintFromBuffer(buf, len);
        }

        if (len < 4 || (len - 4) % 4) {
            PrintAndLogEx(ERR, "GPO response format 1 parsing error. length = %zu", len);
        } else {
            // AIP
            struct tlvdb *f1AIP = tlvdb_fixed(0x82, 2, buf + 2);
            tlvdb_add(tlvRoot, f1AIP);
            if (decodeTLV) {
                PrintAndLogEx(INFO, "\n* * Decode response format 1 (0x80) AIP and AFL:");
                TLVPrintFromTLV(f1AIP);
            }

            // AFL
            struct tlvdb *f1AFL = tlvdb_fixed(0x94, len - 4, buf + 2 + 2);
            tlvdb_add(tlvRoot, f1AFL);
            if (decodeTLV)
                TLVPrintFromTLV(f1AFL);
        }
    } else {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);
    }
}

static int CmdEMVExec(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv exec",
                  "Executes EMV contactless transaction",
                  "emv exec -sat    -> select card, execute MSD transaction, show APDU and TLV\n"
                  "emv exec -satc   -> select card, execute CDA transaction, show APDU and TLV\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",   "Activate field and select card"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results"),
        arg_lit0("j",  "jload",    "Load transaction parameters from `emv_defparams.json` file"),
        arg_lit0(NULL, "force",    "Force search AID. Search AID instead of execute PPSE"),
        arg_rem("By default:",     "Transaction type - MSD"),
        arg_lit0(NULL, "qvsdc",    "Transaction type - qVSDC or M/Chip"),
        arg_lit0("c",  "qvsdccda", "Transaction type - qVSDC or M/Chip plus CDA (SDAD generation)"),
        arg_lit0("x",  "vsdc",     "Transaction type - VSDC. For test only. Not a standard behavior"),
        arg_lit0("g",  "acgpo",    "VISA. generate AC from GPO"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    emv_term_cli_opts_t opts = {0};
    opts.activate_field = arg_get_lit(ctx, 1);
    opts.show_apdu = arg_get_lit(ctx, 2);
    opts.decode_tlv = arg_get_lit(ctx, 3);
    opts.param_load_json = arg_get_lit(ctx, 4);
    opts.force_search = arg_get_lit(ctx, 5);
    opts.tr_type = TT_MSD;
    if (arg_get_lit(ctx, 7)) {
        opts.tr_type = TT_QVSDCMCHIP;
    }
    if (arg_get_lit(ctx, 8)) {
        opts.tr_type = TT_CDA;
    }
    if (arg_get_lit(ctx, 9)) {
        opts.tr_type = TT_VSDC;
    }
    opts.gen_ac_gpo = arg_get_lit(ctx, 10);
    opts.channel = arg_get_lit(ctx, 11) ? CC_CONTACT : CC_CONTACTLESS;
    CLIParserFree(ctx);

    PrintChannel(opts.channel);

    if (IfPm3Smartcard() == false && opts.channel == CC_CONTACT) {
        PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
        return PM3_EDEVNOTSUPP;
    }

    emv_term_ctx_t term_ctx;
    int res = emv_term_ctx_init(&term_ctx, &opts);
    if (res) {
        return res;
    }

    SetAPDULogging(opts.show_apdu);
    res = phase_init_run(&term_ctx);
    if (res == PM3_SUCCESS) {
        res = phase_oda_run(&term_ctx);
    }
    if (res == PM3_SUCCESS) {
        res = emv_transaction_genac1(&term_ctx);
    }

    DropFieldEx(opts.channel);
    emv_term_ctx_free(&term_ctx);
    SetAPDULogging(false);

    if (res) {
        return res;
    }

    PrintAndLogEx(SUCCESS, "\n* Transaction completed.");
    return PM3_SUCCESS;
}


static int CmdEMVScan(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv scan",
                  "Scan EMV card and save it contents to a file.\n"
                  "It executes EMV contactless transaction and saves result to a file which can be used for emulation\n",
                  "emv scan -at -> scan MSD transaction mode and show APDU and TLV\n"
                  "emv scan -c -> scan CDA transaction mode\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("t",  "tlv",      "TLV decode results"),
        arg_lit0("e",  "extract",  "Extract TLV elements and fill Application Data"),
        arg_lit0("j",  "jload",    "Load transaction parameters from `emv_defparams.json` file"),
        arg_rem("By default:",     "Transaction type - MSD"),
        arg_lit0(NULL,  "qvsdc",   "Transaction type - qVSDC or M/Chip"),
        arg_lit0("c",  "qvsdccda", "Transaction type - qVSDC or M/Chip plus CDA (SDAD generation)"),
        arg_lit0("x",  "vsdc",     "Transaction type - VSDC. For test only. Not a standard behavior"),
        arg_lit0("g",  "acgpo",    "VISA. generate AC from GPO"),
        arg_lit0("m",  "merge",    "Merge output file with card's data. (warning: the file may be corrupted!)"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_str1(NULL,  NULL,      "<fn>", "JSON output file name"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool show_apdu = arg_get_lit(ctx, 1);
    bool decodeTLV = arg_get_lit(ctx, 2);
    bool extractTLVElements = arg_get_lit(ctx, 3);
    bool paramLoadJSON = arg_get_lit(ctx, 4);

    enum TransactionType TrType = TT_MSD;
    if (arg_get_lit(ctx, 6)) {
        TrType = TT_QVSDCMCHIP;
    }
    if (arg_get_lit(ctx, 7)) {
        TrType = TT_CDA;
    }
    if (arg_get_lit(ctx, 8)) {
        TrType = TT_VSDC;
    }

    bool GenACGPO = arg_get_lit(ctx, 9);
    bool MergeJSON = arg_get_lit(ctx, 10);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 11)) {
        channel = CC_CONTACT;
    }

    PrintChannel(channel);

    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;

    uint8_t filename[FILE_PATH_SIZE] = {0};
    int filenamelen = sizeof(filename) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 12, filename, &filenamelen);

    CLIParserFree(ctx);

    if (IfPm3Smartcard() == false) {
        if (channel == CC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support, exiting");
            return PM3_EDEVNOTSUPP;
        }
    }

    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint8_t ODAI_list[4096];
    size_t ODAI_listlen = 0;
    uint16_t sw = 0;
    int res;

    json_t *root;
    json_error_t error;

    // current path + file name
    if (MergeJSON) {

        root = json_load_file((char *)filename, 0, &error);
        if (!root) {
            PrintAndLogEx(ERR, "Json error on line %d: %s", error.line, error.text);
            return PM3_EFILE;
        }

        if (!json_is_object(root)) {
            PrintAndLogEx(ERR, "Invalid json format. root must be an object");
            return PM3_EFILE;
        }
    } else {
        root = json_object();
    }

    SetAPDULogging(show_apdu);

    // drop field at start
    DropFieldEx(channel);

    JsonSaveStr(root, "$.File.Created", "proxmark3 `emv scan`");

    if (channel == CC_CONTACTLESS) {
        // iso 14443 select
        PrintAndLogEx(INFO, "GET UID, ATS");

        iso14a_card_select_t card;
        if (Hf14443_4aGetCardData(&card) != PM3_SUCCESS) {
            return PM3_ERFTRANS;
        }

        JsonSaveStr(root, "$.Card.Contactless.Communication", "iso14443-4a");
        JsonSaveBufAsHex(root, "$.Card.Contactless.UID", (uint8_t *)&card.uid, card.uidlen);
        JsonSaveHex(root, "$.Card.Contactless.ATQA", card.atqa[0] + (card.atqa[1] << 2), 2);
        JsonSaveHex(root, "$.Card.Contactless.SAK", card.sak, 0);
        JsonSaveBufAsHex(root, "$.Card.Contactless.ATS", (uint8_t *)card.ats, card.ats_len);
    } else {
        PrintAndLogEx(INFO, "GET ATR");

        smart_card_atr_t card;
        smart_select(true, &card);
        if (!card.atr_len) {
            PrintAndLogEx(ERR, "Can't get ATR from a smart card.");
            return PM3_ERFTRANS;
        }

        JsonSaveStr(root, "$.Card.Contact.Communication", "iso7816");
        JsonSaveBufAsHex(root, "$.Card.Contact.ATR", (uint8_t *)card.atr, card.atr_len);
    }

    // init applets list tree
    const char *al = "Applets list";
    struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // EMV PPSE
    PrintAndLogEx(INFO, "PPSE");
    res = EMVSelectPSE(channel, true, true, 2, buf, sizeof(buf), &len, &sw);

    if (!res && sw == ISO7816_OK) {
        if (decodeTLV)
            TLVPrintFromBuffer(buf, len);

        JsonSaveBufAsHex(root, "$.PPSE.AID", (uint8_t *)"2PAY.SYS.DDF01", 14);

        struct tlvdb *fci = tlvdb_parse_multi(buf, len);
        if (extractTLVElements)
            JsonSaveTLVTree(root, root, "$.PPSE.FCITemplate", fci);
        else
            JsonSaveTLVTreeElm(root, "$.PPSE.FCITemplate", fci, true, true, false);
        JsonSaveTLVValue(root, "$.Application.KernelID", tlvdb_find_full(fci, 0x9f2a));
        tlvdb_free(fci);
    }

    res = EMVSearchPSE(channel, false, true, psenum, decodeTLV, tlvSelect);

    // check PPSE and select application id
    if (!res) {
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    } else {
        // EMV SEARCH with AID list
        SetAPDULogging(false);
        PrintAndLogEx(INFO, "AID search.");
        if (EMVSearch(channel, false, true, decodeTLV, tlvSelect, false)) {
            PrintAndLogEx(ERR, "Can't found any of EMV AID, exiting...");
            tlvdb_free(tlvSelect);
            DropFieldEx(channel);
            return PM3_ERFTRANS;
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    }

    // EMV SELECT application
    SetAPDULogging(show_apdu);
    EMVSelectApplication(tlvSelect, AID, &AIDlen);

    tlvdb_free(tlvSelect);

    if (!AIDlen) {
        PrintAndLogEx(INFO, "Can't select AID. EMV AID not found, exiting...");
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    JsonSaveBufAsHex(root, "$.Application.AID", AID, AIDlen);

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // EMV SELECT applet

    PrintAndLogEx(INFO, "Selecting AID: " _GREEN_("%s"), sprint_hex_inrow(AID, AIDlen));
    SetAPDULogging(show_apdu);
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(ERR, "Can't select AID (%d), exiting...", res);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    if (decodeTLV)
        TLVPrintFromBuffer(buf, len);

    // save mode
    if (tlvdb_get(tlvRoot, 0x9f38, NULL)) {
        JsonSaveStr(root, "$.Application.Mode", TransactionTypeStr[TrType]);
    }

    struct tlvdb *fci = tlvdb_parse_multi(buf, len);
    if (extractTLVElements)
        JsonSaveTLVTree(root, root, "$.Application.FCITemplate", fci);
    else
        JsonSaveTLVTreeElm(root, "$.Application.FCITemplate", fci, true, true, false);

    tlvdb_free(fci);

    // create transaction parameters
    PrintAndLogEx(INFO, "Init transaction parameters");
    InitTransactionParameters(tlvRoot, paramLoadJSON, TrType, GenACGPO);

    PrintAndLogEx(INFO, "Calc PDOL");
    struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Can't create PDOL TLV");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data");
        tlvdb_free(tlvRoot);
        free(pdol_data_tlv);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%zu]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "GPO");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    free(pdol_data_tlv);

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x, exiting...", res, sw);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }
    ProcessGPOResponseFormat1(tlvRoot, buf, len, decodeTLV);

    struct tlvdb *gpofci = tlvdb_parse_multi(buf, len);
    if (extractTLVElements)
        JsonSaveTLVTree(root, root, "$.Application.GPO", gpofci);
    else
        JsonSaveTLVTreeElm(root, "$.Application.GPO", gpofci, true, true, false);

    JsonSaveTLVValue(root, "$.ApplicationData.AIP", tlvdb_find_full(gpofci, 0x82));
    JsonSaveTLVValue(root, "$.ApplicationData.AFL", tlvdb_find_full(gpofci, 0x94));

    tlvdb_free(gpofci);

    PrintAndLogEx(INFO, "Read records from AFL");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(ERR, "Wrong AFL length: %zu", AFL->len);
            break;
        }

        json_t *sfijson = json_path_get(root, "$.Application.Records");
        if (!sfijson) {
            json_t *app = json_path_get(root, "$.Application");
            json_object_set_new(app, "Records", json_array());

            sfijson = json_path_get(root, "$.Application.Records");
        }

        if (!json_is_array(sfijson)) {
            PrintAndLogEx(ERR, "Internal logic error. `$.Application.Records` is not an array.");
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];
            bool first_time = SFIoffline;

            PrintAndLogEx(INFO, "   SFI[%02x] start:%02x end:%02x offline:%02x", SFI, SFIstart, SFIend, SFIoffline);
            if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                PrintAndLogEx(ERR, "SFI ERROR! Skipped...");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "     SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                // Build Input list for Offline Data Authentication
                // EMV 4.3 book3 10.3, page 96
                if (first_time && SFIoffline) {
                    if (SFI < 11) {
                        const unsigned char *abuf = buf;
                        size_t elmlen = len;
                        struct tlv e;
                        if (tlv_parse_tl(&abuf, &elmlen, &e)) {
                            memcpy(ODAI_list + ODAI_listlen, &buf[len - elmlen], elmlen);
                            ODAI_listlen += elmlen;
                        } else {
                            PrintAndLogEx(WARNING, "Error SFI[%02x]. Creating input list for Offline Data Authentication error", SFI);
                        }
                    } else {
                        memcpy(ODAI_list + ODAI_listlen, buf, len);
                        ODAI_listlen += len;
                    }
                    first_time = false;
                }

                if (decodeTLV) {
                    TLVPrintFromBuffer(buf, len);
                    PrintAndLogEx(NORMAL, "");
                }

                json_t *jsonelm = json_object();
                json_array_append_new(sfijson, jsonelm);

                JsonSaveHex(jsonelm, "SFI", SFI, 1);
                JsonSaveHex(jsonelm, "RecordNum", n, 1);
                JsonSaveHex(jsonelm, "Offline", SFIoffline, 1);

                struct tlvdb *rsfi = tlvdb_parse_multi(buf, len);
                if (extractTLVElements) {
                    JsonSaveTLVTree(root, jsonelm, "$.Data", rsfi);
                } else {
                    JsonSaveTLVTreeElm(jsonelm, "$.Data", rsfi, true, true, false);
                }
                tlvdb_free(rsfi);
            }
        }
        break;
    }

    // copy Input list for Offline Data Authentication
    if (ODAI_listlen) {
        struct tlvdb *oda = tlvdb_fixed(0x21, ODAI_listlen, ODAI_list); // not a standard tag
        tlvdb_add(tlvRoot, oda);
        PrintAndLogEx(INFO, "Input list for Offline Data Authentication added to TLV [%zu bytes]", ODAI_listlen);
    }

    // getting certificates
    if (tlvdb_get(tlvRoot, 0x90, NULL)) {
        PrintAndLogEx(INFO, "Recovering certificates");
        PKISetStrictExecution(false);
        RecoveryCertificates(tlvRoot, root);
        PKISetStrictExecution(true);
    }

    // free tlv object
    tlvdb_free(tlvRoot);

    DropFieldEx(channel);
    SetAPDULogging(false);

    if (MergeJSON == false) {
        // create unique new name
        char *fname = newfilenamemcopy((char *)filename, ".json");
        if (fname == NULL) {
            return PM3_EMALLOC;
        }
        strcpy((char *)filename, fname);
        free(fname);
    }

    res = json_dump_file(root, (char *)filename, JSON_INDENT(2));
    if (res) {
        PrintAndLogEx(ERR, "Can't save the file: %s", filename);
        return PM3_EFILE;
    }

    PrintAndLogEx(SUCCESS, "File " _YELLOW_("`%s`") " saved.", filename);

    // free json object
    json_decref(root);
    return PM3_SUCCESS;
}

static int CmdEMVList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "emv", "7816");
}

static int CmdEMVTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv test",
                  "Executes tests\n",
                  "emv test -i\n"
                  "emv test --long\n"
                  "emv test --pin-audit"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("i", "ignore", "Ignore timing tests for VM"),
        arg_lit0("l", "long",   "Run long tests too"),
        arg_lit0(NULL, "pin-audit", "Verify PIN buffer zeroization (lab audit)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool ignoreTimeTest = arg_get_lit(ctx, 1);
    bool runSlowTests = arg_get_lit(ctx, 2);
    bool pinAudit = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    return ExecuteCryptoTests(true, ignoreTimeTest, runSlowTests, pinAudit);
}

static int CmdEMVRoca(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv roca",
                  "Tries to extract public keys and run the ROCA test against them.\n",
                  "emv roca -w  -> select --CONTACT-- card and run test\n"
                  "emv roca     -> select --CONTACTLESS-- card and run test\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "test",   "Perform self tests"),
        arg_lit0("a",  "apdu",     "Show APDU requests and responses"),
        arg_lit0("w",  "wired",    "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    if (arg_get_lit(ctx, 1)) {
        CLIParserFree(ctx);
        return roca_self_test();
    }

    bool show_apdu = arg_get_lit(ctx, 2);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 3))
        channel = CC_CONTACT;

    CLIParserFree(ctx);
    PrintChannel(channel);

    if (IfPm3Smartcard() == false) {
        if (channel == CC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support, exiting");
            return PM3_EDEVNOTSUPP;
        }
    }

    // select card
    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;

    SetAPDULogging(show_apdu);

    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    uint8_t ODAI_list[4096];
    size_t ODAI_listlen = 0;
    int res;

    // init applets list tree
    const char *al = "Applets list";
    struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

    // EMV PPSE
    PrintAndLogEx(INFO, "PPSE");
    res = EMVSearchPSE(channel, false, true, psenum, false, tlvSelect);

    // check PPSE and select application id
    if (!res) {
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    } else {
        // EMV SEARCH with AID list
        PrintAndLogEx(INFO, "starting AID search");
        if (EMVSearch(channel, false, true, false, tlvSelect, false)) {
            PrintAndLogEx(ERR, "Can't found any of EMV AID, exiting");
            tlvdb_free(tlvSelect);
            DropFieldEx(channel);
            SetAPDULogging(false);
            return PM3_ERFTRANS;
        }

        // check search and select application id
        TLVPrintAIDlistFromSelectTLV(tlvSelect);
    }

    // EMV SELECT application
    SetAPDULogging(false);
    EMVSelectApplication(tlvSelect, AID, &AIDlen);

    tlvdb_free(tlvSelect);

    if (!AIDlen) {
        PrintAndLogEx(INFO, "Can't select AID or EMV AID not found, exiting");
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    // Init TLV tree
    const char *alr = "Root terminal TLV tree";
    struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

    // EMV SELECT applet
    PrintAndLogEx(INFO, "Selecting AID: " _YELLOW_("%s"), sprint_hex_inrow(AID, AIDlen));
    res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);

    if (res) {
        PrintAndLogEx(ERR, "Can't select AID (%d), exiting", res);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }

    PrintAndLogEx(INFO, "Init transaction parameters");
    InitTransactionParameters(tlvRoot, true, TT_QVSDCMCHIP, false);

    PrintAndLogEx(INFO, "Calc PDOL");
    struct tlv *pdol_data_tlv = dol_process(tlvdb_get(tlvRoot, 0x9f38, NULL), tlvRoot, 0x83);
    if (!pdol_data_tlv) {
        PrintAndLogEx(ERR, "Can't create PDOL TLV");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ESOFT;
    }

    size_t pdol_data_tlv_data_len;
    unsigned char *pdol_data_tlv_data = tlv_encode(pdol_data_tlv, &pdol_data_tlv_data_len);
    if (!pdol_data_tlv_data) {
        PrintAndLogEx(ERR, "Can't create PDOL data, exiting");
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        free(pdol_data_tlv);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "PDOL data[%zu]: %s", pdol_data_tlv_data_len, sprint_hex(pdol_data_tlv_data, pdol_data_tlv_data_len));

    PrintAndLogEx(INFO, "GPO");
    res = EMVGPO(channel, true, pdol_data_tlv_data, pdol_data_tlv_data_len, buf, sizeof(buf), &len, &sw, tlvRoot);

    free(pdol_data_tlv_data);
    free(pdol_data_tlv);

    if (res) {
        PrintAndLogEx(ERR, "GPO error(%d): %4x, exiting", res, sw);
        tlvdb_free(tlvRoot);
        DropFieldEx(channel);
        return PM3_ERFTRANS;
    }
    ProcessGPOResponseFormat1(tlvRoot, buf, len, false);

    PrintAndLogEx(INFO, "Read records from AFL");
    const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);

    while (AFL && AFL->len) {
        if (AFL->len % 4) {
            PrintAndLogEx(ERR, "Wrong AFL length: %zu", AFL->len);
            break;
        }

        for (int i = 0; i < AFL->len / 4; i++) {
            uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
            uint8_t SFIstart = AFL->value[i * 4 + 1];
            uint8_t SFIend = AFL->value[i * 4 + 2];
            uint8_t SFIoffline = AFL->value[i * 4 + 3];

            PrintAndLogEx(INFO, "   SFI[%02x] start :%02x end :%02x  offline :%02x", SFI, SFIstart, SFIend, SFIoffline);
            if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                PrintAndLogEx(ERR, "SFI ERROR, skipping");
                continue;
            }

            for (int n = SFIstart; n <= SFIend; n++) {
                PrintAndLogEx(INFO, "      SFI[%02x] %d", SFI, n);

                res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    PrintAndLogEx(ERR, "SFI[%02x]. APDU error %4x", SFI, sw);
                    continue;
                }

                // Build Input list for Offline Data Authentication
                // EMV 4.3 book3 10.3, page 96
                if (SFIoffline > 0) {
                    if (SFI < 11) {
                        const unsigned char *abuf = buf;
                        size_t elmlen = len;
                        struct tlv e;
                        if (tlv_parse_tl(&abuf, &elmlen, &e)) {
                            memcpy(ODAI_list + ODAI_listlen, &buf[len - elmlen], elmlen);
                            ODAI_listlen += elmlen;
                        } else {
                            PrintAndLogEx(WARNING, "Error SFI[%02x]. Creating input list for Offline Data Authentication error", SFI);
                        }
                    } else {
                        memcpy(ODAI_list + ODAI_listlen, buf, len);
                        ODAI_listlen += len;
                    }
                    SFIoffline--;
                }
            }
        }
        break;
    }

    // getting certificates
    int ret = PM3_SUCCESS;

    // copy Input list for Offline Data Authentication
    if (ODAI_listlen) {
        struct tlvdb *oda = tlvdb_fixed(0x21, ODAI_listlen, ODAI_list); // not a standard tag
        tlvdb_add(tlvRoot, oda);
        PrintAndLogEx(INFO, "Input list for Offline Data Authentication added to TLV [%zu bytes]", ODAI_listlen);
    }

    if (tlvdb_get(tlvRoot, 0x90, NULL)) {
        PrintAndLogEx(INFO, "Recovering certificates");
        PKISetStrictExecution(false);

        struct emv_pk *pk = get_ca_pk(tlvRoot);
        if (!pk) {
            PrintAndLogEx(ERR, "ERROR: Key not found, exiting");
            ret = PM3_ESOFT;
            goto out;
        }

        struct emv_pk *issuer_pk = emv_pki_recover_issuer_cert(pk, tlvRoot);
        if (!issuer_pk) {
            emv_pk_free(pk);
            PrintAndLogEx(WARNING, "WARNING: Issuer certificate not found, exiting");
            ret = PM3_ESOFT;
            goto out;
        }

        PrintAndLogEx(SUCCESS, "Issuer Public key recovered  RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                      sprint_hex(issuer_pk->rid, 5),
                      issuer_pk->index,
                      sprint_hex(issuer_pk->serial, 3)
                     );


        const struct tlv *sda_tlv = tlvdb_get(tlvRoot, 0x21, NULL);
        struct emv_pk *icc_pk = emv_pki_recover_icc_cert(issuer_pk, tlvRoot, sda_tlv);
        if (!icc_pk) {
            emv_pk_free(pk);
            emv_pk_free(issuer_pk);
            PrintAndLogEx(WARNING, "WARNING: ICC certificate not found, exiting");
            ret = PM3_ESOFT;
            goto out;
        }

        PrintAndLogEx(SUCCESS, "ICC Public key recovered     RID " _YELLOW_("%s") " IDX " _YELLOW_("%02hhx") " CSN " _YELLOW_("%s"),
                      sprint_hex(icc_pk->rid, 5),
                      icc_pk->index,
                      sprint_hex(icc_pk->serial, 3)
                     );

        PrintAndLogEx(INFO, "ICC Public key modulus:");
        print_hex_break(icc_pk->modulus, icc_pk->mlen, 16);

        // icc_pk->exp, icc_pk->elen
        // icc_pk->modulus, icc_pk->mlen
        if (icc_pk->elen > 0 && icc_pk->mlen > 0) {
            PrintAndLogEx(NORMAL, "");
            if (emv_rocacheck(icc_pk->modulus, icc_pk->mlen, false)) {
                PrintAndLogEx(SUCCESS, "ICC Public key is " _RED_("subject") " to ROCA vulnerability, it is considered insecure");
            } else {
                PrintAndLogEx(INFO, "ICC Public key is " _GREEN_("not subject") " to ROCA vulnerability, it is secure");
            }
        }

        PKISetStrictExecution(true);
    }

out:
    SetAPDULogging(false);
    tlvdb_free(tlvRoot);
    DropFieldEx(channel);
    return ret;
}

static int CmdEMVReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "emv reader",
                  "Act as a EMV reader to identify tag. Look for EMV tags until Enter or the pm3 button is pressed\n"
                  "In `verbose` mode it will also try to extract and decode the transaction logs stored on card in either channel.\n",
                  "emv reader\n"
                  "emv reader -v\n"
                  "emv reader -@     -> Continuous mode\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("w", "wired", "Send data via contact (iso7816) interface. (def: Contactless interface)"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_lit0("@",  NULL,   "continuous reader mode"),
        arg_str0(NULL, "terminal-session", "<file>", "Append reader observations to session JSON"),
        arg_lit0(NULL, "terminal-compare", "Hint: diff reader vs terminal APDU patterns"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    Iso7816CommandChannel channel = CC_CONTACTLESS;
    if (arg_get_lit(ctx, 1)) {
        channel = CC_CONTACT;
    }

    uint8_t psenum = (channel == CC_CONTACT) ? 1 : 2;
    bool verbose = arg_get_lit(ctx, 2);
    bool continuous = arg_get_lit(ctx, 3);
    const char *term_session = arg_get_str(ctx, 4)->sval[0];
    bool term_compare = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (term_compare) {
        emv_term_reader_compare_hint();
    }

    if (channel == CC_CONTACT && IfPm3Smartcard() == false) {
        PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support. Exiting.");
        return PM3_EDEVNOTSUPP;
    }

    if (continuous) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    bool old_logging = GetAPDULogging();
    SetAPDULogging(verbose);

    uint8_t AID[APDU_AID_LEN] = {0};
    size_t AIDlen = 0;
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    int res = 0;
    uint16_t sw = 0;

    do {
        if (continuous && kbd_enter_pressed()) {
            break;
        }

        // init applets list tree
        const char *al = "Applets";
        struct tlvdb *tlvSelect = tlvdb_fixed(1, strlen(al), (const unsigned char *)al);

        res = EMVSelectPSE(channel, true, true, 2, buf, sizeof(buf), &len, &sw);

        // search PSE / PPSE
        res |= EMVSearchPSE(channel, false, true, psenum, false, tlvSelect);
        if (res) {
            // EMV SEARCH with AID list
            DropFieldEx(channel);
            if (EMVSearch(channel, true, true, false, tlvSelect, false)) {
                tlvdb_free(tlvSelect);
                DropFieldEx(channel);
                continue;
            }
        }

        // select application
        EMVSelectApplication(tlvSelect, AID, &AIDlen);
        tlvdb_free(tlvSelect);

        if (AIDlen == 0) {
            DropFieldEx(channel);
            continue;
        }

        // Init TLV tree
        const char *alr = "Root";
        struct tlvdb *tlvRoot = tlvdb_fixed(1, strlen(alr), (const unsigned char *)alr);

        // EMV SELECT applet
        res = EMVSelect(channel, false, true, AID, AIDlen, buf, sizeof(buf), &len, &sw, tlvRoot);
        if (res) {
            DropFieldEx(channel);
            continue;
        }

        // decode application parts
        emv_parse_card_details(buf, len, verbose);

        if (term_session && term_session[0]) {
            char note[128] = {0};
            snprintf(note, sizeof(note), "reader select AID=%s", sprint_hex_inrow(AID, AIDlen));
            emv_term_reader_session_log(term_session, sprint_hex_inrow(AID, AIDlen), note);
        }

        // transaction log information
        uint8_t log_file_id = 0x0B;
        uint8_t log_file_records = 31;
        struct tlvdb *tlogDB = NULL;

        // try getting the LOG TEMPLATE.
        bool log_found = false;
        bool log_template_found = false;
        if (emv_extract_log_info(buf, len, &log_file_id, &log_file_records) == PM3_SUCCESS) {
            log_found = true;
        }

        uint16_t extra_data[] = { 0x9F36, 0x9F13, 0x9F17, 0x9F4D, 0x9F4F };
        for (int i = 0; i < ARRAYLEN(extra_data); i++) {
            if (EMVGetData(channel, true, extra_data[i], buf, sizeof(buf), &len, &sw, tlvRoot)) {
                continue;
            }
            // Log template tag
            if (extra_data[i] == 0x9F4F)  {
                struct tlvdb *ttdb = tlvdb_find_full(tlvRoot, extra_data[i]);
                const struct tlv *ttag = tlvdb_get_tlv(ttdb);
                tlogDB = emv_logtemplate_parse(ttag, buf, len);
                log_template_found = true;
            }
        }

        for (TransactionType_t tt = TT_MSD; tt < TT_END; tt++) {

            // create transaction parameters
            bool gen_acgpo = false;
            InitTransactionParameters(tlvRoot, false, tt, gen_acgpo);

            struct tlv *pdol_tlv = dol_process(tlvdb_get(tlvRoot, 0x9F38, NULL), tlvRoot, 0x83);
            if (!pdol_tlv) {
                continue;
            }

            size_t pdtd_len = 0;
            unsigned char *pdol_data_tlv = tlv_encode(pdol_tlv, &pdtd_len);
            if (!pdol_data_tlv) {
                free(pdol_tlv);
                continue;
            }

            res = EMVGPO(channel, true, pdol_data_tlv, pdtd_len, buf, sizeof(buf), &len, &sw, tlvRoot);
            free(pdol_data_tlv);
            free(pdol_tlv);

            if (res) {
                continue;
            }

            ProcessGPOResponseFormat1(tlvRoot, buf, len, false);

            emv_parse_card_details(buf, len, verbose);

            if (tlvdb_get(tlvRoot, 0x77, NULL)) {
                break;
            }
        }

        const struct tlv *AFL = tlvdb_get(tlvRoot, 0x94, NULL);
        if (AFL && AFL->len) {

            if (AFL->len % 4) {
                continue;
            }

            for (int i = 0; i < AFL->len / 4; i++) {
                uint8_t SFI = AFL->value[i * 4 + 0] >> 3;
                uint8_t SFIstart = AFL->value[i * 4 + 1];
                uint8_t SFIend = AFL->value[i * 4 + 2];

                if (SFI == 0 || SFI == 31 || SFIstart == 0 || SFIstart > SFIend) {
                    continue;
                }

                for (int n = SFIstart; n <= SFIend; n++) {
                    res = EMVReadRecord(channel, true, SFI, n, buf, sizeof(buf), &len, &sw, tlvRoot);
                    if (res) {
                        continue;
                    }
                    emv_parse_card_details(buf, len, verbose);
                }
            }
        }

        // only check for logs file if we found 0x9F4D
        if (verbose && log_found  && log_template_found) {

            for (int i = 1; i <= log_file_records; i++) {
                res = EMVReadRecord(channel, true, log_file_id, i, buf, sizeof(buf), &len, &sw, tlvRoot);
                if (res) {
                    continue;
                }

                if (sw == 0x6A83) {
                    break;
                }

                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "Transaction log # " _YELLOW_("%u"), i);
                PrintAndLogEx(INFO, "---------------------");
                emv_parse_log(tlogDB, buf, len);
                PrintAndLogEx(INFO, "");
            }
            tlvdb_free(tlogDB);
        }

        // free tlv object
        tlvdb_free(tlvRoot);
        PrintAndLogEx(INFO, "");
    } while (continuous);

    DropFieldEx(channel);

    SetAPDULogging(old_logging);
    return PM3_SUCCESS;
}

static command_t CommandTable[] =  {
    {"-----------", CmdHelp,                        AlwaysAvailable, "----------------------- " _CYAN_("General") " -----------------------"},
    {"help",        CmdHelp,                        AlwaysAvailable, "This help"},
    {"list",        CmdEMVList,                     AlwaysAvailable, "List ISO7816 history"},
    {"test",        CmdEMVTest,                     AlwaysAvailable, "Perform crypto logic self tests"},
    {"-----------", CmdHelp,                        IfPm3Iso14443a,  "---------------------- " _CYAN_("Operations") " ---------------------"},
    {"challenge",   CmdEMVGenerateChallenge,        IfPm3Iso14443,   "Generate challenge"},
    {"exec",        CmdEMVExec,                     IfPm3Iso14443,   "Executes EMV contactless transaction"},
    {"genac",       CmdEMVAC,                       IfPm3Iso14443,   "Generate ApplicationCryptogram"},
    {"gpo",         CmdEMVGPO,                      IfPm3Iso14443,   "Execute GetProcessingOptions"},
    {"intauth",     CmdEMVInternalAuthenticate,     IfPm3Iso14443,   "Internal authentication"},
    {"pse",         CmdEMVPPSE,                     IfPm3Iso14443,   "Execute PPSE. It selects 2PAY.SYS.DDF01 or 1PAY.SYS.DDF01 directory"},
    {"reader",      CmdEMVReader,                   IfPm3Iso14443a,  "Act like an EMV reader"},
    {"readrec",     CmdEMVReadRecord,               IfPm3Iso14443,   "Read files from card"},
    {"roca",        CmdEMVRoca,                     IfPm3Iso14443,   "Extract public keys and run ROCA test"},
    {"scan",        CmdEMVScan,                     IfPm3Iso14443,   "Scan EMV card and save it contents to json file for emulator"},
    {"search",      CmdEMVSearch,                   IfPm3Iso14443,   "Try to select all applets from applets list and print installed applets"},
    {"select",      CmdEMVSelect,                   IfPm3Iso14443,   "Select applet"},
    {"-----------", CmdHelp,                        IfPm3Iso14443a,  "-------------------- " _CYAN_("terminal emulator") " --------------------"},
    {"terminal",    CmdEMVTerminal,                 AlwaysAvailable, "EMV terminal emulator (phases, PIN, profile, golden tests)"},
    {"-----------", CmdHelp,                        IfPm3Iso14443a,  "---------------------- " _CYAN_("simulation") " ---------------------"},
    {"smart2nfc",   CmdEMVSmartToNFC,               IfPm3Smartcard,  "Complete transaction as a nfc smart card, using the ISO-7816 interface for auth"},
    /*
    {"getrng",      CmdEMVGetrng,                   IfPm3Iso14443,   "Get random number from terminal"},
    {"eload",       CmdEmvELoad,                    IfPm3Iso14443,   "Load EMV tag into device"},
    {"dump",        CmdEmvDump,                     IfPm3Iso14443,   "Dump EMV tag values"},
    {"sim",         CmdEmvSim,                      IfPm3Iso14443,   "Simulate EMV tag"},
    {"clone",       CmdEmvClone,                    IfPm3Iso14443,   "Cone an EMV tag"},
    */
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdEMV(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

