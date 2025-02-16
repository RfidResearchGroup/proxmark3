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
// High frequency iClass commands
//-----------------------------------------------------------------------------

#include "cmdhficlass.h"
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"              // command_t
#include "commonutil.h"             // ARRAYLEN
#include "cmdtrace.h"
#include "util_posix.h"
#include "comms.h"
#include "des.h"
#include "loclass/cipherutils.h"
#include "loclass/cipher.h"
#include "loclass/ikeys.h"
#include "loclass/elite_crack.h"
#include "fileutils.h"
#include "protocols.h"
#include "cardhelper.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "cmdsmartcard.h"           // smart select fct
#include "proxendian.h"
#include "iclass_cmd.h"
#include "crypto/asn1utils.h"       // ASN1 decoder
#include "preferences.h"
#include "generator.h"
#include "cmdhf14b.h"
#include "cmdhw.h"
#include "hidsio.h"


#define NUM_CSNS               9
#define MAC_ITEM_SIZE          24 // csn(8) + epurse(8) + nr(4) + mac(4) = 24 bytes
#define ICLASS_KEYS_MAX        8
#define ICLASS_AUTH_RETRY      10
#define ICLASS_CFG_BLK_SR_BIT  0xA0 // indicates SIO present when set in block6[0] (legacy tags)
#define ICLASS_DECRYPTION_BIN  "iclass_decryptionkey.bin"
#define ICLASS_DEFAULT_KEY_DIC        "iclass_default_keys.dic"
#define ICLASS_DEFAULT_KEY_ELITE_DIC  "iclass_elite_keys.dic"

static void print_picopass_info(const picopass_hdr_t *hdr);
void print_picopass_header(const picopass_hdr_t *hdr);

static picopass_hdr_t iclass_last_known_card;
static void iclass_set_last_known_card(picopass_hdr_t *card) {
    memcpy(&iclass_last_known_card, card, sizeof(picopass_hdr_t));
}

static uint8_t empty[PICOPASS_BLOCK_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t zeros[PICOPASS_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int CmdHelp(const char *Cmd);
static void print_iclass_sio(uint8_t *iclass_dump, size_t dump_len);

static uint8_t iClass_Key_Table[ICLASS_KEYS_MAX][PICOPASS_BLOCK_SIZE] = {
    { 0xAE, 0xA6, 0x84, 0xA6, 0xDA, 0xB2, 0x32, 0x78 },
    { 0xFD, 0xCB, 0x5A, 0x52, 0xEA, 0x8F, 0x30, 0x90 },
    { 0xF0, 0xE1, 0xD2, 0xC3, 0xB4, 0xA5, 0x96, 0x87 },
    { 0x76, 0x65, 0x54, 0x43, 0x32, 0x21, 0x10, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
    { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }
};

static int cmp_uint32(const void *a, const void *b) {

    const iclass_prekey_t *x = (const iclass_prekey_t *)a;
    const iclass_prekey_t *y = (const iclass_prekey_t *)b;

    uint32_t mx = bytes_to_num((uint8_t *)x->mac, 4);
    uint32_t my = bytes_to_num((uint8_t *)y->mac, 4);

    if (mx < my)
        return -1;
    else
        return mx > my;
}

bool check_known_default(uint8_t *csn, uint8_t *epurse, uint8_t *rmac, uint8_t *tmac, uint8_t *key) {

    iclass_prekey_t *prekey = calloc(ICLASS_KEYS_MAX * 2, sizeof(iclass_prekey_t));
    if (prekey == NULL) {
        return false;
    }

    uint8_t ccnr[12];
    memcpy(ccnr, epurse, 8);
    memcpy(ccnr + 8, rmac, 4);

    GenerateMacKeyFrom(csn, ccnr, false, false, (uint8_t *)iClass_Key_Table, ICLASS_KEYS_MAX, prekey);
    GenerateMacKeyFrom(csn, ccnr, false, true, (uint8_t *)iClass_Key_Table, ICLASS_KEYS_MAX, prekey + ICLASS_KEYS_MAX);
    qsort(prekey, ICLASS_KEYS_MAX * 2, sizeof(iclass_prekey_t), cmp_uint32);

    iclass_prekey_t lookup;
    memcpy(lookup.mac, tmac, 4);

    // binsearch
    iclass_prekey_t *item = (iclass_prekey_t *) bsearch(&lookup, prekey, ICLASS_KEYS_MAX * 2, sizeof(iclass_prekey_t), cmp_uint32);
    if (item != NULL) {
        memcpy(key, item->key, 8);
        free(prekey);
        return true;
    }
    free(prekey);
    return false;
}

typedef enum {
    None = 0,
    DES,
    RFU,
    TRIPLEDES
} BLOCK79ENCRYPTION;

// 16 bytes key
static int iclass_load_transport(uint8_t *key, uint8_t n) {
    size_t keylen = 0;
    uint8_t *keyptr = NULL;
    int res = loadFile_safeEx(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Couldn't find any decryption methods");
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "Failed to load transport key from file");
        free(keyptr);
        return PM3_EINVARG;
    }

    if (keylen != n) {
        PrintAndLogEx(ERR, "Array size mismatch");
        free(keyptr);
        return PM3_EINVARG;
    }

    memcpy(key, keyptr, n);
    free(keyptr);
    return PM3_SUCCESS;
}

static void iclass_decrypt_transport(uint8_t *key, uint8_t limit, uint8_t *enc_data, uint8_t *dec_data,  BLOCK79ENCRYPTION aa1_encryption) {

    // tripledes
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);

    bool decrypted_block789 = false;
    for (uint8_t i = 0; i < limit; ++i) {

        uint16_t idx = i * PICOPASS_BLOCK_SIZE;

        switch (aa1_encryption) {
            // Right now, only 3DES is supported
            case TRIPLEDES:
                // Decrypt block 7,8,9 if configured.
                if (i > 6 && i <= 9 && memcmp(enc_data + idx, empty, PICOPASS_BLOCK_SIZE) != 0) {
                    mbedtls_des3_crypt_ecb(&ctx, enc_data + idx, dec_data + idx);
                    decrypted_block789 = true;
                }
                break;
            case DES:
            case RFU:
            case None:
            // Nothing to do for None anyway...
            default:
                continue;
        }

        if (decrypted_block789) {
            // Set the 2 last bits of block6 to 0 to mark the data as decrypted
            dec_data[(6 * PICOPASS_BLOCK_SIZE) + 7] &= 0xFC;
        }
    }

    mbedtls_des3_free(&ctx);
}

static inline uint32_t leadingzeros(uint64_t a) {
#if defined __GNUC__
    return __builtin_clzll(a);
#else
    return 0;
#endif
}

static void iclass_upload_emul(uint8_t *d, uint16_t n, uint16_t offset, uint16_t *bytes_sent) {

    struct p {
        uint16_t offset;
        uint16_t len;
        uint8_t data[];
    } PACKED;

    // fast push mode
    g_conn.block_after_ACK = true;

    //Send to device
    *bytes_sent = 0;
    uint16_t bytes_remaining = n;

    PrintAndLogEx(INFO, "Uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(PM3_CMD_DATA_SIZE - 4, bytes_remaining);
        if (bytes_in_packet == bytes_remaining) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }

        struct p *payload = calloc(4 + bytes_in_packet, sizeof(uint8_t));
        payload->offset = offset + *bytes_sent;
        payload->len = bytes_in_packet;
        memcpy(payload->data, d + *bytes_sent, bytes_in_packet);

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_EML_MEMSET, (uint8_t *)payload, 4 + bytes_in_packet);
        free(payload);

        bytes_remaining -= bytes_in_packet;
        *bytes_sent += bytes_in_packet;

        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "");
}

static const char *card_types[] = {
    "PicoPass 16K / 16",                       // 000
    "PicoPass 32K with current book 16K / 16", // 001
    "Unknown Card Type!",                      // 010
    "Unknown Card Type!",                      // 011
    "PicoPass 2K",                             // 100
    "Unknown Card Type!",                      // 101
    "PicoPass 16K / 2",                        // 110
    "PicoPass 32K with current book 16K / 2",  // 111
};

static uint8_t card_app2_limit[] = {
    0x1f,
    0xff,
    0xff,
    0xff,
    0x1f,
    0xff,
    0xff,
    0xff,
};

static iclass_config_card_item_t iclass_config_options[33] =  {
    //Byte A8 - LED Operations
    {"(LED) - Led idle (Off) / Led read (Off)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x0F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Red) / Led read (Off)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x1F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Grn) / Led read (Off)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Amber) / Led read (Off)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x3F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Off) / Led read (Red)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x4F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Red) / Led read (Red)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x5F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Grn) / Led read (Red)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x6F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Amber) / Led read (Red)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x7F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Off) / Led read (Grn)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x8F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Red) / Led read (Grn)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0x9F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Grn) / Led read (Grn)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0xAF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Amber) / Led read (Red)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0xBF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Off) / Led read (Amber)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0xCF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Red) / Led read (Amber)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0xDF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Grn) / Led read (Amber)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0xEF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(LED) - Led idle (Amber) / Led read (Amber)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA8, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    //Byte A9 - Potentially associated with led blinking / led heartbeat operations?
    //Byte A6 - Potentially associated with beep pitch?
    //Byte A7 - BEEP Operations
    {"(BEEP) - Beep on Read (On)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA7, 0x80, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(BEEP) - Beep on Read (Off)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xA7, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    //Byte AC - MIFARE CSN Operations
    {"(MIFARE) - CSN Default Output", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAC, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(MIFARE) - CSN 32 bit Reverse Output", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAC, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(MIFARE) - CSN 16 bit Output", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAC, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(MIFARE) - CSN 34 bit Output", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAC, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    //Bytes AD, AE, AF, B3 - Keypad Operations + not fully mapped
    {"(KEYPAD Output) - Buffer ONE key (8 bit Dorado)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAE, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(KEYPAD Output) - Buffer ONE to FIVE keys (standard 26 bit)", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAE, 0x0B, 0xAF, 0xFF, 0xAD, 0x15, 0xB3, 0x03}},
    {"(KEYPAD Output) - Local PIN verify", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xBF, 0x18, 0xAD, 0x6D, 0xB3, 0x03, 0x00, 0x00, 0x00, 0x00}},
    //iClass Elite Key Operations
    {"(ELITE Key) - Set ELITE Key and Enable Dual key (Elite + Standard)", {0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0xBF, 0x18, 0xBF, 0x01, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"(ELITE Key) - Set ELITE Key and ENABLE Keyrolling", {0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0xBF, 0x18, 0xBF, 0x03, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    {"(ELITE Key) - Set ELITE Key and DISABLE Standard Key", {0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0xBF, 0x18, 0xBF, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    //Erroneous / incorrect reader behaviors (read below)
    //Elite Bugger:
    //Sets block 3 of card 0 presented to the reader to 0, sets block 3 of card 1 presented to the reader to the original value of card 0's block 3
    //Continues setting block 3 of presented cards to block 3 of the previous card the reader scanned
    //This renders cards unreadable and hardly recoverable unless the order of the scanned cards is known.
    {"(ELITE Bugger) - Renders cards unusable.", {0x0C, 0x00, 0x00, 0x01, 0x00, 0x00, 0xBF, 0x18, 0xBF, 0x02, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}},
    //Reset Operations
    {"(RESET) - Reset READER to defaults", {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(RESET) - Reset ENROLLER to defaults", {0x06, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C, 0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0xFF, 0xFF, 0xFF}},
    //Reader Master Key Operations
    {"(MASTER Key) - Change Reader Master Key to Custom Key", {0x28, 0xCB, 0x91, 0x9D, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}},
    {"(MASTER Key) - Restore Reader Master Key to Factory Defaults", {0x28, 0xCB, 0x91, 0x9D, 0x00, 0x00, 0x00, 0x1C, 0xE0, 0x5C, 0x91, 0xCF, 0x63, 0x34, 0x23, 0xB9}}
};

static const iclass_config_card_item_t *get_config_card_item(int idx) {
    if (idx > -1 && idx < ARRAYLEN(iclass_config_options)) {
        return &iclass_config_options[idx];
    }
    return &iclass_config_options[ARRAYLEN(iclass_config_options)];
}

static void print_config_cards(void) {
    PrintAndLogEx(INFO, "---- " _CYAN_("Config cards options") " ------------");
    for (int i = 0; i < ARRAYLEN(iclass_config_options)   ; ++i) {
        PrintAndLogEx(INFO, "%2d, %s", i, iclass_config_options[i].desc);
    }
    PrintAndLogEx(NORMAL, "");
}

static void iclass_encrypt_block_data(uint8_t *blk_data, uint8_t *key) {
    uint8_t encrypted_data[16];
    uint8_t *encrypted = encrypted_data;
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_enc(&ctx, key);
    mbedtls_des3_crypt_ecb(&ctx, blk_data, encrypted);
    memcpy(blk_data, encrypted, 8);
    mbedtls_des3_free(&ctx);
}

static int generate_config_card(const iclass_config_card_item_t *o,  uint8_t *key, bool got_kr, uint8_t *card_key, bool got_eki, bool use_elite, bool got_mk, uint8_t *master_key) {

    // generated config card header
    picopass_hdr_t configcard;
    memset(&configcard, 0xFF, sizeof(picopass_hdr_t));
    memcpy(configcard.csn, "\x41\x87\x66\x00\xFB\xFF\x12\xE0", 8);
    memcpy(&configcard.conf, "\xFF\xFF\xFF\xFF\xF9\xFF\xFF\xBC", 8);
    memcpy(&configcard.epurse, "\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8);

    if (got_eki) {
        HFiClassCalcDivKey(configcard.csn, card_key, configcard.key_d, use_elite);
    } else {
        // defaulting to AA1 ki 0
        HFiClassCalcDivKey(configcard.csn, iClass_Key_Table[0], configcard.key_d, use_elite);
    }

    // reference
    picopass_hdr_t *cc = &configcard;

    // get header from card
    PrintAndLogEx(INFO, "trying to read a card..");
    int res = read_iclass_csn(false, false, false);
    if (res == PM3_SUCCESS) {
        cc = &iclass_last_known_card;
        // calc diversified key for selected card
        if (got_eki) {
            HFiClassCalcDivKey(cc->csn, card_key, cc->key_d, use_elite);
        } else {
            // defaulting to AA1 ki 0
            HFiClassCalcDivKey(cc->csn, iClass_Key_Table[0], cc->key_d, use_elite);
        }
    } else {
        PrintAndLogEx(FAILED, "failed to read a card");
        PrintAndLogEx(INFO, "falling back to default config card");
    }
    PrintAndLogEx(INFO, "Generating "_YELLOW_("%s"), o->desc);

    // generate dump file
    uint8_t app1_limit = cc->conf.app_limit;
    uint8_t old_limit = app1_limit;
    uint16_t tot_bytes = (app1_limit + 1) * 8;

    PrintAndLogEx(INFO, " APP1 limit: %u", app1_limit);
    PrintAndLogEx(INFO, "total bytes: %u", tot_bytes);
    // normal size
    uint8_t *data = calloc(1, tot_bytes);
    if (data == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    memcpy(data, cc, sizeof(picopass_hdr_t));

    print_picopass_header(cc);
    // KEYROLL need to encrypt
    uint8_t key_en[16] = {0};
    uint8_t *keyptr_en = NULL;
    size_t keylen = 0;
    int res_key = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr_en, &keylen);
    if (res_key != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Failed to find iclass_decryptionkey.bin");
        free(data);
        return PM3_EINVARG;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "Failed to load transport key from file");
        free(keyptr_en);
        free(data);
        return PM3_EINVARG;
    }
    memcpy(key_en, keyptr_en, sizeof(key_en));
    free(keyptr_en);

    // Keyrolling configuration cards are special.
    if (strstr(o->desc, "ELITE") != NULL) {

        if (got_kr == false) {
            PrintAndLogEx(ERR, "please specify ELITE key!");
            free(data);
            return PM3_EINVARG;
        }

        if (app1_limit < 0x16) {
            // if card wasn't large enough before,  adapt to new size
            PrintAndLogEx(WARNING, "Adapting applimit1 for KEY rolling..");

            app1_limit = 0x16;
            cc->conf.app_limit = 0x16;
            tot_bytes = (app1_limit + 1) * 8;

            uint8_t *p = realloc(data, tot_bytes);
            if (p == NULL) {
                PrintAndLogEx(FAILED, "failed to allocate memory");
                free(data);
                return PM3_EMALLOC;
            }
            data = p;
        }

        memset(data + sizeof(picopass_hdr_t), 0xFF,  tot_bytes - sizeof(picopass_hdr_t));

        bool old = GetFlushAfterWrite();
        SetFlushAfterWrite(true);

        PrintAndLogEx(INFO, "Setting up encryption... " NOLF);
        uint8_t ffs[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        if (IsCardHelperPresent(false) != false) {
            if (Encrypt(ffs, ffs) == false) {
                PrintAndLogEx(WARNING, "failed to encrypt FF");
            } else {
                PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
            }
        } else {
            iclass_encrypt_block_data(ffs, key_en);
            PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
        }

        // local key copy
        PrintAndLogEx(INFO, "Encrypting local key... " NOLF);
        uint8_t lkey[8];
        memcpy(lkey, key, sizeof(lkey));
        uint8_t enckey1[8];
        if (IsCardHelperPresent(false) != false) {
            if (Encrypt(lkey, enckey1) == false) {
                PrintAndLogEx(WARNING, "failed to encrypt key1");
            } else {
                PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
            }
        } else {
            iclass_encrypt_block_data(lkey, key_en);
            PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
        }

        PrintAndLogEx(INFO, "Copy data... " NOLF);
        memcpy(data, cc, sizeof(picopass_hdr_t));
        memcpy(data + (6 * 8), o->data, sizeof(o->data));

        // encrypted keyroll key 0D
        if (IsCardHelperPresent(false) != false) {
            memcpy(data + (0x0D * 8), enckey1, sizeof(enckey1));
        } else {
            memcpy(data + (0x0D * 8), lkey, sizeof(enckey1));
        }
        // encrypted 0xFF
        for (uint8_t i = 0x0E; i < 0x13; i++) {
            memcpy(data + (i * 8), ffs, sizeof(ffs));
        }
        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");

        //Block 13 (This is needed for Rev.C readers!)
        uint8_t block_0x13[PICOPASS_BLOCK_SIZE] = {0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1C};
        memcpy(data + (0x13 * 8), block_0x13, sizeof(block_0x13));

        // encrypted partial keyroll key 14
        PrintAndLogEx(INFO, "Setting encrypted partial key14... " NOLF);
        uint8_t foo[8] = {0x15};
        memcpy(foo + 1, key, 7);
        uint8_t enckey2[8];
        if (IsCardHelperPresent(false) != false) {
            if (Encrypt(foo, enckey2) == false) {
                PrintAndLogEx(WARNING, "failed to encrypt partial 1");
            } else {
                PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
                memcpy(data + (0x14 * 8), enckey2, sizeof(enckey2));
            }
        } else {
            iclass_encrypt_block_data(foo, key_en);
            PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
            memcpy(data + (0x14 * 8), foo, sizeof(enckey2));
        }

        // encrypted partial keyroll key 15
        PrintAndLogEx(INFO, "Setting encrypted partial key15... " NOLF);
        memset(foo, 0xFF, sizeof(foo));
        foo[0] = key[7];
        if (IsCardHelperPresent(false) != false) {
            if (Encrypt(foo, enckey2) == false) {
                PrintAndLogEx(WARNING, "failed to encrypt partial 2");
            } else {
                PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
                memcpy(data + (0x15 * 8), enckey2, sizeof(enckey2));
            }
        } else {
            iclass_encrypt_block_data(foo, key_en);
            PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
            memcpy(data + (0x15 * 8), foo, sizeof(enckey2));
        }

        // encrypted 0xFF
        PrintAndLogEx(INFO, "Setting 0xFF's... " NOLF);
        for (uint16_t i = 0x16; i < (app1_limit + 1); i++) {
            memcpy(data + (i * 8), ffs, sizeof(ffs));
        }

        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");

        // revert potential modified app1_limit
        cc->conf.app_limit = old_limit;

        SetFlushAfterWrite(old);
    } else {
        memcpy(data, cc, sizeof(picopass_hdr_t));
        memcpy(data + (6 * 8), o->data, sizeof(o->data));
        if (strstr(o->desc, "Custom") != NULL) {
            if (got_mk == false) {
                PrintAndLogEx(ERR, "please specify New Master Key!");
                free(data);
                return PM3_EINVARG;
            }
            iclass_encrypt_block_data(master_key, key_en);
            memcpy(data + (0x07 * 8), master_key, PICOPASS_BLOCK_SIZE);
        }
    }

    //Send to device
    PrintAndLogEx(INFO, "Uploading to device... ");
    uint16_t bytes_sent = 0;
    iclass_upload_emul(data, tot_bytes, 0, &bytes_sent);
    free(data);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "sent " _YELLOW_("%u") " bytes of data to device emulator memory", bytes_sent);
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass eview") "` to view dump file");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass sim -t 3") "` to start simulating config card");
    return PM3_SUCCESS;
}

static uint8_t isset(uint8_t val, uint8_t mask) {
    return (val & mask);
}

static uint8_t notset(uint8_t val, uint8_t mask) {
    return !(val & mask);
}

uint8_t get_pagemap(const picopass_hdr_t *hdr) {
    return (hdr->conf.fuses & (FUSE_CRYPT0 | FUSE_CRYPT1)) >> 3;
}

static void fuse_config(const picopass_hdr_t *hdr) {

    uint16_t otp = (hdr->conf.otp[1] << 8 | hdr->conf.otp[0]);

    PrintAndLogEx(INFO, "    Raw... " _YELLOW_("%s"), sprint_hex((uint8_t *)&hdr->conf, 8));
    PrintAndLogEx(INFO, "           " _YELLOW_("%02X") " ( %3u ).............  app limit", hdr->conf.app_limit, hdr->conf.app_limit);
    PrintAndLogEx(INFO, "              " _YELLOW_("%04X") " ( %5u )......  OTP", otp, otp);
    PrintAndLogEx(INFO, "                    " _YELLOW_("%02X") "............  block write lock", hdr->conf.block_writelock);
    PrintAndLogEx(INFO, "                       " _YELLOW_("%02X") ".........  chip", hdr->conf.chip_config);
    PrintAndLogEx(INFO, "                          " _YELLOW_("%02X") "......  mem", hdr->conf.mem_config);
    PrintAndLogEx(INFO, "                             " _YELLOW_("%02X") "...  EAS", hdr->conf.eas);
    PrintAndLogEx(INFO, "                                " _YELLOW_("%02X") "  fuses", hdr->conf.fuses);

    uint8_t fuses = hdr->conf.fuses;

    PrintAndLogEx(INFO, "  Fuses:");
    if (isset(fuses, FUSE_FPERS))
        PrintAndLogEx(SUCCESS, "    mode......... " _GREEN_("Personalization (programmable)"));
    else
        PrintAndLogEx(SUCCESS, "    mode......... " _YELLOW_("Application (locked)"));

    if (isset(fuses, FUSE_CODING1)) {
        PrintAndLogEx(SUCCESS, "    coding...... RFU");
    } else {
        if (isset(fuses, FUSE_CODING0))
            PrintAndLogEx(SUCCESS, "    coding....... " _YELLOW_("ISO 14443-2 B / 15693"));
        else
            PrintAndLogEx(SUCCESS, "    coding....... " _YELLOW_("ISO 14443-B only"));
    }

    uint8_t pagemap = get_pagemap(hdr);
    switch (pagemap) {
        case 0x0:
            PrintAndLogEx(INFO, "    crypt........ No auth possible. Read only if RA is enabled");
            break;
        case 0x1:
            PrintAndLogEx(SUCCESS, "    crypt........ Non secured page");
            break;
        case 0x2:
            PrintAndLogEx(INFO, "    crypt........ Secured page, keys locked");
            break;
        case 0x03:
            PrintAndLogEx(SUCCESS, "    crypt........ Secured page, " _GREEN_("keys not locked"));
            break;
    }

    if (isset(fuses, FUSE_RA))
        PrintAndLogEx(SUCCESS, "    RA........... Read access enabled (non-secure mode)");
    else
        PrintAndLogEx(INFO, "    RA........... Read access not enabled");

    if (notset(fuses, FUSE_FPROD0) && isset(fuses, FUSE_FPROD1)) {
        PrintAndLogEx(INFO, "    PROD0/1...... Default production fuses");
    }
}

static void getMemConfig(uint8_t mem_cfg, uint8_t chip_cfg, uint8_t *app_areas, uint8_t *kb, uint8_t *books, uint8_t *pages) {
    // How to determine chip type

    // mem-bit 7 = 16K
    // mem-bit 5 = Book
    // mem-bit 4 = 2K
    // chip-bit 4 = Multi App
    *books = 1;
    *pages = 1;

    uint8_t k16 = isset(mem_cfg, 0x80);
    //uint8_t k2 = isset(mem_cfg, 0x10);
    uint8_t book = isset(mem_cfg, 0x20);

    if (isset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 2;
        *app_areas = 2;
    } else if (isset(chip_cfg, 0x10) && k16 && !book) {
        *kb = 16;
        *app_areas = 2;
    } else if (notset(chip_cfg, 0x10) && !k16 && !book) {
        *kb = 16;
        *app_areas = 16;
        *pages = 8;
    } else if (isset(chip_cfg, 0x10) && k16 && book) {
        *kb = 32;
        *app_areas = 3;
        *books = 2;
    } else if (notset(chip_cfg, 0x10) && !k16 && book) {
        *kb = 32;
        *app_areas = 17;
        *pages = 8;
        *books = 2;
    } else {
        *kb = 32;
        *app_areas = 2;
    }
}

static uint8_t get_mem_config(const picopass_hdr_t *hdr) {
    // three configuration bits that decides sizes
    uint8_t type = (hdr->conf.chip_config & 0x10) >> 2;
    // 16K bit  0 ==  1==
    type |= (hdr->conf.mem_config & 0x80) >> 6;
    //  BOOK bit 0 ==  1==
    type |= (hdr->conf.mem_config & 0x20) >> 5;
    // 2K
    //type |= (hdr->conf.mem_config & 0x10) >> 5;
    return type;
}

static void mem_app_config(const picopass_hdr_t *hdr) {
    uint8_t mem = hdr->conf.mem_config;
    uint8_t chip = hdr->conf.chip_config;
    uint8_t kb = 2;
    uint8_t app_areas = 2;
    uint8_t books = 1;
    uint8_t pages = 1;

    getMemConfig(mem, chip, &app_areas, &kb, &books, &pages);

    uint8_t type = get_mem_config(hdr);
    uint8_t app1_limit = hdr->conf.app_limit - 5; // minus header blocks
    uint8_t app2_limit = card_app2_limit[type];
    uint8_t pagemap = get_pagemap(hdr);

    PrintAndLogEx(INFO, "-------------------------- " _CYAN_("Memory") " --------------------------");

    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        PrintAndLogEx(INFO, " %u KBits ( " _YELLOW_("%u") " bytes )", kb, app2_limit * 8);
        PrintAndLogEx(INFO, "    Tag has not App Areas");
        return;
    }

    PrintAndLogEx(INFO, " %u KBits/%u App Areas ( " _YELLOW_("%u") " bytes )"
                  , kb
                  , app_areas
                  , ((app2_limit + 1) * 8) * books * pages);

    PrintAndLogEx(INFO, "    %u books / %u pages"
                  , books
                  , pages
                 );
    PrintAndLogEx(INFO, " First book / first page configuration");
    PrintAndLogEx(INFO, "    Config | 0 - 5 ( 0x00 - 0x05 ) - 6 blocks ");
    PrintAndLogEx(INFO, "    AA1    | 6 - %2d ( 0x06 - 0x%02X ) - %u blocks", app1_limit + 5, app1_limit + 5, app1_limit);
    if (app1_limit + 5 < app2_limit) {
        PrintAndLogEx(INFO, "    AA2    | %2d - %2d ( 0x%02X - 0x%02X ) - %u blocks", app1_limit + 5 + 1, app2_limit, app1_limit + 5 + 1, app2_limit, app2_limit - app1_limit);
    }
    /*
    [=]  32 KBits/3 App Areas ( 2048 bytes )
    [=]     AA1 blocks 250 { 0x06 - 0xFF (06 - 255) }
    [=]     AA2 blocks 5 { 0x100 - 0xFF (256 - 255) }
    */

    PrintAndLogEx(INFO, "------------------------- " _CYAN_("KeyAccess") " ------------------------");
    PrintAndLogEx(INFO, " * Kd, Debit key, AA1    Kc, Credit key, AA2 *");
    uint8_t keyAccess = isset(mem, 0x01);
    if (keyAccess) {
        PrintAndLogEx(INFO, "    Read AA1..... debit");
        PrintAndLogEx(INFO, "    Write AA1.... debit");
        PrintAndLogEx(INFO, "    Read AA2..... credit");
        PrintAndLogEx(INFO, "    Write AA2.... credit");
        PrintAndLogEx(INFO, "    Debit........ debit or credit");
        PrintAndLogEx(INFO, "    Credit....... credit");
    } else {
        PrintAndLogEx(INFO, "    Read AA1..... debit or credit");
        PrintAndLogEx(INFO, "    Write AA1.... credit");
        PrintAndLogEx(INFO, "    Read AA2..... debit or credit");
        PrintAndLogEx(INFO, "    Write AA2.... credit");
        PrintAndLogEx(INFO, "    Debit........ debit or credit");
        PrintAndLogEx(INFO, "    Credit....... credit");
    }
}

void print_picopass_info(const picopass_hdr_t *hdr) {
    PrintAndLogEx(INFO, "-------------------- " _CYAN_("Card configuration") " --------------------");
    fuse_config(hdr);
    mem_app_config(hdr);
}

void print_picopass_header(const picopass_hdr_t *hdr) {
    PrintAndLogEx(INFO, "--------------------------- " _CYAN_("Card") " ---------------------------");
    PrintAndLogEx(SUCCESS, "    CSN... " _GREEN_("%s") " uid", sprint_hex(hdr->csn, sizeof(hdr->csn)));
    PrintAndLogEx(SUCCESS, " Config... %s card configuration", sprint_hex((uint8_t *)&hdr->conf, sizeof(hdr->conf)));
    PrintAndLogEx(SUCCESS, "E-purse... %s card challenge, CC", sprint_hex(hdr->epurse, sizeof(hdr->epurse)));

    if (memcmp(hdr->key_d, zeros, sizeof(zeros)) && memcmp(hdr->key_d, empty, sizeof(empty))) {
        PrintAndLogEx(SUCCESS, "     Kd... " _YELLOW_("%s") " debit key", sprint_hex(hdr->key_d, sizeof(hdr->key_d)));
    } else {
        PrintAndLogEx(SUCCESS, "     Kd... %s debit key ( hidden )", sprint_hex(hdr->key_d, sizeof(hdr->key_d)));
    }

    if (memcmp(hdr->key_c, zeros, sizeof(zeros)) && memcmp(hdr->key_c, empty, sizeof(empty))) {
        PrintAndLogEx(SUCCESS, "     Kc... " _YELLOW_("%s") " credit key", sprint_hex(hdr->key_c, sizeof(hdr->key_c)));
    } else {
        PrintAndLogEx(SUCCESS, "     Kc... %s credit key ( hidden )", sprint_hex(hdr->key_c, sizeof(hdr->key_c)));
    }

    PrintAndLogEx(SUCCESS, "    AIA... %s application issuer area", sprint_hex(hdr->app_issuer_area, sizeof(hdr->app_issuer_area)));
}

static int CmdHFiClassList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf iclass", "iclass -c");
}

static int CmdHFiClassSniff(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass sniff",
                  "Sniff the communication between reader and tag",
                  "hf iclass sniff\n"
                  "hf iclass sniff -j    --> jam e-purse updates\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("j",  "jam",    "Jam (prevent) e-purse updates"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool jam_epurse_update = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (jam_epurse_update) {
        PrintAndLogEx(INFO, "Sniff with jam of iCLASS e-purse updates...");
    }

    struct {
        uint8_t jam_search_len;
        uint8_t jam_search_string[2];
    } PACKED payload;

    memset(&payload, 0, sizeof(payload));

    if (jam_epurse_update) {
        const uint8_t update_epurse_sequence[2] = {0x87, 0x02};
        payload.jam_search_len = sizeof(update_epurse_sequence);
        memcpy(payload.jam_search_string, update_epurse_sequence, sizeof(payload.jam_search_string));
    }

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_SNIFF, (uint8_t *)&payload, sizeof(payload));

    WaitForResponse(CMD_HF_ICLASS_SNIFF, &resp);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save -f hf_iclass_mytrace") "` to save tracelog for later analysing");
    if (jam_epurse_update) {
        PrintAndLogEx(HINT, "Verify if the jam worked by comparing value in trace and block 2");
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFiClassSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass sim",
                  "Simulate a iCLASS legacy/standard tag",
                  "hf iclass sim -t 0 --csn 031FEC8AF7FF12E0   --> simulate with specified CSN\n"
                  "hf iclass sim -t 1                          --> simulate with default CSN\n"
                  "hf iclass sim -t 2                          --> execute loclass attack online part\n"
                  "hf iclass sim -t 3                          --> simulate full iCLASS 2k tag\n"
                  "hf iclass sim -t 4                          --> Reader-attack, adapted for KeyRoll mode, gather reader responses to extract elite key");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("t", "type", "<0-4> ", "Simulation type to use"),
        arg_str0(NULL, "csn", "<hex>", "Specify CSN as 8 hex bytes to use with sim type 0"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int sim_type = arg_get_int_def(ctx, 1, 3);

    int csn_len = 0;
    uint8_t csn[8] = {0};
    CLIGetHexWithReturn(ctx, 2, csn, &csn_len);

    if (sim_type == 0 && csn_len > 0) {
        if (csn_len != 8) {
            PrintAndLogEx(ERR, "CSN is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        PrintAndLogEx(INFO, " simtype: %02x CSN: %s", sim_type, sprint_hex(csn, 8));
    } else if (sim_type == 0 && csn_len == 0) {
        PrintAndLogEx(ERR, "Simtype 0 requires CSN argument (--csn)");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (sim_type > 4) {
        PrintAndLogEx(ERR, "Undefined simtype %d", sim_type);
        return PM3_EINVARG;
    }

    // remember to change the define NUM_CSNS to match.

    // pre-defined 9 CSN by iceman
    uint8_t csns[NUM_CSNS * PICOPASS_BLOCK_SIZE] = {
        0x01, 0x0A, 0x0F, 0xFF, 0xF7, 0xFF, 0x12, 0xE0,
        0x0C, 0x06, 0x0C, 0xFE, 0xF7, 0xFF, 0x12, 0xE0,
        0x10, 0x97, 0x83, 0x7B, 0xF7, 0xFF, 0x12, 0xE0,
        0x13, 0x97, 0x82, 0x7A, 0xF7, 0xFF, 0x12, 0xE0,
        0x07, 0x0E, 0x0D, 0xF9, 0xF7, 0xFF, 0x12, 0xE0,
        0x14, 0x96, 0x84, 0x76, 0xF7, 0xFF, 0x12, 0xE0,
        0x17, 0x96, 0x85, 0x71, 0xF7, 0xFF, 0x12, 0xE0,
        0xCE, 0xC5, 0x0F, 0x77, 0xF7, 0xFF, 0x12, 0xE0,
        0xD2, 0x5A, 0x82, 0xF8, 0xF7, 0xFF, 0x12, 0xE0
        //0x04, 0x08, 0x9F, 0x78, 0x6E, 0xFF, 0x12, 0xE0
    };

    /* DUMPFILE FORMAT:
     *
     * <8-byte CSN><8-byte CC><4 byte NR><4 byte MAC>....
     * So, it should wind up as
     * 8 * 24 bytes.
     *
     * The returndata from the pm3 is on the following format
     * <4 byte NR><4 byte MAC>
     * CC are all zeroes, CSN is the same as was sent in
     **/
    uint8_t tries = 0;

    switch (sim_type) {

        case ICLASS_SIM_MODE_READER_ATTACK: {
            PrintAndLogEx(INFO, "Starting iCLASS sim 2 attack (elite mode)");
            PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to abort");
            PacketResponseNG resp;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_SIMULATE, sim_type, NUM_CSNS, 1, csns, NUM_CSNS * PICOPASS_BLOCK_SIZE);

            while (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
                tries++;
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard.");
                    return PM3_EOPABORTED;
                }
                if (tries > 20) {
                    PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
                    return PM3_ETIMEOUT;
                }
            }
            uint8_t num_mac  = resp.oldarg[1];
            bool success = (NUM_CSNS == num_mac);
            PrintAndLogEx((success) ? SUCCESS : WARNING, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+' : '!', num_mac, NUM_CSNS, (success) ? "OK" : "FAIL");

            if (num_mac == 0)
                break;

            size_t datalen = NUM_CSNS * MAC_ITEM_SIZE;
            uint8_t *dump = calloc(datalen, sizeof(uint8_t));
            if (!dump) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                return PM3_EMALLOC;
            }

            memset(dump, 0, datalen);//<-- Need zeroes for the EPURSE - field (official)

            uint8_t i = 0;
            for (i = 0 ; i < NUM_CSNS ; i++) {
                //copy CSN
                memcpy(dump + (i * MAC_ITEM_SIZE), csns + i * 8, 8);
                //copy epurse
                memcpy(dump + (i * MAC_ITEM_SIZE) + 8, resp.data.asBytes + i * 16, 8);
                // NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
                memcpy(dump + (i * MAC_ITEM_SIZE) + 16, resp.data.asBytes + i * 16 + 8, 8);
            }
            /** Now, save to dumpfile **/
            saveFile("iclass_mac_attack", ".bin", dump, datalen);
            free(dump);

            PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass loclass -f iclass_mac_attack.bin") "` to recover elite key");
            break;
        }
        case ICLASS_SIM_MODE_READER_ATTACK_KEYROLL: {
            // reader in key roll mode,  when it has two keys it alternates when trying to verify.
            PrintAndLogEx(INFO, "Starting iCLASS sim 4 attack (elite mode, reader in key roll mode)");
            PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to abort");
            PacketResponseNG resp;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_SIMULATE, sim_type, NUM_CSNS, 1, csns, NUM_CSNS * PICOPASS_BLOCK_SIZE);

            while (WaitForResponseTimeout(CMD_ACK, &resp, 2000) == false) {
                tries++;
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard.");
                    return PM3_EOPABORTED;
                }
                if (tries > 20) {
                    PrintAndLogEx(WARNING, "\ntimeout while waiting for reply.");
                    return PM3_ETIMEOUT;
                }
            }
            uint8_t num_mac = resp.oldarg[1];
            bool success = ((NUM_CSNS * 2) == num_mac);
            PrintAndLogEx((success) ? SUCCESS : WARNING, "[%c] %d out of %d MAC obtained [%s]", (success) ? '+' : '!', num_mac, NUM_CSNS * 2, (success) ? "OK" : "FAIL");

            if (num_mac == 0)
                break;

            size_t datalen = NUM_CSNS * MAC_ITEM_SIZE;
            uint8_t *dump = calloc(datalen, sizeof(uint8_t));
            if (!dump) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                return PM3_EMALLOC;
            }

            //KEYROLL 1
            //Need zeroes for the CC-field
            memset(dump, 0, datalen);
            for (uint8_t i = 0; i < NUM_CSNS ; i++) {
                // copy CSN
                memcpy(dump + (i * MAC_ITEM_SIZE), csns + i * 8, 8); //CSN
                // copy EPURSE
                memcpy(dump + (i * MAC_ITEM_SIZE) + 8, resp.data.asBytes + i * 16, 8);
                // copy NR_MAC (eight bytes from the response)  ( 8b csn + 8b epurse == 16)
                memcpy(dump + (i * MAC_ITEM_SIZE) + 16, resp.data.asBytes + i * 16 + 8, 8);
            }
            saveFile("iclass_mac_attack_keyroll_A", ".bin", dump, datalen);

            //KEYROLL 2
            memset(dump, 0, datalen);
            for (uint8_t i = 0; i < NUM_CSNS; i++) {
                uint8_t resp_index = (i + NUM_CSNS) * 16;
                // Copy CSN
                memcpy(dump + (i * MAC_ITEM_SIZE), csns + i * 8, 8);
                // copy EPURSE
                memcpy(dump + (i * MAC_ITEM_SIZE) + 8, resp.data.asBytes + resp_index, 8);
                // copy NR_MAC (eight bytes from the response)  ( 8b csn + 8 epurse == 16)
                memcpy(dump + (i * MAC_ITEM_SIZE) + 16, resp.data.asBytes + resp_index + 8, 8);
                resp_index++;
            }
            saveFile("iclass_mac_attack_keyroll_B", ".bin", dump, datalen);
            free(dump);

            PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass loclass -f iclass_mac_attack_keyroll_A.bin") "` to recover elite key");
            PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass loclass -f iclass_mac_attack_keyroll_B.bin") "` to recover elite key");
            break;
        }
        case ICLASS_SIM_MODE_CSN:
        case ICLASS_SIM_MODE_CSN_DEFAULT:
        case ICLASS_SIM_MODE_FULL:
        default: {
            PrintAndLogEx(INFO, "Starting iCLASS simulation");
            PrintAndLogEx(INFO, "Press " _GREEN_("`pm3 button`") " to abort");
            uint8_t numberOfCSNs = 0;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ICLASS_SIMULATE, sim_type, numberOfCSNs, 1, csn, 8);

            if (sim_type == ICLASS_SIM_MODE_FULL)
                PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass esave -h") "` to save the emulator memory to file");
            break;
        }
    }
    return PM3_SUCCESS;
}

static int CmdHFiClassInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass info",
                  "Act as a iCLASS reader. Reads / fingerprints a iCLASS tag.",
                  "hf iclass info");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool shallow_mod = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    return info_iclass(shallow_mod);
}

int read_iclass_csn(bool loop, bool verbose, bool shallow_mod) {

    iclass_card_select_t payload = {
        .flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE)
    };

    if (shallow_mod) {
        payload.flags |= FLAG_ICLASS_READER_SHALLOW_MOD;
    }

    int res = PM3_SUCCESS;

    do {
        clearCommandBuffer();
        PacketResponseNG resp;
        SendCommandNG(CMD_HF_ICLASS_READER, (uint8_t *)&payload, sizeof(iclass_card_select_t));

        if (WaitForResponseTimeout(CMD_HF_ICLASS_READER, &resp, 2000)) {

            iclass_card_select_resp_t *r = (iclass_card_select_resp_t *)resp.data.asBytes;
            if (loop) {
                if (resp.status == PM3_ERFTRANS) {
                    continue;
                }
            } else {

                if (r->status == FLAG_ICLASS_NULL || resp.status == PM3_ERFTRANS) {
                    if (verbose) PrintAndLogEx(WARNING, "iCLASS / Picopass card select failed ( %d , %d)", r->status, resp.status);
                    res = PM3_EOPABORTED;
                    break;
                }
            }

            picopass_hdr_t *card = calloc(1, sizeof(picopass_hdr_t));
            if (card) {
                memcpy(card, &r->header.hdr, sizeof(picopass_hdr_t));
                if (loop == false) {
                    PrintAndLogEx(NORMAL, "");
                }
                PrintAndLogEx(SUCCESS, "iCLASS / Picopass CSN: " _GREEN_("%s"), sprint_hex(card->csn, sizeof(card->csn)));
                iclass_set_last_known_card(card);
                free(card);
                res = PM3_SUCCESS;
            } else {
                PrintAndLogEx(FAILED, "failed to allocate memory");
                res = PM3_EMALLOC;
            }
        }
    } while (loop && kbd_enter_pressed() == false);

    DropField();
    return res;
}

static int CmdHFiClassReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass reader",
                  "Act as a iCLASS reader. Look for iCLASS tags until Enter or the pm3 button is pressed",
                  "hf iclass reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    bool shallow_mod = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    return read_iclass_csn(cm, false, shallow_mod);
}

static int CmdHFiClassELoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass eload",
                  "Load emulator memory with data from (bin/json) iCLASS dump file",
                  "hf iclass eload -f hf-iclass-AA162D30F8FF12F1-dump.json\n"
                  "hf iclass eload -f hf-iclass-AA162D30F8FF12F1-dump.bin -m\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("m", "mem",  "use RDV4 spiffs"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    if (strlen(filename) == 0) {
        PrintAndLogEx(ERR, "Error: Please specify a filename");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool use_spiffs = arg_get_lit(ctx, 2);
    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // use RDV4 spiffs
    if (use_spiffs && IfPm3Flash() == false) {
        PrintAndLogEx(WARNING, "Device not compiled to support spiffs");
        return PM3_EINVARG;
    }

    if (use_spiffs) {

        if (fnlen > 32) {
            PrintAndLogEx(WARNING, "filename too long for spiffs, expected 32, got %u", fnlen);
            return PM3_EINVARG;
        }

        clearCommandBuffer();
        SendCommandNG(CMD_SPIFFS_ELOAD, (uint8_t *)filename, fnlen);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_SPIFFS_ELOAD, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Loading file from spiffs to emulatore memory failed");
            return PM3_EFLASH;
        }

        PrintAndLogEx(SUCCESS, "File transfered from spiffs to device emulator memory");
        return PM3_SUCCESS;
    }

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 2048;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, 2048);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint8_t *newdump = realloc(dump, bytes_read);
    if (newdump == NULL) {
        free(dump);
        return PM3_EMALLOC;
    } else {
        dump = newdump;
    }

    if (verbose) {
        print_picopass_header((picopass_hdr_t *) dump);
        print_picopass_info((picopass_hdr_t *) dump);
    }

    PrintAndLogEx(NORMAL, "");

    //Send to device
    uint16_t bytes_sent = 0;
    iclass_upload_emul(dump, bytes_read, 0, &bytes_sent);
    free(dump);
    PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", bytes_sent);
    PrintAndLogEx(HINT, "You are ready to simulate. See " _YELLOW_("`hf iclass sim -h`"));
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHFiClassESave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass esave",
                  "Save emulator memory to file (bin/json)\n"
                  "if filename is not supplied, CSN will be used.",
                  "hf iclass esave\n"
                  "hf iclass esave -f hf-iclass-dump\n"
                  "hf iclass esave -s 2048 -f hf-iclass-dump");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_int0("s", "size", "<256|2048>", "number of bytes to save (default 256)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    uint16_t bytes = arg_get_int_def(ctx, 2, 256);

    if (bytes > 4096) {
        PrintAndLogEx(WARNING, "Emulator memory is max 4096bytes. Truncating %u to 4096", bytes);
        bytes = 4096;
    }

    CLIParserFree(ctx);

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading from emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(fptr, sizeof(filename), "hf-iclass-");
        FillFileNameByUID(fptr, dump, "-dump", 8);
    }

    pm3_save_dump(filename, dump, bytes, jsfIclass);
    free(dump);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass view -f") "` to view dump file");
    return PM3_SUCCESS;
}

static int CmdHFiClassEView(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass eview",
                  "Display emulator memory.\n"
                  "Number of bytes to download defaults to 256. Other value is 2048.",
                  "hf iclass eview\n"
                  "hf iclass eview -s 2048\n"
                  "hf iclass eview -s 2048 -v");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("s", "size", "<256|2048>", "number of bytes to save (default 256)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint16_t blocks = 32;
    uint16_t bytes = arg_get_int_def(ctx, 1, 256);
    bool verbose = arg_get_lit(ctx, 2);
    bool dense_output = g_session.dense_output || arg_get_lit(ctx, 3);
    blocks = bytes / 8;

    CLIParserFree(ctx);

    if (bytes > 4096) {
        PrintAndLogEx(WARNING, "Emulator memory is max 4096bytes. Truncating %u to 4096", bytes);
        bytes = 4096;
    }

    if (bytes % 8 != 0) {
        bytes &= 0xFFF8;
        PrintAndLogEx(WARNING, "Number not divided by 8, truncating to %u", bytes);
    }

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }
    memset(dump, 0, bytes);

    PrintAndLogEx(INFO, "downloading from emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    if (verbose) {
        print_picopass_header((picopass_hdr_t *) dump);
        print_picopass_info((picopass_hdr_t *) dump);
    }

    PrintAndLogEx(NORMAL, "");
    printIclassDumpContents(dump, 1, blocks, bytes, dense_output);

    if (verbose) {
        print_iclass_sio(dump, bytes);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdHFiClassESetBlk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass esetblk",
                  "Sets an individual block in emulator memory.",
                  "hf iclass esetblk --blk 7 -d 0000000000000000");

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_str0("d", "data", "<hex>", "bytes to write, 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int blk = arg_get_int_def(ctx, 1, 0);

    if (blk > 255 || blk < 0) {
        PrintAndLogEx(WARNING, "block number must be between 0 and 255. Got " _RED_("%i"), blk);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t data[PICOPASS_BLOCK_SIZE] = {0x00};
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), data, sizeof(data), &datalen);
    CLIParserFree(ctx);

    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    if (datalen != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(WARNING, "block data must include 8 HEX bytes. Got " _RED_("%i"), datalen);
        return PM3_EINVARG;
    }

    uint16_t bytes_sent = 0;
    iclass_upload_emul(data, sizeof(data), blk * PICOPASS_BLOCK_SIZE, &bytes_sent);

    return PM3_SUCCESS;
}

static bool iclass_detect_new_pacs(uint8_t *d) {
    uint8_t n = 0;
    while (n++ < (PICOPASS_BLOCK_SIZE / 2)) {
        if (d[n] && d[n + 1] == 0xA6) {
            return true;
        }
    }
    return false;
}

// block 7 decoder for PACS
static int iclass_decode_credentials_new_pacs(uint8_t *d) {

    uint8_t offset = 0;
    while (d[offset] == 0 && (offset < PICOPASS_BLOCK_SIZE / 2)) {
        offset++;
    }

    uint8_t pad = d[offset];

    PrintAndLogEx(INFO, "%u , %u", offset, pad);

    char *binstr = (char *)calloc((PICOPASS_BLOCK_SIZE * 8) + 1, sizeof(uint8_t));
    if (binstr == NULL) {
        return PM3_EMALLOC;
    }

    uint8_t n = PICOPASS_BLOCK_SIZE - offset - 2;
    bytes_2_binstr(binstr, d + offset + 2, n);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "PACS......... " _GREEN_("%s"), sprint_hex_inrow(d + offset + 2, n));
    PrintAndLogEx(SUCCESS, "padded bin... " _GREEN_("%s") " ( %zu )", binstr, strlen(binstr));

    binstr[strlen(binstr) - pad] = '\0';
    PrintAndLogEx(SUCCESS, "bin.......... " _GREEN_("%s") " ( %zu )", binstr, strlen(binstr));

    size_t hexlen = 0;
    uint8_t hex[16] = {0};
    binstr_2_bytes(hex, &hexlen, binstr);
    PrintAndLogEx(SUCCESS, "hex.......... " _GREEN_("%s"), sprint_hex_inrow(hex, hexlen));

    uint32_t top = 0, mid = 0, bot = 0;
    if (binstring_to_u96(&top, &mid, &bot, binstr) != strlen(binstr)) {
        PrintAndLogEx(ERR, "Binary string contains none <0|1> chars");
        free(binstr);
        return PM3_EINVARG;
    }

    free(binstr);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Wiegand decode");
    decode_wiegand(top, mid, bot, 0);

    return PM3_SUCCESS;
}

static void iclass_decode_credentials(uint8_t *data) {
    picopass_hdr_t *hdr = (picopass_hdr_t *)data;
    if (memcmp(hdr->app_issuer_area, empty, PICOPASS_BLOCK_SIZE)) {
        // Not a Legacy or SR card, nothing to do here.
        return;
    }

    BLOCK79ENCRYPTION encryption = (data[(6 * PICOPASS_BLOCK_SIZE) + 7] & 0x03);

    uint8_t *b7 = data + (PICOPASS_BLOCK_SIZE * 7);

    bool has_new_pacs = iclass_detect_new_pacs(b7);
    bool has_values = (memcmp(b7, empty, PICOPASS_BLOCK_SIZE) != 0) && (memcmp(b7, zeros, PICOPASS_BLOCK_SIZE) != 0);
    if (has_values && encryption == None) {

        // todo:  remove preamble/sentinel
        PrintAndLogEx(INFO, "Block 7 decoder");

        if (has_new_pacs) {
            iclass_decode_credentials_new_pacs(b7);
        } else {
            char hexstr[16 + 1] = {0};
            hex_to_buffer((uint8_t *)hexstr, b7, PICOPASS_BLOCK_SIZE, sizeof(hexstr) - 1, 0, 0, true);

            uint32_t top = 0, mid = 0, bot = 0;
            hexstring_to_u96(&top, &mid, &bot, hexstr);

            char binstr[64 + 1];
            hextobinstring(binstr, hexstr);
            char *pbin = binstr;
            while (strlen(pbin) && *(++pbin) == '0');

            PrintAndLogEx(SUCCESS, "Binary..................... " _GREEN_("%s"), pbin);

            PrintAndLogEx(INFO, "Wiegand decode");
            decode_wiegand(top, mid, bot, 0);
        }

    } else {
        PrintAndLogEx(INFO, "No unencrypted legacy credential found");
    }
}

static int CmdHFiClassDecrypt(const char *Cmd) {
    CLIParserContext *clictx;
    CLIParserInit(&clictx, "hf iclass decrypt",
                  "3DES decrypt data\n"
                  "This is a naive implementation, it tries to decrypt every block after block 6.\n"
                  "Correct behaviour would be to decrypt only the application areas where the key is valid,\n"
                  "which is defined by the configuration block.\n"
                  "\nOBS!\n"
                  "In order to use this function, the file `iclass_decryptionkey.bin` must reside\n"
                  "in the resources directory. The file must be 16 bytes binary data\n"
                  "or...\n"
                  "make sure your cardhelper is placed in the sim module",
                  "hf iclass decrypt -f hf-iclass-AA162D30F8FF12F1-dump.bin\n"
                  "hf iclass decrypt -f hf-iclass-AA162D30F8FF12F1-dump.bin -k 000102030405060708090a0b0c0d0e0f\n"
                  "hf iclass decrypt -d 1122334455667788 -k 000102030405060708090a0b0c0d0e0f");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_str0("d", "data", "<hex>", "3DES encrypted data"),
        arg_str0("k", "key", "<hex>", "3DES transport key"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "d6", "decode as block 6"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_param_end
    };
    CLIExecWithReturn(clictx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(clictx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int enc_data_len = 0;
    uint8_t enc_data[PICOPASS_BLOCK_SIZE] = {0};
    bool have_data = false;

    CLIGetHexWithReturn(clictx, 2, enc_data, &enc_data_len);

    int key_len = 0;
    uint8_t key[16] = {0};
    uint8_t *keyptr = NULL;
    bool have_key = false;

    CLIGetHexWithReturn(clictx, 3, key, &key_len);

    bool verbose = arg_get_lit(clictx, 4);
    bool use_decode6 = arg_get_lit(clictx, 5);
    bool dense_output = g_session.dense_output || arg_get_lit(clictx, 6);
    bool nosave = arg_get_lit(clictx, 7);
    CLIParserFree(clictx);

    // sanity checks
    if (enc_data_len > 0) {
        if (enc_data_len != PICOPASS_BLOCK_SIZE) {
            PrintAndLogEx(ERR, "Data must be 8 hex bytes (16 HEX symbols)");
            return PM3_EINVARG;
        }
        have_data = true;
    }

    if (key_len > 0) {
        if (key_len != 16) {
            PrintAndLogEx(ERR, "Transport key must be 16 hex bytes (32 HEX characters)");
            return PM3_EINVARG;
        }
        have_key = true;
    }

    size_t decryptedlen = 2048;
    uint8_t *decrypted = NULL;
    bool have_file = false;
    int res = PM3_SUCCESS;

    // if user supplied dump file,  time to load it
    if (fnlen > 0) {

        // read dump file
        res = pm3_load_dump(filename, (void **)&decrypted, &decryptedlen, 2048);
        if (res != PM3_SUCCESS) {
            return res;
        }

        have_file = true;
    }

    // load transport key
    bool use_sc = false;
    if (have_key == false) {
        use_sc = IsCardHelperPresent(verbose);
        if (use_sc == false) {
            size_t keylen = 0;
            res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(INFO, "Couldn't find any decryption methods");
                free(decrypted);
                return PM3_EINVARG;
            }

            if (keylen != 16) {
                PrintAndLogEx(ERR, "Failed to load transport key from file");
                free(keyptr);
                free(decrypted);
                return PM3_EINVARG;
            }
            memcpy(key, keyptr, sizeof(key));
            free(keyptr);
        }
    }

    // tripledes
    mbedtls_des3_context ctx;
    mbedtls_des3_set2key_dec(&ctx, key);

    // decrypt user supplied data
    if (have_data) {

        uint8_t dec_data[PICOPASS_BLOCK_SIZE] = {0};
        if (use_sc) {
            Decrypt(enc_data, dec_data);
        } else {
            mbedtls_des3_crypt_ecb(&ctx, enc_data, dec_data);
        }

        PrintAndLogEx(SUCCESS, "encrypted... %s", sprint_hex_inrow(enc_data, sizeof(enc_data)));
        PrintAndLogEx(SUCCESS, "plain....... " _YELLOW_("%s"), sprint_hex_inrow(dec_data, sizeof(dec_data)));

        if (use_sc && use_decode6) {
            DecodeBlock6(dec_data);
        }
    }

    // decrypt dump file data
    if (have_file) {

        picopass_hdr_t *hdr = (picopass_hdr_t *)decrypted;

        uint8_t mem = hdr->conf.mem_config;
        uint8_t chip = hdr->conf.chip_config;
        uint8_t applimit = hdr->conf.app_limit;
        uint8_t kb = 2;
        uint8_t app_areas = 2;
        uint8_t books = 1;
        uint8_t pages = 1;
        getMemConfig(mem, chip, &app_areas, &kb, &books, &pages);

        BLOCK79ENCRYPTION aa1_encryption = (decrypted[(6 * PICOPASS_BLOCK_SIZE) + 7] & 0x03);

        uint8_t limit = MIN(applimit, decryptedlen / 8);

        if (decryptedlen / PICOPASS_BLOCK_SIZE != applimit) {
            PrintAndLogEx(WARNING, "Actual file len " _YELLOW_("%zu") " vs HID app-limit len " _YELLOW_("%u"), decryptedlen, applimit * PICOPASS_BLOCK_SIZE);
            PrintAndLogEx(INFO, "Setting limit to " _GREEN_("%u"), limit * PICOPASS_BLOCK_SIZE);
        }

        //uint8_t numblocks4userid = GetNumberBlocksForUserId(decrypted + (6 * 8));

        bool decrypted_block789 = false;
        for (uint8_t blocknum = 0; blocknum < limit; ++blocknum) {

            uint16_t idx = blocknum * PICOPASS_BLOCK_SIZE;
            memcpy(enc_data, decrypted + idx, PICOPASS_BLOCK_SIZE);

            switch (aa1_encryption) {
                // Right now, only 3DES is supported
                case TRIPLEDES:
                    // Decrypt block 7,8,9 if configured.
                    if (blocknum > 6 && blocknum <= 9 && memcmp(enc_data, empty, PICOPASS_BLOCK_SIZE) != 0) {
                        if (use_sc) {
                            Decrypt(enc_data, decrypted + idx);
                        } else {
                            mbedtls_des3_crypt_ecb(&ctx, enc_data, decrypted + idx);
                        }
                        decrypted_block789 = true;
                    }
                    break;
                case DES:
                case RFU:
                case None:
                // Nothing to do for None anyway...
                default:
                    continue;
            }

            if (decrypted_block789) {
                // Set the 2 last bits of block6 to 0 to mark the data as decrypted
                decrypted[(6 * PICOPASS_BLOCK_SIZE) + 7] &= 0xFC;
            }
        }

        if (nosave) {
            PrintAndLogEx(INFO, "Called with no save option");
            PrintAndLogEx(NORMAL, "");
        } else {

            // use the first block (CSN) for filename
            char *fptr = calloc(50, sizeof(uint8_t));
            if (fptr == false) {
                PrintAndLogEx(WARNING, "Failed to allocate memory");
                free(decrypted);
                return PM3_EMALLOC;
            }

            strcat(fptr, "hf-iclass-");
            FillFileNameByUID(fptr, hdr->csn, "-dump-decrypted", sizeof(hdr->csn));

            pm3_save_dump(fptr, decrypted, decryptedlen, jsfIclass);
            free(fptr);
        }

        printIclassDumpContents(decrypted, 1, (decryptedlen / 8), decryptedlen, dense_output);

        if (verbose) {
            print_iclass_sio(decrypted, decryptedlen);
        }

        PrintAndLogEx(NORMAL, "");

        // decode block 6
        bool has_values = (memcmp(decrypted + (PICOPASS_BLOCK_SIZE * 6), empty, 8) != 0) && (memcmp(decrypted + (PICOPASS_BLOCK_SIZE * 6), zeros, PICOPASS_BLOCK_SIZE) != 0);
        if (has_values && use_sc) {
            DecodeBlock6(decrypted + (PICOPASS_BLOCK_SIZE * 6));
        }

        // decode block 7-8-9
        iclass_decode_credentials(decrypted);

        // decode block 9
        has_values = (memcmp(decrypted + (PICOPASS_BLOCK_SIZE * 9), empty, PICOPASS_BLOCK_SIZE) != 0) && (memcmp(decrypted + (PICOPASS_BLOCK_SIZE * 9), zeros, PICOPASS_BLOCK_SIZE) != 0);
        if (has_values && use_sc) {
            uint8_t usr_blk_len = GetNumberBlocksForUserId(decrypted + (PICOPASS_BLOCK_SIZE * 6));
            if (usr_blk_len < 3) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, "Block 9 decoder");

                uint8_t pinsize = GetPinSize(decrypted + (PICOPASS_BLOCK_SIZE * 6));
                if (pinsize > 0) {

                    uint64_t pin = bytes_to_num(decrypted + (PICOPASS_BLOCK_SIZE * 9), 5);
                    char tmp[17] = {0};
                    snprintf(tmp, sizeof(tmp), "%."PRIu64, BCD2DEC(pin));
                    PrintAndLogEx(INFO, "PIN........................ " _GREEN_("%.*s"), pinsize, tmp);
                }
            }
        }

        PrintAndLogEx(INFO, "-----------------------------------------------------------------");
        free(decrypted);
    }

    mbedtls_des3_free(&ctx);
    return PM3_SUCCESS;
}

static int CmdHFiClassEncryptBlk(const char *Cmd) {
    CLIParserContext *clictx;
    CLIParserInit(&clictx, "hf iclass encrypt",
                  "3DES encrypt data\n"
                  "OBS! In order to use this function, the file 'iclass_decryptionkey.bin' must reside\n"
                  "in the resources directory. The file should be 16 hex bytes of binary data",
                  "hf iclass encrypt -d 0102030405060708\n"
                  "hf iclass encrypt -d 0102030405060708 -k 00112233445566778899AABBCCDDEEFF");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "data to encrypt"),
        arg_str0("k", "key", "<hex>", "3DES transport key"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(clictx, Cmd, argtable, false);

    int blk_data_len = 0;
    uint8_t blk_data[8] = {0};

    CLIGetHexWithReturn(clictx, 1, blk_data, &blk_data_len);

    if (blk_data_len != 8) {
        PrintAndLogEx(ERR, "Block data must be 8 hex bytes (16 HEX symbols)");
        CLIParserFree(clictx);
        return PM3_EINVARG;
    }

    int key_len = 0;
    uint8_t key[16] = {0};
    uint8_t *keyptr = NULL;
    bool have_key = false;

    CLIGetHexWithReturn(clictx, 2, key, &key_len);

    if (key_len > 0) {
        if (key_len != 16) {
            PrintAndLogEx(ERR, "Transport key must be 16 hex bytes (32 HEX characters)");
            CLIParserFree(clictx);
            return PM3_EINVARG;
        }
        have_key = true;
    }

    bool verbose = arg_get_lit(clictx, 3);

    CLIParserFree(clictx);

    bool use_sc = false;
    if (have_key == false) {
        use_sc = IsCardHelperPresent(verbose);
        if (use_sc == false) {
            size_t keylen = 0;
            int res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&keyptr, &keylen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Failed to find any encryption methods");
                return PM3_EINVARG;
            }

            if (keylen != 16) {
                PrintAndLogEx(ERR, "Failed to load transport key from file");
                free(keyptr);
                return PM3_EINVARG;
            }
            memcpy(key, keyptr, sizeof(key));
            free(keyptr);
        }
    }


    PrintAndLogEx(SUCCESS, "plain....... %s", sprint_hex_inrow(blk_data, sizeof(blk_data)));

    if (use_sc) {
        Encrypt(blk_data, blk_data);
    } else {
        iclass_encrypt_block_data(blk_data, key);
    }

    PrintAndLogEx(SUCCESS, "encrypted... " _YELLOW_("%s"), sprint_hex_inrow(blk_data, sizeof(blk_data)));
    return PM3_SUCCESS;
}

static bool select_only(uint8_t *CSN, uint8_t *CCNR, bool verbose, bool shallow_mod) {

    iclass_card_select_t payload = {
        .flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE)
    };

    if (shallow_mod) {
        payload.flags |= FLAG_ICLASS_READER_SHALLOW_MOD;
    }

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ICLASS_READER, (uint8_t *)&payload, sizeof(iclass_card_select_t));

    if (WaitForResponseTimeout(CMD_HF_ICLASS_READER, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return false;
    }

    iclass_card_select_resp_t *r = (iclass_card_select_resp_t *)resp.data.asBytes;
    picopass_hdr_t *hdr = &r->header.hdr;

    // no tag found or button pressed
    if (r->status == FLAG_ICLASS_NULL || resp.status == PM3_ERFTRANS) {
        if (verbose) {
            PrintAndLogEx(FAILED, "failed tag-select, aborting...  (%d)", r->status);
        }
        return false;
    }

    if (CSN != NULL)
        memcpy(CSN, hdr->csn, 8);

    if (CCNR != NULL)
        memcpy(CCNR, hdr->epurse, 8);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "CSN     %s", sprint_hex(CSN, 8));
        PrintAndLogEx(SUCCESS, "epurse  %s", sprint_hex(CCNR, 8));
    }
    return true;
}

static int CmdHFiClassDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass dump",
                  "Dump all memory from a iCLASS tag",
                  "hf iclass dump -k 001122334455667B\n"
                  "hf iclass dump -k AAAAAAAAAAAAAAAA --credit 001122334455667B\n"
                  "hf iclass dump -k AAAAAAAAAAAAAAAA --elite\n"
                  "hf iclass dump --ki 0\n"
                  "hf iclass dump --ki 0 --ci 2");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "save filename"),
        arg_str0("k", "key", "<hex>", "debit key or NR/MAC for replay as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "debit key index to select key from memory 'hf iclass managekeys'"),
        arg_str0(NULL, "credit", "<hex>", "credit key as 8 hex bytes"),
        arg_int0(NULL, "ci", "<dec>", "credit key index to select key from memory 'hf iclass managekeys'"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "raw, the key is interpreted as raw block 3/4"),
        arg_lit0(NULL, "nr", "replay of NR/MAC"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_lit0(NULL, "force", "force unsecure card read"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int key_len = 0;
    uint8_t key[8] = {0};
    bool auth = false;

    CLIGetHexWithReturn(ctx, 2, key, &key_len);

    int deb_key_nr = arg_get_int_def(ctx, 3, -1);

    if (key_len > 0 && deb_key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify debit key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (key_len > 0) {
        auth = true;
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Debit key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    if (deb_key_nr >= 0) {
        if (deb_key_nr < ICLASS_KEYS_MAX) {
            auth = true;
            memcpy(key, iClass_Key_Table[deb_key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using AA1 (debit) key[%d] " _GREEN_("%s"), deb_key_nr, sprint_hex(iClass_Key_Table[deb_key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int credit_key_len = 0;
    uint8_t credit_key[8] = {0};
    bool have_credit_key = false;

    CLIGetHexWithReturn(ctx, 4, credit_key, &credit_key_len);

    int credit_key_nr = arg_get_int_def(ctx, 5, -1);

    if (credit_key_len > 0 && credit_key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify credit key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (credit_key_len > 0) {
        auth = true;
        have_credit_key = true;
        if (credit_key_len != 8) {
            PrintAndLogEx(ERR, "Credit key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    if (credit_key_nr >= 0) {
        if (credit_key_nr < ICLASS_KEYS_MAX) {
            auth = true;
            have_credit_key = true;
            memcpy(credit_key, iClass_Key_Table[credit_key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using AA2 (credit) key[%d] " _GREEN_("%s"), credit_key_nr, sprint_hex(iClass_Key_Table[credit_key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    bool elite = arg_get_lit(ctx, 6);
    bool rawkey = arg_get_lit(ctx, 7);
    bool use_replay = arg_get_lit(ctx, 8);
    bool dense_output = g_session.dense_output || arg_get_lit(ctx, 9);
    bool force = arg_get_lit(ctx, 10);
    bool shallow_mod = arg_get_lit(ctx, 11);
    bool nosave = arg_get_lit(ctx, 12);

    CLIParserFree(ctx);

    if ((use_replay + rawkey + elite) > 1) {
        PrintAndLogEx(ERR, "Can not use a combo of 'elite', 'raw', 'nr'");
        return PM3_EINVARG;
    }

    uint8_t app_limit1 = 0, app_limit2 = 0;

    //get CSN and config
    uint8_t tag_data[0x100 * 8];
    memset(tag_data, 0xFF, sizeof(tag_data));

    iclass_card_select_t payload_rdr = {
        .flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE)
    };

    if (shallow_mod) {
        payload_rdr.flags |= FLAG_ICLASS_READER_SHALLOW_MOD;
    }

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ICLASS_READER, (uint8_t *)&payload_rdr, sizeof(iclass_card_select_t));

    if (WaitForResponseTimeout(CMD_HF_ICLASS_READER, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        DropField();
        return PM3_ESOFT;
    }
    DropField();

    if (resp.status == PM3_ERFTRANS) {
        PrintAndLogEx(FAILED, "no tag found");
        DropField();
        return PM3_ESOFT;
    }

    iclass_card_select_resp_t *r = (iclass_card_select_resp_t *)resp.data.asBytes;
    if (r->status == FLAG_ICLASS_NULL) {
        PrintAndLogEx(FAILED, "failed to read block 0,1,2");
        return PM3_ESOFT;
    }

    picopass_hdr_t *hdr = &r->header.hdr;
    uint8_t pagemap = get_pagemap(hdr);

    if (r->status & (FLAG_ICLASS_CSN | FLAG_ICLASS_CONF | FLAG_ICLASS_CC)) {

        memcpy(tag_data, hdr, 24);

        uint8_t type = get_mem_config(hdr);

        // tags configured for NON SECURE PAGE,  acts different
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {

            PrintAndLogEx(INFO, "Card in non-secure page mode detected");

            app_limit1 = card_app2_limit[type];
            app_limit2 = 0;
        } else if (hdr->conf.app_limit >= hdr->conf.mem_config) {
            PrintAndLogEx(WARNING, "AA1 config is >= card size, using card size as AA1 limit");
            app_limit1 = card_app2_limit[type];
        } else {
            app_limit1 = hdr->conf.app_limit;
            app_limit2 = card_app2_limit[type];
        }
    }

    //
    if (force) {
        pagemap = PICOPASS_NON_SECURE_PAGEMODE;
        PrintAndLogEx(INFO, "Forcing NON SECURE PAGE dumping");
    }

    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        PrintAndLogEx(INFO, "Dumping all available memory, block 3 - %u (0x%02x)", app_limit1, app_limit1);
        if (auth) {
            PrintAndLogEx(INFO, "No keys needed, ignoring user supplied key");
        }
    } else {
        if (auth == false) {
            PrintAndLogEx(FAILED, "Run command with keys");
            return PM3_ESOFT;
        }

        if (app_limit2 != 0) {
            PrintAndLogEx(INFO, "Card has at least 2 application areas. AA1 limit %u (0x%02X) AA2 limit %u (0x%02X)", app_limit1, app_limit1, app_limit2, app_limit2);
        } else {
            PrintAndLogEx(INFO, "Card has 1 application area. AA1 limit %u (0x%02X)", app_limit1, app_limit1);
        }
    }

    iclass_dump_req_t payload = {
        .req.use_raw = rawkey,
        .req.use_elite = elite,
        .req.use_credit_key = false,
        .req.use_replay = use_replay,
        .req.send_reply = true,
        .req.do_auth = auth,
        .req.shallow_mod = shallow_mod,
        .end_block = app_limit1,
    };
    memcpy(payload.req.key, key, 8);

    // tags configured for NON SECURE PAGE,  acts different
    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        payload.start_block = 3;
        payload.req.do_auth = false;
    } else {
        payload.start_block = 5;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_DUMP, (uint8_t *)&payload, sizeof(payload));

    while (true) {

        PrintAndLogEx(NORMAL, "." NOLF);
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            DropField();
            return PM3_EOPABORTED;
        }

        if (WaitForResponseTimeout(CMD_HF_ICLASS_DUMP, &resp, 2000))
            break;
    }

    PrintAndLogEx(NORMAL, "");
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to communicate with card");
        return resp.status;
    }

    struct p_resp {
        bool isOK;
        uint16_t block_cnt;
        uint32_t bb_offset;
    } PACKED;
    struct p_resp *packet = (struct p_resp *)resp.data.asBytes;

    if (packet->isOK == false) {
        PrintAndLogEx(WARNING, "read AA1 blocks failed");
        return PM3_ESOFT;
    }

    uint32_t startindex = packet->bb_offset;
    uint32_t blocks_read = packet->block_cnt;

    uint8_t tempbuf[0x100 * 8];

    // response ok - now get bigbuf content of the dump
    if (!GetFromDevice(BIG_BUF, tempbuf, sizeof(tempbuf), startindex, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (pagemap != PICOPASS_NON_SECURE_PAGEMODE) {
        // div key KD
        memcpy(tag_data + (PICOPASS_BLOCK_SIZE * 3),
               tempbuf + (PICOPASS_BLOCK_SIZE * 3), PICOPASS_BLOCK_SIZE);
    }
    // all memory available
    memcpy(tag_data + (PICOPASS_BLOCK_SIZE * payload.start_block),
           tempbuf + (PICOPASS_BLOCK_SIZE * payload.start_block),
           blocks_read * PICOPASS_BLOCK_SIZE);

    uint16_t bytes_got = (app_limit1 + 1) * 8;

    // try AA2 Kc, Credit
    bool aa2_success = false;

    if (have_credit_key && pagemap != PICOPASS_NON_SECURE_PAGEMODE && app_limit2 != 0) {

        // AA2 authenticate credit key
        memcpy(payload.req.key, credit_key, 8);

        payload.req.use_credit_key = true;
        payload.start_block = app_limit1 + 1;
        payload.end_block = app_limit2;
        payload.req.do_auth = true;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_DUMP, (uint8_t *)&payload, sizeof(payload));

        while (true) {
            PrintAndLogEx(NORMAL, "." NOLF);
            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                DropField();
                return PM3_EOPABORTED;
            }

            if (WaitForResponseTimeout(CMD_HF_ICLASS_DUMP, &resp, 2000))
                break;
        }
        PrintAndLogEx(NORMAL, "");
        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "failed to communicate with card");
            goto write_dump;
        }

        packet = (struct p_resp *)resp.data.asBytes;
        if (packet->isOK == false) {
            PrintAndLogEx(WARNING, "failed read block using credit key");
            goto write_dump;
        }

        blocks_read = packet->block_cnt;
        startindex = packet->bb_offset;

        if (blocks_read * 8 > sizeof(tag_data) - bytes_got) {
            PrintAndLogEx(WARNING, "data exceeded buffer size! ");
            blocks_read = (sizeof(tag_data) - bytes_got) / 8;
        }

        // get dumped data from bigbuf
        if (!GetFromDevice(BIG_BUF, tempbuf, sizeof(tempbuf), startindex, NULL, 0, NULL, 2500, false)) {
            PrintAndLogEx(WARNING, "command execution time out");
            goto write_dump;
        }

        // div key KC
        memcpy(tag_data + (PICOPASS_BLOCK_SIZE * 4), tempbuf + (PICOPASS_BLOCK_SIZE * 4), PICOPASS_BLOCK_SIZE);

        // AA2 data
        memcpy(tag_data + (PICOPASS_BLOCK_SIZE * payload.start_block),
               tempbuf + (PICOPASS_BLOCK_SIZE * payload.start_block),
               blocks_read * PICOPASS_BLOCK_SIZE);

        bytes_got += (blocks_read * PICOPASS_BLOCK_SIZE);

        aa2_success = true;
    }

write_dump:

    if (have_credit_key && pagemap != 0x01 && aa2_success == false) {
        PrintAndLogEx(INFO, "Reading AA2 failed. dumping AA1 data to file");
    }

    // print the dump
    printIclassDumpContents(tag_data, 1, (bytes_got / 8), bytes_got, dense_output);

    if (nosave) {
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    // use CSN as filename
    if (filename[0] == 0) {
        strcat(filename, "hf-iclass-");
        FillFileNameByUID(filename, tag_data, "-dump", 8);
    }

    // save the dump to .bin file
    PrintAndLogEx(SUCCESS, "saving dump file - %u blocks read", bytes_got / 8);

    pm3_save_dump(filename, tag_data, bytes_got, jsfIclass);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass decrypt -f") "` to decrypt dump file");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass view -f") "` to view dump file");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int iclass_write_block(uint8_t blockno, uint8_t *bldata, uint8_t *macdata, uint8_t *KEY, bool use_credit_key, bool elite, bool rawkey, bool replay, bool verbose, bool use_secure_pagemode, bool shallow_mod) {

    iclass_writeblock_req_t payload = {
        .req.use_raw = rawkey,
        .req.use_elite = elite,
        .req.use_credit_key = use_credit_key,
        .req.use_replay = replay,
        .req.blockno = blockno,
        .req.send_reply = true,
        .req.do_auth = use_secure_pagemode,
        .req.shallow_mod = shallow_mod,
    };
    memcpy(payload.req.key, KEY, 8);
    memcpy(payload.data, bldata, sizeof(payload.data));

    if (replay) {
        memcpy(payload.mac, macdata, sizeof(payload.mac));
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_WRITEBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_HF_ICLASS_WRITEBL, &resp, 2000) == 0) {
        if (verbose) PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        return resp.status;
    }

    return (resp.data.asBytes[0] == 1) ? PM3_SUCCESS : PM3_ESOFT;
}

static int CmdHFiClass_WriteBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass wrbl",
                  "Write data to an iCLASS tag",
                  "hf iclass wrbl --blk 10 -d AAAAAAAAAAAAAAAA -k 001122334455667B\n"
                  "hf iclass wrbl --blk 10 -d AAAAAAAAAAAAAAAA -k 001122334455667B --credit\n"
                  "hf iclass wrbl --blk 10 -d AAAAAAAAAAAAAAAA --ki 0");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_str1("d", "data", "<hex>", "data to write as 8 hex bytes"),
        arg_str0("m", "mac", "<hex>", "replay mac data (4 hex bytes)"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_lit0(NULL, "nr", "replay of NR/MAC"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int key_len = 0;
    uint8_t key[8] = {0};

    CLIGetHexWithReturn(ctx, 1, key, &key_len);

    int key_nr = arg_get_int_def(ctx, 2, -1);

    if (key_len > 0 && key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool auth = false;

    if (key_len > 0) {
        auth = true;
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (key_nr >= 0) {
        if (key_nr < ICLASS_KEYS_MAX) {
            auth = true;
            memcpy(key, iClass_Key_Table[key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), key_nr, sprint_hex(iClass_Key_Table[key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int blockno = arg_get_int_def(ctx, 3, 0);

    int data_len = 0;
    uint8_t data[8] = {0};
    CLIGetHexWithReturn(ctx, 4, data, &data_len);

    if (data_len != 8) {
        PrintAndLogEx(ERR, "Data must be 8 hex bytes (16 hex symbols)");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int mac_len = 0;
    uint8_t mac[4] = {0};
    CLIGetHexWithReturn(ctx, 5, mac, &mac_len);

    if (mac_len) {
        if (mac_len != 4) {
            PrintAndLogEx(ERR, "MAC must be 4 hex bytes (8 hex symbols)");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }


    bool use_credit_key = arg_get_lit(ctx, 6);
    bool elite = arg_get_lit(ctx, 7);
    bool rawkey = arg_get_lit(ctx, 8);
    bool use_replay = arg_get_lit(ctx, 9);
    bool verbose = arg_get_lit(ctx, 10);
    bool shallow_mod = arg_get_lit(ctx, 11);

    CLIParserFree(ctx);

    if ((use_replay + rawkey + elite) > 1) {
        PrintAndLogEx(ERR, "Can not use a combo of 'elite', 'raw', 'nr'");
        return PM3_EINVARG;
    }

    int isok = iclass_write_block(blockno, data, mac, key, use_credit_key, elite, rawkey, use_replay, verbose, auth, shallow_mod);
    switch (isok) {
        case PM3_SUCCESS:
            PrintAndLogEx(SUCCESS, "Wrote block " _YELLOW_("%d") " / " _YELLOW_("0x%02X") " ( " _GREEN_("ok") " )", blockno, blockno);
            break;
        case PM3_ETEAROFF:
            if (verbose)
                PrintAndLogEx(INFO, "Writing tear off triggered");
            break;
        default:
            PrintAndLogEx(FAILED, "Writing failed");
            break;
    }
    PrintAndLogEx(NORMAL, "");
    return isok;
}

static int CmdHFiClassCreditEpurse(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass creditepurse",
                  "Credit the epurse on an iCLASS tag. The provided key must be the credit key.\n"
                  "The first two bytes of the epurse are the debit value (big endian) and may be any value except FFFF.\n"
                  "The remaining two bytes of the epurse are the credit value and must be smaller than the previous value.",
                  "hf iclass creditepurse -d FEFFFFFF -k 001122334455667B\n"
                  "hf iclass creditepurse -d FEFFFFFF --ki 0");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Credit  key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_str1("d", "data", "<hex>", "data to write as 8 hex bytes"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int key_len = 0;
    uint8_t key[8] = {0};

    CLIGetHexWithReturn(ctx, 1, key, &key_len);

    int key_nr = arg_get_int_def(ctx, 2, -1);

    if (key_len > 0 && key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (key_len > 0) {
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (key_nr >= 0) {
        if (key_nr < ICLASS_KEYS_MAX) {
            memcpy(key, iClass_Key_Table[key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), key_nr, sprint_hex(iClass_Key_Table[key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(ERR, "Key or key number must be provided");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int blockno = 2;

    int data_len = 0;
    uint8_t data[4] = {0};
    CLIGetHexWithReturn(ctx, 3, data, &data_len);

    if (data_len != 4) {
        PrintAndLogEx(ERR, "Data must be 4 hex bytes (8 hex symbols)");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool elite = arg_get_lit(ctx, 4);
    bool rawkey = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);
    bool shallow_mod = arg_get_lit(ctx, 7);

    CLIParserFree(ctx);

    if ((rawkey + elite) > 1) {
        PrintAndLogEx(ERR, "Can not use a combo of 'elite', 'raw'");
        return PM3_EINVARG;
    }

    iclass_credit_epurse_t payload = {
        .req.use_raw = rawkey,
        .req.use_elite = elite,
        .req.use_credit_key = true,
        .req.use_replay = false,
        .req.blockno = blockno,
        .req.send_reply = true,
        .req.do_auth = true,
        .req.shallow_mod = shallow_mod,
    };
    memcpy(payload.req.key, key, 8);
    memcpy(payload.epurse, data, sizeof(payload.epurse));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_CREDIT_EPURSE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    int isok;
    if (WaitForResponseTimeout(CMD_HF_ICLASS_CREDIT_EPURSE, &resp, 2000) == 0) {
        if (verbose) PrintAndLogEx(WARNING, "command execution time out");
        isok = PM3_ETIMEOUT;
    } else if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        isok = resp.status;
    } else {
        isok = (resp.data.asBytes[0] == 1) ? PM3_SUCCESS : PM3_ESOFT;
    }

    switch (isok) {
        case PM3_SUCCESS:
            PrintAndLogEx(SUCCESS, "Credited epurse successfully");
            break;
        case PM3_ETEAROFF:
            if (verbose)
                PrintAndLogEx(INFO, "Writing tear off triggered");
            break;
        default:
            PrintAndLogEx(FAILED, "Writing failed");
            break;
    }
    return isok;
}

static int CmdHFiClassRestore(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass restore",
                  "Restore data from dumpfile (bin/eml/json) onto a iCLASS tag",
                  "hf iclass restore -f hf-iclass-AA162D30F8FF12F1-dump.bin --first 6 --last 18 --ki 0\n"
                  "hf iclass restore -f hf-iclass-AA162D30F8FF12F1-dump.bin --first 6 --last 18 --ki 0 --elite\n"
                  "hf iclass restore -f hf-iclass-AA162D30F8FF12F1-dump.bin --first 6 --last 18 -k 1122334455667788 --elite\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "specify a filename to restore"),
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_int1(NULL, "first", "<dec>", "The first block number to restore"),
        arg_int1(NULL, "last", "<dec>", "The last block number to restore"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int key_len = 0;
    uint8_t key[8] = {0};

    CLIGetHexWithReturn(ctx, 2, key, &key_len);

    int key_nr = arg_get_int_def(ctx, 3, -1);

    if (key_len > 0 && key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (key_len > 0) {
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (key_nr >= 0) {
        if (key_nr < ICLASS_KEYS_MAX) {
            memcpy(key, iClass_Key_Table[key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), key_nr, sprint_hex(iClass_Key_Table[key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(ERR, "Please specify a key or key index");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int startblock = arg_get_int_def(ctx, 4, 0);
    int endblock = arg_get_int_def(ctx, 5, 0);

    bool use_credit_key = arg_get_lit(ctx, 6);
    bool elite = arg_get_lit(ctx, 7);
    bool rawkey = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);
    bool shallow_mod = arg_get_lit(ctx, 10);

    CLIParserFree(ctx);

    if (rawkey + elite > 1) {
        PrintAndLogEx(FAILED, "Can not use both 'e', 'r'");
        return PM3_EINVARG;
    }

    if (startblock < 5) {
        PrintAndLogEx(WARNING, "you cannot write key blocks this way. yet... make your start block > 4");
        return PM3_EINVARG;
    }

    uint32_t payload_size = sizeof(iclass_restore_req_t) + (sizeof(iclass_restore_item_t) * (endblock - startblock + 1));

    if (payload_size > PM3_CMD_DATA_SIZE) {
        PrintAndLogEx(NORMAL, "Trying to write too many blocks at once.  Max: %d", PM3_CMD_DATA_SIZE / 8);
        return PM3_EINVARG;
    }

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 2048;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, 2048);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read == 0) {
        PrintAndLogEx(ERR, "file reading error");
        free(dump);
        return PM3_EFILE;
    }

    if (bytes_read < ((endblock - startblock + 1) * 8)) {
        PrintAndLogEx(ERR, "file is smaller than your suggested block range ( " _RED_("0x%02x..0x%02x")" )",
                      startblock, endblock
                     );
        free(dump);
        return PM3_EFILE;
    }

    iclass_restore_req_t *payload = calloc(1, payload_size);
    payload->req.use_raw = rawkey;
    payload->req.use_elite = elite;
    payload->req.use_credit_key = use_credit_key;
    payload->req.use_replay = false;
    payload->req.blockno = startblock;
    payload->req.send_reply = true;
    payload->req.do_auth = true;
    payload->req.shallow_mod = shallow_mod;
    memcpy(payload->req.key, key, 8);

    payload->item_cnt = (endblock - startblock + 1);

    // read data from file from block 6 --- 19
    // we will use this struct [data 8 bytes][MAC 4 bytes] for each block calculate all mac number for each data
    // then copy to usbcommand->asbytes;
    // max is 32 - 6 = 28 block.  28 x 12 bytes gives 336 bytes

    for (uint8_t i = 0; i < payload->item_cnt; i++) {
        payload->blocks[i].blockno = startblock + i;
        memcpy(payload->blocks[i].data, dump + (startblock * 8) + (i * 8), sizeof(payload->blocks[i].data));
    }

    free(dump);

    if (verbose) {
        PrintAndLogEx(INFO, "Preparing to restore block range %02d..%02d", startblock, endblock);

        PrintAndLogEx(INFO, "---------+----------------------");
        PrintAndLogEx(INFO, " block#  | data");
        PrintAndLogEx(INFO, "---------+----------------------");

        for (uint8_t i = 0; i < payload->item_cnt; i++) {
            iclass_restore_item_t item = payload->blocks[i];
            PrintAndLogEx(INFO, "%3d/0x%02X | %s", item.blockno, item.blockno, sprint_hex_inrow(item.data, sizeof(item.data)));
        }
    }

    PrintAndLogEx(INFO, "restore started...");

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_RESTORE, (uint8_t *)payload, payload_size);

    if (WaitForResponseTimeout(CMD_HF_ICLASS_RESTORE, &resp, 2500) == 0) {
        PrintAndLogEx(WARNING, "command execution time out");
        DropField();
        free(payload);
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "iCLASS restore " _GREEN_("successful"));
        PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass rdbl") "` to verify data on card");
    } else {
        PrintAndLogEx(WARNING, "iCLASS restore " _RED_("failed"));
    }

    free(payload);
    return resp.status;
}

static int iclass_read_block_ex(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool replay, bool verbose,
                                bool auth, bool shallow_mod, uint8_t *out, bool print) {

    iclass_auth_req_t payload = {
        .use_raw = rawkey,
        .use_elite = elite,
        .use_credit_key = (keyType == 0x18),
        .use_replay = replay,
        .blockno = blockno,
        .send_reply = true,
        .do_auth = auth,
        .shallow_mod = shallow_mod,
    };
    memcpy(payload.key, KEY, 8);

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ICLASS_READBL, (uint8_t *)&payload, sizeof(payload));

    if (WaitForResponseTimeout(CMD_HF_ICLASS_READBL, &resp, 2000) == false) {
        if (verbose) PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        if (verbose) PrintAndLogEx(ERR, "failed to communicate with card");
        return PM3_EWRONGANSWER;
    }

    // return data.
    iclass_readblock_resp_t *packet = (iclass_readblock_resp_t *)resp.data.asBytes;

    if (packet->isOK == false) {
        if (verbose) PrintAndLogEx(FAILED, "authentication error");
        return PM3_ESOFT;
    }

    if (print) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, " block %3d/0x%02X : " _GREEN_("%s"), blockno, blockno, sprint_hex(packet->data, sizeof(packet->data)));
        PrintAndLogEx(NORMAL, "");
    }

    if (out) {
        memcpy(out, packet->data, sizeof(packet->data));
    }

    return PM3_SUCCESS;
}

static int iclass_read_block(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool replay, bool verbose,
                             bool auth, bool shallow_mod, uint8_t *out) {
    return iclass_read_block_ex(KEY, blockno, keyType, elite, rawkey, replay, verbose, auth, shallow_mod, out, true);
}

static int CmdHFiClass_ReadBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass rdbl",
                  "Read a iCLASS block from tag",
                  "hf iclass rdbl --blk 6 -k 0011223344556677\n"
                  "hf iclass rdbl --blk 27 -k 0011223344556677 --credit\n"
                  "hf iclass rdbl --blk 10 --ki 0");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_int1(NULL, "blk", "<dec>", "Block number"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_lit0(NULL, "nr", "replay of NR/MAC"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int key_len = 0;
    uint8_t key[8] = {0};

    CLIGetHexWithReturn(ctx, 1, key, &key_len);

    int key_nr = arg_get_int_def(ctx, 2, -1);

    if (key_len > 0 && key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool auth = false;

    if (key_len > 0) {
        auth = true;
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (key_nr >= 0) {
        if (key_nr < ICLASS_KEYS_MAX) {
            auth = true;
            memcpy(key, iClass_Key_Table[key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), key_nr, sprint_hex(iClass_Key_Table[key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int blockno = arg_get_int_def(ctx, 3, 0);

    uint8_t keyType = 0x88; //debit key
    if (arg_get_lit(ctx, 4)) {
        PrintAndLogEx(SUCCESS, "Using " _YELLOW_("credit") " key");
        keyType = 0x18; //credit key
    }

    bool elite = arg_get_lit(ctx, 5);
    bool rawkey = arg_get_lit(ctx, 6);
    bool use_replay = arg_get_lit(ctx, 7);
    bool verbose = arg_get_lit(ctx, 8);
    bool shallow_mod = arg_get_lit(ctx, 9);

    CLIParserFree(ctx);

    if ((use_replay + rawkey + elite) > 1) {
        PrintAndLogEx(ERR, "Can not use a combo of 'elite', 'raw', 'nr'");
        return PM3_EINVARG;
    }

    if (verbose) {
        if (key_len > 0)
            PrintAndLogEx(SUCCESS, "Using key %s", sprint_hex(key, 8));
    }

    if (auth == false && verbose) {
        PrintAndLogEx(WARNING, "warning: no authentication used with read. Typical for cards configured into `non-secure page`");

    }

    uint8_t data[8] = {0};
    int res = iclass_read_block(key, blockno, keyType, elite, rawkey, use_replay, verbose, auth, shallow_mod, data);
    if (res != PM3_SUCCESS)
        return res;

    if (blockno < 6 || blockno > 7)
        return PM3_SUCCESS;

    if (memcmp(data, empty, 8) == 0)
        return PM3_SUCCESS;

    bool use_sc = IsCardHelperPresent(verbose);
    if (use_sc == false)
        return PM3_SUCCESS;

    // crypto helper available.
    PrintAndLogEx(INFO, "----------------------------- " _CYAN_("Cardhelper") " -----------------------------");

    switch (blockno) {
        case 6: {
            DecodeBlock6(data);
            break;
        }
        case 7: {

            uint8_t dec_data[PICOPASS_BLOCK_SIZE];

            uint64_t a = bytes_to_num(data, PICOPASS_BLOCK_SIZE);
            bool starts = (leadingzeros(a) < 12);
            bool ones = (bitcount64(a) > 16 && bitcount64(a) < 48);

            if (starts && ones) {
                PrintAndLogEx(INFO, "data looks encrypted, False Positives " _YELLOW_("ARE") " possible");
                Decrypt(data, dec_data);
                PrintAndLogEx(SUCCESS, "decrypted : " _GREEN_("%s"), sprint_hex(dec_data, sizeof(dec_data)));
            } else {
                memcpy(dec_data, data, sizeof(dec_data));
                PrintAndLogEx(INFO, "data looks unencrypted, trying to decode");
            }

            bool has_new_pacs = iclass_detect_new_pacs(dec_data);
            bool has_values = (memcmp(dec_data, empty, PICOPASS_BLOCK_SIZE) != 0) && (memcmp(dec_data, zeros, PICOPASS_BLOCK_SIZE) != 0);

            if (has_values) {

                if (has_new_pacs) {
                    iclass_decode_credentials_new_pacs(dec_data);
                } else {
                    //todo:  remove preamble/sentinel
                    uint32_t top = 0, mid = 0, bot = 0;

                    char hexstr[16 + 1] = {0};
                    hex_to_buffer((uint8_t *)hexstr, dec_data, PICOPASS_BLOCK_SIZE, sizeof(hexstr) - 1, 0, 0, true);
                    hexstring_to_u96(&top, &mid, &bot, hexstr);

                    char binstr[64 + 1];
                    hextobinstring(binstr, hexstr);
                    char *pbin = binstr;
                    while (strlen(pbin) && *(++pbin) == '0');

                    PrintAndLogEx(SUCCESS, "      bin : %s", pbin);
                    PrintAndLogEx(INFO, "");
                    PrintAndLogEx(INFO, "------------------------------ " _CYAN_("Wiegand") " -------------------------------");
                    decode_wiegand(top, mid, bot, 0);
                }
            } else {
                PrintAndLogEx(INFO, "no credential found");
            }
            break;
        }
    }
    PrintAndLogEx(INFO, "----------------------------------------------------------------------");
    return PM3_SUCCESS;
}

static int CmdHFiClass_TearBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass trbl",
                  "Tear off an iCLASS tag block",
                  "hf iclass trbl --blk 10 -d AAAAAAAAAAAAAAAA -k 001122334455667B --tdb 100 --tde 150\n"
                  "hf iclass trbl --blk 10 -d AAAAAAAAAAAAAAAA --ki 0  --tdb 100 --tde 150");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_str1("d", "data", "<hex>", "data to write as 8 hex bytes"),
        arg_str0("m", "mac", "<hex>", "replay mac data (4 hex bytes)"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_lit0(NULL, "nr", "replay of NR/MAC"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_int1(NULL, "tdb", "<dec>", "tearoff delay start in ms"),
        arg_int1(NULL, "tde", "<dec>", "tearoff delay end in ms"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int key_len = 0;
    uint8_t key[8] = {0};

    CLIGetHexWithReturn(ctx, 1, key, &key_len);

    int key_nr = arg_get_int_def(ctx, 2, -1);

    if (key_len > 0 && key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool auth = false;

    if (key_len > 0) {
        auth = true;
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (key_nr >= 0) {
        if (key_nr < ICLASS_KEYS_MAX) {
            auth = true;
            memcpy(key, iClass_Key_Table[key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), key_nr, sprint_hex(iClass_Key_Table[key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int blockno = arg_get_int_def(ctx, 3, 0);

    int data_len = 0;
    uint8_t data[8] = {0};
    CLIGetHexWithReturn(ctx, 4, data, &data_len);

    if (data_len != 8) {
        PrintAndLogEx(ERR, "Data must be 8 hex bytes (16 hex symbols)");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int mac_len = 0;
    uint8_t mac[4] = {0};
    CLIGetHexWithReturn(ctx, 5, mac, &mac_len);

    if (mac_len) {
        if (mac_len != 4) {
            PrintAndLogEx(ERR, "MAC must be 4 hex bytes (8 hex symbols)");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int tearoff_start = arg_get_int_def(ctx, 12, 100);
    int tearoff_end = arg_get_int_def(ctx, 13, 200);

    if (tearoff_end <= tearoff_start) {
        PrintAndLogEx(ERR, "Tearoff end delay must be bigger than the start delay.");
        return PM3_EINVARG;
    }

    if (tearoff_start < 0 || tearoff_end <= 0) {
        PrintAndLogEx(ERR, "Tearoff start/end delays should be bigger than 0.");
        return PM3_EINVARG;
    }

    bool use_credit_key = arg_get_lit(ctx, 6);
    bool elite = arg_get_lit(ctx, 7);
    bool rawkey = arg_get_lit(ctx, 8);
    bool use_replay = arg_get_lit(ctx, 9);
    bool verbose = arg_get_lit(ctx, 10);
    bool shallow_mod = arg_get_lit(ctx, 11);

    CLIParserFree(ctx);

    if ((use_replay + rawkey + elite) > 1) {
        PrintAndLogEx(ERR, "Can not use a combo of 'elite', 'raw', 'nr'");
        return PM3_EINVARG;
    }
    int isok = 0;
    tearoff_params_t params;
    bool read_ok = false;
    while (tearoff_start < tearoff_end && !read_ok) {
        //perform read here, repeat if failed or 00s

        uint8_t data_read_orig[8] = {0};
        bool first_read = false;
        bool reread = false;
        while (!first_read) {
            int res_orig = iclass_read_block_ex(key, blockno, 0x88, elite, rawkey, use_replay, verbose, auth, shallow_mod, data_read_orig, false);
            if (res_orig == PM3_SUCCESS && !reread) {
                if (memcmp(data_read_orig, zeros, 8) == 0) {
                    reread = true;
                } else {
                    first_read = true;
                    reread = false;
                }
            } else if (res_orig == PM3_SUCCESS && reread) {
                first_read = true;
                reread = false;
            }
        }

        params.on = true;
        params.delay_us = tearoff_start;
        handle_tearoff(&params, false);
        PrintAndLogEx(INFO, "Tear off delay: "_YELLOW_("%d")" ms", tearoff_start);
        isok = iclass_write_block(blockno, data, mac, key, use_credit_key, elite, rawkey, use_replay, verbose, auth, shallow_mod);
        switch (isok) {
            case PM3_SUCCESS:
                PrintAndLogEx(SUCCESS, "Wrote block " _YELLOW_("%d") " / " _YELLOW_("0x%02X") " ( " _GREEN_("ok") " )", blockno, blockno);
                break;
            case PM3_ETEAROFF:
                break;
            default:
                PrintAndLogEx(FAILED, "Writing failed");
                break;
        }
        //read the data back
        uint8_t data_read[8] = {0};
        first_read = false;
        reread = false;
        bool decrease = false;
        while (!first_read) {
            int res = iclass_read_block_ex(key, blockno, 0x88, elite, rawkey, use_replay, verbose, auth, shallow_mod, data_read, false);
            if (res == PM3_SUCCESS && !reread) {
                if (memcmp(data_read, zeros, 8) == 0) {
                    reread = true;
                } else {
                    first_read = true;
                    reread = false;
                }
            } else if (res == PM3_SUCCESS && reread) {
                first_read = true;
                reread = false;
            } else if (res != PM3_SUCCESS) {
                decrease = true;
            }
        }
        if (decrease && tearoff_start > 0) { //if there was an error reading repeat the tearoff with the same delay
            tearoff_start--;
        }
        bool tear_success = true;
        for (int i = 0; i < PICOPASS_BLOCK_SIZE; i++) {
            if (data[i] != data_read[i]) {
                tear_success = false;
            }
        }
        if (tear_success) { //tearoff succeeded
            read_ok = true;
            PrintAndLogEx(SUCCESS, _GREEN_("Tear-off Success!"));
            PrintAndLogEx(INFO, "Read: %s", sprint_hex(data_read, sizeof(data_read)));
        } else { //tearoff did not succeed
            PrintAndLogEx(FAILED, _RED_("Tear-off Failed!"));
            tearoff_start++;
        }
        PrintAndLogEx(INFO, "---------------");
    }
    PrintAndLogEx(NORMAL, "");
    return isok;
}

static int CmdHFiClass_loclass(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass loclass",
                  "Execute the offline part of loclass attack\n"
                  "  An iclass dumpfile is assumed to consist of an arbitrary number of\n"
                  "  malicious CSNs, and their protocol responses\n"
                  "  The binary format of the file is expected to be as follows: \n"
                  "  <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>\n"
                  "  <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>\n"
                  "  <8 byte CSN><8 byte CC><4 byte NR><4 byte MAC>\n"
                  "   ... totalling N*24 bytes",
                  "hf iclass loclass -f iclass_dump.bin\n"
                  "hf iclass loclass --test");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename with nr/mac data from `hf iclass sim -t 2` "),
        arg_lit0(NULL, "test",        "Perform self test"),
        arg_lit0(NULL, "long",        "Perform self test, including long ones"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool test = arg_get_lit(ctx, 2);
    bool longtest = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    if (test || longtest) {
        int errors = testCipherUtils();
        errors += testMAC();
        errors += doKeyTests();
        errors += testElite(longtest);

        if (errors != PM3_SUCCESS)
            PrintAndLogEx(ERR, "There were errors!!!");

        return PM3_ESOFT;
    }

    return bruteforceFileNoKeys(filename);
}

static void detect_credential(uint8_t *iclass_dump, size_t dump_len, bool *is_legacy, bool *is_se, bool *is_sr, uint8_t **sio_start_ptr, size_t *sio_length) {
    *is_legacy = false;
    *is_sr = false;
    *is_se = false;
    if (sio_start_ptr != NULL) {
        *sio_start_ptr = NULL;
    }
    if (sio_length != NULL) {
        *sio_length = 0;
    }

    if (dump_len < sizeof(picopass_hdr_t)) {
        // Can't really do anything with a dump that doesn't include the header
        return;
    }

    picopass_hdr_t *hdr = (picopass_hdr_t *)iclass_dump;

    if (!memcmp(hdr->app_issuer_area, "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
        // Legacy AIA
        *is_legacy = true;

        if (dump_len < 11 * PICOPASS_BLOCK_SIZE) {
            // Can't reliably detect if the card is SR without checking
            // blocks 6 and 10
            return;
        }

        // SR bit set in legacy config block
        if ((iclass_dump[6 * PICOPASS_BLOCK_SIZE] & ICLASS_CFG_BLK_SR_BIT) == ICLASS_CFG_BLK_SR_BIT) {
            // If the card is blank (all FF's) then we'll reach here too, so check for an empty block 10
            // to avoid false positivies
            if (memcmp(iclass_dump + (10 * PICOPASS_BLOCK_SIZE), "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
                *is_sr = true;
                if (sio_start_ptr != NULL) {
                    // SR SIO starts at block 10
                    *sio_start_ptr = iclass_dump + (10 * PICOPASS_BLOCK_SIZE);
                }
            }
        }
    } else if (!memcmp(hdr->app_issuer_area, "\xFF\xFF\xFF\x00\x06\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
        // SE AIA
        *is_se = true;

        if (sio_start_ptr != NULL) {
            // SE SIO starts at block 6
            *sio_start_ptr = iclass_dump + (6 * PICOPASS_BLOCK_SIZE);
        }
    }

    if (sio_length == NULL || sio_start_ptr == NULL || *sio_start_ptr == NULL) {
        // No need to calculate length
        return;
    }

    uint8_t *sio_start = *sio_start_ptr;

    if (sio_start[0] != 0x30) {
        // SIOs always start with a SEQUENCE(P), if this is missing then bail
        return;
    }

    if (sio_start[1] >= 0x80 || sio_start[1] == 0x00) {
        // We only support definite short form lengths
        return;
    }

    // Length of bytes within the SEQUENCE, plus tag and length bytes for the SEQUENCE tag
    *sio_length = sio_start[1] + 2;
}

// print ASN1 decoded array in TLV view
static void print_iclass_sio(uint8_t *iclass_dump, size_t dump_len) {
    bool is_legacy, is_se, is_sr;
    uint8_t *sio_start;
    size_t sio_length;
    detect_credential(iclass_dump, dump_len, &is_legacy, &is_se, &is_sr, &sio_start, &sio_length);

    if (sio_start == NULL) {
        return;
    }

    if (dump_len < sio_length + (sio_start - iclass_dump)) {
        // SIO length exceeds the size of the dump we have, bail
        return;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------------------- " _CYAN_("SIO - RAW") " ----------------------------");
    print_hex_noascii_break(sio_start, sio_length, 32);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------- " _CYAN_("SIO - ASN1 TLV") " --------------------------");
    asn1_print(sio_start, sio_length, "  ");
    PrintAndLogEx(NORMAL, "");
}

void printIclassDumpContents(uint8_t *iclass_dump, uint8_t startblock, uint8_t endblock, size_t filesize, bool dense_output) {

    picopass_hdr_t *hdr = (picopass_hdr_t *)iclass_dump;
//    picopass_ns_hdr_t *ns_hdr = (picopass_ns_hdr_t *)iclass_dump;
//    uint8_t pagemap = get_pagemap(hdr);
//    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) { }

    uint8_t lock = hdr->conf.block_writelock;

    // is chip in ReadOnly (RO)
    bool ro = ((lock & 0x80) == 0);

    uint8_t maxmemcount;
    uint8_t filemaxblock = filesize / 8;
    uint8_t mem_config = iclass_dump[13];

    if (mem_config & 0x80)
        maxmemcount = 255;
    else
        maxmemcount = 31;

    uint8_t pagemap = get_pagemap(hdr);

    if (startblock == 0) {
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            startblock = 3;
        } else {
            startblock = 6;
        }
    }

    if ((endblock > maxmemcount) || (endblock == 0))
        endblock = maxmemcount;

    // remember endblock needs to relate to zero-index arrays.
    if (endblock > filemaxblock - 1)
        endblock = filemaxblock - 1;

    /*
    PrintAndLogEx(INFO, "startblock: %u, endblock: %u, filesize: %zu, maxmemcount: %u, filemaxblock: %u"
        , startblock
        , endblock
        , filesize
        , maxmemcount
        , filemaxblock
    );
    */

    bool is_legacy, is_se, is_sr;
    uint8_t *sio_start;
    size_t sio_length;
    detect_credential(iclass_dump, endblock * 8, &is_legacy, &is_se, &is_sr, &sio_start, &sio_length);

    bool is_legacy_decrypted = is_legacy && (iclass_dump[(6 * PICOPASS_BLOCK_SIZE) + 7] & 0x03) == 0x00;

    int sio_start_block = 0, sio_end_block = 0;
    if (sio_start && sio_length > 0) {
        sio_start_block = (sio_start - iclass_dump) / PICOPASS_BLOCK_SIZE;
        sio_end_block = sio_start_block + ((sio_length + PICOPASS_BLOCK_SIZE - 1) / PICOPASS_BLOCK_SIZE) - 1;
    }

    int i = startblock;
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--------------------------- " _CYAN_("Tag memory") " ----------------------------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, " block#  | data                    | ascii    |lck| info");
    PrintAndLogEx(INFO, "---------+-------------------------+----------+---+----------------");
    PrintAndLogEx(INFO, "  0/0x00 | " _GREEN_("%s") "| " _GREEN_("%s") " |   | CSN "
                  , sprint_hex(iclass_dump, 8)
                  , sprint_ascii(iclass_dump, 8)
                 );

    if (i != 1)
        PrintAndLogEx(INFO, "  ......");

    bool in_repeated_block = false;
    while (i <= endblock) {
        uint8_t *blk = iclass_dump + (i * 8);

        bool bl_lock = false;
        if (ro == false) {
            switch (i) {
                case 12: {
                    bl_lock = ((lock & 0x40) == 0);
                    break;
                }
                case 11: {
                    bl_lock = ((lock & 0x20) == 0);
                    break;
                }
                case 10: {
                    bl_lock = ((lock & 0x10) == 0);
                    break;
                }
                case 9: {
                    bl_lock = ((lock & 0x08) == 0);
                    break;
                }
                case 8: {
                    bl_lock = ((lock & 0x04) == 0);
                    break;
                }
                case 7: {
                    bl_lock = ((lock & 0x02) == 0);
                    break;
                }
                case 6: {
                    bl_lock = ((lock & 0x01) == 0);
                    break;
                }
            }
        } else {
            bl_lock = true;
        }

        const char *lockstr = (bl_lock) ? _RED_("x") : " ";

        const char *block_info;
        bool regular_print_block = false;
        if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
            const char *info_nonks[] = {"CSN", "Config", "AIA", "User"};
            if (i < 3) {
                block_info = info_nonks[i];
            } else {
                block_info = info_nonks[3];
            }

            regular_print_block = true;
        } else {
            const char *info_ks[] = {"CSN", "Config", "E-purse", "Debit", "Credit", "AIA", "User", "User AA2"};

            if (i >= 6 && i <= 9 && is_legacy) {
                // legacy credential
                PrintAndLogEx(INFO, "%3d/0x%02X | " _YELLOW_("%s") "| " _YELLOW_("%s") " | %s | User / %s "
                              , i
                              , i
                              , sprint_hex(blk, 8)
                              , sprint_ascii(blk, 8)
                              , lockstr
                              , i == 6 ? "HID CFG" : (is_legacy_decrypted ? "Cred" : "Enc Cred")
                             );
            } else if (sio_start_block != 0 && i >= sio_start_block && i <= sio_end_block) {
                // SIO credential
                PrintAndLogEx(INFO, "%3d/0x%02X | " _CYAN_("%s") "| " _CYAN_("%s") " | %s | User / SIO / %s"
                              , i
                              , i
                              , sprint_hex(blk, 8)
                              , sprint_ascii(blk, 8)
                              , lockstr
                              , is_se ? "SE" : "SR"
                             );
            } else {
                if (i < 6) {
                    block_info = info_ks[i];
                } else if (i > hdr->conf.app_limit) {
                    block_info = info_ks[7];
                } else {
                    block_info = info_ks[6];
                }

                regular_print_block = true;
            }
        }

        if (regular_print_block) {
            // suppress repeating blocks, truncate as such that the first and last block with the same data is shown
            // but the blocks in between are replaced with a single line of "......" if dense_output is enabled
            if (dense_output && i > 6 && i < (endblock - 1) && !in_repeated_block && !memcmp(blk, blk - 8, 8) &&
                    !memcmp(blk, blk + 8, 8) && !memcmp(blk, blk + 16, 8)) {
                // we're in a user block that isn't the first user block nor last two user blocks,
                // and the current block data is the same as the previous and next two block
                in_repeated_block = true;
                PrintAndLogEx(INFO, "  ......");
            } else if (in_repeated_block && (memcmp(blk, blk + 8, 8) || i == endblock)) {
                // in a repeating block, but the next block doesn't match anymore, or we're at the end block
                in_repeated_block = false;
            }

            if (in_repeated_block == false) {
                PrintAndLogEx(INFO,
                              "%3d/0x%02X | %s | %s | %s",
                              i,
                              i,
                              sprint_hex_ascii(blk, 8),
                              lockstr,
                              block_info);
            }
        }

        i++;
    }
    PrintAndLogEx(INFO, "---------+-------------------------+----------+---+----------------");
    if (is_legacy)
        PrintAndLogEx(HINT, _YELLOW_("yellow") " = legacy credential");

    if (is_se)
        PrintAndLogEx(HINT, _CYAN_("cyan") " = SIO / SE credential");

    if (is_sr)
        PrintAndLogEx(HINT, _CYAN_("cyan") " = SIO / SR credential");

    PrintAndLogEx(NORMAL, "");
}

static int CmdHFiClassView(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass view",
                  "Print a iCLASS tag dump file (bin/eml/json)",
                  "hf iclass view -f hf-iclass-AA162D30F8FF12F1-dump.bin\n"
                  "hf iclass view --first 1 -f hf-iclass-AA162D30F8FF12F1-dump.bin\n\n"
                  "If --first is not specified it will default to the first user block\n"
                  "which is block 6 for secured chips or block 3 for non-secured chips");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>",  "Specify a filename for dump file"),
        arg_int0(NULL, "first", "<dec>", "Begin printing from this block (default first user block)"),
        arg_int0(NULL, "last", "<dec>", "End printing at this block (default 0, ALL)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int startblock = arg_get_int_def(ctx, 2, 0);
    int endblock = arg_get_int_def(ctx, 3, 0);
    bool verbose = arg_get_lit(ctx, 4);
    bool dense_output = g_session.dense_output || arg_get_lit(ctx, 5);

    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 2048;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, 2048);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), filename);
        PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, (uint16_t)(bytes_read >> 3), (uint16_t)(bytes_read >> 3));
        PrintAndLogEx(INFO, "Printing blocks from: " _YELLOW_("%02d") " to: " _YELLOW_("%02d"), (startblock == 0) ? 6 : startblock, endblock);
    }

    PrintAndLogEx(NORMAL, "");
    print_picopass_header((picopass_hdr_t *) dump);
    print_picopass_info((picopass_hdr_t *) dump);
    printIclassDumpContents(dump, startblock, endblock, bytes_read, dense_output);
    iclass_decode_credentials(dump);

    if (verbose) {
        print_iclass_sio(dump, bytes_read);
    }

    free(dump);
    return PM3_SUCCESS;
}

void HFiClassCalcDivKey(uint8_t *CSN, uint8_t *KEY, uint8_t *div_key, bool elite) {
    if (elite) {
        uint8_t keytable[128] = {0};
        uint8_t key_index[8] = {0};
        uint8_t key_sel[8] = { 0 };
        uint8_t key_sel_p[8] = { 0 };
        hash2(KEY, keytable);
        hash1(CSN, key_index);
        for (uint8_t i = 0; i < 8 ; i++)
            key_sel[i] = keytable[key_index[i]];

        //Permute from iclass format to standard format
        permutekey_rev(key_sel, key_sel_p);
        diversifyKey(CSN, key_sel_p, div_key);
    } else {
        diversifyKey(CSN, KEY, div_key);
    }
}

//when told CSN, oldkey, newkey, if new key is elite (elite), and if old key was elite (oldElite)
//calculate and return xor_div_key (ready for a key write command)
//print all div_keys if verbose
static void HFiClassCalcNewKey(uint8_t *CSN, uint8_t *OLDKEY, uint8_t *NEWKEY, uint8_t *xor_div_key, bool elite, bool oldElite, bool verbose) {
    uint8_t old_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t new_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    //get old div key
    HFiClassCalcDivKey(CSN, OLDKEY, old_div_key, oldElite);
    //get new div key
    HFiClassCalcDivKey(CSN, NEWKEY, new_div_key, elite);

    for (uint8_t i = 0; i < ARRAYLEN(old_div_key); i++) {
        xor_div_key[i] = old_div_key[i] ^ new_div_key[i];
    }
    if (verbose) {
        PrintAndLogEx(SUCCESS, "Old div key......... %s", sprint_hex(old_div_key, 8));
        PrintAndLogEx(SUCCESS, "New div key......... %s", sprint_hex(new_div_key, 8));
        PrintAndLogEx(SUCCESS, "Xor div key......... " _YELLOW_("%s") "\n", sprint_hex(xor_div_key, 8));
    }
}

static int CmdHFiClassCalcNewKey(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass calcnewkey",
                  "Calculate new keys for updating (blocks 3 & 4)",
                  "hf iclass calcnewkey --old 1122334455667788 --new 2233445566778899 --csn deadbeafdeadbeaf --elite2 -> e key to e key given csn\n"
                  "hf iclass calcnewkey --old 1122334455667788 --new 2233445566778899 --elite                         -> std key to e key read csn\n"
                  "hf iclass calcnewkey --old 1122334455667788 --new 2233445566778899                                 -> std to std read csn");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "old", "<hex>", "Specify key as 8 hex bytes"),
        arg_int0(NULL, "oki", "<dec>", "Old key index to select key from memory 'hf iclass managekeys'"),
        arg_str0(NULL, "new", "<hex>", "Specify key as 8 hex bytes"),
        arg_int0(NULL, "nki", "<dec>", "New key index to select key from memory 'hf iclass managekeys'"),
        arg_str0(NULL, "csn", "<hex>", "Specify a Card Serial Number (CSN) to diversify the key (if omitted will attempt to read a CSN)"),
        arg_lit0(NULL, "elite", "Elite computations applied to new key"),
        arg_lit0(NULL, "elite2", "Elite computations applied to both old and new key"),
        arg_lit0(NULL, "oldelite", "Elite computations applied only to old key"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int old_key_len = 0;
    uint8_t old_key[8] = {0};
    CLIGetHexWithReturn(ctx, 1, old_key, &old_key_len);

    int old_key_nr = arg_get_int_def(ctx, 2, -1);

    if (old_key_len > 0 && old_key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify old key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (old_key_len > 0) {
        if (old_key_len != 8) {
            PrintAndLogEx(ERR, "Old key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (old_key_nr >= 0) {
        if (old_key_nr < ICLASS_KEYS_MAX) {
            memcpy(old_key, iClass_Key_Table[old_key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using old key[%d]... " _GREEN_("%s"), old_key_nr, sprint_hex(iClass_Key_Table[old_key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(ERR, "Please specify an old key or old key index");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int new_key_len = 0;
    uint8_t new_key[8] = {0};
    CLIGetHexWithReturn(ctx, 3, new_key, &new_key_len);

    int new_key_nr = arg_get_int_def(ctx, 4, -1);

    if (new_key_len > 0 && new_key_nr >= 0) {
        PrintAndLogEx(ERR, "Please specify new key or index, not both");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    if (new_key_len > 0) {
        if (new_key_len != 8) {
            PrintAndLogEx(ERR, "New key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else if (new_key_nr >= 0) {
        if (new_key_nr < ICLASS_KEYS_MAX) {
            memcpy(new_key, iClass_Key_Table[new_key_nr], 8);
            PrintAndLogEx(SUCCESS, "Using new key[%d]... " _GREEN_("%s"), new_key_nr, sprint_hex(iClass_Key_Table[new_key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key number is invalid");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(ERR, "Please specify an new key or old key index");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int csn_len = 0;
    uint8_t csn[8] = {0};
    CLIGetHexWithReturn(ctx, 5, csn, &csn_len);
    bool givenCSN = false;

    if (csn_len > 0) {
        givenCSN = true;
        if (csn_len != 8) {
            PrintAndLogEx(ERR, "CSN is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    bool elite = arg_get_lit(ctx, 6);
    bool old_elite = false;

    if (arg_get_lit(ctx, 7)) {
        elite = true;
        old_elite = true;
    }

    if (arg_get_lit(ctx, 8)) {
        elite = false;
        old_elite = true;
    }

    CLIParserFree(ctx);

    uint8_t xor_div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (givenCSN == false) {
        uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
        if (select_only(csn, CCNR, true, false) == false) {
            DropField();
            return PM3_ESOFT;
        }
    }

    HFiClassCalcNewKey(csn, old_key, new_key, xor_div_key, elite, old_elite, true);

    return PM3_SUCCESS;
}

static int iclass_load_keys(char *filename) {

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, "", (void **)&dump, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    if (bytes_read > ICLASS_KEYS_MAX *  PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(WARNING, "File is too long to load - bytes: %zu", bytes_read);
        free(dump);
        return PM3_EFILE;
    }
    size_t i = 0;
    for (; i < bytes_read / PICOPASS_BLOCK_SIZE; i++) {
        memcpy(iClass_Key_Table[i], dump + (i * PICOPASS_BLOCK_SIZE), PICOPASS_BLOCK_SIZE);
    }

    free(dump);
    PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2zd") " keys from %s", i, filename);
    return PM3_SUCCESS;
}

static int iclass_print_keys(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "idx| key");
    PrintAndLogEx(INFO, "---+------------------------");
    for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
        if (memcmp(iClass_Key_Table[i], zeros, sizeof(zeros)) == 0)
            PrintAndLogEx(INFO, " %u |", i);
        else
            PrintAndLogEx(INFO, " %u | " _YELLOW_("%s"), i, sprint_hex(iClass_Key_Table[i], PICOPASS_BLOCK_SIZE));
    }
    PrintAndLogEx(INFO, "---+------------------------");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFiClassManageKeys(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass managekeys",
                  "Manage iCLASS Keys in client memory",
                  "hf iclass managekeys --ki 0 -k 1122334455667788 --> set key 1122334455667788 at index 0\n"
                  "hf iclass managekeys -f mykeys.bin --save       --> save key file\n"
                  "hf iclass managekeys -f mykeys.bin --load       --> load key file\n"
                  "hf iclass managekeys -p                         --> print keys");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for load / save operations"),
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Specify key index to set key in memory"),
        arg_lit0(NULL, "save", "Save keys in memory to file specified by filename"),
        arg_lit0(NULL, "load", "Load keys to memory from file specified by filename"),
        arg_lit0("p", "print", "Print keys loaded into memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int key_len = 0;
    uint8_t key[8] = {0};
    CLIGetHexWithReturn(ctx, 2, key, &key_len);
    uint8_t operation = 0;

    if (key_len > 0) {
        operation += 3;
        if (key_len != 8) {
            PrintAndLogEx(ERR, "Key is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int key_nr = arg_get_int_def(ctx, 3, -1);

    if (key_nr >= 0) {
        if (key_nr < ICLASS_KEYS_MAX) {
            PrintAndLogEx(SUCCESS, "Current key[%d] " _YELLOW_("%s"), key_nr, sprint_hex_inrow(iClass_Key_Table[key_nr], 8));
        } else {
            PrintAndLogEx(ERR, "Key index is out-of-range");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    if (arg_get_lit(ctx, 4)) {  //save
        operation += 6;
    }
    if (arg_get_lit(ctx, 5)) {  //load
        operation += 5;
    }
    if (arg_get_lit(ctx, 6)) {  //print
        operation += 4;
    }

    CLIParserFree(ctx);

    if (operation == 0) {
        PrintAndLogEx(ERR, "No operation specified (load, save, or print)\n");
        return PM3_EINVARG;
    }
    if (operation > 6) {
        PrintAndLogEx(ERR, "Too many operations specified\n");
        return PM3_EINVARG;
    }
    if (operation > 4 && fnlen == 0) {
        PrintAndLogEx(ERR, "You must enter a filename when loading or saving\n");
        return PM3_EINVARG;
    }
    if (key_len > 0 && key_nr == -1) {
        PrintAndLogEx(ERR, "Please specify key index when specifying key");
        return PM3_EINVARG;
    }

    switch (operation) {
        case 3:
            memcpy(iClass_Key_Table[key_nr], key, 8);
            PrintAndLogEx(SUCCESS, "    New key[%d] " _GREEN_("%s"), key_nr, sprint_hex_inrow(iClass_Key_Table[key_nr], 8));
            return PM3_SUCCESS;
        case 4:
            return iclass_print_keys();
        case 5:
            return iclass_load_keys(filename);
        case 6: {
            bool isOK = saveFile(filename, ".bin", iClass_Key_Table, sizeof(iClass_Key_Table));
            if (isOK == false) {
                return PM3_EFILE;
            }
        }
    }
    return PM3_SUCCESS;
}

static void add_key(uint8_t *key) {

    uint8_t i;
    for (i = 0; i < ICLASS_KEYS_MAX; i++) {

        if (memcmp(iClass_Key_Table[i], key, 8) == 0) {
            PrintAndLogEx(SUCCESS, "Key already at keyslot " _GREEN_("%d"), i);
            break;
        }

        if (memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0) {
            memcpy(iClass_Key_Table[i], key, 8);
            PrintAndLogEx(SUCCESS, "Added key to keyslot " _GREEN_("%d"), i);
            break;
        }
    }

    if (i == ICLASS_KEYS_MAX) {
        PrintAndLogEx(INFO, "Couldn't find an empty keyslot");
    } else {
        PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass managekeys -p") "` to view keys");
    }
}

static int CmdHFiClassCheckKeys(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass chk",
                  "Checkkeys loads a dictionary text file with 8byte hex keys to test authenticating against a iClass tag",
                  "hf iclass chk -f iclass_default_keys.dic\n"
                  "hf iclass chk -f iclass_elite_keys.dic --elite\n"
                  "hf iclass chk --vb6kdf\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Dictionary file with default iclass keys"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key (raw)"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_lit0(NULL, "vb6kdf", "use the VB6 elite KDF instead of a file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    bool use_vb6kdf = arg_get_lit(ctx, 6);
    bool use_elite = arg_get_lit(ctx, 3);
    bool use_raw = arg_get_lit(ctx, 4);
    if (use_vb6kdf) {
        use_elite = true;
    } else {
        CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    }

    bool use_credit_key = arg_get_lit(ctx, 2);
    bool shallow_mod = arg_get_lit(ctx, 5);

    CLIParserFree(ctx);

    uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    // no filename and don't use algorithm for elite
    // just add the default dictionary
    if ((strlen(filename) == 0) && (use_vb6kdf == false)) {

        if (use_elite) {
            PrintAndLogEx(INFO, "Using default elite dictionary");
            snprintf(filename, sizeof(filename), ICLASS_DEFAULT_KEY_ELITE_DIC);
        } else {
            PrintAndLogEx(INFO, "Using default dictionary");
            snprintf(filename, sizeof(filename), ICLASS_DEFAULT_KEY_DIC);
        }
    }

    uint64_t t1 = msclock();

    // load keys
    uint8_t *keyBlock = NULL;
    uint32_t keycount = 0;

    if (use_vb6kdf) {
        // Generate 5000 keys using VB6 KDF
        keycount = 5000;
        keyBlock = calloc(1, keycount * 8);
        if (keyBlock == NULL) {
            return PM3_EMALLOC;
        }

        picopass_elite_reset();
        for (uint32_t i = 0; i < keycount; i++) {
            picopass_elite_nextKey(keyBlock + (i * 8));
        }
    } else {
        // Load keys
        int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
        if (res != PM3_SUCCESS || keycount == 0) {
            free(keyBlock);
            return res;
        }
    }

    // limit size of keys that can be held in memory
    if (keycount > 100000) {
        PrintAndLogEx(FAILED, "File contains more than 100 000 keys, aborting...");
        free(keyBlock);
        return PM3_EFILE;
    }

    // Get CSN / UID and CCNR
    PrintAndLogEx(SUCCESS, "Reading tag CSN / CCNR...");

    bool got_csn = false;
    for (uint8_t i = 0; i < ICLASS_AUTH_RETRY; i++) {
        got_csn = select_only(CSN, CCNR, false, shallow_mod);
        if (got_csn == false)
            PrintAndLogEx(WARNING, "one more try");
        else
            break;
    }

    if (got_csn == false) {
        PrintAndLogEx(WARNING, "Tried %d times. Can't select card, aborting...", ICLASS_AUTH_RETRY);
        free(keyBlock);
        DropField();
        return PM3_ESOFT;
    }

    // allocate memory for the pre calculated macs
    iclass_premac_t *pre = calloc(keycount, sizeof(iclass_premac_t));
    if (pre == NULL) {
        PrintAndLogEx(WARNING, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s"), sprint_hex(CSN, sizeof(CSN)));
    PrintAndLogEx(SUCCESS, "   CCNR: " _GREEN_("%s"), sprint_hex(CCNR, sizeof(CCNR)));

    PrintAndLogEx(INFO, "Generating diversified keys %s", (use_elite || use_raw) ? NOLF : "");

    if (use_elite)
        PrintAndLogEx(NORMAL, "using " _YELLOW_("elite algo"));

    if (use_raw)
        PrintAndLogEx(NORMAL, "using " _YELLOW_("raw mode"));

    GenerateMacFrom(CSN, CCNR, use_raw, use_elite, keyBlock, keycount, pre);

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") " key...", (use_credit_key) ? "CREDIT" : "DEBIT");

    // USB_COMMAND.  512/4 = 103 mac
    uint32_t max_chunk_size = 0;
    if (keycount > ((PM3_CMD_DATA_SIZE - sizeof(iclass_chk_t)) / 4))
        max_chunk_size = (PM3_CMD_DATA_SIZE - sizeof(iclass_chk_t)) / 4;
    else
        max_chunk_size = keycount;

    // fast push mode
    g_conn.block_after_ACK = true;

    // keep track of position of found key
    uint32_t chunk_offset = 0;
    uint8_t found_offset = 0;
    bool found_key = false;

    // We have
    //  - a list of keys.
    //  - a list of precalculated macs that corresponds to the key list
    // We send a chunk of macs to the device each time

    // main keychunk loop
    for (chunk_offset = 0; chunk_offset < keycount; chunk_offset += max_chunk_size) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "aborted via keyboard!");
            goto out;
        }

        uint32_t curr_chunk_cnt = keycount - chunk_offset;
        if ((keycount - chunk_offset)  > max_chunk_size) {
            curr_chunk_cnt = max_chunk_size;
        }

        // last chunk?
        if (curr_chunk_cnt == keycount - chunk_offset) {
            // Disable fast mode on last command
            g_conn.block_after_ACK = false;
        }

        uint32_t tmp_plen = sizeof(iclass_chk_t) + (4 * curr_chunk_cnt);
        iclass_chk_t *packet = calloc(tmp_plen,  sizeof(uint8_t));
        if (packet == NULL) {
            PrintAndLogEx(WARNING, "failed to allocate memory");
            break;
        }
        packet->use_credit_key = use_credit_key;
        packet->count = curr_chunk_cnt;
        packet->shallow_mod = shallow_mod;
        // copy chunk of pre calculated macs to packet
        memcpy(packet->items, (pre + chunk_offset), (4 * curr_chunk_cnt));

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_CHKKEYS, (uint8_t *)packet, tmp_plen);
        free(packet);

        bool looped = false;
        uint8_t timeout = 0;

        PacketResponseNG resp;
        while (WaitForResponseTimeout(CMD_HF_ICLASS_CHKKEYS, &resp, 2000) == false) {
            timeout++;
            PrintAndLogEx(NORMAL, "." NOLF);
            if (timeout > 10) {
                PrintAndLogEx(WARNING, "\ncommand execution time out, aborting...");
                goto out;
            }
            looped = true;
        }

        if (looped)
            PrintAndLogEx(NORMAL, "");

        if (resp.status == PM3_SUCCESS) {
            found_offset = resp.data.asBytes[0];
            found_key = true;
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS,
                          "Found valid key " _GREEN_("%s")
                          , sprint_hex(keyBlock + (chunk_offset + found_offset) * 8, 8)
                         );
            break;
        } else {
            PrintAndLogEx(INPLACE, "Chunk [%03d/%d]", chunk_offset, keycount);
            fflush(stdout);
        }
    }

out:
    t1 = msclock() - t1;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "time in iclass chk " _YELLOW_("%.1f") " seconds", (float)t1 / 1000.0);
    DropField();

    if (found_key) {
        uint8_t *key = keyBlock + (chunk_offset + found_offset) * 8;
        add_key(key);
    }

    free(pre);
    free(keyBlock);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}


// this method tries to identify in which configuration mode a iCLASS / iCLASS SE reader is in.
// Standard or Elite / HighSecurity mode.  It uses a default key dictionary list in order to work.
#define INITIAL_SEED 0x429080 // VB6 KDF Seed Value

// Functions for generating keys using RNG
uint32_t seed = INITIAL_SEED;
uint8_t key_state[8];
bool prepared = false;

void picopass_elite_reset(void) {
    memset(key_state, 0, sizeof(key_state));
    seed = INITIAL_SEED;
    prepared = false;
}

uint32_t picopass_elite_lcg(void) {
    uint32_t mod = 0x1000000; // 2^24
    uint32_t a = 0xFD43FD;
    uint32_t c = 0xC39EC3;

    return (a * seed + c) % mod;
}

uint32_t picopass_elite_rng(void) {
    seed = picopass_elite_lcg();
    return seed;
}

uint8_t picopass_elite_nextByte(void) {
    return (picopass_elite_rng() >> 16) & 0xFF;
}

void picopass_elite_nextKey(uint8_t *key) {
    if (prepared) {
        for (size_t i = 0; i < 7; i++) {
            key_state[i] = key_state[i + 1];
        }
        key_state[7] = picopass_elite_nextByte();
    } else {
        for (size_t i = 0; i < 8; i++) {
            key_state[i] = picopass_elite_nextByte();
        }
        prepared = true;
    }
    memcpy(key, key_state, 8);
}

static int iclass_recover(uint8_t key[8], uint32_t index_start, uint32_t loop, uint8_t no_first_auth[8], bool debug, bool test, bool allnight) {

    int runs = 1;
    int cycle = 1;
    bool repeat = true;
    if (allnight) {
        runs = 10;
    }

    while (repeat == true) {
        uint32_t payload_size = sizeof(iclass_recover_req_t);
        uint8_t aa2_standard_key[PICOPASS_BLOCK_SIZE] = {0};
        memcpy(aa2_standard_key, iClass_Key_Table[1], PICOPASS_BLOCK_SIZE);
        iclass_recover_req_t *payload = calloc(1, payload_size);
        payload->req.use_raw = true;
        payload->req.use_elite = false;
        payload->req.use_credit_key = false;
        payload->req.use_replay = true;
        payload->req.send_reply = true;
        payload->req.do_auth = true;
        payload->req.shallow_mod = false;
        payload->req2.use_raw = false;
        payload->req2.use_elite = false;
        payload->req2.use_credit_key = true;
        payload->req2.use_replay = false;
        payload->req2.send_reply = true;
        payload->req2.do_auth = true;
        payload->req2.shallow_mod = false;
        payload->index = index_start;
        payload->loop = loop;
        payload->debug = debug;
        payload->test = test;
        memcpy(payload->nfa, no_first_auth, PICOPASS_BLOCK_SIZE);
        memcpy(payload->req.key, key, PICOPASS_BLOCK_SIZE);
        memcpy(payload->req2.key, aa2_standard_key, PICOPASS_BLOCK_SIZE);

        PrintAndLogEx(INFO, "Recover started...");

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ICLASS_RECOVER, (uint8_t *)payload, payload_size);
        WaitForResponse(CMD_HF_ICLASS_RECOVER, &resp);

        if (resp.status == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "iCLASS Key Bits Recovery: " _GREEN_("completed!"));
            repeat = false;
        } else if (resp.status == PM3_ESOFT) {
            PrintAndLogEx(WARNING, "iCLASS Key Bits Recovery: " _RED_("failed/errors"));
            repeat = false;
        } else if (resp.status == PM3_EINVARG) {
            if (allnight) {
                if (runs <= cycle) {
                    repeat = false;
                } else {
                    index_start = index_start + loop;
                    cycle++;
                }
            } else {
                repeat = false;
            }
        }
        free(payload);
        if (!repeat) {
            return resp.status;
        }
    }
    return PM3_SUCCESS;
}

void generate_key_block_inverted(const uint8_t *startingKey, uint64_t index, uint8_t *keyBlock) {
    uint64_t carry = index;
    memcpy(keyBlock, startingKey, PICOPASS_BLOCK_SIZE);

    for (int j = PICOPASS_BLOCK_SIZE - 1; j >= 0; j--) {
        uint8_t increment_value = (carry & 0x1F) << 3;  // Use the first 5 bits of carry and shift left by 3 to occupy the first 5 bits
        keyBlock[j] = (keyBlock[j] & 0x07) | increment_value;  // Preserve last 3 bits, modify the first 5 bits

        carry >>= 5;  // Shift right by 5 bits for the next byte
        if (carry == 0) {
            // If no more carry, break early to avoid unnecessary loops
            break;
        }
    }
}

static int CmdHFiClassLegRecLookUp(const char *Cmd) {

    //Standalone Command Start
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass legbrute",
                  "This command take sniffed trace data and partial raw key and bruteforces the remaining 40 bits of the raw key.",
                  "hf iclass legbrute --epurse feffffffffffffff --macs1 1306cad9b6c24466 --macs2 f0bf905e35f97923 --pk B4F12AADC5301225"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "epurse", "<hex>", "Specify ePurse as 8 hex bytes"),
        arg_str1(NULL, "macs1", "<hex>", "MACs captured from the reader"),
        arg_str1(NULL, "macs2", "<hex>", "MACs captured from the reader, different than the first set (with the same csn and epurse value)"),
        arg_str1(NULL, "pk", "<hex>", "Partial Key from legrec or starting key of keyblock from legbrute"),
        arg_int0(NULL, "index", "<dec>", "Where to start from to retrieve the key, default 0 - value in millions e.g. 1 is 1 million"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int epurse_len = 0;
    uint8_t epurse[PICOPASS_BLOCK_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 1, epurse, &epurse_len);

    int macs_len = 0;
    uint8_t macs[PICOPASS_BLOCK_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 2, macs, &macs_len);

    int macs2_len = 0;
    uint8_t macs2[PICOPASS_BLOCK_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 3, macs2, &macs2_len);

    int startingkey_len = 0;
    uint8_t startingKey[PICOPASS_BLOCK_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 4, startingKey, &startingkey_len);

    uint64_t index = arg_get_int_def(ctx, 6, 0); //has to be 64 as we're bruteforcing 40 bits
    index = index * 1000000;

    CLIParserFree(ctx);

    if (epurse_len && epurse_len != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(ERR, "ePurse is incorrect length");
        return PM3_EINVARG;
    }

    if (macs_len && macs_len != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(ERR, "MAC1 is incorrect length");
        return PM3_EINVARG;
    }

    if (macs2_len && macs2_len != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(ERR, "MAC2 is incorrect length");
        return PM3_EINVARG;
    }

    if (startingkey_len && startingkey_len != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(ERR, "Partial Key is incorrect length");
        return PM3_EINVARG;
    }
    //Standalone Command End

    uint8_t CCNR[12];
    uint8_t MAC_TAG[4] = {0, 0, 0, 0};
    uint8_t CCNR2[12];
    uint8_t MAC_TAG2[4] = {0, 0, 0, 0};

    // Copy CCNR and MAC_TAG
    memcpy(CCNR, epurse, 8);
    memcpy(CCNR2, epurse, 8);
    memcpy(CCNR + 8, macs, 4);
    memcpy(CCNR2 + 8, macs2, 4);
    memcpy(MAC_TAG, macs + 4, 4);
    memcpy(MAC_TAG2, macs2 + 4, 4);

    PrintAndLogEx(SUCCESS, " Epurse: %s", sprint_hex(epurse, 8));
    PrintAndLogEx(SUCCESS, "   MACS1: %s", sprint_hex(macs, 8));
    PrintAndLogEx(SUCCESS, "   MACS2: %s", sprint_hex(macs2, 8));
    PrintAndLogEx(SUCCESS, "   CCNR1: " _GREEN_("%s"), sprint_hex(CCNR, sizeof(CCNR)));
    PrintAndLogEx(SUCCESS, "   CCNR2: " _GREEN_("%s"), sprint_hex(CCNR2, sizeof(CCNR2)));
    PrintAndLogEx(SUCCESS, "TAG MAC1: %s", sprint_hex(MAC_TAG, sizeof(MAC_TAG)));
    PrintAndLogEx(SUCCESS, "TAG MAC2: %s", sprint_hex(MAC_TAG2, sizeof(MAC_TAG2)));
    PrintAndLogEx(SUCCESS, "Starting Key: %s", sprint_hex(startingKey, 8));

    bool verified = false;
    uint8_t div_key[PICOPASS_BLOCK_SIZE] = {0};
    uint8_t generated_mac[4] = {0, 0, 0, 0};

    while (!verified) {

        //generate the key block
        generate_key_block_inverted(startingKey, index, div_key);

        //generate the relevant macs

        doMAC(CCNR, div_key, generated_mac);
        bool mac_match = true;
        for (int i = 0; i < 4; i++) {
            if (MAC_TAG[i] != generated_mac[i]) {
                mac_match = false;
            }
        }

        if (mac_match) {
            //verify this against macs2
            PrintAndLogEx(WARNING, _YELLOW_("Found potentially valid RAW key ") _GREEN_("%s")_YELLOW_(" verifying it..."), sprint_hex(div_key, 8));
            //generate the macs from the key and not the other way around, so we can quickly validate it
            uint8_t verification_mac[4] = {0, 0, 0, 0};
            doMAC(CCNR2, div_key, verification_mac);
            PrintAndLogEx(INFO, "Usr Provided Mac2: " _GREEN_("%s"), sprint_hex(MAC_TAG2, sizeof(MAC_TAG2)));
            PrintAndLogEx(INFO, "Verification  Mac: " _GREEN_("%s"), sprint_hex(verification_mac, sizeof(verification_mac)));
            bool check_values = true;
            for (int i = 0; i < 4; i++) {
                if (MAC_TAG2[i] != verification_mac[i]) {
                    check_values = false;
                }
            }
            if (check_values) {
                PrintAndLogEx(SUCCESS, _GREEN_("CONFIRMED VALID RAW key ") _RED_("%s"), sprint_hex(div_key, 8));
                PrintAndLogEx(INFO, "You can now run ->  "_YELLOW_("hf iclass unhash -k %s")"  <-to find the pre-images.", sprint_hex(div_key, 8));
                verified = true;
            } else {
                PrintAndLogEx(INFO, _YELLOW_("Raw Key Invalid"));
            }

        }
        if (index % 1000000 == 0) {
            PrintAndLogEx(INFO, "Tested: " _YELLOW_("%" PRIu64)" million keys", index / 1000000);
            PrintAndLogEx(INFO, "Last Generated Key Value: " _YELLOW_("%s"), sprint_hex(div_key, 8));
        }
        index++;
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static void generate_single_key_block_inverted_opt(const uint8_t *startingKey, uint32_t index, uint8_t *keyBlock) {

    uint8_t bits_index = index / 16383;
    uint8_t ending_bits[] = { //all possible 70 combinations of 4x0 and 4x1 as key ending bits
        0x0F, 0x17, 0x1B, 0x1D, 0x1E, 0x27, 0x2B, 0x2D, 0x2E, 0x33,
        0x35, 0x36, 0x39, 0x3A, 0x3C, 0x47, 0x4B, 0x4D, 0x4E, 0x53,
        0x55, 0x56, 0x59, 0x5A, 0x5C, 0x63, 0x65, 0x66, 0x69, 0x6A,
        0x6C, 0x71, 0x72, 0x74, 0x78, 0x87, 0x8B, 0x8D, 0x8E, 0x93,
        0x95, 0x96, 0x99, 0x9A, 0x9C, 0xA3, 0xA5, 0xA6, 0xA9, 0xAA,
        0xAC, 0xB1, 0xB2, 0xB4, 0xB8, 0xC3, 0xC5, 0xC6, 0xC9, 0xCA,
        0xCC, 0xD1, 0xD2, 0xD4, 0xD8, 0xE1, 0xE2, 0xE4, 0xE8, 0xF0
    };

    uint8_t binary_endings[8]; // Array to store binary values for each ending bit
    // Extract each bit from the ending_bits[k] and store it in binary_endings
    uint8_t ending = ending_bits[bits_index];
    for (int i = 7; i >= 0; i--) {
        binary_endings[i] = ending & 1;
        ending >>= 1;
    }

    uint8_t binary_mids[8];    // Array to store the 2-bit chunks of index
    // Iterate over the 16-bit integer and store 2 bits at a time in the result array
    for (int i = 0; i < 8; i++) {
        // Shift and mask to get 2 bits and store them as an 8-bit value
        binary_mids[7 - i] = (index >> (i * 2)) & 0x03; // 0x03 is a mask for 2 bits (binary 11)
    }

    memcpy(keyBlock, startingKey, PICOPASS_BLOCK_SIZE);

    // Start from the second byte, index 1 as we're never gonna touch the first byte
    for (int i = 1; i < PICOPASS_BLOCK_SIZE; i++) {
        // Clear the last bit of the current byte (AND with 0xFE)
        keyBlock[i] &= 0xF8;
        // Set the last bit to the corresponding value from binary_endings (OR with binary_endings[i])
        keyBlock[i] |= ((binary_mids[i] & 0x03) << 1) | (binary_endings[i] & 0x01);
    }

}

static int CmdHFiClassLegacyRecSim(void) {

    PrintAndLogEx(INFO, _YELLOW_("This simulation assumes the card is standard keyed."));

    uint8_t key[PICOPASS_BLOCK_SIZE] = {0};
    uint8_t original_key[PICOPASS_BLOCK_SIZE];

    uint8_t csn[8] = {0};
    uint8_t new_div_key[8] = {0};
    uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    if (select_only(csn, CCNR, true, false) == false) {
        DropField();
        return PM3_ESOFT;
    }
    HFiClassCalcDivKey(csn, iClass_Key_Table[0], new_div_key, false);
    memcpy(key, new_div_key, PICOPASS_BLOCK_SIZE);
    memcpy(original_key, key, PICOPASS_BLOCK_SIZE);

    uint8_t zero_key[PICOPASS_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t zero_key_two[PICOPASS_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    int bits_found = -1;
    uint32_t index = 0;
#define MAX_UPDATES 16777216
    while (bits_found == -1 && index < MAX_UPDATES) {
        uint8_t genkeyblock[PICOPASS_BLOCK_SIZE];
        uint8_t xorkeyblock[PICOPASS_BLOCK_SIZE] = {0};

        generate_single_key_block_inverted_opt(zero_key, index, genkeyblock);
        memcpy(xorkeyblock, genkeyblock, PICOPASS_BLOCK_SIZE);

        for (int i = 0; i < 8 ; i++) {
            key[i] = xorkeyblock[i] ^ original_key[i];
            memcpy(zero_key_two, xorkeyblock, PICOPASS_BLOCK_SIZE);
        }

        // Extract the last 3 bits of the first byte
        uint8_t last_three_bits = key[0] & 0x07; // 0x07 is 00000111 in binary - bitmask
        bool same_bits = true;
        // Check if the last 3 bits of all bytes are the same
        for (int i = 1; i < PICOPASS_BLOCK_SIZE; i++) {
            if ((key[i] & 0x07) != last_three_bits) {
                same_bits = false;
            }
        }
        if (same_bits) {
            bits_found = index;
            PrintAndLogEx(SUCCESS, "Original Key: " _GREEN_("%s"), sprint_hex(original_key, sizeof(original_key)));
            PrintAndLogEx(SUCCESS, "Weak Key: " _GREEN_("%s"), sprint_hex(key, sizeof(key)));
            PrintAndLogEx(SUCCESS, "Key Updates Required to Weak Key: " _GREEN_("%d"), index);
            PrintAndLogEx(SUCCESS, "Estimated Time: ~" _GREEN_("%d")" hours", index / 6545);
        }

        index++;
    }//end while

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;

}

static int CmdHFiClassLegacyRecover(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass legrec",
                  "Attempts to recover the diversified key of a specific iClass card. This may take a long time. The Card must remain be on the PM3 antenna during the whole process! This process may brick the card!",
                  "hf iclass legrec --macs 0000000089cb984b\n"
                  "hf iclass legrec --macs 0000000089cb984b --index 0 --loop 100 --notest"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "macs", "<hex>", "AA1 Authentication MACs"),
        arg_int0(NULL, "index", "<dec>", "Where to start from to retrieve the key, default 0"),
        arg_int0(NULL, "loop", "<dec>", "The number of key retrieval cycles to perform, max 10000, default 100"),
        arg_lit0(NULL, "debug", "Re-enables tracing for debugging. Limits cycles to 1."),
        arg_lit0(NULL, "notest", "Perform real writes on the card!"),
        arg_lit0(NULL, "allnight", "Loops the loop for 10 times, recommended loop value of 5000."),
        arg_lit0(NULL, "est", "Estimates the key updates based on the card's CSN assuming standard key."),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int macs_len = 0;
    uint8_t macs[PICOPASS_BLOCK_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 1, macs, &macs_len);
    uint32_t index = arg_get_int_def(ctx, 2, 0);
    uint32_t loop = arg_get_int_def(ctx, 3, 100);
    uint8_t no_first_auth[PICOPASS_BLOCK_SIZE] = {0};
    bool debug = arg_get_lit(ctx, 4);
    bool test = true;
    bool no_test = arg_get_lit(ctx, 5);
    bool allnight = arg_get_lit(ctx, 6);
    bool sim = arg_get_lit(ctx, 7);

    if (sim) {
        CmdHFiClassLegacyRecSim();
        return PM3_SUCCESS;
    }

    if (no_test) {
        test = false;
    }

    if (loop > 10000) {
        PrintAndLogEx(ERR, "Too many loops, arm prone to crashes. For safety specify a number lower than 10000");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    } else if (debug || test) {
        loop = 1;
    }

    uint8_t csn[PICOPASS_BLOCK_SIZE] = {0};
    uint8_t new_div_key[PICOPASS_BLOCK_SIZE] = {0};
    uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (select_only(csn, CCNR, true, false) == false) {
        DropField();
        return PM3_ESOFT;
    }
    diversifyKey(csn, iClass_Key_Table[1], new_div_key);
    memcpy(no_first_auth, new_div_key, PICOPASS_BLOCK_SIZE);

    CLIParserFree(ctx);

    if (macs_len && macs_len != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(ERR, "MAC is incorrect length");
        return PM3_EINVARG;
    }

    iclass_recover(macs, index, loop, no_first_auth, debug, test, allnight);

    PrintAndLogEx(WARNING, _YELLOW_("If the process completed successfully, you can now run 'hf iclass legbrute' with the partial key found."));

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;

}

static int CmdHFiClassUnhash(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass unhash",
                  "Reverses the hash0 function used generate iclass diversified keys after DES encryption,\n"
                  "Function returns the DES crypted CSN.  Next step bruteforcing.",
                  "hf iclass unhash -k B4F12AADC5301A2D"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("k", "divkey", "<hex>", "Card diversified key"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int dk_len = 0;
    uint8_t div_key[PICOPASS_BLOCK_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 1, div_key, &dk_len);

    CLIParserFree(ctx);

    if (dk_len && dk_len != PICOPASS_BLOCK_SIZE) {
        PrintAndLogEx(ERR, "Diversified key is incorrect length");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Diversified key... %s", sprint_hex_inrow(div_key, sizeof(div_key)));

    invert_hash0(div_key);

    PrintAndLogEx(SUCCESS, "You can now retrieve the master key by cracking DES with hashcat!");
    PrintAndLogEx(SUCCESS, "hashcat.exe -a 3 -m 14000 preimage:csn -1 charsets/DES_full.hcchr --hex-charset ?1?1?1?1?1?1?1?1");

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFiClassLookUp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass lookup",
                  "This command take sniffed trace data and try to recovery a iCLASS Standard or iCLASS Elite key.",
                  "hf iclass lookup --csn 9655a400f8ff12e0 --epurse f0ffffffffffffff --macs 0000000089cb984b -f iclass_default_keys.dic\n"
                  "hf iclass lookup --csn 9655a400f8ff12e0 --epurse f0ffffffffffffff --macs 0000000089cb984b -f iclass_default_keys.dic --elite\n"
                  "hf iclass lookup --csn 9655a400f8ff12e0 --epurse f0ffffffffffffff --macs 0000000089cb984b --vb6rng"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Dictionary file with default iclass keys"),
        arg_str1(NULL, "csn", "<hex>", "Specify CSN as 8 hex bytes"),
        arg_str1(NULL, "epurse", "<hex>", "Specify ePurse as 8 hex bytes"),
        arg_str1(NULL, "macs", "<hex>", "MACs"),
        arg_lit0(NULL, "elite", "Elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_lit0(NULL, "vb6rng", "use the VB6 rng for elite keys instead of a dictionary file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool use_vb6kdf = arg_get_lit(ctx, 7);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};

    bool use_elite = arg_get_lit(ctx, 5);
    bool use_raw = arg_get_lit(ctx, 6);
    if (use_vb6kdf) {
        use_elite = true;
    } else {
        CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    }

    int csn_len = 0;
    uint8_t csn[8] = {0};
    CLIGetHexWithReturn(ctx, 2, csn, &csn_len);

    if (csn_len > 0) {
        if (csn_len != 8) {
            PrintAndLogEx(ERR, "CSN is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int epurse_len = 0;
    uint8_t epurse[8] = {0};
    CLIGetHexWithReturn(ctx, 3, epurse, &epurse_len);

    if (epurse_len > 0) {
        if (epurse_len != 8) {
            PrintAndLogEx(ERR, "ePurse is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    int macs_len = 0;
    uint8_t macs[8] = {0};
    CLIGetHexWithReturn(ctx, 4, macs, &macs_len);

    if (macs_len > 0) {
        if (macs_len != 8) {
            PrintAndLogEx(ERR, "MAC is incorrect length");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    CLIParserFree(ctx);

    uint8_t CCNR[12];
    uint8_t MAC_TAG[4] = { 0, 0, 0, 0 };

    // Stupid copy.. CCNR is a combo of epurse and reader nonce
    memcpy(CCNR, epurse, 8);
    memcpy(CCNR + 8, macs, 4);
    memcpy(MAC_TAG, macs + 4, 4);

    PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s"), sprint_hex(csn, sizeof(csn)));
    PrintAndLogEx(SUCCESS, " Epurse: %s", sprint_hex(epurse, sizeof(epurse)));
    PrintAndLogEx(SUCCESS, "   MACS: %s", sprint_hex(macs, sizeof(macs)));
    PrintAndLogEx(SUCCESS, "   CCNR: " _GREEN_("%s"), sprint_hex(CCNR, sizeof(CCNR)));
    PrintAndLogEx(SUCCESS, "TAG MAC: %s", sprint_hex(MAC_TAG, sizeof(MAC_TAG)));

    // Run time
    uint64_t t1 = msclock();

    uint8_t *keyBlock = NULL;
    uint32_t keycount = 0;

    if (!use_vb6kdf) {
        // Load keys
        int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
        if (res != PM3_SUCCESS || keycount == 0) {
            free(keyBlock);
            return res;
        }
    } else {
        // Generate 5000 keys using VB6 KDF
        keycount = 5000;
        keyBlock = calloc(1, keycount * 8);
        if (keyBlock == NULL)  {
            return PM3_EMALLOC;
        }

        picopass_elite_reset();
        for (uint32_t i = 0; i < keycount; i++) {
            picopass_elite_nextKey(keyBlock + (i * 8));
        }
    }

    // Iclass_prekey_t
    iclass_prekey_t *prekey = calloc(keycount, sizeof(iclass_prekey_t));
    if (!prekey) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Generating diversified keys...");
    GenerateMacKeyFrom(csn, CCNR, use_raw, use_elite, keyBlock, keycount, prekey);

    if (use_elite) {
        PrintAndLogEx(INFO, "Using " _YELLOW_("elite algo"));
    }

    if (use_raw) {
        PrintAndLogEx(INFO, "Using " _YELLOW_("raw mode"));
    }

    PrintAndLogEx(INFO, "Sorting...");

    // Sort mac list
    qsort(prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") " key...", "DEBIT");
    iclass_prekey_t *item;
    iclass_prekey_t lookup;
    memcpy(lookup.mac, MAC_TAG, 4);

    // Binsearch
    item = (iclass_prekey_t *) bsearch(&lookup, prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    if (item != NULL) {
        PrintAndLogEx(SUCCESS, "Found valid key " _GREEN_("%s"), sprint_hex(item->key, 8));
        add_key(item->key);
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "Time in iclass lookup " _YELLOW_("%.3f") " seconds", (float)t1 / 1000.0);

    free(prekey);
    free(keyBlock);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

typedef struct {
    uint8_t thread_idx;
    uint8_t use_raw;
    uint8_t use_elite;
    uint32_t keycnt;
    uint8_t csn[8];
    uint8_t cc_nr[12];
    uint8_t *keys;
    union {
        iclass_premac_t *premac;
        iclass_prekey_t *prekey;
    } list;
} PACKED iclass_thread_arg_t;

static size_t iclass_tc = 1;

static pthread_mutex_t generator_mutex = PTHREAD_MUTEX_INITIALIZER;
static void *bf_generate_mac(void *thread_arg) {

    iclass_thread_arg_t *targ = (iclass_thread_arg_t *)thread_arg;
    const uint8_t idx = targ->thread_idx;
    const uint8_t use_raw = targ->use_raw;
    const uint8_t use_elite = targ->use_elite;
    const uint32_t keycnt = targ->keycnt;

    uint8_t *keys = targ->keys;
    iclass_premac_t *list = targ->list.premac;

    uint8_t csn[8];
    uint8_t cc_nr[12];
    memcpy(csn, targ->csn, sizeof(csn));
    memcpy(cc_nr, targ->cc_nr, sizeof(cc_nr));

    uint8_t key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (uint32_t i = idx; i < keycnt; i += iclass_tc) {

        memcpy(key, keys + 8 * i, 8);

        pthread_mutex_lock(&generator_mutex);
        if (use_raw)
            memcpy(div_key, key, 8);
        else
            HFiClassCalcDivKey(csn, key, div_key, use_elite);

        doMAC(cc_nr, div_key, list[i].mac);
        pthread_mutex_unlock(&generator_mutex);
    }
    return NULL;
}

// precalc diversified keys and their MAC
void GenerateMacFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, uint32_t keycnt, iclass_premac_t *list) {

    pthread_mutex_init(&generator_mutex, NULL);

    iclass_tc = num_CPUs();
    pthread_t threads[iclass_tc];
    iclass_thread_arg_t args[iclass_tc];
    // init thread arguments
    for (size_t i = 0; i < iclass_tc; i++) {
        args[i].thread_idx = i;
        args[i].use_raw = use_raw;
        args[i].use_elite = use_elite;
        args[i].keycnt = keycnt;
        args[i].keys = keys;
        args[i].list.premac = list;

        memcpy(args[i].csn, CSN, sizeof(args[i].csn));
        memcpy(args[i].cc_nr, CCNR, sizeof(args[i].cc_nr));
    }

    for (int i = 0; i < iclass_tc; i++) {
        int res = pthread_create(&threads[i], NULL, bf_generate_mac, (void *)&args[i]);
        if (res) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Failed to create pthreads. Quitting");
            return;
        }
    }

    for (int i = 0; i < iclass_tc; i++)
        pthread_join(threads[i], NULL);
}

static void *bf_generate_mackey(void *thread_arg) {

    iclass_thread_arg_t *targ = (iclass_thread_arg_t *)thread_arg;
    const uint8_t idx = targ->thread_idx;
    const uint8_t use_raw = targ->use_raw;
    const uint8_t use_elite = targ->use_elite;
    const uint32_t keycnt = targ->keycnt;

    uint8_t *keys = targ->keys;
    iclass_prekey_t *list = targ->list.prekey;

    uint8_t csn[8];
    uint8_t cc_nr[12];
    memcpy(csn, targ->csn, sizeof(csn));
    memcpy(cc_nr, targ->cc_nr, sizeof(cc_nr));

    uint8_t div_key[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    for (uint32_t i = idx; i < keycnt; i += iclass_tc) {

        memcpy(list[i].key, keys + 8 * i, 8);

        pthread_mutex_lock(&generator_mutex);
        if (use_raw)
            memcpy(div_key, list[i].key, 8);
        else
            HFiClassCalcDivKey(csn, list[i].key, div_key, use_elite);

        doMAC(cc_nr, div_key, list[i].mac);
        pthread_mutex_unlock(&generator_mutex);
    }
    return NULL;
}

void GenerateMacKeyFrom(uint8_t *CSN, uint8_t *CCNR, bool use_raw, bool use_elite, uint8_t *keys, uint32_t keycnt, iclass_prekey_t *list) {

    pthread_mutex_init(&generator_mutex, NULL);
    iclass_tc = num_CPUs();
    pthread_t threads[iclass_tc];
    iclass_thread_arg_t args[iclass_tc];
    // init thread arguments
    for (size_t i = 0; i < iclass_tc; i++) {
        args[i].thread_idx = i;
        args[i].use_raw = use_raw;
        args[i].use_elite = use_elite;
        args[i].keycnt = keycnt;
        args[i].keys = keys;
        args[i].list.prekey = list;

        memcpy(args[i].csn, CSN, sizeof(args[i].csn));
        memcpy(args[i].cc_nr, CCNR, sizeof(args[i].cc_nr));
    }

    for (size_t i = 0; i < iclass_tc; i++) {
        int res = pthread_create(&threads[i], NULL, bf_generate_mackey, (void *)&args[i]);
        if (res) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Failed to create pthreads. Quitting");
            return;
        }
    }

    for (int i = 0; i < iclass_tc; i++)
        pthread_join(threads[i], NULL);

}

// print diversified keys
void PrintPreCalcMac(uint8_t *keys, uint32_t keycnt, iclass_premac_t *pre_list) {

    iclass_prekey_t *b = calloc(keycnt, sizeof(iclass_prekey_t));
    if (!b)
        return;

    for (uint32_t i = 0; i < keycnt; i++) {
        memcpy(b[i].key, keys + 8 * i, 8);
        memcpy(b[i].mac, pre_list[i].mac, 4);
    }
    PrintPreCalc(b, keycnt);
    free(b);
}

void PrintPreCalc(iclass_prekey_t *list, uint32_t itemcnt) {
    PrintAndLogEx(NORMAL, "-----+------------------+---------");
    PrintAndLogEx(NORMAL, "#key | key              | mac");
    PrintAndLogEx(NORMAL, "-----+------------------+---------");
    for (int i = 0; i < itemcnt; i++) {

        if (i < 10) {
            PrintAndLogEx(NORMAL, "[%2d] | %016" PRIx64 " | %08" PRIx64, i, bytes_to_num(list[i].key, 8), bytes_to_num(list[i].mac, 4));
        } else if (i == 10) {
            PrintAndLogEx(SUCCESS, "... skip printing the rest");
        }
    }
}

static void permute(uint8_t *data, uint8_t len, uint8_t *output) {
#define KEY_SIZE 8

    if (len > KEY_SIZE) {
        for (uint8_t m = 0; m < len; m += KEY_SIZE) {
            permute(data + m, KEY_SIZE, output + m);
        }
        return;
    }
    if (len != KEY_SIZE) {
        PrintAndLogEx(WARNING, "wrong key size\n");
        return;
    }
    for (uint8_t i = 0; i < KEY_SIZE; ++i) {
        uint8_t p = 0;
        uint8_t mask = 0x80 >> i;
        for (uint8_t j = 0; j < KEY_SIZE; ++j) {
            p >>= 1;
            if (data[j] & mask)
                p |= 0x80;
        }
        output[i] = p;
    }
}
static void permute_rev(uint8_t *data, uint8_t len, uint8_t *output) {
    permute(data, len, output);
    permute(output, len, data);
    permute(data, len, output);
}
static void simple_crc(const uint8_t *data, uint8_t len, uint8_t *output) {
    uint8_t crc = 0;
    for (uint8_t i = 0; i < len; ++i) {
        // seventh byte contains the crc.
        if ((i & 0x7) == 0x7) {
            output[i] = crc ^ 0xFF;
            crc = 0;
        } else {
            output[i] = data[i];
            crc ^= data[i];
        }
    }
}
// DES doesn't use the MSB.
static void shave(uint8_t *data, uint8_t len) {
    for (uint8_t i = 0; i < len; ++i)
        data[i] &= 0xFE;
}
static void generate_rev(uint8_t *data, uint8_t len) {
    uint8_t *key = calloc(len, sizeof(uint8_t));
    PrintAndLogEx(SUCCESS, "input permuted key | %s \n", sprint_hex(data, len));
    permute_rev(data, len, key);
    PrintAndLogEx(SUCCESS, "    unpermuted key | %s \n", sprint_hex(key, len));
    shave(key, len);
    PrintAndLogEx(SUCCESS, "               key | %s \n", sprint_hex(key, len));
    free(key);
}
static void generate(uint8_t *data, uint8_t len) {
    uint8_t *key = calloc(len, sizeof(uint8_t));
    uint8_t *pkey = calloc(len, sizeof(uint8_t));
    PrintAndLogEx(SUCCESS, "   input key | %s \n", sprint_hex(data, len));
    permute(data, len, pkey);
    PrintAndLogEx(SUCCESS, "permuted key | %s \n", sprint_hex(pkey, len));
    simple_crc(pkey, len, key);
    PrintAndLogEx(SUCCESS, "  CRC'ed key | %s \n", sprint_hex(key, len));
    free(key);
    free(pkey);
}

static int CmdHFiClassPermuteKey(const char *Cmd) {

    uint8_t key[8] = {0};
    uint8_t data[16] = {0};
    int len = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass permutekey",
                  "Permute function from 'heart of darkness' paper.",
                  "hf iclass permutekey --reverse --key 0123456789abcdef\n"
                  "hf iclass permutekey --key ff55330f0055330f\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", "reverse", "reverse permuted key"),
        arg_str1(NULL, "key", "<hex>", "input key, 8 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool isReverse = arg_get_lit(ctx, 1);
    CLIGetHexWithReturn(ctx, 2, data, &len);
    CLIParserFree(ctx);

    memcpy(key, data, 8);

    if (isReverse) {
        generate_rev(data, len);
        uint8_t key_std_format[8] = {0};
        permutekey_rev(key, key_std_format);
        PrintAndLogEx(SUCCESS, "Standard NIST format key " _YELLOW_("%s") " \n", sprint_hex(key_std_format, 8));
    } else {
        generate(data, len);
        uint8_t key_iclass_format[8] = {0};
        permutekey(key, key_iclass_format);
        PrintAndLogEx(SUCCESS, "HID permuted iCLASS format: %s \n", sprint_hex(key_iclass_format, 8));
    }
    return PM3_SUCCESS;
}

static int CmdHFiClassEncode(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass encode",
                  "Encode binary wiegand to block 7,8,9\n"
                  "Use either --bin or --wiegand/--fc/--cn",
                  "hf iclass encode --bin 10001111100000001010100011 --ki 0            -> FC 31 CN 337 (H10301)\n"
                  "hf iclass encode -w H10301 --fc 31 --cn 337 --ki 0                  -> FC 31 CN 337 (H10301)\n"
                  "hf iclass encode --bin 10001111100000001010100011 --ki 0 --elite    -> FC 31 CN 337 (H10301), writing w elite key\n"
                  "hf iclass encode -w H10301 --fc 31 --cn 337 --emu                   -> Writes the ecoded data to emulator memory\n"
                  "When using emulator you have to first load a credential into emulator memory"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_str0(NULL, "enckey", "<hex>", "3DES transport key, 16 hex bytes"),
        arg_u64_0(NULL, "fc", "<dec>", "facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "card number"),
        arg_u64_0(NULL, "issue", "<dec>", "issue level"),
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_lit0(NULL, "emu", "Write to emulation memory instead of card"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_lit0("v", NULL, "verbose (print encoded blocks)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // can only do one block of 8 bytes currently.  There are room for two blocks in the specs.
    uint8_t bin[65] = {0};
    int bin_len = sizeof(bin) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 1, bin, &bin_len);

    int key_nr = arg_get_int_def(ctx, 2, -1);
    bool use_emulator_memory = arg_get_lit(ctx, 11);

    bool auth = false;
    uint8_t key[8] = {0};

    // If we use emulator memory skip key requirement
    if (use_emulator_memory == false) {
        if (key_nr < 0) {
            PrintAndLogEx(ERR, "Missing required arg for --ki or --emu");
            return PM3_EINVARG;
        }

        if (key_nr >= 0) {
            if (key_nr < ICLASS_KEYS_MAX) {
                auth = true;
                memcpy(key, iClass_Key_Table[key_nr], 8);
                PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), key_nr, sprint_hex(iClass_Key_Table[key_nr], 8));
            } else {
                PrintAndLogEx(ERR, "Key number is invalid");
                CLIParserFree(ctx);
                return PM3_EINVARG;
            }
        }
    }

    bool use_credit_key = arg_get_lit(ctx, 3);
    bool elite = arg_get_lit(ctx, 4);
    bool rawkey = arg_get_lit(ctx, 5);

    int enc_key_len = 0;
    uint8_t enc_key[16] = {0};
    uint8_t *enckeyptr = NULL;
    bool have_enc_key = false;
    bool use_sc = false;
    CLIGetHexWithReturn(ctx, 6, enc_key, &enc_key_len);

    // FC / CN / Issue Level
    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));

    card.FacilityCode = arg_get_u32_def(ctx, 7, 0);
    card.CardNumber = arg_get_u32_def(ctx, 8, 0);
    card.IssueLevel = arg_get_u32_def(ctx, 9, 0);

    char format[16] = {0};
    int format_len = 0;

    CLIParamStrToBuf(arg_get_str(ctx, 10), (uint8_t *)format, sizeof(format), &format_len);

    bool shallow_mod = arg_get_lit(ctx, 12);
    bool verbose = arg_get_lit(ctx, 13);

    CLIParserFree(ctx);

    if ((rawkey + elite) > 1) {
        PrintAndLogEx(ERR, "Can not use a combo of 'elite', 'raw'");
        return PM3_EINVARG;
    }

    if (enc_key_len > 0) {
        if (enc_key_len != 16) {
            PrintAndLogEx(ERR, "Transport key must be 16 hex bytes (32 HEX characters)");
            return PM3_EINVARG;
        }
        have_enc_key = true;
    }

    if (bin_len > 64) {
        PrintAndLogEx(ERR, "Binary wiegand string must be less than 64 bits");
        return PM3_EINVARG;
    }

    if (bin_len == 0 && card.FacilityCode == 0 && card.CardNumber == 0) {
        PrintAndLogEx(ERR, "Must provide either --cn/--fc or --bin");
        return PM3_EINVARG;
    }

    if (have_enc_key == false) {
        // The IsCardHelperPresent function clears the emulator memory
        if (use_emulator_memory) {
            use_sc = false;
        } else {
            use_sc = IsCardHelperPresent(false);
        }
        if (use_sc == false) {
            size_t keylen = 0;
            int res = loadFile_safe(ICLASS_DECRYPTION_BIN, "", (void **)&enckeyptr, &keylen);
            if (res != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Failed to find the transport key");
                return PM3_EINVARG;
            }
            if (keylen != 16) {
                PrintAndLogEx(ERR, "Failed to load transport key from file");
                free(enckeyptr);
                return PM3_EINVARG;
            }
            memcpy(enc_key, enckeyptr, sizeof(enc_key));
            free(enckeyptr);
        }
    }

    uint8_t credential[] = {
        0x03, 0x03, 0x03, 0x03, 0x00, 0x03, 0xE0, 0x17,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    };

    uint8_t data[8];
    memset(data, 0, sizeof(data));
    BitstreamOut_t bout = {data, 0, 0 };

    for (int i = 0; i < 64 - bin_len - 1; i++) {
        pushBit(&bout, 0);
    }
    // add binary sentinel bit.
    pushBit(&bout, 1);

    // convert binary string to hex bytes
    for (int i = 0; i < bin_len; i++) {
        char c = bin[i];
        if (c == '1')
            pushBit(&bout, 1);
        else if (c == '0')
            pushBit(&bout, 0);
        else {
            PrintAndLogEx(WARNING, "Ignoring '%c'", c);
        }
    }

    if (bin_len) {
        memcpy(credential + 8, data, sizeof(data));
    } else {
        wiegand_message_t packed;
        memset(&packed, 0, sizeof(wiegand_message_t));

        int format_idx = HIDFindCardFormat(format);
        if (format_idx == -1) {
            PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
            return PM3_EINVARG;
        }

        if (HIDPack(format_idx, &card, &packed, false) == false) {
            PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
            return PM3_ESOFT;
        }

        // iceman: only for formats w length smaller than 37.
        // Needs a check.

        // increase length to allow setting bit just above real data
        packed.Length++;
        // Set sentinel bit
        set_bit_by_position(&packed, true, 0);

#ifdef HOST_LITTLE_ENDIAN
        packed.Mid = BSWAP_32(packed.Mid);
        packed.Bot = BSWAP_32(packed.Bot);
#endif

        memcpy(credential + 8, &packed.Mid, sizeof(packed.Mid));
        memcpy(credential + 12, &packed.Bot, sizeof(packed.Bot));
    }

    // encrypt with transport key
    if (use_sc) {
        Encrypt(credential + 8, credential + 8);
        Encrypt(credential + 16, credential + 16);
        Encrypt(credential + 24, credential + 24);
    } else {
        iclass_encrypt_block_data(credential + 8, enc_key);
        iclass_encrypt_block_data(credential + 16, enc_key);
        iclass_encrypt_block_data(credential + 24, enc_key);
    }

    if (verbose) {
        for (uint8_t i = 0; i < 4; i++) {
            PrintAndLogEx(INFO, "Block %d/0x0%x -> " _YELLOW_("%s"), 6 + i, 6 + i, sprint_hex_inrow(credential + (i * 8), 8));
        }
    }

    if (!g_session.pm3_present) {
        PrintAndLogEx(ERR, "Device offline\n");
        return PM3_EFAILED;
    }

    int isok = PM3_SUCCESS;
    // write
    if (use_emulator_memory) {
        uint16_t byte_sent = 0;
        iclass_upload_emul(credential, sizeof(credential), 6 * PICOPASS_BLOCK_SIZE, &byte_sent);
        PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", byte_sent);
        PrintAndLogEx(HINT, "You are now ready to simulate. See " _YELLOW_("`hf iclass sim -h`"));
    } else {
        for (uint8_t i = 0; i < 4; i++) {
            isok = iclass_write_block(6 + i, credential + (i * 8), NULL, key, use_credit_key, elite, rawkey, false, false, auth, shallow_mod);
            switch (isok) {
                case PM3_SUCCESS:
                    PrintAndLogEx(SUCCESS, "Write block %d/0x0%x ( " _GREEN_("ok") " )  --> " _YELLOW_("%s"), 6 + i, 6 + i, sprint_hex_inrow(credential + (i * 8), 8));
                    break;
                default:
                    PrintAndLogEx(INFO, "Write block %d/0x0%x ( " _RED_("fail") " )", 6 + i, 6 + i);
                    break;
            }
        }
    }
    return isok;
}

/*
static int CmdHFiClassAutopwn(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass autopwn",
                  "Tries to check keys, if found,  dump card and save file",
                  "hf iclass autopwn\n");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    // Check keys.

    // dump

    PrintAndLogEx(INFO, "to be implemented");
    return PM3_SUCCESS;
}
*/

static int CmdHFiClassConfigCard(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass configcard",
                  "Manage reader configuration card via Cardhelper or internal database,\n"
                  "The generated config card will be uploaded to device emulator memory.\n"
                  "You can start simulating `hf iclass sim -t 3` or use the emul commands",
                  "hf iclass configcard -p           --> print all config cards in the database\n"
                  "hf iclass configcard --g 0        --> generate config file with option 0"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "g", "<dec>", "use config option"),
        arg_int0(NULL, "ki", "<dec>", "Card Key - index to select key from memory 'hf iclass managekeys'"),
        arg_int0(NULL, "eki", "<dec>", "Elite Key - index to select key from memory 'hf iclass managekeys'"),
        arg_int0(NULL, "mrki", "<dec>", "Standard Master Key - index to select key from memory 'hf iclass managekeys'"),
        arg_lit0(NULL, "elite", "Use elite key for the the Card Key ki"),
        arg_lit0("p", NULL, "print available cards"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int ccidx = arg_get_int_def(ctx, 1, -1);
    int card_kidx = arg_get_int_def(ctx, 2, -1);
    int kidx = arg_get_int_def(ctx, 3, -1);
    int midx = arg_get_int_def(ctx, 4, -1);
    bool elite = arg_get_lit(ctx, 5);
    bool do_print = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    bool got_eki = false;
    uint8_t card_key[8] = {0};
    if (card_kidx >= 0) {
        if (card_kidx < ICLASS_KEYS_MAX) {
            got_eki = true;
            memcpy(card_key, iClass_Key_Table[card_kidx], 8);
            PrintAndLogEx(SUCCESS, "Using card key[%d] " _GREEN_("%s"), card_kidx, sprint_hex(iClass_Key_Table[card_kidx], 8));
        } else {
            PrintAndLogEx(ERR, "--ki number is invalid");
            return PM3_EINVARG;
        }
    }

    bool got_kr = false;
    uint8_t keyroll_key[8] = {0};
    if (kidx >= 0) {
        if (kidx < ICLASS_KEYS_MAX) {
            got_kr = true;
            memcpy(keyroll_key, iClass_Key_Table[kidx], 8);
            PrintAndLogEx(SUCCESS, "Using keyroll key[%d] " _GREEN_("%s"), kidx, sprint_hex(iClass_Key_Table[kidx], 8));
        } else {
            PrintAndLogEx(ERR, "--eki number is invalid");
            return PM3_EINVARG;
        }
    }

    bool got_mk = false;
    uint8_t master_key[8] = {0};
    if (midx >= 0) {
        if (midx < ICLASS_KEYS_MAX) {
            got_mk = true;
            uint8_t key_iclass_format[8] = {0};
            permutekey(iClass_Key_Table[midx], key_iclass_format);
            memcpy(master_key, key_iclass_format, 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] as new Reader's Master Key" _GREEN_("%s"), midx, sprint_hex(iClass_Key_Table[midx], 8));
        } else {
            PrintAndLogEx(ERR, "--mrki number is invalid");
            return PM3_EINVARG;
        }
    }

    if (do_print) {
        print_config_cards();
    }

    if (ccidx > -1 && ccidx < ARRAYLEN(iclass_config_options)) {
        const iclass_config_card_item_t *item = get_config_card_item(ccidx);
        if (strstr(item->desc, "ELITE") != NULL && got_kr == false) {
            PrintAndLogEx(ERR, "please specify ELITE Key (--eki) !");
            return PM3_EINVARG;
        }
        if (strstr(item->desc, "Custom") != NULL && got_mk == false) {
            PrintAndLogEx(ERR, "please specify New Standard Master Key (--mrki) !");
            return PM3_EINVARG;
        }
        if (strstr(item->desc, "Restore") != NULL && card_kidx == -1) {
            PrintAndLogEx(ERR, "please specify the Current Reader's Key (--ki) !");
            return PM3_EINVARG;
        }
        generate_config_card(item, keyroll_key, got_kr, card_key, got_eki, elite, got_mk, master_key);
    }

    return PM3_SUCCESS;
}

static int CmdHFiClassSAM(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass sam",
                  "Extract PACS via a HID SAM\n",
                  "hf iclass sam\n"
                  "hf iclass sam -p -d a005a103800104 -> get PACS data, but ensure that epurse will stay unchanged\n"
                  "hf iclass sam --break-on-nr-mac -> get Nr-MAC for extracting encrypted SIO\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0("k", "keep", "keep the field active after command executed"),
        arg_lit0("n", "nodetect", "skip selecting the card and sending card details to SAM"),
        arg_lit0("t",  "tlv",      "decode TLV"),
        arg_lit0(NULL, "break-on-nr-mac", "stop tag interaction on nr-mac"),
        arg_lit0("p", "prevent-epurse-update", "fake epurse update"),
        arg_lit0(NULL, "shallow", "shallow mod"),
        arg_strx0("d", "data",     "<hex>", "DER encoded command to send to SAM"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool disconnectAfter = !arg_get_lit(ctx, 2);
    bool skipDetect = arg_get_lit(ctx, 3);
    bool decodeTLV = arg_get_lit(ctx, 4);
    bool breakOnNrMac = arg_get_lit(ctx, 5);
    bool preventEpurseUpdate = arg_get_lit(ctx, 6);
    bool shallow_mod = arg_get_lit(ctx, 7);

    uint8_t flags = 0;
    if (disconnectAfter) flags |= BITMASK(0);
    if (skipDetect) flags |= BITMASK(1);
    if (breakOnNrMac) flags |= BITMASK(2);
    if (preventEpurseUpdate) flags |= BITMASK(3);
    if (shallow_mod) flags |= BITMASK(4);

    uint8_t data[PM3_CMD_DATA_SIZE] = {0};
    data[0] = flags;

    int cmdlen = 0;
    if (CLIParamHexToBuf(arg_get_str(ctx, 8), data+1, PM3_CMD_DATA_SIZE-1, &cmdlen) != PM3_SUCCESS){
        CLIParserFree(ctx);
        return PM3_ESOFT;
    }

    CLIParserFree(ctx);

    if (IsHIDSamPresent(verbose) == false) {
        return PM3_ESOFT;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_SAM_PICOPASS, data, cmdlen+1);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_SAM_PICOPASS, &resp, 4000) == false) {
        PrintAndLogEx(WARNING, "SAM timeout");
        return PM3_ETIMEOUT;
    }

    switch (resp.status) {
        case PM3_SUCCESS:
            break;
        case PM3_ENOPACS:
            PrintAndLogEx(SUCCESS, "No PACS data found. Card empty?");
            return resp.status;
        default:
            PrintAndLogEx(WARNING, "SAM select failed");
            return resp.status;
    }

    uint8_t *d = resp.data.asBytes;
    // check for standard SamCommandGetContentElement response
    // bd 09
    //    8a 07
    //       03 05 <- tag + length
    //          06 85 80 6d c0 <- decoded PACS data
    if (d[0] == 0xbd && d[2] == 0x8a && d[4] == 0x03) {
        uint8_t pacs_length = d[5];
        uint8_t *pacs_data = d + 6;
        int res = HIDDumpPACSBits(pacs_data, pacs_length, verbose);
        if (res != PM3_SUCCESS) {
            return res;
        }
        // check for standard samCommandGetContentElement2:
        // bd 1e
        //    b3 1c
        //       a0 1a
        //          80 05
        //             06 85 80 6d c0
        //          81 0e
        //             2b 06 01 04 01 81 e4 38 01 01 02 04 3c ff
        //          82 01
        //             07
    } else if (d[0] == 0xbd && d[2] == 0xb3 && d[4] == 0xa0) {
        const uint8_t *pacs = d + 6;
        const uint8_t pacs_length = pacs[1];
        const uint8_t *pacs_data = pacs + 2;
        int res = HIDDumpPACSBits(pacs_data, pacs_length, verbose);
        if (res != PM3_SUCCESS) {
            return res;
        }

        const uint8_t *oid = pacs + 2 + pacs_length;
        const uint8_t oid_length = oid[1];
        const uint8_t *oid_data = oid + 2;
        PrintAndLogEx(SUCCESS, "SIO OID.......: " _GREEN_("%s"), sprint_hex_inrow(oid_data, oid_length));

        const uint8_t *mediaType = oid + 2 + oid_length;
        const uint8_t mediaType_data = mediaType[2];
        PrintAndLogEx(SUCCESS, "SIO Media Type: " _GREEN_("%s"), getSioMediaTypeInfo(mediaType_data));
    } else if(breakOnNrMac && d[0] == 0x05) {
        PrintAndLogEx(SUCCESS, "Nr-MAC: " _GREEN_("%s"), sprint_hex_inrow(d+1, 8));
        if(verbose){
            PrintAndLogEx(INFO, "Replay Nr-MAC to dump SIO:");
            PrintAndLogEx(SUCCESS, "    hf iclass dump -k \"%s\" --nr", sprint_hex_inrow(d+1, 8));
        }
    } else {
        print_hex(d, resp.length);
    }
    if (decodeTLV) {
        asn1_print(d, d[1] + 2, " ");
    }

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                    AlwaysAvailable, "This help"},
    {"list",        CmdHFiClassList,            AlwaysAvailable, "List iclass history"},
//    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("General") " ---------------------"},
    {"-----------", CmdHelp,                    IfPm3Iclass,     "------------------- " _CYAN_("Operations") " -------------------"},
//    {"clone",       CmdHFiClassClone,           IfPm3Iclass,     "Create a HID credential to Picopass / iCLASS tag"},
    {"dump",        CmdHFiClassDump,            IfPm3Iclass,     "Dump Picopass / iCLASS tag to file"},
    {"info",        CmdHFiClassInfo,            IfPm3Iclass,     "Tag information"},
    {"rdbl",        CmdHFiClass_ReadBlock,      IfPm3Iclass,     "Read Picopass / iCLASS block"},
    {"reader",      CmdHFiClassReader,          IfPm3Iclass,     "Act like a Picopass / iCLASS reader"},
    {"restore",     CmdHFiClassRestore,         IfPm3Iclass,      "Restore a dump file onto a Picopass / iCLASS tag"},
    {"sniff",       CmdHFiClassSniff,           IfPm3Iclass,     "Eavesdrop Picopass / iCLASS communication"},
    {"view",        CmdHFiClassView,            AlwaysAvailable, "Display content from tag dump file"},
    {"wrbl",        CmdHFiClass_WriteBlock,     IfPm3Iclass,     "Write Picopass / iCLASS block"},
    {"creditepurse", CmdHFiClassCreditEpurse,   IfPm3Iclass,     "Credit epurse value"},
    {"trbl",        CmdHFiClass_TearBlock,      IfPm3Iclass,     "Performs tearoff attack on iClass block"},
    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("Recovery") " --------------------"},
//    {"autopwn",     CmdHFiClassAutopwn,         IfPm3Iclass,     "Automatic key recovery tool for iCLASS"},
    {"chk",         CmdHFiClassCheckKeys,       IfPm3Iclass,     "Check keys"},
    {"loclass",     CmdHFiClass_loclass,        AlwaysAvailable, "Use loclass to perform bruteforce reader attack"},
    {"lookup",      CmdHFiClassLookUp,          AlwaysAvailable, "Uses authentication trace to check for key in dictionary file"},
    {"legrec",      CmdHFiClassLegacyRecover,   IfPm3Iclass,     "Recovers 24 bits of the diversified key of a legacy card provided a valid nr-mac combination"},
    {"legbrute",    CmdHFiClassLegRecLookUp,    AlwaysAvailable, "Bruteforces 40 bits of a partial diversified key, provided 24 bits of the key and two valid nr-macs"},
    {"unhash",      CmdHFiClassUnhash,          AlwaysAvailable, "Reverses a diversified key to retrieve hash0 pre-images after DES encryption"},
    {"-----------", CmdHelp,                    IfPm3Iclass,     "-------------------- " _CYAN_("Simulation") " -------------------"},
    {"sim",         CmdHFiClassSim,             IfPm3Iclass,     "Simulate iCLASS tag"},
    {"eload",       CmdHFiClassELoad,           IfPm3Iclass,     "Upload file into emulator memory"},
    {"esave",       CmdHFiClassESave,           IfPm3Iclass,     "Save emulator memory to file"},
    {"esetblk",     CmdHFiClassESetBlk,         IfPm3Iclass,     "Set emulator memory block data"},
    {"eview",       CmdHFiClassEView,           IfPm3Iclass,     "View emulator memory"},
    {"-----------", CmdHelp,                    AlwaysAvailable, "---------------------- " _CYAN_("Utils") " ----------------------"},
    {"configcard",  CmdHFiClassConfigCard,      IfPm3Iclass,     "Reader configuration card generator"},
    {"calcnewkey",  CmdHFiClassCalcNewKey,      AlwaysAvailable, "Calc diversified keys (blocks 3 & 4) to write new keys"},
    {"encode",      CmdHFiClassEncode,          AlwaysAvailable, "Encode binary wiegand to block 7"},
    {"encrypt",     CmdHFiClassEncryptBlk,      AlwaysAvailable, "Encrypt given block data"},
    {"decrypt",     CmdHFiClassDecrypt,         AlwaysAvailable, "Decrypt given block data or tag dump file" },
    {"managekeys",  CmdHFiClassManageKeys,      AlwaysAvailable, "Manage keys to use with iclass commands"},
    {"permutekey",  CmdHFiClassPermuteKey,      AlwaysAvailable, "Permute function from 'heart of darkness' paper"},
    {"-----------", CmdHelp,                    IfPm3Smartcard,  "----------------------- " _CYAN_("SAM") " -----------------------"},
    {"sam",         CmdHFiClassSAM,             IfPm3Smartcard,  "SAM tests"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFiClass(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// static void test_credential_type(void) {
// need AA1 key
// Block 5 -> tells if its a legacy or SIO,  also tells which key to use.

// tech   | blocks used           | desc                              | num of payloads
// -------+-----------------------+-----------------------------------+------
// legacy | 6,7,8,9               | AA!, Access control payload       | 1
// SE     | 6,7,8,9,10,11,12      | AA1, Secure identity object (SIO) | 1
// SR     | 6,7,8,9,              | AA1, Access control payload       | 2
//        | 10,11,12,13,14,15,16  | AA1, Secure identity object (SIO) |
// SEOS   |                       |                                   |
// MFC SIO|                       |                                   |
// DESFIRE|                       |                                   |
//}

int info_iclass(bool shallow_mod) {

    iclass_card_select_t payload = {
        .flags = (FLAG_ICLASS_READER_INIT | FLAG_ICLASS_READER_CLEARTRACE)
    };

    if (shallow_mod) {
        payload.flags |= FLAG_ICLASS_READER_SHALLOW_MOD;
    }

    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_HF_ICLASS_READER, (uint8_t *)&payload, sizeof(iclass_card_select_t));

    if (WaitForResponseTimeout(CMD_HF_ICLASS_READER, &resp, 2000) == false) {
        DropField();
        return PM3_ETIMEOUT;
    }
    DropField();

    iclass_card_select_resp_t *r = (iclass_card_select_resp_t *)resp.data.asBytes;

    uint8_t *p_response = (uint8_t *)&r->header.hdr;
    // no tag found or button pressed
    if (r->status == FLAG_ICLASS_NULL || resp.status == PM3_ERFTRANS) {
        return PM3_EOPABORTED;
    }

    picopass_hdr_t *hdr = &r->header.hdr;
    picopass_ns_hdr_t *ns_hdr = &r->header.ns_hdr;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ----------------------------------------");

    if ((r->status & FLAG_ICLASS_CSN) == FLAG_ICLASS_CSN) {
        PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s") " uid", sprint_hex(hdr->csn, sizeof(hdr->csn)));
    }

    if ((r->status & FLAG_ICLASS_CONF) == FLAG_ICLASS_CONF) {
        PrintAndLogEx(SUCCESS, " Config: %s card configuration", sprint_hex((uint8_t *)&hdr->conf, sizeof(hdr->conf)));
    }

    // page mapping.  If fuse0|1 == 0x01, card is in non-secure mode, with CSN, CONF, AIA as top 3 blocks.
    // page9 in http://www.proxmark.org/files/Documents/13.56%20MHz%20-%20iClass/DS%20Picopass%202KS%20V1-0.pdf
    uint8_t pagemap = get_pagemap(hdr);
    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        PrintAndLogEx(SUCCESS, "    AIA: %s application issuer area", sprint_hex(ns_hdr->app_issuer_area, sizeof(ns_hdr->app_issuer_area)));
    } else {

        if ((r->status & FLAG_ICLASS_CC) == FLAG_ICLASS_CC) {
            PrintAndLogEx(SUCCESS, "E-purse: %s Card challenge, CC", sprint_hex(hdr->epurse, sizeof(hdr->epurse)));
        }

        if (memcmp(hdr->key_d, zeros, sizeof(zeros))) {
            PrintAndLogEx(SUCCESS, "     Kd: " _YELLOW_("%s") " debit key", sprint_hex(hdr->key_d, sizeof(hdr->key_d)));
        } else {
            PrintAndLogEx(SUCCESS, "     Kd: %s debit key ( hidden )", sprint_hex(hdr->key_d, sizeof(hdr->key_d)));
        }

        if (memcmp(hdr->key_c, zeros, sizeof(zeros))) {
            PrintAndLogEx(SUCCESS, "     Kc: " _YELLOW_("%s") " credit key", sprint_hex(hdr->key_c, sizeof(hdr->key_c)));
        } else {
            PrintAndLogEx(SUCCESS, "     Kc: %s credit key ( hidden )", sprint_hex(hdr->key_c, sizeof(hdr->key_c)));
        }


        if ((r->status & FLAG_ICLASS_AIA) == FLAG_ICLASS_AIA) {
            PrintAndLogEx(SUCCESS, "    AIA: %s application issuer area", sprint_hex(hdr->app_issuer_area, sizeof(hdr->app_issuer_area)));
        }
    }

    if ((r->status & FLAG_ICLASS_CONF) == FLAG_ICLASS_CONF) {
        print_picopass_info(hdr);
    }

    PrintAndLogEx(INFO, "------------------------ " _CYAN_("Fingerprint") " -----------------------");

    uint8_t aia[8];
    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        memcpy(aia, ns_hdr->app_issuer_area, sizeof(aia));
    } else {
        memcpy(aia, hdr->app_issuer_area, sizeof(aia));
    }

    // if CSN starts with E012FFF (big endian), it's inside HID CSN range.
    bool is_hid_range = (hdr->csn[4] & 0xF0) == 0xF0 && (memcmp(hdr->csn + 5, "\xFF\x12\xE0", 3) == 0);

    bool legacy = (memcmp(aia, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0);
    bool se_enabled = (memcmp(aia, "\xff\xff\xff\x00\x06\xff\xff\xff", 8) == 0);

    if (is_hid_range) {
        PrintAndLogEx(SUCCESS, "    CSN.......... " _YELLOW_("HID range"));

        if (legacy) {
            PrintAndLogEx(SUCCESS, "    Credential... " _GREEN_("iCLASS legacy"));
        }

        if (se_enabled) {
            PrintAndLogEx(SUCCESS, "    Credential... " _GREEN_("iCLASS SE"));
        }
    } else {
        PrintAndLogEx(SUCCESS, "    CSN.......... " _YELLOW_("outside HID range"));
    }

    uint8_t cardtype = get_mem_config(hdr);
    PrintAndLogEx(SUCCESS, "    Card type.... " _GREEN_("%s"), card_types[cardtype]);

    if (HF14B_picopass_reader(false, false)) {
        PrintAndLogEx(SUCCESS, "    Card chip.... "_YELLOW_("Old Silicon (14b support)"));
    } else {
        PrintAndLogEx(SUCCESS, "    Card chip.... "_YELLOW_("NEW Silicon (No 14b support)"));
    }
    if (legacy) {

        int res = PM3_ESOFT;
        uint8_t key_type = 0x88; // debit key

        uint8_t dump[PICOPASS_BLOCK_SIZE * 8] = {0};
        // we take all raw bytes from response
        memcpy(dump, p_response, sizeof(picopass_hdr_t));

        uint8_t key[8] = {0};
        for (uint8_t i = 0; i < ARRAYLEN(iClass_Key_Table); i++) {

            memcpy(key, iClass_Key_Table[i], sizeof(key));
            res = iclass_read_block_ex(key, 6, key_type, false, false, false, false, true, false, dump + (PICOPASS_BLOCK_SIZE * 6), false);
            if (res == PM3_SUCCESS) {
                PrintAndLogEx(SUCCESS, "    AA1 Key...... " _GREEN_("%s"), sprint_hex_inrow(key, sizeof(key)));
                break;
            }
        }

        if (res == PM3_SUCCESS) {
            res = iclass_read_block_ex(key, 7, key_type, false, false, false, false, true, false, dump + (PICOPASS_BLOCK_SIZE * 7), false);
            if (res == PM3_SUCCESS) {

                BLOCK79ENCRYPTION aa1_encryption = (dump[(6 * PICOPASS_BLOCK_SIZE) + 7] & 0x03);

                uint8_t decrypted[PICOPASS_BLOCK_SIZE * 8] = {0};
                memcpy(decrypted, dump, 7 * PICOPASS_BLOCK_SIZE);

                uint8_t transport[16] = {0};
                iclass_load_transport(transport, sizeof(transport));
                iclass_decrypt_transport(transport, 8, dump, decrypted, aa1_encryption);
                iclass_decode_credentials(decrypted);
            }
        }
    }

    return PM3_SUCCESS;
}
