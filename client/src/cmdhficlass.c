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
#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN
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
#include "cmdsmartcard.h"   // smart select fct
#include "proxendian.h"
#include "iclass_cmd.h"
#include "crypto/asn1utils.h"      // ASN1 decoder
#include "preferences.h"

#define PICOPASS_BLOCK_SIZE    8
#define NUM_CSNS               9
#define MAC_ITEM_SIZE          24 // csn(8) + epurse(8) + nr(4) + mac(4) = 24 bytes
#define ICLASS_KEYS_MAX        8
#define ICLASS_AUTH_RETRY      10
#define ICLASS_CFG_BLK_SR_BIT  0xA0 // indicates SIO present when set in block6[0] (legacy tags)
#define ICLASS_DECRYPTION_BIN  "iclass_decryptionkey.bin"

static void print_picopass_info(const picopass_hdr_t *hdr);
void print_picopass_header(const picopass_hdr_t *hdr);

static picopass_hdr_t iclass_last_known_card;
static void iclass_set_last_known_card(picopass_hdr_t *card) {
    memcpy(&iclass_last_known_card, card, sizeof(picopass_hdr_t));
}

static uint8_t empty[PICOPASS_BLOCK_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
static uint8_t zeros[PICOPASS_BLOCK_SIZE] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

static int CmdHelp(const char *Cmd);
static void printIclassSIO(uint8_t *iclass_dump);

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

static iclass_config_card_item_t iclass_config_types[14] =  {
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    {"", ""},
    // must be the last entry
    {"no config card info available", ""}
};

static bool check_config_card(const iclass_config_card_item_t *o) {
    if (o == NULL || strlen(o->desc) == 0) {
        PrintAndLogEx(INFO, "No data available");
        PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass config -l") "` to download from cardhelper");
        return false;
    }
    return true;
}

static int load_config_cards(void) {
    PrintAndLogEx(INFO, "detecting cardhelper...");
    if (IsCardHelperPresent(false) == false) {
        PrintAndLogEx(FAILED, "failed to detect cardhelper");
        return PM3_ENODATA;
    }

    for (int i = 0; i < ARRAYLEN(iclass_config_types); ++i) {

        PrintAndLogEx(INPLACE, "loading setting %i", i);
        iclass_config_card_item_t *ret = &iclass_config_types[i];

        uint8_t desc[70] = {0};
        if (GetConfigCardStrByIdx(i, desc) == PM3_SUCCESS) {
            memcpy(ret->desc, desc, sizeof(desc));
        }

        uint8_t blocks[16] = {0};
        if (GetConfigCardByIdx(i, blocks) == PM3_SUCCESS) {
            memcpy(ret->data, blocks, sizeof(blocks));
        }
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf iclass configcard -p") "` to list all");
    return PM3_SUCCESS;
}

static const iclass_config_card_item_t *get_config_card_item(int idx) {
    if (idx > -1 && idx < 14) {
        return &iclass_config_types[idx];
    }
    return &iclass_config_types[13];
}

static void print_config_cards(void) {
    if (check_config_card(&iclass_config_types[0])) {
        PrintAndLogEx(INFO, "---- " _CYAN_("Config cards available") " ------------");
        for (int i = 0; i < ARRAYLEN(iclass_config_types) - 1   ; ++i) {
            PrintAndLogEx(INFO, "%2d, %s", i, iclass_config_types[i].desc);
        }
        PrintAndLogEx(NORMAL, "");
    }
}

static void print_config_card(const iclass_config_card_item_t *o) {
    if (check_config_card(o)) {
        PrintAndLogEx(INFO, "description... " _YELLOW_("%s"), o->desc);
        PrintAndLogEx(INFO, "data.......... " _YELLOW_("%s"), sprint_hex_inrow(o->data, sizeof(o->data)));
    }
}

static int generate_config_card(const iclass_config_card_item_t *o,  uint8_t *key, bool got_kr) {
    if (check_config_card(o) == false) {
        return PM3_EINVARG;
    }

    // generated config card header
    picopass_hdr_t configcard;
    memset(&configcard, 0xFF, sizeof(picopass_hdr_t));
    memcpy(configcard.csn, "\x41\x87\x66\x00\xFB\xFF\x12\xE0", 8);
    memcpy(&configcard.conf, "\xFF\xFF\xFF\xFF\xF9\xFF\xFF\xBC", 8);
    memcpy(&configcard.epurse, "\xFE\xFF\xFF\xFF\xFF\xFF\xFF\xFF", 8);
    // defaulting to known AA1 key
    HFiClassCalcDivKey(configcard.csn, iClass_Key_Table[0], configcard.key_d, false);

    // reference
    picopass_hdr_t *cc = &configcard;

    // get header from card
    PrintAndLogEx(INFO, "trying to read a card..");
    int res = read_iclass_csn(false, false, false);
    if (res == PM3_SUCCESS) {
        cc = &iclass_last_known_card;
        // calc diversified key for selected card
        HFiClassCalcDivKey(cc->csn, iClass_Key_Table[0], cc->key_d, false);
    } else {
        PrintAndLogEx(FAILED, "failed to read a card");
        PrintAndLogEx(INFO, "falling back to default config card");
    }

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

    // Keyrolling configuration cards are special.
    if (strstr(o->desc, "Keyroll") != NULL) {

        if (got_kr == false) {
            PrintAndLogEx(ERR, "please specify KEYROLL key!");
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

        // KEYROLL need to encrypt
        PrintAndLogEx(INFO, "Setting up encryption... " NOLF);
        uint8_t ffs[8] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        if (Encrypt(ffs, ffs) == false) {
            PrintAndLogEx(WARNING, "failed to encrypt FF");
        } else {
            PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
        }

        // local key copy
        PrintAndLogEx(INFO, "Encrypting local key... " NOLF);
        uint8_t lkey[8];
        memcpy(lkey, key, sizeof(lkey));
        uint8_t enckey1[8];
        if (Encrypt(lkey, enckey1) == false) {
            PrintAndLogEx(WARNING, "failed to encrypt key1");
        } else {
            PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
        }

        PrintAndLogEx(INFO, "Copy data... " NOLF);
        memcpy(data, cc, sizeof(picopass_hdr_t));
        memcpy(data + (6 * 8), o->data, sizeof(o->data));

        // encrypted keyroll key 0D
        memcpy(data + (0xD * 8), enckey1, sizeof(enckey1));
        // encrypted 0xFF
        for (uint8_t i = 0xD; i < 0x14; i++) {
            memcpy(data + (i * 8), ffs, sizeof(ffs));
        }
        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");

        // encrypted partial keyroll key 14
        PrintAndLogEx(INFO, "Setting encrypted partial key14... " NOLF);
        uint8_t foo[8] = {0x15};
        memcpy(foo + 1, lkey, 7);
        uint8_t enckey2[8];
        if (Encrypt(foo, enckey2) == false) {
            PrintAndLogEx(WARNING, "failed to encrypt partial 1");
        }
        memcpy(data + (0x14 * 8), enckey2, sizeof(enckey2));
        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");


        // encrypted partial keyroll key 15
        PrintAndLogEx(INFO, "Setting encrypted partial key15... " NOLF);
        memset(foo, 0xFF, sizeof(foo));
        foo[0] = lkey[7];
        if (Encrypt(foo, enckey2) == false) {
            PrintAndLogEx(WARNING, "failed to encrypt partial 2");
        }
        memcpy(data + (0x15 * 8), enckey2, sizeof(enckey2));
        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");

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
                  "Sniff the communication reader and tag",
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
            PrintAndLogEx(INFO, "press " _YELLOW_("`enter`") " to cancel");
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
            PrintAndLogEx(INFO, "press Enter to cancel");
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
            PrintAndLogEx(INFO, "press " _YELLOW_("`button`") " to cancel");
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
                    if (verbose) PrintAndLogEx(WARNING, "iCLASS / Picopass card select failed ( %d )", r->status);
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

    return read_iclass_csn(cm, true, shallow_mod);
}

static int CmdHFiClassELoad(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass eload",
                  "Load emulator memory with data from (bin/eml/json) iCLASS dump file",
                  "hf iclass eload -f hf-iclass-AA162D30F8FF12F1-dump.eml\n"
                  "hf iclass eload -f hf-iclass-AA162D30F8FF12F1-dump.bin -m\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of dump (bin/eml/json)"),
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
                  "Save emulator memory to file.\n"
                  "if filename is not supplied, CSN will be used.",
                  "hf iclass esave\n"
                  "hf iclass esave -f hf-iclass-dump\n"
                  "hf iclass esave -s 2048 -f hf-iclass-dump");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of dump file"),
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

    pm3_save_dump(filename, dump, bytes, jsfIclass, PICOPASS_BLOCK_SIZE);
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
        printIclassSIO(dump);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdHFiClassESetBlk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass esetblk",
                  "Sets an individual block in emulator memory.",
                  "hf iclass esetblk -b 7 -d 0000000000000000");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "blk", "<dec>", "block number"),
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

static void iclass_decode_credentials(uint8_t *data) {
    if (memcmp(data + (5 * PICOPASS_BLOCK_SIZE), "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
        // Not a Legacy or SR card, nothing to do here.
        return;
    }

    BLOCK79ENCRYPTION encryption = (data[(6 * 8) + 7] & 0x03);
    bool has_values = (memcmp(data + (8 * 7), empty, 8) != 0) && (memcmp(data + (8 * 7), zeros, 8) != 0);
    if (has_values && encryption == None) {

        //todo:  remove preamble/sentinel
        uint32_t top = 0, mid = 0, bot = 0;

        PrintAndLogEx(INFO, "Block 7 decoder");

        char hexstr[16 + 1] = {0};
        hex_to_buffer((uint8_t *)hexstr, data + (8 * 7), 8, sizeof(hexstr) - 1, 0, 0, true);
        hexstring_to_u96(&top, &mid, &bot, hexstr);

        char binstr[64 + 1];
        hextobinstring(binstr, hexstr);
        char *pbin = binstr;
        while (strlen(pbin) && *(++pbin) == '0');

        PrintAndLogEx(SUCCESS, "Binary..................... " _GREEN_("%s"), pbin);

        PrintAndLogEx(INFO, "Wiegand decode");
        wiegand_message_t packed = initialize_message_object(top, mid, bot, 0);
        HIDTryUnpack(&packed);
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
                  "in the resources directory. The file should be 16 bytes binary data\n"
                  "or...\n"
                  "make sure your cardhelper is placed in the sim module",
                  "hf iclass decrypt -f hf-iclass-AA162D30F8FF12F1-dump.bin\n"
                  "hf iclass decrypt -f hf-iclass-AA162D30F8FF12F1-dump.bin -k 000102030405060708090a0b0c0d0e0f\n"
                  "hf iclass decrypt -d 1122334455667788 -k 000102030405060708090a0b0c0d0e0f");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of dump file (bin/eml/json)"),
        arg_str0("d", "data", "<hex>", "3DES encrypted data"),
        arg_str0("k", "key", "<hex>", "3DES transport key"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "d6", "decode as block 6"),
        arg_lit0("z", "dense", "dense dump output style"),
        arg_param_end
    };
    CLIExecWithReturn(clictx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(clictx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int enc_data_len = 0;
    uint8_t enc_data[8] = {0};
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
    CLIParserFree(clictx);

    // sanity checks
    if (enc_data_len > 0) {
        if (enc_data_len != 8) {
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

        uint8_t dec_data[8] = {0};
        if (use_sc) {
            Decrypt(enc_data, dec_data);
        } else {
            mbedtls_des3_crypt_ecb(&ctx, enc_data, dec_data);
        }

        PrintAndLogEx(SUCCESS, "encrypted... %s", sprint_hex_inrow(enc_data, sizeof(enc_data)));
        PrintAndLogEx(SUCCESS, "plain....... " _YELLOW_("%s"), sprint_hex_inrow(dec_data, sizeof(dec_data)));

        if (use_sc && use_decode6)
            DecodeBlock6(dec_data);
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

        BLOCK79ENCRYPTION aa1_encryption = (decrypted[(6 * 8) + 7] & 0x03);

        uint8_t limit = MIN(applimit, decryptedlen / 8);

        if (decryptedlen / 8 != applimit) {
            PrintAndLogEx(WARNING, "Actual file len " _YELLOW_("%zu") " vs HID app-limit len " _YELLOW_("%u"), decryptedlen, applimit * 8);
            PrintAndLogEx(INFO, "Setting limit to " _GREEN_("%u"), limit * 8);
        }

        //uint8_t numblocks4userid = GetNumberBlocksForUserId(decrypted + (6 * 8));

        bool decrypted_block789 = false;
        for (uint8_t blocknum = 0; blocknum < limit; ++blocknum) {

            uint16_t idx = blocknum * 8;
            memcpy(enc_data, decrypted + idx, 8);

            switch (aa1_encryption) {
                // Right now, only 3DES is supported
                case TRIPLEDES:
                    // Decrypt block 7,8,9 if configured.
                    if (blocknum > 6 && blocknum <= 9 && memcmp(enc_data, empty, 8) != 0) {
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
                decrypted[(6 * 8) + 7] &= 0xFC;
            }
        }

        // use the first block (CSN) for filename
        char *fptr = calloc(50, sizeof(uint8_t));
        if (fptr == false) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            free(decrypted);
            return PM3_EMALLOC;
        }

        strcat(fptr, "hf-iclass-");
        FillFileNameByUID(fptr, hdr->csn, "-dump-decrypted", sizeof(hdr->csn));

        pm3_save_dump(fptr, decrypted, decryptedlen, jsfIclass, PICOPASS_BLOCK_SIZE);

        printIclassDumpContents(decrypted, 1, (decryptedlen / 8), decryptedlen, dense_output);

        if (verbose) {
            printIclassSIO(decrypted);
        }

        PrintAndLogEx(NORMAL, "");

        // decode block 6
        bool has_values = (memcmp(decrypted + (8 * 6), empty, 8) != 0) && (memcmp(decrypted + (8 * 6), zeros, 8) != 0);
        if (has_values) {
            if (use_sc) {
                DecodeBlock6(decrypted + (8 * 6));
            }
        }

        // decode block 7-8-9
        iclass_decode_credentials(decrypted);

        // decode block 9
        has_values = (memcmp(decrypted + (8 * 9), empty, 8) != 0) && (memcmp(decrypted + (8 * 9), zeros, 8) != 0);
        if (has_values && use_sc) {
            uint8_t usr_blk_len = GetNumberBlocksForUserId(decrypted + (8 * 6));
            if (usr_blk_len < 3) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, "Block 9 decoder");

                uint8_t pinsize = GetPinSize(decrypted + (8 * 6));
                if (pinsize > 0) {

                    uint64_t pin = bytes_to_num(decrypted + (8 * 9), 5);
                    char tmp[17] = {0};
                    snprintf(tmp, sizeof(tmp), "%."PRIu64, BCD2DEC(pin));
                    PrintAndLogEx(INFO, "PIN........................ " _GREEN_("%.*s"), pinsize, tmp);
                }
            }
        }

        PrintAndLogEx(INFO, "-----------------------------------------------------------------");
        free(decrypted);
        free(fptr);
    }

    mbedtls_des3_free(&ctx);
    return PM3_SUCCESS;
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
        PrintAndLogEx(WARNING, "command execute timeout");
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
        PrintAndLogEx(WARNING, "command execute timeout");
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

    if (pagemap == PICOPASS_NON_SECURE_PAGEMODE) {
        // all memory available
        memcpy(tag_data + (8 * 3), tempbuf + (8 * 3), (blocks_read * 8));
    } else {
        // div key KD
        memcpy(tag_data + (8 * 3), tempbuf + (8 * 3), 8);
        // AIA data
        memcpy(tag_data + (8 * 5), tempbuf + (8 * 5), 8);
        // AA1 data
        memcpy(tag_data + (8 * 6), tempbuf + (8 * 6), ((blocks_read - 6) * 8));
    }

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
        memcpy(tag_data + (8 * 4), tempbuf + (8 * 4), 8);

        // AA2 data
        memcpy(tag_data + (8 * (app_limit1 + 1)), tempbuf + (8 * (app_limit1 + 1)), (blocks_read * 8));

        bytes_got = (blocks_read * 8);

        aa2_success = true;
    }

write_dump:

    if (have_credit_key && pagemap != 0x01 && aa2_success == false)
        PrintAndLogEx(INFO, "Reading AA2 failed. dumping AA1 data to file");

    // print the dump
    printIclassDumpContents(tag_data, 1, (bytes_got / 8), bytes_got, dense_output);

    // use CSN as filename
    if (filename[0] == 0) {
        strcat(filename, "hf-iclass-");
        FillFileNameByUID(filename, tag_data, "-dump", 8);
    }

    // save the dump to .bin file
    PrintAndLogEx(SUCCESS, "saving dump file - %u blocks read", bytes_got / 8);

    pm3_save_dump(filename, tag_data, bytes_got, jsfIclass, PICOPASS_BLOCK_SIZE);

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
        if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
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
                  "hf iclass wrbl -b 10 -d AAAAAAAAAAAAAAAA -k 001122334455667B\n"
                  "hf iclass wrbl -b 10 -d AAAAAAAAAAAAAAAA -k 001122334455667B --credit\n"
                  "hf iclass wrbl -b 10 -d AAAAAAAAAAAAAAAA --ki 0");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_int1("b", "block", "<dec>", "The block number to read"),
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
            PrintAndLogEx(SUCCESS, "Wrote block %3d/0x%02X successful", blockno, blockno);
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
                  "Restore data from dumpfile onto a iCLASS tag",
                  "hf iclass restore -f hf-iclass-AA162D30F8FF12F1-dump.bin --first 6 --last 18 --ki 0\n"
                  "hf iclass restore -f hf-iclass-AA162D30F8FF12F1-dump.bin --first 6 --last 18 --ki 0 --elite\n"
                  "hf iclass restore -f hf-iclass-AA162D30F8FF12F1-dump.bin --first 6 --last 18 -k 1122334455667788 --elite\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "specify a filename to restore (bin/eml/json)"),
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
        PrintAndLogEx(WARNING, "command execute timeout");
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

static int iclass_read_block(uint8_t *KEY, uint8_t blockno, uint8_t keyType, bool elite, bool rawkey, bool replay, bool verbose, bool auth, bool shallow_mod, uint8_t *out) {

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
        if (verbose) PrintAndLogEx(WARNING, "Command execute timeout");
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

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, " block %3d/0x%02X : " _GREEN_("%s"), blockno, blockno, sprint_hex(packet->data, sizeof(packet->data)));
    PrintAndLogEx(NORMAL, "");

    if (out)
        memcpy(out, packet->data, sizeof(packet->data));

    return PM3_SUCCESS;
}

static int CmdHFiClass_ReadBlock(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass rdbl",
                  "Read a iCLASS block from tag",
                  "hf iclass rdbl -b 6 -k 0011223344556677\n"
                  "hf iclass rdbl -b 27 -k 0011223344556677 --credit\n"
                  "hf iclass rdbl -b 10 --ki 0");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Access key as 8 hex bytes"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_int1("b", "block", "<dec>", "The block number to read"),
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

            uint8_t dec_data[8];

            uint64_t a = bytes_to_num(data, 8);
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

            if (memcmp(dec_data, empty, 8) != 0) {

                //todo:  remove preamble/sentinel
                uint32_t top = 0, mid = 0, bot = 0;

                char hexstr[16 + 1] = {0};
                hex_to_buffer((uint8_t *)hexstr, dec_data, 8, sizeof(hexstr) - 1, 0, 0, true);
                hexstring_to_u96(&top, &mid, &bot, hexstr);

                char binstr[64 + 1];
                hextobinstring(binstr, hexstr);
                char *pbin = binstr;
                while (strlen(pbin) && *(++pbin) == '0');

                PrintAndLogEx(SUCCESS, "      bin : %s", pbin);
                PrintAndLogEx(INFO, "");
                PrintAndLogEx(INFO, "------------------------------ " _CYAN_("Wiegand") " -------------------------------");
                wiegand_message_t packed = initialize_message_object(top, mid, bot, 0);
                HIDTryUnpack(&packed);
            } else {
                PrintAndLogEx(INFO, "no credential found");
            }
            break;
        }
    }
    PrintAndLogEx(INFO, "----------------------------------------------------------------------");
    return PM3_SUCCESS;
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
        arg_lit0(NULL, "test",        "Perform self-test"),
        arg_lit0(NULL, "long",        "Perform self-test, including long ones"),
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

static void detect_credential(uint8_t *data, bool *legacy, bool *se, bool *sr) {
    *legacy = false;
    *sr = false;
    *se = false;

    // Legacy AIA
    if (!memcmp(data + (5 * PICOPASS_BLOCK_SIZE), "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
        *legacy = true;

        // SR bit set in legacy config block
        if ((data[6 * PICOPASS_BLOCK_SIZE] & ICLASS_CFG_BLK_SR_BIT) == ICLASS_CFG_BLK_SR_BIT) {
            // If the card is blank (all FF's) then we'll reach here too, so check for an empty block 10
            // to avoid false positivies
            if (memcmp(data + (10 * PICOPASS_BLOCK_SIZE), "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
                *sr = true;
            }
        }

        return;
    }

    // SE AIA
    if (!memcmp(data + (5 * PICOPASS_BLOCK_SIZE), "\xFF\xFF\xFF\x00\x06\xFF\xFF\xFF", PICOPASS_BLOCK_SIZE)) {
        *se = true;
        return;
    }
}

// print ASN1 decoded array in TLV view
static void printIclassSIO(uint8_t *iclass_dump) {
    bool isLegacy, isSE, isSR;
    detect_credential(iclass_dump, &isLegacy, &isSE, &isSR);

    uint8_t *sio_start;
    if (isSE) {
        // SE SIO starts at block 6
        sio_start = iclass_dump + (6 * PICOPASS_BLOCK_SIZE);
    } else if (isSR) {
        // SR SIO starts at block 10
        sio_start = iclass_dump + (10 * PICOPASS_BLOCK_SIZE);
    } else {
        // No SIO on Legacy credentials
        return;
    }

    // Readers assume the SIO always fits within 7 blocks (they don't read any further blocks)
    // Search backwards to find the last 0x05 0x00 seen at the end of the SIO
    const uint8_t pattern_sio_end[] = {0x05, 0x00};
    int dlen = byte_strrstr(sio_start, 7 * PICOPASS_BLOCK_SIZE, pattern_sio_end, 2);
    if (dlen == -1) {
        return;
    }

    dlen += sizeof(pattern_sio_end);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------------------------- " _CYAN_("SIO - RAW") " ----------------------------");
    print_hex_noascii_break(sio_start, dlen, 32);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------- " _CYAN_("SIO - ASN1 TLV") " --------------------------");
    asn1_print(sio_start, dlen, "  ");
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

    bool isLegacy = false, isSE = false, isSR = false;
    if (filemaxblock >= 17) {
        detect_credential(iclass_dump, &isLegacy, &isSE, &isSR);
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
            const char *info_ks[] = {"CSN", "Config", "E-purse", "Debit", "Credit", "AIA", "User"};

            if (i >= 6 && i <= 9 && isLegacy && isSE == false) {
                // legacy credential
                PrintAndLogEx(INFO, "%3d/0x%02X | " _YELLOW_("%s") "| " _YELLOW_("%s") " | %s | User / Cred "
                              , i
                              , i
                              , sprint_hex(blk, 8)
                              , sprint_ascii(blk, 8)
                              , lockstr
                             );
            } else if (i >= 6 && i <= 12 && isSE) {
                // SIO credential
                PrintAndLogEx(INFO, "%3d/0x%02X | " _CYAN_("%s") "| " _CYAN_("%s") " | %s | User / SIO / SE"
                              , i
                              , i
                              , sprint_hex(blk, 8)
                              , sprint_ascii(blk, 8)
                              , lockstr
                             );
            } else if (i >= 10 && i <= 16 && isSR) {
                // SIO credential
                PrintAndLogEx(INFO, "%3d/0x%02X | " _CYAN_("%s") "| " _CYAN_("%s") " | %s | User / SIO / SR"
                              , i
                              , i
                              , sprint_hex(blk, 8)
                              , sprint_ascii(blk, 8)
                              , lockstr
                             );
            } else {
                if (i < 6) {
                    block_info = info_ks[i];
                } else {
                    block_info = info_ks[6];
                }

                regular_print_block = true;
            }
        }

        if (regular_print_block) {
            // suppress repeating blocks, truncate as such that the first and last block with the same data is shown
            // but the blocks in between are replaced with a single line of "*" if dense_output is enabled
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
                              "%3d/0x%02X | %s | %s | %s ",
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
    if (isLegacy)
        PrintAndLogEx(HINT, _YELLOW_("yellow") " = legacy credential");

    if (isSE)
        PrintAndLogEx(HINT, _CYAN_("cyan") " = SIO / SE credential");

    if (isSR)
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
        arg_str1("f", "file", "<fn>",  "filename of dump (bin/eml/json)"),
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
        printIclassSIO(dump);
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

static int loadKeys(char *filename) {

    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    if (loadFile_safe(filename, "", (void **)&dump, &bytes_read) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }

    if (bytes_read > ICLASS_KEYS_MAX * 8) {
        PrintAndLogEx(WARNING, "File is too long to load - bytes: %zu", bytes_read);
        free(dump);
        return PM3_EFILE;
    }
    size_t i = 0;
    for (; i < bytes_read / 8; i++)
        memcpy(iClass_Key_Table[i], dump + (i * 8), 8);

    free(dump);
    PrintAndLogEx(SUCCESS, "Loaded " _GREEN_("%2zd") " keys from %s", i, filename);
    return PM3_SUCCESS;
}

static int saveKeys(char *filename) {
    FILE *f;
    f = fopen(filename, "wb");
    if (!f) {
        PrintAndLogEx(FAILED, "File: " _YELLOW_("%s") ": not found or locked.", filename);
        return PM3_EFILE;
    }
    for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
        if (fwrite(iClass_Key_Table[i], 8, 1, f) != 1) {
            PrintAndLogEx(WARNING, "save key failed to write to file:" _YELLOW_("%s"), filename);
            break;
        }
    }
    fclose(f);
    return PM3_SUCCESS;
}

static int printKeys(void) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "idx| key");
    PrintAndLogEx(INFO, "---+------------------------");
    for (uint8_t i = 0; i < ICLASS_KEYS_MAX; i++) {
        if (memcmp(iClass_Key_Table[i], "\x00\x00\x00\x00\x00\x00\x00\x00", 8) == 0)
            PrintAndLogEx(INFO, " %u |", i);
        else
            PrintAndLogEx(INFO, " %u | " _YELLOW_("%s"), i, sprint_hex(iClass_Key_Table[i], 8));
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
            return printKeys();
        case 5:
            return loadKeys(filename);
        case 6:
            return saveKeys(filename);
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
                  "hf iclass chk -f iclass_default_keys.dic --elite");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Dictionary file with default iclass keys"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key (raw)"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool use_credit_key = arg_get_lit(ctx, 2);
    bool use_elite = arg_get_lit(ctx, 3);
    bool use_raw = arg_get_lit(ctx, 4);
    bool shallow_mod = arg_get_lit(ctx, 5);

    CLIParserFree(ctx);

    uint8_t CSN[8] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t CCNR[12] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

    uint64_t t1 = msclock();

    // load keys
    uint8_t *keyBlock = NULL;
    uint32_t keycount = 0;
    int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
    if (res != PM3_SUCCESS || keycount == 0) {
        free(keyBlock);
        return res;
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
                PrintAndLogEx(WARNING, "\ncommand execute timeout, aborting...");
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
static int CmdHFiClassLookUp(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass lookup",
                  "Lookup keys takes some sniffed trace data and tries to verify what key was used against a dictionary file",
                  "hf iclass lookup --csn 9655a400f8ff12e0 --epurse f0ffffffffffffff --macs 0000000089cb984b -f iclass_default_keys.dic\n"
                  "hf iclass lookup --csn 9655a400f8ff12e0 --epurse f0ffffffffffffff --macs 0000000089cb984b -f iclass_default_keys.dic --elite");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Dictionary file with default iclass keys"),
        arg_str1(NULL, "csn", "<hex>", "Specify CSN as 8 hex bytes"),
        arg_str1(NULL, "epurse", "<hex>", "Specify ePurse as 8 hex bytes"),
        arg_str1(NULL, "macs", "<hex>", "MACs"),
        arg_lit0(NULL, "elite", "Elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

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

    bool use_elite = arg_get_lit(ctx, 5);
    bool use_raw = arg_get_lit(ctx, 6);

    CLIParserFree(ctx);

    uint8_t CCNR[12];
    uint8_t MAC_TAG[4] = { 0, 0, 0, 0 };

    // stupid copy.. CCNR is a combo of epurse and reader nonce
    memcpy(CCNR, epurse, 8);
    memcpy(CCNR + 8, macs, 4);
    memcpy(MAC_TAG, macs + 4, 4);

    PrintAndLogEx(SUCCESS, "    CSN: " _GREEN_("%s"), sprint_hex(csn, sizeof(csn)));
    PrintAndLogEx(SUCCESS, " Epurse: %s", sprint_hex(epurse, sizeof(epurse)));
    PrintAndLogEx(SUCCESS, "   MACS: %s", sprint_hex(macs, sizeof(macs)));
    PrintAndLogEx(SUCCESS, "   CCNR: " _GREEN_("%s"), sprint_hex(CCNR, sizeof(CCNR)));
    PrintAndLogEx(SUCCESS, "TAG MAC: %s", sprint_hex(MAC_TAG, sizeof(MAC_TAG)));

    // run time
    uint64_t t1 = msclock();

    uint8_t *keyBlock = NULL;
    uint32_t keycount = 0;

    // load keys
    int res = loadFileDICTIONARY_safe(filename, (void **)&keyBlock, 8, &keycount);
    if (res != PM3_SUCCESS || keycount == 0) {
        free(keyBlock);
        return res;
    }

    //iclass_prekey_t
    iclass_prekey_t *prekey = calloc(keycount, sizeof(iclass_prekey_t));
    if (!prekey) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "Generating diversified keys...");
    GenerateMacKeyFrom(csn, CCNR, use_raw, use_elite, keyBlock, keycount, prekey);

    if (use_elite)
        PrintAndLogEx(INFO, "Using " _YELLOW_("elite algo"));
    if (use_raw)
        PrintAndLogEx(INFO, "Using " _YELLOW_("raw mode"));

    PrintAndLogEx(INFO, "Sorting...");

    // sort mac list.
    qsort(prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    PrintAndLogEx(SUCCESS, "Searching for " _YELLOW_("%s") " key...", "DEBIT");
    iclass_prekey_t *item;
    iclass_prekey_t lookup;
    memcpy(lookup.mac, MAC_TAG, 4);

    // binsearch
    item = (iclass_prekey_t *) bsearch(&lookup, prekey, keycount, sizeof(iclass_prekey_t), cmp_uint32);

    if (item != NULL) {
        PrintAndLogEx(SUCCESS, "Found valid key " _GREEN_("%s"), sprint_hex(item->key, 8));
        add_key(item->key);
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "time in iclass lookup " _YELLOW_("%.3f") " seconds", (float)t1 / 1000.0);

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
                  "hf iclass encode --bin 10001111100000001010100011 --ki 0 --elite    -> FC 31 CN 337 (H10301), writing w elite key"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_int1(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_lit0(NULL, "credit", "key is assumed to be the credit key"),
        arg_lit0(NULL, "elite", "elite computations applied to key"),
        arg_lit0(NULL, "raw", "no computations applied to key"),
        arg_str0(NULL, "enckey", "<hex>", "3DES transport key, 16 hex bytes"),
        arg_u64_0(NULL, "fc", "<dec>", "facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "card number"),
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_lit0(NULL, "shallow", "use shallow (ASK) reader modulation instead of OOK"),
        arg_lit0("v", NULL, "verbose (print encoded blocks)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int bin_len = 63;
    uint8_t bin[70] = {0};
    CLIGetStrWithReturn(ctx, 1, bin, &bin_len);

    int key_nr = arg_get_int_def(ctx, 2, -1);
    bool auth = false;

    uint8_t key[8] = {0};
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

    bool use_credit_key = arg_get_lit(ctx, 3);
    bool elite = arg_get_lit(ctx, 4);
    bool rawkey = arg_get_lit(ctx, 5);

    int enc_key_len = 0;
    uint8_t enc_key[16] = {0};
    uint8_t *enckeyptr = NULL;
    bool have_enc_key = false;
    bool use_sc = false;
    CLIGetHexWithReturn(ctx, 6, enc_key, &enc_key_len);

    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));
    card.FacilityCode = arg_get_u32_def(ctx, 7, 0);
    card.CardNumber = arg_get_u32_def(ctx, 8, 0);

    char format[16] = {0};
    int format_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 9), (uint8_t *)format, sizeof(format), &format_len);

    bool shallow_mod = arg_get_lit(ctx, 10);
    bool verbose = arg_get_lit(ctx, 11);

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

    if (bin_len > 127) {
        PrintAndLogEx(ERR, "Binary wiegand string must be less than 128 bits");
        return PM3_EINVARG;
    }

    if (bin_len == 0 && card.FacilityCode == 0 && card.CardNumber == 0) {
        PrintAndLogEx(ERR, "Must provide either --cn/--fc or --bin");
        return PM3_EINVARG;
    }

    if (have_enc_key == false) {
        use_sc = IsCardHelperPresent(false);
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
                  "Manage reader configuration card via Cardhelper,\n"
                  "The generated config card will be uploaded to device emulator memory.\n"
                  "You can start simulating `hf iclass sim -t 3` or use the emul commands",
                  "hf iclass configcard -l           --> download config card settings\n"
                  "hf iclass configcard -p           --> print all config cards\n"
                  "hf iclass configcard --ci 1       --> view config card setting in slot 1\n"
                  "hf iclass configcard -g --ci 0    --> generate config file from slot 0"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "ci", "<dec>", "use config slot at index"),
        arg_int0(NULL, "ki", "<dec>", "Key index to select key from memory 'hf iclass managekeys'"),
        arg_lit0("g", NULL, "generate card dump file"),
        arg_lit0("l", NULL, "load available cards"),
        arg_lit0("p", NULL, "print available cards"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int ccidx = arg_get_int_def(ctx, 1, -1);
    int kidx = arg_get_int_def(ctx, 2, -1);
    bool do_generate = arg_get_lit(ctx, 3);
    bool do_load = arg_get_lit(ctx, 4);
    bool do_print = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    bool got_kr = false;
    uint8_t key[8] = {0};
    if (kidx >= 0) {
        if (kidx < ICLASS_KEYS_MAX) {
            got_kr = true;
            memcpy(key, iClass_Key_Table[kidx], 8);
            PrintAndLogEx(SUCCESS, "Using key[%d] " _GREEN_("%s"), kidx, sprint_hex(iClass_Key_Table[kidx], 8));
        } else {
            PrintAndLogEx(ERR, "--ki number is invalid");
            return PM3_EINVARG;
        }
    }

    if (do_load) {
        if (load_config_cards() != PM3_SUCCESS) {
            PrintAndLogEx(INFO, "failed to load, check your cardhelper");
        }
    }

    if (do_print) {
        print_config_cards();
    }

    if (ccidx > -1 && ccidx < 14) {
        const iclass_config_card_item_t *item = get_config_card_item(ccidx);
        print_config_card(item);
    }

    if (do_generate) {
        const iclass_config_card_item_t *item = get_config_card_item(ccidx);
        if (strstr(item->desc, "Keyroll") != NULL) {
            if (got_kr == false) {
                PrintAndLogEx(ERR, "please specify KEYROLL key!");
                return PM3_EINVARG;
            }
        }
        generate_config_card(item, key, got_kr);
    }

    return PM3_SUCCESS;
}

static int CmdHFiClassSAM(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf iclass sam",
                  "Manage via SAM\n",
                  "hf iclass sam\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<hex>", "data"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 0;
    uint8_t data[128] = {0};
    CLIGetHexWithReturn(ctx, 1, data, &dlen);

    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    Iso7816CommandChannel channel = CC_CONTACT;
    if (IfPm3Smartcard() == false) {
        if (channel == CC_CONTACT) {
            PrintAndLogEx(WARNING, "PM3 does not have SMARTCARD support, exiting");
            return PM3_EDEVNOTSUPP;
        }
    }

    int res = IsHIDSamPresent(verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    SetAPDULogging(verbose);

// do things with sending apdus..

    SetAPDULogging(false);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                    AlwaysAvailable, "This help"},
    {"list",        CmdHFiClassList,            AlwaysAvailable, "List iclass history"},
    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("general") " ---------------------"},
//    {"clone",       CmdHFiClassClone,           IfPm3Iclass,     "Create a HID credential to Picopass / iCLASS tag"},
    {"dump",        CmdHFiClassDump,            IfPm3Iclass,     "Dump Picopass / iCLASS tag to file"},
    {"info",        CmdHFiClassInfo,            AlwaysAvailable, "Tag information"},
    {"rdbl",        CmdHFiClass_ReadBlock,      IfPm3Iclass,     "Read Picopass / iCLASS block"},
    {"reader",      CmdHFiClassReader,          IfPm3Iclass,     "Act like a Picopass / iCLASS reader"},
    {"restore",     CmdHFiClassRestore,         IfPm3Iclass,      "Restore a dump file onto a Picopass / iCLASS tag"},
    {"sniff",       CmdHFiClassSniff,           IfPm3Iclass,     "Eavesdrop Picopass / iCLASS communication"},
    {"view",        CmdHFiClassView,            AlwaysAvailable, "Display content from tag dump file"},
    {"wrbl",        CmdHFiClass_WriteBlock,     IfPm3Iclass,     "Write Picopass / iCLASS block"},
    {"-----------", CmdHelp,                    AlwaysAvailable, "--------------------- " _CYAN_("recovery") " --------------------"},
//    {"autopwn",     CmdHFiClassAutopwn,         IfPm3Iclass,     "Automatic key recovery tool for iCLASS"},
    {"chk",         CmdHFiClassCheckKeys,       IfPm3Iclass,     "Check keys"},
    {"loclass",     CmdHFiClass_loclass,        AlwaysAvailable, "Use loclass to perform bruteforce reader attack"},
    {"lookup",      CmdHFiClassLookUp,          AlwaysAvailable, "Uses authentication trace to check for key in dictionary file"},
    {"-----------", CmdHelp,                    IfPm3Iclass,     "-------------------- " _CYAN_("simulation") " -------------------"},
    {"sim",         CmdHFiClassSim,             IfPm3Iclass,     "Simulate iCLASS tag"},
    {"eload",       CmdHFiClassELoad,           IfPm3Iclass,     "Load Picopass / iCLASS dump file into emulator memory"},
    {"esave",       CmdHFiClassESave,           IfPm3Iclass,     "Save emulator memory to file"},
    {"esetblk",     CmdHFiClassESetBlk,         IfPm3Iclass,     "Set emulator memory block data"},
    {"eview",       CmdHFiClassEView,           IfPm3Iclass,     "View emulator memory"},
    {"-----------", CmdHelp,                    AlwaysAvailable, "---------------------- " _CYAN_("utils") " ----------------------"},
    {"configcard",  CmdHFiClassConfigCard,      AlwaysAvailable, "Reader configuration card"},
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

//static void test_credential_type(void) {
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

    // if CSN ends with FF12E0, it's inside HID CSN range.
    bool isHidRange = (memcmp(hdr->csn + 5, "\xFF\x12\xE0", 3) == 0);

    bool legacy = (memcmp(aia, "\xff\xff\xff\xff\xff\xff\xff\xff", 8) == 0);
    bool se_enabled = (memcmp(aia, "\xff\xff\xff\x00\x06\xff\xff\xff", 8) == 0);

    if (isHidRange) {
        PrintAndLogEx(SUCCESS, "    CSN.......... " _YELLOW_("HID range"));
        if (legacy)
            PrintAndLogEx(SUCCESS, "    Credential... " _GREEN_("iCLASS legacy"));
        if (se_enabled)
            PrintAndLogEx(SUCCESS, "    Credential... " _GREEN_("iCLASS SE"));
    } else {
        PrintAndLogEx(SUCCESS, "    CSN.......... " _YELLOW_("outside HID range"));
    }

    uint8_t cardtype = get_mem_config(hdr);
    PrintAndLogEx(SUCCESS, "    Card type.... " _GREEN_("%s"), card_types[cardtype]);

    return PM3_SUCCESS;
}
