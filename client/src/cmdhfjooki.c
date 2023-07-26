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
// High frequency Jooki commands
//-----------------------------------------------------------------------------
#include "cmdhfjooki.h"
#include <ctype.h>
#include <string.h>       // memset
#include "commonutil.h"   // ARRAYLEN
#include "ui.h"           // PrintAndLog
#include "cmdparser.h"
#include "generator.h"
#include "base64.h"
#include "nfc/ndef.h"     // print decode ndef
#include "mifare/mifarehost.h"  // mfemlsetmem_xt
#include "cliparser.h"
#include "cmdhfmfu.h"
#include "cmdmain.h"
#include "fileutils.h"    // convert_mfu..

static int CmdHelp(const char *Cmd);

typedef struct {
    uint8_t typeid;
    uint8_t figureid;
    const char figdesc[40];
    const char typedesc[12];
} PACKED jooki_figure_t;

typedef struct {
    uint8_t uid[7];
    const char b64[17];
    uint8_t typeid;
    uint8_t figureid;
} PACKED jooki_test_t;

// sample set for selftest.
static jooki_test_t jooks[] = {
    { {0x04, 0xDA, 0xB7, 0x6A, 0xE7, 0x4C, 0x80}, "ruxow8lnn88uyeX+", 0x01, 0x00},
    { {0x04, 0xf0, 0x22, 0xc2, 0x33, 0x5e, 0x80}, "\0", 0x01, 0x00},
    { {0x04, 0x8C, 0xEC, 0xDA, 0xF0, 0x4A, 0x80}, "ONrsVf7jX6IaSNV6", 0x01, 0x01},
    { {0x04, 0x92, 0xA7, 0x6A, 0xE7, 0x4C, 0x81}, "Hjjpcx/mZwuveTF+", 0x01, 0x02},
    { {0x04, 0xD0, 0xB0, 0x3A, 0xD3, 0x63, 0x80}, "\0", 0x01, 0x02},
    { {0x04, 0x96, 0x42, 0xDA, 0xF0, 0x4A, 0x80}, "vEWy0WO9wZNEzEok", 0x01, 0x03},
    { {0x04, 0x33, 0xb5, 0x62, 0x39, 0x4d, 0x80}, "\0", 0x01, 0x03},
    { {0x04, 0x17, 0xB7, 0x3A, 0xD3, 0x63, 0x81}, "f0axEma+g2WnLGAm", 0x01, 0x05},
    { {0x04, 0x84, 0x27, 0x6A, 0xE7, 0x4C, 0x80}, "VZB/OLBwOiM5Mpnp", 0x01, 0x05},
    { {0x04, 0x28, 0xF4, 0xDA, 0xF0, 0x4A, 0x81}, "7WzlgEzqLgwTnWNy", 0x01, 0x05},
};

static jooki_figure_t jooks_figures[] = {
    {0x01, 0x00, "Dragon", "Figurine"},
    {0x01, 0x01, "Fox", "Figurine"},
    {0x01, 0x02, "Ghost", "Figurine"},
    {0x01, 0x03, "Knight", "Figurine"},
    {0x01, 0x04, "ThankYou", "Figurine"},
    {0x01, 0x05, "Whale", "Figurine"},
    {0x01, 0x06, "Black Dragon", "Figurine"},
    {0x01, 0x07, "Black Fox", "Figurine"},
    {0x01, 0x08, "Black Knight", "Figurine"},
    {0x01, 0x09, "Black Whale", "Figurine"},
    {0x01, 0x0A, "White Dragon", "Figurine"},
    {0x01, 0x0B, "White Fox", "Figurine"},
    {0x01, 0x0C, "White Knight", "Figurine"},
    {0x01, 0x0D, "White Whale", "Figurine"},

    {0x02, 0x00, "Generic Flat", "Stone"},

    {0x03, 0x00, "record", "Sys"},
    {0x03, 0x01, "factory_mode_on", "Sys"},
    {0x03, 0x02, "factory_mode_off", "Sys"},
    {0x03, 0x03, "airplane_mode_on", "Sys"},
    {0x03, 0x04, "airplane_mode_off", "Sys"},
    {0x03, 0x05, "toy_safe_on", "Sys"},
    {0x03, 0x06, "toy_safe_off", "Sys"},
    {0x03, 0x07, "wifi_on", "Sys"},
    {0x03, 0x08, "wifi_off", "Sys"},
    {0x03, 0x09, "bt_on", "Sys"},
    {0x03, 0x0A, "bt_off", "Sys"},
    {0x03, 0x0B, "production_finished", "Sys"},

    {0x04, 0x00, "test.0", "Test"},
    {0x04, 0x01, "test.1", "Test"},
    {0x04, 0x02, "test.2", "Test"},
    {0x04, 0x03, "test.3", "Test"},
    {0x04, 0x04, "test.4", "Test"},
    {0x04, 0x05, "test.5", "Test"},
    {0x04, 0x06, "test.6", "Test"},
    {0x04, 0x07, "test.7", "Test"},
    {0x04, 0x08, "test.8", "Test"},
    {0x04, 0x09, "test.9", "Test"},
    {0x04, 0x10, "test.10", "Test"},
    {0x04, 0x11, "test.11", "Test"},
    {0x04, 0x12, "test.12", "Test"},
    {0x04, 0x13, "test.13", "Test"},
    {0x04, 0x14, "test.14", "Test"},
    {0x04, 0x15, "test.15", "Test"},
    {0x04, 0x16, "test.16", "Test"},
    {0x04, 0x17, "test.17", "Test"},
    {0x04, 0x18, "test.18", "Test"},
    {0x04, 0x19, "test.19", "Test"},
    {0x04, 0x20, "test.20", "Test"},
};

static int jooki_lookup(uint8_t tid, uint8_t fid) {
    for (int i = 0; i < ARRAYLEN(jooks_figures); i++) {
        jooki_figure_t tmp = jooks_figures[i];
        if (tmp.typeid == tid && tmp.figureid == fid) {
            return i;
        }
    }
    return -1;
}

//static const uint8_t jooki_secret[] = {0x20, 0x20, 0x20, 0x6D, 0x24, 0x0B, 0xEB, 0x94, 0x2C, 0x80, 0x45, 0x16};
static const uint8_t nfc_secret[] = { 0x03, 0x9c, 0x25, 0x6f, 0xb9, 0x2e, 0xe8, 0x08, 0x09, 0x83, 0xd9, 0x33, 0x56};

#define JOOKI_UID_LEN  7
#define JOOKI_IV_LEN   3
#define JOOKI_B64_LEN (16 + 1)
#define JOOKI_PLAIN_LEN 12

static int jooki_encode(uint8_t *iv, uint8_t tid, uint8_t fid, uint8_t *uid, uint8_t *out) {
    if (out == NULL) {
        PrintAndLogEx(ERR, "(encode jooki) base64ndef param is NULL");
        return PM3_EINVARG;
    }

    out[0] = 0x00;
    if (iv == NULL || uid == NULL) {
        PrintAndLogEx(ERR, "(encode jooki) iv or uid param is NULL");
        return PM3_EINVARG;
    }

    const uint8_t d[JOOKI_PLAIN_LEN] = {iv[0], iv[1], iv[2], tid, fid, uid[0], uid[1], uid[2], uid[3], uid[4], uid[5], uid[6]};
    uint8_t enc[JOOKI_PLAIN_LEN] = {0};
    for (uint8_t i = 0; i < JOOKI_PLAIN_LEN; i++) {

        if (i < 3)
            enc[i] = d[i] ^ nfc_secret[i];
        else
            enc[i] = d[i] ^ nfc_secret[i] ^ d[i % 3];
    }

    PrintAndLogEx(DEBUG, "encoded result.... %s", sprint_hex(enc, sizeof(enc)));

    size_t b64len = 0;
    uint8_t b64[20];
    memset(b64, 0, 20);
    mbedtls_base64_encode(b64, sizeof(b64), &b64len, (const unsigned char *)enc, sizeof(enc));
    memcpy(out, b64, b64len);
    return PM3_SUCCESS;
}

static int jooki_decode(uint8_t *b64, uint8_t *result) {
    uint8_t ndef[JOOKI_PLAIN_LEN] = {0};
    size_t outputlen = 0;
    mbedtls_base64_decode(ndef, sizeof(ndef), &outputlen, (const unsigned char *)b64, 16);

    PrintAndLogEx(DEBUG, "(decode_jooki) raw encoded... " _GREEN_("%s"), sprint_hex(ndef, sizeof(ndef)));

    for (uint8_t i = 0; i < JOOKI_PLAIN_LEN; i++) {
        if (i < 3)
            result[i] = ndef[i] ^ nfc_secret[i];
        else
            result[i] = ndef[i] ^ nfc_secret[i] ^ ndef[i % 3] ^ nfc_secret[i % 3];
    }
    PrintAndLogEx(DEBUG, "(decode_jooki) plain......... %s", sprint_hex(result, sizeof(ndef)));
    return PM3_SUCCESS;
}

static int jooki_create_ndef(uint8_t *b64ndef, uint8_t *ndefrecord) {
    // sample of url:   https://s.jooki.rocks/s/?s=ONrsVf7jX6IaSNV6
    if (ndefrecord == NULL) {
        PrintAndLogEx(ERR, "(jooki_create_ndef) ndefrecord param is NULL");
        return PM3_EINVARG;
    }
    memcpy(ndefrecord,
           "\x01\x03\xa0\x0c\x34\x03\x29\xd1"
           "\x01\x25\x55\x04\x73\x2e\x6a\x6f"
           "\x6f\x6b\x69\x2e\x72\x6f\x63\x6b"
           "\x73\x2f\x73\x2f\x3f\x73\x3d", 31);
    memcpy(ndefrecord + 31, b64ndef, 16);
    memcpy(ndefrecord + 47, "\x0a\xFE\x00\x00\x00", 5);
    return PM3_SUCCESS;
}

static void jooki_printEx(uint8_t *b64, uint8_t *iv, uint8_t tid, uint8_t fid, uint8_t *uid, bool verbose) {
    int idx = jooki_lookup(tid, fid);

    PrintAndLogEx(INFO, "Encoded URL.. %s ( " _YELLOW_("%s") " )", sprint_hex(b64, 12), b64);
    PrintAndLogEx(INFO, "Figurine..... %02x %02x - " _GREEN_("%s, %s")
                  , tid
                  , fid
                  , (idx != -1) ?  jooks_figures[idx].typedesc : "n/a"
                  , (idx != -1) ?  jooks_figures[idx].figdesc : "n/a"
                 );
    PrintAndLogEx(INFO, "iv........... %s", sprint_hex(iv, JOOKI_IV_LEN));
    PrintAndLogEx(INFO, "uid.......... %s", sprint_hex(uid, JOOKI_UID_LEN));

    uint8_t ndefmsg[52] = {0};
    jooki_create_ndef(b64, ndefmsg);
    PrintAndLogEx(INFO, "NDEF raw..... %s", sprint_hex_inrow(ndefmsg, sizeof(ndefmsg)));

    if (verbose) {
        int res = NDEFRecordsDecodeAndPrint(ndefmsg, sizeof(ndefmsg), verbose);
        if (res != PM3_SUCCESS) {
            NDEFDecodeAndPrint(ndefmsg, sizeof(ndefmsg), verbose);
        }
    }
}

static void jooki_print(uint8_t *b64, uint8_t *result, bool verbose) {
    if (b64 == NULL || result == NULL)
        return;

    uint8_t iv[JOOKI_IV_LEN] = {0};
    uint8_t uid[JOOKI_UID_LEN] = {0};
    memcpy(iv, result, JOOKI_IV_LEN);
    uint8_t tid = result[3];
    uint8_t fid = result[4];
    memcpy(uid, result + 5, JOOKI_UID_LEN);

    jooki_printEx(b64, iv, tid, fid, uid, verbose);
}

static int jooki_selftest(void) {

    PrintAndLogEx(INFO, "======== " _CYAN_("selftest") " ===========================================");
    for (int i = 0; i < ARRAYLEN(jooks); i++) {
        if (strlen(jooks[i].b64) == 0)
            continue;

        uint8_t iv[JOOKI_IV_LEN] = {0};
        uint8_t uid[JOOKI_UID_LEN] = {0};
        uint8_t result[JOOKI_PLAIN_LEN] = {0};
        jooki_decode((uint8_t *)jooks[i].b64, result);

        memcpy(iv, result, JOOKI_IV_LEN);
        uint8_t tid = result[3];
        uint8_t fid = result[4];
        memcpy(uid, result + 5, sizeof(uid));

        bool tid_ok = (tid == jooks[i].typeid);
        bool fid_ok = (fid == jooks[i].figureid);
        bool uid_ok = (memcmp(uid, jooks[i].uid, sizeof(uid)) == 0);

        int idx = jooki_lookup(tid, fid);

        PrintAndLogEx(INFO, "Encoded URL.. %s ( %s )", sprint_hex((const uint8_t *)jooks[i].b64, 12), jooks[i].b64);
        PrintAndLogEx(INFO, "Type......... %02x - " _GREEN_("%s") " ( %s )", tid, (idx != -1) ? jooks_figures[idx].typedesc : "n/a", tid_ok ? _GREEN_("ok") : _RED_("fail"));
        PrintAndLogEx(INFO, "Figurine..... %02x - " _GREEN_("%s") " ( %s )", fid, (idx != -1) ? jooks_figures[idx].figdesc : "n/a", fid_ok ? _GREEN_("ok") : _RED_("fail"));
        PrintAndLogEx(INFO, "iv........... %s", sprint_hex(iv, sizeof(iv)));
        PrintAndLogEx(INFO, "uid.......... %s ( %s )", sprint_hex(uid, sizeof(uid)), uid_ok ? _GREEN_("ok") : _RED_("fail"));

        uint8_t b64[JOOKI_B64_LEN] = {0};
        memset(b64, 0, sizeof(b64));
        jooki_encode(iv, tid, fid, uid, b64);

        uint8_t ndefmsg[52] = {0};
        jooki_create_ndef(b64, ndefmsg);
        PrintAndLogEx(INFO, "NDEF raw .... %s", sprint_hex(ndefmsg, sizeof(ndefmsg)));

        int status = NDEFRecordsDecodeAndPrint(ndefmsg, sizeof(ndefmsg), true);
        if (status != PM3_SUCCESS) {
            status = NDEFDecodeAndPrint(ndefmsg, sizeof(ndefmsg), true);
        }
        PrintAndLogEx(INFO, "==================================================================");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AJookiEncode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki encode",
                  "Encode a Jooki token to base64 NDEF URI format",
                  "hf jooki encode -t            --> selftest\n"
                  "hf jooki encode -r --dragon   --> read uid from tag and use for encoding\n"
                  "hf jooki encode --uid 04010203040506 --dragon\n"
                  "hf jooki encode --uid 04010203040506 --tid 1 --fid 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid",  "<hex>", "uid bytes"),
        arg_lit0("r", NULL, "read uid from tag instead"),
        arg_lit0("t", NULL, "selftest"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "dragon", "figurine type"),
        arg_lit0(NULL, "fox", "figurine type"),
        arg_lit0(NULL, "ghost", "figurine type"),
        arg_lit0(NULL, "knight", "figurine type"),
        arg_lit0(NULL, "whale", "figurine type"),
        arg_lit0(NULL, "blackdragon", "figurine type"),
        arg_lit0(NULL, "blackfox", "figurine type"),
        arg_lit0(NULL, "blackknight", "figurine type"),
        arg_lit0(NULL, "blackwhale", "figurine type"),
        arg_lit0(NULL, "whitedragon", "figurine type"),
        arg_lit0(NULL, "whitefox", "figurine type"),
        arg_lit0(NULL, "whiteknight", "figurine type"),
        arg_lit0(NULL, "whitewhale", "figurine type"),
        arg_u64_0(NULL, "tid", "<dec>", "figurine type id"),
        arg_u64_0(NULL, "fid", "<dec>", "figurine id"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int ulen = 0;
    uint8_t uid[JOOKI_UID_LEN] = {0x00};
    memset(uid, 0x0, sizeof(uid));
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), uid, sizeof(uid), &ulen);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool use_tag = arg_get_lit(ctx, 2);
    bool selftest = arg_get_lit(ctx, 3);
    bool verbose = arg_get_lit(ctx, 4);
    bool t0 = arg_get_lit(ctx, 5);
    bool t1 = arg_get_lit(ctx, 6);
    bool t2 = arg_get_lit(ctx, 7);
    bool t3 = arg_get_lit(ctx, 8);
    bool t5 = arg_get_lit(ctx, 9);
    bool t6 = arg_get_lit(ctx, 10);
    bool t7 = arg_get_lit(ctx, 11);
    bool t8 = arg_get_lit(ctx, 12);
    bool t9 = arg_get_lit(ctx, 13);
    bool ta = arg_get_lit(ctx, 14);
    bool tb = arg_get_lit(ctx, 15);
    bool tc = arg_get_lit(ctx, 16);
    bool td = arg_get_lit(ctx, 17);

    uint8_t ftid = arg_get_u32_def(ctx, 18, 0);
    uint8_t ffid = arg_get_u32_def(ctx, 19, 0);

    bool figure_abbr = true;

    CLIParserFree(ctx);

    if (selftest) {
        return jooki_selftest();
    }

    uint8_t tid, fid;

    if (ftid || ffid) {
        figure_abbr = false;
    }

    if (ftid > 0x04 || ffid > 0x20) {
        PrintAndLogEx(ERR, "Use a valid Figure Type ID and Figure ID");
        return PM3_EINVARG;
    }

    uint8_t figure_abbr_val = t0 + t1 + t2 + t3 + t5 + t6 + t7 + t8 + t9 + ta + tb + tc + td;

    if (figure_abbr_val > 1) {
        PrintAndLogEx(ERR, "Select one tag type or use figurine type id and figurine id");
        return PM3_EINVARG;
    }

    if (figure_abbr_val == 1 && !figure_abbr) {
        PrintAndLogEx(ERR, "Use either --tid and --fid or one of the figurine types");
        return PM3_EINVARG;
    }

    if (figure_abbr) {
        tid = 0x01;
    } else {
        tid = ftid;
    }
    fid = ffid;

    if (t1)
        fid = 0x01;
    if (t2)
        fid = 0x02;
    if (t3)
        fid = 0x03;
    if (t5)
        fid = 0x05;
    if (t6)
        fid = 0x06;
    if (t7)
        fid = 0x07;
    if (t8)
        fid = 0x08;
    if (t9)
        fid = 0x09;
    if (ta)
        fid = 0x0a;
    if (tb)
        fid = 0x0b;
    if (tc)
        fid = 0x0c;
    if (td)
        fid = 0x0d;

    uint8_t iv[JOOKI_IV_LEN] = {0x80, 0x77, 0x51};
    if (use_tag) {
        res = ul_read_uid(uid);
        if (res != PM3_SUCCESS) {
            return res;
        }
    } else {
        if (ulen != JOOKI_UID_LEN) {
            PrintAndLogEx(ERR, "Wrong length of UID, expect %u, got %d", JOOKI_UID_LEN, ulen);
            return PM3_EINVARG;
        }
    }

    uint8_t b64[JOOKI_B64_LEN] = {0};
    memset(b64, 0, sizeof(b64));
    jooki_encode(iv, tid, fid, uid, b64);
    jooki_printEx(b64, iv, tid, fid, uid, verbose);
    return PM3_SUCCESS;
}

static int CmdHF14AJookiDecode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki decode",
                  "Decode a base64-encode Jooki token in NDEF URI format",
                  "hf jooki decode -d 7WzlgEzqLgwTnWNy"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<base64>", "base64 url parameter"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int dlen = 16;
    uint8_t b64[JOOKI_B64_LEN] = {0x00};
    memset(b64, 0x0, sizeof(b64));
    CLIGetStrWithReturn(ctx, 1, b64, &dlen);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    uint8_t result[JOOKI_PLAIN_LEN] = {0};
    int res = jooki_decode(b64, result);
    if (res == PM3_SUCCESS) {
        jooki_print(b64, result, verbose);
    }
    return PM3_SUCCESS;
}

static int CmdHF14AJookiSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki sim",
                  "Simulate a Jooki token.  Either `hf mfu eload` before or use `-d` param",
                  "hf jooki sim                      --> use token in emulator memory\n"
                  "hf jooki sim -b 7WzlgEzqLgwTnWNy  --> using base64 url parameter"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("b", "b64", "<base64>", "base64 url parameter"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int dlen = 16;
    uint8_t b64[JOOKI_B64_LEN] = {0x00};
    memset(b64, 0x0, sizeof(b64));
    CLIGetStrWithReturn(ctx, 1, b64, &dlen);
    CLIParserFree(ctx);

    uint8_t result[JOOKI_PLAIN_LEN] = {0};
    int res = jooki_decode(b64, result);
    if (res != PM3_SUCCESS) {
        return res;
    }

    jooki_print(b64, result, false);

    // copy UID from base64 url parameter
    uint8_t uid[7] = {0};
    memcpy(uid, result + 5, 7);

    // hf mfu sim...
    uint8_t *data = calloc(144, sizeof(uint8_t));

    memcpy(data, uid, 3);
    memcpy(data + (1 * 4), uid + 3, 4);

    // bbc0
    data[3] = 0x88 ^ data[0] ^ data[1] ^ data[2];

    // bbc1
    data[8] = data[4] ^ data[5] ^ data[6] ^ data[7];

    // copy NDEF magic firs, skip BBC1
    memcpy(data + (2 * 4) + 1, "\x48\x00\x00\xE1\x10\x12\x00", 7);

    // copy raw NDEF
    jooki_create_ndef(b64, data + (4 * 4));

    // convert plain or old mfu format to new format
    size_t datalen = 144;
    res = convert_mfu_dump_format(&data, &datalen, true);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Failed convert on load to new Ultralight/NTAG format");
        free(data);
        return res;
    }

    mfu_dump_t *mfu_dump = (mfu_dump_t *)data;
    memcpy(mfu_dump->version, "\x00\x04\x04\x02\x01\x00\x0F\x03", 8);
    mfu_dump->counter_tearing[2][3] = 0xBD;
    mfu_dump->pages = 0x2c;

    printMFUdumpEx(mfu_dump, mfu_dump->pages + 1, 0);

    // upload to emulator memory
    PrintAndLogEx(INFO, "Uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);

    // fast push mode
    g_conn.block_after_ACK = true;
    uint8_t blockwidth = 4, counter = 0, blockno = 0;

    // 12 is the size of the struct the fct mfEmlSetMem_xt uses to transfer to device
    uint16_t max_avail_blocks = ((PM3_CMD_DATA_SIZE - 12) / blockwidth) * blockwidth;

    while (datalen) {
        if (datalen == blockwidth) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }
        uint16_t chunk_size = MIN(max_avail_blocks, datalen);
        uint16_t blocks_to_send = chunk_size / blockwidth;

        if (mfEmlSetMem_xt(data + counter, blockno, blocks_to_send, blockwidth) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Cant set emul block: %3d", blockno);
            free(data);
            return PM3_ESOFT;
        }
        blockno += blocks_to_send;
        counter += chunk_size;
        datalen -= chunk_size;
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", counter);

    struct {
        uint8_t tagtype;
        uint8_t flags;
        uint8_t uid[10];
        uint8_t exitAfter;
    } PACKED payload;

    // NTAG,  7 byte UID in eloaded data.
    payload.tagtype = 7;
    payload.flags = FLAG_UID_IN_EMUL;
    payload.exitAfter = 0;
    memcpy(payload.uid, uid, sizeof(uid));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Starting simulating");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " or pm3-button to abort simulation");
    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "User aborted");
            break;
        }

        if (WaitForResponseTimeout(CMD_HF_MIFARE_SIMULATE, &resp, 1500) == false)
            continue;

        if (resp.status != PM3_SUCCESS)
            break;
    }
    free(data);
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf 14a list") "` to view trace log");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHF14AJookiClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf jooki clone",
                  "Write a Jooki token to a Ultralight or NTAG tag",
                  "hf jooki clone -d <hex bytes>         --> where hex is raw NDEF\n"
                  "hf jooki clone --b64 7WzlgEzqLgwTnWNy --> using base64 url parameter"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("b", "b64",  "<base64>", "base64 url parameter"),
        arg_str0("d", "data", "<hex>",    "raw NDEF bytes"),
        arg_str0("p", "pwd",  "<hex>",    "password for authentication (EV1/NTAG 4 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int blen = 16;
    uint8_t b64[JOOKI_B64_LEN] = {0x00};
    memset(b64, 0x0, sizeof(b64));
    CLIGetStrWithReturn(ctx, 1, b64, &blen);

    int dlen = 0;
    uint8_t data[52] = {0x00};
    memset(data, 0x0, sizeof(data));
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), data, sizeof(data), &dlen);
    if (res) {
        CLIParserFree(ctx);
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    int plen = 0;
    uint8_t pwd[4] = {0x00};
    CLIGetHexWithReturn(ctx, 3, pwd, &plen);
    CLIParserFree(ctx);

    if (dlen != 52) {
        PrintAndLogEx(ERR, "Wrong data length. Expected 52 got %d", dlen);
        return PM3_EINVARG;
    }

    bool has_pwd = false;
    if (plen == 4) {
        has_pwd = true;
    }

    // 0 - no authentication
    // 2 - pwd  (4 bytes)
    uint8_t keytype = 0, blockno = 4, i = 0;

    while ((i * 4) < dlen) {

        uint8_t cmddata[8] = {0};
        memcpy(cmddata, data + (i * 4), 4);
        if (has_pwd) {
            memcpy(cmddata + 4, pwd, 4);
            keytype = 2;
        }
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFAREU_WRITEBL, blockno, keytype, 0, cmddata, sizeof(cmddata));

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
            uint8_t isOK  = resp.oldarg[0] & 0xff;
            PrintAndLogEx(SUCCESS, "Write block %d ( %s )", blockno, isOK ? _GREEN_("ok") : _RED_("fail"));
        } else {
            PrintAndLogEx(WARNING, "Command execute timeout");
        }

        blockno++;
        i++;
    }

    PrintAndLogEx(INFO, "Done");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf mfu ndefread") "` to view");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,              AlwaysAvailable, "This help"},
    {"clone",  CmdHF14AJookiClone,   IfPm3Iso14443a,  "Write a Jooki token"},
    {"decode", CmdHF14AJookiDecode,  AlwaysAvailable, "Decode Jooki token"},
    {"encode", CmdHF14AJookiEncode,  AlwaysAvailable, "Encode Jooki token"},
    {"sim",    CmdHF14AJookiSim,     IfPm3Iso14443a,  "Simulate Jooki token"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF_Jooki(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
