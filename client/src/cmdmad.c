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
// MAD commands
//-----------------------------------------------------------------------------

#include "cmdmad.h"
#include <string.h>
#include "cmdparser.h"
#include "commonutil.h"
#include "comms.h"
#include "ui.h"
#include "cliparser.h"
#include "fileutils.h"
#include "mifare/mad.h"
#include "mifare/mifarehost.h"
#include "mifare/mifare4.h"
#include "mifare/mifaredefault.h"
#include "mifare.h"
#include "crc.h"
#include "util.h"
#include "mifare/mad_test.h"

// --- Card transport adapters ---

static int mfc_read_sector(uint8_t sector_no, uint8_t key_type,
                           const uint8_t *key, uint8_t *buf, bool verbose) {
    (void)verbose;
    return mf_read_sector(sector_no, key_type, key, buf);
}

static int mfc_write_sector_data(uint8_t sector_no, uint8_t key_type,
                                 const uint8_t *key, const uint8_t *data, bool verbose) {
    (void)verbose;
    uint8_t first = mfFirstBlockOfSector(sector_no);
    uint8_t ndata = mfNumBlocksPerSector(sector_no) - 1;
    for (int i = 0; i < ndata; i++) {
        int res = mf_write_block(first + i, key_type, key, data + i * MFBLOCK_SIZE);
        if (res != PM3_SUCCESS)
            return res;
    }
    return PM3_SUCCESS;
}

static int mfp_read_sector(uint8_t sector_no, uint8_t key_type,
                           const uint8_t *key, uint8_t *buf, bool verbose) {
    return mfpReadSector(sector_no, key_type, (uint8_t *)key, buf, verbose);
}

static int mfp_write_sector_data(uint8_t sector_no, uint8_t key_type,
                                 const uint8_t *key, const uint8_t *data, bool verbose) {
    return mfpWriteSector(sector_no, key_type, (uint8_t *)key, data, verbose);
}

// --- Card type detection ---

typedef enum {
    MAD_CARD_CLASSIC,
    MAD_CARD_PLUS,
} mad_card_type_t;

static int mad_detect_card(mad_card_type_t *out) {
    uint8_t sector0[MFBLOCK_SIZE * 4] = {0};

    if (mf_read_sector(MF_MAD1_SECTOR, MF_KEY_A, g_mifare_mad_key, sector0) == PM3_SUCCESS) {
        *out = MAD_CARD_CLASSIC;
        return PM3_SUCCESS;
    }

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, false) == PM3_SUCCESS) {
        *out = MAD_CARD_PLUS;
        return PM3_SUCCESS;
    }

    PrintAndLogEx(ERR, "Could not authenticate to MAD sector with default keys (Classic or Plus)");
    return PM3_ESOFT;
}

static void mad_fill_ops(mad_ops_t *ops, mad_card_type_t card_type,
                         const uint8_t *mad_key, const uint8_t *app_key,
                         uint8_t key_type, bool verbose) {
    if (card_type == MAD_CARD_CLASSIC) {
        ops->read_sector = mfc_read_sector;
        ops->write_sector_data = mfc_write_sector_data;
        ops->mad_key = mad_key ? mad_key : g_mifare_mad_key;
        ops->app_key = app_key ? app_key : g_mifare_ndef_key;
    } else {
        ops->read_sector = mfp_read_sector;
        ops->write_sector_data = mfp_write_sector_data;
        ops->mad_key = mad_key ? mad_key : g_mifarep_mad_key;
        ops->app_key = app_key ? app_key : g_mifarep_ndef_key;
    }
    ops->mad_key_type = MF_KEY_A;
    ops->app_key_type = key_type;
    ops->verbose = verbose;
}

// Determine card type from key length, or auto-detect
static int mad_resolve_card(int keylen, int madkeylen, mad_card_type_t *out, bool force_classic, bool force_plus) {
    if (force_classic) {
        *out = MAD_CARD_CLASSIC;
        return PM3_SUCCESS;
    }
    if (force_plus) {
        *out = MAD_CARD_PLUS;
        return PM3_SUCCESS;
    }
    if (keylen == AES_KEY_LEN || madkeylen == AES_KEY_LEN) {
        *out = MAD_CARD_PLUS;
        return PM3_SUCCESS;
    }
    if (keylen == MIFARE_KEY_SIZE || madkeylen == MIFARE_KEY_SIZE) {
        *out = MAD_CARD_CLASSIC;
        return PM3_SUCCESS;
    }
    return mad_detect_card(out);
}

// --- Shared read/write/verify implementation ---

static int mad_cmd_read(const char *Cmd, const char *cmd_name, bool force_classic, bool force_plus) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, cmd_name,
                  "Read application data from sectors matching a MAD AID",
                  "mad read --aid e103 -> read NDEF data (auto-detect card)\n"
                  "mad read --aid e103 -k ffffffffffff -b -> Classic, key B\n"
                  "mad read --aid e103 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> Plus\n"
                  "mad read --aid e103 -v -f mydata.bin -> verbose, save to file");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "verbose output"),
        arg_str1(NULL, "aid",      "<hex>", "application ID (2 hex bytes)"),
        arg_str0("k",  "key",      "<hex>", "key for data sectors"),
        arg_lit0("b",  "keyb",     "use key B (def: key A)"),
        arg_str0(NULL, "mad-key",  "<hex>", "key for MAD sectors"),
        arg_lit0(NULL, "be",       "big-endian AID byte swap"),
        arg_lit0(NULL, "override", "override failed CRC check"),
        arg_str0("f",  "file",     "<fn>", "save raw data to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool verbose = arg_get_lit(ctx, 1);
    uint8_t aid[2] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t userkey[AES_KEY_LEN] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 3, userkey, &keylen);
    bool keyB = arg_get_lit(ctx, 4);
    uint8_t madkey[AES_KEY_LEN] = {0};
    int madkeylen = 0;
    CLIGetHexWithReturn(ctx, 5, madkey, &madkeylen);
    bool swapmad = arg_get_lit(ctx, 6);
    bool override = arg_get_lit(ctx, 7);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 8), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    mad_card_type_t card_type;
    int res = mad_resolve_card(keylen, madkeylen, &card_type, force_classic, force_plus);
    if (res != PM3_SUCCESS)
        return res;

    if (verbose)
        PrintAndLogEx(INFO, "Using %s transport", card_type == MAD_CARD_CLASSIC ? "MIFARE Classic" : "MIFARE Plus");

    mad_ops_t ops = {0};
    mad_fill_ops(&ops, card_type,
                 madkeylen > 0 ? madkey : NULL,
                 keylen > 0 ? userkey : NULL,
                 keyB ? MF_KEY_B : MF_KEY_A, verbose);

    uint16_t aaid = (aid[0] << 8) | aid[1];
    uint8_t data[MIFARE_4K_MAX_BYTES] = {0};
    size_t datalen = 0;
    res = mad_app_read(&ops, aaid, swapmad, override, data, sizeof(data), &datalen);
    if (res != PM3_SUCCESS)
        return res;

    PrintAndLogEx(INFO, "read %zu bytes from AID 0x%04X", datalen, aaid);
    print_buffer_with_offset(data, datalen, 0, true);

    if (fnlen > 0)
        pm3_save_dump(filename, data, datalen, jsfRaw);

    return PM3_SUCCESS;
}

static int mad_cmd_write(const char *Cmd, const char *cmd_name, bool force_classic, bool force_plus) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, cmd_name,
                  "Write application data to sectors matching a MAD AID",
                  "mad write --aid e103 -d 0102030405060708 -> write data\n"
                  "mad write --aid e103 -f mydata.bin -> write from file\n"
                  "mad write --aid e103 -k ffffffffffff -d 0102030405 -> Classic, custom key");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "verbose output"),
        arg_str1(NULL, "aid",      "<hex>", "application ID (2 hex bytes)"),
        arg_str0("k",  "key",      "<hex>", "key for data sectors"),
        arg_lit0("b",  "keyb",     "use key B (def: key A)"),
        arg_str0(NULL, "mad-key",  "<hex>", "key for MAD sectors"),
        arg_lit0(NULL, "be",       "big-endian AID byte swap"),
        arg_lit0(NULL, "override", "override failed CRC check"),
        arg_str0("d",  "data",     "<hex>", "data to write"),
        arg_str0("f",  "file",     "<fn>", "load data from file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool verbose = arg_get_lit(ctx, 1);
    uint8_t aid[2] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t userkey[AES_KEY_LEN] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 3, userkey, &keylen);
    bool keyB = arg_get_lit(ctx, 4);
    uint8_t madkey[AES_KEY_LEN] = {0};
    int madkeylen = 0;
    CLIGetHexWithReturn(ctx, 5, madkey, &madkeylen);
    bool swapmad = arg_get_lit(ctx, 6);
    bool override = arg_get_lit(ctx, 7);
    uint8_t hexdata[MIFARE_4K_MAX_BYTES] = {0};
    int hexdatalen = 0;
    CLIGetHexWithReturn(ctx, 8, hexdata, &hexdatalen);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 9), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint8_t *wdata = hexdata;
    size_t wdata_len = hexdatalen;
    uint8_t *dump = NULL;

    if (fnlen > 0) {
        size_t bytes_read = 0;
        int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, MIFARE_4K_MAX_BYTES);
        if (res != PM3_SUCCESS)
            return res;
        wdata = dump;
        wdata_len = bytes_read;
    }

    if (wdata_len == 0) {
        PrintAndLogEx(ERR, "no data to write (use -d or -f)");
        free(dump);
        return PM3_EINVARG;
    }

    mad_card_type_t card_type;
    int res = mad_resolve_card(keylen, madkeylen, &card_type, force_classic, force_plus);
    if (res != PM3_SUCCESS) {
        free(dump);
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Using %s transport", card_type == MAD_CARD_CLASSIC ? "MIFARE Classic" : "MIFARE Plus");

    mad_ops_t ops = {0};
    mad_fill_ops(&ops, card_type,
                 madkeylen > 0 ? madkey : NULL,
                 keylen > 0 ? userkey : NULL,
                 keyB ? MF_KEY_B : MF_KEY_A, verbose);

    uint16_t aaid = (aid[0] << 8) | aid[1];
    res = mad_app_write(&ops, aaid, swapmad, override, wdata, wdata_len);
    free(dump);
    return res;
}

static int mad_cmd_verify(const char *Cmd, const char *cmd_name, bool force_classic, bool force_plus) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, cmd_name,
                  "Read back and verify application data against expected content",
                  "mad verify --aid e103 -d 0102030405060708 -> verify data\n"
                  "mad verify --aid e103 -f mydata.bin -> verify against file");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "verbose output"),
        arg_str1(NULL, "aid",      "<hex>", "application ID (2 hex bytes)"),
        arg_str0("k",  "key",      "<hex>", "key for data sectors"),
        arg_lit0("b",  "keyb",     "use key B (def: key A)"),
        arg_str0(NULL, "mad-key",  "<hex>", "key for MAD sectors"),
        arg_lit0(NULL, "be",       "big-endian AID byte swap"),
        arg_lit0(NULL, "override", "override failed CRC check"),
        arg_str0("d",  "data",     "<hex>", "expected data"),
        arg_str0("f",  "file",     "<fn>", "load expected data from file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool verbose = arg_get_lit(ctx, 1);
    uint8_t aid[2] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t userkey[AES_KEY_LEN] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 3, userkey, &keylen);
    bool keyB = arg_get_lit(ctx, 4);
    uint8_t madkey[AES_KEY_LEN] = {0};
    int madkeylen = 0;
    CLIGetHexWithReturn(ctx, 5, madkey, &madkeylen);
    bool swapmad = arg_get_lit(ctx, 6);
    bool override = arg_get_lit(ctx, 7);
    uint8_t hexdata[MIFARE_4K_MAX_BYTES] = {0};
    int hexdatalen = 0;
    CLIGetHexWithReturn(ctx, 8, hexdata, &hexdatalen);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 9), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    uint8_t *edata = hexdata;
    size_t edata_len = hexdatalen;
    uint8_t *dump = NULL;

    if (fnlen > 0) {
        size_t bytes_read = 0;
        int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, MIFARE_4K_MAX_BYTES);
        if (res != PM3_SUCCESS)
            return res;
        edata = dump;
        edata_len = bytes_read;
    }

    if (edata_len == 0) {
        PrintAndLogEx(ERR, "no expected data (use -d or -f)");
        free(dump);
        return PM3_EINVARG;
    }

    mad_card_type_t card_type;
    int res = mad_resolve_card(keylen, madkeylen, &card_type, force_classic, force_plus);
    if (res != PM3_SUCCESS) {
        free(dump);
        return res;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Using %s transport", card_type == MAD_CARD_CLASSIC ? "MIFARE Classic" : "MIFARE Plus");

    mad_ops_t ops = {0};
    mad_fill_ops(&ops, card_type,
                 madkeylen > 0 ? madkey : NULL,
                 keylen > 0 ? userkey : NULL,
                 keyB ? MF_KEY_B : MF_KEY_A, verbose);

    uint16_t aaid = (aid[0] << 8) | aid[1];
    res = mad_app_verify(&ops, aaid, swapmad, override, edata, edata_len);
    free(dump);
    return res;
}

// --- Auto-detect commands (mad read / mad write / mad verify) ---

static int CmdMADRead(const char *Cmd)   { return mad_cmd_read(Cmd, "mad read", false, false); }
static int CmdMADWrite(const char *Cmd)  { return mad_cmd_write(Cmd, "mad write", false, false); }
static int CmdMADVerify(const char *Cmd) { return mad_cmd_verify(Cmd, "mad verify", false, false); }

// --- Card-specific wrappers (for hf mf / hf mfp aliases) ---

int CmdMADMFRead(const char *Cmd)    { return mad_cmd_read(Cmd, "hf mf madread", true, false); }
int CmdMADMFWrite(const char *Cmd)   { return mad_cmd_write(Cmd, "hf mf madwrite", true, false); }
int CmdMADMFVerify(const char *Cmd)  { return mad_cmd_verify(Cmd, "hf mf madverify", true, false); }
int CmdMADMFPRead(const char *Cmd)   { return mad_cmd_read(Cmd, "hf mfp madread", false, true); }
int CmdMADMFPWrite(const char *Cmd)  { return mad_cmd_write(Cmd, "hf mfp madwrite", false, true); }
int CmdMADMFPVerify(const char *Cmd) { return mad_cmd_verify(Cmd, "hf mfp madverify", false, true); }

// --- Decode (offline) ---

static int CmdMADDecode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mad decode",
                  "Decode a MAD byte array and print the directory",
                  "mad decode -d <sector0 hex>                    -> decode MAD1\n"
                  "mad decode -d <sector0 hex> --mad2 <sector16 hex> -> decode MAD1 + MAD2\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "verbose output"),
        arg_str1("d",  "data",     "<hex>", "MAD1 sector 0 data (64 bytes)"),
        arg_str0(NULL, "mad2",     "<hex>", "MAD2 sector 16 data (64 bytes)"),
        arg_lit0(NULL, "be",       "big-endian AID byte swap"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool verbose = arg_get_lit(ctx, 1);
    uint8_t data[MFBLOCK_SIZE * 4] = {0};
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), data, sizeof(data), &datalen);
    uint8_t data2[MFBLOCK_SIZE * 4] = {0};
    int data2len = 0;
    int res2 = CLIParamHexToBuf(arg_get_str(ctx, 3), data2, sizeof(data2), &data2len);
    bool swapmad = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);
    if (res) {
        PrintAndLogEx(FAILED, "Error parsing MAD1 hex data");
        return PM3_EINVARG;
    }
    if (data2len > 0 && res2) {
        PrintAndLogEx(FAILED, "Error parsing MAD2 hex data");
        return PM3_EINVARG;
    }

    if (datalen < (int)sizeof(mad1_sector_t)) {
        PrintAndLogEx(ERR, "Need at least %zu bytes for MAD1 (got %d)", sizeof(mad1_sector_t), datalen);
        return PM3_EINVARG;
    }

    MADPrintHeader();
    bool haveMAD2 = false;
    MAD1DecodeAndPrint((const mad1_sector_t *)data, swapmad, verbose, &haveMAD2);

    if (data2len >= (int)sizeof(mad2_sector_t)) {
        MAD2DecodeAndPrint((const mad2_sector_t *)data2, swapmad, verbose);
    } else if (haveMAD2 && data2len == 0) {
        PrintAndLogEx(HINT, "MAD1 indicates v2, use --mad2 to provide sector 16 data");
    }

    return PM3_SUCCESS;
}

// --- Encode ---

// parse "1-3,5,7-9" into sector numbers, returns count or -1 on error
static int parse_sector_ranges(const char *str, uint8_t *sectors, int max_sectors) {
    int count = 0;
    const char *p = str;

    while (*p) {
        while (*p == ' ' || *p == '\t') p++;
        if (*p == '\0') break;

        char *end = NULL;
        long start = strtol(p, &end, 10);
        if (end == p || start < 0 || start > 39)
            return -1;

        long stop = start;
        if (*end == '-') {
            p = end + 1;
            stop = strtol(p, &end, 10);
            if (end == p || stop < start || stop > 39)
                return -1;
        }

        for (long s = start; s <= stop; s++) {
            if (s == 0 || s == 16) {
                PrintAndLogEx(ERR, "Sector %ld is reserved for MAD directory", s);
                return -1;
            }
            if (count >= max_sectors)
                return -1;
            sectors[count++] = (uint8_t)s;
        }

        p = end;
        if (*p == ',') p++;
    }
    return count;
}

static int CmdMADEncode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mad encode",
                  "Encode a MAD byte array from AID-to-sector mappings",
                  "mad encode --aid E103:1-3 --aid 484D:4          -> MAD1 with NDEF + HID\n"
                  "mad encode --aid E103:1-3,5                     -> non-contiguous sectors\n"
                  "mad encode --aid E103:1-3,17-18 --aid 484D:4    -> MAD1 + MAD2\n"
                  "mad encode --aid E103:1-3 -q                    -> quiet, hex only\n");

    void *argtable[] = {
        arg_param_begin,
        arg_strn(NULL, "aid",   "<hex:sectors>", 1, 8, "AID and sector ranges (e.g. E103:1-3,5)"),
        arg_lit0("q",  "quiet", "quiet output, hex bytes only"),
        arg_lit0(NULL, "be",    "big-endian AID byte swap"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int aid_count = 0;
    struct arg_str *aid_arg = arg_get_str(ctx, 1);
    aid_count = aid_arg->count;

    uint16_t sector_aids[40] = {0};
    bool have_mad2 = false;

    for (int a = 0; a < aid_count; a++) {
        const char *val = aid_arg->sval[a];

        const char *colon = strchr(val, ':');
        if (colon == NULL) {
            PrintAndLogEx(ERR, "Invalid format '%s', expected <aid>:<sectors> (e.g. E103:1-3)", val);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        int aid_hex_len = colon - val;
        if (aid_hex_len != 4) {
            PrintAndLogEx(ERR, "AID must be 4 hex chars, got %d in '%s'", aid_hex_len, val);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        char aid_str[5] = {0};
        memcpy(aid_str, val, 4);
        uint16_t aid_val = (uint16_t)strtoul(aid_str, NULL, 16);

        uint8_t sectors[40] = {0};
        int nsectors = parse_sector_ranges(colon + 1, sectors, 40);
        if (nsectors <= 0) {
            PrintAndLogEx(ERR, "Invalid sector range in '%s'", val);
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        for (int s = 0; s < nsectors; s++) {
            uint8_t sno = sectors[s];
            if (sector_aids[sno] != 0) {
                PrintAndLogEx(ERR, "Sector %d already assigned to AID 0x%04X", sno, sector_aids[sno]);
                CLIParserFree(ctx);
                return PM3_EINVARG;
            }
            sector_aids[sno] = aid_val;
            if (sno > 15) have_mad2 = true;
        }
    }

    bool quiet = arg_get_lit(ctx, 2);
    bool swapmad = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // build MAD1
    mad1_sector_t s0;
    memset(&s0, 0, sizeof(s0));
    s0.mad.info = 0x00;
    for (int i = 0; i < MAD1_NUM_AIDS; i++) {
        uint16_t a = sector_aids[i + 1];
        s0.mad.aid[i] = swapmad ? BSWAP_16(a) : a;
    }
    s0.mad.crc = CRC8Mad((uint8_t *)&s0.mad.info, sizeof(mad1_t) - 1);
    memcpy(s0.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
    s0.trailer.access[0] = 0x78;
    s0.trailer.access[1] = 0x77;
    s0.trailer.access[2] = 0x88;
    s0.trailer.gpb = have_mad2 ? 0xC2 : 0xC1; // DA=1, MA=1, version
    memcpy(s0.trailer.key_b, g_mifare_mad_key_b, MIFARE_KEY_SIZE);

    // build MAD2 if needed
    mad2_sector_t s16;
    memset(&s16, 0, sizeof(s16));
    if (have_mad2) {
        s16.mad.info = 0x00;
        for (int i = 0; i < MAD2_NUM_AIDS; i++) {
            uint16_t a = sector_aids[i + 17];
            s16.mad.aid[i] = swapmad ? BSWAP_16(a) : a;
        }
        s16.mad.crc = CRC8Mad((uint8_t *)&s16.mad.info, sizeof(mad2_t) - 1);
        memcpy(s16.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
        s16.trailer.access[0] = 0x78;
        s16.trailer.access[1] = 0x77;
        s16.trailer.access[2] = 0x88;
        s16.trailer.gpb = 0xC2;
        memcpy(s16.trailer.key_b, g_mifare_mad_key_b, MIFARE_KEY_SIZE);
    }

    if (!quiet) {
        MADPrintHeader();
        bool dummy = false;
        MAD1DecodeAndPrint(&s0, swapmad, false, &dummy);
        if (have_mad2) {
            MAD2DecodeAndPrint(&s16, swapmad, false);
        }
        PrintAndLogEx(NORMAL, "");
    }

    PrintAndLogEx(SUCCESS, "MAD1 sector (64 bytes):");
    PrintAndLogEx(SUCCESS, "%s", sprint_hex_inrow((const uint8_t *)&s0, sizeof(s0)));

    if (have_mad2) {
        PrintAndLogEx(SUCCESS, "MAD2 sector (64 bytes):");
        PrintAndLogEx(SUCCESS, "%s", sprint_hex_inrow((const uint8_t *)&s16, sizeof(s16)));
    }

    return PM3_SUCCESS;
}

// --- Command table ---

static int CmdMADTest(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "mad test",
                  "Run MAD regression tests (offline, no card needed)",
                  "mad test\n"
                  "mad test -v -> verbose output");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    return exec_mad_test(verbose);
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"--------", CmdHelp,      AlwaysAvailable, "--------------- " _CYAN_("MAD") " -----------------"},
    {"read",     CmdMADRead,   IfPm3Iso14443a,  "Read data from MAD AID sectors"},
    {"write",    CmdMADWrite,  IfPm3Iso14443a,  "Write data to MAD AID sectors"},
    {"verify",   CmdMADVerify, IfPm3Iso14443a,  "Verify data in MAD AID sectors"},
    {"--------", CmdHelp,      AlwaysAvailable, "------------- " _CYAN_("General") " ---------------"},
    {"help",     CmdHelp,      AlwaysAvailable, "This help"},
    {"decode",   CmdMADDecode, AlwaysAvailable, "Decode MAD byte array"},
    {"encode",   CmdMADEncode, AlwaysAvailable, "Encode MAD byte array from AID mappings"},
    {"test",     CmdMADTest,   AlwaysAvailable, "Run MAD regression tests"},
    {NULL, NULL, NULL, NULL}
};

int CmdMAD(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}
