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
// Low frequency Hitag S support
//-----------------------------------------------------------------------------

#include "cmdlfhitaghts.h"
#include <ctype.h>
#include "cmdparser.h"  // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "commonutil.h"
#include "hitag.h"
#include "fileutils.h"  // savefile
#include "protocols.h"  // defines
#include "cliparser.h"
#include "crc.h"
#include "graph.h"      // MAX_GRAPH_TRACE_LEN
#include "lfdemod.h"
#include "cmddata.h"    // setDemodBuff
#include "pm3_cmd.h"    // return codes
#include "hitag2/hitag2_crypto.h"
#include "util_posix.h"             // msclock

static int CmdHelp(const char *Cmd);

static const char *hts_get_type_str(uint32_t uid) {
    //uid s/n        ********
    uint8_t type = (uid >> 4) & 0xF;
    switch (type) {
        case 1:
            return "PCF 7936";
        case 2:
            return "PCF 7946";
        case 3:
            return "PCF 7947";
        case 4:
            return "PCF 7942/44";
        case 5:
            return "PCF 7943";
        case 6:
            return "PCF 7941";
        case 7:
            return "PCF 7952";
        case 9:
            return "PCF 7945";
        default:
            return "";
    }
}

static bool hts_get_uid(uint32_t *uid) {
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_UID, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_UID, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return false;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - failed getting UID");
        return false;
    }

    if (uid) {
        *uid = bytes_to_num(resp.data.asBytes, HITAG_UID_SIZE);
    }
    return true;
}

int read_hts_uid(void) {
    uint32_t uid = 0;
    if (hts_get_uid(&uid) == false) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%08X"), uid);
    PrintAndLogEx(SUCCESS, "TYPE... " _GREEN_("%s"), hts_get_type_str(uid));
    return PM3_SUCCESS;
}

static int CmdLFHitagSRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts rdbl",
                  "Read Hitag S memory.\n\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n\n"
                  "  8268/8310 password mode: \n"
                  "    - default password BBDD3399\n",
                  "  lf hitag hts rdbl                         -> Hitag S/8211, plain mode\n"
                  "  lf hitag hts rdbl --82xx -k BBDD3399      -> 8268/8310, password mode\n"
                  "  lf hitag hts rdbl --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag hts rdbl --crypto                -> Hitag S, crypto mode, def key\n"
                  "  lf hitag hts rdbl -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0("8", "82xx", "8268/8310 mode"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "pwd or key, 4 or 6 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_plain = false;

    uint8_t nrar[8];
    int nrar_len = 0;

    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), nrar, sizeof(nrar), &nrar_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool use_nrar = nrar_len > 0;
    bool use_82xx = arg_get_lit(ctx, 2);
    bool use_crypto = arg_get_lit(ctx, 3);

    uint8_t key[6];
    int key_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 4), key, sizeof(key), &key_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (key_len != 0 && key_len != 4 && key_len != 6) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0, 4 or 6, got %d", key_len);
        return PM3_EINVARG;
    }

    if (nrar_len && nrar_len != HITAGS_NRAR_SIZE) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected %d, got %d", HITAGS_NRAR_SIZE, nrar_len);
        return PM3_EINVARG;
    }

    // complete options
    if (key_len == 4) {
        use_82xx = true;
    }

    if (key_len == 6) {
        use_crypto = true;
    }

    if ((key_len == 0) && use_82xx) {
        memcpy(key, "\xBB\xDD\x33\x99", 4);
        key_len = 4;
    }

    if ((key_len == 0) && use_crypto) {
        memcpy(key, "ONMIKR", 6);
        key_len = 6;
    }

    // check coherence
    uint8_t auth_methods = (use_plain + use_nrar + use_82xx + use_crypto);
    if (auth_methods > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    }

    if (auth_methods == 0) {
        use_plain = true;
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    if (use_nrar) {
        packet.cmd = RHTSF_CHALLENGE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));
    }

    if (use_82xx) {
        packet.cmd = RHTSF_82xx;
        memcpy(packet.pwd, key, sizeof(packet.pwd));
    }

    if (use_crypto) {
        packet.cmd = RHTSF_KEY;
        memcpy(packet.key, key, sizeof(packet.key));
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_READ, (uint8_t *) &packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_READ, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - hitag failed");
        return PM3_ESOFT;
    }

    // ??
    if (use_nrar) {
        return PM3_SUCCESS;
    }

    uint8_t *data = resp.data.asBytes;

    hitags_config_t config = hitags_config_unpack(&data[HITAGS_PAGE_SIZE * HITAGS_CONFIG_PADR]);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    hitags_config_print(config);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Data") " ----------------------------------");

    const int hts_mem_sizes[] = {4, 32, 256, 0};
    uint32_t size = hts_mem_sizes[config.memory_type];

    print_hex_break(data, size, HITAGS_PAGE_SIZE);

    return PM3_SUCCESS;
}

static int CmdLFHitagSWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts wrbl",
                  "Write a page in Hitag S memory.\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n\n"
                  "  8268/8310 password mode: \n"
                  "    - default password BBDD3399\n",
                  "  lf hitag hts wrbl -p 6 -d 01020304                         -> Hitag S/8211, plain mode\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --82xx -k BBDD3399      -> 8268/8310, password mode\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 --crypto                -> Hitag S, crypto mode, default key\n"
                  "  lf hitag hts wrbl -p 6 -d 01020304 -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
        arg_lit0("8", "82xx", "8268/8310 mode"),
        arg_lit0(NULL, "crypto", "crypto mode"),
        arg_str0("k", "key", "<hex>", "pwd or key, 4 or 6 hex bytes"),
        arg_int1("p", "page", "<dec>", "page address to write to"),
        arg_str1("d", "data", "<hex>", "data, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool use_plain = false;

    uint8_t nrar[8];
    int nrar_len = 0;

    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), nrar, sizeof(nrar), &nrar_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool use_nrar = nrar_len > 0;
    bool use_82xx = arg_get_lit(ctx, 2);
    bool use_crypto = arg_get_lit(ctx, 3);

    uint8_t key[6];
    int key_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 4), key, sizeof(key), &key_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int page = arg_get_int_def(ctx, 5, 0);

    uint8_t data[4];
    int data_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 6), data, sizeof(data), &data_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (key_len != 0 && key_len != 4 && key_len != 6) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected 0, 4 or 6, got %d", key_len);
        return PM3_EINVARG;
    }

    if (nrar_len && nrar_len != HITAGS_NRAR_SIZE) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected %d, got %d", HITAGS_NRAR_SIZE, nrar_len);
        return PM3_EINVARG;
    }

    // complete options
    if (key_len == 4) {
        use_82xx = true;
    }
    if (key_len == 6) {
        use_crypto = true;
    }
    if ((key_len == 0) && use_82xx) {
        memcpy(key, "\xBB\xDD\x33\x99", 4);
        key_len = 4;
    }
    if ((key_len == 0) && use_crypto) {
        memcpy(key, "ONMIKR", 6);
        key_len = 6;
    }

    // check coherence
    uint8_t auth_methods = (use_plain + use_nrar + use_82xx + use_crypto);
    if (auth_methods > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    } else if (auth_methods == 0) {
        use_plain = true;
        PrintAndLogEx(INFO, "Write to " _YELLOW_("Hitag S") " in Plain mode");
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.page = page;
    memcpy(packet.data, data, sizeof(data));

    if (use_nrar) {
        packet.cmd = WHTSF_CHALLENGE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in Challenge mode");
    }

    if (use_82xx) {
        packet.cmd = WHTSF_82xx;
        memcpy(packet.pwd, key, sizeof(packet.pwd));
    }

    if (use_crypto) {
        packet.cmd = WHTSF_KEY;
        memcpy(packet.key, key, sizeof(packet.key));
        PrintAndLogEx(INFO, "Authenticating to " _YELLOW_("Hitag S") " in Crypto mode");
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_WRITE, (uint8_t *) &packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_HITAGS_WRITE, &resp, 4000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_ETEAROFF) {
        PrintAndLogEx(INFO, "Writing tear off triggered");
        return PM3_SUCCESS;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
        return resp.status;
    }

    PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static int CmdLFHitagSReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts reader",
                  "Act as a Hitag S reader.  Look for Hitag S tags until Enter or the pm3 button is pressed\n",
                  "lf hitag hts reader\n"
                  "lf hitag hts reader -@   -> Continuous mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        // read UID
        uint32_t uid = 0;
        if (hts_get_uid(&uid)) {
            PrintAndLogEx(SUCCESS, "UID.... " _GREEN_("%08X"), uid);
        }
    } while (cm && kbd_enter_pressed() == false);

    return PM3_SUCCESS;
}

static int CmdLFHitagSSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag hts sim",
                  "Simulate Hitag S transponder\n"
                  "You need to `lf hitag hts eload` first",
                  "lf hitag hts sim\n"
                  "lf hitag hts sim --82xx");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("8", "82xx", "simulate 8268/8310"),
        arg_param_end};
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    // bool use_82xx = arg_get_lit(ctx, 1);    // not implemented yet
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HITAGS_SIMULATE, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLFHitagSList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "lf hitag hts", "hitags");
}

hitags_config_t hitags_config_unpack(const uint8_t *config_bytes) {
    hitags_config_t result = {
        .memory_type    = (config_bytes[0] >> 0) & 0x03,
        .authentication = (config_bytes[1] >> 7) & 0x01,
        .ttf_coding     = (config_bytes[1] >> 6) & 0x01,
        .ttf_data_rate  = (config_bytes[1] >> 4) & 0x03,
        .ttf_mode       = (config_bytes[1] >> 2) & 0x03,
        .lock_config    = (config_bytes[1] >> 1) & 0x01,
        .lock_key       = (config_bytes[1] >> 0) & 0x01
    };
    return result;
}

void hitags_config_print(hitags_config_t config) {
    PrintAndLogEx(INFO, " Memory type...... " _GREEN_("%s"),
    (const char *[]) {
        "Hitag S 32", "Hitag S 256", "Hitag S 2048",
        "Unknown Hitag S/8211"
    }[config.memory_type]);

    PrintAndLogEx(INFO, " Authenticaion.... %s", config.authentication ? _YELLOW_("Yes") : "No");

    PrintAndLogEx(INFO, " TTF coding....... %s",
    (const char *[]) {"Manchester", "Biphase"}[config.ttf_coding]);

    PrintAndLogEx(INFO, " TTF data rate.... %s",
    (const char *[]) {
        "4 kBit", "8 kBit", "2 kBit",
        "2 kBit and Pigeon Race Standard"
    }[config.ttf_data_rate]);

    PrintAndLogEx(INFO, " TTF mode......... %s",
    (const char *[]) {
        "TTF Mode disabled (= RTF Mode)", "Page 4, Page 5",
        "Page 4, Page 5, Page 6, Page 7", "Page 4"
    }[config.ttf_mode]);

    PrintAndLogEx(INFO, " Config locked.... %s", config.lock_config ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Key/PWD locked... %s", config.lock_key ? _RED_("Yes") : _GREEN_("No"));
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,           AlwaysAvailable, "This help"},
    {"list",        CmdLFHitagSList,   AlwaysAvailable, "List Hitag S trace history"},
    {"-----------", CmdHelp,           IfPm3Hitag,      "----------------------- " _CYAN_("General") " ------------------------"},
    {"reader",      CmdLFHitagSReader, IfPm3Hitag,      "Act like a Hitag S reader"},
    {"rdbl",        CmdLFHitagSRead,   IfPm3Hitag,      "Read Hitag S memory"},
    {"wrbl",        CmdLFHitagSWrite,  IfPm3Hitag,      "Write Hitag S page"},
    {"sim",         CmdLFHitagSSim,    IfPm3Hitag,      "Simulate Hitag transponder"},
    {NULL,          NULL,              0,               NULL}
};

static int CmdHelp(const char *Cmd) {
    (void) Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFHitagS(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}


