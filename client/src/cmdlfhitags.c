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

#include "cmdlfhitags.h"
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


static int CmdLFHitagSRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag s read",
                  "Read Hitag S memory.\n\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n",
                  "  lf hitag s read                         -> Hitag S, plain mode\n"
                  "  lf hitag s read --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag s read --crypto                -> Hitag S, crypto mode, def key\n"
                  "  lf hitag s read -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
    );

    void *argtable[] = {
            arg_param_begin,
            arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
            arg_lit0(NULL, "crypto", "crypto mode"),
            arg_str0("k", "key", "<hex>", "key, 4 or 6 hex bytes"),
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
    bool use_crypto = arg_get_lit(ctx, 2);

    uint8_t key[6];
    int key_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 3), key, sizeof(key), &key_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (key_len && key_len != HITAGS_CRYPTOKEY_SIZE) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected %d, got %d", HITAGS_CRYPTOKEY_SIZE, key_len);
        return PM3_EINVARG;
    }

    if (nrar_len && nrar_len != HITAGS_NRAR_SIZE) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected %d, got %d", HITAGS_NRAR_SIZE, nrar_len);
        return PM3_EINVARG;
    }

    if (!key_len && use_crypto) {
        memcpy(key, "ONMIKR", 6);
        key_len = 6;
    }

    // check coherence
    uint8_t auth_methods = (use_plain + use_nrar + use_crypto);
    if (auth_methods > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    } else if (auth_methods == 0) {
        use_plain = true;
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    int pm3cmd = CMD_LF_HITAGS_READ;

    if (use_nrar) {
        packet.cmd = RHTSF_CHALLENGE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));
    }

    if (use_crypto) {
        packet.cmd = RHTSF_KEY;
        memcpy(packet.key, key, sizeof(packet.key));
    }

    clearCommandBuffer();
    SendCommandNG(pm3cmd, (uint8_t *) &packet, sizeof(packet));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(pm3cmd, &resp, 2000) == false) {
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

    hitags_config_t config = hitags_config_unpack(data + HITAGS_PAGE_SIZE);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");

    hitags_config_print(config);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Data") " ----------------------------------");

    uint32_t size = (const int[]) {4, 32, 256, 0}[config.memory_type];

    print_hex_break(data, size, HITAGS_PAGE_SIZE);

    return PM3_SUCCESS;
}

static int CmdLFHitagSWrite(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hitag s write",
                  "Write a page in Hitag S memory.\n"
                  "  Crypto mode: \n"
                  "    - key format ISK high + ISK low\n"
                  "    - default key 4F4E4D494B52 (ONMIKR)\n",
                  "  lf hitag write -p 6 -d 01020304                         -> Hitag S, plain mode\n"
                  "  lf hitag write -p 6 -d 01020304 --nrar 0102030411223344 -> Hitag S, challenge mode\n"
                  "  lf hitag write -p 6 -d 01020304 --crypto                -> Hitag S, crypto mode, def key\n"
                  "  lf hitag write -p 6 -d 01020304 -k 4F4E4D494B52         -> Hitag S, crypto mode\n\n"
    );

    void *argtable[] = {
            arg_param_begin,
            arg_str0(NULL, "nrar", "<hex>", "nonce / answer writer, 8 hex bytes"),
            arg_lit0(NULL, "crypto", "crypto mode"),
            arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
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
    bool use_crypto = arg_get_lit(ctx, 2);

    uint8_t key[6];
    int key_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 3), key, sizeof(key), &key_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int page = arg_get_int_def(ctx, 4, 0);

    uint8_t data[4];
    int data_len = 0;

    res = CLIParamHexToBuf(arg_get_str(ctx, 5), data, sizeof(data), &data_len);
    if (res != 0) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (key_len && key_len != HITAGS_CRYPTOKEY_SIZE) {
        PrintAndLogEx(WARNING, "Wrong KEY len expected %d, got %d", HITAGS_CRYPTOKEY_SIZE, key_len);
        return PM3_EINVARG;
    }

    if (nrar_len && nrar_len != HITAGS_NRAR_SIZE) {
        PrintAndLogEx(WARNING, "Wrong NR/AR len expected %d, got %d", HITAGS_NRAR_SIZE, nrar_len);
        return PM3_EINVARG;
    }

    if (!key_len && use_crypto) {
        memcpy(key, "ONMIKR", 6);
        key_len = 6;
    }

    // check coherence
    uint8_t auth_methods = (use_plain + use_nrar + use_crypto);
    if (auth_methods > 1) {
        PrintAndLogEx(WARNING, "Specify only one authentication mode");
        return PM3_EINVARG;
    } else if (auth_methods == 0) {
        use_plain = true;
    }

    lf_hitag_data_t packet;
    memset(&packet, 0, sizeof(packet));

    packet.page = page;
    memcpy(packet.data, data, sizeof(data));

    if (use_nrar) {
        packet.cmd = WHTSF_CHALLENGE;
        memcpy(packet.NrAr, nrar, sizeof(packet.NrAr));
    }

    if (use_crypto) {
        packet.cmd = WHTSF_KEY;
        memcpy(packet.key, key, sizeof(packet.key));
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

static int CmdLFHitagSList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "lf hitag s", "hitags");
}

static command_t CommandTable[] = {
        {"help",        CmdHelp,          AlwaysAvailable, "This help"},
        {"list",        CmdLFHitagSList,  AlwaysAvailable, "List Hitag S trace history"},
        {"-----------", CmdHelp,          IfPm3Hitag,      "----------------------- " _CYAN_("General") " ------------------------"},
        {"read",        CmdLFHitagSRead,  IfPm3Hitag,      "Read Hitag S memory"},
        {"write",       CmdLFHitagSWrite, IfPm3Hitag,      "Write Hitag S page"},
        {NULL, NULL,                      0, NULL}
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
                  (const char *[]) {"Hitag S 32", "Hitag S 256", "Hitag S 2048"}[config.memory_type]);

    PrintAndLogEx(INFO, " Authenticaion.... %s", config.authentication ? _YELLOW_("Yes") : "No");

    PrintAndLogEx(INFO, " TTF coding....... %s",
                  (const char *[]) {"Manchester", "Biphase"}[config.ttf_coding]);

    PrintAndLogEx(INFO, " TTF data rate.... %s",
                  (const char *[]) {"4 kBit", "8 kBit", "2 kBit",
                                    "2 kBit and Pigeon Race Standard"}[config.ttf_data_rate]);

    PrintAndLogEx(INFO, " TTF mode......... %s",
                  (const char *[]) {"TTF Mode disabled (= RTF Mode)", "Page 4, Page 5",
                                    "Page 4, Page 5, Page 6, Page 7", "Page 4"}[config.ttf_mode]);

    PrintAndLogEx(INFO, " Config locked.... %s", config.lock_config ? _RED_("Yes") : _GREEN_("No"));
    PrintAndLogEx(INFO, " Key/PWD locked... %s", config.lock_key ? _RED_("Yes") : _GREEN_("No"));
}
