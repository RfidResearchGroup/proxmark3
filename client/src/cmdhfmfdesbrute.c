//-----------------------------------------------------------------------------
// Copyright (C) X41 D-Sec GmbH, Yasar Klawohn, Markus Vervier
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
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------
#include "cmdhfmfdesbrute.h"
#include <ctype.h>
#include <string.h>
#include "cmdparser.h"    // command_t
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"        // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "cmdhfmf.h"
#include "cmdhfmfu.h"
#include "iso7816/iso7816core.h"
#include "emv/emvcore.h"
#include "ui.h"
#include "crc16.h"
#include "util_posix.h"  // msclock
#include "aidsearch.h"
#include "cmdhf.h"       // handle HF plot
#include "cliparser.h"
#include "protocols.h"     // definitions of ISO14A/7816 protocol, MAGIC_GEN_1A
#include "iso7816/apduinfo.h"  // GetAPDUCodeDescription
#include "nfc/ndef.h"      // NDEFRecordsDecodeAndPrint
#include "cmdnfc.h"        // print_type4_cc_info
#include "fileutils.h"     // saveFile
#include "atrs.h"          // getATRinfo

static int CmdHelp(const char *Cmd);

// ## simulate iso14443a tag
int CmdHfMfDesBruteGetChallenge(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdesbrute get_challenge",
                  "Tools for attacking weakly generated keys", // TODO fix description
                  "hf mfdesbrute get_challenge -t <tag type> -u <uid>");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("t", "type", "<1-10> ", "Simulation type to use"),
        arg_str0("u", "uid", "<hex>", "7 byte UID"),
        //arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int tagtype = arg_get_int(ctx, 1);

    int uid_len = 0;
    uint8_t uid[10] = {0};
    CLIGetHexWithReturn(ctx, 2, uid, &uid_len);

    uint16_t flags = 0;
    bool useUIDfromEML = true;

    if (uid_len > 0) {
        if (uid_len == 7) {
            flags |= FLAG_7B_UID_IN_DATA;
        } else {
            PrintAndLogEx(ERR, "Please specify a 7 byte UID");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        PrintAndLogEx(SUCCESS, "Emulating a" _YELLOW_("DESFIRE EV1 tag")" with " _GREEN_("%d byte UID (%s)"), uid_len, sprint_hex(uid, uid_len));
        useUIDfromEML = false;
    }

    CLIParserFree(ctx);

    sector_t *k_sector = NULL;
    uint8_t k_sectorsCount = 40;

    if (useUIDfromEML) {
        flags |= FLAG_UID_IN_EMUL;
    }

    struct {
        uint8_t tagtype;
        uint16_t flags;
        uint8_t uid[10];
        uint8_t key[16];
    } PACKED payload;

    payload.tagtype = tagtype;
    payload.flags = flags;
    memcpy(payload.uid, uid, uid_len);
    memset(payload.key, 0, 16);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EV1_GET_LOCK_CHALLENGE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press pm3-button to abort simulation");
    bool keypress = kbd_enter_pressed();
    while (!keypress) {

        if (WaitForResponseTimeout(CMD_HF_MIFARE_EV1_GET_LOCK_CHALLENGE, &resp, 1500) == 0) continue;
        if (resp.status != PM3_SUCCESS) break;

        keypress = kbd_enter_pressed();
    }

    if (keypress) {
        if ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) {
            // inform device to break the sim loop since client has exited
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        }

        if (resp.status == PM3_EOPABORTED && ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK)) {
            showSectorTable(k_sector, k_sectorsCount);
        }
    }

    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

int CmdHfMfDesBruteOpenDoor(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mfdesbrute open_door",
                  "Tools for attacking weakly generated keys", // TODO fix description
                  "hf mfdesbrute open_door -t <tag type> -u <uid> -k <key>");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("t", "type", "<1-10> ", "Simulation type to use"),
        arg_str0("u", "uid", "<hex>", "7 byte UID"),
        arg_str0("k", "key", "<hex>", "16 byte key"),
        //arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int tagtype = arg_get_int(ctx, 1);

    int uid_len = 0;
    uint8_t uid[10] = {0};
    CLIGetHexWithReturn(ctx, 2, uid, &uid_len);

    uint16_t flags = 0;
    bool useUIDfromEML = true;

    if (uid_len > 0) {
        if (uid_len == 7) {
            flags |= FLAG_7B_UID_IN_DATA;
        } else {
            PrintAndLogEx(ERR, "Please specify a 7 byte UID");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        PrintAndLogEx(SUCCESS, "Emulating a" _YELLOW_("DESFIRE EV1 tag")" with " _GREEN_("%d byte UID (%s)"), uid_len, sprint_hex(uid, uid_len));
        useUIDfromEML = false;
    }

    int key_len = 0;
    uint8_t key[16] = {0};
    CLIGetHexWithReturn(ctx, 3, key, &key_len);

    if (key_len != 16) {
        PrintAndLogEx(ERR, "Please specify a key of length 16");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    sector_t *k_sector = NULL;
    uint8_t k_sectorsCount = 40;

    if (useUIDfromEML) {
        flags |= FLAG_UID_IN_EMUL;
    }

    struct {
        uint8_t tagtype;
        uint16_t flags;
        uint8_t uid[10];
        uint8_t key[16];
    } PACKED payload;

    payload.tagtype = tagtype;
    payload.flags = flags;
    memcpy(payload.uid, uid, uid_len);
    memcpy(payload.key, key, key_len);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EV1_OPEN_DOOR, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press pm3-button to abort simulation");
    bool keypress = kbd_enter_pressed();
    while (!keypress) {

        if (WaitForResponseTimeout(CMD_HF_MIFARE_EV1_OPEN_DOOR, &resp, 1500) == 0) continue;
        if (resp.status != PM3_SUCCESS) break;

        keypress = kbd_enter_pressed();
    }

    if (keypress) {
        if ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) {
            // inform device to break the sim loop since client has exited
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
        }

        if (resp.status == PM3_EOPABORTED && ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK)) {
            showSectorTable(k_sector, k_sectorsCount);
        }
    }

    PrintAndLogEx(INFO, "Done");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",           CmdHelp,                      AlwaysAvailable, "This help"},
    {"get_challenge",  CmdHfMfDesBruteGetChallenge,  IfPm3Iso14443a,  "Get a challenge from a lock"},
    {"open_door",      CmdHfMfDesBruteOpenDoor,      IfPm3Iso14443a,  "AES auth simulation for Telenot Complex systems"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHfMfDesBrute(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
