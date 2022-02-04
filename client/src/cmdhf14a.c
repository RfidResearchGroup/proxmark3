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
// High frequency ISO14443A commands
//-----------------------------------------------------------------------------
#include "cmdhf14a.h"
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

static bool APDUInFramingEnable = true;

static int CmdHelp(const char *Cmd);
static int waitCmd(bool i_select, uint32_t timeout, bool verbose);

static const manufactureName_t manufactureMapping[] = {
    // ID,  "Vendor Country"
    { 0x01, "Motorola UK" },
    { 0x02, "ST Microelectronics SA France" },
    { 0x03, "Hitachi, Ltd Japan" },
    { 0x04, "NXP Semiconductors Germany" },
    { 0x05, "Infineon Technologies AG Germany" },
    { 0x06, "Cylink USA" },
    { 0x07, "Texas Instrument France" },
    { 0x08, "Fujitsu Limited Japan" },
    { 0x09, "Matsushita Electronics Corporation, Semiconductor Company Japan" },
    { 0x0A, "NEC Japan" },
    { 0x0B, "Oki Electric Industry Co. Ltd Japan" },
    { 0x0C, "Toshiba Corp. Japan" },
    { 0x0D, "Mitsubishi Electric Corp. Japan" },
    { 0x0E, "Samsung Electronics Co. Ltd Korea" },
    { 0x0F, "Hynix / Hyundai, Korea" },
    { 0x10, "LG-Semiconductors Co. Ltd Korea" },
    { 0x11, "Emosyn-EM Microelectronics USA" },
    { 0x12, "INSIDE Technology France" },
    { 0x13, "ORGA Kartensysteme GmbH Germany" },
    { 0x14, "SHARP Corporation Japan" },
    { 0x15, "ATMEL France" },
    { 0x16, "EM Microelectronic-Marin SA Switzerland" },
    { 0x17, "KSW Microtec GmbH Germany" },
    { 0x18, "ZMD AG Germany" },
    { 0x19, "XICOR, Inc. USA" },
    { 0x1A, "Sony Corporation Japan" },
    { 0x1B, "Malaysia Microelectronic Solutions Sdn. Bhd Malaysia" },
    { 0x1C, "Emosyn USA" },
    { 0x1D, "Shanghai Fudan Microelectronics Co. Ltd. P.R. China" },
    { 0x1E, "Magellan Technology Pty Limited Australia" },
    { 0x1F, "Melexis NV BO Switzerland" },
    { 0x20, "Renesas Technology Corp. Japan" },
    { 0x21, "TAGSYS France" },
    { 0x22, "Transcore USA" },
    { 0x23, "Shanghai belling corp., ltd. China" },
    { 0x24, "Masktech Germany Gmbh Germany" },
    { 0x25, "Innovision Research and Technology Plc UK" },
    { 0x26, "Hitachi ULSI Systems Co., Ltd. Japan" },
    { 0x27, "Cypak AB Sweden" },
    { 0x28, "Ricoh Japan" },
    { 0x29, "ASK France" },
    { 0x2A, "Unicore Microsystems, LLC Russian Federation" },
    { 0x2B, "Dallas Semiconductor/Maxim USA" },
    { 0x2C, "Impinj, Inc. USA" },
    { 0x2D, "RightPlug Alliance USA" },
    { 0x2E, "Broadcom Corporation USA" },
    { 0x2F, "MStar Semiconductor, Inc Taiwan, ROC" },
    { 0x30, "BeeDar Technology Inc. USA" },
    { 0x31, "RFIDsec Denmark" },
    { 0x32, "Schweizer Electronic AG Germany" },
    { 0x33, "AMIC Technology Corp Taiwan" },
    { 0x34, "Mikron JSC Russia" },
    { 0x35, "Fraunhofer Institute for Photonic Microsystems Germany" },
    { 0x36, "IDS Microchip AG Switzerland" },
    { 0x37, "Thinfilm - Kovio USA" },
    { 0x38, "HMT Microelectronic Ltd Switzerland" },
    { 0x39, "Silicon Craft Technology Thailand" },
    { 0x3A, "Advanced Film Device Inc. Japan" },
    { 0x3B, "Nitecrest Ltd UK" },
    { 0x3C, "Verayo Inc. USA" },
    { 0x3D, "HID Global USA" },
    { 0x3E, "Productivity Engineering Gmbh Germany" },
    { 0x3F, "Austriamicrosystems AG (reserved) Austria" },
    { 0x40, "Gemalto SA France" },
    { 0x41, "Renesas Electronics Corporation Japan" },
    { 0x42, "3Alogics Inc Korea" },
    { 0x43, "Top TroniQ Asia Limited Hong Kong" },
    { 0x44, "Gentag Inc. USA" },
    { 0x45, "Invengo Information Technology Co.Ltd China" },
    { 0x46, "Guangzhou Sysur Microelectronics, Inc China" },
    { 0x47, "CEITEC S.A. Brazil" },
    { 0x48, "Shanghai Quanray Electronics Co. Ltd. China" },
    { 0x49, "MediaTek Inc Taiwan" },
    { 0x4A, "Angstrem PJSC Russia" },
    { 0x4B, "Celisic Semiconductor (Hong Kong) Limited China" },
    { 0x4C, "LEGIC Identsystems AG Switzerland" },
    { 0x4D, "Balluff GmbH Germany" },
    { 0x4E, "Oberthur Technologies France" },
    { 0x4F, "Silterra Malaysia Sdn. Bhd. Malaysia" },
    { 0x50, "DELTA Danish Electronics, Light & Acoustics Denmark" },
    { 0x51, "Giesecke & Devrient GmbH Germany" },
    { 0x52, "Shenzhen China Vision Microelectronics Co., Ltd. China" },
    { 0x53, "Shanghai Feiju Microelectronics Co. Ltd. China" },
    { 0x54, "Intel Corporation USA" },
    { 0x55, "Microsensys GmbH Germany" },
    { 0x56, "Sonix Technology Co., Ltd. Taiwan" },
    { 0x57, "Qualcomm Technologies Inc USA" },
    { 0x58, "Realtek Semiconductor Corp Taiwan" },
    { 0x59, "Freevision Technologies Co. Ltd China" },
    { 0x5A, "Giantec Semiconductor Inc. China" },
    { 0x5B, "JSC Angstrem-T Russia" },
    { 0x5C, "STARCHIP France" },
    { 0x5D, "SPIRTECH France" },
    { 0x5E, "GANTNER Electronic GmbH Austria" },
    { 0x5F, "Nordic Semiconductor Norway" },
    { 0x60, "Verisiti Inc USA" },
    { 0x61, "Wearlinks Technology Inc. China" },
    { 0x62, "Userstar Information Systems Co., Ltd Taiwan" },
    { 0x63, "Pragmatic Printing Ltd. UK" },
    { 0x64, "Associacao do Laboratorio de Sistemas Integraveis Tecnologico - LSI-TEC Brazil" },
    { 0x65, "Tendyron Corporation China" },
    { 0x66, "MUTO Smart Co., Ltd. Korea" },
    { 0x67, "ON Semiconductor USA" },
    { 0x68, "TUBITAK BILGEM Turkey" },
    { 0x69, "Huada Semiconductor Co., Ltd China" },
    { 0x6A, "SEVENEY France" },
    { 0x6B, "ISSM France" },
    { 0x6C, "Wisesec Ltd Israel" },
    { 0x7C, "DB HiTek Co Ltd Korea" },
    { 0x7D, "SATO Vicinity Australia" },
    { 0x7E, "Holtek Taiwan" },
    { 0x00, "no tag-info available" } // must be the last entry
};

// get a product description based on the UID
//  uid[8] tag uid
// returns description of the best match
const char *getTagInfo(uint8_t uid) {

    int i;

    for (i = 0; i < ARRAYLEN(manufactureMapping); ++i)
        if (uid == manufactureMapping[i].uid)
            return manufactureMapping[i].desc;

    //No match, return default
    return manufactureMapping[ARRAYLEN(manufactureMapping) - 1].desc;
}

static const hintAIDList_t hintAIDList[] = {
    // AID, AID len, name, hint - how to use
    { "\xA0\x00\x00\x06\x47\x2F\x00\x01", 8, "FIDO", "hf fido" },
    { "\xA0\x00\x00\x03\x08\x00\x00\x10\x00\x01\x00", 11, "PIV", "" },
    { "\xD2\x76\x00\x01\x24\x01", 8, "OpenPGP", "" },
    { "\x31\x50\x41\x59\x2E\x53\x59\x53\x2E\x44\x44\x46\x30\x31", 14, "EMV (pse)", "emv" },
    { "\x32\x50\x41\x59\x2E\x53\x59\x53\x2E\x44\x44\x46\x30\x31", 14, "EMV (ppse)", "emv" },
    { "\x41\x44\x20\x46\x31", 5, "CIPURSE", "hf cipurse" },
    { "\xd2\x76\x00\x00\x85\x01\x00", 7, "desfire", "hf mfdes" },
};

// iso14a apdu input frame length
static uint16_t gs_frame_len = 0;
static uint8_t gs_frames_num = 0;
static uint16_t atsFSC[] = {16, 24, 32, 40, 48, 64, 96, 128, 256};

static int CmdHF14AList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf 14a", "14a");
}

int hf14a_getconfig(hf14a_config *config) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    if (config == NULL)
        return PM3_EINVARG;

    clearCommandBuffer();

    SendCommandNG(CMD_HF_ISO14443A_GET_CONFIG, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_ISO14443A_GET_CONFIG, &resp, 2000)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    memcpy(config, resp.data.asBytes, sizeof(hf14a_config));
    return PM3_SUCCESS;
}

int hf14a_setconfig(hf14a_config *config, bool verbose) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    clearCommandBuffer();
    if (config != NULL) {
        SendCommandNG(CMD_HF_ISO14443A_SET_CONFIG, (uint8_t *)config, sizeof(hf14a_config));
        if (verbose) {
            SendCommandNG(CMD_HF_ISO14443A_PRINT_CONFIG, NULL, 0);
        }
    } else {
        SendCommandNG(CMD_HF_ISO14443A_PRINT_CONFIG, NULL, 0);
    }

    return PM3_SUCCESS;
}

static int hf_14a_config_example(void) {
    PrintAndLogEx(NORMAL, "\nExamples to revive Gen2/DirectWrite magic cards failing at anticollision:");
    PrintAndLogEx(NORMAL, _CYAN_("    MFC 1k 4b UID")":");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --atqa force --bcc ignore --cl2 skip --rats skip"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344440804006263646566676869"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --std"));
    PrintAndLogEx(NORMAL, _CYAN_("    MFC 4k 4b UID")":");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --atqa force --bcc ignore --cl2 skip --rats skip"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 11223344441802006263646566676869"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --std"));
    PrintAndLogEx(NORMAL, _CYAN_("    MFC 1k 7b UID")":");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip --rats skip"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 04112233445566084400626364656667"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --std"));
    PrintAndLogEx(NORMAL, _CYAN_("    MFC 4k 7b UID")":");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --atqa forcce --bcc ignore --cl2 force --cl3 skip --rats skip"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf mf wrbl --blk 0 -k FFFFFFFFFFFF -d 04112233445566184200626364656667"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --std"));
    PrintAndLogEx(NORMAL, _CYAN_("    MFUL ")"/" _CYAN_(" MFUL EV1 ")"/" _CYAN_(" MFULC")":");
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --atqa force --bcc ignore --cl2 force --cl3 skip -rats skip"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf mfu setuid --uid 04112233445566"));
    PrintAndLogEx(NORMAL, _YELLOW_("          hf 14a config --std"));
    return PM3_SUCCESS;
}
static int CmdHf14AConfig(const char *Cmd) {
    if (!g_session.pm3_present) return PM3_ENOTTY;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a config",
                  "Configure 14a settings (use with caution)",
                  "hf 14a config              -> Print current configuration\n"
                  "hf 14a config --std        -> Reset default configuration (follow standard)\n"
                  "hf 14a config --atqa std   -> Follow standard\n"
                  "hf 14a config --atqa force -> Force execution of anticollision\n"
                  "hf 14a config --atqa skip  -> Skip anticollision\n"
                  "hf 14a config --bcc std    -> Follow standard\n"
                  "hf 14a config --bcc fix    -> Fix bad BCC in anticollision\n"
                  "hf 14a config --bcc ignore -> Ignore bad BCC and use it as such\n"
                  "hf 14a config --cl2 std    -> Follow standard\n"
                  "hf 14a config --cl2 force  -> Execute CL2\n"
                  "hf 14a config --cl2 skip   -> Skip CL2\n"
                  "hf 14a config --cl3 std    -> Follow standard\n"
                  "hf 14a config --cl3 force  -> Execute CL3\n"
                  "hf 14a config --cl3 skip   -> Skip CL3\n"
                  "hf 14a config --rats std   -> Follow standard\n"
                  "hf 14a config --rats force -> Execute RATS\n"
                  "hf 14a config --rats skip  -> Skip RATS");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "atqa", "<std|force|skip>", "Configure ATQA<>anticollision behavior"),
        arg_str0(NULL, "bcc", "<std|fix|ignore>", "Configure BCC behavior"),
        arg_str0(NULL, "cl2", "<std|force|skip>", "Configure SAK<>CL2 behavior"),
        arg_str0(NULL, "cl3", "<std|force|skip>", "Configure SAK<>CL3 behavior"),
        arg_str0(NULL, "rats", "<std|force|skip>", "Configure RATS behavior"),
        arg_lit0(NULL, "std", "Reset default configuration: follow all standard"),
        arg_lit0("v", "verbose", "verbose output, also prints examples for reviving Gen2 cards"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool defaults = arg_get_lit(ctx, 6);
    int vlen = 0;
    char value[10];
    int atqa = defaults ? 0 : -1;
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)value, sizeof(value), &vlen);
    if (vlen > 0) {
        if (strcmp(value, "std") == 0) atqa = 0;
        else if (strcmp(value, "force") == 0) atqa = 1;
        else if (strcmp(value, "skip") == 0) atqa = 2;
        else {
            PrintAndLogEx(ERR, "atqa argument must be 'std', 'force', or 'skip'");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    int bcc = defaults ? 0 : -1;
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)value, sizeof(value), &vlen);
    if (vlen > 0) {
        if (strcmp(value, "std") == 0) bcc = 0;
        else if (strcmp(value, "fix") == 0) bcc = 1;
        else if (strcmp(value, "ignore") == 0) bcc = 2;
        else {
            PrintAndLogEx(ERR, "bcc argument must be 'std', 'fix', or 'ignore'");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    int cl2 = defaults ? 0 : -1;
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)value, sizeof(value), &vlen);
    if (vlen > 0) {
        if (strcmp(value, "std") == 0) cl2 = 0;
        else if (strcmp(value, "force") == 0) cl2 = 1;
        else if (strcmp(value, "skip") == 0) cl2 = 2;
        else {
            PrintAndLogEx(ERR, "cl2 argument must be 'std', 'force', or 'skip'");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    int cl3 = defaults ? 0 : -1;
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)value, sizeof(value), &vlen);
    if (vlen > 0) {
        if (strcmp(value, "std") == 0) cl3 = 0;
        else if (strcmp(value, "force") == 0) cl3 = 1;
        else if (strcmp(value, "skip") == 0) cl3 = 2;
        else {
            PrintAndLogEx(ERR, "cl3 argument must be 'std', 'force', or 'skip'");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }
    int rats = defaults ? 0 : -1;
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)value, sizeof(value), &vlen);
    if (vlen > 0) {
        if (strcmp(value, "std") == 0) rats = 0;
        else if (strcmp(value, "force") == 0) rats = 1;
        else if (strcmp(value, "skip") == 0) rats = 2;
        else {
            PrintAndLogEx(ERR, "rats argument must be 'std', 'force', or 'skip'");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    bool verbose = arg_get_lit(ctx, 7);

    CLIParserFree(ctx);

    // validations
    if (strlen(Cmd) == 0) {
        return hf14a_setconfig(NULL, verbose);
    }

    if (verbose) {
        hf_14a_config_example();
    }

    hf14a_config config = {
        .forceanticol = atqa,
        .forcebcc = bcc,
        .forcecl2 = cl2,
        .forcecl3 = cl3,
        .forcerats = rats
    };

    return hf14a_setconfig(&config, verbose);
}

int Hf14443_4aGetCardData(iso14a_card_select_t *card) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);

    PacketResponseNG resp;
    WaitForResponse(CMD_ACK, &resp);

    memcpy(card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision

    if (select_status == 0) {
        PrintAndLogEx(ERR, "E->iso14443a card select failed");
        return 1;
    }

    if (select_status == 2) {
        PrintAndLogEx(ERR, "E->Card doesn't support iso14443-4 mode");
        return 1;
    }

    if (select_status == 3) {
        PrintAndLogEx(INFO, "E->Card doesn't support standard iso14443-3 anticollision");
        PrintAndLogEx(SUCCESS, "\tATQA : %02x %02x", card->atqa[1], card->atqa[0]);
        return 1;
    }

    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card->uid, card->uidlen));
    PrintAndLogEx(SUCCESS, "ATQA: %02x %02x", card->atqa[1], card->atqa[0]);
    PrintAndLogEx(SUCCESS, " SAK: %02x [%" PRIu64 "]", card->sak, resp.oldarg[0]);
    if (card->ats_len < 3) { // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
        PrintAndLogEx(INFO, "E-> Error ATS length(%d) : %s", card->ats_len, sprint_hex(card->ats, card->ats_len));
        return 1;
    }

    if (card->ats_len == card->ats[0] + 2)
        PrintAndLogEx(SUCCESS, " ATS: [%d] %s", card->ats[0], sprint_hex(card->ats, card->ats[0]));
    else
        PrintAndLogEx(SUCCESS, " ATS: [%d] %s", card->ats_len, sprint_hex(card->ats, card->ats_len));
    return 0;
}

static int CmdHF14AReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a reader",
                  "Act as a ISO-14443a reader to identify tag. Look for ISO-14443a tags until Enter or the pm3 button is pressed",
                  "hf 14a reader\n"
                  "hf 14a reader -@     -> Continuous mode\n"
                  "hf 14a reader --ecp  -> trigger apple enhanced contactless polling\n"
                  "hf 14a reader --mag  -> trigger apple magsafe polling\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "keep the field active after command executed"),
        arg_lit0("s", "silent", "silent (no messages)"),
        arg_lit0(NULL, "drop", "just drop the signal field"),
        arg_lit0(NULL, "skip", "ISO14443-3 select only (skip RATS)"),
        arg_lit0(NULL, "ecp", "Use enhanced contactless polling"),
        arg_lit0(NULL, "mag", "Use Apple magsafe polling"),
        arg_lit0("@", NULL, "continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool disconnectAfter = true;
    if (arg_get_lit(ctx, 1)) {
        disconnectAfter = false;
    }

    bool silent = arg_get_lit(ctx, 2);

    uint32_t cm = ISO14A_CONNECT;
    if (arg_get_lit(ctx, 3)) {
        cm &= ~ISO14A_CONNECT;
    }

    if (arg_get_lit(ctx, 4)) {
        cm |= ISO14A_NO_RATS;
    }

    if (arg_get_lit(ctx, 5)) {
        cm |= ISO14A_USE_ECP;
    }

    if (arg_get_lit(ctx, 6)) {
        cm |= ISO14A_USE_MAGSAFE;
    }

    bool continuous = arg_get_lit(ctx, 7);

    CLIParserFree(ctx);

    int res = PM3_SUCCESS;

    if (!disconnectAfter)
        cm |= ISO14A_NO_DISCONNECT;
    if (continuous) {
        PrintAndLogEx(INFO, "Press " _GREEN_("Enter") " to exit");
    }
    do {
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443A_READER, cm, 0, 0, NULL, 0);

        if (ISO14A_CONNECT & cm) {
            PacketResponseNG resp;
            if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
                if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
                DropField();
                res = PM3_ESOFT;
                goto plot;
            }

            iso14a_card_select_t card;
            memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

            /*
                0: couldn't read
                1: OK, with ATS
                2: OK, no ATS
                3: proprietary Anticollision
            */
            uint64_t select_status = resp.oldarg[0];

            if (select_status == 0) {
                if (!silent) PrintAndLogEx(WARNING, "iso14443a card select failed");
                DropField();
                res = PM3_ESOFT;
                goto plot;
            }

            if (select_status == 3) {
                if (!(silent && continuous)) {
                    PrintAndLogEx(INFO, "Card doesn't support standard iso14443-3 anticollision");
                    PrintAndLogEx(SUCCESS, "ATQA: %02x %02x", card.atqa[1], card.atqa[0]);
                }
                DropField();
                res = PM3_ESOFT;
                goto plot;
            }
            PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
            if (!(silent && continuous)) {
                PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02x %02x"), card.atqa[1], card.atqa[0]);
                PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02x [%" PRIu64 "]"), card.sak, resp.oldarg[0]);

                if (card.ats_len >= 3) { // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
                    if (card.ats_len == card.ats[0] + 2)
                        PrintAndLogEx(SUCCESS, " ATS: "  _GREEN_("%s"), sprint_hex(card.ats, card.ats[0]));
                    else {
                        PrintAndLogEx(SUCCESS, " ATS: [%d] "  _GREEN_("%s"), card.ats_len, sprint_hex(card.ats, card.ats_len));
                    }
                }
            }
            if (!disconnectAfter) {
                if (!silent) PrintAndLogEx(SUCCESS, "Card is selected. You can now start sending commands");
            }
        }
plot:
        if (continuous) {
            res = handle_hf_plot();
            if (res != PM3_SUCCESS) {
                break;
            }
        }

        if (kbd_enter_pressed()) {
            break;
        }

    } while (continuous);

    if (disconnectAfter == false) {
        if (silent == false) {
            PrintAndLogEx(INFO, "field is on");
        }
    }

    if (continuous)
        return PM3_SUCCESS;
    else
        return res;
}

static int CmdHF14AInfo(const char *Cmd) {
    bool verbose = true;
    bool do_nack_test = false;
    bool do_aid_search = false;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a info",
                  "This command makes more extensive tests against a ISO14443a tag in order to collect information",
                  "hf 14a info -nsv -> shows full information about the card\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",   "adds some information to results"),
        arg_lit0("n",  "nacktest",   "test for nack bug"),
        arg_lit0("s",  "aidsearch", "checks if AIDs from aidlist.json is present on the card and prints information about found AIDs"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    verbose = arg_get_lit(ctx, 1);
    do_nack_test = arg_get_lit(ctx, 2);
    do_aid_search = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    infoHF14A(verbose, do_nack_test, do_aid_search);
    return PM3_SUCCESS;
}

// Collect ISO14443 Type A UIDs
static int CmdHF14ACUIDs(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a cuids",
                  "Collect n>0 ISO14443-a UIDs in one go",
                  "hf 14a cuids -n 5   --> Collect 5 UIDs");

    void *argtable[] = {
        arg_param_begin,
        arg_int0("n", "num", "<dec>", "Number of UIDs to collect"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    // requested number of UIDs
    // collect at least 1 (e.g. if no parameter was given)
    int n = arg_get_int_def(ctx, 1, 1);

    CLIParserFree(ctx);

    uint64_t t1 =  msclock();
    PrintAndLogEx(SUCCESS, "collecting %d UIDs", n);

    // repeat n times
    for (int i = 0; i < n; i++) {

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard!\n");
            break;
        }

        // execute anticollision procedure
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);

        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);

        iso14a_card_select_t *card = (iso14a_card_select_t *) resp.data.asBytes;

        // check if command failed
        if (resp.oldarg[0] == 0) {
            PrintAndLogEx(WARNING, "card select failed.");
        } else {
            char uid_string[20];
            for (uint16_t m = 0; m < card->uidlen; m++) {
                sprintf(&uid_string[2 * m], "%02X", card->uid[m]);
            }
            PrintAndLogEx(SUCCESS, "%s", uid_string);
        }
    }
    PrintAndLogEx(SUCCESS, "end: %" PRIu64 " seconds", (msclock() - t1) / 1000);
    return 1;
}

// ## simulate iso14443a tag
int CmdHF14ASim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a sim",
                  "Simulate ISO/IEC 14443 type A tag with 4,7 or 10 byte UID",
                  "hf 14a sim -t 1 --uid 11223344      -> MIFARE Classic 1k\n"
                  "hf 14a sim -t 2                     -> MIFARE Ultralight\n"
                  "hf 14a sim -t 3                     -> MIFARE Desfire\n"
                  "hf 14a sim -t 4                     -> ISO/IEC 14443-4\n"
                  "hf 14a sim -t 5                     -> MIFARE Tnp3xxx\n"
                  "hf 14a sim -t 6                     -> MIFARE Mini\n"
                  "hf 14a sim -t 7                     -> AMIIBO (NTAG 215),  pack 0x8080\n"
                  "hf 14a sim -t 8                     -> MIFARE Classic 4k\n"
                  "hf 14a sim -t 9                     -> FM11RF005SH Shanghai Metro\n"
                  "hf 14a sim -t 10                    -> ST25TA IKEA Rothult\n");

    void *argtable[] = {
        arg_param_begin,
        arg_int1("t", "type", "<1-10> ", "Simulation type to use"),
        arg_str0("u", "uid", "<hex>", "4, 7 or 10 byte UID"),
        arg_int0("n", "num", "<dec>", "Exit simulation after <numreads> blocks have been read by reader. 0 = infinite"),
        arg_lit0("x",  NULL, "Performs the 'reader attack', nr/ar attack against a reader"),
        arg_lit0(NULL, "sk", "Fill simulator keys from found keys"),
        arg_lit0("v", "verbose", "verbose output"),
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
        switch (uid_len) {
            case 10:
                flags |= FLAG_10B_UID_IN_DATA;
                break;
            case 7:
                flags |= FLAG_7B_UID_IN_DATA;
                break;
            case 4:
                flags |= FLAG_4B_UID_IN_DATA;
                break;
            default:
                PrintAndLogEx(ERR, "Please specify a 4, 7, or 10 byte UID");
                CLIParserFree(ctx);
                return PM3_EINVARG;
        }
        PrintAndLogEx(SUCCESS, "Emulating " _YELLOW_("ISO/IEC 14443 type A tag")" with " _GREEN_("%d byte UID (%s)"), uid_len, sprint_hex(uid, uid_len));
        useUIDfromEML = false;
    }

    uint8_t exitAfterNReads = arg_get_int(ctx, 3);

    if (arg_get_lit(ctx, 4)) {
        flags |= FLAG_NR_AR_ATTACK;
    }

    bool setEmulatorMem = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);

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
        uint8_t exitAfter;
    } PACKED payload;

    payload.tagtype = tagtype;
    payload.flags = flags;
    payload.exitAfter = exitAfterNReads;
    memcpy(payload.uid, uid, uid_len);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_SIMULATE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;

    PrintAndLogEx(INFO, "Press pm3-button to abort simulation");
    bool keypress = kbd_enter_pressed();
    while (!keypress) {

        if (WaitForResponseTimeout(CMD_HF_MIFARE_SIMULATE, &resp, 1500) == 0) continue;
        if (resp.status != PM3_SUCCESS) break;

        if ((flags & FLAG_NR_AR_ATTACK) != FLAG_NR_AR_ATTACK) break;

        nonces_t *data = (nonces_t *)resp.data.asBytes;
        readerAttack(k_sector, k_sectorsCount, data[0], setEmulatorMem, verbose);

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

int CmdHF14ASniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a sniff",
                  "Collect data from the field and save into command buffer.\n"
                  "Buffer accessible from command 'hf 14a list'",
                  " hf 14a sniff -c -r");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("c", "card", "triggered by first data from card"),
        arg_lit0("r", "reader", "triggered by first 7-bit request from reader (REQ,WUP,...)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t param = 0;

    if (arg_get_lit(ctx, 1)) {
        param |= 0x01;
    }

    if (arg_get_lit(ctx, 2)) {
        param |= 0x02;
    }

    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_SNIFF, (uint8_t *)&param, sizeof(uint8_t));
    return PM3_SUCCESS;
}

int ExchangeRAW14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, bool silentMode) {
    
    uint16_t cmdc = 0;
    *dataoutlen = 0;

    if (activateField) {
        // select with no disconnect and set gs_frame_len
        int selres = SelectCard14443A_4(false, !silentMode, NULL);
        gs_frames_num = 0;
        if (selres != PM3_SUCCESS)
            return selres;
    }

    if (leaveSignalON)
        cmdc |= ISO14A_NO_DISCONNECT;

    uint8_t data[PM3_CMD_DATA_SIZE] = { 0x0a | gs_frames_num, 0x00};
    gs_frames_num ^= 1;
    memcpy(&data[2], datain, datainlen & 0xFFFF);
    SendCommandOLD(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | cmdc, (datainlen & 0xFFFF) + 2, 0, data, (datainlen & 0xFFFF) + 2);

    uint8_t *recv;
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        recv = resp.data.asBytes;
        int iLen = resp.oldarg[0];

        if (!iLen) {
            if (!silentMode) PrintAndLogEx(ERR, "No card response.");
            return 1;
        }

        *dataoutlen = iLen - 2;
        if (*dataoutlen < 0)
            *dataoutlen = 0;

        if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
            if (!silentMode) PrintAndLogEx(ERR, "Buffer too small(%d). Needs %d bytes", *dataoutlen, maxdataoutlen);
            return 2;
        }

        if (recv[0] != data[0]) {
            if (!silentMode) PrintAndLogEx(ERR, "iso14443-4 framing error. Card send %2x must be %2x", recv[0], data[0]);
            return 2;
        }

        memcpy(dataout, &recv[2], *dataoutlen);

        // CRC Check
        if (iLen == -1) {
            if (!silentMode) PrintAndLogEx(ERR, "ISO 14443A CRC error.");
            return 3;
        }

    } else {
        if (!silentMode) PrintAndLogEx(ERR, "Reply timeout.");
        return 4;
    }

    return 0;
}

int SelectCard14443A_4(bool disconnect, bool verbose, iso14a_card_select_t *card) {

    // global vars should be prefixed with g_
    gs_frame_len = 0;
    gs_frames_num = 0;

    if (card) {
        memset(card, 0, sizeof(iso14a_card_select_t));
    }

    DropField();

    // Anticollision + SELECT card
    PacketResponseNG resp;
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    // check result
    if (resp.oldarg[0] == 0) {
        if (verbose) {
            PrintAndLogEx(FAILED, "No card in field");
        }
        return PM3_ECARDEXCHANGE;
    }

    if (resp.oldarg[0] != 1 && resp.oldarg[0] != 2) {
        PrintAndLogEx(WARNING, "Card not in iso14443-4, res=%" PRId64 ".", resp.oldarg[0]);
        return PM3_ECARDEXCHANGE;
    }

    if (resp.oldarg[0] == 2) { // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision
        // get ATS
        uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, sizeof(rats), 0, rats, sizeof(rats));
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
            PrintAndLogEx(WARNING, "Command execute timeout");
            return PM3_ETIMEOUT;
        }

        if (resp.oldarg[0] == 0) { // ats_len
            if (verbose) {
                PrintAndLogEx(FAILED, "Can't get ATS");
            }
            return PM3_ECARDEXCHANGE;
        }

        // get frame length from ATS in data field
        if (resp.oldarg[0] > 1) {
            uint8_t fsci = resp.data.asBytes[1] & 0x0f;
            if (fsci < ARRAYLEN(atsFSC)) {
                gs_frame_len = atsFSC[fsci];
            }
        }
    } else {
        // get frame length from ATS in card data structure
        iso14a_card_select_t *vcard = (iso14a_card_select_t *) resp.data.asBytes;
        if (vcard->ats_len > 1) {
            uint8_t fsci = vcard->ats[1] & 0x0f;
            if (fsci < ARRAYLEN(atsFSC)) {
                gs_frame_len = atsFSC[fsci];
            }
        }

        if (card) {
            memcpy(card, vcard, sizeof(iso14a_card_select_t));
        }
    }

    SetISODEPState(ISODEP_NFCA);

    if (disconnect) {
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdExchangeAPDU(bool chainingin, uint8_t *datain, int datainlen, bool activateField, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, bool *chainingout) {
    *chainingout = false;

    if (activateField) {
        // select with no disconnect and set gs_frame_len
        int selres = SelectCard14443A_4(false, true, NULL);
        if (selres != PM3_SUCCESS)
            return selres;
    }

    uint16_t cmdc = 0;
    if (chainingin)
        cmdc = ISO14A_SEND_CHAINING;

    // "Command APDU" length should be 5+255+1, but javacard's APDU buffer might be smaller - 133 bytes
    // https://stackoverflow.com/questions/32994936/safe-max-java-card-apdu-data-command-and-respond-size
    // here length PM3_CMD_DATA_SIZE=512
    // timeout must be authomatically set by "get ATS"
    if (datain)
        SendCommandOLD(CMD_HF_ISO14443A_READER, ISO14A_APDU | ISO14A_NO_DISCONNECT | cmdc, (datainlen & 0x1FF), 0, datain, datainlen & 0x1FF);
    else
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_APDU | ISO14A_NO_DISCONNECT | cmdc, 0, 0, NULL, 0);

    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        uint8_t *recv = resp.data.asBytes;
        int iLen = resp.oldarg[0];
        uint8_t res = resp.oldarg[1];

        int dlen = iLen - 2;
        if (dlen < 0)
            dlen = 0;
        *dataoutlen += dlen;

        if (maxdataoutlen && *dataoutlen > maxdataoutlen) {
            PrintAndLogEx(ERR, "APDU: Buffer too small(%d), needs %d bytes", *dataoutlen, maxdataoutlen);
            return PM3_EAPDU_FAIL;
        }

        // I-block ACK
        if ((res & 0xF2) == 0xA2) {
            *dataoutlen = 0;
            *chainingout = true;
            return PM3_SUCCESS;
        }

        if (!iLen) {
            PrintAndLogEx(ERR, "APDU: No APDU response");
            return PM3_EAPDU_FAIL;
        }

        // check apdu length
        if (iLen < 2 && iLen >= 0) {
            PrintAndLogEx(ERR, "APDU: Small APDU response, len %d", iLen);
            return PM3_EAPDU_FAIL;
        }

        // check block TODO
        if (iLen == -2) {
            PrintAndLogEx(ERR, "APDU: Block type mismatch");
            return PM3_EAPDU_FAIL;
        }

        memcpy(dataout, recv, dlen);

        // chaining
        if ((res & 0x10) != 0) {
            *chainingout = true;
        }

        // CRC Check
        if (iLen == -1) {
            PrintAndLogEx(ERR, "APDU: ISO 14443A CRC error");
            return PM3_EAPDU_FAIL;
        }
    } else {
        PrintAndLogEx(ERR, "APDU: Reply timeout");
        return PM3_EAPDU_FAIL;
    }

    return PM3_SUCCESS;
}

int ExchangeAPDU14a(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    *dataoutlen = 0;
    bool chaining = false;
    int res;

    // 3 byte here - 1b framing header, 2b crc16
    if (APDUInFramingEnable &&
            ((gs_frame_len && (datainlen > gs_frame_len - 3)) || (datainlen > PM3_CMD_DATA_SIZE - 3))) {

        int clen = 0;

        bool vActivateField = activateField;

        do {
            int vlen = MIN(gs_frame_len - 3, datainlen - clen);
            bool chainBlockNotLast = ((clen + vlen) < datainlen);

            *dataoutlen = 0;
            res = CmdExchangeAPDU(chainBlockNotLast, &datain[clen], vlen, vActivateField, dataout, maxdataoutlen, dataoutlen, &chaining);
            if (res != PM3_SUCCESS) {
                if (leaveSignalON == false)
                    DropField();

                return 200;
            }

            // check R-block ACK
//TODO check this one...
            if ((*dataoutlen == 0) && (chaining != chainBlockNotLast)) {
                if (leaveSignalON == false)
                    DropField();

                return 201;
            }

            clen += vlen;
            vActivateField = false;
            if (*dataoutlen) {
                if (clen != datainlen) {
                    PrintAndLogEx(ERR, "APDU: I-block/R-block sequence error. Data len=%d, Sent=%d, Last packet len=%d", datainlen, clen, *dataoutlen);
                }
                break;
            }
        } while (clen < datainlen);

    } else {
        res = CmdExchangeAPDU(false, datain, datainlen, activateField, dataout, maxdataoutlen, dataoutlen, &chaining);
        if (res != PM3_SUCCESS) {
            if (leaveSignalON == false) {
                DropField();
            }
            return res;
        }
    }

    while (chaining) {
        // I-block with chaining
        res = CmdExchangeAPDU(false, NULL, 0, false, &dataout[*dataoutlen], maxdataoutlen, dataoutlen, &chaining);
        if (res != PM3_SUCCESS) {
            if (leaveSignalON == false) {
                DropField();
            }
            return 100;
        }
    }

    if (leaveSignalON == false) {
        DropField();
    }

    return PM3_SUCCESS;
}

// ISO14443-4. 7. Half-duplex block transmission protocol
static int CmdHF14AAPDU(const char *Cmd) {
    uint8_t data[PM3_CMD_DATA_SIZE];
    int datalen = 0;
    uint8_t header[PM3_CMD_DATA_SIZE];
    int headerlen = 0;
    bool activateField = false;
    bool leaveSignalON = false;
    bool decodeTLV = false;
    bool decodeAPDU = false;
    bool makeAPDU = false;
    bool extendedAPDU = false;
    int le = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a apdu",
                  "Sends an ISO 7816-4 APDU via ISO 14443-4 block transmission protocol (T=CL). works with all apdu types from ISO 7816-4:2013",
                  "hf 14a apdu -st 00A404000E325041592E5359532E444446303100\n"
                  "hf 14a apdu -sd 00A404000E325041592E5359532E444446303100        -> decode apdu\n"
                  "hf 14a apdu -sm 00A40400 325041592E5359532E4444463031 -l 256    -> encode standard apdu\n"
                  "hf 14a apdu -sm 00A40400 325041592E5359532E4444463031 -el 65536 -> encode extended apdu\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("s",  "select",   "activate field and select card"),
        arg_lit0("k",  "keep",     "keep signal field ON after receive"),
        arg_lit0("t",  "tlv",      "executes TLV decoder if it possible"),
        arg_lit0("d",  "decapdu",  "decode apdu request if it possible"),
        arg_str0("m",  "make",     "<head (CLA INS P1 P2) hex>", "make apdu with head from this field and data from data field. Must be 4 bytes length: <CLA INS P1 P2>"),
        arg_lit0("e",  "extended", "make extended length apdu if `m` parameter included"),
        arg_int0("l",  "le",       "<Le (int)>", "Le apdu parameter if `m` parameter included"),
        arg_strx1(NULL, NULL,       "<APDU (hex) | data (hex)>", "data if `m` parameter included"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    activateField = arg_get_lit(ctx, 1);
    leaveSignalON = arg_get_lit(ctx, 2);
    decodeTLV = arg_get_lit(ctx, 3);
    decodeAPDU = arg_get_lit(ctx, 4);

    CLIGetHexWithReturn(ctx, 5, header, &headerlen);
    makeAPDU = headerlen > 0;
    if (makeAPDU && headerlen != 4) {
        PrintAndLogEx(ERR, "header length must be 4 bytes instead of %d", headerlen);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    extendedAPDU = arg_get_lit(ctx, 6);
    le = arg_get_int_def(ctx, 7, 0);

    if (makeAPDU) {
        uint8_t apdudata[PM3_CMD_DATA_SIZE] = {0};
        int apdudatalen = 0;

        CLIGetHexBLessWithReturn(ctx, 8, apdudata, &apdudatalen, 1 + 2);

        APDU_t apdu;
        apdu.cla = header[0];
        apdu.ins = header[1];
        apdu.p1 = header[2];
        apdu.p2 = header[3];

        apdu.lc = apdudatalen;
        apdu.data = apdudata;

        apdu.extended_apdu = extendedAPDU;
        apdu.le = le;

        if (APDUEncode(&apdu, data, &datalen)) {
            PrintAndLogEx(ERR, "can't make apdu with provided parameters.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

    } else {
        if (extendedAPDU) {
            PrintAndLogEx(ERR, "make mode not set but here `e` option.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
        if (le > 0) {
            PrintAndLogEx(ERR, "make mode not set but here `l` option.");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }

        // len = data + PCB(1b) + CRC(2b)
        CLIGetHexBLessWithReturn(ctx, 8, data, &datalen, 1 + 2);
    }
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "( " _YELLOW_("%s%s%s")" )",
                  activateField ? "select" : "",
                  leaveSignalON ? ", keep" : "",
                  decodeTLV ? ", TLV" : ""
                 );
    PrintAndLogEx(SUCCESS, ">>> %s", sprint_hex_inrow(data, datalen));

    if (decodeAPDU) {
        APDU_t apdu;

        if (APDUDecode(data, datalen, &apdu) == 0)
            APDUPrint(apdu);
        else
            PrintAndLogEx(WARNING, "can't decode APDU.");
    }

    int res = ExchangeAPDU14a(data, datalen, activateField, leaveSignalON, data, PM3_CMD_DATA_SIZE, &datalen);
    if (res != PM3_SUCCESS)
        return res;

    PrintAndLogEx(SUCCESS, "<<< %s | %s", sprint_hex_inrow(data, datalen), sprint_ascii(data, datalen));
    PrintAndLogEx(SUCCESS, "<<< status: %02x %02x - %s", data[datalen - 2], data[datalen - 1], GetAPDUCodeDescription(data[datalen - 2], data[datalen - 1]));

    // TLV decoder
    if (decodeTLV && datalen > 4) {
        TLVPrintFromBuffer(data, datalen - 2);
    }

    return PM3_SUCCESS;
}

static int CmdHF14ACmdRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a raw",
                  "Sends raw bytes over ISO14443a. With option to use TOPAZ 14a mode.",
                  "hf 14a raw -sc 3000     -> select, crc, where 3000 == 'read block 00'\n"
                  "hf 14a raw -ak -b 7 40  -> send 7 bit byte 0x40\n"
                  "hf 14a raw --ecp -s     -> send ECP before select"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a",  NULL, "active signal field ON without select"),
        arg_int0("b",  NULL, "<dec>", "number of bits to send. Useful for send partial byte"),
        arg_lit0("c",  NULL, "calculate and append CRC"),
        arg_lit0("k",  NULL, "keep signal field ON after receive"),
        arg_lit0("3",  NULL, "ISO14443-3 select only (skip RATS)"),
        arg_lit0("r",  NULL, "do not read response"),
        arg_lit0("s",  NULL, "active signal field ON with select"),
        arg_int0("t",  "timeout", "<ms>", "timeout in milliseconds"),
        arg_lit0("v",  "verbose", "Verbose output"),
        arg_lit0(NULL, "topaz", "use Topaz protocol to send command"),
        arg_lit0(NULL, "ecp", "use enhanced contactless polling"),
        arg_lit0(NULL, "mag", "use Apple magsafe polling"),
        arg_strx1(NULL, NULL, "<hex>", "raw bytes to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool active = arg_get_lit(ctx, 1);
    uint16_t numbits = (uint16_t)arg_get_int_def(ctx, 2, 0);
    bool crc = arg_get_lit(ctx, 3);
    bool keep_field_on = arg_get_lit(ctx, 4);
    bool no_rats =  arg_get_lit(ctx, 5);
    bool reply = (arg_get_lit(ctx, 6) == false);
    bool active_select = arg_get_lit(ctx, 7);
    uint32_t timeout = (uint32_t)arg_get_int_def(ctx, 8, 0);
    bool verbose = arg_get_lit(ctx, 9);
    bool topazmode = arg_get_lit(ctx, 10);
    bool use_ecp = arg_get_lit(ctx, 11);
    bool use_magsafe = arg_get_lit(ctx, 12);

    int datalen = 0;
    uint8_t data[PM3_CMD_DATA_SIZE];
    CLIGetHexWithReturn(ctx, 13, data, &datalen);
    CLIParserFree(ctx);

    bool bTimeout = (timeout) ? true : false;

    // ensure we can add 2byte crc to input data
    if (datalen >= sizeof(data) + 2) {
        if (crc) {
            PrintAndLogEx(FAILED, "Buffer is full, we can't add CRC to your data");
            return PM3_EINVARG;
        }
    }

    if (crc && datalen > 0 && datalen < sizeof(data) - 2) {
        uint8_t first, second;
        if (topazmode) {
            compute_crc(CRC_14443_B, data, datalen, &first, &second);
        } else {
            compute_crc(CRC_14443_A, data, datalen, &first, &second);
        }
        data[datalen++] = first;
        data[datalen++] = second;
    }

    uint16_t flags = 0;
    if (active || active_select) {
        flags |= ISO14A_CONNECT;
        if (active)
            flags |= ISO14A_NO_SELECT;
    }

    uint32_t argtimeout = 0;
    if (bTimeout) {
#define MAX_TIMEOUT 40542464 // = (2^32-1) * (8*16) / 13560000Hz * 1000ms/s
        flags |= ISO14A_SET_TIMEOUT;
        if (timeout > MAX_TIMEOUT) {
            timeout = MAX_TIMEOUT;
            PrintAndLogEx(INFO, "Set timeout to 40542 seconds (11.26 hours). The max we can wait for response");
        }
        argtimeout = 13560000 / 1000 / (8 * 16) * timeout; // timeout in ETUs (time to transfer 1 bit, approx. 9.4 us)
    }

    if (keep_field_on) {
        flags |= ISO14A_NO_DISCONNECT;
    }

    if (datalen > 0) {
        flags |= ISO14A_RAW;
    }

    if (topazmode) {
        flags |= ISO14A_TOPAZMODE;
    }

    if (no_rats) {
        flags |= ISO14A_NO_RATS;
    }

    if (use_ecp) {
        flags |= ISO14A_USE_ECP;
    }

    if (use_magsafe) {
        flags |= ISO14A_USE_MAGSAFE;
    }

    // Max buffer is PM3_CMD_DATA_SIZE
    datalen = (datalen > PM3_CMD_DATA_SIZE) ? PM3_CMD_DATA_SIZE : datalen;

    clearCommandBuffer();
    SendCommandOLD(CMD_HF_ISO14443A_READER, flags, (datalen & 0xFFFF) | ((uint32_t)(numbits << 16)), argtimeout, data, datalen & 0xFFFF);

    if (reply) {
        int res = 0;
        if (active_select)
            res = waitCmd(true, timeout, verbose);
        if (res == PM3_SUCCESS && datalen > 0)
            waitCmd(false, timeout, verbose);
    }
    return PM3_SUCCESS;
}

static int waitCmd(bool i_select, uint32_t timeout, bool verbose) {
    PacketResponseNG resp;

    if (WaitForResponseTimeout(CMD_ACK, &resp, timeout + 1500)) {
        uint16_t len = (resp.oldarg[0] & 0xFFFF);
        if (i_select) {
            len = (resp.oldarg[1] & 0xFFFF);
            if (len) {
                if (verbose) {
                    PrintAndLogEx(SUCCESS, "Card selected. UID[%u]:", len);
                } else {
                    return PM3_SUCCESS;
                }

            } else {
                PrintAndLogEx(WARNING, "Can't select card.");
            }
        } else {
            if (verbose) {
                PrintAndLogEx(SUCCESS, "received " _YELLOW_("%u") " bytes", len);
            }
        }

        if (len == 0) {
            return PM3_ESOFT;
        }

        uint8_t *data = resp.data.asBytes;

        if (i_select == false && len >= 3) {
            bool crc = check_crc(CRC_14443_A, data, len);

            char s[16];
            sprintf(s,
                    (crc) ? _GREEN_("%02X %02X") : _RED_("%02X %02X"),
                    data[len - 2],
                    data[len - 1]
                   );

            PrintAndLogEx(SUCCESS, "%s[ %s ]",  sprint_hex(data, len - 2), s);
        } else {
            PrintAndLogEx(SUCCESS, "%s", sprint_hex(data, len));
        }

    } else {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

static int CmdHF14AAntiFuzz(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a antifuzz",
                  "Tries to fuzz the ISO14443a anticollision phase",
                  "hf 14a antifuzz -4\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("4",   NULL,  "4 byte uid"),
        arg_lit0("7",   NULL,  "7 byte uid"),
        arg_lit0(NULL,  "10",  "10 byte uid"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    struct {
        uint8_t flag;
    } PACKED param;
    param.flag = FLAG_4B_UID_IN_DATA;

    if (arg_get_lit(ctx, 2))
        param.flag = FLAG_7B_UID_IN_DATA;
    if (arg_get_lit(ctx, 3))
        param.flag = FLAG_10B_UID_IN_DATA;

    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_ANTIFUZZ, (uint8_t *)&param, sizeof(param));
    return PM3_SUCCESS;
}

static int CmdHF14AChaining(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a chaining",
                  "Enable/Disable ISO14443a input chaining. Maximum input length goes from ATS.",
                  "hf 14a chaining disable -> disable chaining\n"
                  "hf 14a chaining         -> show chaining enable/disable state\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, NULL,      "<enable/disable or 0/1>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct arg_str *str = arg_get_str(ctx, 1);
    int len = arg_get_str_len(ctx, 1);

    if (len && (!strcmp(str->sval[0], "enable") || !strcmp(str->sval[0], "1")))
        APDUInFramingEnable = true;

    if (len && (!strcmp(str->sval[0], "disable") || !strcmp(str->sval[0], "0")))
        APDUInFramingEnable = false;

    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "\nISO 14443-4 input chaining %s.\n", APDUInFramingEnable ? "enabled" : "disabled");

    return PM3_SUCCESS;
}

static void printTag(const char *tag) {
    PrintAndLogEx(SUCCESS, "   " _YELLOW_("%s"), tag);
}

typedef enum {
    MTNONE = 0,
    MTCLASSIC = 1,
    MTMINI = 2,
    MTDESFIRE = 4,
    MTPLUS = 8,
    MTULTRALIGHT = 16,
    HID_SEOS = 32,
    MTOTHER = 64
} nxp_mifare_type_t;

// Based on NXP AN10833 Rev 3.6 and NXP AN10834 Rev 4.1
static int detect_nxp_card(uint8_t sak, uint16_t atqa, uint64_t select_status) {
    int type = MTNONE;

    PrintAndLogEx(SUCCESS, "Possible types:");

    if ((sak & 0x02) != 0x02) {
        if ((sak & 0x19) == 0x19) {
            printTag("MIFARE Classic 2K");
            type |= MTCLASSIC;
        } else if ((sak & 0x38) == 0x38) {
            printTag("SmartMX with MIFARE Classic 4K");
            type |= MTCLASSIC;
        } else if ((sak & 0x18) == 0x18) {
            if (select_status == 1) {
                if ((atqa & 0x0040) == 0x0040) {
                    printTag("MIFARE Plus EV1 4K CL2 in SL1");
                    printTag("MIFARE Plus S 4K CL2 in SL1");
                    printTag("MIFARE Plus X 4K CL2 in SL1");
                } else {
                    printTag("MIFARE Plus EV1 4K in SL1");
                    printTag("MIFARE Plus S 4K in SL1");
                    printTag("MIFARE Plus X 4K in SL1");
                }

                type |= MTPLUS;
            } else {
                if ((atqa & 0x0040) == 0x0040) {
                    printTag("MIFARE Classic 4K CL2");
                } else {
                    printTag("MIFARE Classic 4K");
                }

                type |= MTCLASSIC;
            }
        } else if ((sak & 0x09) == 0x09) {
            if ((atqa & 0x0040) == 0x0040) {
                printTag("MIFARE Mini 0.3K CL2");
            } else {
                printTag("MIFARE Mini 0.3K");
            }

            type |= MTMINI;
        } else if ((sak & 0x28) == 0x28) {
            printTag("SmartMX with MIFARE Classic 1K");
            type |= MTCLASSIC;
        } else if ((sak & 0x08) == 0x08) {
            if (select_status == 1) {
                if ((atqa & 0x0040) == 0x0040) {
                    printTag("MIFARE Plus EV1 2K CL2 in SL1");
                    printTag("MIFARE Plus S 2K CL2 in SL1");
                    printTag("MIFARE Plus X 2K CL2 in SL1");
                    printTag("MIFARE Plus SE 1K CL2");
                } else {
                    printTag("MIFARE Plus EV1 2K in SL1");
                    printTag("MIFARE Plus S 2K in SL1");
                    printTag("MIFARE Plus X 2K in SL1");
                    printTag("MIFARE Plus SE 1K");
                }

                type |= MTPLUS;
            } else {
                if ((atqa & 0x0040) == 0x0040) {
                    printTag("MIFARE Classic 1K CL2");
                } else {
                    printTag("MIFARE Classic 1K");
                }

                type |= MTCLASSIC;
            }
        } else if ((sak & 0x11) == 0x11) {
            printTag("MIFARE Plus 4K in SL2");
            type |= MTPLUS;
        } else if ((sak & 0x10) == 0x10) {
            printTag("MIFARE Plus 2K in SL2");
            type |= MTPLUS;
        } else if ((sak & 0x01) == 0x01) {
            printTag("TNP3xxx (TagNPlay, Activision Game Appliance)");
            type |= MTCLASSIC;
        } else if ((sak & 0x24) == 0x24) {
            printTag("MIFARE DESFire CL1");
            printTag("MIFARE DESFire EV1 CL1");
            type |= MTDESFIRE;
        } else if ((sak & 0x20) == 0x20) {
            if (select_status == 1) {
                if ((atqa & 0x0040) == 0x0040) {
                    if ((atqa & 0x0300) == 0x0300) {
                        printTag("MIFARE DESFire CL2");
                        printTag("MIFARE DESFire EV1 256B/2K/4K/8K CL2");
                        printTag("MIFARE DESFire EV2 2K/4K/8K/16K/32K");
                        printTag("MIFARE DESFire EV3 2K/4K/8K");
                        printTag("MIFARE DESFire Light 640B");
                    } else {
                        printTag("MIFARE Plus EV1 2K/4K CL2 in SL3");
                        printTag("MIFARE Plus S 2K/4K CL2 in SL3");
                        printTag("MIFARE Plus X 2K/4K CL2 in SL3");
                        printTag("MIFARE Plus SE 1K CL2");
                        type |= MTPLUS;
                    }
                } else {

                    if ((atqa & 0x0001) == 0x0001) {
                        printTag("HID SEOS (smartmx / javacard)");
                        type |= HID_SEOS;
                    } else {
                        printTag("MIFARE Plus EV1 2K/4K in SL3");
                        printTag("MIFARE Plus S 2K/4K in SL3");
                        printTag("MIFARE Plus X 2K/4K in SL3");
                        printTag("MIFARE Plus SE 1K");
                        type |= MTPLUS;
                    }
                }

                printTag("NTAG 4xx");
                type |= MTDESFIRE;
            }
        } else if ((sak & 0x04) == 0x04) {
            printTag("Any MIFARE CL1");
            type |= MTDESFIRE;
        } else {
            printTag("MIFARE Ultralight");
            printTag("MIFARE Ultralight C");
            printTag("MIFARE Ultralight EV1");
            printTag("MIFARE Ultralight Nano");
            printTag("MIFARE Hospitality");
            printTag("NTAG 2xx");
            type |= MTULTRALIGHT;
        }
    }

    if (type == MTNONE) {
        PrintAndLogEx(WARNING, "   failed to fingerprint");
    }
    return type;
}

typedef struct {
    uint8_t uid0;
    uint8_t uid1;
    const char *desc;
} uid_label_name_t;

static const uid_label_name_t uid_label_map[] = {
    // UID0, UID1, TEXT
    {0x02, 0x84, "M24SR64-Y"},
    {0x02, 0xA3, "25TA02KB-P"},
    {0x02, 0xC4, "25TA64K"},
    {0x02, 0xE3, "25TA02KB"},
    {0x02, 0xE4, "25TA512B"},
    {0x02, 0xF3, "25TA02KB-D"},
    {0x11, 0x22, "NTAG21x Modifiable"},
    {0x00, 0x00, "None"}
};

static void getTagLabel(uint8_t uid0, uint8_t uid1) {
    int i = 0;
    while (uid_label_map[i].uid0 != 0x00) {
        if ((uid_label_map[i].uid0 == uid0) && (uid_label_map[i].uid1 == uid1)) {
            PrintAndLogEx(SUCCESS, _YELLOW_("    %s"), uid_label_map[i].desc);
            return;
        }
        i += 1;
    }
}

int infoHF14A(bool verbose, bool do_nack_test, bool do_aid_search) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
        if (verbose) PrintAndLogEx(WARNING, "iso14443a card select failed");
        DropField();
        return 0;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        if (verbose) PrintAndLogEx(WARNING, "iso14443a card select failed");
        DropField();
        return select_status;
    }

    PrintAndLogEx(NORMAL, "");

    if (select_status == 3) {
        PrintAndLogEx(INFO, "Card doesn't support standard iso14443-3 anticollision");
        PrintAndLogEx(SUCCESS, "ATQA: %02x %02x", card.atqa[1], card.atqa[0]);
        DropField();
        return select_status;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "--- " _CYAN_("ISO14443-a Information") "---------------------");
    }

    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02x %02x"), card.atqa[1], card.atqa[0]);
    PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02x [%" PRIu64 "]"), card.sak, resp.oldarg[0]);

    bool isMifareClassic = true;
    bool isMifareDESFire = false;
    bool isMifarePlus = false;
    bool isMifareUltralight = false;
    bool isST = false;
    bool isEMV = false;
    int nxptype = MTNONE;

    if (card.uidlen <= 4) {
        nxptype = detect_nxp_card(card.sak, ((card.atqa[1] << 8) + card.atqa[0]), select_status);

        isMifareClassic = ((nxptype & MTCLASSIC) == MTCLASSIC);
        isMifareDESFire = ((nxptype & MTDESFIRE) == MTDESFIRE);
        isMifarePlus = ((nxptype & MTPLUS) == MTPLUS);
        isMifareUltralight = ((nxptype & MTULTRALIGHT) == MTULTRALIGHT);

        if ((nxptype & MTOTHER) == MTOTHER)
            isMifareClassic = true;

    } else {

        // Double & triple sized UID, can be mapped to a manufacturer.
        PrintAndLogEx(SUCCESS, "MANUFACTURER: " _YELLOW_("%s"), getTagInfo(card.uid[0]));

        switch (card.uid[0]) {
            case 0x02: // ST
                isST = true;
                break;
            case 0x04: // NXP
                nxptype = detect_nxp_card(card.sak, ((card.atqa[1] << 8) + card.atqa[0]), select_status);

                isMifareClassic = ((nxptype & MTCLASSIC) == MTCLASSIC);
                isMifareDESFire = ((nxptype & MTDESFIRE) == MTDESFIRE);
                isMifarePlus = ((nxptype & MTPLUS) == MTPLUS);
                isMifareUltralight = ((nxptype & MTULTRALIGHT) == MTULTRALIGHT);

                if ((nxptype & MTOTHER) == MTOTHER)
                    isMifareClassic = true;

                break;
            case 0x05: // Infineon
                if ((card.uid[1] & 0xF0) == 0x10) {
                    printTag("my-d(tm) command set SLE 66R04/16/32P, SLE 66R04/16/32S");
                } else if ((card.uid[1] & 0xF0) == 0x20) {
                    printTag("my-d(tm) command set SLE 66R01/16/32P (Type 2 Tag)");
                } else if ((card.uid[1] & 0xF0) == 0x30) {
                    printTag("my-d(tm) move lean SLE 66R01P/66R01PN");
                } else if ((card.uid[1] & 0xF0) == 0x70) {
                    printTag("my-d(tm) move lean SLE 66R01L");
                }
                isMifareUltralight = true;
                isMifareClassic = false;

                if (card.sak == 0x88) {
                    printTag("Infineon MIFARE CLASSIC 1K");
                    isMifareUltralight = false;
                    isMifareClassic = true;
                }
                getTagLabel(card.uid[0], card.uid[1]);
                break;
            case 0x46:
                if (memcmp(card.uid, "FSTN10m", 7) == 0) {
                    isMifareClassic = false;
                    printTag("Waveshare NFC-Powered e-Paper 1.54\" (please disregard MANUFACTURER mapping above)");
                }
                break;
            case 0x57:
                if (memcmp(card.uid, "WSDZ10m", 7) == 0) {
                    isMifareClassic = false;
                    printTag("Waveshare NFC-Powered e-Paper (please disregard MANUFACTURER mapping above)");
                }
                break;
            default:
                getTagLabel(card.uid[0], card.uid[1]);
                switch (card.sak) {
                    case 0x00: {
                        isMifareClassic = false;

                        // ******** is card of the MFU type (UL/ULC/NTAG/ etc etc)
                        DropField();

                        uint32_t tagT = GetHF14AMfU_Type();
                        if (tagT != UL_ERROR) {
                            ul_print_type(tagT, 0);
                            isMifareUltralight = true;
                            printTag("MIFARE Ultralight/C/NTAG Compatible");
                        } else {
                            printTag("Possible AZTEK (iso14443a compliant)");
                        }

                        // reconnect for further tests
                        clearCommandBuffer();
                        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
                        WaitForResponse(CMD_ACK, &resp);

                        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

                        select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS

                        if (select_status == 0) {
                            DropField();
                            return select_status;
                        }
                        break;
                    }
                    case 0x0A: {
                        if (card.atqa[0] == 0x03)
                            // Uses MIFARE Crypto-1 algo
                            printTag("FM11RF005M (FUDAN MIFARE Classic clone)");
                        else if (card.atqa[0] == 0x05)
                            // Uses Shanghai algo
                            printTag("FM11RF005SH (FUDAN Shanghai Metro)");
                        break;
                    }
                    case 0x20: {
                        printTag("JCOP 31/41");
                        break;
                    }
                    case 0x28: {
                        printTag("JCOP31 or JCOP41 v2.3.1");
                        break;
                    }
                    case 0x38: {
                        printTag("Nokia 6212 or 6131");
                        break;
                    }
                    case 0x98: {
                        printTag("Gemplus MPCOS");
                        break;
                    }
                    default: {
                        break;
                    }
                }
                break;
        }
    }

    // try to request ATS even if tag claims not to support it
    if (select_status == 2) {
        uint8_t rats[] = { 0xE0, 0x80 }; // FSDI=8 (FSD=256), CID=0
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_DISCONNECT, 2, 0, rats, sizeof(rats));
        WaitForResponse(CMD_ACK, &resp);

        memcpy(card.ats, resp.data.asBytes, resp.oldarg[0]);
        card.ats_len = resp.oldarg[0]; // note: ats_len includes CRC Bytes
        if (card.ats_len > 3)
            select_status = 1;
    }

    if (card.ats_len >= 3) {        // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes

        PrintAndLogEx(INFO, "-------------------------- " _CYAN_("ATS") " --------------------------");
        bool ta1 = 0, tb1 = 0, tc1 = 0;

        if (select_status == 2) {
            PrintAndLogEx(INFO, "--> SAK incorrectly claims that card doesn't support RATS <--");
        }

        if (card.ats[0] != card.ats_len - 2) {
            PrintAndLogEx(WARNING, "ATS may be corrupted. Length of ATS (%d bytes incl. 2 Bytes CRC) doesn't match TL", card.ats_len);
        }

        PrintAndLogEx(SUCCESS, "ATS: " _YELLOW_("%s")"[ %02x %02x ]", sprint_hex(card.ats, card.ats_len - 2), card.ats[card.ats_len - 1], card.ats[card.ats_len]);
        PrintAndLogEx(INFO, "     " _YELLOW_("%02x") "...............  TL    length is " _GREEN_("%d") " bytes", card.ats[0], card.ats[0]);

        if ((card.ats[0] > 1) && (card.ats_len > 1)) { // there is a format byte (T0)
            ta1 = (card.ats[1] & 0x10) == 0x10;
            tb1 = (card.ats[1] & 0x20) == 0x20;
            tc1 = (card.ats[1] & 0x40) == 0x40;
            int16_t fsci = card.ats[1] & 0x0f;

            PrintAndLogEx(INFO, "        " _YELLOW_("%02X") "............  T0    TA1 is%s present, TB1 is%s present, "
                          "TC1 is%s present, FSCI is %d (FSC = %d)",
                          card.ats[1],
                          (ta1 ? "" : _RED_(" NOT")),
                          (tb1 ? "" : _RED_(" NOT")),
                          (tc1 ? "" : _RED_(" NOT")),
                          fsci,
                          fsci < ARRAYLEN(atsFSC) ? atsFSC[fsci] : -1
                         );
        }
        int pos = 2;
        if (ta1 && (card.ats_len > pos)) {
            char dr[16], ds[16];
            dr[0] = ds[0] = '\0';
            if (card.ats[pos] & 0x10) strcat(ds, "2, ");
            if (card.ats[pos] & 0x20) strcat(ds, "4, ");
            if (card.ats[pos] & 0x40) strcat(ds, "8, ");
            if (card.ats[pos] & 0x01) strcat(dr, "2, ");
            if (card.ats[pos] & 0x02) strcat(dr, "4, ");
            if (card.ats[pos] & 0x04) strcat(dr, "8, ");
            if (strlen(ds) != 0) ds[strlen(ds) - 2] = '\0';
            if (strlen(dr) != 0) dr[strlen(dr) - 2] = '\0';
            PrintAndLogEx(INFO, "           " _YELLOW_("%02X") ".........  TA1   different divisors are%s supported, "
                          "DR: [%s], DS: [%s]",
                          card.ats[pos],
                          ((card.ats[pos] & 0x80) ? _RED_(" NOT") : ""),
                          dr,
                          ds
                         );

            pos++;
        }

        if (tb1 && (card.ats_len > pos)) {
            uint32_t sfgi = card.ats[pos] & 0x0F;
            uint32_t fwi = card.ats[pos] >> 4;

            PrintAndLogEx(INFO, "              " _YELLOW_("%02X") "......  TB1   SFGI = %d (SFGT = %s%d/fc), FWI = " _YELLOW_("%d") " (FWT = %d/fc)",
                          card.ats[pos],
                          (sfgi),
                          sfgi ? "" : "(not needed) ",
                          sfgi ? (1 << 12) << sfgi : 0,
                          fwi,
                          (1 << 12) << fwi
                         );
            pos++;
        }

        if (tc1 && (card.ats_len > pos)) {
            PrintAndLogEx(INFO, "                 " _YELLOW_("%02X") "...  TC1   NAD is%s supported, CID is%s supported",
                          card.ats[pos],
                          (card.ats[pos] & 0x01) ? "" : _RED_(" NOT"),
                          (card.ats[pos] & 0x02) ? "" : _RED_(" NOT")
                         );
            pos++;
        }

        // ATS - Historial bytes and identify based on it
        if (card.ats[0] > pos && card.ats[0] <=  card.ats_len - 2) {
            char tip[60];
            tip[0] = '\0';
            if (card.ats[0] - pos >= 7) {

                snprintf(tip, sizeof(tip), "     ");

                if ((card.sak & 0x70) == 0x40) {  // and no GetVersion()..

                    if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
                        snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus X 2K/4K (SL3)");

                    } else if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {

                        if ((card.atqa[0] & 0x02) == 0x02)
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus S 2K (SL3)");
                        else if ((card.atqa[0] & 0x04) == 0x04)
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus S 4K (SL3)");

                    } else if (memcmp(card.ats + pos, "\xC1\x05\x21\x30\x00\xF6\xD1", 7) == 0) {
                        snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus SE 1K (17pF)");

                    } else if (memcmp(card.ats + pos, "\xC1\x05\x21\x30\x10\xF6\xD1", 7) == 0) {
                        snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus SE 1K (70pF)");
                    }

                } else {  //SAK B4,5,6

                    if ((card.sak & 0x20) == 0x20) {  // and no GetVersion()..


                        if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus X 2K (SL1)");
                        } else if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus S 2K (SL1)");
                        } else if (memcmp(card.ats + pos, "\xC1\x05\x21\x30\x00\xF6\xD1", 7) == 0) {
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus SE 1K (17pF)");
                        } else if (memcmp(card.ats + pos, "\xC1\x05\x21\x30\x10\xF6\xD1", 7) == 0) {
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus SE 1K (70pF)");
                        }
                    } else {
                        if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x01\xBC\xD6", 7) == 0) {
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus X 4K (SL1)");
                        } else if (memcmp(card.ats + pos, "\xC1\x05\x2F\x2F\x00\x35\xC7", 7) == 0) {
                            snprintf(tip + strlen(tip), sizeof(tip) - strlen(tip), _GREEN_("%s"), "MIFARE Plus S 4K (SL1)");
                        }
                    }
                }
            }

            uint8_t calen = card.ats[0] - pos;
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------------------- " _CYAN_("Historical bytes") " --------------------");

            if (card.ats[pos] == 0xC1) {
                PrintAndLogEx(INFO, "    %s%s", sprint_hex(card.ats + pos, calen), tip);
                PrintAndLogEx(SUCCESS, "    C1.....................   Mifare or (multiple) virtual cards of various type");
                PrintAndLogEx(SUCCESS, "       %02x..................   length is " _YELLOW_("%d") " bytes", card.ats[pos + 1], card.ats[pos + 1]);
                switch (card.ats[pos + 2] & 0xf0) {
                    case 0x10:
                        PrintAndLogEx(SUCCESS, "          1x...............   MIFARE DESFire");
                        isMifareDESFire = true;
                        isMifareClassic = false;
                        isMifarePlus = false;
                        break;
                    case 0x20:
                        PrintAndLogEx(SUCCESS, "          2x...............   MIFARE Plus");
                        isMifarePlus = true;
                        isMifareDESFire = false;
                        isMifareClassic = false;
                        break;
                }
                switch (card.ats[pos + 2] & 0x0f) {
                    case 0x00:
                        PrintAndLogEx(SUCCESS, "          x0...............   < 1 kByte");
                        break;
                    case 0x01:
                        PrintAndLogEx(SUCCESS, "          x1...............   1 kByte");
                        break;
                    case 0x02:
                        PrintAndLogEx(SUCCESS, "          x2...............   2 kByte");
                        break;
                    case 0x03:
                        PrintAndLogEx(SUCCESS, "          x3...............   4 kByte");
                        break;
                    case 0x04:
                        PrintAndLogEx(SUCCESS, "          x4...............   8 kByte");
                        break;
                }
                switch (card.ats[pos + 3] & 0xf0) {
                    case 0x00:
                        PrintAndLogEx(SUCCESS, "             0x............   Engineering sample");
                        break;
                    case 0x20:
                        PrintAndLogEx(SUCCESS, "             2x............   Released");
                        break;
                }
                switch (card.ats[pos + 3] & 0x0f) {
                    case 0x00:
                        PrintAndLogEx(SUCCESS, "             x0............   Generation 1");
                        break;
                    case 0x01:
                        PrintAndLogEx(SUCCESS, "             x1............   Generation 2");
                        break;
                    case 0x02:
                        PrintAndLogEx(SUCCESS, "             x2............   Generation 3");
                        break;
                }
                switch (card.ats[pos + 4] & 0x0f) {
                    case 0x00:
                        PrintAndLogEx(SUCCESS, "                x0.........   Only VCSL supported");
                        break;
                    case 0x01:
                        PrintAndLogEx(SUCCESS, "                x1.........   VCS, VCSL, and SVC supported");
                        break;
                    case 0x0E:
                        PrintAndLogEx(SUCCESS, "                xE.........   no VCS command supported");
                        break;
                }
            } else {

                if (card.ats[pos] == 0x80)
                    PrintAndLogEx(SUCCESS, "   %s  (compact TLV data object)", sprint_hex_inrow(card.ats + pos, calen));
                else
                    PrintAndLogEx(SUCCESS, "   %s", sprint_hex_inrow(card.ats + pos, calen));

                PrintAndLogEx(NORMAL, "");
            }
        }

        if (do_aid_search) {

            PrintAndLogEx(INFO, "-------------------- " _CYAN_("AID Search") " --------------------");

            json_t *root = AIDSearchInit(verbose);
            if (root != NULL) {
                bool found = false;
                bool ActivateField = true;
                for (size_t elmindx = 0; elmindx < json_array_size(root); elmindx++) {

                    if (kbd_enter_pressed()) {
                        break;
                    }

                    json_t *data = AIDSearchGetElm(root, elmindx);
                    uint8_t vaid[200] = {0};
                    int vaidlen = 0;
                    if (!AIDGetFromElm(data, vaid, sizeof(vaid), &vaidlen) || !vaidlen)
                        continue;

                    uint16_t sw = 0;
                    uint8_t result[1024] = {0};
                    size_t resultlen = 0;
                    int res = Iso7816Select(CC_CONTACTLESS, ActivateField, true, vaid, vaidlen, result, sizeof(result), &resultlen, &sw);
                    ActivateField = false;
                    if (res)
                        continue;

                    uint8_t dfname[200] = {0};
                    size_t dfnamelen = 0;
                    if (resultlen > 3) {
                        struct tlvdb *tlv = tlvdb_parse_multi(result, resultlen);
                        if (tlv) {
                            // 0x84 Dedicated File (DF) Name
                            const struct tlv *dfnametlv = tlvdb_get_tlv(tlvdb_find_full(tlv, 0x84));
                            if (dfnametlv) {
                                dfnamelen = dfnametlv->len;
                                memcpy(dfname, dfnametlv->value, dfnamelen);
                            }
                            tlvdb_free(tlv);
                        }
                    }

                    if (sw == 0x9000 || sw == 0x6283 || sw == 0x6285) {
                        if (sw == 0x9000) {
                            if (verbose) PrintAndLogEx(SUCCESS, "Application ( " _GREEN_("ok") " )");
                        } else {
                            if (verbose) PrintAndLogEx(WARNING, "Application ( " _RED_("blocked") " )");
                        }

                        PrintAIDDescriptionBuf(root, vaid, vaidlen, verbose);

                        if (dfnamelen) {
                            if (dfnamelen == vaidlen) {
                                if (memcmp(dfname, vaid, vaidlen) == 0) {
                                    if (verbose) PrintAndLogEx(INFO, "(DF) Name found and equal to AID");
                                } else {
                                    PrintAndLogEx(INFO, "(DF) Name not equal to AID: %s :", sprint_hex(dfname, dfnamelen));
                                    PrintAIDDescriptionBuf(root, dfname, dfnamelen, verbose);
                                }
                            } else {
                                PrintAndLogEx(INFO, "(DF) Name not equal to AID: %s :", sprint_hex(dfname, dfnamelen));
                                PrintAIDDescriptionBuf(root, dfname, dfnamelen, verbose);
                            }
                        } else {
                            if (verbose) PrintAndLogEx(INFO, "(DF) Name not found");
                        }

                        if (verbose) PrintAndLogEx(SUCCESS, "----------------------------------------------------");
                        found = true;
                        isEMV = true;
                    }

                }
                DropField();
                if (verbose == false && found)
                    PrintAndLogEx(INFO, "----------------------------------------------------");
            }
        }
    } else {
        PrintAndLogEx(INFO, "proprietary non iso14443-4 card found, RATS not supported");
        if ((card.sak & 0x20) == 0x20) {
            PrintAndLogEx(INFO, "--> SAK incorrectly claims that card supports RATS <--");
        }
        if (select_status == 1)
            select_status = 2;
    }

    int isMagic = 0;
    if (isMifareClassic) {
        isMagic = detect_mf_magic(true);
    }
    if (isMifareUltralight) {
        isMagic = (detect_mf_magic(false) == MAGIC_NTAG21X);
    }
    if (isMifareClassic) {
        int res = detect_classic_static_nonce();
        if (res == NONCE_STATIC)
            PrintAndLogEx(SUCCESS, "Static nonce: " _YELLOW_("yes"));

        if (res == NONCE_FAIL && verbose)
            PrintAndLogEx(SUCCESS, "Static nonce:  " _RED_("read failed"));

        if (res == NONCE_NORMAL) {

            // not static
            res = detect_classic_prng();
            if (res == 1)
                PrintAndLogEx(SUCCESS, "Prng detection: " _GREEN_("weak"));
            else if (res == 0)
                PrintAndLogEx(SUCCESS, "Prng detection: " _YELLOW_("hard"));
            else
                PrintAndLogEx(FAILED, "Prng detection:  " _RED_("fail"));

            if (do_nack_test)
                detect_classic_nackbug(false);
        }

        uint8_t signature[32] = {0};
        res = detect_mfc_ev1_signature(signature);
        if (res == PM3_SUCCESS) {
            mfc_ev1_print_signature(card.uid, card.uidlen, signature, sizeof(signature));
        }

        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mf`") " commands");
    }

    if (isMifareUltralight)
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfu info`"));

    if (isMifarePlus && isMagic == 0 && isEMV == false)
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfp info`"));

    if (isMifareDESFire && isMagic == 0 && isEMV == false)
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf mfdes info`"));

    if (isST)
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf st info`"));

    if (isEMV)
        PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`emv search -s`"));

    PrintAndLogEx(NORMAL, "");
    DropField();
    return select_status;
}

int infoHF14A4Applications(bool verbose) {
    bool cardFound[ARRAYLEN(hintAIDList)] = {0};
    bool ActivateField = true;
    int found = 0;
    for (int i = 0; i < ARRAYLEN(hintAIDList); i++) {
        uint16_t sw = 0;
        uint8_t result[1024] = {0};
        size_t resultlen = 0;
        int res = Iso7816Select(CC_CONTACTLESS, ActivateField, true, (uint8_t *)hintAIDList[i].aid, hintAIDList[i].aid_length, result, sizeof(result), &resultlen, &sw);
        ActivateField = false;
        if (res)
            break;

        if (sw == 0x9000 || sw == 0x6283 || sw == 0x6285) {
            if (!found) {
                if (verbose)
                    PrintAndLogEx(INFO, "----------------- " _CYAN_("Short AID search") " -----------------");
            }
            found++;

            if (sw == 0x9000) {
                if (verbose)
                    PrintAndLogEx(SUCCESS, "Application " _CYAN_("%s") " ( " _GREEN_("ok") " )", hintAIDList[i].desc);
                cardFound[i] = true;
            } else {
                if (verbose)
                    PrintAndLogEx(WARNING, "Application " _CYAN_("%s") " ( " _RED_("blocked") " )", hintAIDList[i].desc);
            }
        }
    }

    if (found) {
        if (verbose)
            PrintAndLogEx(INFO, "---------------------------------------------------");
        else
            PrintAndLogEx(INFO, "Short AID search:");

        if (found >= ARRAYLEN(hintAIDList) - 1) {
            PrintAndLogEx(HINT, "Hint: card answers to all AID. It maybe the latest revision of plus/desfire/ultralight card.");
        } else {
            for (int i = 0; i < ARRAYLEN(hintAIDList); i++) {
                if (cardFound[i] && strlen(hintAIDList[i].hint))
                    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("%s") " commands", hintAIDList[i].hint);
            }
        }
    }

    DropField();
    return found;
}

static uint64_t inc_sw_error_occurrence(uint16_t sw, uint64_t all_sw[256][256]) {
    uint8_t sw1 = (uint8_t)(sw >> 8);
    uint8_t sw2 = (uint8_t)(0xff & sw);
    if (sw1 == 0x90 && sw2 == 0x00) {
        return 0; // Don't count successes.
    }
    if (sw1 == 0x6d && sw2 == 0x00) {
        return 0xffffffffffffffffULL; // Always max "Instruction not supported".
    }
    return ++all_sw[sw1][sw2];
}

static int CmdHf14AFindapdu(const char *Cmd) {
    // TODO: Option to select AID/File (and skip INS 0xA4).
    // TODO: Check all instructions with extended APDUs if the card support it.
    // TODO: Option to reset tag before every command.
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a apdufind",
                  "Enumerate APDU's of ISO7816 protocol to find valid CLS/INS/P1/P2 commands.\n"
                  "It loops all 256 possible values for each byte.\n"
                  "The loop oder is INS -> P1/P2 (alternating) -> CLA.\n"
                  "Tag must be on antenna before running.",
                  "hf 14a apdufind\n"
                  "hf 14a apdufind --cla 80\n"
                  "hf 14a apdufind --cla 80 --error-limit 20 --skip-ins a4 --skip-ins b0 --with-le\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("c",  "cla",           "<hex>",    "Start value of CLASS (1 hex byte)"),
        arg_str0("i",  "ins",           "<hex>",    "Start value of INSTRUCTION (1 hex byte)"),
        arg_str0(NULL, "p1",            "<hex>",    "Start value of P1 (1 hex byte)"),
        arg_str0(NULL, "p2",            "<hex>",    "Start value of P2 (1 hex byte)"),
        arg_u64_0("r", "reset",         "<number>", "Minimum secondes before resetting the tag (to prevent timeout issues). Default is 5 minutes"),
        arg_u64_0("e", "error-limit",   "<number>", "Maximum times an status word other than 0x9000 or 0x6D00 is shown. Default is 512."),
        arg_strx0("s", "skip-ins",      "<hex>",    "Do not test an instruction (can be specified multiple times)"),
        arg_lit0("l",  "with-le",                   "Search  for APDUs with Le=0 (case 2S) as well"),
        arg_lit0("v",  "verbose",                   "Verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int cla_len = 0;
    uint8_t cla_arg[1] = {0};
    CLIGetHexWithReturn(ctx, 1, cla_arg, &cla_len);
    int ins_len = 0;
    uint8_t ins_arg[1] = {0};
    CLIGetHexWithReturn(ctx, 2, ins_arg, &ins_len);
    int p1_len = 0;
    uint8_t p1_arg[1] = {0};
    CLIGetHexWithReturn(ctx, 3, p1_arg, &p1_len);
    int p2_len = 0;
    uint8_t p2_arg[1] = {0};
    CLIGetHexWithReturn(ctx, 4, p2_arg, &p2_len);
    uint64_t reset_time = arg_get_u64_def(ctx, 5, 5 * 60);
    uint64_t error_limit = arg_get_u64_def(ctx, 6, 512);
    int ignore_ins_len = 0;
    uint8_t ignore_ins_arg[250] = {0};
    CLIGetHexWithReturn(ctx, 7, ignore_ins_arg, &ignore_ins_len);
    bool with_le = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);

    CLIParserFree(ctx);

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t cla = cla_arg[0];
    uint8_t ins = ins_arg[0];
    uint8_t p1 = p1_arg[0];
    uint8_t p2 = p2_arg[0];
    uint8_t response[PM3_CMD_DATA_SIZE];
    int response_n = 0;
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;

    // Check if the tag reponds to APDUs.
    PrintAndLogEx(INFO, "Sending a test APDU (select file command) to check if the tag is responding to APDU");
    param_gethex_to_eol("00a404000aa000000440000101000100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, true, false, response, sizeof(response), &response_n);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Tag did not respond to a test APDU (select file command). Aborting");
        return res;
    }
    PrintAndLogEx(SUCCESS, "Got response. Starting the APDU finder [ CLA " _GREEN_("%02X") " INS " _GREEN_("%02X") " P1 " _GREEN_("%02X") " P2 " _GREEN_("%02X") " ]", cla, ins, p1, p2);
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");

    bool inc_p1 = true;
    bool skip_ins = false;
    uint64_t all_sw[256][256] = { { 0 } };
    uint64_t sw_occurrences = 0;
    uint64_t t_start = msclock();
    uint64_t t_last_reset = msclock();

    // Enumerate APDUs.
    do {
        do {
            do {
retry_ins:
                // Exit (was the Enter key pressed)?
                if (kbd_enter_pressed()) {
                    PrintAndLogEx(INFO, "User interrupted detected. Aborting");
                    goto out;
                }

                // Skip/Ignore this instrctuion?
                for (int i = 0; i < ignore_ins_len; i++) {
                    if (ins == ignore_ins_arg[i]) {
                        skip_ins = true;
                        break;
                    }
                }
                if (skip_ins) {
                    skip_ins = false;
                    continue;
                }

                if (verbose) {
                    PrintAndLogEx(INFO, "Status: [ CLA " _GREEN_("%02X") " INS " _GREEN_("%02X") " P1 " _GREEN_("%02X") " P2 " _GREEN_("%02X") " ]", cla, ins, p1, p2);
                }

                // Send APDU without Le (case 1) and with Le = 0 (case 2S), if "with-le" was set.
                uint8_t command[5] = {cla, ins, p1, p2, 0x00};
                int command_n = 4;
                for (int i = 0; i < 1 + with_le; i++) {
                    // Send APDU.
                    res = ExchangeAPDU14a(command, command_n + i, activate_field, keep_field_on, response, sizeof(response), &response_n);
                    if (res != PM3_SUCCESS) {
                        DropField();
                        activate_field = true;
                        goto retry_ins;
                    }
                    uint16_t sw = get_sw(response, response_n);
                    sw_occurrences = inc_sw_error_occurrence(sw, all_sw);

                    // Show response.
                    if (sw_occurrences < error_limit) {
                        logLevel_t log_level = INFO;
                        if (sw == 0x9000) {
                            log_level = SUCCESS;
                        }
                        PrintAndLogEx(log_level, "Got response for APDU \"%s\": %04X (%s)", sprint_hex_inrow(command, command_n + i),
                                      sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
                        if (response_n > 2) {
                            PrintAndLogEx(SUCCESS, "Response data is: %s | %s", sprint_hex_inrow(response, response_n - 2),
                                          sprint_ascii(response, response_n - 2));
                        }
                    }
                }
                activate_field = false; // Do not reativate the filed until the next reset.
            } while (++ins != ins_arg[0]);
            // Increment P1/P2 in an alternating fashion.
            if (inc_p1) {
                p1++;
            } else {
                p2++;
            }
            inc_p1 = !inc_p1;
            // Check if re-selecting the card is needed.
            uint64_t t_since_last_reset = ((msclock() - t_last_reset) / 1000);
            if (t_since_last_reset > reset_time) {
                DropField();
                activate_field = true;
                t_last_reset = msclock();
                PrintAndLogEx(INFO, "Last reset was %" PRIu64 " seconds ago. Resetting the tag to prevent timeout issues", t_since_last_reset);
            }
            PrintAndLogEx(INFO, "Status: [ CLA " _GREEN_("%02X") " INS " _GREEN_("%02X") " P1 " _GREEN_("%02X") " P2 " _GREEN_("%02X") " ]", cla, ins, p1, p2);
        } while (p1 != p1_arg[0] || p2 != p2_arg[0]);
        cla++;
        PrintAndLogEx(INFO, "Status: [ CLA " _GREEN_("%02X") " INS " _GREEN_("%02X") " P1 " _GREEN_("%02X") " P2 " _GREEN_("%02X") " ]", cla, ins, p1, p2);
    } while (cla != cla_arg[0]);

out:
    PrintAndLogEx(SUCCESS, "Runtime: %" PRIu64 " seconds\n", (msclock() - t_start) / 1000);
    DropField();
    return PM3_SUCCESS;
}

int CmdHF14ANdefRead(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf 14a ndefread",
                  "Read NFC Data Exchange Format (NDEF) file on Type 4 NDEF tag",
                  "hf 14a ndefread\n"
                  "hf 14a ndefread -f myfilename -> save raw NDEF to file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "save raw NDEF to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;
    bool backward_compatibility_v1 = false;

    // ---------------  Select NDEF Tag application ----------------
    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol("00a4040007d276000085010100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    if (resplen < 2) {
        DropField();
        return PM3_ESOFT;
    }

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        // Try NDEF Type 4 Tag v1.0
        param_gethex_to_eol("00a4040007d2760000850100", 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
        res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            return res;
        }
        if (resplen < 2) {
            DropField();
            return PM3_ESOFT;
        }

        sw = get_sw(response, resplen);
        if (sw != 0x9000) {
            PrintAndLogEx(ERR, "Selecting NDEF aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
            DropField();
            return PM3_ESOFT;
        }
        backward_compatibility_v1 = true;
    }

    activate_field = false;
    keep_field_on = true;

    // ---------------  CC file reading ----------------

    uint8_t aSELECT_FILE_CC[30];
    int aSELECT_FILE_CC_n = 0;
    if (backward_compatibility_v1) {
        param_gethex_to_eol("00a4000002e103", 0, aSELECT_FILE_CC, sizeof(aSELECT_FILE_CC), &aSELECT_FILE_CC_n);
    } else {
        param_gethex_to_eol("00a4000c02e103", 0, aSELECT_FILE_CC, sizeof(aSELECT_FILE_CC), &aSELECT_FILE_CC_n);
    }
    res = ExchangeAPDU14a(aSELECT_FILE_CC, aSELECT_FILE_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    uint8_t aREAD_CC[30];
    int aREAD_CC_n = 0;
    param_gethex_to_eol("00b000000f", 0, aREAD_CC, sizeof(aREAD_CC), &aREAD_CC_n);
    res = ExchangeAPDU14a(aREAD_CC, aREAD_CC_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }
    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading CC file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // Parse CC data
    uint8_t cc_data[resplen - 2];
    memcpy(cc_data, response, sizeof(cc_data));
    uint8_t file_id[2] = {cc_data[9], cc_data[10]};

    print_type4_cc_info(cc_data, sizeof(cc_data));
    uint16_t max_rapdu_size = (cc_data[3] << 8 | cc_data[4]) - 2;
    max_rapdu_size = max_rapdu_size < sizeof(response) - 2 ? max_rapdu_size : sizeof(response) - 2;

    // ---------------  NDEF file reading ----------------
    uint8_t aSELECT_FILE_NDEF[30];
    int aSELECT_FILE_NDEF_n = 0;
    if (backward_compatibility_v1) {
        param_gethex_to_eol("00a4000002", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);
    } else {
        param_gethex_to_eol("00a4000c02", 0, aSELECT_FILE_NDEF, sizeof(aSELECT_FILE_NDEF), &aSELECT_FILE_NDEF_n);
    }
    memcpy(aSELECT_FILE_NDEF + aSELECT_FILE_NDEF_n, file_id, sizeof(file_id));
    res = ExchangeAPDU14a(aSELECT_FILE_NDEF, aSELECT_FILE_NDEF_n + sizeof(file_id), activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }

    // read first 2 bytes to get NDEF length

    uint8_t aREAD_NDEF[30];
    int aREAD_NDEF_n = 0;
    param_gethex_to_eol("00b0000002", 0, aREAD_NDEF, sizeof(aREAD_NDEF), &aREAD_NDEF_n);
    res = ExchangeAPDU14a(aREAD_NDEF, aREAD_NDEF_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return PM3_ESOFT;
    }
    uint16_t ndef_size = (response[0] << 8) + response[1];
    uint16_t offset = 2;
    uint8_t *ndef_file = calloc(ndef_size, sizeof(uint8_t));
    if (ndef_file == NULL) {
        PrintAndLogEx(ERR, "Out of memory error in CmdHF14ANdef(). Aborting...\n");
        DropField();
        return PM3_EMALLOC;
    }
    for (uint16_t i = offset; i < ndef_size + offset; i += max_rapdu_size) {
        uint16_t segment_size = max_rapdu_size < ndef_size + offset - i ? max_rapdu_size : ndef_size + offset - i;
        keep_field_on = i < ndef_size + offset - max_rapdu_size;
        aREAD_NDEF_n = 0;
        param_gethex_to_eol("00b00000", 0, aREAD_NDEF, sizeof(aREAD_NDEF), &aREAD_NDEF_n);
        aREAD_NDEF[2] = i >> 8;
        aREAD_NDEF[3] = i & 0xFF;
        aREAD_NDEF[4] = segment_size;
        res = ExchangeAPDU14a(aREAD_NDEF, aREAD_NDEF_n + 1, activate_field, keep_field_on, response, sizeof(response), &resplen);
        if (res != PM3_SUCCESS) {
            DropField();
            free(ndef_file);
            return res;
        }
        sw = get_sw(response, resplen);
        if (sw != 0x9000) {
            PrintAndLogEx(ERR, "reading NDEF file failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
            DropField();
            free(ndef_file);
            return PM3_ESOFT;
        }
        if (resplen != segment_size + 2) {
            PrintAndLogEx(ERR, "reading NDEF file failed, expected %i bytes, got %i bytes.", segment_size, resplen - 2);
            DropField();
            free(ndef_file);
            return PM3_ESOFT;
        }
        memcpy(ndef_file + (i - offset), response, segment_size);
    }
    if (fnlen != 0) {
        saveFile(filename, ".bin", ndef_file, ndef_size);
    }
    NDEFRecordsDecodeAndPrint(ndef_file, ndef_size);
    free(ndef_file);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,              AlwaysAvailable, "This help"},
    {"list",        CmdHF14AList,         AlwaysAvailable, "List ISO 14443-a history"},
    {"info",        CmdHF14AInfo,         IfPm3Iso14443a,  "Tag information"},
    {"reader",      CmdHF14AReader,       IfPm3Iso14443a,  "Act like an ISO14443-a reader"},
    {"ndefread",    CmdHF14ANdefRead,     IfPm3Iso14443a,  "Read an NDEF file from ISO 14443-A Type 4 tag"},
    {"cuids",       CmdHF14ACUIDs,        IfPm3Iso14443a,  "Collect n>0 ISO14443-a UIDs in one go"},
    {"sim",         CmdHF14ASim,          IfPm3Iso14443a,  "Simulate ISO 14443-a tag"},
    {"sniff",       CmdHF14ASniff,        IfPm3Iso14443a,  "sniff ISO 14443-a traffic"},
    {"apdu",        CmdHF14AAPDU,         IfPm3Iso14443a,  "Send ISO 14443-4 APDU to tag"},
    {"chaining",    CmdHF14AChaining,     IfPm3Iso14443a,  "Control ISO 14443-4 input chaining"},
    {"raw",         CmdHF14ACmdRaw,       IfPm3Iso14443a,  "Send raw hex data to tag"},
    {"antifuzz",    CmdHF14AAntiFuzz,     IfPm3Iso14443a,  "Fuzzing the anticollision phase.  Warning! Readers may react strange"},
    {"config",      CmdHf14AConfig,       IfPm3Iso14443a,  "Configure 14a settings (use with caution)"},
    {"apdufind",    CmdHf14AFindapdu,     IfPm3Iso14443a,  "Enumerate APDUs - CLA/INS/P1P2"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHF14A(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
