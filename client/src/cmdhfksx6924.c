// -*- mode: c; indent-tabs-mode: nil; tab-width: 3 -*-
//-----------------------------------------------------------------------------
// Copyright (C) 2019 micolous+git@gmail.com
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Commands for KS X 6924 transit cards (T-Money, Snapper+)
//-----------------------------------------------------------------------------
// This is used in T-Money (South Korea) and Snapper plus (Wellington, New
// Zealand).
//
// References:
// - https://github.com/micolous/metrodroid/wiki/T-Money (in English)
// - https://github.com/micolous/metrodroid/wiki/Snapper (in English)
// - https://kssn.net/StdKS/ks_detail.asp?k1=X&k2=6924-1&k3=4
//   (KS X 6924, only available in Korean)
// - http://www.tta.or.kr/include/Download.jsp?filename=stnfile/TTAK.KO-12.0240_%5B2%5D.pdf
//   (TTAK.KO 12.0240, only available in Korean)
//-----------------------------------------------------------------------------


#include "cmdhfksx6924.h"

#include <inttypes.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <unistd.h>
#include "comms.h"
#include "cmdmain.h"
#include "util.h"
#include "ui.h"
#include "proxmark3.h"
#include "cliparser.h"
#include "ksx6924/ksx6924core.h"
#include "emv/tlv.h"
#include "iso7816/apduinfo.h"
#include "cmdhf14a.h"

static int CmdHelp(const char *Cmd);

static void getAndPrintBalance() {
    uint32_t balance;
    bool ret = KSX6924GetBalance(&balance);
    if (!ret) {
        PrintAndLogEx(ERR, "Error getting balance");
        return;
    }

    PrintAndLogEx(SUCCESS, "Current balance: %ld won/cents", balance);
}

static int CmdHFKSX6924Balance(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 balance",
                  "Gets the current purse balance.\n",
                  "Usage:\n\thf ksx6924 balance\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    bool ret = KSX6924TrySelect();
    if (!ret) {
        goto end;
    }

    getAndPrintBalance();

end:
    if (!leaveSignalON) {
        DropField();
    }
    return 0;
}

static int CmdHFKSX6924Info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 info",
                  "Get info about a KS X 6924 transit card.\nThis application is used by T-Money (South Korea) and Snapper+ (Wellington, New Zealand).\n",
                  "Usage:\n\thf ksx6924 info\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    // KSX6924 info
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = KSX6924Select(true, true, buf, sizeof(buf), &len, &sw);

    if (res) {
        if (!leaveSignalON) {
            DropField();
        }
        return res;
    }

    if (sw != 0x9000) {
        if (sw) {
            PrintAndLogEx(INFO, "Not a KS X 6924 card! APDU response: %04x - %s",
                          sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        } else {
            PrintAndLogEx(ERR, "APDU exchange error. Card returns 0x0000.");
        }
        goto end;
    }


    // PrintAndLogEx(DEBUG, "APDU response: %s", sprint_hex(buf, len));

    // FCI Response is a BER-TLV, we are interested in tag 6F,B0 only.
    const uint8_t *p = buf;
    struct tlv fci_tag;

    while (len > 0) {
        memset(&fci_tag, 0, sizeof(fci_tag));
        bool ret = tlv_parse_tl(&p, &len, &fci_tag);

        if (!ret) {
            PrintAndLogEx(FAILED, "Error parsing FCI!");
            goto end;
        }

        // PrintAndLog("tag %02x, len %d, value %s",
        //             fci_tag.tag, fci_tag.len,
        //             sprint_hex(p, fci_tag.len));

        if (fci_tag.tag == 0x6f) { /* FCI template */
            break;
        } else {
            p += fci_tag.len;
            continue;
        }
    }

    if (fci_tag.tag != 0x6f) {
        PrintAndLogEx(ERR, "Couldn't find tag 6F (FCI) in SELECT response");
        goto end;
    }

    // We now are at Tag 6F (FCI template), get Tag B0 inside of it
    while (len > 0) {
        memset(&fci_tag, 0, sizeof(fci_tag));
        bool ret = tlv_parse_tl(&p, &len, &fci_tag);

        if (!ret) {
            PrintAndLogEx(ERR, "Error parsing FCI!");
            goto end;
        }

        // PrintAndLog("tag %02x, len %d, value %s",
        //             fci_tag.tag, fci_tag.len,
        //             sprint_hex(p, fci_tag.len));

        if (fci_tag.tag == 0xb0) { /* KS X 6924 purse info */
            break;
        } else {
            p += fci_tag.len;
            continue;
        }
    }

    if (fci_tag.tag != 0xb0) {
        PrintAndLogEx(FAILED, "Couldn't find tag B0 (KS X 6924 purse info) in FCI");
        goto end;
    }

    struct ksx6924_purse_info purseInfo;
    bool ret = KSX6924ParsePurseInfo(p, fci_tag.len, &purseInfo);

    if (!ret) {
        PrintAndLogEx(FAILED, "Error parsing KS X 6924 purse info");
        goto end;
    }

    KSX6924PrintPurseInfo(&purseInfo);

    getAndPrintBalance();

end:
    if (!leaveSignalON) {
        DropField();
    }
    return 0;
}

static int CmdHFKSX6924Select(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 select",
                  "Selects KS X 6924 application, and leaves field up.\n",
                  "Usage:\n\thf ksx6924 select\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    bool ret = KSX6924TrySelect();
    if (ret) {
        PrintAndLogEx(SUCCESS, "OK");
    } else {
        // Wrong app, drop field.
        DropField();
    }

    return 0;
}

static int CmdHFKSX6924InitializeCard(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 initializecard",
                  "Perform transaction initialization. (Mpda)\n",
                  "Usage:\n\thf ksx6924 initializecard 000003e8 -> Mpda\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_strx1(NULL,  NULL,     "<Mpda 4byte hex>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 3, data, &datalen);
    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (datalen != 4) {
        PrintAndLogEx(WARNING, "Mpda parameter must be 4 byte long (eg: 000003e8)");
        goto end;
    }

    bool ret = KSX6924TrySelect();
    if (!ret) {
        goto end;
    }

    PrintAndLogEx(NORMAL, "Initialize Card : Mpda -> %02X %02X %02X %02X", data[0], data[1], data[2], data[3]);
    uint8_t response[25];
    if (!KSX6924InitializeCard(data[0], data[1], data[2], data[3], response)) {
        PrintAndLogEx(FAILED, "Initialize Card Error");
        goto end;
    }

    PrintAndLogEx(NORMAL, "Response : %s", sprint_hex(response, sizeof(response)));

end:
    if (!leaveSignalON) {
        DropField();
    }
    return 0;
}

static int CmdHFKSX6924PRec(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 prec",
                  "Executes proprietary read record command.\nData format is unknown. Other records are available with 'emv getrec'.\n",
                  "Usage:\n\thf ksx6924 prec 0b -> read proprietary record 0x0b\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("kK",  "keep",    "keep field ON for next command"),
        arg_lit0("aA",  "apdu",    "show APDU reqests and responses"),
        arg_strx1(NULL,  NULL,     "<record 1byte HEX>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool leaveSignalON = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);
    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 3, data, &datalen);
    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (datalen != 1) {
        PrintAndLogEx(WARNING, "Record parameter must be 1 byte long (eg: 0f)");
        goto end;
    }

    bool ret = KSX6924TrySelect();
    if (!ret) {
        goto end;
    }

    PrintAndLogEx(NORMAL, "Getting record %02x...", data[0]);
    uint8_t recordData[0x10];
    if (!KSX6924ProprietaryGetRecord(data[0], recordData, sizeof(recordData))) {
        PrintAndLogEx(FAILED, "Error getting record");
        goto end;
    }

    PrintAndLogEx(NORMAL, "  %s", sprint_hex(recordData, sizeof(recordData)));

end:
    if (!leaveSignalON) {
        DropField();
    }
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,             AlwaysAvailable, "This help."},
    {"info",    CmdHFKSX6924Info,    AlwaysAvailable, "Get info about a KS X 6924 (T-Money, Snapper+) transit card"},
    {"select",  CmdHFKSX6924Select,  AlwaysAvailable, "Select application, and leave field up"},
    {"balance", CmdHFKSX6924Balance, AlwaysAvailable, "Get current purse balance"},
    {"initializecard", CmdHFKSX6924InitializeCard, AlwaysAvailable, "Perform transaction initialization (Mpda)"},
    {"prec",    CmdHFKSX6924PRec,    AlwaysAvailable, "Send proprietary get record command (CLA=90, INS=4C)"},
    {NULL, NULL, NULL, NULL}
};

int CmdHFKSX6924(const char *Cmd) {
    (void)WaitForResponseTimeout(CMD_ACK, NULL, 100);
    CmdsParse(CommandTable, Cmd);
    return 0;
}

static int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}

