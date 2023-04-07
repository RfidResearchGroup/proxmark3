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
#include "protocols.h"   // ISO7816 APDU return codes

static int CmdHelp(const char *Cmd);

static int get_and_print_balance(void) {
    uint32_t balance = 0;
    if (KSX6924GetBalance(&balance) == false) {
        PrintAndLogEx(ERR, "Error getting balance");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Current balance: " _YELLOW_("%u") " won/cents", balance);
    return PM3_SUCCESS;
}

static int CmdHFKSX6924Balance(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 balance",
                  "Gets the current purse balance",
                  "hf ksx6924 balance\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "keep field ON for next command"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (KSX6924TrySelect()) {
        get_and_print_balance();
    }

    if (keep == false) {
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdHFKSX6924Info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 info",
                  "Get info about a KS X 6924 transit card.\n"
                  "This application is used by T-Money (South Korea) and\n"
                  "Snapper+ (Wellington, New Zealand).",
                  "hf ksx6924 info\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k", "keep", "keep field ON for next command"),
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    // KSX6924 info
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;
    int res = KSX6924Select(true, true, buf, sizeof(buf), &len, &sw);

    if (res || (len == 0)) {
        if (keep == false) {
            DropField();
        }
        return res;
    }

    if (sw != ISO7816_OK) {
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
    memset(&fci_tag, 0, sizeof(fci_tag));

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

    get_and_print_balance();

end:
    if (keep == false) {
        DropField();
    }
    return PM3_SUCCESS;
}

static int CmdHFKSX6924Select(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 select",
                  "Selects KS X 6924 application, and leaves field up",
                  "hf ksx6924 select\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", "apdu", "Show APDU requests and responses"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool APDULogging = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (KSX6924TrySelect()) {
        PrintAndLogEx(SUCCESS, "Card is selected and field is up");
    } else {
        // Wrong app, drop field.
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdHFKSX6924Initialize(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 init",
                  "Perform transaction initialization with Mpda (Money of Purchase Transaction)",
                  "hf ksx6924 init 000003e8 -> Mpda\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",  "keep", "keep field ON for next command"),
        arg_lit0("a",  "apdu", "Show APDU requests and responses"),
        arg_str1(NULL, NULL,  "<Mpda 4 bytes hex>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 3, data, &datalen);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (datalen != 4) {
        PrintAndLogEx(WARNING, "Mpda parameter must be 4 bytes long (eg: 000003e8)");
        return PM3_EINVARG;
    }

    // try selecting card
    if (KSX6924TrySelect() == false) {
        goto end;
    }

    uint8_t resp[APDU_RES_LEN] = {0};
    size_t resp_len = 0;
    if (KSX6924InitializeCard(data[0], data[1], data[2], data[3], resp, &resp_len) == false) {
        goto end;
    }

    uint8_t *r = resp;
    struct ksx6924_initialize_card_response initCardResponse;
    bool ret = KSX6924ParseInitializeCardResponse(r, resp_len, &initCardResponse);

    if (!ret) {
        PrintAndLogEx(FAILED, "Error parsing KS X 6924 initialize card response");
        goto end;
    }

    KSX6924PrintInitializeCardResponse(&initCardResponse);

end:
    if (keep == false) {
        DropField();
    }

    return PM3_SUCCESS;
}

static int CmdHFKSX6924PRec(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf ksx6924 prec",
                  "Executes proprietary read record command.\n"
                  "Data format is unknown. Other records are available with 'emv getrec'.\n",
                  "hf ksx6924 prec 0b -> read proprietary record 0x0b");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("k",   "keep", "keep field ON for next command"),
        arg_lit0("a",   "apdu", "Show APDU requests and responses"),
        arg_str1(NULL,  NULL,  "<record 1byte HEX>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool keep = arg_get_lit(ctx, 1);
    bool APDULogging = arg_get_lit(ctx, 2);

    uint8_t data[APDU_RES_LEN] = {0};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 3, data, &datalen);

    CLIParserFree(ctx);
    SetAPDULogging(APDULogging);

    if (datalen != 1) {
        PrintAndLogEx(WARNING, "Record parameter must be 1 byte long (eg: 0f)");
        return PM3_EINVARG;
    }

    if (KSX6924TrySelect() == false) {
        goto end;
    }

    PrintAndLogEx(SUCCESS, "Getting record %02x ...", data[0]);

    uint8_t recordData[0x10] = {0};
    if (KSX6924ProprietaryGetRecord(data[0], recordData, sizeof(recordData))) {
        PrintAndLogEx(SUCCESS, "  %s", sprint_hex(recordData, sizeof(recordData)));
    } else {
        PrintAndLogEx(FAILED, "Error getting record");
    }

end:
    if (keep == false) {
        DropField();
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",       CmdHelp,                AlwaysAvailable, "This help"},
    {"select",     CmdHFKSX6924Select,     IfPm3Iso14443a,  "Select application, and leave field up"},
    {"info",       CmdHFKSX6924Info,       IfPm3Iso14443a,  "Get info about a KS X 6924 (T-Money, Snapper+) transit card"},
    {"balance",    CmdHFKSX6924Balance,    IfPm3Iso14443a,  "Get current purse balance"},
    {"init",       CmdHFKSX6924Initialize, IfPm3Iso14443a,  "Perform transaction initialization with Mpda"},
    {"prec",       CmdHFKSX6924PRec,       IfPm3Iso14443a,  "Send proprietary get record command (CLA=90, INS=4C)"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFKSX6924(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}



