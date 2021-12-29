/**
 * Matt Moran (@DarkMatterMatt), 2021
 * -----------------------------------------------------------------------------
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * -----------------------------------------------------------------------------
 * High frequency GALLAGHER tag commands.
 * MIFARE DESFire, AIDs 2081F4-2F81F4
 */

#include "cmdhfgallagher.h"
#include "mifare/gallaghercore.h"
#include <stdio.h>
#include "common.h"
#include "cmdparser.h"
#include "cliparser.h"
#include "ui.h"

static int CmdHelp(const char *Cmd);

static int CmdGallagherReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher reader",
                    "read a GALLAGHER tag",
                    "hf gallagher reader -@   -> continuous reader mode"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        // read
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

static int CmdGallagherClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher clone",
                    "clone a GALLAGHER card to a blank DESFire card.",
                    "hf gallagher clone --rc 1 --fc 22 --cn 3333 --il 4"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "rc", "<decimal>", "Region code. 4 bits max"),
        arg_u64_1(NULL, "fc", "<decimal>", "Facility code. 2 bytes max"),
        arg_u64_1(NULL, "cn", "<decimal>", "Card number. 3 bytes max"),
        arg_u64_1(NULL, "il", "<decimal>", "Issue level. 4 bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint64_t region_code = arg_get_u64(ctx, 1); // uint16, will be validated later
    uint64_t facility_code = arg_get_u64(ctx, 2); // uint32, will be validated later
    uint64_t card_number = arg_get_u64(ctx, 3); // uint64
    uint64_t issue_level = arg_get_u64(ctx, 4); // uint32, will be validated later
    CLIParserFree(ctx);

    if (!isValidGallagherCredentials(region_code, facility_code, card_number, issue_level)) {
        return PM3_EINVARG;
    }

    // TODO: create data

    PrintAndLogEx(INFO, "Preparing to clone Gallagher from specified data.");

    // TODO: write data

    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`hf gallagher reader`") " to verify");
    return PM3_ENOTIMPL;
}

static int CmdGallagherSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf gallagher sim",
                  "Enables simulation of GALLAGHER card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n",
                  "hf gallagher sim --rc 1 --fc 22 --cn 3333 --il 4"
                );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "rc", "<decimal>", "Region code. 4 bits max"),
        arg_u64_1(NULL, "fc", "<decimal>", "Facility code. 2 bytes max"),
        arg_u64_1(NULL, "cn", "<decimal>", "Card number. 3 bytes max"),
        arg_u64_1(NULL, "il", "<decimal>", "Issue level. 4 bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint64_t region_code = arg_get_u64(ctx, 1); // uint16, will be validated later
    uint64_t facility_code = arg_get_u64(ctx, 2); // uint32, will be validated later
    uint64_t card_number = arg_get_u64(ctx, 3); // uint64
    uint64_t issue_level = arg_get_u64(ctx, 4); // uint32, will be validated later
    CLIParserFree(ctx);

    if (!isValidGallagherCredentials(region_code, facility_code, card_number, issue_level)) {
        return PM3_EINVARG;
    }

    // TODO: create data

    // TODO: simulate

    return PM3_ENOTIMPL;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,            AlwaysAvailable, "This help"},
    {"reader", CmdGallagherReader, IfPm3Iso14443,   "attempt to read and extract tag data"},
    {"clone",  CmdGallagherClone,  IfPm3Iso14443,   "clone GALLAGHER tag to a blank DESFire card"},
    {"sim",    CmdGallagherSim,    IfPm3Iso14443,   "simulate GALLAGHER tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void) Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFGallagher(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
