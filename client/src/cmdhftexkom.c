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
// High frequency proximity cards from TEXCOM commands
//-----------------------------------------------------------------------------

#include "cmdhftexkom.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmdhf14a.h" 

static int CmdHFTexkomReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf texkom reader",
                  "Read a texkom tag",
                  "hf texkom reader");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    uint32_t samplesCount = 40000;
    SendCommandNG(CMD_HF_ACQ_RAW_ADC, (uint8_t *)&samplesCount, sizeof(uint32_t));

    return PM3_SUCCESS;
}


static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable,  "This help"},
    {"reader",  CmdHFTexkomReader,  IfPm3Iso14443a,   "Act like a Texkom reader"},
    //{"sim",     CmdHFTexkomSim,     IfPm3Iso14443a,   "Simulate a Texkom tag"},
    //{"write",   CmdHFTexkomWrite,   IfPm3Iso14443a,   "Write a Texkom tag"},
    {NULL,      NULL,               0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFTexkom(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
