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
#include "cmddata.h" 
#include "graph.h" 

#define TEXKOM_NOISE_THRESHOLD (10)

inline uint32_t GetGraphBuffer(uint32_t indx) {
    if (g_GraphBuffer[indx] < -128)
        return 0;
    else
        return g_GraphBuffer[indx] + 128;
}

static uint32_t TexkomSearchStart(uint32_t indx, uint32_t threshold) {
    // one bit length = 27, minimal noise = 60
    uint32_t lownoisectr = 0;
    for (uint32_t i = indx; i < g_GraphTraceLen; i++) {
        if (lownoisectr > 60) {
            if (GetGraphBuffer(i) > threshold)
                return i;
        } else {
            if (GetGraphBuffer(i) > threshold)
                lownoisectr = 0;
            else
                lownoisectr++;
        }
    }

    return 0;
}

static uint32_t TexkomSearchLength(uint32_t indx, uint32_t threshold) {
    // one bit length = 27, minimal noise = 60
    uint32_t lownoisectr = 0;
    uint32_t datalen = 0;
    for (uint32_t i = indx; i < g_GraphTraceLen; i++) {
        if (lownoisectr > 60) {
            break;
        } else {
            if (GetGraphBuffer(i) > threshold) {
                lownoisectr = 0;
                datalen = i - indx + 27;
            } else {
                lownoisectr++;
            }
        }
    }

    return datalen;
}

static uint32_t TexkomSearchMax(uint32_t indx, uint32_t len) {
    uint32_t res = 0;

    for (uint32_t i = 0; i < len; i++) {
        if (i + indx > g_GraphTraceLen)
            break;

        if (GetGraphBuffer(indx + i) > res)
            res = GetGraphBuffer(indx + i);
    }

    return res;
}

static bool TexkomCorrelate(uint32_t indx, uint32_t threshold) {
    if (indx < 2 || indx + 2 > g_GraphTraceLen)
        return false;

    uint32_t g1 = GetGraphBuffer(indx - 2);
    uint32_t g2 = GetGraphBuffer(indx - 1);
    uint32_t g3 = GetGraphBuffer(indx);
    uint32_t g4 = GetGraphBuffer(indx + 1);
    uint32_t g5 = GetGraphBuffer(indx + 2);

    return (
        (g3 > threshold) &&
        (g3 >= g2) && (g3 >= g1) && (g3 > g4) && (g3 > g5)
    );
}

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

    uint32_t samplesCount = 12000;
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ACQ_RAW_ADC, (uint8_t *)&samplesCount, sizeof(uint32_t));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_ACQ_RAW_ADC, &resp, 2500)) {
        PrintAndLogEx(WARNING, "(hf texkom reader) command execution time out");
        return PM3_ETIMEOUT;
    }

    uint32_t size = (resp.data.asDwords[0]);
    if (size > 0) {
        if (getSamples(samplesCount, true) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Get samples error");
            return PM3_EFAILED;
        };
    }

    uint32_t sindx = 0;
    while (sindx < samplesCount - 5) {
        sindx = TexkomSearchStart(sindx, TEXKOM_NOISE_THRESHOLD);
        if (sindx == 0 || sindx > samplesCount - 5)
            break;

        uint32_t slen = TexkomSearchLength(sindx, TEXKOM_NOISE_THRESHOLD);
        if (slen == 0)
            continue;

        uint32_t maxlvl = TexkomSearchMax(sindx, 1760);
        if (maxlvl < TEXKOM_NOISE_THRESHOLD) {
            sindx += 1700;
            continue;
        }

        uint32_t noiselvl = maxlvl / 5;
        if (noiselvl < TEXKOM_NOISE_THRESHOLD)
            noiselvl = TEXKOM_NOISE_THRESHOLD;

        PrintAndLogEx(WARNING, "--- indx: %d, len: %d, max: %d, noise: %d", sindx, slen, maxlvl, noiselvl);
      
        uint32_t implengths[256] = {};
        uint32_t implengthslen = 0;
        uint32_t impulseindx = 0;
        uint32_t impulsecnt = 0;
        for (uint32_t i = 0; i < slen; i++) {
            if (TexkomCorrelate(sindx + i, noiselvl)) {
                impulsecnt++;

                if (impulseindx != 0) {
                    if (implengthslen < 256)
                        implengths[implengthslen++] = sindx + i - impulseindx;
                }
                impulseindx = sindx + i;
            }
        }
        PrintAndLogEx(WARNING, "--- impulses: %d, lenarray: %d, [%d,%d]", impulsecnt, implengthslen, implengths[0], implengths[1]);

    }

    PrintAndLogEx(WARNING, "Texkom card is not found");

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
