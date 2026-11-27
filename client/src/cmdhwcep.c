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
// CEP (Type-C Extended Port) commands. `hw cep logic`'s fetch/decode/render
// helpers (VCD, table) are in cmdhwceplogic.c - this file is just the
// command table and CLI argument handling.
//-----------------------------------------------------------------------------

#include "cmdparser.h" // command_t
#include "cliparser.h"
#include "comms.h"
#include "ui.h"
#include "cmdhwcep.h"
#include "cmdhwceplogic.h"
#include "cmdhw.h"
#include "pm3_cmd.h"
#include "util.h"      // FILE_PATH_SIZE

static int CmdCepLogicStart(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw cep logic start",
                  "Start recording CEP bus traffic (PM5 built with PLATFORM_EXTRAS=CEPLOGIC): every SPI1 MOSI/MISO byte\n"
                  "and USART1 handshake byte, each with a capture timestamp. Does not\n"
                  "clear a previous capture - use 'hw cep logic clear' first for a fresh one.",
                  "hw cep logic start\n"
                  "hw cep logic start -i   --> skip FAP-style idle MOSI polls (0xFF/0x00), so the\n"
                  "                          4096-entry ring lasts for real traffic, not filler");
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("i", "skipidle", "don't record 0xFF/0x00 MOSI idle-poll filler"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool skip_idle = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    cep_logic_status_t st;
    int ret = cep_logic_ctrl(CEP_LOGIC_ACTION_START, skip_idle, &st);
    if (ret == PM3_SUCCESS) {
        cep_logic_print_status(&st);
    }
    return ret;
}

static int CmdCepLogicStop(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw cep logic stop", "Stop recording CEP bus traffic (PM5 built with PLATFORM_EXTRAS=CEPLOGIC).",
                  "hw cep logic stop");
    void *argtable[] = {arg_param_begin, arg_param_end};
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    cep_logic_status_t st;
    int ret = cep_logic_ctrl(CEP_LOGIC_ACTION_STOP, false, &st);
    if (ret == PM3_SUCCESS) {
        cep_logic_print_status(&st);
    }
    return ret;
}

static int CmdCepLogicClear(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw cep logic clear", "Stop recording and discard the captured trace (PM5 built with PLATFORM_EXTRAS=CEPLOGIC).",
                  "hw cep logic clear");
    void *argtable[] = {arg_param_begin, arg_param_end};
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    cep_logic_status_t st;
    int ret = cep_logic_ctrl(CEP_LOGIC_ACTION_CLEAR, false, &st);
    if (ret == PM3_SUCCESS) {
        cep_logic_print_status(&st);
    }
    return ret;
}

static int CmdCepLogicStatus(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw cep logic status", "Show the CEP bus logger's state (PM5 built with PLATFORM_EXTRAS=CEPLOGIC).",
                  "hw cep logic status");
    void *argtable[] = {arg_param_begin, arg_param_end};
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    cep_logic_status_t st;
    int ret = cep_logic_ctrl(CEP_LOGIC_ACTION_STATUS, false, &st);
    if (ret == PM3_SUCCESS) {
        cep_logic_print_status(&st);
    }
    return ret;
}

static int CmdCepLogicFetch(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw cep logic fetch",
                  "Pull the recorded CEP bus trace (PM5 built with PLATFORM_EXTRAS=CEPLOGIC). Byte/timestamp resolution -\n"
                  "every SPI1 MOSI/MISO byte and USART1 handshake byte PM5 itself moved,\n"
                  "with a capture timestamp - not an electrical edge-level capture.\n"
                  "Plain run just prints the count; add -a for the decoded data table,\n"
                  "-f to save a VCD file for PulseView/GTKWave, and/or -g to load the\n"
                  "trace into this client's own graph window (zoom/pan, decoded\n"
                  "commands/responses/handshakes as markers).",
                  "hw cep logic fetch             --> just show how many entries\n"
                  "hw cep logic fetch -a          --> print the decoded data table\n"
                  "hw cep logic fetch -f trace     --> save for PulseView/GTKWave\n"
                  "hw cep logic fetch -g          --> load into the graph window\n"
                  "hw cep logic fetch -a -f trace  --> both");
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "save the trace as a VCD file"),
        arg_lit0("a", "ascii", "print the decoded data table"),
        arg_lit0("g", "graph", "load into the graph window, with decoded markers"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int vcdlen = 0;
    char vcdfile[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)vcdfile, sizeof(vcdfile), &vcdlen);
    bool do_ascii = arg_get_lit(ctx, 2);
    bool do_graph = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    cep_logic_entry_t *entries = NULL;
    uint32_t n = 0;
    int ret = cep_logic_fetch_all(&entries, &n);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    PrintAndLogEx(SUCCESS, "fetched " _YELLOW_("%u") " entries", n);

    if (do_ascii) {
        cep_logic_print_table(entries, n);
    }
    if (vcdlen > 0) {
        cep_logic_write_vcd(vcdfile, entries, n);
    }
    if (do_graph) {
        cep_logic_plot(entries, n);
    }

    free(entries);
    return PM3_SUCCESS;
}

static int CmdHelpCepLogic(const char *Cmd);

// Gated on IfCep, not a dedicated capability bit: CEPLOGIC is opt-in and
// capabilities_t is shared by every PM5 build, so a bit here would bump
// CAPABILITIES_VERSION for builds that never asked for it (breaks anything
// pinning an exact version, e.g. the Flipper FAP). Firmware without
// PLATFORM_EXTRAS=CEPLOGIC replies PM3_ENOTIMPL instead; see cep_logic_ctrl().
static command_t CepLogicCommandTable[] = {
    {"help",   CmdHelpCepLogic,  AlwaysAvailable, "This help"},
    {"start",  CmdCepLogicStart, IfCep, "Start recording CEP bus traffic"},
    {"stop",   CmdCepLogicStop,  IfCep, "Stop recording"},
    {"clear",  CmdCepLogicClear, IfCep, "Stop and discard the captured trace"},
    {"status", CmdCepLogicStatus, IfCep, "Show recorder state (running/entries/overflow)"},
    {"fetch",  CmdCepLogicFetch, IfCep, "Pull the trace, as a VCD file and/or a plot"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelpCepLogic(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CepLogicCommandTable);
    return PM3_SUCCESS;
}

static int CmdCepLogic(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CepLogicCommandTable, Cmd);
}

static int CmdHelpCep(const char *Cmd);

static command_t CepCommandTable[] = {
    {"help",  CmdHelpCep, AlwaysAvailable, "This help"},
    {"logic", CmdCepLogic, IfCep, "{ CEP bus logic logger: start/stop/status/fetch (PLATFORM_EXTRAS=CEPLOGIC) }"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelpCep(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CepCommandTable);
    return PM3_SUCCESS;
}

int CmdCep(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CepCommandTable, Cmd);
}
