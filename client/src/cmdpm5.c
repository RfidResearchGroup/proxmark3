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
// PM5 ICSD commands - talk to an ICS/ICSD device attached to the PM5's
// OTGFS1 port as a USB host CDC (ACM) device. The firmware side lives in
// armsrc/pm5_usb_host_cdc.c and is driven by CMD_PM5_ICSD_RAW / _RD.
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <string.h>

#include "cmdparser.h" // command_t
#include "cliparser.h"
#include "comms.h"
#include "ui.h"
#include "cmdpm5.h"
#include "pm3_cmd.h"

// How long to wait for the device to answer a single command line.
#define PM5_ICSD_TIMEOUT_MS 5000

static int CmdHelpPm5(const char *Cmd);
static int CmdHelpPm5Icsd(const char *Cmd);

static void pm5_icsd_print(const PacketResponseNG *resp) {
    if (resp->length == 0) {
        PrintAndLogEx(NORMAL, "(no response)");
        return;
    }
    uint16_t n = resp->length;
    if (n > PM3_CMD_DATA_SIZE) {
        n = PM3_CMD_DATA_SIZE;
    }
    char buf[PM3_CMD_DATA_SIZE + 1] = {0};
    memcpy(buf, resp->data.asBytes, n);
    buf[n] = '\0';
    PrintAndLogEx(SUCCESS, "%s", buf);
}

// Send an arbitrary command line via CMD_PM5_ICSD_RAW and print the reply.
static int pm5_icsd_send_raw(const char *cmdline) {
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_ICSD_RAW, (uint8_t *)cmdline, (uint16_t)strlen(cmdline));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_ICSD_RAW, &resp, PM5_ICSD_TIMEOUT_MS) == false) {
        PrintAndLogEx(WARNING, "timeout waiting for the ICSD device (is one attached as USB host?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "ICSD device did not respond");
        return resp.status;
    }
    pm5_icsd_print(&resp);
    return PM3_SUCCESS;
}

// Read a card frame via CMD_PM5_ICSD_RD (firmware sends "RD\r\n") and print it.
static int pm5_icsd_send_rd(void) {
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_ICSD_RD, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_ICSD_RD, &resp, PM5_ICSD_TIMEOUT_MS) == false) {
        PrintAndLogEx(WARNING, "timeout waiting for the ICSD device (is one attached as USB host?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "ICSD device did not respond");
        return resp.status;
    }
    pm5_icsd_print(&resp);
    return PM3_SUCCESS;
}

// Shared body for the no-argument subcommands.
static int pm5_icsd_noarg(const char *Cmd, const char *name, const char *cmdline) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, name, "Send a command to the attached ICSD device over USB host CDC.", name);
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return pm5_icsd_send_raw(cmdline);
}

static int CmdPm5IcsdWho(const char *Cmd) {
    return pm5_icsd_noarg(Cmd, "pm5 icsd who", "Who\r\n");
}

static int CmdPm5IcsdStatus(const char *Cmd) {
    static const char *gstate_names[] = {
        "USBH_IDLE", "USBH_PORT_EN", "USBH_ATTACHED", "USBH_DISCONNECT",
        "USBH_DEV_SPEED", "USBH_ENUMERATION", "USBH_CLASS_REQUEST", "USBH_CLASS",
        "USBH_CTRL_XFER", "USBH_USER_HANDLER", "USBH_SUSPEND", "USBH_SUSPENDED",
        "USBH_WAKEUP", "USBH_UNSUPPORT", "USBH_ERROR_STATE"
    };
    static const char *enum_names[] = {
        "ENUM_IDLE", "ENUM_GET_MIN_DESC", "ENUM_GET_FULL_DESC", "ENUM_SET_ADDR",
        "ENUM_GET_CFG", "ENUM_GET_FULL_CFG", "ENUM_GET_MFC_STRING",
        "ENUM_GET_PRODUCT_STRING", "ENUM_GET_SERIALNUM_STRING",
        "ENUM_SET_CONFIG", "ENUM_COMPLETE"
    };
    static const char *req_names[] = {
        "CONTROL_IDLE", "CONTROL_SETUP", "CONTROL_SETUP_WAIT",
        "CONTROL_DATA_IN", "CONTROL_DATA_IN_WAIT", "CONTROL_DATA_OUT",
        "CONTROL_DATA_OUT_WAIT", "CONTROL_STATUS_IN", "CONTROL_STATUS_IN_WAIT",
        "CONTROL_STATUS_OUT", "CONTROL_STATUS_OUT_WAIT", "CONTROL_ERROR",
        "CONTROL_STALL", "CONTROL_COMPLETE"
    };

    (void)Cmd;
    clearCommandBuffer();
    SendCommandNG(CMD_PM5_ICSD_STATUS, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_ICSD_STATUS, &resp, PM5_ICSD_TIMEOUT_MS) == false) {
        PrintAndLogEx(WARNING, "timeout waiting for ICSD host telemetry (is one attached as USB host?)");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS || resp.length < 7) {
        PrintAndLogEx(FAILED, "ICSD host telemetry unavailable");
        return resp.status;
    }

    const uint8_t *d = resp.data.asBytes;
    uint8_t initialized = d[0];
    uint8_t connected   = d[1];
    uint8_t global_state = d[2];
    uint8_t enum_state   = d[3];
    uint8_t req_state    = d[4];
    uint8_t conn_sts     = d[5];
    uint8_t port_enable  = d[6];

    PrintAndLogEx(SUCCESS, "ICSD USB host telemetry:");
    PrintAndLogEx(NORMAL, "  initialized : %s", initialized ? "yes" : "no");
    PrintAndLogEx(NORMAL, "  connected   : %s", connected ? "yes" : "no");
    PrintAndLogEx(NORMAL, "  global_state: %s (%u)",
                  global_state < 15 ? gstate_names[global_state] : "UNKNOWN", global_state);
    PrintAndLogEx(NORMAL, "  enum_state  : %s (%u)",
                  enum_state < 11 ? enum_names[enum_state] : "UNKNOWN", enum_state);
    PrintAndLogEx(NORMAL, "  req_state   : %s (%u)",
                  req_state < 14 ? req_names[req_state] : "UNKNOWN", req_state);
    PrintAndLogEx(NORMAL, "  conn_sts    : %u", conn_sts);
    PrintAndLogEx(NORMAL, "  port_enable : %u", port_enable);
    return PM3_SUCCESS;
}

static int CmdPm5IcsdClear(const char *Cmd) {
    return pm5_icsd_noarg(Cmd, "pm5 icsd clear", "CLEAR\r\n");
}

static int CmdPm5IcsdBits(const char *Cmd) {
    return pm5_icsd_noarg(Cmd, "pm5 icsd bits", "BITS\r\n");
}

static int CmdPm5IcsdBrute(const char *Cmd) {
    return pm5_icsd_noarg(Cmd, "pm5 icsd brute", "BRUTE\r\n");
}

static int CmdPm5IcsdRd(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "pm5 icsd rd",
                  "Read a card frame from the ICSD device (sends \"RD\").",
                  "pm5 icsd rd");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return pm5_icsd_send_rd();
}

static int CmdPm5IcsdDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "pm5 icsd dump",
                  "Dump a slot from the ICSD device (sends \"DUMP <slot>\").",
                  "pm5 icsd dump 1");
    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, NULL, "<slot>", "slot number to dump (0-7)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    struct arg_str *slot = arg_get_str(ctx, 1);

    char cmd[64];
    if (slot->count > 0) {
        snprintf(cmd, sizeof(cmd), "DUMP %s\r\n", slot->sval[0]);
    } else {
        snprintf(cmd, sizeof(cmd), "DUMP\r\n");
    }
    CLIParserFree(ctx);
    return pm5_icsd_send_raw(cmd);
}

static int CmdPm5IcsdMode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "pm5 icsd mode",
                  "Set the ICSD device mode (sends \"MODE <bridge|sniff>\").",
                  "pm5 icsd mode --mode bridge");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("m", "mode", "<bridge|sniff>", "operating mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    const char *mode = arg_get_str(ctx, 1)->sval[0];
    CLIParserFree(ctx);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "MODE %s\r\n", mode);
    return pm5_icsd_send_raw(cmd);
}

static int CmdPm5IcsdTimeout(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "pm5 icsd timeout",
                  "Set the ICSD device response timeout (sends \"TIMEOUT <ms>\").",
                  "pm5 icsd timeout --ms 500");
    void *argtable[] = {
        arg_param_begin,
        arg_str1("t", "ms", "<ms>", "timeout in milliseconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    const char *ms = arg_get_str(ctx, 1)->sval[0];
    CLIParserFree(ctx);

    char cmd[64];
    snprintf(cmd, sizeof(cmd), "TIMEOUT %s\r\n", ms);
    return pm5_icsd_send_raw(cmd);
}

static int CmdPm5IcsdInit(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "pm5 icsd init",
                  "Force CEP into USB host CDC mode for ICSD (no CC auto-detect wait).",
                  "pm5 icsd init");
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_PM5_ICSD_INIT, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_PM5_ICSD_INIT, &resp, PM5_ICSD_TIMEOUT_MS) == false) {
        PrintAndLogEx(WARNING, "timeout waiting for ICSD host init");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "ICSD host init failed");
        return resp.status;
    }
    PrintAndLogEx(SUCCESS, "ICSD USB host mode forced");
    return PM3_SUCCESS;
}

static int CmdPm5IcsdRaw(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "pm5 icsd raw",
                  "Send an arbitrary command string to the ICSD device.",
                  "pm5 icsd raw \"Who\\r\\n\"");
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, NULL, "<cmd>", "raw command string (e.g. \"Who\\r\\n\")"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    const char *line = arg_get_str(ctx, 1)->sval[0];
    CLIParserFree(ctx);
    return pm5_icsd_send_raw(line);
}

static command_t IcsdCommandTable[] = {
    {"help",    CmdHelpPm5Icsd,   AlwaysAvailable, "This help"},
    {"init",    CmdPm5IcsdInit,   IfPm5,           "Force CEP into USB host CDC mode"},
    {"who",     CmdPm5IcsdWho,    IfPm5,           "Identify the device (sends \"Who\")"},
    {"rd",      CmdPm5IcsdRd,     IfPm5,           "Read a card frame (sends \"RD\")"},
    {"status",  CmdPm5IcsdStatus, IfPm5,           "Query device status (sends \"STATUS\")"},
    {"dump",    CmdPm5IcsdDump,   IfPm5,           "Dump a slot (sends \"DUMP <slot>\")"},
    {"clear",   CmdPm5IcsdClear,  IfPm5,           "Clear device state (sends \"CLEAR\")"},
    {"mode",    CmdPm5IcsdMode,   IfPm5,           "Set mode (sends \"MODE <bridge|sniff>\")"},
    {"timeout", CmdPm5IcsdTimeout, IfPm5,           "Set device timeout (sends \"TIMEOUT <ms>\")"},
    {"bits",    CmdPm5IcsdBits,   IfPm5,           "Query bit config (sends \"BITS\")"},
    {"brute",   CmdPm5IcsdBrute,  IfPm5,           "Start brute force (sends \"BRUTE\")"},
    {"raw",     CmdPm5IcsdRaw,    IfPm5,           "Send an arbitrary command string"},
    {NULL, NULL, NULL, NULL}
};

static int CmdPm5Icsd(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(IcsdCommandTable, Cmd);
}

static int CmdHelpPm5Icsd(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(IcsdCommandTable);
    return PM3_SUCCESS;
}

static command_t Pm5CommandTable[] = {
    {"help", CmdHelpPm5, AlwaysAvailable, "This help"},
    {"icsd", CmdPm5Icsd, IfPm5,          "{ ICSD (USB host CDC) commands... }"},
    {NULL, NULL, NULL, NULL}
};

int CmdPm5(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(Pm5CommandTable, Cmd);
}

static int CmdHelpPm5(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(Pm5CommandTable);
    return PM3_SUCCESS;
}
