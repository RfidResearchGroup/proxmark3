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
// Hardware commands
// low-level hardware control
//-----------------------------------------------------------------------------

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "comms.h"
#include "usart_defs.h"
#include "ui.h"
#include "cmdhw.h"
#include "cmddata.h"
#include "commonutil.h"
#include "pm3_cmd.h"
#include "pmflash.h"      // rdv40validation_t
#include "cmdflashmem.h"  // get_signature..

static int CmdHelp(const char *Cmd);

static void lookupChipID(uint32_t iChipID, uint32_t mem_used) {
    char asBuff[120];
    memset(asBuff, 0, sizeof(asBuff));
    uint32_t mem_avail = 0;
    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Hardware") " ]");

    switch (iChipID) {
        case 0x270B0A40:
            sprintf(asBuff, "AT91SAM7S512 Rev A");
            break;
        case 0x270B0A4F:
            sprintf(asBuff, "AT91SAM7S512 Rev B");
            break;
        case 0x270D0940:
            sprintf(asBuff, "AT91SAM7S256 Rev A");
            break;
        case 0x270B0941:
            sprintf(asBuff, "AT91SAM7S256 Rev B");
            break;
        case 0x270B0942:
            sprintf(asBuff, "AT91SAM7S256 Rev C");
            break;
        case 0x270B0943:
            sprintf(asBuff, "AT91SAM7S256 Rev D");
            break;
        case 0x270C0740:
            sprintf(asBuff, "AT91SAM7S128 Rev A");
            break;
        case 0x270A0741:
            sprintf(asBuff, "AT91SAM7S128 Rev B");
            break;
        case 0x270A0742:
            sprintf(asBuff, "AT91SAM7S128 Rev C");
            break;
        case 0x270A0743:
            sprintf(asBuff, "AT91SAM7S128 Rev D");
            break;
        case 0x27090540:
            sprintf(asBuff, "AT91SAM7S64 Rev A");
            break;
        case 0x27090543:
            sprintf(asBuff, "AT91SAM7S64 Rev B");
            break;
        case 0x27090544:
            sprintf(asBuff, "AT91SAM7S64 Rev C");
            break;
        case 0x27080342:
            sprintf(asBuff, "AT91SAM7S321 Rev A");
            break;
        case 0x27080340:
            sprintf(asBuff, "AT91SAM7S32 Rev A");
            break;
        case 0x27080341:
            sprintf(asBuff, "AT91SAM7S32 Rev B");
            break;
        case 0x27050241:
            sprintf(asBuff, "AT9SAM7S161 Rev A");
            break;
        case 0x27050240:
            sprintf(asBuff, "AT91SAM7S16 Rev A");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= uC: " _YELLOW_("%s"), asBuff);

    switch ((iChipID & 0xE0) >> 5) {
        case 1:
            sprintf(asBuff, "ARM946ES");
            break;
        case 2:
            sprintf(asBuff, "ARM7TDMI");
            break;
        case 4:
            sprintf(asBuff, "ARM920T");
            break;
        case 5:
            sprintf(asBuff, "ARM926EJS");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Embedded Processor: %s", asBuff);

    switch ((iChipID & 0xF0000) >> 16) {
        case 1:
            sprintf(asBuff, "1K bytes");
            break;
        case 2:
            sprintf(asBuff, "2K bytes");
            break;
        case 3:
            sprintf(asBuff, "6K bytes");
            break;
        case 4:
            sprintf(asBuff, "112K bytes");
            break;
        case 5:
            sprintf(asBuff, "4K bytes");
            break;
        case 6:
            sprintf(asBuff, "80K bytes");
            break;
        case 7:
            sprintf(asBuff, "160K bytes");
            break;
        case 8:
            sprintf(asBuff, "8K bytes");
            break;
        case 9:
            sprintf(asBuff, "16K bytes");
            break;
        case 10:
            sprintf(asBuff, "32K bytes");
            break;
        case 11:
            sprintf(asBuff, "64K bytes");
            break;
        case 12:
            sprintf(asBuff, "128K bytes");
            break;
        case 13:
            sprintf(asBuff, "256K bytes");
            break;
        case 14:
            sprintf(asBuff, "96K bytes");
            break;
        case 15:
            sprintf(asBuff, "512K bytes");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Internal SRAM size: %s", asBuff);

    switch ((iChipID & 0xFF00000) >> 20) {
        case 0x19:
            sprintf(asBuff, "AT91SAM9xx Series");
            break;
        case 0x29:
            sprintf(asBuff, "AT91SAM9XExx Series");
            break;
        case 0x34:
            sprintf(asBuff, "AT91x34 Series");
            break;
        case 0x37:
            sprintf(asBuff, "CAP7 Series");
            break;
        case 0x39:
            sprintf(asBuff, "CAP9 Series");
            break;
        case 0x3B:
            sprintf(asBuff, "CAP11 Series");
            break;
        case 0x40:
            sprintf(asBuff, "AT91x40 Series");
            break;
        case 0x42:
            sprintf(asBuff, "AT91x42 Series");
            break;
        case 0x55:
            sprintf(asBuff, "AT91x55 Series");
            break;
        case 0x60:
            sprintf(asBuff, "AT91SAM7Axx Series");
            break;
        case 0x61:
            sprintf(asBuff, "AT91SAM7AQxx Series");
            break;
        case 0x63:
            sprintf(asBuff, "AT91x63 Series");
            break;
        case 0x70:
            sprintf(asBuff, "AT91SAM7Sxx Series");
            break;
        case 0x71:
            sprintf(asBuff, "AT91SAM7XCxx Series");
            break;
        case 0x72:
            sprintf(asBuff, "AT91SAM7SExx Series");
            break;
        case 0x73:
            sprintf(asBuff, "AT91SAM7Lxx Series");
            break;
        case 0x75:
            sprintf(asBuff, "AT91SAM7Xxx Series");
            break;
        case 0x92:
            sprintf(asBuff, "AT91x92 Series");
            break;
        case 0xF0:
            sprintf(asBuff, "AT75Cxx Series");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Architecture identifier: %s", asBuff);

    switch ((iChipID & 0x70000000) >> 28) {
        case 0:
            sprintf(asBuff, "ROM");
            break;
        case 1:
            sprintf(asBuff, "ROMless or on-chip Flash");
            break;
        case 2:
            sprintf(asBuff, "Embedded flash memory");
            break;
        case 3:
            sprintf(asBuff, "ROM and Embedded flash memory\nNVPSIZ is ROM size\nNVPSIZ2 is Flash size");
            break;
        case 4:
            sprintf(asBuff, "SRAM emulating ROM");
            break;
    }
    switch ((iChipID & 0xF00) >> 8) {
        case 0:
            mem_avail = 0;
            break;
        case 1:
            mem_avail = 8;
            break;
        case 2:
            mem_avail = 16;
            break;
        case 3:
            mem_avail = 32;
            break;
        case 5:
            mem_avail = 64;
            break;
        case 7:
            mem_avail = 128;
            break;
        case 9:
            mem_avail = 256;
            break;
        case 10:
            mem_avail = 512;
            break;
        case 12:
            mem_avail = 1024;
            break;
        case 14:
            mem_avail = 2048;
            break;
    }

    PrintAndLogEx(NORMAL, "  --= %s " _YELLOW_("%uK") " bytes ( " _YELLOW_("%2.0f%%") " used )"
                  , asBuff
                  , mem_avail
                  , mem_avail == 0 ? 0.0f : (float)mem_used / (mem_avail * 1024) * 100
                 );

    /*
    switch ((iChipID & 0xF000) >> 12) {
        case 0:
            sprintf(asBuff, "None");
            break;
        case 1:
            sprintf(asBuff, "8K bytes");
            break;
        case 2:
            sprintf(asBuff, "16K bytes");
            break;
        case 3:
            sprintf(asBuff, "32K bytes");
            break;
        case 5:
            sprintf(asBuff, "64K bytes");
            break;
        case 7:
            sprintf(asBuff, "128K bytes");
            break;
        case 9:
            sprintf(asBuff, "256K bytes");
            break;
        case 10:
            sprintf(asBuff, "512K bytes");
            break;
        case 12:
            sprintf(asBuff, "1024K bytes");
            break;
        case 14:
            sprintf(asBuff, "2048K bytes");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Second nonvolatile program memory size: %s", asBuff);
    */
}

static int CmdDbg(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw dbg",
                  "Set device side debug level output.\n"
                  "Note: option -4, this option may cause malfunction itself",
                  "hw dbg -1\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("0", NULL, "no debug messages"),
        arg_lit0("1", NULL, "error messages"),
        arg_lit0("2", NULL, "plus information messages"),
        arg_lit0("3", NULL, "plus debug messages"),
        arg_lit0("4", NULL, "print even debug messages in timing critical functions"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lv0 = arg_get_lit(ctx, 1);
    bool lv1 = arg_get_lit(ctx, 2);
    bool lv2 = arg_get_lit(ctx, 3);
    bool lv3 = arg_get_lit(ctx, 4);
    bool lv4 = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if ((lv0 + lv1 + lv2 + lv3 + lv4) > 1) {
        PrintAndLogEx(INFO, "Can only set one debug level");
        return PM3_EINVARG;
    }

    uint8_t dbg = 0;
    if (lv0)
        dbg = 0;
    else if (lv1)
        dbg = 1;
    else if (lv2)
        dbg = 2;
    else if (lv3)
        dbg = 3;
    else if (lv4)
        dbg = 4;

    SendCommandNG(CMD_SET_DBGMODE, &dbg, sizeof(dbg));
    return PM3_SUCCESS;
}

static int CmdDetectReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw detectreader",
                  "Start to detect presences of reader field",
                  "hw detectreader -L\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("L", "LF", "detect low frequency 125/134 kHz"),
        arg_lit0("H", "HF", "detect high frequency 13.56 MHZ"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lf = arg_get_lit(ctx, 1);
    bool hf = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if ((lf + hf) > 1) {
        PrintAndLogEx(INFO, "Can only set one frequency");
        return PM3_EINVARG;
    }

    uint8_t arg = 0;
    if (lf)
        arg = 1;
    else if (hf)
        arg = 2;

    PrintAndLogEx(INFO, "press pm3 button to change modes and finally exit");
    clearCommandBuffer();
    SendCommandNG(CMD_LISTEN_READER_FIELD, (uint8_t *)&arg, sizeof(arg));
    return PM3_SUCCESS;
}

// ## FPGA Control
static int CmdFPGAOff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw fpgaoff",
                  "Turn of fpga and antenna field",
                  "hw fpgaoff\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_FPGA_MAJOR_MODE_OFF, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdLCD(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw lcd",
                  "Send command/data to LCD",
                  "hw lcd -r AA -c 03    -> sends 0xAA three times"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1("r", "raw", "<hex>",  "data "),
        arg_int1("c", "cnt", "<dec>",  "number of times to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    int r_len = 0;
    uint8_t raw[1] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &r_len);
    int j = arg_get_int(ctx, 2);
    if (j < 1) {
        PrintAndLogEx(WARNING, "Count must be larger than zero");
        return PM3_EINVARG;
    }

    while (j--) {
        clearCommandBuffer();
        SendCommandMIX(CMD_LCD, raw[0], 0, 0, NULL, 0);
    }
    return PM3_SUCCESS;
}

static int CmdLCDReset(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw lcdreset",
                  "Hardware reset LCD",
                  "hw lcdreset\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_LCD_RESET, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdReadmem(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw readmem",
                  "Read memory at decimal address from ARM chip flash.",
                  "hw readmem -a 10000"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("a", "adr", "<dec>", "address to read"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t address = arg_get_u32(ctx, 1);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_READ_MEM, (uint8_t *)&address, sizeof(address));
    return PM3_SUCCESS;
}

static int CmdReset(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw reset",
                  "Reset the Proxmark3 device.",
                  "hw reset"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_HARDWARE_RESET, NULL, 0);
    PrintAndLogEx(INFO, "Proxmark3 has been reset.");
    return PM3_SUCCESS;
}

/*
 * Sets the divisor for LF frequency clock: lets the user choose any LF frequency below
 * 600kHz.
 */
static int CmdSetDivisor(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw setlfdivisor",
                  "Drive LF antenna at 12 MHz / (divisor + 1).",
                  "hw setlfdivisor -d 88"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("d", "div", "<dec>", "19 - 255 divisor value (def 95)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t arg = arg_get_u32_def(ctx, 1, 95);
    CLIParserFree(ctx);

    if (arg < 19) {
        PrintAndLogEx(ERR, "Divisor must be between" _YELLOW_("19") " and " _YELLOW_("255"));
        return PM3_EINVARG;
    }
    // 12 000 000 (12MHz)
    clearCommandBuffer();
    SendCommandNG(CMD_LF_SET_DIVISOR, (uint8_t *)&arg, sizeof(arg));
    PrintAndLogEx(SUCCESS, "Divisor set, expected " _YELLOW_("%.1f")" kHz", ((double)12000 / (arg + 1)));
    return PM3_SUCCESS;
}

static int CmdSetMux(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw setmux",
                  "Set the ADC mux to a specific value",
                  "hw setmux --hipkd    -> set HIGH PEAK\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "lopkd", "low peak"),
        arg_lit0(NULL, "loraw", "low raw"),
        arg_lit0(NULL, "hipkd", "high peak"),
        arg_lit0(NULL, "hiraw", "high raw"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lopkd = arg_get_lit(ctx, 1);
    bool loraw = arg_get_lit(ctx, 2);
    bool hipkd = arg_get_lit(ctx, 3);
    bool hiraw = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if ((lopkd + loraw + hipkd + hiraw) > 1) {
        PrintAndLogEx(INFO, "Can only set one mux");
        return PM3_EINVARG;
    }

#ifdef WITH_FPC_USART
    if (loraw || hiraw) {
        PrintAndLogEx(INFO, "this ADC mux option is unavailable on RDV4 compiled with FPC USART");
        return PM3_EINVARG;
    }
#endif

    uint8_t arg = 0;
    if (lopkd)
        arg = 0;
    else if (loraw)
        arg = 1;
    else if (hipkd)
        arg = 2;
    else if (hiraw)
        arg = 3;

    clearCommandBuffer();
    SendCommandNG(CMD_SET_ADC_MUX, (uint8_t *)&arg, sizeof(arg));
    return PM3_SUCCESS;
}

static int CmdStandalone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw standalone",
                  "Start standalone mode",
                  "hw standalone       -> start \n"
                  "hw standalone -a 1  -> start and send arg 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("a", "arg", "<dec>", "argument byte"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t arg = arg_get_u32(ctx, 1);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_STANDALONE, (uint8_t *)&arg, sizeof(arg));
    return PM3_SUCCESS;
}

static int CmdTune(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw tune",
                  "Measure antenna tuning",
                  "hw tune"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return CmdTuneSamples(Cmd);
}

static int CmdVersion(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw version",
                  "Show version information about the client and the connected Proxmark3",
                  "hw version"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    pm3_version(true, false);
    return PM3_SUCCESS;
}

static int CmdStatus(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw status",
                  "Show runtime status information about the connected Proxmark3",
                  "hw status"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_STATUS, NULL, 0);
    if (WaitForResponseTimeout(CMD_STATUS, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "Status command timeout. Communication speed test timed out");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

int handle_tearoff(tearoff_params_t *params, bool verbose) {

    if (params == NULL)
        return PM3_EINVARG;

    clearCommandBuffer();
    SendCommandNG(CMD_SET_TEAROFF, (uint8_t *)params, sizeof(tearoff_params_t));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SET_TEAROFF, &resp, 500) == false) {
        PrintAndLogEx(WARNING, "Tear-off command timeout.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        if (params->delay_us > 0 && verbose)
            PrintAndLogEx(INFO, "Tear-off hook configured with delay of " _GREEN_("%i us"), params->delay_us);

        if (params->on && verbose)
            PrintAndLogEx(INFO, "Tear-off hook " _GREEN_("enabled"));

        if (params->off && verbose)
            PrintAndLogEx(INFO, "Tear-off hook " _RED_("disabled"));
    } else if (verbose)
        PrintAndLogEx(WARNING, "Tear-off command failed.");
    return resp.status;
}

static int CmdTearoff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw tearoff",
                  "Configure a tear-off hook for the next write command supporting tear-off\n"
                  "After having been triggered by a write command, the tear-off hook is deactivated\n"
                  "Delay (in us) must be between 1 and 43000 (43ms). Precision is about 1/3us.",
                  "hw tearoff --delay 1200 --> define delay of 1200us\n"
                  "hw tearoff --on --> (re)activate a previously defined delay\n"
                  "hw tearoff --off --> deactivate a previously activated but not yet triggered hook\n");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "delay", "<dec>", "Delay in us before triggering tear-off, must be between 1 and 43000"),
        arg_lit0(NULL, "on", "Activate tear-off hook"),
        arg_lit0(NULL, "off", "Deactivate tear-off hook"),
        arg_lit0("s", "silent", "less verbose output"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, false);
    tearoff_params_t params;
    int delay = arg_get_int_def(ctx, 1, -1);
    params.on = arg_get_lit(ctx, 2);
    params.off = arg_get_lit(ctx, 3);
    bool silent = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (delay != -1) {
        if ((delay < 1) || (delay > 43000)) {
            PrintAndLogEx(WARNING, "You can't set delay out of 1..43000 range!");
            return PM3_EINVARG;
        }
    } else {
        delay = 0; // will be ignored by ARM
    }

    params.delay_us = delay;
    if (params.on && params.off) {
        PrintAndLogEx(WARNING, "You can't set both --on and --off!");
        return PM3_EINVARG;
    }

    return handle_tearoff(&params, !silent);
}

static int CmdTia(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw tia",
                  "Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider",
                  "hw tia"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "Triggering new Timing Interval Acquisition (TIA)...");
    clearCommandBuffer();
    SendCommandNG(CMD_TIA, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_TIA, &resp, 2000) == false) {
        PrintAndLogEx(WARNING, "TIA command timeout. You probably need to unplug the Proxmark3.");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(INFO, "TIA done.");
    return PM3_SUCCESS;
}

static int CmdPing(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw ping",
                  "Test if the Proxmark3 is responsive",
                  "hw ping\n"
                  "hw ping --len 32"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("l", "len", "<dec>", "length of payload to send"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint32_t len = arg_get_u32(ctx, 1);
    CLIParserFree(ctx);

    if (len > PM3_CMD_DATA_SIZE)
        len = PM3_CMD_DATA_SIZE;

    if (len) {
        PrintAndLogEx(INFO, "Ping sent with payload len " _YELLOW_("%d"), len);
    } else {
        PrintAndLogEx(INFO, "Ping sent");
    }

    clearCommandBuffer();
    PacketResponseNG resp;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};

    for (uint16_t i = 0; i < len; i++)
        data[i] = i & 0xFF;

    SendCommandNG(CMD_PING, data, len);
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000)) {
        if (len) {
            bool error = (memcmp(data, resp.data.asBytes, len) != 0);
            PrintAndLogEx((error) ? ERR : SUCCESS, "Ping response " _GREEN_("received") " and content is %s", error ? _RED_("NOT ok") : _GREEN_("OK"));
        } else {
            PrintAndLogEx(SUCCESS, "Ping response " _GREEN_("received"));
        }
    } else
        PrintAndLogEx(WARNING, "Ping response " _RED_("timeout"));
    return PM3_SUCCESS;
}

static int CmdConnect(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw connect",
                  "Connects to a Proxmark3 device via specified serial port.\n"
                  "Baudrate here is only for physical UART or UART-BT, NOT for USB-CDC or blue shark add-on",
                  "hw connect -p "SERIAL_PORT_EXAMPLE_H"\n"
                  "hw connect -p "SERIAL_PORT_EXAMPLE_H" -b 115200"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "port", NULL, "Serial port to connect to, else retry the last used one"),
        arg_u64_0("b", "baud", "<dec>", "Baudrate"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int p_len = FILE_PATH_SIZE;
    char port[FILE_PATH_SIZE] = {0};
    CLIGetStrWithReturn(ctx, 1, (uint8_t *)port, &p_len);
    uint32_t baudrate = arg_get_u32_def(ctx, 2, USART_BAUD_RATE);
    CLIParserFree(ctx);

    if (baudrate == 0) {
        PrintAndLogEx(WARNING, "Baudrate can't be zero");
        return PM3_EINVARG;
    }

    // default back to previous used serial port
    if (strlen(port) == 0) {
        if (strlen(g_conn.serial_port_name) == 0) {
            PrintAndLogEx(WARNING, "Must specify a serial port");
            return PM3_EINVARG;
        }
        memcpy(port, g_conn.serial_port_name, sizeof(port));
    }

    if (g_session.pm3_present) {
        CloseProxmark(g_session.current_device);
    }

    // 10 second timeout
    OpenProxmark(&g_session.current_device, port, false, 10, false, baudrate);

    if (g_session.pm3_present && (TestProxmark(g_session.current_device) != PM3_SUCCESS)) {
        PrintAndLogEx(ERR, _RED_("ERROR:") " cannot communicate with the Proxmark3\n");
        CloseProxmark(g_session.current_device);
        return PM3_ENOTTY;
    }
    return PM3_SUCCESS;
}

static int CmdBreak(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw break",
                  "send break loop package",
                  "hw break\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    return PM3_SUCCESS;
}


static command_t CommandTable[] = {
    {"-------------", CmdHelp,         AlwaysAvailable, "----------------------- " _CYAN_("Hardware") " -----------------------"},
    {"help",          CmdHelp,         AlwaysAvailable, "This help"},
    {"break",         CmdBreak,        IfPm3Present,    "Send break loop usb command"},
    {"connect",       CmdConnect,      AlwaysAvailable, "Connect Proxmark3 to serial port"},
    {"dbg",           CmdDbg,          IfPm3Present,    "Set Proxmark3 debug level"},
    {"detectreader",  CmdDetectReader, IfPm3Present,    "Detect external reader field"},
    {"fpgaoff",       CmdFPGAOff,      IfPm3Present,    "Set FPGA off"},
    {"lcd",           CmdLCD,          IfPm3Lcd,        "Send command/data to LCD"},
    {"lcdreset",      CmdLCDReset,     IfPm3Lcd,        "Hardware reset LCD"},
    {"ping",          CmdPing,         IfPm3Present,    "Test if the Proxmark3 is responsive"},
    {"readmem",       CmdReadmem,      IfPm3Present,    "Read memory at decimal address from flash"},
    {"reset",         CmdReset,        IfPm3Present,    "Reset the Proxmark3"},
    {"setlfdivisor",  CmdSetDivisor,   IfPm3Present,    "Drive LF antenna at 12MHz / (divisor + 1)"},
    {"setmux",        CmdSetMux,       IfPm3Present,    "Set the ADC mux to a specific value"},
    {"standalone",    CmdStandalone,   IfPm3Present,    "Jump to the standalone mode"},
    {"status",        CmdStatus,       IfPm3Present,    "Show runtime status information about the connected Proxmark3"},
    {"tearoff",       CmdTearoff,      IfPm3Present,    "Program a tearoff hook for the next command supporting tearoff"},
    {"tia",           CmdTia,          IfPm3Present,    "Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider"},
    {"tune",          CmdTune,         IfPm3Present,    "Measure antenna tuning"},
    {"version",       CmdVersion,      AlwaysAvailable, "Show version information about the client and the connected Proxmark3, if any"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHW(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

void pm3_version(bool verbose, bool oneliner) {

#if defined(__MINGW64__)
# define PM3CLIENTCOMPILER "MinGW-w64 "
#elif defined(__MINGW32__)
# define PM3CLIENTCOMPILER "MinGW "
#elif defined(__clang__)
# define PM3CLIENTCOMPILER "Clang/LLVM "
#elif defined(__GNUC__) || defined(__GNUG__)
# define PM3CLIENTCOMPILER "GCC "
#else
# define PM3CLIENTCOMPILER "unknown compiler "
#endif

#if defined(__APPLE__) || defined(__MACH__)
# define PM3HOSTOS "OSX"
#elif defined(__ANDROID__) || defined(ANDROID)
// must be tested before __linux__
# define PM3HOSTOS "Android"
#elif defined(__linux__)
# define PM3HOSTOS "Linux"
#elif defined(__FreeBSD__)
# define PM3HOSTOS "FreeBSD"
#elif defined(__NetBSD__)
# define PM3HOSTOS "NetBSD"
#elif defined(__OpenBSD__)
# define PM3HOSTOS "OpenBSD"
#elif defined(__CYGWIN__)
# define PM3HOSTOS "Cygwin"
#elif defined(_WIN64) || defined(__WIN64__)
// must be tested before _WIN32
# define PM3HOSTOS "Windows (64b)"
#elif defined(_WIN32) || defined(__WIN32__)
# define PM3HOSTOS "Windows (32b)"
#else
# define PM3HOSTOS "unknown"
#endif

#if defined(__x86_64__)
# define PM3HOSTARCH "x86_64"
#elif defined(__i386__)
# define PM3HOSTARCH "x86"
#elif defined(__aarch64__)
# define PM3HOSTARCH "aarch64"
#elif defined(__arm__)
# define PM3HOSTARCH "arm"
#elif defined(__powerpc64__)
# define PM3HOSTARCH "powerpc64"
#elif defined(__mips__)
# define PM3HOSTARCH "mips"
#else
# define PM3HOSTARCH "unknown"
#endif

    char temp[PM3_CMD_DATA_SIZE - 12]; // same limit as for ARM image

    if (oneliner) {
        // For "proxmark3 -v", simple printf, avoid logging
        FormatVersionInformation(temp, sizeof(temp), "Client: ", &g_version_information);
        PrintAndLogEx(NORMAL, "%s compiled with " PM3CLIENTCOMPILER __VERSION__ " OS:" PM3HOSTOS " ARCH:" PM3HOSTARCH "\n", temp);
        return;
    }

    if (!verbose)
        return;

    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Proxmark3 RFID instrument") " ]");
    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("CLIENT") " ]");
    FormatVersionInformation(temp, sizeof(temp), "  ", &g_version_information);
    PrintAndLogEx(NORMAL, "%s", temp);
    PrintAndLogEx(NORMAL, "  compiled with............. " PM3CLIENTCOMPILER __VERSION__);
    PrintAndLogEx(NORMAL, "  platform.................. " PM3HOSTOS " / " PM3HOSTARCH);
#if defined(HAVE_READLINE)
    PrintAndLogEx(NORMAL, "  Readline support.......... " _GREEN_("present"));
#elif defined(HAVE_LINENOISE)
    PrintAndLogEx(NORMAL, "  Linenoise support......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Readline/Linenoise support." _YELLOW_("absent"));
#endif
#ifdef HAVE_GUI
    PrintAndLogEx(NORMAL, "  QT GUI support............ " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  QT GUI support............ " _YELLOW_("absent"));
#endif
#ifdef HAVE_BLUEZ
    PrintAndLogEx(NORMAL, "  native BT support......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  native BT support......... " _YELLOW_("absent"));
#endif
#ifdef HAVE_PYTHON
    PrintAndLogEx(NORMAL, "  Python script support..... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Python script support..... " _YELLOW_("absent"));
#endif
#ifdef HAVE_LUA_SWIG
    PrintAndLogEx(NORMAL, "  Lua SWIG support.......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Lua SWIG support.......... " _YELLOW_("absent"));
#endif
#ifdef HAVE_PYTHON_SWIG
    PrintAndLogEx(NORMAL, "  Python SWIG support....... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Python SWIG support....... " _YELLOW_("absent"));
#endif

    if (g_session.pm3_present) {
        PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("PROXMARK3") " ]");

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_VERSION, NULL, 0);

        if (WaitForResponseTimeout(CMD_VERSION, &resp, 1000)) {
            if (IfPm3Rdv4Fw()) {

                bool is_genuine_rdv4 = false;
                // validate signature data
                rdv40_validation_t mem;
                if (rdv4_get_signature(&mem) == PM3_SUCCESS) {
                    if (rdv4_validate(&mem) == PM3_SUCCESS) {
                        is_genuine_rdv4 = true;
                    }
                }

                PrintAndLogEx(NORMAL, "  device.................... %s", (is_genuine_rdv4) ? _GREEN_("RDV4") : _RED_("device / fw mismatch"));
                PrintAndLogEx(NORMAL, "  firmware.................. %s", (is_genuine_rdv4) ? _GREEN_("RDV4") : _YELLOW_("RDV4"));
                PrintAndLogEx(NORMAL, "  external flash............ %s", IfPm3Flash() ? _GREEN_("present") : _YELLOW_("absent"));
                PrintAndLogEx(NORMAL, "  smartcard reader.......... %s", IfPm3Smartcard() ? _GREEN_("present") : _YELLOW_("absent"));
                PrintAndLogEx(NORMAL, "  FPC USART for BT add-on... %s", IfPm3FpcUsartHost() ? _GREEN_("present") : _YELLOW_("absent"));
            } else {
                PrintAndLogEx(NORMAL, "  firmware.................. %s", _YELLOW_("PM3 GENERIC"));
                if (IfPm3FpcUsartHost()) {
                    PrintAndLogEx(NORMAL, "  FPC USART for BT add-on... %s", _GREEN_("present"));
                }
            }

            if (IfPm3FpcUsartDevFromUsb()) {
                PrintAndLogEx(NORMAL, "  FPC USART for developer... %s", _GREEN_("present"));
            }

            PrintAndLogEx(NORMAL, "");

            struct p {
                uint32_t id;
                uint32_t section_size;
                uint32_t versionstr_len;
                char versionstr[PM3_CMD_DATA_SIZE - 12];
            } PACKED;

            struct p *payload = (struct p *)&resp.data.asBytes;

            bool armsrc_mismatch = false;
            char *ptr = strstr(payload->versionstr, " os: ");
            if (ptr != NULL) {
                ptr = strstr(ptr, "\n");
                if ((ptr != NULL) && (strlen(g_version_information.armsrc) == 9)) {
                    if (strncmp(ptr-9, g_version_information.armsrc, 9) != 0) {
                        armsrc_mismatch = true;
                    }
                }
            }
            PrintAndLogEx(NORMAL,  payload->versionstr);
            if (strstr(payload->versionstr, "2s30vq100") == NULL) {
                PrintAndLogEx(NORMAL, "  FPGA firmware... %s", _RED_("chip mismatch"));
            }

            lookupChipID(payload->id, payload->section_size);
            if (armsrc_mismatch) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, _RED_("ARM firmware does not match the source at the time the client was compiled"));
                PrintAndLogEx(WARNING,  "Make sure to flash a correct and up-to-date version");
            }
        }
    }
    PrintAndLogEx(NORMAL, "");
}
