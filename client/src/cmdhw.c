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

#ifdef HAVE_PYTHON
#include <Python.h>
#endif

#include "cmdparser.h"      // command_t
#include "cliparser.h"
#include "comms.h"
#include "usart_defs.h"
#include "ui.h"
#include "fpga.h"
#include "cmdhw.h"
#include "cmddata.h"
#include "commonutil.h"
#include "preferences.h"
#include "pm3_cmd.h"
#include "pmflash.h"        // rdv40validation_t
#include "cmdflashmem.h"    // get_signature..
#include "uart/uart.h"      // configure timeout
#include "util_posix.h"
#include "flash.h"          // reboot to bootloader mode
#include "proxgui.h"
#include "graph.h"          // for graph data

#include "lua.h"

static int CmdHelp(const char *Cmd);

static void lookup_chipid_short(uint32_t iChipID, uint32_t mem_used) {
    const char *asBuff;
    switch (iChipID) {
        case 0x270B0A40:
            asBuff = "AT91SAM7S512 Rev A";
            break;
        case 0x270B0A4E:
        case 0x270B0A4F:
            asBuff = "AT91SAM7S512 Rev B";
            break;
        case 0x270D0940:
            asBuff = "AT91SAM7S256 Rev A";
            break;
        case 0x270B0941:
            asBuff = "AT91SAM7S256 Rev B";
            break;
        case 0x270B0942:
            asBuff = "AT91SAM7S256 Rev C";
            break;
        case 0x270B0943:
            asBuff = "AT91SAM7S256 Rev D";
            break;
        case 0x270C0740:
            asBuff = "AT91SAM7S128 Rev A";
            break;
        case 0x270A0741:
            asBuff = "AT91SAM7S128 Rev B";
            break;
        case 0x270A0742:
            asBuff = "AT91SAM7S128 Rev C";
            break;
        case 0x270A0743:
            asBuff = "AT91SAM7S128 Rev D";
            break;
        case 0x27090540:
            asBuff = "AT91SAM7S64 Rev A";
            break;
        case 0x27090543:
            asBuff = "AT91SAM7S64 Rev B";
            break;
        case 0x27090544:
            asBuff = "AT91SAM7S64 Rev C";
            break;
        case 0x27080342:
            asBuff = "AT91SAM7S321 Rev A";
            break;
        case 0x27080340:
            asBuff = "AT91SAM7S32 Rev A";
            break;
        case 0x27080341:
            asBuff = "AT91SAM7S32 Rev B";
            break;
        case 0x27050241:
            asBuff = "AT9SAM7S161 Rev A";
            break;
        case 0x27050240:
            asBuff = "AT91SAM7S16 Rev A";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "    MCU....... " _YELLOW_("%s"), asBuff);

    uint32_t mem_avail = 0;
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

    PrintAndLogEx(NORMAL, "    Memory.... " _YELLOW_("%u") " KB ( " _YELLOW_("%2.0f%%") " used )"
                  , mem_avail
                  , mem_avail == 0 ? 0.0f : (float)mem_used / (mem_avail * 1024) * 100
                 );

    PrintAndLogEx(NORMAL, "");
}

static void lookupChipID(uint32_t iChipID, uint32_t mem_used) {
    const char *asBuff;
    uint32_t mem_avail = 0;
    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Hardware") " ]");

    switch (iChipID) {
        case 0x270B0A40:
            asBuff = "AT91SAM7S512 Rev A";
            break;
        case 0x270B0A4E:
        case 0x270B0A4F:
            asBuff = "AT91SAM7S512 Rev B";
            break;
        case 0x270D0940:
            asBuff = "AT91SAM7S256 Rev A";
            break;
        case 0x270B0941:
            asBuff = "AT91SAM7S256 Rev B";
            break;
        case 0x270B0942:
            asBuff = "AT91SAM7S256 Rev C";
            break;
        case 0x270B0943:
            asBuff = "AT91SAM7S256 Rev D";
            break;
        case 0x270C0740:
            asBuff = "AT91SAM7S128 Rev A";
            break;
        case 0x270A0741:
            asBuff = "AT91SAM7S128 Rev B";
            break;
        case 0x270A0742:
            asBuff = "AT91SAM7S128 Rev C";
            break;
        case 0x270A0743:
            asBuff = "AT91SAM7S128 Rev D";
            break;
        case 0x27090540:
            asBuff = "AT91SAM7S64 Rev A";
            break;
        case 0x27090543:
            asBuff = "AT91SAM7S64 Rev B";
            break;
        case 0x27090544:
            asBuff = "AT91SAM7S64 Rev C";
            break;
        case 0x27080342:
            asBuff = "AT91SAM7S321 Rev A";
            break;
        case 0x27080340:
            asBuff = "AT91SAM7S32 Rev A";
            break;
        case 0x27080341:
            asBuff = "AT91SAM7S32 Rev B";
            break;
        case 0x27050241:
            asBuff = "AT9SAM7S161 Rev A";
            break;
        case 0x27050240:
            asBuff = "AT91SAM7S16 Rev A";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= uC: " _YELLOW_("%s"), asBuff);

    switch ((iChipID & 0xE0) >> 5) {
        case 1:
            asBuff = "ARM946ES";
            break;
        case 2:
            asBuff = "ARM7TDMI";
            break;
        case 4:
            asBuff = "ARM920T";
            break;
        case 5:
            asBuff = "ARM926EJS";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Embedded Processor: %s", asBuff);

    switch ((iChipID & 0xF0000) >> 16) {
        case 1:
            asBuff = "1K bytes";
            break;
        case 2:
            asBuff = "2K bytes";
            break;
        case 3:
            asBuff = "6K bytes";
            break;
        case 4:
            asBuff = "112K bytes";
            break;
        case 5:
            asBuff = "4K bytes";
            break;
        case 6:
            asBuff = "80K bytes";
            break;
        case 7:
            asBuff = "160K bytes";
            break;
        case 8:
            asBuff = "8K bytes";
            break;
        case 9:
            asBuff = "16K bytes";
            break;
        case 10:
            asBuff = "32K bytes";
            break;
        case 11:
            asBuff = "64K bytes";
            break;
        case 12:
            asBuff = "128K bytes";
            break;
        case 13:
            asBuff = "256K bytes";
            break;
        case 14:
            asBuff = "96K bytes";
            break;
        case 15:
            asBuff = "512K bytes";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Internal SRAM size: %s", asBuff);

    switch ((iChipID & 0xFF00000) >> 20) {
        case 0x19:
            asBuff = "AT91SAM9xx Series";
            break;
        case 0x29:
            asBuff = "AT91SAM9XExx Series";
            break;
        case 0x34:
            asBuff = "AT91x34 Series";
            break;
        case 0x37:
            asBuff = "CAP7 Series";
            break;
        case 0x39:
            asBuff = "CAP9 Series";
            break;
        case 0x3B:
            asBuff = "CAP11 Series";
            break;
        case 0x40:
            asBuff = "AT91x40 Series";
            break;
        case 0x42:
            asBuff = "AT91x42 Series";
            break;
        case 0x55:
            asBuff = "AT91x55 Series";
            break;
        case 0x60:
            asBuff = "AT91SAM7Axx Series";
            break;
        case 0x61:
            asBuff = "AT91SAM7AQxx Series";
            break;
        case 0x63:
            asBuff = "AT91x63 Series";
            break;
        case 0x70:
            asBuff = "AT91SAM7Sxx Series";
            break;
        case 0x71:
            asBuff = "AT91SAM7XCxx Series";
            break;
        case 0x72:
            asBuff = "AT91SAM7SExx Series";
            break;
        case 0x73:
            asBuff = "AT91SAM7Lxx Series";
            break;
        case 0x75:
            asBuff = "AT91SAM7Xxx Series";
            break;
        case 0x92:
            asBuff = "AT91x92 Series";
            break;
        case 0xF0:
            asBuff = "AT75Cxx Series";
            break;
        default:
            asBuff = "Unknown";
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Architecture identifier: %s", asBuff);

    switch ((iChipID & 0x70000000) >> 28) {
        case 0:
            asBuff = "ROM";
            break;
        case 1:
            asBuff = "ROMless or on-chip Flash";
            break;
        case 2:
            asBuff = "Embedded flash memory";
            break;
        case 3:
            asBuff = "ROM and Embedded flash memory\nNVPSIZ is ROM size\nNVPSIZ2 is Flash size";
            break;
        case 4:
            asBuff = "SRAM emulating ROM";
            break;
        default:
            asBuff = "Unknown";
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
            asBuff = "None");
            break;
        case 1:
            asBuff = "8K bytes");
            break;
        case 2:
            asBuff = "16K bytes");
            break;
        case 3:
            asBuff = "32K bytes");
            break;
        case 5:
            asBuff = "64K bytes");
            break;
        case 7:
            asBuff = "128K bytes");
            break;
        case 9:
            asBuff = "256K bytes");
            break;
        case 10:
            asBuff = "512K bytes");
            break;
        case 12:
            asBuff = "1024K bytes");
            break;
        case 14:
            asBuff = "2048K bytes");
            break;
    }
    PrintAndLogEx(NORMAL, "  --= Second nonvolatile program memory size: %s", asBuff);
    */
}

static int CmdDbg(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw dbg",
                  "Set device side debug level output.\n"
                  "Note: option `-4`, this option may cause malfunction itself by\n"
                  "introducing delays in time critical functions like simulation or sniffing",
                  "hw dbg    --> get current log level\n"
                  "hw dbg -1 --> set log level to _error_\n"
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

    uint8_t curr = DBG_NONE;
    if (getDeviceDebugLevel(&curr) != PM3_SUCCESS)
        return PM3_EFAILED;

    const char *dbglvlstr;
    switch (curr) {
        case DBG_NONE:
            dbglvlstr = "none";
            break;
        case DBG_ERROR:
            dbglvlstr = "error";
            break;
        case DBG_INFO:
            dbglvlstr = "info";
            break;
        case DBG_DEBUG:
            dbglvlstr = "debug";
            break;
        case DBG_EXTENDED:
            dbglvlstr = "extended";
            break;
        default:
            dbglvlstr = "unknown";
            break;
    }
    PrintAndLogEx(INFO, "  Current debug log level..... %d ( " _YELLOW_("%s")" )", curr, dbglvlstr);


    if ((lv0 + lv1 + lv2 + lv3 + lv4) == 1) {
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

        if (setDeviceDebugLevel(dbg, true) != PM3_SUCCESS)
            return PM3_EFAILED;
    }
    return PM3_SUCCESS;
}

static int CmdDetectReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw detectreader",
                  "Start to detect presences of reader field",
                  "hw detectreader\n"
                  "hw detectreader -L\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("L", "LF", "only detect low frequency 125/134 kHz"),
        arg_lit0("H", "HF", "only detect high frequency 13.56 MHZ"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool lf = arg_get_lit(ctx, 1);
    bool hf = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    // 0: Detect both frequency in mode 1
    // 1: LF_ONLY
    // 2: HF_ONLY
    uint8_t arg = 0;
    if (lf == true && hf == false) {
        arg = 1;
    } else if (hf == true && lf == false) {
        arg = 2;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LISTEN_READER_FIELD, (uint8_t *)&arg, sizeof(arg));
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or " _GREEN_("<Enter>") " to change modes and exit");

    for (;;) {
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, _GREEN_("<Enter>") " pressed");
        }

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_LISTEN_READER_FIELD, &resp, 1000)) {
            if (resp.status != PM3_EOPABORTED) {
                PrintAndLogEx(ERR, "Unexpected response: %d", resp.status);
            }
            break;
        }
    }
    PrintAndLogEx(INFO, "Done!");
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

    int r_len = 0;
    uint8_t raw[1] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &r_len);
    int j = arg_get_int_def(ctx, 2, 1);
    CLIParserFree(ctx);
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
                  "Reads processor flash memory into a file or views on console",
                  "hw readmem -f myfile                    -> save 512KB processor flash memory to file\n"
                  "hw readmem -a 8192 -l 512               -> display 512 bytes from offset 8192\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0("a", "adr", "<dec>", "flash address to start reading from"),
        arg_u64_0("l", "len", "<dec>", "length (default 32 or 512KB)"),
        arg_str0("f", "file", "<fn>", "save to file"),
        arg_u64_0("c", "cols", "<dec>", "column breaks"),
        arg_lit0("r", "raw", "use raw address mode: read from anywhere, not just flash"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    // check for -file option first to determine the output mode
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool save_to_file = fnlen > 0;

    // default len to 512KB when saving to file, to 32 bytes when viewing on the console.
    uint32_t default_len = save_to_file ? 512 * 1024 : 32;

    uint32_t address = arg_get_u32_def(ctx, 1, 0);
    uint32_t len = arg_get_u32_def(ctx, 2, default_len);
    int breaks = arg_get_int_def(ctx, 4, 32);
    bool raw = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    uint8_t *buffer = calloc(len, sizeof(uint8_t));
    if (!buffer) {
        PrintAndLogEx(ERR, "error, cannot allocate memory ");
        return PM3_EMALLOC;
    }

    const char *flash_str = raw ? "" : " flash";
    PrintAndLogEx(INFO, "reading "_YELLOW_("%u")" bytes from processor%s memory",
                  len, flash_str);

    DeviceMemType_t type = raw ? MCU_MEM : MCU_FLASH;
    if (!GetFromDevice(type, buffer, len, address, NULL, 0, NULL, -1, true)) {
        PrintAndLogEx(FAILED, "ERROR; reading from MCU flash memory");
        free(buffer);
        return PM3_EFLASH;
    }

    if (save_to_file) {
        saveFile(filename, ".bin", buffer, len);
    } else {
        PrintAndLogEx(INFO, "---- " _CYAN_("processor%s memory") " ----", flash_str);
        print_hex_break(buffer, len, breaks);
    }

    free(buffer);
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
        PrintAndLogEx(ERR, "Divisor must be between " _YELLOW_("19") " and " _YELLOW_("255"));
        return PM3_EINVARG;
    }
    // 12 000 000 (12MHz)
    clearCommandBuffer();
    SendCommandNG(CMD_LF_SET_DIVISOR, (uint8_t *)&arg, sizeof(arg));
    PrintAndLogEx(SUCCESS, "Divisor set, expected " _YELLOW_("%.1f")" kHz", ((double)12000 / (arg + 1)));
    return PM3_SUCCESS;
}

static int CmdSetHFThreshold(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw sethfthresh",
                  "Set thresholds in HF/14a and Legic mode.",
                  "hw sethfthresh -t 7 -i 20 -l 8"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("t", "thresh", "<dec>", "threshold, used in 14a reader mode (def 7)"),
        arg_int0("i", "high", "<dec>", "high threshold, used in 14a sniff mode (def 20)"),
        arg_int0("l", "legic", "<dec>", "threshold used in Legic mode (def 8)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct {
        uint8_t threshold;
        uint8_t threshold_high;
        uint8_t legic_threshold;
    } PACKED params;

    params.threshold = arg_get_int_def(ctx, 1, 7);
    params.threshold_high = arg_get_int_def(ctx, 2, 20);
    params.legic_threshold = arg_get_int_def(ctx, 3, 8);
    CLIParserFree(ctx);

    if ((params.threshold < 1) || (params.threshold > 63) || (params.threshold_high < 1) || (params.threshold_high > 63)) {
        PrintAndLogEx(ERR, "Thresholds must be between " _YELLOW_("1") " and " _YELLOW_("63"));
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443A_SET_THRESHOLDS, (uint8_t *)&params, sizeof(params));
    PrintAndLogEx(SUCCESS, "Thresholds set.");
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
        arg_str0("b", NULL, "<str>", "UniSniff arg: 14a, 14b, 15, iclass"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    struct p {
        uint8_t arg;
        uint8_t mlen;
        uint8_t mode[10];
    } PACKED packet;

    packet.arg = arg_get_u32_def(ctx, 1, 1);
    int mlen = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 2), packet.mode, sizeof(packet.mode), &mlen);
    if (mlen) {
        packet.mlen = mlen;
    }
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_STANDALONE, (uint8_t *)&packet, sizeof(struct p));
    return PM3_SUCCESS;
}

static int CmdTune(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw tune",
                  "Measure tuning of device antenna. Results shown in graph window.\n"
                  "This command doesn't actively tune your antennas, \n"
                  "it's only informative by measuring voltage that the antennas will generate",
                  "hw tune"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

#define NON_VOLTAGE     1000
#define LF_UNUSABLE_V   2000
#define LF_MARGINAL_V   10000
#define HF_UNUSABLE_V   3000
#define HF_MARGINAL_V   5000
#define ANTENNA_ERROR   1.00 // current algo has 3% error margin.

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("Reminder") " ----------------------------");
    PrintAndLogEx(INFO, "`" _YELLOW_("hw tune") "` doesn't actively tune your antennas.");
    PrintAndLogEx(INFO, "It's only informative.");
    PrintAndLogEx(INFO, "Measuring antenna characteristics...");

    // hide demod plot line
    g_DemodBufferLen = 0;
    setClockGrid(0, 0);
    RepaintGraphWindow();
    int timeout = 0;
    int timeout_max = 20;

    clearCommandBuffer();
    SendCommandNG(CMD_MEASURE_ANTENNA_TUNING, NULL, 0);
    PacketResponseNG resp;
    PrintAndLogEx(INPLACE, "% 3i", timeout_max - timeout);
    while (!WaitForResponseTimeout(CMD_MEASURE_ANTENNA_TUNING, &resp, 500)) {
        fflush(stdout);
        if (timeout >= timeout_max) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            return PM3_ETIMEOUT;
        }
        timeout++;
        PrintAndLogEx(INPLACE, "% 3i", timeout_max - timeout);
    }
    PrintAndLogEx(NORMAL, "");

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Antenna tuning failed");
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("LF Antenna") " ----------");
    // in mVolt
    struct p {
        uint32_t v_lf134;
        uint32_t v_lf125;
        uint32_t v_lfconf;
        uint32_t v_hf;
        uint32_t peak_v;
        uint32_t peak_f;
        int divisor;
        uint8_t results[256];
    } PACKED;

    struct p *package = (struct p *)resp.data.asBytes;

    if (package->v_lf125 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "%.2f kHz ........... " _YELLOW_("%5.2f") " V", LF_DIV2FREQ(LF_DIVISOR_125), (package->v_lf125 * ANTENNA_ERROR) / 1000.0);

    if (package->v_lf134 > NON_VOLTAGE)
        PrintAndLogEx(SUCCESS, "%.2f kHz ........... " _YELLOW_("%5.2f") " V", LF_DIV2FREQ(LF_DIVISOR_134), (package->v_lf134 * ANTENNA_ERROR) / 1000.0);

    if (package->v_lfconf > NON_VOLTAGE && package->divisor > 0 && package->divisor != LF_DIVISOR_125 && package->divisor != LF_DIVISOR_134)
        PrintAndLogEx(SUCCESS, "%.2f kHz ........... " _YELLOW_("%5.2f") " V", LF_DIV2FREQ(package->divisor), (package->v_lfconf * ANTENNA_ERROR) / 1000.0);

    if (package->peak_v > NON_VOLTAGE && package->peak_f > 0)
        PrintAndLogEx(SUCCESS, "%.2f kHz optimal.... " _BACK_GREEN_("%5.2f") " V", LF_DIV2FREQ(package->peak_f), (package->peak_v * ANTENNA_ERROR) / 1000.0);

    // Empirical measures in mV
    const double vdd_rdv4 = 9000;
    const double vdd_other = 5400;
    double vdd = IfPm3Rdv4Fw() ? vdd_rdv4 : vdd_other;

    if (package->peak_v > NON_VOLTAGE && package->peak_f > 0) {

        // Q measure with Q=f/delta_f
        double v_3db_scaled = (double)(package->peak_v * 0.707) / 512; // /512 == >>9
        uint32_t s2 = 0, s4 = 0;
        for (int i = 1; i < 256; i++) {
            if ((s2 == 0) && (package->results[i] > v_3db_scaled)) {
                s2 = i;
            }
            if ((s2 != 0) && (package->results[i] < v_3db_scaled)) {
                s4 = i;
                break;
            }
        }

        PrintAndLogEx(SUCCESS, "");
        PrintAndLogEx(SUCCESS, "Approx. Q factor measurement");
        double lfq1 = 0;
        if (s4 != 0) { // we got all our points of interest
            double a = package->results[s2 - 1];
            double b = package->results[s2];
            double f1 = LF_DIV2FREQ(s2 - 1 + (v_3db_scaled - a) / (b - a));
            double c = package->results[s4 - 1];
            double d = package->results[s4];
            double f2 = LF_DIV2FREQ(s4 - 1 + (c - v_3db_scaled) / (c - d));
            lfq1 = LF_DIV2FREQ(package->peak_f) / (f1 - f2);
            PrintAndLogEx(SUCCESS, "Frequency bandwidth... " _YELLOW_("%.1lf"), lfq1);
        }

        // Q measure with Vlr=Q*(2*Vdd/pi)
        double lfq2 = (double)package->peak_v * 3.14 / 2 / vdd;
        PrintAndLogEx(SUCCESS, "Peak voltage.......... " _YELLOW_("%.1lf"), lfq2);
        // cross-check results
        if (lfq1 > 3) {
            double approx_vdd = (double)package->peak_v * 3.14 / 2 / lfq1;
            // Got 8858 on a RDV4 with large antenna 134/14
            // Got 8761 on a non-RDV4
            const double approx_vdd_other_max = 8840;

            // 1% over threshold and supposedly non-RDV4
            if ((approx_vdd > approx_vdd_other_max * 1.01) && (!IfPm3Rdv4Fw())) {
                PrintAndLogEx(WARNING, "Contradicting measures seem to indicate you're running a " _YELLOW_("PM3GENERIC firmware on a RDV4"));
                PrintAndLogEx(WARNING, "False positives is possible but please check your setup");
            }
            // 1% below threshold and supposedly RDV4
            if ((approx_vdd < approx_vdd_other_max * 0.99) && (IfPm3Rdv4Fw())) {
                PrintAndLogEx(WARNING, "Contradicting measures seem to indicate you're running a " _YELLOW_("PM3_RDV4 firmware on a generic device"));
                PrintAndLogEx(WARNING, "False positives is possible but please check your setup");
            }
        }
    }

    char judgement[20];
    memset(judgement, 0, sizeof(judgement));
    // LF evaluation
    if (package->peak_v < LF_UNUSABLE_V)
        snprintf(judgement, sizeof(judgement), _RED_("unusable"));
    else if (package->peak_v < LF_MARGINAL_V)
        snprintf(judgement, sizeof(judgement), _YELLOW_("marginal"));
    else
        snprintf(judgement, sizeof(judgement), _GREEN_("ok"));

    //PrintAndLogEx((package->peak_v < LF_UNUSABLE_V) ? WARNING : SUCCESS, "LF antenna ( %s )", judgement);
    PrintAndLogEx((package->peak_v < LF_UNUSABLE_V) ? WARNING : SUCCESS, "LF antenna............ %s", judgement);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-------- " _CYAN_("HF Antenna") " ----------");
    // HF evaluation
    if (package->v_hf > NON_VOLTAGE) {
        PrintAndLogEx(SUCCESS, "13.56 MHz............. " _BACK_GREEN_("%5.2f") " V", (package->v_hf * ANTENNA_ERROR) / 1000.0);
    }

    memset(judgement, 0, sizeof(judgement));

    PrintAndLogEx(SUCCESS, "");
    PrintAndLogEx(SUCCESS, "Approx. Q factor measurement");

    if (package->v_hf >= HF_UNUSABLE_V) {
        // Q measure with Vlr=Q*(2*Vdd/pi)
        double hfq = (double)package->v_hf * 3.14 / 2 / vdd;
        PrintAndLogEx(SUCCESS, "Peak voltage.......... " _YELLOW_("%.1lf"), hfq);
    }

    if (package->v_hf < HF_UNUSABLE_V)
        snprintf(judgement, sizeof(judgement), _RED_("unusable"));
    else if (package->v_hf < HF_MARGINAL_V)
        snprintf(judgement, sizeof(judgement), _YELLOW_("marginal"));
    else
        snprintf(judgement, sizeof(judgement), _GREEN_("ok"));

    PrintAndLogEx((package->v_hf < HF_UNUSABLE_V) ? WARNING : SUCCESS, "HF antenna ( %s )", judgement);

    // graph LF measurements
    // even here, these values has 3% error.
    uint16_t test1 = 0;
    for (int i = 0; i < 256; i++) {
        g_GraphBuffer[i] = package->results[i] - 128;
        test1 += package->results[i];
    }

    if (test1 > 0) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------- " _CYAN_("LF tuning graph") " ------------");
        PrintAndLogEx(SUCCESS, "Orange line - divisor %d / %.2f kHz"
                      , LF_DIVISOR_125
                      , LF_DIV2FREQ(LF_DIVISOR_125)
                     );
        PrintAndLogEx(SUCCESS, "Blue line - divisor   %d / %.2f kHz\n\n"
                      , LF_DIVISOR_134
                      , LF_DIV2FREQ(LF_DIVISOR_134)
                     );
        g_GraphTraceLen = 256;
        g_MarkerC.pos = LF_DIVISOR_125;
        g_MarkerD.pos = LF_DIVISOR_134;
        ShowGraphWindow();
        RepaintGraphWindow();
    } else {
        PrintAndLogEx(FAILED, "\nAll values are zero. Not showing LF tuning graph\n\n");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Q factor must be measured without tag on the antenna");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
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
                  "hw status\n"
                  "hw status --ms 1000 -> Test connection speed with 1000ms timeout\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("m", "ms", "<ms>", "speed test timeout in micro seconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int32_t speedTestTimeout = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    clearCommandBuffer();
    PacketResponseNG resp;
    if (speedTestTimeout < 0) {
        speedTestTimeout = 0;
        SendCommandNG(CMD_STATUS, NULL, 0);
    } else {
        SendCommandNG(CMD_STATUS, (uint8_t *)&speedTestTimeout, sizeof(speedTestTimeout));
    }

    if (WaitForResponseTimeout(CMD_STATUS, &resp, 2000 + speedTestTimeout) == false) {
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

static int CmdTimeout(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw timeout",
                  "Set the communication timeout on the client side",
                  "hw timeout            --> Show current timeout\n"
                  "hw timeout -m 20      --> Set the timeout to 20ms\n"
                  "hw timeout --ms 500   --> Set the timeout to 500ms\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0("m", "ms", "<ms>", "timeout in micro seconds"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int32_t arg = arg_get_int_def(ctx, 1, -1);
    CLIParserFree(ctx);

    uint32_t oldTimeout = uart_get_timeouts();

    // timeout is not given/invalid, just show the current timeout then return
    if (arg < 0) {
        PrintAndLogEx(INFO, "Current communication timeout... " _GREEN_("%u") " ms", oldTimeout);
        return PM3_SUCCESS;
    }

    uint32_t newTimeout = arg;
    // UART_USB_CLIENT_RX_TIMEOUT_MS is considered as the minimum required timeout.
    if (newTimeout < UART_USB_CLIENT_RX_TIMEOUT_MS) {
        PrintAndLogEx(WARNING, "Timeout less than %u ms might cause errors.", UART_USB_CLIENT_RX_TIMEOUT_MS);
    } else if (newTimeout > 5000) {
        PrintAndLogEx(WARNING, "Timeout greater than 5000 ms makes the client unresponsive.");
    }
    uart_reconfigure_timeouts(newTimeout);
    PrintAndLogEx(INFO, "Old communication timeout... %u ms", oldTimeout);
    PrintAndLogEx(INFO, "New communication timeout... " _GREEN_("%u") " ms", newTimeout);
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
    uint32_t len = arg_get_u32_def(ctx, 1, 32);
    CLIParserFree(ctx);

    if (len > PM3_CMD_DATA_SIZE)
        len = PM3_CMD_DATA_SIZE;

    if (len) {
        PrintAndLogEx(INFO, "Ping sent with payload len... " _YELLOW_("%d"), len);
    } else {
        PrintAndLogEx(INFO, "Ping sent");
    }

    clearCommandBuffer();
    PacketResponseNG resp;
    uint8_t data[PM3_CMD_DATA_SIZE] = {0};

    for (uint16_t i = 0; i < len; i++) {
        data[i] = i & 0xFF;
    }

    uint64_t tms = msclock();
    SendCommandNG(CMD_PING, data, len);
    if (WaitForResponseTimeout(CMD_PING, &resp, 1000)) {
        tms = msclock() - tms;
        if (len) {
            bool error = (memcmp(data, resp.data.asBytes, len) != 0);
            PrintAndLogEx((error) ? ERR : SUCCESS, "Ping response " _GREEN_("received")
                          " in " _YELLOW_("%" PRIu64) " ms and content ( %s )",
                          tms, error ? _RED_("fail") : _GREEN_("ok"));
        } else {
            PrintAndLogEx(SUCCESS, "Ping response " _GREEN_("received")
                          " in " _YELLOW_("%" PRIu64) " ms", tms);
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

    char port[FILE_PATH_SIZE] = {0};
    int p_len = sizeof(port) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated;
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

static int CmdBootloader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hw bootloader",
                  "Reboot Proxmark3 into bootloader mode",
                  "hw bootloader\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    flash_reboot_bootloader(g_conn.serial_port_name, false);
    return PM3_SUCCESS;
}

int set_fpga_mode(uint8_t mode) {
    if (mode < FPGA_BITSTREAM_MIN || mode > FPGA_BITSTREAM_MAX) {
        return PM3_EINVARG;
    }
    uint8_t d[] = {mode};
    clearCommandBuffer();
    SendCommandNG(CMD_SET_FPGAMODE, d, sizeof(d));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_SET_FPGAMODE, &resp, 1000) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "failed to set FPGA mode");
    }
    return resp.status;
}

static command_t CommandTable[] = {
    {"help",          CmdHelp,         AlwaysAvailable,  "This help"},
    {"-------------", CmdHelp,         AlwaysAvailable,  "----------------------- " _CYAN_("Operation") " -----------------------"},
    {"detectreader",  CmdDetectReader, IfPm3Present,     "Detect external reader field"},
    {"status",        CmdStatus,       IfPm3Present,     "Show runtime status information about the connected Proxmark3"},
    {"tearoff",       CmdTearoff,      IfPm3Present,     "Program a tearoff hook for the next command supporting tearoff"},
    {"timeout",       CmdTimeout,      AlwaysAvailable,  "Set the communication timeout on the client side"},
    {"version",       CmdVersion,      AlwaysAvailable,  "Show version information about the client and Proxmark3"},
    {"-------------", CmdHelp,         AlwaysAvailable,  "----------------------- " _CYAN_("Hardware") " -----------------------"},
    {"break",         CmdBreak,        IfPm3Present,     "Send break loop usb command"},
    {"bootloader",    CmdBootloader,   IfPm3Present,     "Reboot into bootloader mode"},
    {"connect",       CmdConnect,      AlwaysAvailable,  "Connect to the device via serial port"},
    {"dbg",           CmdDbg,          IfPm3Present,     "Set device side debug level"},
    {"fpgaoff",       CmdFPGAOff,      IfPm3Present,     "Turn off FPGA on device"},
    {"lcd",           CmdLCD,          IfPm3Lcd,         "Send command/data to LCD"},
    {"lcdreset",      CmdLCDReset,     IfPm3Lcd,         "Hardware reset LCD"},
    {"ping",          CmdPing,         IfPm3Present,     "Test if the Proxmark3 is responsive"},
    {"readmem",       CmdReadmem,      IfPm3Present,     "Read from MCU flash"},
    {"reset",         CmdReset,        IfPm3Present,     "Reset the device"},
    {"setlfdivisor",  CmdSetDivisor,   IfPm3Lf,          "Drive LF antenna at 12MHz / (divisor + 1)"},
    {"sethfthresh",   CmdSetHFThreshold, IfPm3Iso14443a, "Set thresholds in HF/14a mode"},
    {"setmux",        CmdSetMux,       IfPm3Present,     "Set the ADC mux to a specific value"},
    {"standalone",    CmdStandalone,   IfPm3Present,     "Start installed standalone mode on device"},
    {"tia",           CmdTia,          IfPm3Present,     "Trigger a Timing Interval Acquisition to re-adjust the RealTimeCounter divider"},
    {"tune",          CmdTune,         IfPm3Lf,          "Measure tuning of device antenna"},
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

void pm3_version_short(void) {
    PrintAndLogEx(NORMAL, "  [ " _CYAN_("Proxmark3 RFID instrument") " ]");
    PrintAndLogEx(NORMAL, "");

    if (g_session.pm3_present) {

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_VERSION, NULL, 0);

        if (WaitForResponseTimeout(CMD_VERSION, &resp, 1000)) {

            struct p {
                uint32_t id;
                uint32_t section_size;
                uint32_t versionstr_len;
                char versionstr[PM3_CMD_DATA_SIZE - 12];
            } PACKED;

            struct p *payload = (struct p *)&resp.data.asBytes;

            lookup_chipid_short(payload->id, payload->section_size);

            // client
            char temp[PM3_CMD_DATA_SIZE - 12]; // same limit as for ARM image
            format_version_information_short(temp, sizeof(temp), &g_version_information);
            PrintAndLogEx(NORMAL, "    Client.... %s", temp);

            bool armsrc_mismatch = false;
            char *ptr = strstr(payload->versionstr, " os: ");
            if (ptr != NULL) {
                ptr = strstr(ptr, "\n");
                if ((ptr != NULL) && (strlen(g_version_information.armsrc) == 9)) {
                    if (strncmp(ptr - 9, g_version_information.armsrc, 9) != 0) {
                        armsrc_mismatch = true;
                    }
                }
            }

            // bootrom
            ptr = strstr(payload->versionstr, " bootrom: ");
            if (ptr != NULL) {
                char *ptr_end = strstr(ptr, "\n");
                if (ptr_end != NULL) {
                    uint8_t len = ptr_end - 19 - ptr;
                    PrintAndLogEx(NORMAL, "    Bootrom... %.*s", len, ptr + 10);
                }
            }

            // os:
            ptr = strstr(payload->versionstr, " os: ");
            if (ptr != NULL) {
                char *ptr_end = strstr(ptr, "\n");
                if (ptr_end != NULL) {
                    uint8_t len = ptr_end - 14 - ptr;
                    PrintAndLogEx(NORMAL, "    OS........ %.*s", len, ptr + 5);
                }
            }


            if (IfPm3Rdv4Fw()) {

                bool is_genuine_rdv4 = false;
                // validate signature data
                rdv40_validation_t mem;
                if (rdv4_get_signature(&mem) == PM3_SUCCESS) {
                    if (rdv4_validate(&mem) == PM3_SUCCESS) {
                        is_genuine_rdv4 = true;
                    }
                }

                PrintAndLogEx(NORMAL, "    Target.... %s", (is_genuine_rdv4) ? _YELLOW_("RDV4") : _RED_("device / fw mismatch"));
            } else {
                PrintAndLogEx(NORMAL, "    Target.... %s", _YELLOW_("PM3 GENERIC"));
            }

            PrintAndLogEx(NORMAL, "");

            if (armsrc_mismatch) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, " --> " _RED_("ARM firmware does not match the source at the time the client was compiled"));
                PrintAndLogEx(WARNING, " --> Make sure to flash a correct and up-to-date version");
            }
        }
    }
    PrintAndLogEx(NORMAL, "");
}

void pm3_version(bool verbose, bool oneliner) {

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
    PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Client") " ]");
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
    PrintAndLogEx(NORMAL, "  Python script support..... " _GREEN_("present") " ( " _YELLOW_(PY_VERSION) " )");
#else
    PrintAndLogEx(NORMAL, "  Python script support..... " _YELLOW_("absent"));
#endif
#ifdef HAVE_PYTHON_SWIG
    PrintAndLogEx(NORMAL, "  Python SWIG support....... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Python SWIG support....... " _YELLOW_("absent"));
#endif
    PrintAndLogEx(NORMAL, "  Lua script support........ " _GREEN_("present") " ( " _YELLOW_("%s.%s.%s") " )", LUA_VERSION_MAJOR, LUA_VERSION_MINOR, LUA_VERSION_RELEASE);
#ifdef HAVE_LUA_SWIG
    PrintAndLogEx(NORMAL, "  Lua SWIG support.......... " _GREEN_("present"));
#else
    PrintAndLogEx(NORMAL, "  Lua SWIG support.......... " _YELLOW_("absent"));
#endif

    if (g_session.pm3_present) {
        PrintAndLogEx(NORMAL, "\n [ " _YELLOW_("Proxmark3") " ]");

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
                if (IfPm3Flash()) {
                    PrintAndLogEx(NORMAL, "  external flash............ %s", _GREEN_("present"));
                }

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
                    if (strncmp(ptr - 9, g_version_information.armsrc, 9) != 0) {
                        armsrc_mismatch = true;
                    }
                }
            }
            PrintAndLogEx(NORMAL,  payload->versionstr);
            if (strstr(payload->versionstr, FPGA_TYPE) == NULL) {
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
