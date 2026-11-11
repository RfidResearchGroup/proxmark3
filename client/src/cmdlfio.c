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
// Low frequency Kantech ioProx commands
// FSK2a, rf/64, 64 bits (complete)
//-----------------------------------------------------------------------------

#include "cmdlfio.h"
#include <stdio.h>        // sscanf
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "graph.h"
#include "cmdlf.h"
#include "ui.h"           // PrintAndLog
#include "lfdemod.h"      // parityTest, bitbytes_to_byte
#include "protocols.h"    // for T55xx config register definitions
#include "cmddata.h"
#include "cmdlft55xx.h"   // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

// this read loops on device side.
// uses the demod in lfops.c
static int CmdIOProxWatch(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf io watch",
                  "Enables ioProx compatible reader mode printing details.\n"
                  "By default, values are printed and logged until the button is pressed or another USB command is issued.",
                  "lf io watch"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Watching for IO Prox cards - place tag on antenna");
    PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " to stop reading cards");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_IO_WATCH, NULL, 0);
    return lfsim_wait_check(CMD_LF_IO_WATCH);
}

static int io_decode_bits(const uint8_t *bits, size_t len) {
    if (len < 64) {
        return PM3_ESOFT;
    }

    // Index map
    // 0           10          20          30          40          50          60
    // |           |           |           |           |           |           |
    // 01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
    // -----------------------------------------------------------------------------
    // 00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1 ???????? 11
    //
    // XSF(version)facility:codeone+codetwo (raw)

    uint8_t work[64];
    memcpy(work, bits, sizeof(work));

    if (bytebits_to_byte(work, 9) != 0 || bytebits_to_byte(work + 9, 8) != 0xF0 ||
        !work[17] || !work[26] || !work[35] || !work[44] || !work[53] || !work[62] || !work[63]) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox frame markers invalid");
        return PM3_ESOFT;
    }

    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d", work[0], work[1], work[2], work[3], work[4], work[5], work[6], work[7], work[8]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d", work[9], work[10], work[11], work[12], work[13], work[14], work[15], work[16], work[17]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d facility", work[18], work[19], work[20], work[21], work[22], work[23], work[24], work[25], work[26]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d version", work[27], work[28], work[29], work[30], work[31], work[32], work[33], work[34], work[35]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d code1", work[36], work[37], work[38], work[39], work[40], work[41], work[42], work[43], work[44]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d code2", work[45], work[46], work[47], work[48], work[49], work[50], work[51], work[52], work[53]);
    PrintAndLogEx(DEBUG, "%d%d%d%d%d%d%d%d %d%d checksum", work[54], work[55], work[56], work[57], work[58], work[59], work[60], work[61], work[62], work[63]);

    uint32_t code = bytebits_to_byte(work, 32);
    uint32_t code2 = bytebits_to_byte(work + 32, 32);
    uint8_t version = bytebits_to_byte(work + 27, 8);
    uint8_t facilitycode = bytebits_to_byte(work + 18, 8);
    uint16_t number = (bytebits_to_byte(work + 36, 8) << 8) | bytebits_to_byte(work + 45, 8);
    uint8_t crc = bytebits_to_byte(work + 54, 8);
    uint8_t calccrc = 0;

    for (uint8_t i = 1; i < 6; ++i) {
        calccrc += bytebits_to_byte(work + 9 * i, 8);
    }
    calccrc &= 0xff;
    calccrc = 0xff - calccrc;

    int retval = PM3_SUCCESS;
    char crc_str[40] = {0};

    if (crc == calccrc) {
        snprintf(crc_str, sizeof(crc_str), "( " _GREEN_("ok") " )");
    } else {
        snprintf(crc_str, sizeof(crc_str), "( " _RED_("fail") " ) 0x%02X != 0x%02X", crc, calccrc);
        retval = PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "IO Prox - " _GREEN_("XSF(%02d)%02x:%05d") ", Raw: %08x%08x %s", version, facilitycode, number, code, code2, crc_str);
    PrintAndLogEx(SUCCESS, "IO Prox SSF - " _GREEN_("%02x%02x:%05u"), version, facilitycode, number);

    if (g_debugMode && crc != calccrc) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox crc failed");
    }
    return retval;
}

//IO-Prox demod - FSK RF/64 with preamble of 000000001
//print ioProx ID and some format details
int demodIOProx(bool verbose) {
    (void) verbose; // unused so far
    int idx = 0, retval = PM3_SUCCESS;
    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    size_t size = getFromGraphBuffer(bits);
    if (size < 65) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox not enough samples in GraphBuffer");
        free(bits);
        return PM3_ESOFT;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    idx = detectIOProx(bits, &size, &waveIdx);
    if (idx < 0) {
        if (g_debugMode) {
            if (idx == -1) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox not enough samples");
            } else if (idx == -2) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox just noise detected");
            } else if (idx == -3) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox error during fskdemod");
            } else if (idx == -4) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox preamble not found");
            } else if (idx == -5) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO size not correct, size %zu", size);
            } else if (idx == -6) {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox separator bits not found");
            } else {
                PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox error demoding fsk %d", idx);
            }
        }
        free(bits);
        return PM3_ESOFT;
    }
    setDemodBuff(bits, size, idx);
    setClockGrid(64, waveIdx + (idx * 64));

    if (idx == 0) {
        if (g_debugMode) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - IO prox data not found - FSK Bits: %zu", size);
            if (size > 92) PrintAndLogEx(DEBUG, "%s", sprint_bytebits_bin_break(bits, 92, 16));
        }
        free(bits);
        return PM3_ESOFT;
    }

    retval = io_decode_bits(bits + idx, size);

    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "DEBUG: IO prox idx: %d, Len: %zu, Printing DemodBuffer:", idx, size);
        printDemodBuff(0, false, false, true);
        printDemodBuff(0, false, false, false);
    }
    free(bits);
    return retval;
}

static int CmdIOProxDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf io demod",
                  "Try to find ioProx preamble, if found decode / descramble data",
                  "lf io demod\n"
                  "lf io demod --raw 007840603059cf3f -> decode raw 64-bit ioProx hex"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex bytes (8 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int raw_len = 0;
    uint8_t raw[8] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (raw_len > 0) {
        if (raw_len != 8) {
            PrintAndLogEx(FAILED, "Raw data must be 8 bytes (64-bit), got " _YELLOW_("%d"), raw_len);
            return PM3_EINVARG;
        }
        uint8_t bits[64] = {0};
        bytes_to_bytebits(raw, sizeof(raw), bits);
        res = io_decode_bits(bits, sizeof(bits));
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Invalid ioProx raw data");
        }
        return res;
    }

    return demodIOProx(true);
}
// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdIOProxReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf io reader",
                  "read a ioProx tag",
                  "lf io reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    do {
        lf_read(false, 12000);
        demodIOProx(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdIOProxSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf io sim",
                  "Enables simulation of ioProx card with specified facility-code and card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf io sim --vn 1 --fc 101 --cn 1337\n"
                  "lf io sim --ssf 8004 --cn 45732\n"
                  "lf io sim --raw 007840603059cf3f"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "vn", "<dec>", "8bit version"),
        arg_u64_0(NULL, "fc", "<dec>", "8bit facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "16bit card number"),
        arg_str0(NULL, "ssf", "<hex>", "Kantech SSF 2-byte prefix (version+fc hex)"),
        arg_str0("r", "raw", "<hex>", "raw hex bytes (8 bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t vn_arg = arg_get_u32_def(ctx, 1, UINT32_MAX);
    uint32_t fc_arg = arg_get_u32_def(ctx, 2, UINT32_MAX);
    uint32_t cn_arg = arg_get_u32_def(ctx, 3, UINT32_MAX);

    int ssf_len = 0;
    uint8_t ssf[2] = {0};
    int res1 = CLIParamHexToBuf(arg_get_str(ctx, 4), ssf, sizeof(ssf), &ssf_len);

    int raw_len = 0;
    uint8_t raw[8] = {0};
    int res2 = CLIParamHexToBuf(arg_get_str(ctx, 5), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);
    if (res1 || res2) {
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len > 0);
    bool use_ssf = (ssf_len > 0);

    if (use_raw && raw_len != 8) {
        PrintAndLogEx(FAILED, "Raw data must be 8 bytes (64-bit), got %d", raw_len);
        return PM3_EINVARG;
    }
    if (use_raw && (use_ssf || vn_arg != UINT32_MAX || fc_arg != UINT32_MAX || cn_arg != UINT32_MAX)) {
        PrintAndLogEx(FAILED, "Can't combine --raw with --vn/--fc/--cn/--ssf");
        return PM3_EINVARG;
    }
    if (use_ssf && ssf_len != 2) {
        PrintAndLogEx(FAILED, "SSF prefix must be 2 hex bytes (4 hex chars), got %d", ssf_len);
        return PM3_EINVARG;
    }
    if (use_ssf && (vn_arg != UINT32_MAX || fc_arg != UINT32_MAX || cn_arg == UINT32_MAX)) {
        PrintAndLogEx(FAILED, "Use --ssf <hex> with --cn <dec> (without --vn or --fc)");
        return PM3_EINVARG;
    }
    if (!use_raw && !use_ssf && (vn_arg == UINT32_MAX || fc_arg == UINT32_MAX || cn_arg == UINT32_MAX)) {
        PrintAndLogEx(FAILED, "Must specify --vn/--fc/--cn, --ssf/--cn, or --raw");
        return PM3_EINVARG;
    }

    uint8_t bs[64];
    memset(bs, 0x00, sizeof(bs));

    if (use_raw) {
        bytes_to_bytebits(raw, sizeof(raw), bs);
        PrintAndLogEx(SUCCESS, "Simulating ioProx - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));
    } else {
        uint8_t version = use_ssf ? ssf[0] : (uint8_t)vn_arg;
        uint8_t fc = use_ssf ? ssf[1] : (uint8_t)fc_arg;
        if (cn_arg > 0xFFFF) {
            PrintAndLogEx(INFO, "Card Number Truncated to 16-bits (ioProx): %u", cn_arg & 0xFFFF);
        }
        uint16_t cn = (uint16_t)(cn_arg & 0xFFFF);

        PrintAndLogEx(SUCCESS, "Simulating ioProx version: " _YELLOW_("%u") " FC: " _YELLOW_("%u (0x%02x)") " CN: " _YELLOW_("%u"), version, fc, fc, cn);
        if (getIOProxBits(version, fc, cn, bs) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation.");
            return PM3_ESOFT;
        }
    }
    PrintAndLogEx(SUCCESS, "Press " _GREEN_("pm3 button") " to abort simulation or run another command");
    // ioProx uses: fcHigh: 10, fcLow: 8, clk: 64, invert: 1
    // arg1 --- fcHigh<<8 + fcLow
    // arg2 --- Invert and clk setting
    // size --- 64 bits == 8 bytes
    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->fchigh = 10;
    payload->fclow = 8;
    payload->separator = 1;
    payload->clock = 64;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);
    PacketResponseNG resp;
    WaitForResponse(CMD_LF_FSK_SIMULATE, &resp);
    PrintAndLogEx(INFO, "Done!");
    if (resp.status != PM3_EOPABORTED) {
        return resp.status;
    }
    return PM3_SUCCESS;
}

static int CmdIOProxClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf io clone",
                  "clone a ioProx card with specified facility-code and card number\n"
                  "to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "Tag must be on the antenna when issuing this command.",
                  "lf io clone --vn 1 --fc 101 --cn 1337\n"
                  "lf io clone --ssf 8004 --cn 45732\n"
                  "lf io clone --raw 007840603059cf3f"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "vn", "<dec>", "8bit version"),
        arg_u64_0(NULL, "fc", "<dec>", "8bit facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "16bit card number"),
        arg_str0(NULL, "ssf", "<hex>", "Kantech SSF 2-byte prefix (version+fc hex)"),
        arg_str0("r", "raw", "<hex>", "raw hex bytes (8 bytes)"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t vn_arg = arg_get_u32_def(ctx, 1, UINT32_MAX);
    uint32_t fc_arg = arg_get_u32_def(ctx, 2, UINT32_MAX);
    uint32_t cn_arg = arg_get_u32_def(ctx, 3, UINT32_MAX);

    int ssf_len = 0;
    uint8_t ssf[2] = {0};
    int res1 = CLIParamHexToBuf(arg_get_str(ctx, 4), ssf, sizeof(ssf), &ssf_len);

    int raw_len = 0;
    uint8_t raw[8] = {0};
    int res2 = CLIParamHexToBuf(arg_get_str(ctx, 5), raw, sizeof(raw), &raw_len);

    bool q5 = arg_get_lit(ctx, 6);
    bool em = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);
    if (res1 || res2) {
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len > 0);
    bool use_ssf = (ssf_len > 0);

    if (use_raw && raw_len != 8) {
        PrintAndLogEx(FAILED, "Raw data must be 8 bytes (64-bit), got %d", raw_len);
        return PM3_EINVARG;
    }
    if (use_raw && (use_ssf || vn_arg != UINT32_MAX || fc_arg != UINT32_MAX || cn_arg != UINT32_MAX)) {
        PrintAndLogEx(FAILED, "Can't combine --raw with --vn/--fc/--cn/--ssf");
        return PM3_EINVARG;
    }
    if (use_ssf && ssf_len != 2) {
        PrintAndLogEx(FAILED, "SSF prefix must be 2 hex bytes (4 hex chars), got %d", ssf_len);
        return PM3_EINVARG;
    }
    if (use_ssf && (vn_arg != UINT32_MAX || fc_arg != UINT32_MAX || cn_arg == UINT32_MAX)) {
        PrintAndLogEx(FAILED, "Use --ssf <hex> with --cn <dec> (without --vn or --fc)");
        return PM3_EINVARG;
    }
    if (!use_raw && !use_ssf && (vn_arg == UINT32_MAX || fc_arg == UINT32_MAX || cn_arg == UINT32_MAX)) {
        PrintAndLogEx(FAILED, "Must specify --vn/--fc/--cn, --ssf/--cn, or --raw");
        return PM3_EINVARG;
    }

    uint32_t blocks[3] = {T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_64 | 2 << T55x7_MAXBLOCK_SHIFT, 0, 0};
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 2 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        // TODO: it seems an EM4305 tag supporting FSK still runs at RF/50 even if configured at RF/64
        // lf em 4x05 info <> lf read ; data detectclock --fs
        // So, it seems cloning ioProx on EM4305 is not possible...
        blocks[0] = EM4305_IOPROX_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    if (use_raw) {
        blocks[1] = bytes_to_num(raw, 4);
        blocks[2] = bytes_to_num(raw + 4, 4);
        PrintAndLogEx(INFO, "Preparing to clone ioProx to " _YELLOW_("%s") " raw " _GREEN_("%s"), cardtype, sprint_hex_inrow(raw, sizeof(raw)));
    } else {
        uint8_t version = use_ssf ? ssf[0] : (uint8_t)vn_arg;
        uint8_t fc = use_ssf ? ssf[1] : (uint8_t)fc_arg;
        if (cn_arg > 0xFFFF) {
            PrintAndLogEx(INFO, "Card Number Truncated to 16-bits (ioProx): %u", cn_arg & 0xFFFF);
        }
        uint16_t cn = (uint16_t)(cn_arg & 0xFFFF);

        uint8_t bits[64];
        memset(bits, 0, sizeof(bits));
        if (getIOProxBits(version, fc, cn, bits) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation.");
            return PM3_ESOFT;
        }
        blocks[1] = bytebits_to_byte(bits, 32);
        blocks[2] = bytebits_to_byte(bits + 32, 32);
        PrintAndLogEx(INFO, "Preparing to clone ioProx to " _YELLOW_("%s") " with Version: " _GREEN_("%u") " FC: " _GREEN_("%u (0x%02x)") " CN: " _GREEN_("%u")
                      , cardtype
                      , version
                      , fc
                      , fc
                      , cn
                     );
    }

    // EM4305
    if (em) {
        // invert FSK data
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] = blocks[i] ^ 0xFFFFFFFF;
        }
    }

    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf io reader`") " to verify");
    return res;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "this help"},
    {"demod",   CmdIOProxDemod,  AlwaysAvailable, "demodulate an ioProx tag from the GraphBuffer"},
    {"reader",  CmdIOProxReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdIOProxClone,  IfPm3Lf,         "clone ioProx tag to T55x7 or Q5/T5555"},
    {"sim",     CmdIOProxSim,    IfPm3Lf,         "simulate ioProx tag"},
    {"watch",   CmdIOProxWatch,  IfPm3Lf,         "continuously watch for cards. Reader mode"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFIO(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

//Index map
//0           10          20          30          40          50          60
//|           |           |           |           |           |           |
//01234567 8 90123456 7 89012345 6 78901234 5 67890123 4 56789012 3 45678901 23
//-----------------------------------------------------------------------------
//00000000 0 11110000 1 facility 1 version* 1 code*one 1 code*two 1   crc    11
//XSF(version)facility:codeone+codetwo (raw)
int getIOProxBits(uint8_t version, uint8_t fc, uint16_t cn, uint8_t *bits) {
#define SEPARATOR 1
    uint8_t pos = 0;
    // the return bits, preamble 0000 0000 0
    uint8_t pre[64];
    memset(pre, 0, sizeof(pre));

    // skip 9 zeros as preamble
    pos = 9;

    // another fixed byte 11110000 = 0xF0
    num_to_bytebits(0xF0, 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // add facilitycode
    num_to_bytebits(fc, 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // add version
    num_to_bytebits(version, 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // cardnumber high byte
    num_to_bytebits(((cn & 0xFF00) >> 8), 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // cardnumber low byte
    num_to_bytebits((cn & 0xFF), 8, pre + pos);
    pos += 8;
    pre[pos] = SEPARATOR;
    pos++;

    // calculate and add CRC
    uint16_t crc = 0;
    for (uint8_t i = 1; i < 6; ++i)
        crc += bytebits_to_byte(pre + 9 * i, 8);

    crc &= 0xFF;
    crc = 0xff - crc;
    num_to_bytebits(crc, 8, pre + pos);
    pos += 8;

    // Final two ONES
    pre[pos] = SEPARATOR;
    pre[++pos] = SEPARATOR;

    memcpy(bits, pre, sizeof(pre));

    PrintAndLogEx(SUCCESS, "IO raw bits:\n %s \n", sprint_bytebits_bin(bits, 64));
    return PM3_SUCCESS;
}
