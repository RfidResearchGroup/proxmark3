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
// Low frequency WatchNET tag commands
// FSK2a, RF/50, 96 bits
//-----------------------------------------------------------------------------
#include "cmdlfwatchnet.h"
#include <string.h>
#include <stdlib.h>
#include "commonutil.h"
#include "cmdparser.h"
#include "cliparser.h"
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"
#include "lfdemod.h"
#include "parity.h"
#include "cmdlft55xx.h"
#include "cmdlfem4x05.h"

static int CmdHelp(const char *Cmd);

static const uint8_t watchnet_preamble[] = {0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 0};

static int watchnet_decode_bits(const uint8_t *frame_bits, uint8_t *fmt_len_out, uint32_t *fc_out, uint32_t *cn_out,
                                uint32_t *w_hi_out, uint32_t *w_lo_out, bool *parity_ok_out) {
    if (memcmp(frame_bits, watchnet_preamble, sizeof(watchnet_preamble)) != 0) {
        return PM3_ESOFT;
    }

    uint8_t work[96];
    memcpy(work, frame_bits, sizeof(work));

    size_t len = removeParity(work, 12, 4, 1, 84);
    if (len != 63) {
        return PM3_ESOFT;
    }

    uint8_t fmt_len = (uint8_t)bytebits_to_byte(work, 8);
    if (fmt_len < 26 || fmt_len > 55) {
        return PM3_ESOFT;
    }

    *fmt_len_out = fmt_len;

    if (fmt_len == 55) {
        *fc_out = bytebits_to_byte(work + 9, 21);
        *cn_out = bytebits_to_byte(work + 30, 32);
        *w_hi_out = bytebits_to_byte(work + 8, 23);
        *w_lo_out = bytebits_to_byte(work + 31, 32);

        // 55-bit Wiegand overlaps middle data bit (index 35) for both 27-bit halves
        uint8_t ep = work[8];
        uint8_t op = work[62];
        bool ep_ok = (ep == (evenparity32(bytebits_to_byte(work + 9, 27)) & 1));
        bool op_ok = (op == (oddparity32(bytebits_to_byte(work + 35, 27)) & 1));
        *parity_ok_out = (ep_ok && op_ok);
    }

    return PM3_SUCCESS;
}

static void watchnet_print_result(uint8_t fmt_len, uint32_t fc, uint32_t cn, uint32_t w_hi, uint32_t w_lo,
                                  bool parity_ok, const uint8_t *raw) {
    if (fmt_len == 55) {
        PrintAndLogEx(SUCCESS, "WatchNET - len: " _GREEN_("55") " FC: " _GREEN_("%u") " CN: " _GREEN_("%u")
                      " - Wiegand: " _GREEN_("%x%08x") " parity ( %s ), Raw: %s",
                      fc, cn, w_hi, w_lo,
                      parity_ok ? _GREEN_("ok") : _RED_("fail"),
                      sprint_hex_inrow(raw, 12));
    } else {
        PrintAndLogEx(SUCCESS, "WatchNET - len: " _GREEN_("%u") " (unsupported format), Raw: %s",
                      fmt_len, sprint_hex_inrow(raw, 12));
    }
}

int getWatchnetBits(uint32_t fc, uint32_t cn, uint8_t *bits) {
    if (bits == NULL || fc > 0x1FFFFF) {
        return PM3_EINVARG;
    }

    memset(bits, 0, 96);
    memcpy(bits, watchnet_preamble, sizeof(watchnet_preamble));

    uint8_t pre[63] = {0};
    num_to_bytebits(55, 8, pre);
    num_to_bytebits(fc, 21, pre + 9);
    num_to_bytebits(cn, 32, pre + 30);

    pre[8] = evenparity32(bytebits_to_byte(pre + 9, 27)) & 1;
    pre[62] = oddparity32(bytebits_to_byte(pre + 35, 27)) & 1;

    if (addParity(pre, bits + 12, sizeof(pre), 4, 1) != 84) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

int detectWatchnet(uint8_t *dest, size_t *size, int *wave_start_idx) {
    if (*size < 96 * 50) {
        return -1;
    }

    if (getSignalProperties()->isnoise) {
        return -2;
    }

    *size = fskdemod(dest, *size, 50, 1, 10, 8, wave_start_idx);
    if (*size < 96) {
        return -3;
    }

    size_t orig_size = *size;
    size_t start_idx = 0;
    uint8_t preamble[sizeof(watchnet_preamble)];
    memcpy(preamble, watchnet_preamble, sizeof(preamble));
    if (preambleSearch(dest, preamble, sizeof(preamble), size, &start_idx) == false) {
        return -4;
    }

    if (*size != 96 || start_idx + 96 > orig_size) {
        return -5;
    }

    return (int)start_idx;
}

int demodWatchnet(bool verbose) {
    (void) verbose;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = getFromGraphBuffer(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET not enough samples");
        free(bits);
        return PM3_ESOFT;
    }

    int wave_idx = 0;
    int idx = detectWatchnet(bits, &size, &wave_idx);
    if (idx < 0) {
        if (idx == -1) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET: not enough samples");
        } else if (idx == -2) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET: just noise detected");
        } else if (idx == -3) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET: problem during FSK demod");
        } else if (idx == -4) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET: preamble not found");
        } else {
            PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET: size not correct: %zu", size);
        }
        free(bits);
        return PM3_ESOFT;
    }

    uint8_t fmt_len = 0;
    uint32_t fc = 0, cn = 0, w_hi = 0, w_lo = 0;
    bool parity_ok = false;
    if (watchnet_decode_bits(bits + idx, &fmt_len, &fc, &cn, &w_hi, &w_lo, &parity_ok) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - WatchNET: parity or format length check failed");
        free(bits);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, 96, idx);
    setClockGrid(50, wave_idx + (idx * 50));

    uint8_t raw[12] = {0};
    bits_to_array(bits + idx, 96, raw);
    watchnet_print_result(fmt_len, fc, cn, w_hi, w_lo, parity_ok, raw);

    free(bits);
    return PM3_SUCCESS;
}

static int CmdWatchnetDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf watchnet demod",
                  "Try to find WatchNET preamble, if found decode / descramble data",
                  "lf watchnet demod\n"
                  "lf watchnet demod --raw 1fe2be111128811111118d88"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw bytes. 12 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int raw_len = 0;
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (raw_len == 0) {
        return demodWatchnet(true);
    }

    if (raw_len != 12) {
        PrintAndLogEx(FAILED, "Must specify 12 bytes, got " _YELLOW_("%d"), raw_len);
        return PM3_EINVARG;
    }

    uint8_t bits[96];
    bytes_to_bytebits(raw, sizeof(raw), bits);

    uint8_t fmt_len = 0;
    uint32_t fc = 0, cn = 0, w_hi = 0, w_lo = 0;
    bool parity_ok = false;
    if (watchnet_decode_bits(bits, &fmt_len, &fc, &cn, &w_hi, &w_lo, &parity_ok) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Invalid WatchNET raw data");
        return PM3_ESOFT;
    }

    watchnet_print_result(fmt_len, fc, cn, w_hi, w_lo, parity_ok, raw);
    return PM3_SUCCESS;
}

static int CmdWatchnetReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf watchnet reader",
                  "Read a WatchNET tag",
                  "lf watchnet reader -@   -> continuous reader mode"
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
        lf_read(false, 12000);
        demodWatchnet(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdWatchnetClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf watchnet clone",
                  "Clone a WatchNET tag to a T55x7, Q5/T5555 or EM4305/4469 tag",
                  "lf watchnet clone --fc 100 --cn 1234\n"
                  "lf watchnet clone --raw 1fe2be111128811111118d88\n"
                  "lf watchnet clone --fc 100 --cn 1234 --q5\n"
                  "lf watchnet clone --fc 100 --cn 1234 --em"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "fc", "<dec>", "facility code (0..2097151)"),
        arg_u64_0(NULL, "cn", "<dec>", "card number (32-bit)"),
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint64_t fc_arg = arg_get_u64_def(ctx, 1, UINT64_MAX);
    uint64_t cn_arg = arg_get_u64_def(ctx, 2, UINT64_MAX);

    int raw_len = 0;
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 3), raw, sizeof(raw), &raw_len);
    bool q5 = arg_get_lit(ctx, 4);
    bool em = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    bool use_fc_cn = (fc_arg != UINT64_MAX || cn_arg != UINT64_MAX);
    if (use_fc_cn && raw_len != 0) {
        PrintAndLogEx(FAILED, "Can't specify both FC/CN and RAW at the same time");
        return PM3_EINVARG;
    }

    if (use_fc_cn == false && raw_len == 0) {
        PrintAndLogEx(FAILED, "Must specify either --fc/--cn or --raw");
        return PM3_EINVARG;
    }

    uint32_t blocks[4] = {0};
    if (raw_len != 0) {
        if (raw_len != 12) {
            PrintAndLogEx(ERR, "Data must be 12 bytes (24 HEX characters), got %d", raw_len);
            return PM3_EINVARG;
        }
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
        }
    } else {
        if (fc_arg == UINT64_MAX || cn_arg == UINT64_MAX) {
            PrintAndLogEx(FAILED, "Must specify both --fc and --cn");
            return PM3_EINVARG;
        }
        if (fc_arg > 0x1FFFFF || cn_arg > 0xFFFFFFFF) {
            PrintAndLogEx(FAILED, "FC max is 2097151 and CN max is 4294967295");
            return PM3_EINVARG;
        }

        uint8_t bs[96] = {0};
        if (getWatchnetBits((uint32_t)fc_arg, (uint32_t)cn_arg, bs) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation");
            return PM3_ESOFT;
        }
        blocks[1] = bytebits_to_byte(bs, 32);
        blocks[2] = bytebits_to_byte(bs + 32, 32);
        blocks[3] = bytebits_to_byte(bs + 64, 32);
    }

    blocks[0] = T55X7_WATCHNET_CONFIG_BLOCK;
    char cardtype[16] = {"T55x7"};
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        blocks[0] = EM4305_WATCHNET_CONFIG_BLOCK;
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] ^= 0xFFFFFFFF;
        }
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone WatchNET to " _YELLOW_("%s"), cardtype);
    print_blocks(blocks, ARRAYLEN(blocks));

    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf watchnet reader`") " to verify");
    return res;
}

static int CmdWatchnetSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf watchnet sim",
                  "Enables simulation of WatchNET card with specified facility code and card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf watchnet sim --fc 100 --cn 1234\n"
                  "lf watchnet sim --raw 1fe2be111128811111118d88"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "fc", "<dec>", "facility code (0..2097151)"),
        arg_u64_0(NULL, "cn", "<dec>", "card number (32-bit)"),
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint64_t fc_arg = arg_get_u64_def(ctx, 1, UINT64_MAX);
    uint64_t cn_arg = arg_get_u64_def(ctx, 2, UINT64_MAX);

    int raw_len = 0;
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 3), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    bool use_fc_cn = (fc_arg != UINT64_MAX || cn_arg != UINT64_MAX);
    if (use_fc_cn && raw_len != 0) {
        PrintAndLogEx(FAILED, "Can't specify both FC/CN and RAW at the same time");
        return PM3_EINVARG;
    }

    if (use_fc_cn == false && raw_len == 0) {
        PrintAndLogEx(FAILED, "Must specify either --fc/--cn or --raw");
        return PM3_EINVARG;
    }

    uint8_t bs[96] = {0};
    if (raw_len != 0) {
        if (raw_len != 12) {
            PrintAndLogEx(ERR, "Data must be 12 bytes (24 HEX characters), got %d", raw_len);
            return PM3_EINVARG;
        }
        bytes_to_bytebits(raw, sizeof(raw), bs);
    } else {
        if (fc_arg == UINT64_MAX || cn_arg == UINT64_MAX) {
            PrintAndLogEx(FAILED, "Must specify both --fc and --cn");
            return PM3_EINVARG;
        }
        if (fc_arg > 0x1FFFFF || cn_arg > 0xFFFFFFFF) {
            PrintAndLogEx(FAILED, "FC max is 2097151 and CN max is 4294967295");
            return PM3_EINVARG;
        }
        if (getWatchnetBits((uint32_t)fc_arg, (uint32_t)cn_arg, bs) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Error with tag bitstream generation");
            return PM3_ESOFT;
        }
        bits_to_array(bs, sizeof(bs), raw);
    }

    PrintAndLogEx(SUCCESS, "Simulating WatchNET - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->fchigh = 10;
    payload->fclow = 8;
    payload->separator = 0;
    payload->clock = 50;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload, sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    return lfsim_wait_check(CMD_LF_FSK_SIMULATE);
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,           AlwaysAvailable, "This help"},
    {"demod",  CmdWatchnetDemod,  AlwaysAvailable, "demodulate a WatchNET FSK tag from the GraphBuffer"},
    {"reader", CmdWatchnetReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdWatchnetClone,  IfPm3Lf,         "clone WatchNET tag to T55x7, Q5/T5555 or EM4305/4469"},
    {"sim",    CmdWatchnetSim,    IfPm3Lf,         "simulate WatchNET tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFWatchnet(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
