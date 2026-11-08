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
// Low frequency PCF7931 commands
//-----------------------------------------------------------------------------
#include "cmdlfpcf7931.h"
#include <string.h>
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

#define PCF7931_DEFAULT_INITDELAY 17450
#define PCF7931_DEFAULT_OFFSET_WIDTH 0
#define PCF7931_DEFAULT_OFFSET_POSITION 0

#define PCF7931_BLOCKS 8
#define PCF7931_BLOCK_SIZE 16
#define PCF7931_MAX_CAPTURE 16

// Default values - Configuration
static struct pcf7931_config configPcf = {
    {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF},
    PCF7931_DEFAULT_INITDELAY,
    PCF7931_DEFAULT_OFFSET_WIDTH,
    PCF7931_DEFAULT_OFFSET_POSITION
};

// Resets the configuration settings to default values.
int pcf7931_resetConfig(void) {
    memset(configPcf.Pwd, 0xFF, sizeof(configPcf.Pwd));
    configPcf.InitDelay = PCF7931_DEFAULT_INITDELAY;
    configPcf.OffsetWidth = PCF7931_DEFAULT_OFFSET_WIDTH;
    configPcf.OffsetPosition = PCF7931_DEFAULT_OFFSET_POSITION;
    PrintAndLogEx(INFO, "Configuration reset");
    PrintAndLogEx(HINT, "Hint: Try `" _YELLOW_("lf pcf7931 config") "` to view current settings");
    return PM3_SUCCESS;
}

int pcf7931_printConfig(void) {
    PrintAndLogEx(INFO, "Password (LSB first on bytes)... " _YELLOW_("%s"), sprint_hex(configPcf.Pwd, sizeof(configPcf.Pwd)));
    PrintAndLogEx(INFO, "Tag initialization delay........ " _YELLOW_("%d") " us", configPcf.InitDelay);
    PrintAndLogEx(INFO, "Offset low pulses width......... " _YELLOW_("%d") " us", configPcf.OffsetWidth);
    PrintAndLogEx(INFO, "Offset low pulses position...... " _YELLOW_("%d") " us", configPcf.OffsetPosition);
    return PM3_SUCCESS;
}

// smallest cycle length repeating over the whole capture, 0 if none
static size_t pcf7931_find_cycle(const uint8_t *blocks, size_t n) {
    for (size_t p = 1; p <= PCF7931_BLOCKS && p < n; p++) {
        bool ok = true;
        for (size_t i = 0; i + p < n; i++) {
            if (memcmp(blocks + i * PCF7931_BLOCK_SIZE, blocks + (i + p) * PCF7931_BLOCK_SIZE, PCF7931_BLOCK_SIZE)) {
                ok = false;
                break;
            }
        }
        if (ok) {
            return p;
        }
    }
    return 0;
}

// block numbers sent per cycle according to the selection in block 1 (datasheet fig 10)
static size_t pcf7931_sequence(const uint8_t *blk1, uint8_t *seq) {
    uint8_t rfb = blk1[14] & 0x07;
    uint8_t rlb = blk1[15] & 0x07;
    size_t len = 0;
    if (blk1[14] & 0x80) {
        seq[len++] = 1;
    }
    for (uint8_t b = rfb; ; b = (b + 1) & 0x07) {
        seq[len++] = b;
        if (b == rlb) {
            break;
        }
    }
    return len;
}

// number each block of the cycle by finding the one block 1 whose selection explains it.
// returns false if no or more than one numbering fits
static bool pcf7931_number_cycle(const uint8_t *cycle, size_t p, uint8_t *num) {
    int found = 0;
    for (size_t c = 0; c < p; c++) {
        const uint8_t *blk1 = cycle + c * PCF7931_BLOCK_SIZE;
        uint8_t seq[PCF7931_BLOCKS + 1];
        if (pcf7931_sequence(blk1, seq) != p) {
            continue;
        }
        for (size_t s = 0; s < p; s++) {
            if (seq[s] != 1) {
                continue;
            }
            uint8_t cand[PCF7931_BLOCKS + 1];
            bool ok = true;
            for (size_t t = 0; t < p; t++) {
                size_t idx = (c + t) % p;
                cand[idx] = seq[(s + t) % p];
                // block 1 may be sent twice per cycle (RB1), both must match
                if (cand[idx] == 1 && memcmp(cycle + idx * PCF7931_BLOCK_SIZE, blk1, PCF7931_BLOCK_SIZE)) {
                    ok = false;
                }
                // with PAC set the password reads as zeros
                if (cand[idx] == 0 && (cycle[idx * PCF7931_BLOCK_SIZE + 7] & 0x01)) {
                    static const uint8_t zeros[7] = {0};
                    if (memcmp(cycle + idx * PCF7931_BLOCK_SIZE, zeros, sizeof(zeros))) {
                        ok = false;
                    }
                }
            }
            if (ok == false) {
                continue;
            }
            if (found && memcmp(num, cand, p)) {
                return false;
            }
            memcpy(num, cand, p);
            found = 1;
        }
    }
    return found;
}

static void pcf7931_print_blocks(const uint8_t *blocks, size_t n) {
    size_t p = pcf7931_find_cycle(blocks, n);
    uint8_t num[PCF7931_BLOCKS + 1] = {0};

    if (p == 0 || pcf7931_number_cycle(blocks, p, num) == false) {
        PrintAndLogEx(WARNING, "Could not identify block 0/1, blocks in received order:");
        for (size_t i = 0; i < n; i++) {
            PrintAndLogEx(INFO, "Block ? | %s", sprint_hex(blocks + i * PCF7931_BLOCK_SIZE, PCF7931_BLOCK_SIZE));
        }
        if (p == 1) {
            PrintAndLogEx(HINT, "Hint: a single repeated block is likely block 0 with RFB = RLB = 0 (factory default)");
        }
        return;
    }

    const uint8_t *mem[PCF7931_BLOCKS] = {NULL};
    for (size_t i = 0; i < p; i++) {
        mem[num[i]] = blocks + i * PCF7931_BLOCK_SIZE;
    }

    uint8_t seq[PCF7931_BLOCKS + 1];
    size_t len = pcf7931_sequence(mem[1], seq);
    char order[3 * (PCF7931_BLOCKS + 1) + 1] = {0};
    for (size_t i = 0; i < len; i++) {
        snprintf(order + strlen(order), sizeof(order) - strlen(order), "%u ", seq[i]);
    }

    PrintAndLogEx(INFO, "Transmission cycle... %s", order);
    PrintAndLogEx(INFO, "-----+-------------------------------------------------");
    for (int b = 0; b < PCF7931_BLOCKS; b++) {
        if (mem[b]) {
            PrintAndLogEx(SUCCESS, " %2d  | %s", b, sprint_hex(mem[b], PCF7931_BLOCK_SIZE));
        } else {
            PrintAndLogEx(INFO, " %2d  | " _YELLOW_("not transmitted"), b);
        }
    }
    PrintAndLogEx(INFO, "-----+-------------------------------------------------");

    if (mem[0]) {
        bool pac = mem[0][7] & 0x01;
        PrintAndLogEx(INFO, "PAC (password check).... %s", pac ? _RED_("enabled") " (password reads as 00)" : _GREEN_("disabled"));
        if (pac == false) {
            PrintAndLogEx(INFO, "Password................ " _YELLOW_("%s"), sprint_hex(mem[0], 7));
        }
        char bwp[3 * PCF7931_BLOCKS + 1] = {0};
        for (int b = 0; b < PCF7931_BLOCKS; b++) {
            if (mem[0][8] & (1 << b)) {
                snprintf(bwp + strlen(bwp), sizeof(bwp) - strlen(bwp), "%d ", b);
            }
        }
        PrintAndLogEx(INFO, "Write protected blocks.. %s", strlen(bwp) ? bwp : "none");
    }
    PrintAndLogEx(INFO, "Selection............... RFB %u, RLB %u, RB1 %u",
                  mem[1][14] & 0x07, mem[1][15] & 0x07, mem[1][14] >> 7);
}

static int CmdLFPCF7931Reader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pcf7931 reader",
                  "read a PCF7931 tag",
                  "lf pcf7931 reader -@   -> continuous reader mode"
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
        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_LF_PCF7931_READ, NULL, 0);
        if (WaitForResponseTimeout(CMD_LF_PCF7931_READ, &resp, 15000) == false) {
            PrintAndLogEx(WARNING, "command execution time out");
            return PM3_ETIMEOUT;
        }

        size_t n = MIN(resp.length / PCF7931_BLOCK_SIZE, PCF7931_MAX_CAPTURE);
        if (n == 0) {
            PrintAndLogEx(WARNING, "No PCF7931 tag found");
        } else {
            pcf7931_print_blocks(resp.data.asBytes, n);
        }
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdLFPCF7931Config(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pcf7931 config",
                  "This command tries to set the configuration used with PCF7931 commands\n"
                  "The time offsets could be useful to correct slew rate generated by the antenna\n"
                  "Caling without some parameter will print the current configuration.",
                  "lf pcf7931 config --reset\n"
                  "lf pcf7931 config --pwd 11223344556677 -d 20000\n"
                  "lf pcf7931 config --pwd 11223344556677 -d 17500 --lw -10 --lp 30"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", "reset", "Reset configuration to default values"),
        arg_str0("p", "pwd", "<hex>", "Password, 7bytes, LSB-order"),
        arg_u64_0("d", "delay", "<dec>", "Tag initialization delay (in us)"),
        arg_int0(NULL, "lw", "<dec>", "offset, low pulses width (in us), optional!"),
        arg_int0(NULL, "lp", "<dec>", "offset, low pulses position (in us), optional!"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_reset = arg_get_lit(ctx, 1);
    if (use_reset) {
        CLIParserFree(ctx);
        return pcf7931_resetConfig();
    }

    int pwd_len = 0;
    uint8_t pwd[7] = {0};
    CLIGetHexWithReturn(ctx, 2, pwd, &pwd_len);

    uint32_t delay = arg_get_u32_def(ctx, 3, -1);
    int ow = arg_get_int_def(ctx, 4, 0xFFFF);
    int op = arg_get_int_def(ctx, 5, 0xFFFF);
    CLIParserFree(ctx);

    if (pwd_len && pwd_len < sizeof(pwd)) {
        PrintAndLogEx(ERR, "Password must be 7 bytes");
        return PM3_EINVARG;
    }

    if (delay != -1 && (delay == 0 || delay > 0xFFFF)) {
        PrintAndLogEx(ERR, "Delay must be between 1-65535 us");
        return PM3_EINVARG;
    }

    if ((ow != 0xFFFF && (ow < -128 || ow > 127)) || (op != 0xFFFF && (op < -128 || op > 127))) {
        PrintAndLogEx(ERR, "Offsets must be between -128 and 127 us");
        return PM3_EINVARG;
    }

    if (pwd_len) {
        memcpy(configPcf.Pwd, pwd, sizeof(configPcf.Pwd));
    }
    if (delay != -1) {
        configPcf.InitDelay = (delay & 0xFFFF);
    }
    if (ow != 0xFFFF) {
        configPcf.OffsetWidth = (ow & 0xFFFF);
    }
    if (op != 0xFFFF) {
        configPcf.OffsetPosition = (op & 0xFFFF);
    }

    pcf7931_printConfig();
    return PM3_SUCCESS;
}

static int CmdLFPCF7931Write(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pcf7931 write",
                  "This command tries to write a PCF7931 tag.",
                  "lf pcf7931 write --blk 2 --idx 1 -d FF  -> Write 0xFF to block 2, index 1 "
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1("b", "blk", "<dec>", "[0-7] block number"),
        arg_u64_1("i", "idx", "<dec>", "[0-15] index of byte inside block"),
        arg_str1("d", "data", "<hex>", "one byte to be written"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t block = arg_get_u32_def(ctx, 1, 0);
    uint8_t idx = arg_get_u32_def(ctx, 2, 0);

    int data_len = 0;
    uint8_t data[1] = {0};
    CLIGetHexWithReturn(ctx, 3, data, &data_len);
    CLIParserFree(ctx);

    if (block > 7) {
        PrintAndLogEx(ERR, "out-of-range error, block must be between 0-7");
        return PM3_EINVARG;
    }

    if (idx > 15) {
        PrintAndLogEx(ERR, "out-of-range error, index must be between 0-15");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Writing block %u at idx %u with data 0x%02X", block, idx, data[0]);

    pcf7931_write_t payload = {
        .offset_width = (uint8_t)(configPcf.OffsetWidth + 128),
        .offset_position = (uint8_t)(configPcf.OffsetPosition + 128),
        .init_delay = configPcf.InitDelay,
        .address = block,
        .byte = idx,
        .data = data[0],
    };
    memcpy(payload.pwd, configPcf.Pwd, sizeof(payload.pwd));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PCF7931_WRITE, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_LF_PCF7931_WRITE, &resp, 4000) == false) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply");
        return PM3_ETIMEOUT;
    }

    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf pcf7931 reader`") " to verify");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,            AlwaysAvailable, "This help"},
    {"reader", CmdLFPCF7931Reader, IfPm3Lf,         "Read content of a PCF7931 transponder"},
    {"write",  CmdLFPCF7931Write,  IfPm3Lf,         "Write data on a PCF7931 transponder."},
    {"config", CmdLFPCF7931Config, AlwaysAvailable, "Configure the password, the tags initialization delay and time offsets (optional)"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFPCF7931(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

