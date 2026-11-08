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
#include "commonutil.h"  // ARRAYLEN

static int CmdHelp(const char *Cmd);

#define PCF7931_DEFAULT_INITDELAY 17450
#define PCF7931_DEFAULT_OFFSET_WIDTH 0
#define PCF7931_DEFAULT_OFFSET_POSITION 0

#define PCF7931_BLOCKS 8
#define PCF7931_BLOCK_SIZE 16

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

#define PCF7931_POS_UNKNOWN 0xFF

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

// the same block number must always carry the same data
static bool pcf7931_numbering_fits(const pcf7931_read_t *rd, const uint8_t *num, size_t k) {
    for (size_t j = 0; j < k; j++) {
        if (num[j] == num[k] && num[k] != PCF7931_POS_UNKNOWN && memcmp(rd->blocks[j], rd->blocks[k], PCF7931_BLOCK_SIZE)) {
            return false;
        }
    }
    // with PAC set the password reads as zeros
    if (num[k] == 0 && (rd->blocks[k][7] & 0x01)) {
        static const uint8_t zeros[7] = {0};
        if (memcmp(rd->blocks[k], zeros, sizeof(zeros))) {
            return false;
        }
    }
    return true;
}

// smallest number of blocks per cycle consistent with the data, 0 if none.
// up to 9: with RB1 block 1 is sent twice when RFB..RLB covers all blocks
static size_t pcf7931_period(const pcf7931_read_t *rd) {
    for (size_t p = 1; p <= PCF7931_BLOCKS + 1; p++) {
        bool ok = true;
        for (size_t k = 0; k < rd->count && ok; k++) {
            for (size_t j = 0; j < k && ok; j++) {
                if (rd->pos[j] == PCF7931_POS_UNKNOWN || rd->pos[k] == PCF7931_POS_UNKNOWN) {
                    continue;
                }
                if ((rd->pos[j] % p) == (rd->pos[k] % p) && memcmp(rd->blocks[j], rd->blocks[k], PCF7931_BLOCK_SIZE)) {
                    ok = false;
                }
            }
        }
        if (ok) {
            return p;
        }
    }
    return 0;
}

typedef struct {
    uint8_t num[PCF7931_READ_MAX_BLOCKS];   // block number of each received block
    const uint8_t *blk1;
    bool aligned;                           // first block after reset is the first of the sequence
    int reserved;                           // reserved bits set in block 1
} pcf7931_cand_t;

// bits reserved for future use in block 1 (datasheet fig 8), expected 0
static int pcf7931_reserved_bits(const uint8_t *blk1) {
    int n = __builtin_popcount(blk1[14] & 0x78) + __builtin_popcount(blk1[15] & 0xF8);
    for (int i = 8; i < 14; i++) {
        n += __builtin_popcount(blk1[i]);
    }
    return n;
}

// every numbering in which one received block, taken as block 1, explains all the data
static size_t pcf7931_block1_candidates(const pcf7931_read_t *rd, pcf7931_cand_t *cands, size_t max) {
    size_t n = 0;
    size_t p = pcf7931_period(rd);

    for (size_t c = 0; c < rd->count; c++) {
        if (rd->pos[c] == PCF7931_POS_UNKNOWN) {
            continue;
        }
        uint8_t seq[PCF7931_BLOCKS + 1];
        size_t len = pcf7931_sequence(rd->blocks[c], seq);
        // a longer selection could explain any repeating data, it must match the data exactly
        if (len != p) {
            continue;
        }
        for (size_t s = 0; s < len; s++) {
            if (seq[s] != 1) {
                continue;
            }
            // shift putting block c at sequence index s
            size_t off = (s + len - (rd->pos[c] % len)) % len;
            pcf7931_cand_t cand = { .blk1 = rd->blocks[c], .aligned = (off == 0), .reserved = pcf7931_reserved_bits(rd->blocks[c]) };
            bool ok = true;
            for (size_t k = 0; k < rd->count && ok; k++) {
                cand.num[k] = (rd->pos[k] == PCF7931_POS_UNKNOWN) ? PCF7931_POS_UNKNOWN : seq[(rd->pos[k] + off) % len];
                ok = pcf7931_numbering_fits(rd, cand.num, k);
                // block 1 may be sent twice per cycle (RB1), both must match
                if (ok && cand.num[k] == 1 && memcmp(rd->blocks[k], rd->blocks[c], PCF7931_BLOCK_SIZE)) {
                    ok = false;
                }
            }
            if (ok == false) {
                continue;
            }
            bool dup = false;
            for (size_t i = 0; i < n; i++) {
                if (memcmp(cands[i].num, cand.num, rd->count) == 0) {
                    dup = true;
                }
            }
            if (dup == false && n < max) {
                cands[n++] = cand;
            }
        }
    }
    return n;
}

// keep only the candidates matching keep[], unless that would drop all of them
static size_t pcf7931_filter(pcf7931_cand_t *cands, size_t n, const bool *keep) {
    size_t m = 0;
    for (size_t i = 0; i < n; i++) {
        m += keep[i];
    }
    if (m == 0 || m == n) {
        return n;
    }
    m = 0;
    for (size_t i = 0; i < n; i++) {
        if (keep[i]) {
            cands[m++] = cands[i];
        }
    }
    return m;
}

static void pcf7931_print_memory(const uint8_t **mem) {
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
}

static void pcf7931_print_blocks(const pcf7931_read_t *rd, int user_rfb) {
    const uint8_t *mem[PCF7931_BLOCKS] = {NULL};
    pcf7931_cand_t cands[2 * PCF7931_READ_MAX_BLOCKS];
    size_t nc = pcf7931_block1_candidates(rd, cands, ARRAYLEN(cands));

    if (nc) {
        bool keep[ARRAYLEN(cands)];
        const char *why = NULL;

        for (size_t i = 0; i < nc; i++) {
            keep[i] = cands[i].aligned;
        }
        nc = pcf7931_filter(cands, nc, keep);
        if (cands[0].aligned == false) {
            PrintAndLogEx(WARNING, "Transmission start not aligned to RFB, numbering from block 1 only");
        }

        if (user_rfb >= 0 && nc > 1) {
            for (size_t i = 0; i < nc; i++) {
                keep[i] = ((cands[i].blk1[14] & 0x07) == user_rfb);
            }
            size_t before = nc;
            nc = pcf7931_filter(cands, nc, keep);
            if (nc < before) {
                why = "RFB given";
            }
        }

        if (nc > 1) {
            int best = INT32_MAX;
            for (size_t i = 0; i < nc; i++) {
                best = MIN(best, cands[i].reserved);
            }
            for (size_t i = 0; i < nc; i++) {
                keep[i] = (cands[i].reserved == best);
            }
            size_t before = nc;
            nc = pcf7931_filter(cands, nc, keep);
            if (nc < before) {
                why = "chosen by fewest reserved bits set";
            }
        }

        if (nc > 1) {
            // order after reset is known, which block is block 1 is not
            size_t p = pcf7931_period(rd);
            char rfbs[3 * ARRAYLEN(cands) + 1] = {0};
            for (size_t i = 0; i < nc; i++) {
                snprintf(rfbs + strlen(rfbs), sizeof(rfbs) - strlen(rfbs), "%u ", cands[i].blk1[14] & 0x07);
            }
            PrintAndLogEx(WARNING, "More than one block fits as block 1, numbering is ambiguous");
            PrintAndLogEx(INFO, "Possible RFB............ %s", rfbs);
            PrintAndLogEx(INFO, "-----+-------------------------------------------------");
            for (size_t i = 0; i < p; i++) {
                const uint8_t *blk = NULL;
                for (size_t k = 0; k < rd->count; k++) {
                    if (rd->pos[k] != PCF7931_POS_UNKNOWN && (rd->pos[k] % p) == i) {
                        blk = rd->blocks[k];
                    }
                }
                if (blk) {
                    PrintAndLogEx(SUCCESS, " #%zu  | %s", i, sprint_hex(blk, PCF7931_BLOCK_SIZE));
                }
            }
            PrintAndLogEx(INFO, "-----+-------------------------------------------------");
            PrintAndLogEx(HINT, "Hint: #n is the n-th block sent after reset, use `" _YELLOW_("--rfb <n>") "` to pick the numbering");
            return;
        }

        for (size_t k = 0; k < rd->count; k++) {
            if (cands[0].num[k] != PCF7931_POS_UNKNOWN) {
                mem[cands[0].num[k]] = rd->blocks[k];
            }
        }
        const uint8_t *blk1 = cands[0].blk1;

        uint8_t seq[PCF7931_BLOCKS + 1];
        size_t len = pcf7931_sequence(blk1, seq);
        char order[3 * (PCF7931_BLOCKS + 1) + 1] = {0};
        for (size_t i = 0; i < len; i++) {
            snprintf(order + strlen(order), sizeof(order) - strlen(order), "%u ", seq[i]);
        }
        PrintAndLogEx(INFO, "Transmission cycle...... %s", order);
        pcf7931_print_memory(mem);
        PrintAndLogEx(INFO, "Selection............... RFB %u, RLB %u, RB1 %u%s%s%s",
                      blk1[14] & 0x07, blk1[15] & 0x07, blk1[14] >> 7,
                      why ? " (" : "", why ? why : "", why ? ")" : "");
        return;
    }

    // block 1 is not sent: order is known from the reset, block numbers are not
    size_t p = pcf7931_period(rd);
    if (p == 0 || p >= PCF7931_BLOCKS) {
        PrintAndLogEx(WARNING, "Inconsistent read, blocks in received order:");
        for (size_t k = 0; k < rd->count; k++) {
            PrintAndLogEx(INFO, "Block ? | %s", sprint_hex(rd->blocks[k], PCF7931_BLOCK_SIZE));
        }
        return;
    }

    const uint8_t *cycle[PCF7931_BLOCKS] = {NULL};
    for (size_t k = 0; k < rd->count; k++) {
        if (rd->pos[k] != PCF7931_POS_UNKNOWN) {
            cycle[rd->pos[k] % p] = rd->blocks[k];
        }
    }

    // RB1 = 0 and block 1 outside RFB..RLB
    char rfb_list[3 * PCF7931_BLOCKS + 1] = {0};
    int ncand = 0, rfb = -1;
    for (int r = 0; r < PCF7931_BLOCKS; r++) {
        if (((1 - r) & 0x07) >= (int)p) {
            snprintf(rfb_list + strlen(rfb_list), sizeof(rfb_list) - strlen(rfb_list), "%d ", r);
            ncand++;
            rfb = r;
        }
    }

    PrintAndLogEx(INFO, "Block 1 not identified, the tag does not send block numbers");
    PrintAndLogEx(INFO, "Blocks per cycle........ %zu%s", p, (p == 1) ? " (or more identical blocks)" : "");
    PrintAndLogEx(INFO, "Possible RFB............ %s", rfb_list);

    if (user_rfb >= 0) {
        if (((1 - user_rfb) & 0x07) < (int)p) {
            PrintAndLogEx(WARNING, "RFB %d would include block 1 in the cycle", user_rfb);
        }
        rfb = user_rfb;
    } else if (ncand != 1) {
        PrintAndLogEx(INFO, "-------+-------------------------------------------------");
        for (size_t i = 0; i < p; i++) {
            if (cycle[i]) {
                PrintAndLogEx(SUCCESS, " RFB+%zu | %s", i, sprint_hex(cycle[i], PCF7931_BLOCK_SIZE));
            } else {
                PrintAndLogEx(INFO, " RFB+%zu | " _YELLOW_("not received"), i);
            }
        }
        PrintAndLogEx(INFO, "-------+-------------------------------------------------");
        PrintAndLogEx(HINT, "Hint: blocks are in transmission order, use `" _YELLOW_("--rfb <n>") "` to number them");
        return;
    }

    for (size_t i = 0; i < p; i++) {
        mem[(rfb + i) & 0x07] = cycle[i];
    }
    pcf7931_print_memory(mem);
    PrintAndLogEx(INFO, "Selection............... RFB %d, RLB %d, RB1 0 (%s)",
                  rfb, (int)((rfb + p - 1) & 0x07), (user_rfb >= 0) ? "RFB given" : "inferred");
}

static int CmdLFPCF7931Reader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf pcf7931 reader",
                  "read a PCF7931 tag",
                  "lf pcf7931 reader -@      -> continuous reader mode\n"
                  "lf pcf7931 reader --rfb 2 -> number blocks starting at 2 when block 1 is missing or ambiguous"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_int0(NULL, "rfb", "<0-7>", "first transmitted block, used when block 1 is missing or ambiguous"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    int rfb = arg_get_int_def(ctx, 2, -1);
    CLIParserFree(ctx);

    if (rfb < -1 || rfb >= PCF7931_BLOCKS) {
        PrintAndLogEx(ERR, "RFB must be between 0-7");
        return PM3_EINVARG;
    }

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

        if (resp.length != sizeof(pcf7931_read_t)) {
            PrintAndLogEx(ERR, "Wrong reply length, firmware and client do not match");
            return PM3_ESOFT;
        }

        pcf7931_read_t *rd = (pcf7931_read_t *)resp.data.asBytes;
        rd->count = MIN(rd->count, PCF7931_READ_MAX_BLOCKS);
        if (rd->count == 0) {
            PrintAndLogEx(WARNING, "No PCF7931 tag found");
        } else {
            pcf7931_print_blocks(rd, rfb);
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

