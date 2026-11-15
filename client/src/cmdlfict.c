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
// Low frequency ICT tag commands
// FSK2a, RF/50, 224 bits (7 blocks)
//-----------------------------------------------------------------------------
#include "cmdlfict.h"
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
#include "cmdlft55xx.h"
#include "cmdlfem4x05.h"

#define ICT_FRAME_BITS   224
#define ICT_BLOCK_COUNT  7

static int CmdHelp(const char *Cmd);

typedef enum {
    ICT_TYPE_UNKNOWN = 0,
    ICT_TYPE_24X,
    ICT_TYPE_GT081,
} ict_tag_type_t;

static bool ict_manchester_decode_blocks(const uint32_t *blocks, uint8_t num_blocks, uint16_t start_bit,
                                         uint8_t *decoded_bits, size_t *decoded_len) {
    if (blocks == NULL || decoded_bits == NULL || decoded_len == NULL) {
        return false;
    }
    if ((start_bit & 1) != 0 || num_blocks == 0 || start_bit >= (uint16_t)num_blocks * 32) {
        return false;
    }

    size_t cnt = 0;
    for (uint8_t b = (uint8_t)(start_bit / 32); b < num_blocks; b++) {
        uint8_t first = (b == start_bit / 32) ? (uint8_t)(start_bit & 31) : 0;
        for (int p = first; p <= 30; p += 2) {
            uint8_t b0 = (blocks[b] >> (31 - p)) & 1;
            uint8_t b1 = (blocks[b] >> (30 - p)) & 1;
            if (b0 == b1) {
                return false;
            }
            decoded_bits[cnt++] = b0;
        }
    }

    *decoded_len = cnt;
    return true;
}

static ict_tag_type_t ict_classify_blocks(const uint32_t blocks[ICT_BLOCK_COUNT], uint8_t *decoded_bits, size_t *decoded_len) {
    if ((blocks[0] >> 28) != 0xF || blocks[6] != 0) {
        return ICT_TYPE_UNKNOWN;
    }

    if (blocks[5] != 0) {
        if ((blocks[0] >> 24) == 0xF6 &&
                ict_manchester_decode_blocks(blocks, 6, 4, decoded_bits, decoded_len)) {
            return ICT_TYPE_24X;
        }
    } else {
        if ((blocks[4] & 0xF) == 0 && (blocks[0] >> 12) == 0xF5565) {
            uint32_t work[5] = {blocks[0], blocks[1], blocks[2], blocks[3], blocks[4] | 0x5};
            if (ict_manchester_decode_blocks(work, 5, 4, decoded_bits, decoded_len)) {
                return ICT_TYPE_GT081;
            }
        }
    }

    return ICT_TYPE_UNKNOWN;
}

static void ict_bits_to_hex(const uint8_t *bits, size_t bit_len, char *out, size_t out_size) {
    size_t padded = (bit_len + 3) & ~(size_t)3;
    size_t nibbles = padded / 4;
    size_t lead_zeros = padded - bit_len;

    if (nibbles + 1 > out_size) {
        if (out_size > 0) {
            out[0] = '\0';
        }
        return;
    }

    static const char hex_chars[] = "0123456789abcdef";
    for (size_t n = 0; n < nibbles; n++) {
        uint8_t val = 0;
        for (size_t k = 0; k < 4; k++) {
            size_t pos = n * 4 + k;
            uint8_t bit = (pos < lead_zeros) ? 0 : bits[pos - lead_zeros];
            val = (uint8_t)((val << 1) | bit);
        }
        out[n] = hex_chars[val];
    }
    out[nibbles] = '\0';
}

static void ict_print_result(ict_tag_type_t type, const uint8_t *decoded_bits, size_t decoded_len,
                             const uint32_t blocks[ICT_BLOCK_COUNT]) {
    char dec_hex[32] = {0};
    if (type != ICT_TYPE_UNKNOWN) {
        ict_bits_to_hex(decoded_bits, decoded_len, dec_hex, sizeof(dec_hex));
    }

    const char *label = (type == ICT_TYPE_24X) ? "ICT 24X" :
                        (type == ICT_TYPE_GT081) ? "ICT GT 081" : "Unknown";

    if (type != ICT_TYPE_UNKNOWN) {
        PrintAndLogEx(SUCCESS, "ICT - Type: " _GREEN_("%s") ", Decoded (%zu bits): " _GREEN_("%s")
                      ", Raw: %08x%08x%08x%08x%08x%08x%08x",
                      label, decoded_len, dec_hex,
                      blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], blocks[6]);
    } else {
        PrintAndLogEx(SUCCESS, "ICT - Type: " _YELLOW_("%s") ", Raw: %08x%08x%08x%08x%08x%08x%08x",
                      label,
                      blocks[0], blocks[1], blocks[2], blocks[3], blocks[4], blocks[5], blocks[6]);
    }
}

int detectLFICT(uint8_t *dest, size_t *size, int *wave_start_idx) {
    if (*size < ICT_FRAME_BITS * 50) {
        return -1;
    }

    if (getSignalProperties()->isnoise) {
        return -2;
    }

    *size = fskdemod(dest, *size, 50, 1, 10, 8, wave_start_idx);
    if (*size < ICT_FRAME_BITS) {
        return -3;
    }

    static const uint8_t preamble[4] = {1, 1, 1, 1};
    static const uint8_t postamble[32] = {0};

    for (size_t i = 0; i + ICT_FRAME_BITS <= *size; i++) {
        if (memcmp(dest + i, preamble, sizeof(preamble)) != 0) {
            continue;
        }
        if (memcmp(dest + i + 192, postamble, sizeof(postamble)) != 0) {
            continue;
        }
        if (i + ICT_FRAME_BITS + 4 <= *size &&
                memcmp(dest + i + ICT_FRAME_BITS, preamble, sizeof(preamble)) != 0) {
            continue;
        }

        uint32_t blocks[ICT_BLOCK_COUNT];
        for (uint8_t b = 0; b < ICT_BLOCK_COUNT; b++) {
            blocks[b] = bytebits_to_byte(dest + i + (b * 32), 32);
        }

        uint8_t dec_bits[128] = {0};
        size_t dec_len = 0;
        if (ict_classify_blocks(blocks, dec_bits, &dec_len) != ICT_TYPE_UNKNOWN) {
            *size = ICT_FRAME_BITS;
            return (int)i;
        }
    }

    return -4;
}

int demodLFICT(bool verbose) {
    (void) verbose;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = getFromGraphBuffer(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - ICT not enough samples");
        free(bits);
        return PM3_ESOFT;
    }

    int wave_idx = 0;
    int idx = detectLFICT(bits, &size, &wave_idx);
    if (idx < 0) {
        if (idx == -1) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - ICT: not enough samples");
        } else if (idx == -2) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - ICT: just noise detected");
        } else if (idx == -3) {
            PrintAndLogEx(DEBUG, "DEBUG: Error - ICT: problem during FSK demod");
        } else {
            PrintAndLogEx(DEBUG, "DEBUG: Error - ICT: preamble or format not found");
        }
        free(bits);
        return PM3_ESOFT;
    }

    uint32_t blocks[ICT_BLOCK_COUNT];
    for (uint8_t b = 0; b < ICT_BLOCK_COUNT; b++) {
        blocks[b] = bytebits_to_byte(bits + idx + (b * 32), 32);
    }

    uint8_t dec_bits[128] = {0};
    size_t dec_len = 0;
    ict_tag_type_t type = ict_classify_blocks(blocks, dec_bits, &dec_len);
    if (type == ICT_TYPE_UNKNOWN) {
        free(bits);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, ICT_FRAME_BITS, idx);
    setClockGrid(50, wave_idx + (idx * 50));

    ict_print_result(type, dec_bits, dec_len, blocks);

    free(bits);
    return PM3_SUCCESS;
}

static int CmdICTDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ict demod",
                  "Try to find LF ICT preamble, if found decode tag data",
                  "lf ict demod\n"
                  "lf ict demod --raw f656595a5a6566696a9596999aa5a6a9aa5556595a65666900000000"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw bytes. 28 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int raw_len = 0;
    uint8_t raw[28] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (raw_len == 0) {
        return demodLFICT(true);
    }

    if (raw_len != 28) {
        PrintAndLogEx(FAILED, "Must specify 28 bytes, got " _YELLOW_("%d"), raw_len);
        return PM3_EINVARG;
    }

    uint32_t blocks[ICT_BLOCK_COUNT];
    for (uint8_t b = 0; b < ICT_BLOCK_COUNT; b++) {
        blocks[b] = bytes_to_num(raw + (b * 4), sizeof(uint32_t));
    }

    if ((blocks[0] >> 28) != 0xF || blocks[6] != 0) {
        PrintAndLogEx(FAILED, "Invalid LF ICT preamble/postamble");
        return PM3_ESOFT;
    }

    uint8_t dec_bits[128] = {0};
    size_t dec_len = 0;
    ict_tag_type_t type = ict_classify_blocks(blocks, dec_bits, &dec_len);
    ict_print_result(type, dec_bits, dec_len, blocks);
    return PM3_SUCCESS;
}

static int CmdICTReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ict reader",
                  "Read an LF ICT tag",
                  "lf ict reader -@   -> continuous reader mode"
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
        lf_read(false, 24000);
        demodLFICT(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdICTClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ict clone",
                  "Clone an LF ICT tag to a T55x7, Q5/T5555 or EM4305/4469 tag",
                  "lf ict clone --raw f656595a5a6566696a9596999aa5a6a9aa5556595a65666900000000\n"
                  "lf ict clone --raw f656595a5a6566696a9596999aa5a6a9aa5556595a65666900000000 --q5\n"
                  "lf ict clone --raw f656595a5a6566696a9596999aa5a6a9aa5556595a65666900000000 --em"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "raw hex data. 28 bytes"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[28] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if (raw_len != 28) {
        PrintAndLogEx(ERR, "Data must be 28 bytes (56 HEX characters), got %d", raw_len);
        return PM3_EINVARG;
    }

    uint32_t blocks[8] = {0};
    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    blocks[0] = T55X7_ICT_CONFIG_BLOCK;
    char cardtype[16] = {"T55x7"};
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 7 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        blocks[0] = EM4305_ICT_CONFIG_BLOCK;
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] ^= 0xFFFFFFFF;
        }
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone LF ICT to " _YELLOW_("%s"), cardtype);
    print_blocks(blocks, ARRAYLEN(blocks));

    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf ict reader`") " to verify");
    return res;
}

static int CmdICTSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf ict sim",
                  "Enables simulation of LF ICT card from raw hex data.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf ict sim --raw f656595a5a6566696a9596999aa5a6a9aa5556595a65666900000000"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("r", "raw", "<hex>", "raw hex data. 28 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[28] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (raw_len != 28) {
        PrintAndLogEx(ERR, "Data must be 28 bytes (56 HEX characters), got %d", raw_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Simulating LF ICT - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    uint8_t bs[sizeof(raw) * 8];
    bytes_to_bytebits(raw, sizeof(raw), bs);

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
    {"help",   CmdHelp,      AlwaysAvailable, "This help"},
    {"demod",  CmdICTDemod,  AlwaysAvailable, "demodulate an LF ICT FSK tag from the GraphBuffer"},
    {"reader", CmdICTReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdICTClone,  IfPm3Lf,         "clone LF ICT tag to T55x7, Q5/T5555 or EM4305/4469"},
    {"sim",    CmdICTSim,    IfPm3Lf,         "simulate LF ICT tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd;
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFICT(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
