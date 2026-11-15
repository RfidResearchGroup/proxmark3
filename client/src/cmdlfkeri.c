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
// Low frequency KERI tag commands
// PSK1, RF/128, RF/2, 64 bits long (MS/Internal)
// FSK2a, RF/50, 128 bits long (NXT)
//-----------------------------------------------------------------------------
#include "cmdlfkeri.h"
#include <string.h>
#include <inttypes.h>
#include <ctype.h>
#include <stdlib.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"    // for T55xx config register definitions
#include "lfdemod.h"      // preamble test
#include "crc.h"
#include "cmdlft55xx.h"   // verifywrite
#include "cmdlfem4x05.h"  //

#define KERI_NXT_FRAME_BITS  128
#define KERI_NXT_BLOCK_COUNT 4

static int CmdHelp(const char *Cmd);
typedef enum  {Scramble = 0, Descramble = 1} KeriMSScramble_t;

static int CmdKeriMSScramble(KeriMSScramble_t Action, uint32_t *FC, uint32_t *ID, uint32_t *CardID) {
    // 255 = Not used/Unknown other values are the bit offset in the ID/FC values
    const uint8_t CardToID [] = { 255, 255, 255, 255, 13, 12, 20,  5, 16,  6, 21, 17,  8, 255,  0,  7,
                                  10, 15, 255, 11,  4,  1, 255, 18, 255, 19,  2, 14,  3,  9, 255, 255
                                };

    const uint8_t CardToFC [] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  0, 255, 255,
                                  255, 255,  2, 255, 255, 255,  3, 255,  4, 255, 255, 255, 255, 255,  1, 255
                                };

    uint8_t card_idx; // 0 - 31

    if (Action == Descramble) {
        *FC = 0;
        *ID = 0;
        for (card_idx = 0; card_idx < 32; card_idx++) {
            // Get Bit State
            bool BitState = (*CardID >> card_idx) & 1;
            // Card ID
            if (CardToID[card_idx] < 32) {
                *ID = *ID | (BitState << CardToID[card_idx]);
            }
            // Card FC
            if (CardToFC[card_idx] < 32) {
                *FC = *FC | (BitState << CardToFC[card_idx]);
            }
        }
    }

    if (Action == Scramble) {
        *CardID = 0; // set to 0

        for (card_idx = 0; card_idx < 32; card_idx++) {
            // Card ID
            if (CardToID[card_idx] < 32) {
                if ((*ID & (1U << CardToID[card_idx])) > 0)
                    *CardID |= (1U << card_idx);
            }
            // Card FC
            if (CardToFC[card_idx] < 32) {
                if ((*FC & (1U << CardToFC[card_idx])) > 0)
                    *CardID |= (1U << card_idx);
            }
        }

        // Fixed bits and parity/check bits
        /*
            Add Parity and Fixed bits
            Bit  3 - Note Used/Fixed 1 - TBC
            Bit 31 - 1 Fixed Not in check/parity
            Bit  0,1 - 2 Bit Parity
        */
        *CardID |= (1 <<  3);

        // Check/Parity Bits
        int parity = 1;
        for (card_idx = 4; card_idx <= 31; card_idx += 2) {
            parity ^= ((*CardID >> card_idx) & 11);
        }
        *CardID = *CardID | parity;

        // Bit 31 was fixed but not in check/parity bits
        *CardID |= 1UL << 31;

        PrintAndLogEx(SUCCESS, "Scrambled MS - FC: " _GREEN_("%d") " Card: " _GREEN_("%d") ", Raw: E0000000%08X", *FC, *ID, *CardID);
    }
    return PM3_SUCCESS;
}

static const uint8_t keri_nxt_preamble[] = {
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
    0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 1
};

static bool keri_nxt_is_pyramid_frame(const uint8_t *bits) {
    uint8_t work[KERI_NXT_FRAME_BITS];
    memcpy(work, bits, sizeof(work));

    uint8_t checksum = bytebits_to_byte(work + 120, 8);
    uint8_t cs_buf[13];
    for (uint8_t i = 0; i < ARRAYLEN(cs_buf); i++) {
        cs_buf[i] = bytebits_to_byte(work + 16 + (i * 8), 8);
    }

    if (checksum != CRC8Maxim(cs_buf, ARRAYLEN(cs_buf))) {
        return false;
    }

    return removeParity(work, 8, 8, 1, 112) == 98;
}

static bool keri_nxt_validate_bits(uint8_t *bits) {
    if (memcmp(bits, keri_nxt_preamble, sizeof(keri_nxt_preamble)) != 0) {
        return false;
    }

    uint32_t w1 = bytebits_to_byte(bits + 32, 32);
    uint32_t w2 = bytebits_to_byte(bits + 64, 32);
    uint32_t w3 = bytebits_to_byte(bits + 96, 32);
    if (w1 == 0 && w2 == 0 && w3 == 0) {
        return false;
    }

    return !keri_nxt_is_pyramid_frame(bits);
}

static void keri_nxt_print_result(const uint8_t *raw) {
    uint32_t w0 = bytes_to_num((uint8_t *)raw, 4);
    uint32_t w1 = bytes_to_num((uint8_t *)raw + 4, 4);
    uint32_t w2 = bytes_to_num((uint8_t *)raw + 8, 4);
    uint32_t w3 = bytes_to_num((uint8_t *)raw + 12, 4);
    PrintAndLogEx(SUCCESS, "KERI NXT - Raw: %08X%08X%08X%08X", w0, w1, w2, w3);
}

static void keri_ms_print_result(const uint8_t *bits) {
    uint32_t fc = 0;
    uint32_t cardid = 0;
    uint32_t raw1 = bytebits_to_byte((uint8_t *)bits, 32);
    uint32_t raw2 = bytebits_to_byte((uint8_t *)bits + 32, 32);
    uint32_t id = raw2 & 0x7FFFFFFF;

    PrintAndLogEx(SUCCESS, "KERI - Internal ID: " _GREEN_("%u") ", Raw: %08X%08X", id, raw1, raw2);

    // Just need to the low 32 bits without the 111 trailer
    CmdKeriMSScramble(Descramble, &fc, &cardid, &raw2);

    PrintAndLogEx(SUCCESS, "Descrambled MS - FC: " _GREEN_("%d") " Card: " _GREEN_("%d"), fc, cardid);
}

static int demodKeriNXT(bool verbose) {
    (void) verbose;

    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = getFromGraphBuffer(bits);
    if (size < KERI_NXT_FRAME_BITS * 50) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI NXT: not enough samples");
        free(bits);
        return PM3_ESOFT;
    }

    if (getSignalProperties()->isnoise) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI NXT: just noise detected");
        free(bits);
        return PM3_ESOFT;
    }

    int wave_idx = 0;
    size = fskdemod(bits, size, 50, 1, 10, 8, &wave_idx);
    if (size < KERI_NXT_FRAME_BITS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI NXT: FSK demod failed");
        free(bits);
        return PM3_ESOFT;
    }

    int found_idx = -1;
    for (size_t i = 0; i + KERI_NXT_FRAME_BITS + sizeof(keri_nxt_preamble) <= size; i++) {
        if (memcmp(bits + i, keri_nxt_preamble, sizeof(keri_nxt_preamble)) == 0 &&
                memcmp(bits + i + KERI_NXT_FRAME_BITS, keri_nxt_preamble, sizeof(keri_nxt_preamble)) == 0 &&
                keri_nxt_validate_bits(bits + i)) {
            found_idx = (int)i;
            break;
        }
    }

    if (found_idx < 0 && size < KERI_NXT_FRAME_BITS + sizeof(keri_nxt_preamble)) {
        for (size_t i = 0; i + KERI_NXT_FRAME_BITS <= size; i++) {
            if (keri_nxt_validate_bits(bits + i)) {
                found_idx = (int)i;
                break;
            }
        }
    }

    if (found_idx < 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI NXT: preamble not found");
        free(bits);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, KERI_NXT_FRAME_BITS, found_idx);
    setClockGrid(50, wave_idx + (found_idx * 50));

    uint8_t raw[16] = {0};
    bits_to_array(bits + found_idx, KERI_NXT_FRAME_BITS, raw);
    keri_nxt_print_result(raw);

    free(bits);
    return PM3_SUCCESS;
}

int demodKeri(bool verbose) {
    if (PSKDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: PSK1 Demod failed");
        return demodKeriNXT(verbose);
    }

    bool invert = false;
    size_t size = g_DemodBufferLen;
    int idx = detectKeri(g_DemodBuffer, &size, &invert);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: too few bits found");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: preamble not found");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: Size not correct: 64 != %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: ans: %d", idx);

        return demodKeriNXT(verbose);
    }
    setDemodBuff(g_DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    /*
        000000000000000000000000000001XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX111
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^1###############################^^^
        Preamble block 29 bits of ZEROS
        32 bit Internal ID  (First bit always 1)
        3 bit of 1s in the end

        How this is decoded to Facility ID, Card number is unknown
        Facility ID =  0-31  (indicates 5 bits)
        Card number = up to 10 digits

        Might be a hash of FC & CN to generate Internal ID
    */

    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably KERI");
        for (size_t i = 0; i < size; i++)
            g_DemodBuffer[i] ^= 1;

        CmdPrintDemodBuff("-x");
    }

    keri_ms_print_result(g_DemodBuffer);
    return PM3_SUCCESS;
}

static int CmdKeriDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf keri demod",
                  "Try to find KERI preamble, if found decode / descramble data",
                  "lf keri demod\n"
                  "lf keri demod --raw E00000008001B669\n"
                  "lf keri demod --raw 0001010101010101123456789ABCDEF0"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 8 bytes (MS/Internal) or 16 bytes (NXT)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int raw_len = 0;
    uint8_t raw[16] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (raw_len == 0) {
        return demodKeri(true);
    }

    if (raw_len == 8) {
        uint8_t bits[64];
        bytes_to_bytebits(raw, 8, bits);

        bool invert = false;
        size_t size = sizeof(bits);
        int idx = detectKeri(bits, &size, &invert);
        if (idx != 0 || size < 64) {
            PrintAndLogEx(FAILED, "Invalid KERI raw data");
            return PM3_ESOFT;
        }
        if (invert) {
            for (size_t i = 0; i < sizeof(bits); i++) {
                bits[i] ^= 1;
            }
        }
        keri_ms_print_result(bits);
        return PM3_SUCCESS;
    }

    if (raw_len == 16) {
        uint8_t bits[KERI_NXT_FRAME_BITS];
        bytes_to_bytebits(raw, 16, bits);
        if (!keri_nxt_validate_bits(bits)) {
            PrintAndLogEx(FAILED, "Invalid KERI NXT raw data");
            return PM3_ESOFT;
        }
        keri_nxt_print_result(raw);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Raw data must be 8 bytes (MS/Internal) or 16 bytes (NXT), got " _YELLOW_("%d"), raw_len);
    return PM3_EINVARG;
}

static int CmdKeriReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf keri reader",
                  "read a keri tag",
                  "lf keri reader -@   -> continuous reader mode"
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
        lf_read(false, 16000);
        demodKeri(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdKeriClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf keri clone",
                  "clone a KERI tag to a T55x7, Q5/T5555 or EM4305/4469 tag",
                  "lf keri clone -t i --cn 12345         -> Internal ID\n"
                  "lf keri clone -t m --fc 6 --cn 12345  -> MS ID\n"
                  "lf keri clone -t n --raw 0001010101010101123456789ABCDEF0 -> NXT"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("t",  "type", "<m|i|n>", "Type m - MS, i - Internal ID, n - NXT"),
        arg_int0(NULL, "fc",   "<dec>", "Facility Code"),
        arg_int0(NULL, "cn",   "<dec>", "KERI card ID"),
        arg_str0("r",  "raw",  "<hex>", "raw hex data. 8 bytes (MS/Internal) or 16 bytes (NXT)"),
        arg_lit0(NULL, "q5", "specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t keritype[2] = {0, 0};
    int typeLen = sizeof(keritype) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 1, keritype, &typeLen);

    int fc_arg = arg_get_int_def(ctx, 2, -1);
    int cn_arg = arg_get_int_def(ctx, 3, -1);

    int raw_len = 0;
    uint8_t raw[16] = {0};
    int raw_res = CLIParamHexToBuf(arg_get_str(ctx, 4), raw, sizeof(raw), &raw_len);
    bool q5 = arg_get_lit(ctx, 5);
    bool em = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (raw_res) {
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    char type_ch = (typeLen > 0) ? (char)tolower(keritype[0]) : ((raw_len == 16) ? 'n' : 'i');
    bool use_raw = (raw_len > 0);

    if (use_raw && (fc_arg != -1 || cn_arg != -1)) {
        PrintAndLogEx(FAILED, "Can't specify both raw and fc/cn at the same time");
        return PM3_EINVARG;
    }

    uint32_t blocks[5] = {0};
    size_t block_count = 0;
    char cardtype[16] = {"T55x7"};

    if (type_ch == 'n') {
        if (!use_raw || raw_len != 16) {
            PrintAndLogEx(FAILED, "Must specify 16 bytes --raw for Keri NXT");
            return PM3_EINVARG;
        }
        if (bytes_to_num(raw, 4) != 0x00010101) {
            PrintAndLogEx(FAILED, "Invalid Keri NXT preamble (expected 00010101)");
            return PM3_EINVARG;
        }

        blocks[0] = T55X7_KERI_NXT_CONFIG_BLOCK;
        for (uint8_t i = 0; i < KERI_NXT_BLOCK_COUNT; i++) {
            blocks[i + 1] = bytes_to_num(raw + (i * 4), 4);
        }

        if (q5) {
            blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 4 << T5555_MAXBLOCK_SHIFT;
            snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
        } else if (em) {
            PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
            blocks[0] = EM4305_KERI_NXT_CONFIG_BLOCK;
            for (uint8_t i = 1; i <= KERI_NXT_BLOCK_COUNT; i++) {
                blocks[i] ^= 0xFFFFFFFF;
            }
            snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
        }

        block_count = 5;
        PrintAndLogEx(INFO, "Preparing to clone KERI NXT to " _YELLOW_("%s") " from raw hex", cardtype);
    } else {
        blocks[0] = T55x7_TESTMODE_DISABLED | T55x7_X_MODE | T55x7_MODULATION_PSK1 | T55x7_PSKCF_RF_2 | 2 << T55x7_MAXBLOCK_SHIFT;
        // dynamic bitrate used
        blocks[0] |= 0xF << 18;

        if (q5) {
            blocks[0] = T5555_FIXED | T5555_MODULATION_PSK1 | T5555_SET_BITRATE(32) | T5555_PSK_RF_2 | 2 << T5555_MAXBLOCK_SHIFT;
            snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
        } else if (em) {
            blocks[0] = EM4305_KERI_CONFIG_BLOCK;
            snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
        }

        uint64_t data = 0;

        if (use_raw) {
            if (type_ch != 'i' && type_ch != 'm') {
                PrintAndLogEx(ERR, "Invalid type");
                return PM3_EINVARG;
            }
            if (raw_len != 8) {
                PrintAndLogEx(FAILED, "Must specify 8 bytes --raw for Keri MS/Internal, got " _YELLOW_("%d"), raw_len);
                return PM3_EINVARG;
            }
            blocks[1] = bytes_to_num(raw, 4);
            blocks[2] = bytes_to_num(raw + 4, 4);
            PrintAndLogEx(INFO, "Preparing to clone KERI to " _YELLOW_("%s") " from raw hex", cardtype);
        } else {
            if (cn_arg == -1) {
                PrintAndLogEx(FAILED, "Must specify --cn or --raw");
                return PM3_EINVARG;
            }
            if (fc_arg == -1) {
                fc_arg = 0;
            }
            if (fc_arg < 0 || cn_arg < 0) {
                PrintAndLogEx(FAILED, "FC and CN can't be negative");
                return PM3_EINVARG;
            }

            // the MS scramble carries 5 bits of fc and 22 of cn
            if (type_ch == 'm' && (fc_arg > 31 || cn_arg > 0x3FFFFF)) {
                PrintAndLogEx(FAILED, "MS FC has a max value of 31 and CN has a max value of 4194303");
                return PM3_EINVARG;
            }

            uint32_t fc = (uint32_t)fc_arg;
            uint32_t cid = (uint32_t)cn_arg;
            uint32_t internalid = 0;
            switch (type_ch) {
                case 'i' : // Internal ID
                    // MSB is ONE
                    internalid = cid | 0x80000000;
                    break;
                case 'm' : // MS
                    CmdKeriMSScramble(Scramble, &fc, &cid, &internalid);
                    break;
                default  :
                    PrintAndLogEx(ERR, "Invalid type");
                    return PM3_EINVARG;
            }

            // 3 LSB is ONE
            data = ((uint64_t)internalid << 3) + 7;
            blocks[1] = data >> 32;
            blocks[2] = data & 0xFFFFFFFF;
            PrintAndLogEx(INFO, "Preparing to clone KERI to " _YELLOW_("%s") " with Internal Id " _YELLOW_("%" PRIx32), cardtype, internalid);
        }

        block_count = 3;
    }

    print_blocks(blocks, block_count);

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, block_count, 0, false);
    } else {
        res = clone_t55xx_tag(blocks, block_count);
    }

    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf keri reader`") " to verify");
    return res;
}

static int CmdKeriSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf keri sim",
                  "Enables simulation of KERI card with internal ID, MS ID, or NXT raw hex.\n"
                  "You supply a KERI card id and it will converted to a KERI internal ID.",
                  "lf keri sim --id 112233\n"
                  "lf keri sim -t m --fc 6 --cn 12345\n"
                  "lf keri sim -t n --raw 0001010101010101123456789ABCDEF0"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_0(NULL, "id", "<dec>", "KERI card ID (Internal ID)"),
        arg_str0("t", "type", "<m|i|n>", "Type m - MS, i - Internal ID, n - NXT"),
        arg_int0(NULL, "fc", "<dec>", "Facility Code (for MS)"),
        arg_int0(NULL, "cn", "<dec>", "Card Number"),
        arg_str0("r", "raw", "<hex>", "raw hex data. 8 bytes (MS/Internal) or 16 bytes (NXT)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint64_t id_arg = arg_get_u64_def(ctx, 1, UINT64_MAX);
    uint8_t keritype[2] = {0, 0};
    int typeLen = sizeof(keritype) - 1;
    CLIGetStrWithReturn(ctx, 2, keritype, &typeLen);
    int fc_arg = arg_get_int_def(ctx, 3, -1);
    int cn_arg = arg_get_int_def(ctx, 4, -1);

    int raw_len = 0;
    uint8_t raw[16] = {0};
    int raw_res = CLIParamHexToBuf(arg_get_str(ctx, 5), raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    if (raw_res) {
        return PM3_EINVARG;
    }

    char type_ch = (typeLen > 0) ? (char)tolower(keritype[0]) : ((raw_len == 16) ? 'n' : 'i');
    bool use_raw = (raw_len > 0);

    if (use_raw && (id_arg != UINT64_MAX || fc_arg != -1 || cn_arg != -1)) {
        PrintAndLogEx(FAILED, "Can't specify both raw and id/fc/cn at the same time");
        return PM3_EINVARG;
    }

    if (type_ch == 'n') {
        if (!use_raw || raw_len != 16) {
            PrintAndLogEx(FAILED, "Must specify 16 bytes --raw for Keri NXT");
            return PM3_EINVARG;
        }
        if (bytes_to_num(raw, 4) != 0x00010101) {
            PrintAndLogEx(FAILED, "Invalid Keri NXT preamble (expected 00010101)");
            return PM3_EINVARG;
        }

        PrintAndLogEx(SUCCESS, "Simulating KERI NXT - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, 16));

        uint8_t bs[KERI_NXT_FRAME_BITS] = {0};
        bytes_to_bytebits(raw, 16, bs);

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

    uint64_t frame_val = 0;
    if (use_raw) {
        if (type_ch != 'i' && type_ch != 'm') {
            PrintAndLogEx(ERR, "Invalid type");
            return PM3_EINVARG;
        }
        if (raw_len != 8) {
            PrintAndLogEx(FAILED, "Must specify 8 bytes --raw for Keri MS/Internal, got " _YELLOW_("%d"), raw_len);
            return PM3_EINVARG;
        }
        frame_val = bytes_to_num(raw, 8);
        PrintAndLogEx(SUCCESS, "Simulating KERI - Raw: %016" PRIX64, frame_val);
    } else if (type_ch == 'm') {
        int card = (cn_arg != -1) ? cn_arg : ((id_arg != UINT64_MAX) ? (int)id_arg : -1);
        int fc = (fc_arg == -1) ? 0 : fc_arg;
        if (card < 0 || fc < 0) {
            PrintAndLogEx(FAILED, "Must specify non-negative --cn (or --id) for Keri MS");
            return PM3_EINVARG;
        }
        if (fc > 31 || card > 0x3FFFFF) {
            PrintAndLogEx(FAILED, "MS FC has a max value of 31 and CN has a max value of 4194303");
            return PM3_EINVARG;
        }
        uint32_t fc_u = (uint32_t)fc;
        uint32_t cid_u = (uint32_t)card;
        uint32_t internalid32 = 0;
        CmdKeriMSScramble(Scramble, &fc_u, &cid_u, &internalid32);
        PrintAndLogEx(SUCCESS, "Simulating KERI MS - Internal Id " _YELLOW_("%u") ", Raw: E0000000%08X", internalid32 & 0x7FFFFFFF, internalid32);
        frame_val = ((uint64_t)internalid32 << 3) + 7;
    } else if (type_ch == 'i') {
        uint64_t internalid = (id_arg != UINT64_MAX) ? id_arg : ((cn_arg >= 0) ? (uint64_t)cn_arg : UINT64_MAX);
        if (internalid == UINT64_MAX) {
            PrintAndLogEx(FAILED, "Must specify --id, --cn, or --raw");
            return PM3_EINVARG;
        }
        // the frame carries 31 bits of internal id
        if (internalid > 0x7FFFFFFF) {
            PrintAndLogEx(FAILED, "Internal Id has a max value of 2147483647");
            return PM3_EINVARG;
        }

        PrintAndLogEx(SUCCESS, "Simulating KERI - Internal Id " _YELLOW_("%" PRIu64) ", Raw: E0000000%08" PRIX64, internalid, internalid | 0x80000000);

        internalid |= 0x80000000;
        internalid <<= 3;
        internalid += 7;
        frame_val = internalid;
    } else {
        PrintAndLogEx(ERR, "Invalid type");
        return PM3_EINVARG;
    }

    uint8_t bs[64] = {0x00};
    // loop to bits
    uint8_t j = 0;
    for (int8_t i = 63; i >= 0; --i) {
        bs[j++] = ((frame_val >> i) & 1);
    }

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->carrier =  2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_PSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done!");
    if (resp.status != PM3_EOPABORTED) {
        return resp.status;
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,       AlwaysAvailable, "This help"},
    {"demod",  CmdKeriDemod,  AlwaysAvailable, "demodulate an KERI tag from the GraphBuffer"},
    {"reader", CmdKeriReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdKeriClone,  IfPm3Lf,         "clone KERI tag to T55x7, Q5/T5555 or EM4305/4469"},
    {"sim",    CmdKeriSim,    IfPm3Lf,         "simulate KERI tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFKeri(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find KERI preamble in already demoded data
int detectKeri(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[] = {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    // sanity check.
    if (*size < sizeof(preamble)) return -1;

    size_t startIdx = 0;
    size_t found_size = *size;

    if (!preambleSearch(dest, preamble, sizeof(preamble), &found_size, &startIdx)) {

        found_size = *size;
        // if didn't find preamble try again inverting
        uint8_t preamble_i[] = {0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
        if (!preambleSearch(dest, preamble_i, sizeof(preamble_i), &found_size, &startIdx))
            return -2;

        *invert ^= 1;
    }

    if (found_size < 64) return -3; //wrong demoded size

    *size = found_size;

    return (int)startIdx;
}

