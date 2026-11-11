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
// Low frequency Securakey tag commands
// ASK/Manchester, RF/40, 96 bits long (standard) or 64 bits long (short)
//-----------------------------------------------------------------------------
#include "cmdlfsecurakey.h"
#include <string.h>       // memcpy
#include <ctype.h>        // tolower
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"      // preamble test
#include "parity.h"       // for wiegand parity test
#include "protocols.h"    // t55xx defines
#include "cmdlft55xx.h"   // clone..
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

static void securakey_short_encode(uint32_t cn, uint8_t *raw) {
    uint32_t raw1 = 0x7FC00000;
    uint32_t raw2 = (cn & 0xFF) | ((cn << 1) & 0x0001FE00) | ((cn << 2) & 0x03FC0000);
    num_to_bytes(raw1, 4, raw);
    num_to_bytes(raw2, 4, raw + 4);
}

static int securakey_decode_64(const uint8_t *bits) {
    uint32_t raw1 = bytebits_to_byte((uint8_t *)bits, 32);
    uint32_t raw2 = bytebits_to_byte((uint8_t *)bits + 32, 32);
    if (raw1 != 0x7FC00000 || (raw2 & 0x04020100) != 0) {
        return PM3_ESOFT;
    }
    uint32_t cn = (raw2 & 0xFF) | ((raw2 >> 1) & 0xFF00) | ((raw2 >> 2) & 0xFF0000);
    PrintAndLogEx(SUCCESS, "Securakey Short - CN: " _GREEN_("%u") ", Raw: %08X%08X", cn, raw1, raw2);
    return PM3_SUCCESS;
}

static int securakey_decode_96(const uint8_t *bits, bool verbose) {
    //got a good demod
    uint32_t raw1 = bytebits_to_byte((uint8_t *)bits, 32);
    uint32_t raw2 = bytebits_to_byte((uint8_t *)bits + 32, 32);
    uint32_t raw3 = bytebits_to_byte((uint8_t *)bits + 64, 32);

    // 26 bit format
    // preamble     ??bitlen   reserved        EPx   xxxxxxxy   yyyyyyyy   yyyyyyyOP  CS?        CS2?
    // 0111111111 0 01011010 0 00000000 0 00000010 0 00110110 0 00111110 0 01100010 0 00001111 0 01100000 0 00000000 0 0000

    // 32 bit format
    // preamble     ??bitlen   reserved  EPxxxxxxx   xxxxxxxy   yyyyyyyy   yyyyyyyOP  CS?        CS2?
    // 0111111111 0 01100000 0 00000000 0 10000100 0 11001010 0 01011011 0 01010110 0 00010110 0 11100000 0 00000000 0 0000

    // x = FC?
    // y = card #
    // standard wiegand parities.
    // unknown checksum 11 bits? at the end
    uint8_t bits_no_spacer[85];
    memcpy(bits_no_spacer, bits + 11, 85);

    // remove marker bits (0's every 9th digit after preamble) (pType = 3 (always 0s))
    size_t size = removeParity(bits_no_spacer, 0, 9, 3, 85);
    if (size != 85 - 9) {
        PrintAndLogEx(DEBUG, "DEBUG: Error removeParity: %zu", size);
        return PM3_ESOFT;
    }

    uint8_t bitLen = (uint8_t)bytebits_to_byte(bits_no_spacer + 2, 6);
    uint32_t fc = 0, lWiegand = 0, rWiegand = 0;
    if (bitLen > 40) { //securakey's max bitlen is 40 bits...
        PrintAndLogEx(DEBUG, "DEBUG: Error bitLen too long: %u", bitLen);
        return PM3_ESOFT;
    }
    if (bitLen < 18) {
        PrintAndLogEx(DEBUG, "DEBUG: Error bitLen too short: %u", bitLen);
        return PM3_ESOFT;
    }
    // get left 1/2 wiegand & right 1/2 wiegand (for parity test and wiegand print)
    lWiegand = bytebits_to_byte(bits_no_spacer + 48 - bitLen, bitLen / 2);
    rWiegand = bytebits_to_byte(bits_no_spacer + 48 - bitLen + bitLen / 2, bitLen / 2);
    // get FC
    fc = bytebits_to_byte(bits_no_spacer + 49 - bitLen, bitLen - 2 - 16);

    // test bitLen
    if (bitLen != 26 && bitLen != 32)
        PrintAndLogEx(NORMAL, "***unknown securakey bitLen - share with forum***");

    uint32_t cardid = bytebits_to_byte(bits_no_spacer + 8 + 23, 16);
    // test parities - evenparity32 looks to add an even parity returns 0 if already even...
    bool parity = !evenparity32(lWiegand) && !oddparity32(rWiegand);

    PrintAndLogEx(SUCCESS, "Securakey - len: " _GREEN_("%u") " FC: " _GREEN_("0x%X")" Card: " _GREEN_("%u") ", Raw: %08X%08X%08X", bitLen, fc, cardid, raw1, raw2, raw3);
    if (bitLen <= 32)
        PrintAndLogEx(SUCCESS, "Wiegand: " _GREEN_("%08X") " parity ( %s )", (lWiegand << (bitLen / 2)) | rWiegand, parity ? _GREEN_("ok") : _RED_("fail"));

    if (verbose) {
        PrintAndLogEx(INFO, "\nHow the FC translates to printed FC is unknown");
        PrintAndLogEx(INFO, "How the checksum is calculated is unknown");
        PrintAndLogEx(INFO, "Help the community identify this format further\nby sharing your tag on the pm3 forum or discord");
    }
    return PM3_SUCCESS;
}

//see ASKDemod for what args are accepted
int demodSecurakey(bool verbose) {
    //ASK / Manchester
    bool st = false;
    if (ASKDemod_ext(40, 0, 0, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: ASK/Manchester Demod failed");
        return PM3_ESOFT;
    }
    if (st)
        return PM3_ESOFT;

    size_t size = g_DemodBufferLen;
    int ans = detectSecurakey(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: ans: %d", ans);
        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, size, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    if (size == 64) {
        return securakey_decode_64(g_DemodBuffer);
    }
    return securakey_decode_96(g_DemodBuffer, verbose);
}

static int CmdSecurakeyDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf securakey demod",
                  "Try to find Securakey preamble, if found decode / descramble data",
                  "lf securakey demod\n"
                  "lf securakey demod --raw 7FCB400001ADEA5344300000\n"
                  "lf securakey demod --raw 7fc000000065cc92"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 8 bytes (short) or 12 bytes (standard)"),
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
        return demodSecurakey(true);
    }

    if (raw_len == 8) {
        uint8_t bits[64];
        bytes_to_bytebits(raw, 8, bits);
        if (securakey_decode_64(bits) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Invalid Securakey Short raw data");
            return PM3_ESOFT;
        }
        return PM3_SUCCESS;
    }

    if (raw_len == 12) {
        uint8_t bits[96];
        bytes_to_bytebits(raw, 12, bits);
        size_t size = sizeof(bits);
        if (detectSecurakey(bits, &size) != 0 || size != 96) {
            PrintAndLogEx(FAILED, "Invalid Securakey raw data");
            return PM3_ESOFT;
        }
        return securakey_decode_96(bits, true);
    }

    PrintAndLogEx(FAILED, "Raw data must be 8 bytes (short) or 12 bytes (standard), got " _YELLOW_("%d"), raw_len);
    return PM3_EINVARG;
}

static int CmdSecurakeyReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf securakey reader",
                  "read a Securakey tag",
                  "lf securakey reader -@   -> continuous reader mode"
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
        lf_read(false, 8000);
        demodSecurakey(!cm);
    } while (cm && (kbd_enter_pressed() == false));

    return PM3_SUCCESS;
}

static int CmdSecurakeyClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf securakey clone",
                  "clone a Securakey tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf securakey clone --raw 7FCB400001ADEA5344300000      -> encode for T55x7 tag\n"
                  "lf securakey clone --raw 7FCB400001ADEA5344300000 --q5 -> encode for Q5/T5555 tag\n"
                  "lf securakey clone --raw 7FCB400001ADEA5344300000 --em -> encode for EM4305/4469\n"
                  "lf securakey clone --cn 1697426                        -> encode 24-bit short for T55x7 tag"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 8 bytes (short) or 12 bytes (standard)"),
        arg_int0(NULL, "cn", "<dec>", "24-bit card number (Securakey Short)"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    int cn_arg = arg_get_int_def(ctx, 2, -1);
    bool q5 = arg_get_lit(ctx, 3);
    bool em = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len > 0);
    if (use_raw && cn_arg != -1) {
        PrintAndLogEx(FAILED, "Can't specify both --raw and --cn at the same time");
        return PM3_EINVARG;
    }
    if (!use_raw && cn_arg == -1) {
        PrintAndLogEx(FAILED, "Must specify either --raw or --cn");
        return PM3_EINVARG;
    }

    if (!use_raw) {
        if (cn_arg < 0 || cn_arg > 0xFFFFFF) {
            PrintAndLogEx(FAILED, "CN must be between 0 and 16777215");
            return PM3_EINVARG;
        }
        securakey_short_encode((uint32_t)cn_arg, raw);
        raw_len = 8;
    } else if (raw_len != 8 && raw_len != 12) {
        PrintAndLogEx(ERR, "Data must be 8 or 12 bytes (16 or 24 HEX characters), got %d", raw_len);
        return PM3_EINVARG;
    }

    size_t data_blocks = (raw_len == 8) ? 2 : 3;
    uint32_t blocks[4] = {0};
    for (size_t i = 1; i <= data_blocks; i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    //Securakey - compat mode, ASK/Man, data rate 40, 2 or 3 data blocks
    blocks[0] = (raw_len == 8) ? T55X7_SECURAKEY_SHORT_CONFIG_BLOCK
                : (T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_40 | 3 << T55x7_MAXBLOCK_SHIFT);
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(40) | T5555_ST_TERMINATOR | (uint32_t)(data_blocks << T5555_MAXBLOCK_SHIFT);
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = (raw_len == 8) ? EM4305_SECURAKEY_SHORT_CONFIG_BLOCK : EM4305_SECURAKEY_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone Securakey%s to " _YELLOW_("%s") " with %s",
                  (raw_len == 8) ? " Short" : "",
                  cardtype,
                  use_raw ? "raw hex" : "card number"
                 );
    print_blocks(blocks, data_blocks + 1);

    if (em) {
        res = em4x05_clone_tag(blocks, data_blocks + 1, 0, false);
    } else {
        res = clone_t55xx_tag(blocks, data_blocks + 1);
    }
    PrintAndLogEx(SUCCESS, "Done!");
    PrintAndLogEx(HINT, "Hint: Try " _YELLOW_("`lf securakey reader`") " to verify");
    return res;
}

static int CmdSecurakeySim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf securakey sim",
                  "Enables simulation of Securakey card with raw hex or 24-bit card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf securakey sim --raw 7FCB400001ADEA5344300000\n"
                  "lf securakey sim --cn 1697426"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 8 bytes (short) or 12 bytes (standard)"),
        arg_int0(NULL, "cn", "<dec>", "24-bit card number (Securakey Short)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof(raw), &raw_len);
    int cn_arg = arg_get_int_def(ctx, 2, -1);
    CLIParserFree(ctx);

    if (res) {
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len > 0);
    if (use_raw && cn_arg != -1) {
        PrintAndLogEx(FAILED, "Can't specify both --raw and --cn at the same time");
        return PM3_EINVARG;
    }
    if (!use_raw && cn_arg == -1) {
        PrintAndLogEx(FAILED, "Must specify either --raw or --cn");
        return PM3_EINVARG;
    }

    if (!use_raw) {
        if (cn_arg < 0 || cn_arg > 0xFFFFFF) {
            PrintAndLogEx(FAILED, "CN must be between 0 and 16777215");
            return PM3_EINVARG;
        }
        securakey_short_encode((uint32_t)cn_arg, raw);
        raw_len = 8;
    } else if (raw_len != 8 && raw_len != 12) {
        PrintAndLogEx(ERR, "Data must be 8 or 12 bytes (16 or 24 HEX characters), got %d", raw_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Simulating SecuraKey%s - raw " _YELLOW_("%s"),
                  (raw_len == 8) ? " Short" : "",
                  sprint_hex_inrow(raw, (size_t)raw_len)
                 );

    size_t bit_len = (size_t)raw_len * 8;
    uint8_t bs[96] = {0};
    bytes_to_bytebits(raw, (size_t)raw_len, bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + bit_len);
    if (payload == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 40;
    memcpy(payload->data, bs, bit_len);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload, sizeof(lf_asksim_t) + bit_len);
    free(payload);

    return lfsim_wait_check(CMD_LF_ASK_SIMULATE);
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"demod",   CmdSecurakeyDemod,  AlwaysAvailable, "demodulate an Securakey tag from the GraphBuffer"},
    {"reader",  CmdSecurakeyReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdSecurakeyClone,  IfPm3Lf,         "clone Securakey tag to T55x7, Q5/T5555 or EM4305/4469"},
    {"sim",     CmdSecurakeySim,    IfPm3Lf,         "simulate Securakey tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFSecurakey(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by marshmellow
// find Securakey preamble in already demoded data
int detectSecurakey(uint8_t *dest, size_t *size) {
    size_t orig_size = *size;
    if (orig_size < 64) return -1; //make sure buffer has data

    int long_err = -2;
    size_t long_err_size = orig_size;

    if (orig_size >= 96) {
        size_t startIdx = 0;
        size_t found_size = orig_size;
        uint8_t preamble[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1};
        if (preambleSearch(dest, preamble, sizeof(preamble), &found_size, &startIdx)) {
            if (found_size == 96) {
                *size = 96;
                return (int)startIdx;
            }
            long_err = -3;
            long_err_size = found_size;
        }
    }

    // Fallback: 64-bit Securakey Short (`0x7FC00000` preamble + marker-free CN bytes)
    static const uint8_t short_preamble[] = {
        0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
    };

    for (size_t i = 0; i + 64 + sizeof(short_preamble) <= orig_size; i++) {
        if (memcmp(dest + i, short_preamble, sizeof(short_preamble)) == 0 &&
                memcmp(dest + i + 64, short_preamble, sizeof(short_preamble)) == 0) {
            uint32_t raw2 = bytebits_to_byte(dest + i + 32, 32);
            if ((raw2 & 0x04020100) == 0) {
                *size = 64;
                return (int)i;
            }
        }
    }

    if (orig_size < 96) {
        for (size_t i = 0; i + 64 <= orig_size; i++) {
            if (memcmp(dest + i, short_preamble, sizeof(short_preamble)) == 0) {
                uint32_t raw2 = bytebits_to_byte(dest + i + 32, 32);
                if ((raw2 & 0x04020100) == 0) {
                    *size = 64;
                    return (int)i;
                }
            }
        }
        return -1;
    }

    if (long_err == -3) {
        *size = long_err_size;
        return -3;
    }
    return -2; //preamble not found
}

