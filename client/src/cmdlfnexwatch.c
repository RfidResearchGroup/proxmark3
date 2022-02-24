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
// Low frequency Honeywell NexWatch tag commands
// PSK1 RF/16, RF/2, 128 bits long (known)
//-----------------------------------------------------------------------------

#include "cmdlfnexwatch.h"
#include <inttypes.h>      // PRIu
#include <string.h>
#include <ctype.h>         // tolower
#include <stdlib.h>        // free, alloc
#include "commonutil.h"    // ARRAYLEN
#include "cmdparser.h"     // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"       // preamblesearch
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"     // t55xx defines
#include "cmdlft55xx.h"    // clone..
#include "cmdlfem4x05.h"   //
#include "cliparser.h"
#include "util.h"


typedef enum {
    SCRAMBLE,
    DESCRAMBLE
} NexWatchScramble_t;

static int CmdHelp(const char *Cmd);

// scramble parity (1234) -> (4231)
static uint8_t nexwatch_parity_swap(uint8_t parity) {
    uint8_t a = (((parity >> 3) & 1));
    a |= (((parity >> 1) & 1) << 1);
    a |= (((parity >> 2) & 1) << 2);
    a |= ((parity & 1) << 3);
    return a;
}
// parity check
// from 32b hex id, 4b mode,
static uint8_t nexwatch_parity(const uint8_t hexid[5]) {
    uint8_t p = 0;
    for (uint8_t i = 0; i < 5; i++) {
        p ^= NIBBLE_HIGH(hexid[i]);
        p ^= NIBBLE_LOW(hexid[i]);
    }
    return nexwatch_parity_swap(p);
}

/// NETWATCH checksum
/// @param magic =  0xBE  Quadrakey,  0x88 Nexkey, 0x86 Honeywell
/// @param id = descrambled id (printed card number)
/// @param parity =  the parity based upon the scrambled raw id.
static uint8_t nexwatch_checksum(uint8_t magic, uint32_t id, uint8_t parity) {
    uint8_t a = ((id >> 24) & 0xFF);
    a -= ((id >> 16) & 0xFF);
    a -= ((id >> 8) & 0xFF);
    a -= (id & 0xFF);
    a -= magic;
    a -= (reflect8(parity) >> 4);
    return reflect8(a);
}

// Scrambled id ( 88 bit cardnumber format)
// ref::  http://www.proxmark.org/forum/viewtopic.php?pid=14662#p14662
static int nexwatch_scamble(NexWatchScramble_t action, uint32_t *id, uint32_t *scambled) {

    // 255 = Not used/Unknown other values are the bit offset in the ID/FC values
    const uint8_t hex_2_id [] = {
        31, 27, 23, 19, 15, 11, 7, 3,
        30, 26, 22, 18, 14, 10, 6, 2,
        29, 25, 21, 17, 13, 9, 5, 1,
        28, 24, 20, 16, 12, 8, 4, 0
    };

    switch (action) {
        case DESCRAMBLE: {
            *id = 0;
            for (uint8_t idx = 0; idx < 32; idx++) {

                if (hex_2_id[idx] == 255)
                    continue;

                bool bit_state = (*scambled >> hex_2_id[idx]) & 1;
                *id |= (bit_state << (31 - idx));
            }
            break;
        }
        case SCRAMBLE: {
            *scambled = 0;
            for (uint8_t idx = 0; idx < 32; idx++) {

                if (hex_2_id[idx] == 255)
                    continue;

                bool bit_state = (*id >> idx) & 1;
                *scambled |= (bit_state << (31 - hex_2_id[idx]));
            }
            break;
        }
        default:
            break;
    }
    return PM3_SUCCESS;
}

static int nexwatch_magic_bruteforce(uint32_t cn, uint8_t calc_parity, uint8_t chk) {
    for (uint8_t magic = 0; magic < 255; magic++) {
        uint8_t temp_checksum;
        temp_checksum = nexwatch_checksum(magic, cn, calc_parity);
        if (temp_checksum == chk) {
            PrintAndLogEx(SUCCESS, "    Magic number : " _GREEN_("0x%X"),  magic);
            return PM3_SUCCESS;
        }
    }
    PrintAndLogEx(DEBUG, "DEBUG: Error - Magic number not found");
    return PM3_ESOFT;
}


int demodNexWatch(bool verbose) {
    (void) verbose; // unused so far
    if (PSKDemod(0, 0, 100, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch can't demod signal");
        return PM3_ESOFT;
    }
    bool invert = false;
    size_t size = g_DemodBufferLen;
    int idx = detectNexWatch(g_DemodBuffer, &size, &invert);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch not enough samples");
        // else if (idx == -2)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch only noise found");
        // else if (idx == -3)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch problem during PSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch preamble not found");
        // else if (idx == -5)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch error %d", idx);

        return PM3_ESOFT;
    }

    // skip the 4 first bits from the nexwatch preamble identification (we use 4 extra zeros..)
    idx += 4;

    setDemodBuff(g_DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    if (invert) {
        PrintAndLogEx(INFO, "Inverted the demodulated data");
        for (size_t i = 0; i < size; i++)
            g_DemodBuffer[i] ^= 1;
    }

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 32 + 32, 32);

    // get rawid
    uint32_t rawid = 0;
    for (uint8_t k = 0; k < 4; k++) {
        for (uint8_t m = 0; m < 8; m++) {
            rawid = (rawid << 1) | g_DemodBuffer[m + k + (m * 4)];
        }
    }

    // descrambled id
    uint32_t cn = 0;
    uint32_t scambled = bytebits_to_byte(g_DemodBuffer + 8 + 32, 32);
    nexwatch_scamble(DESCRAMBLE, &cn, &scambled);

    uint8_t mode = bytebits_to_byte(g_DemodBuffer + 72, 4);
    uint8_t parity = bytebits_to_byte(g_DemodBuffer + 76, 4);
    uint8_t chk = bytebits_to_byte(g_DemodBuffer + 80, 8);

    // parity check
    // from 32b hex id, 4b mode
    uint8_t hex[5] = {0};
    for (uint8_t i = 0; i < 5; i++) {
        hex[i] = bytebits_to_byte(g_DemodBuffer + 8 + 32 + (i * 8), 8);
    }
    // mode is only 4 bits.
    hex[4] &= 0xf0;
    uint8_t calc_parity = nexwatch_parity(hex);

    // Checksum
    typedef struct {
        uint8_t magic;
        char desc[13];
        uint8_t chk;
    } nexwatch_magic_t;
    nexwatch_magic_t items[] = {
        {0xBE, "Quadrakey", 0},
        {0x88, "Nexkey", 0},
        {0x86, "Honeywell", 0}
    };

    uint8_t m_idx;
    for (m_idx = 0; m_idx < ARRAYLEN(items); m_idx++) {

        items[m_idx].chk = nexwatch_checksum(items[m_idx].magic, cn, calc_parity);
        if (items[m_idx].chk == chk) {
            break;
        }
    }

    // output
    PrintAndLogEx(SUCCESS, " NexWatch raw id : " _YELLOW_("0x%08"PRIx32), rawid);

    if (m_idx < ARRAYLEN(items)) {
        PrintAndLogEx(SUCCESS, "     fingerprint : " _GREEN_("%s"),  items[m_idx].desc);
    } else {
        nexwatch_magic_bruteforce(cn, calc_parity, chk);
    }
    PrintAndLogEx(SUCCESS, "        88bit id : " _YELLOW_("%"PRIu32) " ("  _YELLOW_("0x%08"PRIx32)")", cn, cn);
    PrintAndLogEx(SUCCESS, "            mode : %x", mode);


    if (parity == calc_parity) {
        PrintAndLogEx(DEBUG, "          parity : ( %s ) 0x%X", _GREEN_("ok"), parity);
    } else {
        PrintAndLogEx(DEBUG, "          parity : ( %s ) 0x%X != 0x%X", _RED_("fail"), parity, calc_parity);
    }

    PrintAndLogEx(DEBUG, "        checksum : ( %s ) 0x%02X", (m_idx < ARRAYLEN(items)) ? _GREEN_("ok") : _RED_("fail"), chk);

    PrintAndLogEx(INFO, " Raw : " _YELLOW_("%08"PRIX32"%08"PRIX32"%08"PRIX32), raw1, raw2, raw3);
    return PM3_SUCCESS;
}

static int CmdNexWatchDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch demod",
                  "Try to find Nexwatch preamble, if found decode / descramble data",
                  "lf nexwatch demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodNexWatch(true);
}

static int CmdNexWatchReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch reader",
                  "read a Nexwatch tag",
                  "lf nexwatch reader -@   -> continuous reader mode"
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
        lf_read(false, 20000);
        demodNexWatch(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

static int CmdNexWatchClone(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch clone",
                  "clone a Nexwatch tag to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "You can use raw hex values or create a credential based on id, mode\n"
                  "and type of credential (Nexkey / Quadrakey / Russian)",
                  "lf nexwatch clone --raw 5600000000213C9F8F150C00\n"
                  "lf nexwatch clone --cn 521512301 -m 1 --nc    -> Nexkey credential\n"
                  "lf nexwatch clone --cn 521512301 -m 1 --qc    -> Quadrakey credential\n"
                  "lf nexwatch clone --cn 521512301 -m 1 --hc    -> Honeywell credential\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes"),
        arg_u64_0(NULL, "cn", "<dec>", "card id"),
        arg_u64_0("m", "mode", "<dec>", "mode (decimal) (0-15, defaults to 1)"),
        arg_lit0(NULL, "nc", "Nexkey credential"),
        arg_lit0(NULL, "qc", "Quadrakey credential"),
        arg_lit0(NULL, "hc", "Honeywell credential"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_str0(NULL, "magic", "<hex>", "optional - magic hex data. 1 byte"),
        arg_lit0(NULL, "psk2", "optional - specify writing a tag in psk2 modulation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0x56, 0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    uint32_t cn = arg_get_u32_def(ctx, 2, -1);
    uint32_t mode = arg_get_u32_def(ctx, 3, -1);
    bool use_nexkey = arg_get_lit(ctx, 4);
    bool use_quadrakey = arg_get_lit(ctx, 5);
    bool use_honeywell = arg_get_lit(ctx, 6);
    bool q5 = arg_get_lit(ctx, 7);
    bool em = arg_get_lit(ctx, 8);

    uint8_t magic_arg[2];
    int mlen = 0;
    CLIGetHexWithReturn(ctx, 9, magic_arg, &mlen);

    bool use_psk2 = arg_get_lit(ctx, 10);

    CLIParserFree(ctx);

    if (use_nexkey && use_quadrakey) {
        PrintAndLogEx(FAILED, "Can't specify both Nexkey and Quadrakey at the same time");
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    // 56000000 00213C9F 8F150C00
    bool use_raw = (raw_len != 0);

    bool use_custom_magic = (mlen != 0);

    if (mlen > 1) {
        PrintAndLogEx(FAILED, "Can't specify a magic number bigger than one byte");
        return PM3_EINVARG;
    }

    if (use_raw && cn != -1) {
        PrintAndLogEx(FAILED, "Can't specify both Raw and Card id at the same time");
        return PM3_EINVARG;
    }

    if (cn != -1) {
        uint32_t scrambled;
        nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
        num_to_bytes(scrambled, 4, raw + 5);
    }

    if (mode != -1) {
        if (mode > 15) {
            mode = 1;
        }
        mode &= 0x0F;
        raw[9] |= (mode << 4);
    }

    uint8_t magic = 0xBE;
    if (use_custom_magic) {
        magic = magic_arg[0];
    } else {
        if (use_nexkey)
            magic = 0x88;

        if (use_quadrakey)
            magic = 0xBE;

        if (use_honeywell)
            magic = 0x86;

    }
    PrintAndLogEx(INFO, "Magic byte selected... " _YELLOW_("0x%X"), magic);

    uint32_t blocks[4];

    //Nexwatch - compat mode, PSK, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_PSK1 | T55x7_BITRATE_RF_32 | 3 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};

    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(64) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_NEXWATCH_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    if (use_raw == false) {
        uint8_t parity = nexwatch_parity(raw + 5) & 0xF;
        raw[9] |= parity;
        raw[10] |= nexwatch_checksum(magic, cn, parity);
    }

    if (use_psk2) {
        blocks[0] = 0x00042080;

        uint8_t *res_shifted = calloc(96, sizeof(uint8_t));
        uint8_t *res = calloc(96, sizeof(uint8_t));

        bytes_to_bytebits(raw, 12, res);
        psk1TOpsk2(res, 96);
        memcpy(res_shifted, &res[1], 95 * sizeof(uint8_t));
        free(res);
        bits_to_array(res_shifted, 96, raw);
        free(res_shifted);
    }


    for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
        blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
    }

    PrintAndLogEx(INFO, "Preparing to clone NexWatch to " _YELLOW_("%s") " raw " _YELLOW_("%s"), cardtype, sprint_hex_inrow(raw, sizeof(raw)));
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf nexwatch reader`") " to verify");
    return res;
}

static int CmdNexWatchSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf nexwatch sim",
                  "Enables simulation of secura card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "You can use raw hex values or create a credential based on id, mode\n"
                  "and type of credential (Nexkey/Quadrakey)",
                  "lf nexwatch sim --raw 5600000000213C9F8F150C00\n"
                  "lf nexwatch sim --cn 521512301 -m 1 --nc    -> Nexkey credential\n"
                  "lf nexwatch sim --cn 521512301 -m 1 --qc    -> Quadrakey credential\n"
                  "lf nexwatch sim --cn 521512301 -m 1 --hc    -> Honeywell credential\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes"),
        arg_u64_0(NULL, "cn", "<dec>", "card id"),
        arg_u64_0("m", "mode", "<dec>", "mode (decimal) (0-15, defaults to 1)"),
        arg_lit0(NULL, "nc", "Nexkey credential"),
        arg_lit0(NULL, "qc", "Quadrakey credential"),
        arg_lit0(NULL, "hc", "Honeywell credential"),
        arg_str0(NULL, "magic", "<hex>", "optional - magic hex data. 1 byte"),
        arg_lit0(NULL, "psk2", "optional - specify writing a tag in psk2 modulation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0x56, 0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    uint32_t cn = arg_get_u32_def(ctx, 2, -1);
    uint32_t mode = arg_get_u32_def(ctx, 3, -1);
    bool use_nexkey = arg_get_lit(ctx, 4);
    bool use_quadrakey = arg_get_lit(ctx, 5);
    bool use_unk = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (use_nexkey && use_quadrakey) {
        PrintAndLogEx(FAILED, "Can't specify both Nexkey and Quadrakey at the same time");
        return PM3_EINVARG;
    }

    bool use_raw = (raw_len != 0);

    if (use_raw && cn != -1) {
        PrintAndLogEx(FAILED, "Can't specify both Raw and Card id at the same time");
        return PM3_EINVARG;
    }

    if (cn != -1) {
        uint32_t scrambled;
        nexwatch_scamble(SCRAMBLE, &cn, &scrambled);
        num_to_bytes(scrambled, 4, raw + 5);
    }

    if (mode != -1) {
        if (mode > 15) {
            mode = 1;
        }
        mode &= 0x0F;
        raw[9] |= (mode << 4);
    }

    uint8_t magic = 0xBE;
    if (use_nexkey)
        magic = 0x88;

    if (use_quadrakey)
        magic = 0xBE;

    if (use_unk)
        magic = 0x86;

    if (use_raw == false) {
        uint8_t parity = nexwatch_parity(raw + 5) & 0xF;
        raw[9] |= parity;
        raw[10] |= nexwatch_checksum(magic, cn, parity);
    }

    uint8_t bs[96];
    memset(bs, 0, sizeof(bs));

    // hex to bits.  (3 * 32 == 96)
    for (size_t i = 0; i < 3; i++) {
        uint32_t tmp = bytes_to_num(raw + (i * sizeof(uint32_t)), sizeof(uint32_t));
        num_to_bytebits(tmp, sizeof(uint32_t) * 8, bs + (i * sizeof(uint32_t) * 8));
    }

    PrintAndLogEx(SUCCESS, "Simulating NexWatch - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier = 2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_PSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,           AlwaysAvailable, "This help"},
    {"demod",  CmdNexWatchDemod,  AlwaysAvailable, "demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer"},
    {"reader", CmdNexWatchReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdNexWatchClone,  IfPm3Lf,         "clone NexWatch tag to T55x7"},
    {"sim",    CmdNexWatchSim,    IfPm3Lf,         "simulate NexWatch tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNEXWATCH(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int detectNexWatch(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[28]   = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // sanity check.
    if (*size < 96) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(g_DemodBuffer, preamble, sizeof(preamble), size, &startIdx)) {
        // if didn't find preamble try again inverting
        uint8_t preamble_i[28] = {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        if (!preambleSearch(g_DemodBuffer, preamble_i, sizeof(preamble_i), size, &startIdx)) return -4;
        *invert ^= 1;
    }

    // size tests?
    return (int) startIdx;
}
