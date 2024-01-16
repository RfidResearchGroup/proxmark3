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
// Low frequency AWID26/50 commands
// FSK2a, RF/50, 96 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfawid.h"    // AWID function declarations
#include <ctype.h>
#include <stdlib.h>
#include <string.h>
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "graph.h"
#include "cmddata.h"
#include "ui.h"           // PrintAndLog
#include "lfdemod.h"      // parityTest
#include "cmdlf.h"        // lf read
#include "protocols.h"    // for T55xx config register definitions
#include "util_posix.h"
#include "cmdlft55xx.h"   // verifywrite
#include "cliparser.h"
#include "cmdlfem4x05.h"  // EM defines

static int CmdHelp(const char *Cmd);

static int sendPing(void) {
    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    SendCommandNG(CMD_PING, NULL, 0);
    clearCommandBuffer();
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_PING, &resp, 1000))
        return PM3_ETIMEOUT;
    return PM3_SUCCESS;
}

static int sendTry(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint32_t delay, uint8_t *bits, size_t bs_len, bool verbose) {

    if (verbose)
        PrintAndLogEx(INFO, "Trying FC: " _YELLOW_("%u") " CN: " _YELLOW_("%u"), fc, cn);

    if (getAWIDBits(fmtlen, fc, cn, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + bs_len);
    payload->fchigh = 10;
    payload->fclow = 8;
    payload->separator = 1;
    payload->clock = 50;
    memcpy(payload->data, bits, bs_len);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + bs_len);
    free(payload);

    msleep(delay);
    return sendPing();
}

static void verify_values(uint8_t *fmtlen, uint32_t *fc, uint32_t *cn) {
    switch (*fmtlen) {
        case 50:
            if ((*fc & 0xFFFF) != *fc) {
                *fc &= 0xFFFF;
                PrintAndLogEx(INFO, "Facility-Code Truncated to 16-bits (AWID50): %u", *fc);
            }
            break;
        case 37:
            if ((*fc & 0x1FFF) != *fc) {
                *fc &= 0x1FFF;
                PrintAndLogEx(INFO, "Facility-Code Truncated to 13-bits (AWID37): %u", *fc);
            }
            if ((*cn & 0x3FFFF) != *cn) {
                *cn &= 0x3FFFF;
                PrintAndLogEx(INFO, "Card Number Truncated to 18-bits (AWID37): %u", *cn);
            }
            break;
        case 34:
            if ((*fc & 0xFF) != *fc) {
                *fc &= 0xFF;
                PrintAndLogEx(INFO, "Facility-Code Truncated to 8-bits (AWID34): %u", *fc);
            }
            if ((*cn & 0xFFFFFF) != *cn) {
                *cn &= 0xFFFFFF;
                PrintAndLogEx(INFO, "Card Number Truncated to 24-bits (AWID34): %u", *cn);
            }
            break;
        case 26:
        default:
            *fmtlen = 26;
            if ((*fc & 0xFF) != *fc) {
                *fc &= 0xFF;
                PrintAndLogEx(INFO, "Facility-Code Truncated to 8-bits (AWID26): %u", *fc);
            }
            if ((*cn & 0xFFFF) != *cn) {
                *cn &= 0xFFFF;
                PrintAndLogEx(INFO, "Card Number Truncated to 16-bits (AWID26): %u", *cn);
            }
            break;
    }
}

// this read loops on device side.
// uses the demod in lfops.c
static int CmdAWIDWatch(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf awid watch",
                  "Enables AWID compatible reader mode printing details of scanned AWID26 or AWID50 tags.\n"
                  "Run until the button is pressed or another USB command is issued.",
                  "lf awid watch"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Watching for AWID cards - place tag on antenna");
    PrintAndLogEx(INFO, "Press pm3-button to stop reading cards");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_AWID_WATCH, NULL, 0);
    return lfsim_wait_check(CMD_LF_AWID_WATCH);
}

//by marshmellow
//AWID Prox demod - FSK2a RF/50 with preamble of 00000001  (always a 96 bit data stream)
//print full AWID Prox ID and some bit format details if found
int demodAWID(bool verbose) {
    (void) verbose; // unused so far
    uint8_t *bits = calloc(MAX_GRAPH_TRACE_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - AWID failed to allocate memory");
        return PM3_EMALLOC;
    }

    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - AWID not enough samples");
        free(bits);
        return PM3_ENODATA;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    int idx = detectAWID(bits, &size, &waveIdx);
    if (idx <= 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - AWID not enough samples");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - AWID only noise found");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - AWID problem during FSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - AWID preamble not found");
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - AWID size not correct, size %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - AWID error demoding fsk %d", idx);

        free(bits);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));


    // Index map
    // 0            10            20            30              40            50              60
    // |            |             |             |               |             |               |
    // 01234567 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 456 7 890 1 234 5 678 9 012 3 - to 96
    // -----------------------------------------------------------------------------
    // 00000001 000 1 110 1 101 1 011 1 101 1 010 0 000 1 000 1 010 0 001 0 110 1 100 0 000 1 000 1
    // premable bbb o bbb o bbw o fff o fff o ffc o ccc o ccc o ccc o ccc o ccc o wxx o xxx o xxx o - to 96
    //          |---26 bit---|    |-----117----||-------------142-------------|
    // b = format bit len, o = odd parity of last 3 bits
    // f = facility code, c = card number
    // w = wiegand parity
    // (26 bit format shown)

    //get raw ID before removing parities
    uint32_t rawLo = bytebits_to_byte(bits + idx + 64, 32);
    uint32_t rawHi = bytebits_to_byte(bits + idx + 32, 32);
    uint32_t rawHi2 = bytebits_to_byte(bits + idx, 32);

    size = removeParity(bits, idx + 8, 4, 1, 88);
    if (size != 66) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - AWID at parity check-tag size does not match AWID format");
        free(bits);
        return PM3_ESOFT;
    }
    // ok valid card found!

    // Index map
    // 0           10         20        30          40        50        60
    // |           |          |         |           |         |         |
    // 01234567 8 90123456 7890123456789012 3 456789012345678901234567890123456
    // -----------------------------------------------------------------------------
    // 00011010 1 01110101 0000000010001110 1 000000000000000000000000000000000
    // bbbbbbbb w ffffffff cccccccccccccccc w xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
    // |26 bit|   |-117--| |-----142------|
    //
    // 00110010 0 0000111110100000 00000000000100010010100010000111 1 000000000
    // bbbbbbbb w ffffffffffffffff cccccccccccccccccccccccccccccccc w xxxxxxxxx
    // |50 bit|   |----4000------| |-----------2248975------------|
    // b = format bit len, o = odd parity of last 3 bits
    // f = facility code, c = card number
    // w = wiegand parity

    uint32_t fc = 0;
    uint32_t cardnum = 0;
    uint32_t code1 = 0;
    uint32_t code2 = 0;
    uint8_t fmtLen = bytebits_to_byte(bits, 8);

    switch (fmtLen) {
        case 26:
            fc = bytebits_to_byte(bits + 9, 8);
            cardnum = bytebits_to_byte(bits + 17, 16);
            code1 = bytebits_to_byte(bits + 8, fmtLen);
            PrintAndLogEx(SUCCESS, "AWID - len: " _GREEN_("%d") " FC: " _GREEN_("%d") " Card: " _GREEN_("%u") " - Wiegand: " _GREEN_("%x") ", Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, rawHi2, rawHi, rawLo);
            break;
        case 34:
            fc = bytebits_to_byte(bits + 9, 8);
            cardnum = bytebits_to_byte(bits + 17, 24);
            code1 = bytebits_to_byte(bits + 8, (fmtLen - 32));
            code2 = bytebits_to_byte(bits + 8 + (fmtLen - 32), 32);
            PrintAndLogEx(SUCCESS, "AWID - len: " _GREEN_("%d") " FC: " _GREEN_("%d") " Card: " _GREEN_("%u") " - Wiegand: " _GREEN_("%x%08x") ", Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);
            break;
        case 37:
            fc = bytebits_to_byte(bits + 9, 13);
            cardnum = bytebits_to_byte(bits + 22, 18);
            code1 = bytebits_to_byte(bits + 8, (fmtLen - 32));
            code2 = bytebits_to_byte(bits + 8 + (fmtLen - 32), 32);
            PrintAndLogEx(SUCCESS, "AWID - len: " _GREEN_("%d")" FC: " _GREEN_("%d")" Card: " _GREEN_("%u") " - Wiegand: " _GREEN_("%x%08x") ", Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);
            break;
        // case 40:
        // break;
        case 50:
            fc = bytebits_to_byte(bits + 9, 16);
            cardnum = bytebits_to_byte(bits + 25, 32);
            code1 = bytebits_to_byte(bits + 8, (fmtLen - 32));
            code2 = bytebits_to_byte(bits + 8 + (fmtLen - 32), 32);
            PrintAndLogEx(SUCCESS, "AWID - len: " _GREEN_("%d") " FC: " _GREEN_("%d") " Card: " _GREEN_("%u") " - Wiegand: " _GREEN_("%x%08x") ", Raw: %08x%08x%08x", fmtLen, fc, cardnum, code1, code2, rawHi2, rawHi, rawLo);
            break;
        default:
            if (fmtLen > 32) {
                cardnum = bytebits_to_byte(bits + 8 + (fmtLen - 17), 16);
                code1 = bytebits_to_byte(bits + 8, fmtLen - 32);
                code2 = bytebits_to_byte(bits + 8 + (fmtLen - 32), 32);
                PrintAndLogEx(SUCCESS, "AWID - len: " _GREEN_("%d") " -unknown- (%u) - Wiegand: " _GREEN_("%x%08x") ", Raw: %08x%08x%08x", fmtLen, cardnum, code1, code2, rawHi2, rawHi, rawLo);
            } else {
                cardnum = bytebits_to_byte(bits + 8 + (fmtLen - 17), 16);
                code1 = bytebits_to_byte(bits + 8, fmtLen);
                PrintAndLogEx(SUCCESS, "AWID - len: " _GREEN_("%d") " -unknown- (%u) - Wiegand: " _GREEN_("%x") ", Raw: %08x%08x%08x", fmtLen, cardnum, code1, rawHi2, rawHi, rawLo);
            }
            break;
    }
    free(bits);

    PrintAndLogEx(DEBUG, "DEBUG: AWID idx: %d, Len: %zu", idx, size);
    PrintAndLogEx(DEBUG, "DEBUG: Printing DemodBuffer:");
    if (g_debugMode) {
        printDemodBuff(0, false, false, true);
        printDemodBuff(0, false, false, false);
    }

    return PM3_SUCCESS;
}

static int CmdAWIDDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf awid demod",
                  "Try to find AWID Prox preamble, if found decode / descramble data",
                  "lf awid demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodAWID(true);
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdAWIDReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf awid reader",
                  "read a AWID Prox tag",
                  "lf awid reader -@   -> continuous reader mode"
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
        demodAWID(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static int CmdAWIDClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf awid clone",
                  "clone a AWID Prox tag to a T55x7, Q5/T5555 or EM4305/4469 tag",
                  "lf awid clone --fmt 26 --fc 123 --cn 1337       -> encode for T55x7 tag\n"
                  "lf awid clone --fmt 50 --fc 2001 --cn 13371337  -> encode long fmt for T55x7 tag\n"
                  "lf awid clone --fmt 26 --fc 123 --cn 1337 --q5  -> encode for Q5/T5555 tag\n"
                  "lf awid clone --fmt 26 --fc 123 --cn 1337 --em  -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "fmt", "<dec>", "format length 26|34|37|50"),
        arg_u64_1(NULL, "fc", "<dec>", "8|16bit value facility code"),
        arg_u64_1(NULL, "cn", "<dec>", "16|32-bit value card number"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t fmtlen = arg_get_u32_def(ctx, 1, 0);
    uint32_t fc = arg_get_u32_def(ctx, 2, 0);
    uint32_t cn = arg_get_u32_def(ctx, 3, 0);
    bool q5 = arg_get_lit(ctx, 4);
    bool em = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint32_t blocks[4] = {T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 3 << T55x7_MAXBLOCK_SHIFT, 0, 0, 0};
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        //t5555 (Q5) BITRATE = (RF-2)/2 (iceman)
        blocks[0] = T5555_FIXED | T5555_MODULATION_FSK2 | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(50) | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        blocks[0] = EM4305_AWID_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    verify_values(&fmtlen, &fc, &cn);

    uint8_t *bits = calloc(96, sizeof(uint8_t));

    if (getAWIDBits(fmtlen, fc, cn, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        free(bits);
        return PM3_ESOFT;
    }

    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);
    blocks[3] = bytebits_to_byte(bits + 64, 32);

    // EM4305
    if (em) {
        // invert FSK data
        for (uint8_t i = 1; i < ARRAYLEN(blocks) ; i++) {
            blocks[i] = blocks[i] ^ 0xFFFFFFFF;
        }
    }

    free(bits);

    PrintAndLogEx(INFO, "Preparing to clone AWID %u to " _YELLOW_("%s") " with FC: " _GREEN_("%u") " CN: " _GREEN_("%u"), fmtlen, cardtype, fc, cn);
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf awid reader`") " to verify");
    return res;
}

static int CmdAWIDSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf awid sim",
                  "Enables simulation of AWID card with specified facility-code and card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf awid sim --fmt 26 --fc 123 --cn 1337\n"
                  "lf awid sim --fmt 50 --fc 2001 --cn 13371337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "fmt", "<dec>", "format length 26|32|36|40"),
        arg_u64_1(NULL, "fc", "<dec>", "8-bit value facility code"),
        arg_u64_1(NULL, "cn", "<dec>", "16-bit value card number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t fmtlen = arg_get_u32_def(ctx, 1, 0);
    uint32_t fc = arg_get_u32_def(ctx, 2, 0);
    uint32_t cn = arg_get_u32_def(ctx, 3, 0);
    CLIParserFree(ctx);

    uint8_t bs[96];
    memset(bs, 0x00, sizeof(bs));

    verify_values(&fmtlen, &fc, &cn);

    if (getAWIDBits(fmtlen, fc, cn, bs) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Simulating "_YELLOW_("AWID %u") " -- FC: " _YELLOW_("%u") " CN: " _YELLOW_("%u"), fmtlen, fc, cn);

    // AWID uses: FSK2a fcHigh: 10, fcLow: 8, clk: 50, invert: 1
    // arg1 --- fcHigh<<8 + fcLow
    // arg2 --- Inversion and clk setting
    // 96   --- Bitstream length: 96-bits == 12 bytes
    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    payload->fchigh = 10;
    payload->fclow =  8;
    payload->separator = 1;
    payload->clock = 50;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    return lfsim_wait_check(CMD_LF_FSK_SIMULATE);
}

static int CmdAWIDBrute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf awid brute",
                  "Enables bruteforce of AWID reader with specified facility-code.\n"
                  "This is a attack against reader. if cardnumber is given, it starts with it and goes up / down one step\n"
                  "if cardnumber is not given, it starts with 1 and goes up to 65535",
                  "lf awid brute --fmt 26 --fc 224\n"
                  "lf awid brute --fmt 50 --fc 2001 --delay 2000\n"
                  "lf awid brute --fmt 50 --fc 2001 --cn 200 --delay 2000 -v"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_u64_1(NULL, "fmt", "<dec>", "format length 26|50"),
        arg_u64_1(NULL, "fc", "<dec>", "8|16bit value facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "optional -  card number to start with, max 65535"),
        arg_u64_0(NULL, "delay", "<dec>", "optional - delay betweens attempts in ms. Default 1000ms"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t fmtlen = arg_get_u32_def(ctx, 1, 0);
    uint32_t fc = arg_get_u32_def(ctx, 2, 0);
    uint32_t cn = arg_get_u32_def(ctx, 3, 0);
    uint32_t delay = arg_get_u32_def(ctx, 4, 1000);
    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // limit fc according to selected format
    switch (fmtlen) {
        case 50:
            if ((fc & 0xFFFF) != fc) {
                fc &= 0xFFFF;
                PrintAndLogEx(INFO, "Facility-code truncated to 16-bits (AWID50): %u", fc);
            }
            break;
        default:
            if ((fc & 0xFF) != fc) {
                fc &= 0xFF;
                PrintAndLogEx(INFO, "Facility-code truncated to 8-bits (AWID26): %u", fc);
            }
            break;
    }


    // truncate card number
    if ((cn & 0xFFFF) != cn) {
        cn &= 0xFFFF;
        PrintAndLogEx(INFO, "Card number truncated to 16-bits : %u", cn);
    }

    PrintAndLogEx(SUCCESS, "Bruteforceing AWID %d reader", fmtlen);
    PrintAndLogEx(SUCCESS, "Press pm3-button to abort simulation or press Enter");

    uint16_t up = cn;
    uint16_t down = cn;

    uint8_t bits[96];
    size_t size = sizeof(bits);
    memset(bits, 0x00, size);

    // main loop
    for (;;) {

        if (!g_session.pm3_present) {
            PrintAndLogEx(WARNING, "Device offline\n");
            return PM3_ENODATA;
        }
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard!");
            return sendPing();
        }

        // Do one up
        if (up < 0xFFFF) {
            if (sendTry(fmtlen, fc, up++, delay, bits, size, verbose) != PM3_SUCCESS) {
                return PM3_ESOFT;
            }
        }

        // Do one down  (if cardnumber is given)
        if (cn > 1) {
            if (down > 1) {
                if (sendTry(fmtlen, fc, --down, delay, bits, size, verbose) != PM3_SUCCESS) {
                    return PM3_ESOFT;
                }
            }
        }
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "this help"},
    {"demod",   CmdAWIDDemod,   AlwaysAvailable, "demodulate an AWID FSK tag from the GraphBuffer"},
    {"reader",  CmdAWIDReader,  IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdAWIDClone,   IfPm3Lf,         "clone AWID tag to T55x7 or Q5/T5555"},
    {"sim",     CmdAWIDSim,     IfPm3Lf,         "simulate AWID tag"},
    {"brute",   CmdAWIDBrute,   IfPm3Lf,         "bruteforce card number against reader"},
    {"watch",   CmdAWIDWatch,   IfPm3Lf,         "continuously watch for cards.  Reader mode"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFAWID(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

//refactored by marshmellow
int getAWIDBits(uint8_t fmtlen, uint32_t fc, uint32_t cn, uint8_t *bits) {

    // the return bits, preamble 0000 0001
    bits[7] = 1;

    uint8_t pre[66];
    memset(pre, 0, sizeof(pre));

    // add formatlength
    num_to_bytebits(fmtlen, 8, pre);

    // add facilitycode, cardnumber and wiegand parity bits
    switch (fmtlen) {
        case 26: {
            uint8_t wiegand[24];
            num_to_bytebits(fc, 8, wiegand);
            num_to_bytebits(cn, 16, wiegand + 8);
            wiegand_add_parity(pre + 8, wiegand,  sizeof(wiegand));
            break;
        }
        case 34: {
            uint8_t wiegand[32];
            num_to_bytebits(fc, 8, wiegand);
            num_to_bytebits(cn, 24, wiegand + 8);
            wiegand_add_parity(pre + 8, wiegand,  sizeof(wiegand));
            break;
        }
        case 37: {
            uint8_t wiegand[31];
            num_to_bytebits(fc, 13, wiegand);
            num_to_bytebits(cn, 18, wiegand + 13);
            wiegand_add_parity(pre + 8, wiegand,  sizeof(wiegand));
            break;
        }
        case 50: {
            uint8_t wiegand[48];
            num_to_bytebits(fc, 16, wiegand);
            num_to_bytebits(cn, 32, wiegand + 16);
            wiegand_add_parity(pre + 8, wiegand, sizeof(wiegand));
            break;
        }
    }

    // add AWID 4bit parity
    size_t bitLen = addParity(pre, bits + 8, 66, 4, 1);

    if (bitLen != 88)
        return PM3_ESOFT;

    PrintAndLogEx(DEBUG, "awid raw bits:\n %s \n", sprint_bytebits_bin(bits, bitLen));

    return PM3_SUCCESS;
}
