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
// Low frequency HID commands (known)
//
// Useful resources:
// RF interface, programming a T55x7 clone, 26-bit HID H10301 encoding:
// http://www.proxmark.org/files/Documents/125%20kHz%20-%20HID/HID_format_example.pdf
//
// "Understanding Card Data Formats"
// https://www.hidglobal.com/sites/default/files/hid-understanding_card_data_formats-wp-en.pdf
//
// "What Format Do You Need?"
// https://www.hidglobal.com/sites/default/files/resource_files/hid-prox-br-en.pdf
//-----------------------------------------------------------------------------

#include "cmdlfhid.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h"   // ARRAYLEN
#include "cliparser.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"      // g_debugMode, demodbuff cmds
#include "cmdlf.h"        // lf_read, lfsim_wait_check
#include "util_posix.h"
#include "lfdemod.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "cmdlfem4x05.h"  // EM defines

#ifndef BITS
# define BITS 96
#endif

static int CmdHelp(const char *Cmd);

// sending three times.  Didn't seem to break the previous sim?
static int sendPing(void) {
    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
    SendCommandNG(CMD_PING, NULL, 0);
    clearCommandBuffer();
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_PING, &resp, 1000))
        return PM3_ETIMEOUT;
    return PM3_SUCCESS;
}
static int sendTry(uint8_t format_idx, wiegand_card_t *card, uint32_t delay, bool verbose) {

    wiegand_message_t packed;
    memset(&packed, 0, sizeof(wiegand_message_t));

    if (HIDPack(format_idx, card, &packed, true) == false) {
        PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Trying FC: " _YELLOW_("%u") " CN: " _YELLOW_("%"PRIu64) " Issue level: " _YELLOW_("%u") " OEM: " _YELLOW_("%u")
                      , card->FacilityCode
                      , card->CardNumber
                      , card->IssueLevel
                      , card->OEM
                     );
    }

    lf_hidsim_t payload = {
        .EM = false,
        .Q5 = false,
        .hi2 = packed.Top,
        .hi = packed.Mid,
        .lo = packed.Bot,
        .longFMT = (packed.Mid > 0xFFF)
    };

    clearCommandBuffer();

    SendCommandNG(CMD_LF_HID_SIMULATE, (uint8_t *)&payload,  sizeof(payload));
    /*
        PacketResponseNG resp;
        WaitForResponse(CMD_LF_HID_SIMULATE, &resp);
        if (resp.status == PM3_EOPABORTED)
            return resp.status;
    */
    msleep(delay);
    return sendPing();
}

//by marshmellow (based on existing demod + holiman's refactor)
//HID Prox demod - FSK RF/50 with preamble of 00011101 (then manchester encoded)
//print full HID Prox ID and some bit format details if found
int demodHID(bool verbose) {
    (void) verbose; // unused so far

    // HID simulation etc uses 0/1 as signal data. This must be converted in order to demod it back again
    if (isGraphBitstream()) {
        convertGraphFromBitstream();
    }

    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint32_t hi2 = 0, hi = 0, lo = 0;

    uint8_t bits[g_GraphTraceLen];
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID not enough samples"));
        return PM3_ESOFT;
    }
    //get binary from fsk wave
    int waveIdx = 0;
    int idx = HIDdemodFSK(bits, &size, &hi2, &hi, &lo, &waveIdx);
    if (idx < 0) {

        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID not enough samples"));
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID just noise detected"));
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID problem during FSK demod"));
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID preamble not found"));
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID error in Manchester data, size %zu"), size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID error demoding fsk %d"), idx);

        return PM3_ESOFT;
    }

    setDemodBuff(bits, size, idx);
    setClockGrid(50, waveIdx + (idx * 50));

    if (hi2 == 0 && hi == 0 && lo == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("HID no values found"));
        return PM3_ESOFT;
    }

    wiegand_message_t packed = initialize_message_object(hi2, hi, lo, 0);
    if (HIDTryUnpack(&packed) == false) {
        printDemodBuff(0, false, false, true);
    }
    PrintAndLogEx(INFO, "raw: " _GREEN_("%08x%08x%08x"), hi2, hi, lo);

    PrintAndLogEx(DEBUG, "DEBUG: HID idx: %d, Len: %zu, Printing DemodBuffer: ", idx, size);
    if (g_debugMode) {
        PrintAndLogEx(DEBUG, "raw: " _GREEN_("%08x%08x%08x"), hi2, hi, lo);

        printDemodBuff(0, false, false, false);
    }

    return PM3_SUCCESS;
}

static int CmdHIDDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid demod",
                  "Try to find HID Prox preamble, if found decode / descramble data",
                  "lf hid demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodHID(true);
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdHIDReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid reader",
                  "read a HID Prox tag",
                  "lf hid reader -@   -> continuous reader mode"
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
        demodHID(!cm);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

// this read loops on device side.
// uses the demod in lfops.c
static int CmdHIDWatch(const char *Cmd) {
    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf hid watch",
                  "Enables HID compatible reader mode printing details.\n"
                  "By default, values are printed and logged until the button is pressed or another USB command is issued.\n",
                  "lf hid watch"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    PrintAndLogEx(SUCCESS, "Watching for HID Prox cards - place tag on antenna");
    PrintAndLogEx(INFO, "Press pm3-button to stop reading cards");
    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_WATCH, NULL, 0);
    return lfsim_wait_check(CMD_LF_HID_WATCH);
}

static int CmdHIDSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid sim",
                  "Enables simulation of HID card with card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.",
                  "lf hid sim -r 2006ec0c86                -> HID 10301 26 bit\n"
                  "lf hid sim -r 2e0ec00c87                -> HID Corporate 35 bit\n"
                  "lf hid sim -r 01f0760643c3              -> HID P10001 40 bit\n"
                  "lf hid sim -r 01400076000c86            -> HID Corporate 48 bit\n"
                  "lf hid sim -w H10301 --fc 118 --cn 1603 -> HID 10301 26 bit\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_u64_0(NULL, "fc",      "<dec>", "facility code"),
        arg_u64_0(NULL, "cn",      "<dec>", "card number"),
        arg_u64_0("i",    NULL,     "<dec>", "issue level"),
        arg_u64_0("o",   "oem",     "<dec>", "OEM code"),
        arg_str0("r",  "raw",     "<hex>", "raw bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char format[16] = {0};
    int format_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)format, sizeof(format), &format_len);

    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));
    card.FacilityCode = arg_get_u32_def(ctx, 2, 0);
    card.CardNumber = arg_get_u32_def(ctx, 3, 0);
    card.IssueLevel = arg_get_u32_def(ctx, 4, 0);
    card.OEM = arg_get_u32_def(ctx, 5, 0);

    int raw_len = 0;
    char raw[40] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)raw, sizeof(raw), &raw_len);
    CLIParserFree(ctx);

    wiegand_message_t packed;
    memset(&packed, 0, sizeof(wiegand_message_t));

    // format validation
    int format_idx = HIDFindCardFormat(format);
    if (format_idx == -1 && raw_len == 0) {
        PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
        return PM3_EINVARG;
    }

    if (raw_len) {
        uint32_t top = 0, mid = 0, bot = 0;
        hexstring_to_u96(&top, &mid, &bot, raw);
        packed.Top = top;
        packed.Mid = mid;
        packed.Bot = bot;
    } else {
        if (HIDPack(format_idx, &card, &packed, true) == false) {
            PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
            return PM3_ESOFT;
        }
    }

    if (raw_len == 0) {
        PrintAndLogEx(INFO, "Simulating HID tag");
        HIDTryUnpack(&packed);
    } else {
        PrintAndLogEx(INFO, "Simulating HID tag using raw " _GREEN_("%s"),  raw);
    }

    lf_hidsim_t payload;
    payload.hi2 = packed.Top;
    payload.hi = packed.Mid;
    payload.lo = packed.Bot;
    payload.longFMT = (packed.Mid > 0xFFF);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_SIMULATE, (uint8_t *)&payload,  sizeof(payload));
    return lfsim_wait_check(CMD_LF_HID_SIMULATE);
}

static int CmdHIDClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid clone",
                  "clone a HID Prox tag to a T55x7, Q5/T5555 or EM4305/4469 tag.\n"
                  "Tag must be on the antenna when issuing this command.",
                  "lf hid clone -r 2006ec0c86                      -> write raw value for T55x7 tag (HID 10301 26 bit)\n"
                  "lf hid clone -r 2e0ec00c87                      -> write raw value for T55x7 tag (HID Corporate 35 bit)\n"
                  "lf hid clone -r 01f0760643c3                    -> write raw value for T55x7 tag (HID P10001 40 bit)\n"
                  "lf hid clone -r 01400076000c86                  -> write raw value for T55x7 tag (HID Corporate 48 bit)\n"
                  "lf hid clone -w H10301 --fc 118 --cn 1603       -> HID 10301 26 bit, encode for T55x7 tag\n"
                  "lf hid clone -w H10301 --fc 118 --cn 1603 --q5  -> HID 10301 26 bit, encode for Q5/T5555 tag\n"
                  "lf hid clone -w H10301 --fc 118 --cn 1603 --em  -> HID 10301 26 bit, encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_u64_0(NULL, "fc",      "<dec>", "facility code"),
        arg_u64_0(NULL, "cn",      "<dec>", "card number"),
        arg_int0("i",    NULL,     "<dec>", "issue level"),
        arg_int0("o",   "oem",     "<dec>", "OEM code"),
        arg_str0("r",  "raw",     "<hex>", "raw bytes"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char format[16] = {0};
    int format_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)format, sizeof(format), &format_len);

    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));
    card.FacilityCode = arg_get_u32_def(ctx, 2, 0);
    card.CardNumber = arg_get_u32_def(ctx, 3, 0);
    card.IssueLevel = arg_get_u32_def(ctx, 4, 0);
    card.OEM = arg_get_u32_def(ctx, 5, 0);

    int raw_len = 0;
    char raw[40] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)raw, sizeof(raw), &raw_len);

    bool q5 = arg_get_lit(ctx, 7);
    bool em = arg_get_lit(ctx, 8);

    int bin_len = 63;
    uint8_t bin[70] = {0};
    CLIGetStrWithReturn(ctx, 9, bin, &bin_len);
    CLIParserFree(ctx);

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if (bin_len > 127) {
        PrintAndLogEx(ERR, "Binary wiegand string must be less than 128 bits");
        return PM3_EINVARG;
    }

    wiegand_message_t packed;
    memset(&packed, 0, sizeof(wiegand_message_t));

    // format validation
    int format_idx = HIDFindCardFormat(format);
    if (format_idx == -1 && raw_len == 0) {
        PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
        return PM3_EINVARG;
    }

    uint32_t top = 0, mid = 0, bot = 0;
    if (raw_len) {
        hexstring_to_u96(&top, &mid, &bot, raw);
        packed.Top = top;
        packed.Mid = mid;
        packed.Bot = bot;
    } else if (bin_len) {
        int res = binstring_to_u96(&top, &mid, &bot, (const char *)bin);
        if (res != bin_len) {
            PrintAndLogEx(ERR, "Binary string contains none <0|1> chars");
            return PM3_EINVARG;
        }
        packed.Top = top;
        packed.Mid = mid;
        packed.Bot = bot;
    } else {
        if (HIDPack(format_idx, &card, &packed, true) == false) {
            PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
            return PM3_ESOFT;
        }
    }

    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        PrintAndLogEx(WARNING, "Beware some EM4305 tags don't support FSK and datarate = RF/50, check your tag copy!");
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    if (raw_len == 0) {
        PrintAndLogEx(INFO, "Preparing to clone HID tag");
        HIDUnpack(format_idx, &packed);
    } else {
        PrintAndLogEx(INFO, "Preparing to clone HID tag using raw " _YELLOW_("%s"),  raw);
    }

    lf_hidsim_t payload;
    payload.hi2 = packed.Top;
    payload.hi = packed.Mid;
    payload.lo = packed.Bot;
    payload.longFMT = (packed.Mid > 0xFFF);
    payload.Q5 = q5;
    payload.EM = em;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_CLONE, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_HID_CLONE, &resp);
    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Done");
    } else {
        PrintAndLogEx(FAILED, "Failed cloning");
        return resp.status;
    }

    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf hid reader`") " to verify");
    return PM3_SUCCESS;
}

/*
    PrintAndLogEx(NORMAL, "HID | OEM | FC   | CN      |  Wiegand  |  HID Formatted");
    PrintAndLogEx(NORMAL, "----+-----+------+---------+-----------+--------------------");
    PrintAndLogEx(NORMAL, " %u | %03u | %03u  | %" PRIu64 "  | %" PRIX64 "  |  %" PRIX64,
                      fmtlen[i],
                      oem,
                      fc,
                      cardnum,
                      wiegand,
                      blocks
                     );
    }
    PrintAndLogEx(NORMAL, "----+-----+-----+-------+-----------+--------------------");
*/

static int CmdHIDBrute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid brute",
                  "Enables bruteforce of HID readers with specified facility code or card number. This is an attack against the reader.\n"
                  "If the field being bruteforced is provided, it starts with it and goes up / down one step while maintaining other supplied values.\n"
                  "If the field being bruteforced is not provided, it will iterate through the full range while maintaining other supplied values.",
                  "lf hid brute -w H10301 --field fc --fc 224 --cn 6278\n"
                  "lf hid brute -w H10301 --field cn --fc 21 -d 2000\n"
                  "lf hid brute -v -w H10301 --field cn --fc 21 --cn 200 -d 2000\n"
                  "lf hid brute -v -w H10301 --field fc --fc 21 --cn 200 -d 2000 --up\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose",             "verbose output"),
        arg_str1("w", "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_str1(NULL, "field",   "<fc|cn>", "field to bruteforce"),
        arg_u64_0(NULL, "fc",     "<dec>",   "facility code"),
        arg_u64_0(NULL, "cn",     "<dec>",   "card number"),
        arg_u64_0("i",  "issue",  "<dec>",   "issue level"),
        arg_u64_0("o", "oem",     "<dec>",   "OEM code"),
        arg_u64_0("d", "delay",   "<dec>",   "delay betweens attempts in ms. (def is 1000)"),
        arg_lit0(NULL, "up",                 "direction to increment field value. (def is both directions)"),
        arg_lit0(NULL, "down",               "direction to decrement field value. (def is both directions)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);

    char format[16] = {0};
    int format_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)format, sizeof(format), &format_len);

    int format_idx = HIDFindCardFormat(format);
    if (format_idx == -1) {
        PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    wiegand_card_t card_hi, card_low;
    memset(&card_hi, 0, sizeof(wiegand_card_t));

    char field[3] = {0};
    int field_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 3), (uint8_t *)field, sizeof(field), &field_len);

    card_hi.FacilityCode = arg_get_u32_def(ctx, 4, 0);
    card_hi.CardNumber = arg_get_u32_def(ctx, 5, 0);
    card_hi.IssueLevel = arg_get_u32_def(ctx, 6, 0);
    card_hi.OEM = arg_get_u32_def(ctx, 7, 0);

    uint32_t delay = arg_get_u32_def(ctx, 8, 1000);

    int direction = 0;
    if (arg_get_lit(ctx, 9) && arg_get_lit(ctx, 10)) {
        direction = 0;
    } else if (arg_get_lit(ctx, 9)) {
        direction = 1;
    } else if (arg_get_lit(ctx, 10)) {
        direction = 2;
    }

    CLIParserFree(ctx);

    if (verbose) {
        PrintAndLogEx(INFO, "Wiegand format... %i", format_idx);
        PrintAndLogEx(INFO, "OEM.............. %u", card_hi.OEM);
        PrintAndLogEx(INFO, "ISSUE............ %u", card_hi.IssueLevel);
        PrintAndLogEx(INFO, "Facility code.... %u", card_hi.FacilityCode);
        PrintAndLogEx(INFO, "Card number...... %" PRIu64, card_hi.CardNumber);
        PrintAndLogEx(INFO, "Delay............ " _YELLOW_("%d"), delay);
        if (strcmp(field, "fc") == 0) {
            PrintAndLogEx(INFO, "Field............ " _YELLOW_("fc"));
        } else if (strcmp(field, "cn") == 0) {
            PrintAndLogEx(INFO, "Field............ " _YELLOW_("cn"));
        }
        switch (direction) {
            case 0:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("both"));
                break;
            case 1:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("up"));
                break;
            case 2:
                PrintAndLogEx(INFO, "Direction........ " _YELLOW_("down"));
                break;
            default:
                break;
        }
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Started bruteforcing HID Prox reader");
    PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " or pm3-button to abort simulation");
    PrintAndLogEx(NORMAL, "");
    // copy values to low.
    card_low = card_hi;

    // main loop
    bool exitloop = false;
    bool fin_hi, fin_low;
    fin_hi = fin_low = false;
    do {

        if (g_session.pm3_present == false) {
            PrintAndLogEx(WARNING, "Device offline\n");
            return PM3_ENODATA;
        }

        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "aborted via keyboard!");
            return sendPing();
        }

        // do one up
        if (direction != 2 && fin_hi != true) {
            if (sendTry(format_idx, &card_hi, delay, verbose) != PM3_SUCCESS) {
                return PM3_ESOFT;
            }
            if (strcmp(field, "fc") == 0) {
                if (card_hi.FacilityCode < 0xFF) {
                    card_hi.FacilityCode++;
                } else {
                    fin_hi = true;
                }
            } else if (strcmp(field, "cn") == 0) {
                if (card_hi.CardNumber < 0xFFFF) {
                    card_hi.CardNumber++;
                } else {
                    fin_hi = true;
                }
            }
        }

        // do one down
        if (direction != 1 && fin_low != true) {
            if (sendTry(format_idx, &card_low, delay, verbose) != PM3_SUCCESS) {
                return PM3_ESOFT;
            }
            if (strcmp(field, "fc") == 0) {
                if (card_low.FacilityCode > 0) {
                    card_low.FacilityCode--;
                } else {
                    fin_low = true;
                }
            } else if (strcmp(field, "cn") == 0) {
                if (card_low.CardNumber > 0) {
                    card_low.CardNumber--;
                } else {
                    fin_low = true;
                }
            }
        }

        switch (direction) {
            case 0:
                if (fin_hi && fin_low) {
                    exitloop = true;
                }
                break;
            case 1:
                exitloop = fin_hi;
                break;
            case 2:
                exitloop = fin_low;
                break;
            default:
                break;
        }

    } while (exitloop == false);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Bruteforcing finished");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "this help"},
    {"demod",   CmdHIDDemod,    AlwaysAvailable, "demodulate HID Prox tag from the GraphBuffer"},
    {"reader",  CmdHIDReader,   IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdHIDClone,    IfPm3Lf,         "clone HID tag to T55x7"},
    {"sim",     CmdHIDSim,      IfPm3Lf,         "simulate HID tag"},
    {"brute",   CmdHIDBrute,    IfPm3Lf,         "bruteforce facility code or card number against reader"},
    {"watch",   CmdHIDWatch,    IfPm3Lf,         "continuously watch for cards.  Reader mode"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFHID(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
