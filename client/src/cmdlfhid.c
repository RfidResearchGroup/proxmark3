//-----------------------------------------------------------------------------
// Copyright (C) 2010 iZsh <izsh at fail0verflow.com>
// 2016,2017, marshmellow, iceman
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
#include "commonutil.h"  // ARRAYLEN
#include "cliparser.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"  //for g_debugMode, demodbuff cmds
#include "cmdlf.h"    // lf_read
#include "util_posix.h"
#include "lfdemod.h"
#include "wiegand_formats.h"

#ifndef BITS
# define BITS 96
#endif

static int CmdHelp(const char *Cmd);

// sending three times.  Didn't seem to break the previous sim?
static int sendPing(void) {
    SendCommandNG(CMD_PING, NULL, 0);
    SendCommandNG(CMD_PING, NULL, 0);
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

    if (HIDPack(format_idx, card, &packed) == false) {
        PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
        return PM3_ESOFT;
    }

    if (verbose)
        PrintAndLogEx(INFO, "Trying FC: %u; CN: %"PRIu64";  Issue level: %u; OEM: %u", card->FacilityCode, card->CardNumber, card->IssueLevel, card->OEM);

    lf_hidsim_t payload;
    payload.hi2 = packed.Top;
    payload.hi = packed.Mid;
    payload.lo = packed.Bot;

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

    uint8_t bits[GraphTraceLen];
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

    if (hi2 != 0) { //extra large HID tags
        PrintAndLogEx(SUCCESS, "HID Prox - " _GREEN_("%x%08x%08x (%u)"), hi2, hi, lo, (lo >> 1) & 0xFFFF);
    } else {  //standard HID tags <38 bits
        uint8_t fmtLen = 0;
        uint32_t cc = 0;
        uint32_t fc = 0;
        uint32_t cardnum = 0;
        uint8_t oem = 0;
        if (((hi >> 5) & 1) == 1) {//if bit 38 is set then < 37 bit format is used
            uint32_t lo2 = 0;
            lo2 = (((hi & 31) << 12) | (lo >> 20)); //get bits 21-37 to check for format len bit
            uint8_t idx3 = 1;
            while (lo2 > 1) { //find last bit set to 1 (format len bit)
                lo2 >>= 1;
                idx3++;
            }
            fmtLen = idx3 + 19;
            fc = 0;
            cardnum = 0;
            if (fmtLen == 26) {
                cardnum = (lo >> 1) & 0xFFFF;
                fc = (lo >> 17) & 0xFF;
            }
            if (fmtLen == 32 && (lo & 0x40000000)) { //if 32 bit and Kastle bit set
                cardnum = (lo >> 1) & 0xFFFF;
                fc = (lo >> 17) & 0xFF;
                cc = (lo >> 25) & 0x1F;
            }
            if (fmtLen == 34) {
                cardnum = (lo >> 1) & 0xFFFF;
                fc = ((hi & 1) << 15) | (lo >> 17);
            }
            if (fmtLen == 35) {
                cardnum = (lo >> 1) & 0xFFFFF;
                fc = ((hi & 1) << 11) | (lo >> 21);
            }
            if (fmtLen == 36) {
                oem = (lo >> 1) & 0x3;
                cardnum = (lo >> 3) & 0xFFFF;
                fc = (hi & 0x7) << 13 | ((lo >> 19) & 0xFFFF);
            }
        } else { //if bit 38 is not set then 37 bit format is used
            fmtLen = 37;
            cardnum = (lo >> 1) & 0x7FFFF;
            fc = ((hi & 0xF) << 12) | (lo >> 20);
        }
        if (fmtLen == 32 && (lo & 0x40000000)) { //if 32 bit and Kastle bit set
            PrintAndLogEx(SUCCESS,
                          "HID Prox (Kastle format) - " _GREEN_("%x%08x (%u)") " - len: " _GREEN_("32") " bit CC: " _GREEN_("%u") " FC: " _GREEN_("%u") " Card: " _GREEN_("%u"), hi, lo, (lo >> 1) & 0xFFFF, cc, fc, cardnum);
        } else {
            PrintAndLogEx(SUCCESS,
                          "HID Prox - " _GREEN_("%x%08x (%u)") " - len: " _GREEN_("%u") " bit - OEM: " _GREEN_("%03u") " FC: " _GREEN_("%u")" Card: " _GREEN_("%u"),
                          hi, lo, cardnum, fmtLen, oem, fc, cardnum);
        }
    }

    PrintAndLogEx(DEBUG, "DEBUG: HID idx: %d, Len: %zu, Printing Demod Buffer: ", idx, size);
    if (g_debugMode)
        printDemodBuff();

    return PM3_SUCCESS;
}

static int CmdHIDDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return demodHID(true);
}

// this read is the "normal" read,  which download lf signal and tries to demod here.
static int CmdHIDRead(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    lf_read(false, 12000);
    return demodHID(true);
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
    PacketResponseNG resp;
    WaitForResponse(CMD_LF_HID_WATCH, &resp);
    PrintAndLogEx(INFO, "Done");
    return resp.status;
}

static int CmdHIDSim(const char *Cmd) {
    int idlen = 0;
    uint8_t id[10] = {0};
    lf_hidsim_t payload;
    payload.longFMT = 0;
    uint32_t hi2 = 0, hi = 0, lo = 0;
    uint32_t i = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid sim",
                  "Enables simulation of HID card with card number.",
                  "lf hid sim 2006ec0c86"
                );
    
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("l", "long", "Simulate HID tag with long ID"),
        arg_str1(NULL, NULL, "<hex>", "HID tag ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool long_id = arg_get_lit(ctx, 1);

    CLIGetHexWithReturn(ctx, 2, id, &idlen);

    CLIParserFree(ctx);

    if (long_id) {
        for (i=0; i < idlen; ++i) {
            hi2 = (hi2 << 4) | (hi >> 28);
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] >> 4);  //get first 4 bits

            hi2 = (hi2 << 4) | (hi >> 28);
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] & 0xf); //get last 4 bits
        }
        PrintAndLogEx(INFO, "Simulating HID tag with long ID: " _GREEN_("%x%08x%08x"), hi2, hi, lo);
        payload.longFMT = 1;
    } else {
        for (i=0; i < idlen; ++i) {
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] >> 4);  //get first 4 bits

            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] & 0xf); //get last 4 bits
        }
        PrintAndLogEx(SUCCESS, "Simulating HID tag with ID: " _GREEN_("%x%08x"), hi, lo);
        hi2 = 0;
    }

    PrintAndLogEx(INFO, "Press pm3-button to abort simulation");

    payload.hi2 = hi2;
    payload.hi = hi;
    payload.lo = lo;

    clearCommandBuffer();
    SendCommandNG(CMD_LF_HID_SIMULATE, (uint8_t *)&payload,  sizeof(payload));
    PacketResponseNG resp;
    WaitForResponse(CMD_LF_HID_SIMULATE, &resp);
    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static int CmdHIDClone(const char *Cmd) {
    int idlen = 0;
    uint8_t id[10] = {0};

    uint32_t hi2 = 0, hi = 0, lo = 0;
    uint32_t i = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid clone",
                  "Clone HID to T55x7. Tag must be on antenna!",
                  "lf hid clone 2006ec0c86\n"
                  "lf hid clone -l 2006ec0c86"
                );
    
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("l", "long", "84bit HID long ID"),
        arg_str1(NULL, NULL, "<hex>", "HID tag ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool long_id = arg_get_lit(ctx, 1);

    CLIGetHexWithReturn(ctx, 2, id, &idlen);

    CLIParserFree(ctx);

    uint8_t longid[1] = {0};

    if (long_id) {
        for (i=0; i < idlen; ++i) {
            hi2 = (hi2 << 4) | (hi >> 28);
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] >> 4);  //get first 4 bits

            hi2 = (hi2 << 4) | (hi >> 28);
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] & 0xf); //get last 4 bits
        }
        PrintAndLogEx(INFO, "Preparing to clone HID tag with long ID: " _GREEN_("%x%08x%08x"), hi2, hi, lo);

        longid[0] = 1;
    } else {
        for (i=0; i < idlen; ++i) {
            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] >> 4);  //get first 4 bits

            hi = (hi << 4) | (lo >> 28);
            lo = (lo << 4) | (id[i] & 0xf); //get last 4 bits
        }
        PrintAndLogEx(INFO, "Preparing to clone HID tag with ID: " _GREEN_("%x%08x"), hi, lo);
        hi2 = 0;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_LF_HID_CLONE, hi2, hi, lo, longid, sizeof(longid));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf hid read`") " to verify");
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

    uint32_t delay = 1000;
    int format_idx = -1;
    int direction = 0;
    uint8_t format[16] = {0};
    int formatLen;

    wiegand_card_t cn_hi, cn_low;
    memset(&cn_hi, 0, sizeof(wiegand_card_t));

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf hid brute",
                  "Enables bruteforce of HID readers with specified facility code.\n"
                  "This is a attack against reader. if cardnumber is given, it starts with it and goes up / down one step\n"
                  "if cardnumber is not given, it starts with 1 and goes up to 65535",
                  "lf hid brute -w H10301 -f 224\n"
                  "lf hid brute -w H10301 -f 21 -d 2000\n"
                  "lf hid brute -v -w H10301 -f 21 -c 200 -d 2000\n"
                );
    
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose",           "verbose logging, show all tries"),
        arg_str1("w", "wiegand", "format", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_int0("f", "fn",      "dec",    "facility code"),
        arg_int0("c", "cn",      "dec",    "card number to start with"),
        arg_int0("i", NULL,      "dec",    "issue level"),
        arg_int0("o", "oem",     "dec",    "OEM code"),
        arg_int0("d", "delay",   "dec",    "delay betweens attempts in ms. Default 1000ms"), 
        arg_lit0(NULL, "up",               "direction to increment card number. (default is both directions)"),
        arg_lit0(NULL, "down",             "direction to decrement card number. (default is both directions)"),        
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    bool verbose = arg_get_lit(ctx, 1);
    
    CLIGetStrWithReturn(ctx, 2, format, &formatLen);

    format_idx = HIDFindCardFormat((char*) format);
    if (format_idx == -1) {
        PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    cn_hi.FacilityCode = arg_get_int_def(ctx, 3, 0);
    cn_hi.CardNumber = arg_get_int_def(ctx, 4, 0);
    cn_hi.IssueLevel = arg_get_int_def(ctx, 5, 0);
    cn_hi.OEM = arg_get_int_def(ctx, 6, 0);
    delay = arg_get_int_def(ctx, 7, 1000);

    CLIParserFree(ctx);

    if (arg_get_lit(ctx, 8) && arg_get_lit(ctx, 9)) {
        direction = 0;
    } else if (arg_get_lit(ctx, 8)) {
        direction = 1;
    } else if (arg_get_lit(ctx, 9)) {
        direction = 2;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Wiegand format#.. %i", format_idx);
        PrintAndLogEx(INFO, "OEM#............. %u", cn_hi.OEM);
        PrintAndLogEx(INFO, "ISSUE#........... %u", cn_hi.IssueLevel);
        PrintAndLogEx(INFO, "Facility#........ %u", cn_hi.FacilityCode);
        PrintAndLogEx(INFO, "Card#............ %" PRIu64, cn_hi.CardNumber);
        switch (direction) {
            case 0:
                PrintAndLogEx(INFO, "Brute-forcing direction: " _YELLOW_("BOTH"));
                break;
            case 1:
                PrintAndLogEx(INFO, "Brute-forcing direction: " _YELLOW_("UP"));
                break;
            case 2:
                PrintAndLogEx(INFO, "Brute-forcing direction: " _YELLOW_("DOWN"));
                break;
            default:
                break;
        }
    }
    PrintAndLogEx(INFO, "Brute-forcing HID reader");
    PrintAndLogEx(INFO, "Press pm3-button to abort simulation or press `enter` to exit");

    // copy values to low.
    cn_low = cn_hi;

    // main loop
    // iceman:  could add options for bruteforcing OEM, ISSUE or FC aswell..
    bool exitloop = false;
    bool fin_hi, fin_low;
    fin_hi = fin_low = false;
    do {

        if (!session.pm3_present) {
            PrintAndLogEx(WARNING, "Device offline\n");
            return PM3_ENODATA;
        }

        if (kbd_enter_pressed()) {
            PrintAndLogEx(INFO, "aborted via keyboard!");
            return sendPing();
        }

        // do one up
        if (direction != 2) {
            if (cn_hi.CardNumber < 0xFFFF) {
                cn_hi.CardNumber++;
                if (sendTry(format_idx, &cn_hi, delay, verbose) != PM3_SUCCESS) return PM3_ESOFT;
            } else {
                fin_hi = true;
            }
        }

        // do one down
        if (direction != 1) {
            if (cn_low.CardNumber > 0) {
                cn_low.CardNumber--;
                if (sendTry(format_idx, &cn_low, delay, verbose) != PM3_SUCCESS) return PM3_ESOFT;
            } else {
                fin_low = true;
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

    PrintAndLogEx(INFO, "Brute forcing finished");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "this help"},
    {"demod",   CmdHIDDemod,    AlwaysAvailable, "demodulate HID Prox tag from the GraphBuffer"},
    {"read",    CmdHIDRead,     IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",   CmdHIDClone,    IfPm3Lf,         "clone HID tag to T55x7"},
    {"sim",     CmdHIDSim,      IfPm3Lf,         "simulate HID tag"},
    {"brute",   CmdHIDBrute,    IfPm3Lf,         "bruteforce card number against reader"},
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
