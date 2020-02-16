//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Thinfilm commands
//-----------------------------------------------------------------------------
#include "cmdhfthinfilm.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h" // manufacture

static int CmdHelp(const char *Cmd);

static int usage_thinfilm_info(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf thinfilm info [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h    this help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf thinfilm info");
    return PM3_SUCCESS;
}

static int usage_thinfilm_sim(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf thinfilm sim [h] [d <data>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h          this help");
    PrintAndLogEx(NORMAL, "           d <bytes>  bytes to send, in hex");
    PrintAndLogEx(NORMAL, "           r          raw, provided bytes should include CRC");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf thinfilm sim d B70470726f786d61726b2e636f6d");
    return PM3_SUCCESS;
}

// Printing function based upon the code in libnfc
// ref
//    https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-barcode.c
static int print_barcode(uint8_t *barcode, const size_t barcode_len, bool verbose) {

    PrintAndLogEx(NORMAL, "");
    // remove start bit
    uint8_t mb = barcode[0] & ~0x80;
    PrintAndLogEx(SUCCESS, "    Manufacturer : "_YELLOW_("%s") "[0x%02X]",  getTagInfo(mb), mb);

    if (verbose) {
        PrintAndLogEx(SUCCESS, "     Data format : "_YELLOW_("%02X"), barcode[1]);
        if (barcode_len > 2) {
            uint8_t b1, b2;
            compute_crc(CRC_14443_A, barcode, barcode_len - 2, &b1, &b2);
            bool isok = (barcode[barcode_len - 1] == b1 && barcode[barcode_len - 2] == b2);

            PrintAndLogEx(SUCCESS, "        Checksum : "_YELLOW_("%02X %02X")"- %s", b2, b1, (isok) ? _GREEN_("OK") : _RED_("fail"));
        } else {
            PrintAndLogEx(SUCCESS, "        Checksum : "_YELLOW_("too few data for checksum")"- " _RED_("fail"));
        }
        PrintAndLogEx(SUCCESS, " Data len (bits) : "_YELLOW_("%zu")"- %s", barcode_len * 8, (barcode_len == 16 || barcode_len == 32) ? _GREEN_("OK") : _YELLOW_("warning"));
        PrintAndLogEx(SUCCESS, "        Raw data : "_YELLOW_("%s"), sprint_hex(barcode, barcode_len));
        if (barcode_len < 4) // too few to go to next decoding stages
            return PM3_ESOFT;
    }

    char s[45];
    memset(s, 0x00, sizeof(s));

    switch (barcode[1]) {
        case 0:
            PrintAndLogEx(SUCCESS, "     Data format : Reserved for allocation by tag manufacturer");
            return PM3_SUCCESS;
        case 1:
            snprintf(s, sizeof(s), "http://www.");
            break;
        case 2:
            snprintf(s, sizeof(s), "https://www.");
            break;
        case 3:
            snprintf(s, sizeof(s), "http://");
            break;
        case 4:
            snprintf(s, sizeof(s), "https://");
            break;
        case 5:
            if (barcode_len < 16) {
                PrintAndLogEx(WARNING, "EPC: (partial data) %s", sprint_hex(barcode + 2, barcode_len - 2));
                return PM3_ESOFT;
            }
            PrintAndLogEx(SUCCESS, "EPC: %s", sprint_hex(barcode + 2, 12));
            return PM3_SUCCESS;
        default:
            PrintAndLogEx(SUCCESS, "     Data format : RFU Reserved for future use (%02X)", barcode[1]);
            if (!verbose)
                PrintAndLogEx(SUCCESS, "Raw data with CRC: "_YELLOW_("%s"), sprint_hex(barcode, barcode_len));
            return PM3_SUCCESS;
    }

    snprintf(s + strlen(s), barcode_len - 3, (const char *)&barcode[2], barcode_len - 4);

    for (uint8_t i = 0; i < strlen(s); i++) {

        // terminate string
        if ((uint8_t) s[i] == 0xFE) {
            s[i] = 0;
            break;
        }
    }
    PrintAndLogEx(SUCCESS, " Decoded NFC URL : "_YELLOW_("%s"), s);
    return PM3_SUCCESS;
}


static int CmdHfThinFilmInfo(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_thinfilm_info();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        usage_thinfilm_info();
        return PM3_EINVARG;
    }

    return infoThinFilm(true);
}

int infoThinFilm(bool verbose) {

    clearCommandBuffer();
    SendCommandNG(CMD_HF_THINFILM_READ, NULL, 0);

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_HF_THINFILM_READ, &resp, 1500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        if (resp.length == 16 || resp.length == 32)  {
            print_barcode(resp.data.asBytes, resp.length, verbose);
        } else {
            if (verbose)
                PrintAndLogEx(WARNING, "Response is wrong length. (%d)", resp.length);

            return PM3_ESOFT;
        }
    }

    return resp.status;
}

static int CmdHfThinFilmSim(const char *Cmd) {
    uint8_t cmdp = 0;
    uint8_t data[512];
    int datalen = 0;

    bool addcrc = true;
    bool errors = false;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_thinfilm_sim();
            case 'd':
                // Retrieve the data
                param_gethex_ex(Cmd, cmdp + 1, data, &datalen);
                datalen >>= 1;
                cmdp += 2;
                break;
            case 'r':
                addcrc = false;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors || cmdp == 0 || datalen == 0 || datalen > 512) return usage_thinfilm_sim();
    if (addcrc && datalen <= 510) {
        uint8_t b1, b2;
        compute_crc(CRC_14443_A, data, datalen, &b1, &b2);
        data[datalen++] = b2;
        data[datalen++] = b1;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_THINFILM_SIMULATE, (uint8_t *)&data, datalen);
    PacketResponseNG resp;
    PrintAndLogEx(SUCCESS, "press pm3-button to abort simulation");

    int ret;
    while (!(ret = kbd_enter_pressed())) {
        if (WaitForResponseTimeout(CMD_HF_THINFILM_SIMULATE, &resp, 500) == 0) continue;
        if (resp.status != PM3_SUCCESS) break;
    }
    if (ret) {
        PrintAndLogEx(INFO, "Client side interrupted");
        PrintAndLogEx(WARNING, "Simulation still running on Proxmark3 till next command or button press");
    } else {
        PrintAndLogEx(INFO, "Done");
    }
    return PM3_SUCCESS;
}

static int CmdHfThinFilmList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("thinfilm");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"info",    CmdHfThinFilmInfo,  IfPm3NfcBarcode, "Tag information"},
    {"list",    CmdHfThinFilmList,  AlwaysAvailable, "List NFC Barcode / Thinfilm history - not correct"},
    {"sim",     CmdHfThinFilmSim,   IfPm3NfcBarcode, "Fake Thinfilm tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFThinfilm(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
