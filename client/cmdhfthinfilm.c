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


// Printing function based upon the code in libnfc
// ref
//    https://github.com/nfc-tools/libnfc/blob/master/utils/nfc-barcode.c
static int print_barcode(uint8_t *barcode, const size_t barcode_len) {

    PrintAndLogEx(SUCCESS, "    Manufacturer : "_YELLOW_("%s") "[0x%02X]",  (barcode[0] == 0xB7) ? "Thinfilm" : "unknown", barcode[0] );
    PrintAndLogEx(SUCCESS, "     Data format : "_YELLOW_("%02X"), barcode[1]);

    uint8_t b1, b2;
    compute_crc(CRC_14443_A, barcode, barcode_len - 2, &b1, &b2);
    bool isok = (barcode[barcode_len - 1] == b1 && barcode[barcode_len - 2] == b2);
    
    PrintAndLogEx(SUCCESS, "        checksum : "_YELLOW_("%02X %02X")"- %s", b2, b1, (isok) ? _GREEN_("OK") : _RED_("fail"));
    PrintAndLogEx(SUCCESS, "        Raw data : "_YELLOW_("%s"),
             sprint_hex(barcode, barcode_len)
             );


    char s[45];
    memset(s, 0x00, sizeof(s));
    
    switch (barcode[1]) {
        case 0:
            printf("Data Format Field: Reserved for allocation by tag manufacturer\n");
            return PM3_SUCCESS;
        case 1:
            snprintf(s, sizeof(s), "http://www." );
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
            PrintAndLogEx(SUCCESS, "EPC: %s", sprint_hex(barcode + 2, 12) );
            return PM3_SUCCESS;
        default:
            PrintAndLogEx(SUCCESS, "Data Format Field: unknown (%02X)", barcode[1]);
            PrintAndLogEx(SUCCESS, "Data:" _YELLOW_("%s"), sprint_hex(barcode + 2, barcode_len - 2) );
            return PM3_SUCCESS;
    }
    
    snprintf(s + strlen(s), barcode_len - 3, (const char*)&barcode[2] , barcode_len - 4);

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

    return infoThinFilm();
}

int infoThinFilm(void) {
    
    clearCommandBuffer();    
    SendCommandNG(CMD_THINFILM_READ, NULL, 0);

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_THINFILM_READ, &resp, 1500)) {
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }
    
    if ( resp.status == PM3_SUCCESS ) {   
        print_barcode( resp.data.asBytes, resp.length );
    }

    return resp.status;
}

static int CmdHfThinFilmSim(const char *Cmd) {
    PrintAndLogEx(INFO, "To be implemented");
    return PM3_ENOTIMPL;
}

static int CmdHfThinFilmList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("14a");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"info",    CmdHfThinFilmInfo,  IfPm3Flash,      "Tag information"},
    {"list",    CmdHfThinFilmList,  AlwaysAvailable, "List ISO 14443A / Thinfilm history - not correct"},
    {"sim",     CmdHfThinFilmSim,   IfPm3Flash,      "Fake Thinfilm tag"},
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
