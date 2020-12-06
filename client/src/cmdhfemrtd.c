//-----------------------------------------------------------------------------
// Copyright (C) 2020 A. Ozkal
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency Electronic Machine Readable Travel Document commands
//-----------------------------------------------------------------------------

#include "cmdhfemrtd.h"
#include <ctype.h>
#include "fileutils.h"
#include "cmdparser.h"     // command_t
#include "comms.h"         // clearCommandBuffer
#include "cmdtrace.h"
#include "cliparser.h"
#include "crc16.h"
#include "cmdhf14a.h"
#include "protocols.h"     // definitions of ISO14A/7816 protocol
#include "emv/apduinfo.h"  // GetAPDUCodeDescription

#define TIMEOUT 2000

// ISO7816 commands
#define SELECT "A4"
#define GET_CHALLENGE "84"
#define READ_BINARY "B0"
#define P1_SELECT_BY_EF "02"
#define P1_SELECT_BY_NAME "04"
#define P2_PROPRIETARY "0C"

// File IDs
#define EF_CARDACCESS "011C"
#define EF_COM "011E"
#define EF_DG1 "0101"

// App IDs
#define AID_MRTD "A0000002471001"

static int CmdHelp(const char *Cmd);

static uint16_t get_sw(uint8_t *d, uint8_t n) {
    if (n < 2)
        return 0;

    n -= 2;
    return d[n] * 0x0100 + d[n + 1];
}

static int select_aid(const char *select_by, const char *file_id) {
    bool activate_field = true;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    size_t file_id_len = strlen(file_id) / 2;

    char cmd[50];
    sprintf(cmd, "00%s%s0C%02lu%s", SELECT, select_by, file_id_len, file_id);
    PrintAndLogEx(INFO, "Sending: %s", cmd);

    uint8_t aSELECT_AID[80];
    int aSELECT_AID_n = 0;
    param_gethex_to_eol(cmd, 0, aSELECT_AID, sizeof(aSELECT_AID), &aSELECT_AID_n);
    int res = ExchangeAPDU14a(aSELECT_AID, aSELECT_AID_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res) {
        DropField();
        return false;
    }

    if (resplen < 2) {
        DropField();
        return false;
    }
    PrintAndLogEx(INFO, "Response: %s", sprint_hex(response, resplen));

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Selecting Card Access aid failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return false;
    }
    return true;
}

static int asn1datalength(uint8_t *datain, int datainlen) {
    char* dataintext = sprint_hex_inrow(datain, datainlen);

    // lazy - https://stackoverflow.com/a/4214350/3286892
    char subbuff[8];
    memcpy(subbuff, &dataintext[2], 2);
    subbuff[2] = '\0';

    int thing = (int)strtol(subbuff, NULL, 16);
    if (thing <= 0x7f) {
        return thing;
    } else if (thing == 0x81) {
        memcpy(subbuff, &dataintext[2], 3);
        subbuff[3] = '\0';
        return (int)strtol(subbuff, NULL, 16);
    } else if (thing == 0x82) {
        memcpy(subbuff, &dataintext[2], 5);
        subbuff[5] = '\0';
        return (int)strtol(subbuff, NULL, 16);
    } else if (thing == 0x83) {
        memcpy(subbuff, &dataintext[2], 7);
        subbuff[7] = '\0';
        return (int)strtol(subbuff, NULL, 16);
    }
    return false;
}

static int asn1fieldlength(uint8_t *datain, int datainlen) {
    char* dataintext = sprint_hex_inrow(datain, datainlen);

    // lazy - https://stackoverflow.com/a/4214350/3286892
    char subbuff[8];
    memcpy(subbuff, &dataintext[2], 2);
    subbuff[2] = '\0';

    int thing = (int)strtol(subbuff, NULL, 16);
    if (thing <= 0x7f) {
        return 2;
    } else if (thing == 0x81) {
        return 4;
    } else if (thing == 0x82) {
        return 6;
    } else if (thing == 0x83) {
        return 8;
    }
    return false;
}

static int _read_binary(int offset, int bytes_to_read, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    bool activate_field = false;
    bool keep_field_on = true;
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;

    char cmd[50];
    sprintf(cmd, "00%s%04i%02i", READ_BINARY, offset, bytes_to_read);
    PrintAndLogEx(INFO, "Sending: %s", cmd);

    uint8_t aREAD_BINARY[80];
    int aREAD_BINARY_n = 0;
    param_gethex_to_eol(cmd, 0, aREAD_BINARY, sizeof(aREAD_BINARY), &aREAD_BINARY_n);
    int res = ExchangeAPDU14a(aREAD_BINARY, aREAD_BINARY_n, activate_field, keep_field_on, response, sizeof(response), &resplen);
    if (res) {
        DropField();
        return false;
    }
    PrintAndLogEx(INFO, "Response: %s", sprint_hex(response, resplen));

    // drop sw
    memcpy(dataout, &response, resplen - 2);
    *dataoutlen = (resplen - 2);

    uint16_t sw = get_sw(response, resplen);
    if (sw != 0x9000) {
        PrintAndLogEx(ERR, "Reading binary failed (%04x - %s).", sw, GetAPDUCodeDescription(sw >> 8, sw & 0xff));
        DropField();
        return false;
    }
    return true;
}

static int read_file(uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t response[PM3_CMD_DATA_SIZE];
    int resplen = 0;
    uint8_t tempresponse[PM3_CMD_DATA_SIZE];
    int tempresplen = 0;

    if (!_read_binary(0, 4, response, sizeof(response), &resplen)) {
        return false;
    }

    int datalen = asn1datalength(response, resplen);
    int readlen = datalen - (3 - asn1fieldlength(response, resplen) / 2);
    int offset = 4;
    int toread;

    while (readlen > 0) {
        toread = readlen;
        if (readlen > 118) {
            toread = 118;
        }

        if (!_read_binary(offset, toread, tempresponse, sizeof(tempresponse), &tempresplen)) {
            return false;
        }

        memcpy(&response[resplen], &tempresponse, tempresplen);
        offset += toread;
        readlen -= toread;
        resplen += tempresplen;
    }

    memcpy(dataout, &response, resplen);
    *dataoutlen = resplen;
    return true;
}

int infoHF_EMRTD(void) {
    // const uint8_t *data
    if (select_aid(P1_SELECT_BY_EF, EF_CARDACCESS)) {
        uint8_t response[PM3_CMD_DATA_SIZE];
        int resplen = 0;

        read_file(response, sizeof(response), &resplen);

        PrintAndLogEx(INFO, "EF_CardAccess: %s", sprint_hex(response, resplen));
    } else {
        PrintAndLogEx(INFO, "PACE unsupported. Will not read EF_CardAccess.");
    }

    DropField();
    return PM3_SUCCESS;
}

static int cmd_hf_emrtd_info(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf emrtd info",
                  "Get info about an eMRTD",
                  "hf emrtd info"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoHF_EMRTD();
}

static int cmd_hf_emrtd_list(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t 7816");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,           AlwaysAvailable, "This help"},
    {"info",    cmd_hf_emrtd_info, IfPm3Iso14443a,  "Tag information"},
    {"list",    cmd_hf_emrtd_list, AlwaysAvailable, "List ISO 14443A/7816 history"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFeMRTD(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
