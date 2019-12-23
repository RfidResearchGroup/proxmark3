//-----------------------------------------------------------------------------
// Copyright (C) 2019 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// LTO-CM commands
// LTO Cartridge memory
//-----------------------------------------------------------------------------
#include "cmdhflto.h"
#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include <inttypes.h>
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "protocols.h"

static int CmdHelp(const char *Cmd);

static int usage_lto_info(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf lto info [h]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h    this help");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf lto info");
    return PM3_SUCCESS;
}

static void lto_switch_off_field(void) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, 0, 0, 0, NULL, 0);
}

static void lto_switch_on_field(void) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

// send a raw LTO-CM command, returns the length of the response (0 in case of error)
static int lto_send_cmd_raw(uint8_t *cmd, uint8_t len, uint8_t *response, uint16_t *response_len, bool verbose) {

    SendCommandOLD(CMD_HF_ISO14443A_READER, ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, len, 0, cmd, len);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] == *response_len) {
        *response_len = resp.oldarg[0];

        PrintAndLogEx(INFO, "%s", sprint_hex(resp.data.asBytes, *response_len));
        if (*response_len > 0) {
            memcpy(response, resp.data.asBytes, *response_len);
        }
    } else {
        if (verbose) PrintAndLogEx(WARNING, "Wrong response length (%d != %" PRIu64 ")", *response_len, resp.oldarg[0]);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}


// select a LTO-CM tag. Send WUPA and RID.
static int lto_select(uint8_t *id_response, uint8_t id_len, bool verbose) {
    // Todo: implement anticollision

    uint8_t resp[] = {0, 0};
    uint16_t resp_len;
    uint8_t wupa_cmd[] = {LTO_REQ_STANDARD};
    uint8_t select_cmd[] = {LTO_SELECT, 0x20};
    uint8_t select_1_cmd[] = {LTO_SELECT_1, 0x70, 0, 0, 0, 0, 0};

    lto_switch_on_field();

    resp_len = 2;
    int status = lto_send_cmd_raw(wupa_cmd, sizeof(wupa_cmd), resp, &resp_len, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        lto_switch_off_field();
        return PM3_ESOFT; // WUPA failed
    }

    resp_len = id_len;
    status = lto_send_cmd_raw(select_cmd, sizeof(select_cmd), id_response, &resp_len, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        lto_switch_off_field();
        return PM3_EWRONGANSVER; // SELECT failed
    }

    resp_len = 1;
    status = lto_send_cmd_raw(select_1_cmd, sizeof(select_1_cmd), resp, &resp_len, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        lto_switch_off_field();
        return PM3_EWRONGANSVER; // SELECT failed
    }

    // tag is now INIT and SELECTED.
    return PM3_SUCCESS;
}


static int CmdHfLTOInfo(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lto_info();
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        usage_lto_info();
        return PM3_EINVARG;
    }

    return infoLTO(true);
}

int infoLTO(bool verbose) {

    clearCommandBuffer();

    uint8_t serial_number[5];
    uint8_t serial_len = 0;

    int ret_val = lto_select(serial_number, serial_len, verbose);

    lto_switch_off_field();
    /*

    --    "hf 14a raw -a -p -b 7 45"
    --    "hf 14a raw -c -p 9320"
    --    "hf 14a raw -c -p 9370%s", serial_number
    --    "disconnect"


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
    */
    return ret_val;
}

static int CmdHfLTOList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("14a");
//    CmdTraceList("lto");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,             AlwaysAvailable, "This help"},
    {"info",    CmdHfLTOInfo,        IfPm3Iso14443a, "Tag information"},
//    {"rdbl",    CmdHfLTOReadBlock,   IfPm3Iso14443a, "Read block"},
//    {"wrbl",    CmdHfLTOWriteBlock,  IfPm3Iso14443a, "Write block"},
//    {"sim",     CmdHfLTOSim,         IfPm3Iso14443a, "<uid> Simulate LTO-CM tag"},
    {"list",    CmdHfLTOList,        AlwaysAvailable, "List LTO-CM history"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFLTO(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

