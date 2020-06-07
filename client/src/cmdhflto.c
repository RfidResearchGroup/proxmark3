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
#include "fileutils.h"  //saveFile

#define CM_MEM_MAX_SIZE     0x1FE0  // (32byte/block * 255block = 8160byte)

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

static int usage_lto_rdbl(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf lto rdbl [h] s <start block> e <end block>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h     this help");
    PrintAndLogEx(NORMAL, "           s     start block in decimal >= 0");
    PrintAndLogEx(NORMAL, "           e     end block in decimal <= 254");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf lto rdbl s 0 e 254 - Read data block from 0 to 254");
    return PM3_SUCCESS;
}

static int usage_lto_wrbl(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf lto wrbl [h] b <block> d <data>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h     this help");
    PrintAndLogEx(NORMAL, "           b     block address (decimal, 0 - 254) ");
    PrintAndLogEx(NORMAL, "           d     32 bytes of data to write (64 hex characters, no space)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf lto wrbl b 128 d 0001020304050607080910111213141516171819202122232425262728293031 - write 00..31 to block address 128");
    PrintAndLogEx(NORMAL, "           Use 'hf lto rdbl' for verification");
    return PM3_SUCCESS;
}

static int usage_lto_dump(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf lto dump [h|p] f <filename>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h     this help");
    PrintAndLogEx(NORMAL, "           f     file name");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf lto dump f myfile");
    return PM3_SUCCESS;
}

static int usage_lto_restore(void) {
    PrintAndLogEx(NORMAL, "Usage:  hf lto restore [h] f <filename>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "           h     this help");
    PrintAndLogEx(NORMAL, "           f     file name [.bin|.eml]");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "           hf lto restore f hf_lto_92C7842CFF.bin|.eml");
    return PM3_SUCCESS;
}

static void lto_switch_off_field(void) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, 0, 0, 0, NULL, 0);
}

static void lto_switch_on_field(void) {
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS, 0, 0, NULL, 0);
}

// send a raw LTO-CM command, returns the length of the response (0 in case of error)
static int lto_send_cmd_raw(uint8_t *cmd, uint8_t len, uint8_t *response, uint16_t *response_len, bool addcrc, bool is7bits, bool verbose) {

    uint64_t arg0 = ISO14A_RAW | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS;
    uint32_t arg1;

    if (addcrc) {
        arg0 |= ISO14A_APPEND_CRC;
    }

    if (is7bits) {
        arg1 = 7 << 16;
    } else {
        arg1 = 0;
    }

    arg1 |= len;

    SendCommandMIX(CMD_HF_ISO14443A_READER, arg0, arg1, 0, cmd, len);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        if (verbose) PrintAndLogEx(WARNING, "timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.oldarg[0] == *response_len) {
        *response_len = resp.oldarg[0];
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
static int lto_select(uint8_t *id_response, uint8_t id_len, uint8_t *type_response, bool verbose) {
    // Todo: implement anticollision

    uint8_t resp[] = {0, 0};
    uint16_t resp_len;
    uint8_t wupa_cmd[] = {LTO_REQ_STANDARD};
    uint8_t select_sn_cmd[] = {LTO_SELECT, 0x20};
    uint8_t select_cmd[] = {LTO_SELECT, 0x70, 0, 0, 0, 0, 0};

    resp_len = 2;
    int status = lto_send_cmd_raw(wupa_cmd, sizeof(wupa_cmd), type_response, &resp_len, false, true, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_ESOFT; // WUPA failed
    }

    resp_len = id_len;
    status = lto_send_cmd_raw(select_sn_cmd, sizeof(select_sn_cmd), id_response, &resp_len, false, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // REQUEST SERIAL NUMBER failed
    }

    memcpy(select_cmd + 2, id_response, sizeof(select_cmd) - 2);
    resp_len = 1;
    status = lto_send_cmd_raw(select_cmd, sizeof(select_cmd), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // SELECT failed
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
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];

    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);
    lto_switch_off_field();

    if (ret_val == PM3_SUCCESS) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "UID: " _YELLOW_("%s"), sprint_hex_inrow(serial_number, sizeof(serial_number)));
        PrintAndLogEx(SUCCESS, "TYPE INFO: " _YELLOW_("%s"), sprint_hex_inrow(type_info, sizeof(type_info)));
    }

    return ret_val;
}

static int CmdHfLTOList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("lto");
    return PM3_SUCCESS;
}

static int lto_rdbl(uint8_t blk, uint8_t *block_responce, uint8_t *block_cnt_responce, bool verbose) {

    uint16_t resp_len = 18;
    uint8_t rdbl_cmd[] = {0x30, blk};
    uint8_t rdbl_cnt_cmd[] = {0x80};

    int status = lto_send_cmd_raw(rdbl_cmd, sizeof(rdbl_cmd), block_responce, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK failed
    }

    status = lto_send_cmd_raw(rdbl_cnt_cmd, sizeof(rdbl_cnt_cmd), block_cnt_responce, &resp_len, false, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK CONTINUE failed
    }

    return PM3_SUCCESS;
}

int rdblLTO(uint8_t st_blk, uint8_t end_blk, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    uint8_t block_data_d00_d15[18];
    uint8_t block_data_d16_d31[18];
    uint8_t block_data[32];

    for (uint8_t i = st_blk; i < end_blk + 1; i++) {

        ret_val = lto_rdbl(i, block_data_d00_d15,  block_data_d16_d31, verbose);

        if (ret_val == PM3_SUCCESS) {
            //Remove CRCs
            for (int t = 0; t < 16; t++) {
                block_data[t] = block_data_d00_d15[t];
                block_data[t + 16] = block_data_d16_d31[t];
            }

            PrintAndLogEx(SUCCESS, "BLK %03d: " _YELLOW_("%s"), i, sprint_hex_inrow(block_data, sizeof(block_data)));
        } else {
            lto_switch_off_field();
            return ret_val;
        }
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTOReadBlock(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    uint8_t st_blk = 0;
    uint8_t end_blk = 254;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lto_rdbl();
            case 's':
                st_blk = param_get8(Cmd, cmdp + 1);
                if (end_blk < st_blk) {
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;

            case 'e':
                end_blk = param_get8(Cmd, cmdp + 1);
                if (end_blk < st_blk) {
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;

            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        usage_lto_rdbl();
        return PM3_EINVARG;
    }

    return rdblLTO(st_blk, end_blk, true);
}

static int lto_wrbl(uint8_t blk, uint8_t *data, bool verbose) {

    uint8_t resp[] = {0, 0};
    uint16_t resp_len = 1;
    uint8_t wrbl_cmd[] = {0xA0, blk};
    uint8_t wrbl_d00_d15[16];
    uint8_t wrbl_d16_d31[16];

    for (int i = 0; i < 16; i++) {
        wrbl_d00_d15[i] = data[i];
        wrbl_d16_d31[i] = data[i + 16];
    }

    int status = lto_send_cmd_raw(wrbl_cmd, sizeof(wrbl_cmd), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // WRITE BLOCK failed
    }

    status = lto_send_cmd_raw(wrbl_d00_d15, sizeof(wrbl_d00_d15), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // WRITE BLOCK failed
    }

    status = lto_send_cmd_raw(wrbl_d16_d31, sizeof(wrbl_d16_d31), resp, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT || resp[0] != 0x0A) {
        return PM3_EWRONGANSWER; // WRITE BLOCK failed
    }

    return PM3_SUCCESS;
}

int wrblLTO(uint8_t blk, uint8_t *data, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    ret_val = lto_wrbl(blk, data, verbose);
    lto_switch_off_field();

    if (ret_val == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "BLK %03d: " _YELLOW_("write success"), blk);
    } else {
        PrintAndLogEx(WARNING, "BLK %03d: write error. Maybe this is a read-only block address.",  blk);
    }

    return ret_val;
}

static int CmdHfLTOWriteBlock(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    bool b_opt_selected = false;
    bool d_opt_selected = false;
    uint8_t blk = 128;
    uint8_t blkData[32] = {0};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lto_wrbl();
            case 'b':
                blk = param_get8(Cmd, cmdp + 1);
                b_opt_selected = true;
                cmdp += 2;
                break;
            case 'd':
                if (param_gethex(Cmd, cmdp + 1, blkData, 64)) {
                    PrintAndLogEx(WARNING, "block data must include 64 HEX symbols");
                    errors = true;
                    break;
                }
                d_opt_selected = true;
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        usage_lto_wrbl();
        return PM3_EINVARG;
    } else if (b_opt_selected == false || d_opt_selected == false) {
        PrintAndLogEx(WARNING, "Need to specify block address and data. See usage, h option");
        return PM3_EINVARG;
    }

    return wrblLTO(blk, blkData, true);
}

int dumpLTO(uint8_t *dump, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    uint8_t type_info[2];
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    uint8_t block_data_d00_d15[18];
    uint8_t block_data_d16_d31[18];

    for (uint8_t i = 0; i < 255; i++) {

        ret_val = lto_rdbl(i, block_data_d00_d15,  block_data_d16_d31, verbose);

        if (ret_val == PM3_SUCCESS) {
            //Remove CRCs
            for (int t = 0; t < 16; t++) {
                dump[t + i * 32] = block_data_d00_d15[t];
                dump[t + i * 32 + 16] = block_data_d16_d31[t];
            }
        } else {
            lto_switch_off_field();
            return ret_val;
        }
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTODump(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    uint32_t dump_len = CM_MEM_MAX_SIZE;
    char filename[FILE_PATH_SIZE] = {0};
    char serial_number[10] = {0};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lto_dump();
            case 'f':
                if (param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE) >= FILE_PATH_SIZE) {
                    PrintAndLogEx(FAILED, "filename too long");
                    errors = true;
                    break;
                }
                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    //Validations
    if (errors) {
        usage_lto_dump();
        return PM3_EINVARG;
    }

    // alloc memory
    uint8_t *dump = calloc(dump_len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory");
        return PM3_EMALLOC;
    }

    // loop all blocks
    int ret_val = dumpLTO(dump, true);
    if (ret_val != PM3_SUCCESS) {
        free(dump);
        return ret_val;
    }

    // save to file
    if (filename[0] == '\0') {
        memcpy(serial_number, sprint_hex_inrow(dump, sizeof(serial_number)), sizeof(serial_number));
        char tmp_name[17] = "hf_lto_";
        strcat(tmp_name, serial_number);
        memcpy(filename, tmp_name, sizeof(tmp_name));
    }
    saveFile(filename, ".bin", dump, dump_len);
    saveFileEML(filename, dump, dump_len, 32);

    // free memory
    free(dump);

    return PM3_SUCCESS;
}

int restoreLTO(uint8_t *dump, bool verbose) {

    clearCommandBuffer();
    lto_switch_on_field();

    uint8_t type_info[2];
    uint8_t serial_number[5];
    uint8_t serial_len = sizeof(serial_number);
    int ret_val = lto_select(serial_number, serial_len, type_info, verbose);

    if (ret_val != PM3_SUCCESS) {
        lto_switch_off_field();
        return ret_val;
    }

    uint8_t blkData[32] = {0};

    //Block address 0 and 1 are read-only
    for (uint8_t blk = 2; blk < 255; blk++) {

        for (int i = 0; i < 32; i++) {
            blkData[i] = dump[i + blk * 32];
        }

        ret_val = lto_wrbl(blk, blkData, verbose);

        if (ret_val == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Block %03d - " _YELLOW_("write success"), blk);
        } else {
            lto_switch_off_field();
            return ret_val;
        }
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTRestore(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    char filename[FILE_PATH_SIZE] = {0};

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lto_restore();
            case 'f':
                param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (strlen(filename) < 5)
                    errors = true;

                cmdp += 2;
                break;
            default:
                PrintAndLogEx(WARNING, "unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || strlen(Cmd) == 0 ) {
        return usage_lto_restore();
    }

    size_t dump_len = 0;
    char *lowstr = str_dup(filename);
    str_lower(lowstr);

    if (str_endswith(lowstr, ".bin")) {

        uint8_t *dump = NULL;
        if (loadFile_safe(filename, "", (void**)&dump, &dump_len) == PM3_SUCCESS) {
            restoreLTO(dump, true);
        }
        free(dump);

    } else if (str_endswith(lowstr, ".eml")) {

        uint8_t *dump = NULL;
        if (loadFileEML_safe(filename, (void**)&dump, &dump_len) == PM3_SUCCESS) {
            restoreLTO(dump, true);
        }
        free(dump);

    } else {
        PrintAndLogEx(WARNING, "Warning: invalid dump filename " _YELLOW_("%s") " to restore", filename);
    }
    free(lowstr);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,             AlwaysAvailable, "This help"},
    {"dump",     CmdHfLTODump,        IfPm3Iso14443a, "Dump LTO-CM tag to file"},
    {"restore",  CmdHfLTRestore,      IfPm3Iso14443a, "Restore dump file to LTO-CM tag"},
    {"info",     CmdHfLTOInfo,        IfPm3Iso14443a, "Tag information"},
    {"rdbl",     CmdHfLTOReadBlock,   IfPm3Iso14443a, "Read block"},
    {"wrbl",     CmdHfLTOWriteBlock,  IfPm3Iso14443a, "Write block"},
    {"list",     CmdHfLTOList,        AlwaysAvailable, "List LTO-CM history"},
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
