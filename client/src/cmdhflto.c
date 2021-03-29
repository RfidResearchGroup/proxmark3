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
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "cmdtrace.h"
#include "crc16.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "protocols.h"
#include "fileutils.h"  //saveFile

/*
  iceman notes
  We can't dump LTO 5 or 6 tags yet since we don't have a datasheet.
  If you have access to datasheet,  le me know!

  LTO w Type info 00 01   has 101 blocks.
  LTO w Type info 00 02   has  95 blocks.
  LTO w Type info 00 03   has 255 blocks.
  LTO w Type info 00 xx   has NN blocks.
*/
#define CM_MEM_MAX_SIZE     0x1FE0  // (32byte/block * 255block = 8160byte)

static int CmdHelp(const char *Cmd);

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
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto info",
                  "Get info from LTO tags",
                  "hf lto info");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return infoLTO(true);
}

static const char *lto_print_size(uint8_t ti) {
    switch (ti) {
        case 1:
            return "101 blocks / 3232 bytes";
        case 2:
            return "95 blocks / 3040 bytes";
        case 3:
            return "255 blocks / 8160 bytes";
        default :
            return "unknown";
    }
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
        PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
        PrintAndLogEx(INFO, "UID......... " _YELLOW_("%s"), sprint_hex_inrow(serial_number, sizeof(serial_number)));
        PrintAndLogEx(INFO, "Type info... " _YELLOW_("%s"), sprint_hex_inrow(type_info, sizeof(type_info)));
        PrintAndLogEx(INFO, "Memory...... " _YELLOW_("%s"), lto_print_size(type_info[1]));
        if (type_info[1] > 3) {
            PrintAndLogEx(INFO, "Unknown LTO tag, report to @iceman!");
        }
    }

    return ret_val;
}

static int CmdHfLTOList(const char *Cmd) {
    char args[128] = {0};
    if (strlen(Cmd) == 0) {
        snprintf(args, sizeof(args), "-t lto");
    } else {
        strncpy(args, Cmd, sizeof(args) - 1);
    }
    return CmdTraceList(args);
}

static int lto_rdbl(uint8_t blk, uint8_t *block_response, uint8_t *block_cnt_response, bool verbose) {

    uint16_t resp_len = 18;
    uint8_t rdbl_cmd[] = {0x30, blk};
    uint8_t rdbl_cnt_cmd[] = {0x80};

    int status = lto_send_cmd_raw(rdbl_cmd, sizeof(rdbl_cmd), block_response, &resp_len, true, false, verbose);
    if (status == PM3_ETIMEOUT || status == PM3_ESOFT) {
        return PM3_EWRONGANSWER; // READ BLOCK failed
    }

    status = lto_send_cmd_raw(rdbl_cnt_cmd, sizeof(rdbl_cnt_cmd), block_cnt_response, &resp_len, false, false, verbose);
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
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto rdbl",
                  "Reead blocks from LTO tag",
                  "hf lto rdbl --first 0 --last 254");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "first", "<dec>", "The first block number to read as an integer"),
        arg_int0(NULL, "last", "<dec>", "The last block number to read as an integer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int startblock = arg_get_int_def(ctx, 1, 0);
    int endblock = arg_get_int_def(ctx, 2, 254);

    CLIParserFree(ctx);

    //Validations
    if (endblock < startblock) {
        PrintAndLogEx(ERR, "First block must be less than last block");
        return PM3_EINVARG;
    }

    return rdblLTO(startblock, endblock, true);
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
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto wrbl",
                  "Write data to block on LTO tag",
                  "hf lto wrbl --block 128 -d 0001020304050607080910111213141516171819202122232425262728293031");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "32 bytes of data to write (64 hex symbols, no spaces)"),
        arg_int1(NULL, "block", "<dec>", "The  block number to write to as an integer"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int block_data_len = 0;
    uint8_t block_data[32] = {0};

    CLIGetHexWithReturn(ctx, 1, block_data, &block_data_len);

    if (block_data_len != 32) {
        PrintAndLogEx(ERR, "Block data is incorrect length");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int blk = arg_get_int_def(ctx, 2, 0);

    CLIParserFree(ctx);

    int res = wrblLTO(blk, block_data, true);
    if (res == PM3_SUCCESS)
        PrintAndLogEx(HINT, "Try use 'hf lto rdbl' for verification");

    return res;
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
    // 0003 == 255 blocks x 32 = 8160 bytes
    // 0002 ==  95 blocks x 32 = 3040 bytes
    // 0001 == 101 blocks x 32 = 3232 bytes
    uint8_t blocks = 0xFF;
    if (type_info[1] == 0x01) {
        blocks = 0x65;
    } else if (type_info[1] == 0x02) {
        blocks = 0x5F;
    }
    PrintAndLogEx(SUCCESS, "Found LTO tag w " _YELLOW_("%s") " memory", lto_print_size(type_info[1]));

    uint8_t block_data_d00_d15[18];
    uint8_t block_data_d16_d31[18];

    for (uint8_t i = 0; i < blocks; i++) {

        ret_val = lto_rdbl(i, block_data_d00_d15,  block_data_d16_d31, verbose);

        if (ret_val == PM3_SUCCESS) {
            // remove CRCs
            memcpy(dump + i * 32, block_data_d00_d15, 16);
            memcpy(dump + (i * 32) + 16, block_data_d16_d31, 16);
        } else {
            lto_switch_off_field();
            return ret_val;
        }
        PrintAndLogEx(INPLACE, "...reading block %d", i);
        fflush(stdout);
    }

    lto_switch_off_field();
    return ret_val;
}

static int CmdHfLTODump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto dump",
                  "Dump data from LTO tag",
                  "hf lto dump -f myfile");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<filename>", "specify a filename for dumpfile"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    uint32_t dump_len = CM_MEM_MAX_SIZE;

    uint8_t *dump = calloc(dump_len, sizeof(uint8_t));
    if (!dump) {
        PrintAndLogEx(ERR, "error, cannot allocate memory");
        return PM3_EMALLOC;
    }

    int ret_val = dumpLTO(dump, true);
    PrintAndLogEx(NORMAL, "");
    if (ret_val != PM3_SUCCESS) {
        free(dump);
        return ret_val;
    }

    if (filename[0] == '\0') {
        char *fptr = filename;
        fptr += sprintf(fptr, "hf-lto-");
        FillFileNameByUID(fptr, dump, "-dump", 5);
    }
    saveFile(filename, ".bin", dump, dump_len);
    saveFileEML(filename, dump, dump_len, 32);

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

    uint8_t block_data[32] = {0};

    //Block address 0 and 1 are read-only
    for (uint8_t blk = 2; blk < 255; blk++) {

        memcpy(block_data, dump + (blk * 32), 32);

        ret_val = lto_wrbl(blk, block_data, verbose);

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
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf lto restore",
                  "Restore data from dumpfile to LTO tag",
                  "hf lto restore -f hf-lto-92C7842CFF.bin|.eml");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<filename>", "specify a filename for dumpfile"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    size_t dump_len = 0;
    char *lowstr = str_dup(filename);
    str_lower(lowstr);

    if (str_endswith(lowstr, ".bin")) {

        uint8_t *dump = NULL;
        if (loadFile_safe(filename, "", (void **)&dump, &dump_len) == PM3_SUCCESS) {
            restoreLTO(dump, true);
        }
        free(dump);

    } else if (str_endswith(lowstr, ".eml")) {

        uint8_t *dump = NULL;
        if (loadFileEML_safe(filename, (void **)&dump, &dump_len) == PM3_SUCCESS) {
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
