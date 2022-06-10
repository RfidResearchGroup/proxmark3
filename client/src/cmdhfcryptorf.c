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
// High frequency CryptoRF commands (ISO14443B)
//-----------------------------------------------------------------------------

#include "cmdhfcryptorf.h"

#include <ctype.h>
#include "fileutils.h"

#include "cmdparser.h"    // command_t
#include "comms.h"        // clearCommandBuffer
#include "cmdtrace.h"
#include "crc16.h"
#include "protocols.h"    // definitions of ISO14B protocol
#include "iso14b.h"
#include "cliparser.h"    // cliparsing

#define TIMEOUT 2000

#ifndef CRYPTORF_MEM_SIZE
# define CRYPTORF_MEM_SIZE 1024
#endif

static int CmdHelp(const char *Cmd);

static iso14b_card_select_t last_known_card;
static void set_last_known_card(iso14b_card_select_t card) {
    last_known_card = card;
}

static int switch_off_field_cryptorf(void) {
    SetISODEPState(ISODEP_INACTIVE);
    iso14b_raw_cmd_t packet = {
        .flags = ISO14B_DISCONNECT,
        .timeout = 0,
        .rawlen = 0,
    };
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf cryptorf", "cryptorf");
}

static int CmdHFCryptoRFSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf sim",
                  "Simulate a CryptoRF tag\n"
                  _RED_("not implemented"),
                  "hf cryptorf sim");

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_CRYPTORF_SIM, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFSniff(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf sniff",
                  "Sniff the communication reader and tag",
                  "hf cryptorf sniff\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_SNIFF, NULL, 0);

    PrintAndLogEx(HINT, "Try `" _YELLOW_("hf cryptorf list") "` to view captured tracelog");
    PrintAndLogEx(HINT, "Try `" _YELLOW_("trace save -f hf_cryptorf_mytrace") "` to save tracelog for later analysing");
    return PM3_SUCCESS;
}

static bool get_14b_UID(iso14b_card_select_t *card) {

    if (card == NULL)
        return false;

    int8_t retry = 3;
    while (retry--) {

        iso14b_raw_cmd_t packet = {
            .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
            .timeout = 0,
            .rawlen = 0,
        };
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT)) {
            if (resp.oldarg[0] == 0) {
                memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
                return true;
            }
        }
    } // retry

    if (retry <= 0)
        PrintAndLogEx(FAILED, "command execution timeout");

    return false;
}

// Print extended information about tag.
static int infoHFCryptoRF(bool verbose) {
    iso14b_raw_cmd_t packet = {
        .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
        .timeout = 0,
        .rawlen = 0,
    };
    // 14b get and print UID only (general info)
    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, TIMEOUT) == false) {
        if (verbose) {
            PrintAndLogEx(WARNING, "command execution timeout");
        }
        switch_off_field_cryptorf();
        return false;
    }

    iso14b_card_select_t card;
    memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));

    uint64_t status = resp.oldarg[0];

    switch (status) {
        case 0:
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID    : %s", sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, " ATQB   : %s", sprint_hex(card.atqb, sizeof(card.atqb)));
            PrintAndLogEx(SUCCESS, " CHIPID : %02X", card.chipid);
            return PM3_SUCCESS;
        case 2:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 ATTRIB fail");
            break;
        case 3:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-3 CRC fail");
            break;
        default:
            if (verbose) PrintAndLogEx(FAILED, "ISO 14443-b card select failed");
            break;
    }
    return PM3_ESOFT;
}

static int CmdHFCryptoRFInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf info",
                  "Act as a CryptoRF reader.",
                  "hf cryptorf info");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    int res = infoHFCryptoRF(verbose);
    if (res != PM3_SUCCESS && verbose) {
        PrintAndLogEx(FAILED, "no CryptoRF / ISO14443-B tag found");
    }
    return res;
}

// get and print general info cryptoRF
int readHFCryptoRF(bool loop, bool verbose) {

    int res = PM3_ESOFT;
    do {
        iso14b_raw_cmd_t packet = {
            .flags = (ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT),
            .timeout = 0,
            .rawlen = 0,
        };
        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t));
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            uint8_t status = resp.oldarg[0] & 0xFF;

            if (loop) {
                if (status != 0) {
                    continue;
                }
            } else {
                // when not in continuous mode
                if (status != 0) {
                    if (verbose) PrintAndLogEx(WARNING, "cryptoRF / ISO14443-b card select failed");
                    res = PM3_EOPABORTED;
                    break;
                }
            }

            iso14b_card_select_t card;
            memcpy(&card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex_inrow(card.uid, card.uidlen));
            set_last_known_card(card);
        }
    } while (loop && kbd_enter_pressed() == false);

    DropField();
    return res;
}

static int CmdHFCryptoRFReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf reader",
                  "Act as a cryptoRF reader. Look for cryptoRF tags until Enter or the pm3 button is pressed",
                  "hf cryptorf reader -@   -> continuous reader mode"
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
    return readHFCryptoRF(cm, false);
}

// need to write to file
static int CmdHFCryptoRFDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf dump",
                  "Dump all memory from a CryptoRF tag (512/4096 bit size)",
                  "hf cryptorf dump\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename to save dump to"),
        arg_lit0(NULL, "64", "64byte / 512bit memory"),
        arg_lit0(NULL, "512", "512byte / 4096bit memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m64 = arg_get_lit(ctx, 2);
    bool m512 = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (m512 + m64 > 1) {
        PrintAndLogEx(INFO, "Select only one card memory size");
        return PM3_EINVARG;
    }

    uint16_t cardsize = 0;
    uint8_t blocks = 0;
    if (m64) {
        cardsize = (512 / 8) + 4;
        blocks = 0x0F;
    }
    if (m512) {
        cardsize = (4096 / 8) + 4;
        blocks = 0x7F;
    }

    iso14b_card_select_t card;
    if (get_14b_UID(&card) == false) {
        PrintAndLogEx(WARNING, "No tag found.");
        return PM3_SUCCESS;
    }

    // detect blocksize from card :)
    PrintAndLogEx(INFO, "Reading memory from tag UID " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));

    // select tag
    iso14b_raw_cmd_t *packet = (iso14b_raw_cmd_t *)calloc(1, sizeof(iso14b_raw_cmd_t) + 2);
    if (packet == NULL) {
        PrintAndLogEx(FAILED, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    packet->flags = (ISO14B_CONNECT | ISO14B_SELECT_SR);
    packet->timeout = 0;
    packet->rawlen = 0;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)packet, sizeof(iso14b_raw_cmd_t));
    PacketResponseNG resp;

    // select
    int status;
    if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {
        status = resp.oldarg[0];
        if (status < 0) {
            PrintAndLogEx(FAILED, "failed to select %" PRId64 "]", resp.oldarg[0]);
            free(packet);
            return switch_off_field_cryptorf();
        }
    }

    PrintAndLogEx(INFO, "." NOLF);

    uint8_t data[cardsize];
    memset(data, 0, sizeof(data));
    uint16_t blocknum = 0;

    for (int retry = 0; retry < 5; retry++) {

        // set up the read command
        packet->flags = (ISO14B_APPEND_CRC | ISO14B_RAW);
        packet->rawlen = 2;
        packet->raw[0] = ISO14443B_READ_BLK;
        packet->raw[1] = blocknum & 0xFF;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_ISO14443B_COMMAND, (uint8_t *)&packet, sizeof(iso14b_raw_cmd_t) + 2);
        if (WaitForResponseTimeout(CMD_HF_ISO14443B_COMMAND, &resp, 2000)) {

            status = resp.oldarg[0];
            if (status < 0) {
                PrintAndLogEx(FAILED, "retrying one more time");
                continue;
            }

            uint16_t len = (resp.oldarg[1] & 0xFFFF);
            uint8_t *recv = resp.data.asBytes;

            if (check_crc(CRC_14443_B, recv, len) == false) {
                PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                continue;
            }

            memcpy(data + (blocknum * 4), resp.data.asBytes, 4);

            // last read
            if (blocknum == 0xFF) {
                break;
            }

            retry = 0;
            blocknum++;
            if (blocknum > blocks) {
                // read config block
                blocknum = 0xFF;
            }

            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }
    }
    free(packet);

    PrintAndLogEx(NORMAL, "");

    if (blocknum != 0xFF) {
        PrintAndLogEx(FAILED, "dump failed");
        return switch_off_field_cryptorf();
    }

    PrintAndLogEx(INFO, "block#   | data         | ascii");
    PrintAndLogEx(INFO, "---------+--------------+----------");

    for (int i = 0; i <= blocks; i++) {
        PrintAndLogEx(INFO,
                      "%3d/0x%02X | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      sprint_ascii(data + (i * 4), 4)
                     );
    }
    PrintAndLogEx(INFO, "---------+--------------+----------");
    PrintAndLogEx(NORMAL, "");

    size_t datalen = (blocks + 1) * 4;

    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        char *fptr = filename + snprintf(filename, sizeof(filename), "hf-cryptorf-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }

    saveFileEML(filename, data, datalen, 4);
    saveFile(filename, ".bin", data, datalen);
    // json?
    return switch_off_field_cryptorf();
}

static int CmdHFCryptoRFELoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf eload",
                  "Loads CryptoRF tag dump into emulator memory on device",
                  "hf cryptorf eload -f hf-cryptorf-0102030405-dump.bin\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of dump"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (fnlen == 0) {
        PrintAndLogEx(ERR, "Error: Please specify a filename");
        return PM3_EINVARG;
    }

    size_t datalen = CRYPTORF_MEM_SIZE;
    // set up buffer
    uint8_t *data = calloc(datalen, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    if (loadFile_safe(filename, ".bin", (void **)&data, &datalen) != PM3_SUCCESS) {
        free(data);
        PrintAndLogEx(WARNING, "Error, reading file");
        return PM3_EFILE;
    }

    PrintAndLogEx(SUCCESS, "Uploading to emulator memory");

    uint32_t bytes_sent = 0;
    /*
    //Send to device
    uint32_t bytes_remaining  = bytes_read;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(PM3_CMD_DATA_SIZE, bytes_remaining);
        if (bytes_in_packet == bytes_remaining) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_CRYPTORF_EML_MEMSET, bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);
        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
    }
    */
    free(data);
    PrintAndLogEx(SUCCESS, "sent %d bytes of data to device emulator memory", bytes_sent);
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFESave(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf cryptorf esave",
                  "Save emulator memory to bin/eml/json file\n"
                  "if filename is not supplied, UID will be used.",
                  "hf cryptorf esave\n"
                  "hf cryptorf esave -f filename"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of dumpfile"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    size_t numofbytes = CRYPTORF_MEM_SIZE;

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (GetFromDevice(BIG_BUF_EML, data, numofbytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (fnlen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        char *fptr = filename + snprintf(filename, sizeof(filename), "hf-cryptorf-");
        FillFileNameByUID(fptr, data, "-dump", 4);
    }

    saveFile(filename, ".bin", data, numofbytes);
    //needs to change
    saveFileEML(filename, data, numofbytes, 8);
    //needs to change
    saveFileJSON(filename, jsfRaw, data, numofbytes, NULL);
    free(data);
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,              AlwaysAvailable, "This help"},
    {"dump",    CmdHFCryptoRFDump,    IfPm3Iso14443b,  "Read all memory pages of an CryptoRF tag, save to file"},
    {"info",    CmdHFCryptoRFInfo,    IfPm3Iso14443b,  "Tag information"},
    {"list",    CmdHFCryptoRFList,    AlwaysAvailable,  "List ISO 14443B history"},
    {"reader",  CmdHFCryptoRFReader,  IfPm3Iso14443b,  "Act as a CryptoRF reader to identify a tag"},
    {"sim",     CmdHFCryptoRFSim,     IfPm3Iso14443b,  "Fake CryptoRF tag"},
    {"sniff",   CmdHFCryptoRFSniff,   IfPm3Iso14443b,  "Eavesdrop CryptoRF"},
    {"eload",   CmdHFCryptoRFELoad,   AlwaysAvailable, "Load binary dump to emulator memory"},
    {"esave",   CmdHFCryptoRFESave,   AlwaysAvailable, "Save emulator memory to binary file"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFCryptoRF(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

