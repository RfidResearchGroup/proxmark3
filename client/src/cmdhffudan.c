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
// High frequency proximity cards from ISO14443A / Fudan commands
//-----------------------------------------------------------------------------

#include "cmdhffudan.h"

#include <stdio.h>
#include <string.h>
#include <ctype.h>
#include "cliparser.h"
#include "cmdparser.h"  // command_t
#include "comms.h"
#include "cmdhf14a.h"
#include "cmddata.h"
#include "mifare.h"     // xiso
#include "cmdhf.h"      //
#include "fileutils.h"  // saveFile
#include "ui.h"
#include "commonutil.h" // MemLeToUint2byte
#include "protocols.h"  // ISO14 defines
#include "crc16.h"      // compute_crc
#include "util_posix.h" // msclock

#define FUDAN_BLOCK_READ_RETRY 3
#define MAX_FUDAN_BLOCK_SIZE   4
#define MAX_FUDAN_05_BLOCKS    8 // 16
#define MAX_FUDAN_08_BLOCKS    64

#ifndef AddCrc14A
# define AddCrc14A(data, len) compute_crc(CRC_14443_A, (data), (len), (data)+(len), (data)+(len)+1)
#endif


// iceman:  these types are quite unsure.
typedef enum {
    FM11RF005M,
    FM11RF008M,
    FM11RF005SH,
    FM11RF08SH,
    FUDAN_NONE,
} fudan_type_t;

static void fudan_print_blocks(uint16_t n, uint8_t *d) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "----+-------------+-----------------");
    PrintAndLogEx(INFO, "blk | data        | ascii");
    PrintAndLogEx(INFO, "----+-------------+-----------------");
    for (uint16_t b = 0; b < n; b++) {
        PrintAndLogEx(INFO, "%3d | %s ", b, sprint_hex_ascii(d + (b * MAX_FUDAN_BLOCK_SIZE), MAX_FUDAN_BLOCK_SIZE));
    }
    PrintAndLogEx(INFO, "----+-------------+-----------------");
    PrintAndLogEx(NORMAL, "");
}

static char *GenerateFilename(iso14a_card_select_t *card, const char *prefix, const char *suffix) {
    if (card == NULL) {
        return NULL;
    }
    char *fptr = calloc(sizeof(char) * (strlen(prefix) + strlen(suffix)) + sizeof(card->uid) * 2 + 1,  sizeof(uint8_t));
    strcpy(fptr, prefix);
    FillFileNameByUID(fptr, card->uid, suffix, card->uidlen);
    return fptr;
}

static fudan_type_t fudan_detected(iso14a_card_select_t *card) {

    if ((card->sak & 0x0A) == 0x0A) {

        uint8_t atqa = MemLeToUint2byte(card->atqa);
        if ((atqa & 0x0003) == 0x0003) {
            // Uses Shanghai algo
            // printTag("FM11RF005SH (FUDAN Shanghai Metro)");
            return FM11RF005SH;
        } else if ((atqa & 0x0005) == 0x0005) {
            // printTag("FM11RF005M (FUDAN MIFARE Classic clone)");
            return FM11RF005M;
        } else if ((atqa & 0x0008) == 0x0008) {
            // printTag("FM11RF008M (FUDAN MIFARE Classic clone)");
            return FM11RF008M;
        }

    } else if ((card->sak & 0x53) == 0x53) {
        // printTag("FM11RF08SH (FUDAN)");
        return FM11RF08SH;
    }
    return FUDAN_NONE;
}

static int fudan_get_type(iso14a_card_select_t *card, bool verbose) {

    if (card == NULL) {
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ESOFT;
    }

    memcpy(card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        DropField();
        return PM3_ESOFT;
    }

    if (select_status == 3) {
        if (verbose) {
            PrintAndLogEx(INFO, "Card doesn't support standard iso14443-3 anticollision");
            PrintAndLogEx(SUCCESS, "ATQA: %02X %02X", card->atqa[1], card->atqa[0]);
        }
        DropField();
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card->uid, card->uidlen));
    if (verbose) {
        PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02X %02X"), card->atqa[1], card->atqa[0]);
        PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02X [%" PRIu64 "]"), card->sak, select_status);

        if (card->ats_len >= 3) { // a valid ATS consists of at least the length byte (TL) and 2 CRC bytes
            if (card->ats_len == card->ats[0] + 2)
                PrintAndLogEx(SUCCESS, " ATS: "  _GREEN_("%s"), sprint_hex(card->ats, card->ats[0]));
            else {
                PrintAndLogEx(SUCCESS, " ATS: [%d] "  _GREEN_("%s"), card->ats_len, sprint_hex(card->ats, card->ats_len));
            }
        }
    }
    return PM3_SUCCESS;
}

int read_fudan_uid(bool loop, bool verbose) {

    do {
        iso14a_card_select_t card;

        int res = fudan_get_type(&card, verbose);

        if (loop) {
            if (res != PM3_SUCCESS) {
                continue;
            }
        } else {
            switch (res) {
                case PM3_EFAILED:
                case PM3_EINVARG:
                    return res;
                case PM3_ETIMEOUT:
                    PrintAndLogEx(DEBUG, "command execution time out");
                    return res;
                case PM3_ESOFT:
                    PrintAndLogEx(DEBUG, "fudan card select failed");
                    return PM3_ESOFT;
                default:
                    break;
            }
        }


        if (loop) {
            res = handle_hf_plot();
            if (res != PM3_SUCCESS) {
                break;
            }
        }

        // decoding code
        if (loop == false) {
            PrintAndLogEx(NORMAL, "");
        }

    } while (loop && kbd_enter_pressed() == false);


    return PM3_SUCCESS;
}

static int CmdHFFudanReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fudan reader",
                  "Read a fudan tag",
                  "hf fudan reader\n"
                  "hf fudan reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "verbose output"),
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool cm = arg_get_lit(ctx, 2);

    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    read_fudan_uid(cm, verbose);

    DropField();
    return PM3_SUCCESS;
}

static int CmdHFFudanDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fudan dump",
                  "Dump FUDAN tag to binary file\n"
                  "If no <name> given, UID will be used as filename",
                  "hf fudan dump -f mydump        --> dump using filename\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of dump"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int datafnlen = 0;
    char dataFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)dataFilename, FILE_PATH_SIZE, &datafnlen);
    CLIParserFree(ctx);

    // Select card to get UID/UIDLEN/ATQA/SAK information
    // leaves the field on
    iso14a_card_select_t card;
    int res = fudan_get_type(&card, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to select a fudan card. Exiting...");
        DropField();
        return PM3_SUCCESS;
    }

    // validations
    fudan_type_t t = fudan_detected(&card);
    if (t == FUDAN_NONE) {
        PrintAndLogEx(FAILED, "failed to detect a fudan card. Exiting...");
        DropField();
        return PM3_SUCCESS;
    }

    // detect card size
    // 512b, 8kbits
    uint8_t num_blocks = MAX_FUDAN_05_BLOCKS;
    switch (t) {
        case FM11RF008M:
            num_blocks = MAX_FUDAN_08_BLOCKS;
            break;
        case FM11RF005SH:
        case FM11RF005M:
        case FM11RF08SH:
        case FUDAN_NONE:
        default:
            break;
    }

    uint8_t carddata[num_blocks * MAX_FUDAN_BLOCK_SIZE];

    //
    uint16_t flags = (ISO14A_NO_SELECT | ISO14A_NO_DISCONNECT | ISO14A_NO_RATS | ISO14A_RAW);
    uint32_t argtimeout = 0;
    uint32_t numbits = 0;

    PrintAndLogEx(SUCCESS, "." NOLF);
    // dump memory
    for (uint8_t b = 0; b < num_blocks; b++) {

        // read block
        uint8_t cmd[4] = {ISO14443A_CMD_READBLOCK, b, 0x00, 0x00};
        AddCrc14A(cmd, 2);

        for (uint8_t tries = 0; tries < FUDAN_BLOCK_READ_RETRY; tries++) {

            clearCommandBuffer();
            PacketResponseNG resp;
            SendCommandOLD(CMD_HF_ISO14443A_READER, flags, sizeof(cmd) | ((uint32_t)(numbits << 16)), argtimeout, cmd, sizeof(cmd));

            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
                if (resp.status == PM3_SUCCESS) {
                    uint8_t *data  = resp.data.asBytes;
                    memcpy(carddata + (b * MAX_FUDAN_BLOCK_SIZE), data, MAX_FUDAN_BLOCK_SIZE);
                    PrintAndLogEx(NORMAL, "." NOLF);
                    break;
                } else {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(FAILED, "could not read block %2d", b);
                }
            } else {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(WARNING, "command execute timeout when trying to read block %2d", b);
            }
        }

    }
    DropField();

    PrintAndLogEx(SUCCESS, "\nSucceeded in dumping all blocks");

    fudan_print_blocks(num_blocks, carddata);

    // create filename if none was given
    if (strlen(dataFilename) < 1) {
        char *fptr = GenerateFilename(&card, "hf-fudan-", "-dump");
        if (fptr == NULL)
            return PM3_ESOFT;

        strcpy(dataFilename, fptr);
        free(fptr);
    }

    saveFile(dataFilename, ".bin", (uint8_t *)carddata, sizeof(carddata));
    saveFileEML(dataFilename, (uint8_t *)carddata, sizeof(carddata), MAX_FUDAN_BLOCK_SIZE);

    iso14a_mf_extdump_t xdump;
    xdump.card_info = card;
    xdump.dump = (uint8_t *)carddata;
    xdump.dumplen = sizeof(carddata);
    saveFileJSON(dataFilename, jsfFudan, (uint8_t *)&xdump, sizeof(xdump), NULL);
    return PM3_SUCCESS;
}

static int CmdHFFudanWrBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fudan wrbl",
                  "Write fudan block with 4 hex bytes of data\n",
                  "hf fudan wrbl --blk 1 -k FFFFFFFFFFFF -d 01020304"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_str0("d", "data", "<hex>", "bytes to write, 4 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int b = arg_get_int_def(ctx, 1, 1);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 2, key, &keylen);

    uint8_t block[MAX_FUDAN_BLOCK_SIZE] = {0x00};
    int blen = 0;
    CLIGetHexWithReturn(ctx, 3, block, &blen);
    CLIParserFree(ctx);

    if (blen != MAX_FUDAN_BLOCK_SIZE) {
        PrintAndLogEx(WARNING, "block data must include 4 HEX bytes. Got %i", blen);
        return PM3_EINVARG;
    }

    if (b > 255) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Not implemented yet. Feel free to contribute!");

    /*

    uint8_t blockno = (uint8_t)b;

    PrintAndLogEx(INFO, "Writing block no %d, key %s", blockno, sprint_hex_inrow(key, sizeof(key)));
    PrintAndLogEx(INFO, "data: %s", sprint_hex(block, sizeof(block)));

    uint8_t data[26];
    memcpy(data, key, sizeof(key));
    memcpy(data + 10, block, sizeof(block));
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_WRITEBL, blockno, 0, 0, data, sizeof(data));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(FAILED, "Command execute timeout");
        return PM3_ETIMEOUT;
    }

    uint8_t isok  = resp.oldarg[0] & 0xff;
    if (isok) {
        PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
        PrintAndLogEx(HINT, "try `" _YELLOW_("hf fudan rdbl") "` to verify");
    } else {
        PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
    }
    */
    return PM3_SUCCESS;
}

static int CmdHFFudanRdBl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fudan rdbl",
                  "Read fudan block",
                  "hf fudan rdbl --blk 0 -k FFFFFFFFFFFF\n"
                  "hf fudan rdbl --blk 3 -v\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int b = arg_get_int_def(ctx, 1, 0);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 2, key, &keylen);
//    bool verbose = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (b > 255) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Not implemented yet. Feel free to contribute!");
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}


static int CmdHFFudanView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf fudan view",
                  "Print a FUDAN dump file (bin/eml/json)",
                  "hf fudan view -f hf-fudan-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "filename of dump"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, (MAX_FUDAN_BLOCK_SIZE * MAX_FUDAN_08_BLOCKS));
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint16_t block_cnt = MIN(MAX_FUDAN_05_BLOCKS, (bytes_read / MAX_FUDAN_BLOCK_SIZE));

    fudan_print_blocks(block_cnt, dump);

    free(dump);
    return PM3_SUCCESS;
}

static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable,  "This help"},
    {"reader",  CmdHFFudanReader,   IfPm3Iso14443a,   "Act like a fudan reader"},
    {"dump",    CmdHFFudanDump,     IfPm3Iso14443a,   "Dump FUDAN tag to binary file"},
    //{"sim",    CmdHFFudanSim,     IfPm3Iso14443a,   "Simulate a fudan tag"},
    {"rdbl",    CmdHFFudanRdBl,     IfPm3Iso14443a,   "Read a fudan tag"},
    {"view",    CmdHFFudanView,     AlwaysAvailable,  "Display content from tag dump file"},
    {"wrbl",    CmdHFFudanWrBl,     IfPm3Iso14443a,   "Write a fudan tag"},
    {NULL,      NULL,               0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFFudan(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
