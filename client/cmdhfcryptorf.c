//-----------------------------------------------------------------------------
// Copyright (C) 2020 iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
#include "cmdhf14a.h"
#include "protocols.h"  // definitions of ISO14B protocol

#define TIMEOUT 2000
static int CmdHelp(const char *Cmd);

static int usage_hf_cryptorf_info(void) {
    PrintAndLogEx(NORMAL, "Usage: hf cryptorf info [h] [v]\n"
            "Options:\n"
            "    h    this help\n"
            "    v    verbose\n"
            "\n"
            "Example:\n"
            _YELLOW_("    hf cryptorf info")
            );
    return PM3_SUCCESS;
}
static int usage_hf_cryptorf_reader(void) {
    PrintAndLogEx(NORMAL, "Usage: hf cryptorf reader [h] [v]\n"
            "Options:\n"
            "    h    this help\n"
            "    v    verbose\n"
            "\n"
            "Example:\n"
            _YELLOW_("    hf cryptorf reader")
            );
    return PM3_SUCCESS;
}
static int usage_hf_cryptorf_sniff(void) {
    PrintAndLogEx(NORMAL, "It get data from the field and saves it into command buffer\n"
            "Buffer accessible from command " _YELLOW_("'hf list cryptorf'") "\n"
            "Usage: hf cryptorf sniff [h]\n"
            "Options:\n"
            "    h    this help\n"
            "\n"
            "Example:\n"
            _YELLOW_("    hf cryptorf sniff")
            );
    return PM3_SUCCESS;
}
static int usage_hf_cryptorf_sim(void) {
    PrintAndLogEx(NORMAL, "Emulating CryptoRF tag with 4 UID / PUPI\n"
            "Usage: hf cryptorf sim [h] [u <uid>]\n"
            "Options:\n"
            "    h    this help\n"
            "    u    4byte UID/PUPI\n"
            "\n"
            "Example:\n"
            _YELLOW_("    hf cryptorf sim")
            );
    return PM3_SUCCESS;
}
static int usage_hf_cryptorf_dump(void) {
    PrintAndLogEx(NORMAL, "This command dumps the contents of a ISO-14443-B tag and save it to file\n"
            "\n"
            "Usage: hf cryptorf dump [h] [card memory] <f filname> \n"
            "Options:\n"
            "    h         this help\n"
            "    f <name>  filename,  if no <name> UID will be used as filename\n"
            "\n"
            "Examples:\n"
            "\thf cryptorf dump\n"
            "\thf cryptorf dump f mydump");
    return PM3_SUCCESS;
}
static int usage_hf_cryptorf_eload(void) {
    PrintAndLogEx(NORMAL, "It loads a binary dump into emulator memory\n"
            "Usage:  hf cryptorf eload [f <file name w/o `.eml`>]\n"
            "Options:\n"
            "    h         this help\n"
            "    f <name>  filename,  if no <name> UID will be used as filename\n"
            "\n"
            "Examples:\n"
            _YELLOW_("        hf cryptorf eload f filename")
            );
    return PM3_SUCCESS;
}
static int usage_hf_cryptorf_esave(void) {
    PrintAndLogEx(NORMAL, "It saves bin/eml/json dump file of emulator memory\n"
            " Usage:  hf cryptorf esave [f <file name w/o `.eml`>]\n"
            "Options:\n"
            "    h         this help\n"
            "    f <name>  filename,  if no <name> UID will be used as filename\n"
            "\n"
            "Examples:\n"
            _YELLOW_("        hf cryptorf esave ")
            _YELLOW_("        hf cryptorf esave f filename")
            );
    return PM3_SUCCESS;
}

static int switch_off_field_cryptorf(void) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_DISCONNECT, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFList(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdTraceList("14b");
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFSim(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_cryptorf_sim();

    uint32_t pupi = 0;
    if (cmdp == 'u') {
        pupi = param_get32ex(Cmd, 1, 0, 16);
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_SIMULATE, pupi, 0, 0, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdHFCryptoRFSniff(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_cryptorf_sniff();

    clearCommandBuffer();
    SendCommandNG(CMD_HF_ISO14443B_SNIFF, NULL, 0);
    return PM3_SUCCESS;
}

static bool get_14b_UID(iso14b_card_select_t *card) {

    if (!card)
        return false;

    int8_t retry = 3;
    PacketResponseNG resp;

    // test for 14b SR
    while (retry--) {

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_SR | ISO14B_DISCONNECT, 0, 0, NULL, 0);
        if (WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {

            uint8_t status = resp.oldarg[0];
            if (status == 0) {
                memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
                return true;
            }
        }
    } // retry

    // test 14b standard
    retry = 3;
    while (retry--) {

        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0, NULL, 0);
        if (WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {

            uint8_t status = resp.oldarg[0];
            if (status == 0) {
                memcpy(card, (iso14b_card_select_t *)resp.data.asBytes, sizeof(iso14b_card_select_t));
                return true;
            }
        }
    } // retry

    if (retry <= 0)
        PrintAndLogEx(WARNING, "timeout while waiting for reply.");

    return false;
}

static int CmdHFCryptoRFInfo(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_cryptorf_info();

    bool verbose = (cmdp == 'v');

    int res = infoHFCryptoRF(verbose);
    if (res != PM3_SUCCESS && verbose) {
        PrintAndLogEx(FAILED, "no 14443-B tag found");
    }
    return res;
}

static int CmdHFCryptoRFReader(const char *Cmd) {
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf_cryptorf_reader();

    bool verbose = (cmdp == 'v');

    int res = readHFCryptoRF(verbose);
    if (res != PM3_SUCCESS && verbose) {
        PrintAndLogEx(FAILED, "no 14443-B tag found");
    }
    return res;
}

// need to write to file
static int CmdHFCryptoRFDump(const char *Cmd) {

    uint8_t fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    bool errors = false;
    uint8_t cmdp = 0, cardtype = 1;
    uint16_t cardsize = 0;
    uint8_t blocks = 0;
    iso14b_card_select_t card;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_hf_cryptorf_dump();
            case 'f':
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                cmdp += 2;
                break;
            default:
                if (cmdp == 0) {
                    cardtype = param_get8ex(Cmd, cmdp, 1, 10);
                    cmdp++;
                } else {
                    PrintAndLogEx(WARNING, "Unknown parameter '%c'\n", param_getchar(Cmd, cmdp));
                    errors = true;
                    break;
                }
        }
    }

    //Validations
    if (errors) return usage_hf_cryptorf_dump();

    switch (cardtype) {
        case 2:
            cardsize = (512 / 8) + 4;
            blocks = 0x0F;
            break;
        case 1:
        default:
            cardsize = (4096 / 8) + 4;
            blocks = 0x7F;
            break;
    }

    if (!get_14b_UID(&card)) {
        PrintAndLogEx(WARNING, "No tag found.");
        return PM3_SUCCESS;
    }

    if (fileNameLen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += sprintf(fptr, "hf-cryptorf-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }

    // detect blocksize from card :)
    PrintAndLogEx(NORMAL, "Reading memory from tag UID %s", sprint_hex(card.uid, card.uidlen));

    uint8_t data[cardsize];
    memset(data, 0, sizeof(data));

    int blocknum = 0;
    uint8_t *recv = NULL;

    PacketResponseNG resp;
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND,  ISO14B_CONNECT | ISO14B_SELECT_SR, 0, 0, NULL, 0);

    //select
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {
        if (resp.oldarg[0]) {
            PrintAndLogEx(INFO, "failed to select %" PRId64 " | %" PRId64, resp.oldarg[0], resp.oldarg[1]);
            goto out;
        }
    }

    uint8_t req[2] = {ISO14443B_READ_BLK};

    for (int retry = 0; retry < 5; retry++) {

        req[1] = blocknum;

        clearCommandBuffer();
        SendCommandOLD(CMD_HF_ISO14443B_COMMAND,  ISO14B_APPEND_CRC | ISO14B_RAW, 2, 0, req, sizeof(req));

        if (WaitForResponseTimeout(CMD_ACK, &resp, 2000)) {

            uint8_t status = resp.oldarg[0] & 0xFF;
            if (status > 0) {
                continue;
            }

            uint16_t len = (resp.oldarg[1] & 0xFFFF);
            recv = resp.data.asBytes;

            if (!check_crc(CRC_14443_B, recv, len)) {
                PrintAndLogEx(FAILED, "crc fail, retrying one more time");
                continue;
            }

            memcpy(data + (blocknum * 4), resp.data.asBytes, 4);

            if (blocknum == 0xFF) {
                //last read.
                break;
            }


            retry = 0;
            blocknum++;
            if (blocknum > blocks) {
                // read config block
                blocknum = 0xFF;
            }

            printf(".");
            fflush(stdout);
        }
    }

    if (blocknum != 0xFF) {
        PrintAndLogEx(NORMAL, "\n Dump failed");
        goto out;
    }

    PrintAndLogEx(NORMAL, "\n");
    PrintAndLogEx(NORMAL, "block#   | data         | ascii");
    PrintAndLogEx(NORMAL, "---------+--------------+----------");

    for (int i = 0; i <= blocks; i++) {
        PrintAndLogEx(NORMAL,
                      "%3d/0x%02X | %s | %s",
                      i,
                      i,
                      sprint_hex(data + (i * 4), 4),
                      sprint_ascii(data + (i * 4), 4)
                     );
    }

    PrintAndLogEx(NORMAL, "\n");


    size_t datalen = (blocks + 1) * 4;
    saveFileEML(filename, data, datalen, 4);
    saveFile(filename, ".bin", data, datalen);
out:
    return switch_off_field_cryptorf();
}

static int CmdHFCryptoRFELoad(const char *Cmd) {

    size_t datalen = 1024;
    int fileNameLen = 0;
    char filename[FILE_PATH_SIZE] = {0x00};
    bool errors = false;
    uint8_t cmdp = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h' :
                return usage_hf_cryptorf_eload();
            case 'f' :
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (!fileNameLen)
                    errors = true;
                if (fileNameLen > FILE_PATH_SIZE - 5)
                    fileNameLen = FILE_PATH_SIZE - 5;
                cmdp += 2;
                break;
            default :
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || strlen(Cmd) == 0) return usage_hf_cryptorf_eload();

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

/*
    // fast push mode
    conn.block_after_ACK = true;

    //Send to device
    uint32_t bytes_sent = 0;
    uint32_t bytes_remaining  = bytes_read;

    while (bytes_remaining > 0) {
        uint32_t bytes_in_packet = MIN(PM3_CMD_DATA_SIZE, bytes_remaining);
        if (bytes_in_packet == bytes_remaining) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();
        SendCommandOLD(CMD_HF_CRYPTORF_EML_MEMSET, bytes_sent, bytes_in_packet, 0, data + bytes_sent, bytes_in_packet);
        bytes_remaining -= bytes_in_packet;
        bytes_sent += bytes_in_packet;
    }
    free(data);
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Done");
*/  
  return PM3_SUCCESS;
}

static int CmdHFCryptoRFESave(const char *Cmd) {

    char filename[FILE_PATH_SIZE] = {0};
    char *fptr = filename;
    int fileNameLen = 0;
    size_t numofbytes = 1024;
    bool errors = false;
    uint8_t cmdp = 0;
    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h' :
                return usage_hf_cryptorf_esave();
            case 'f' :
                fileNameLen = param_getstr(Cmd, cmdp + 1, filename, FILE_PATH_SIZE);
                if (!fileNameLen)
                    errors = true;
                if (fileNameLen > FILE_PATH_SIZE - 5)
                    fileNameLen = FILE_PATH_SIZE - 5;
                cmdp += 2;
                break;
            default :
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }
    //Validations
    if (errors || strlen(Cmd) == 0) return usage_hf_cryptorf_esave();

    // set up buffer
    uint8_t *data = calloc(numofbytes, sizeof(uint8_t));
    if (!data) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    // download emulator memory
    PrintAndLogEx(SUCCESS, "Reading emulator memory...");
    if (!GetFromDevice(BIG_BUF_EML, data, numofbytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(data);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (fileNameLen < 1) {
        PrintAndLogEx(INFO, "Using UID as filename");
        fptr += sprintf(fptr, "hf-cryptorf-");
        FillFileNameByUID(fptr, data, "-dump", 4);
    }

    saveFile(filename, ".bin", data, numofbytes);
    //needs to change
    saveFileEML(filename, data, numofbytes, 8);
    //needs to change
    saveFileJSON(filename, jsfRaw, data, numofbytes);
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

// Print extented information about tag.  
int infoHFCryptoRF(bool verbose) {
    
     int res = PM3_ESOFT;

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "command execution timeout");
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
            res = PM3_SUCCESS;
            break;
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

    return res;
}

// get and print general info cryptoRF
int readHFCryptoRF(bool verbose) {

    int res = PM3_ESOFT;

    // 14b get and print UID only (general info)
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443B_COMMAND, ISO14B_CONNECT | ISO14B_SELECT_STD | ISO14B_DISCONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;

    if (!WaitForResponseTimeout(CMD_ACK, &resp, TIMEOUT)) {
        if (verbose) PrintAndLogEx(WARNING, "command execution timeout");
        return PM3_ETIMEOUT;
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
            res = PM3_SUCCESS;
            break;
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
    return res;
}
