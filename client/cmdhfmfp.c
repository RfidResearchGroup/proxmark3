//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
// Copyright (C) 2018 drHatson
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// High frequency MIFARE  Plus commands
//-----------------------------------------------------------------------------

#include "cmdhfmfp.h"

#include <string.h>

#include "cmdparser.h"    // command_t
#include "commonutil.h"  // ARRAYLEN

#include "comms.h"
#include "ui.h"
#include "cmdhf14a.h"
#include "mifare/mifare4.h"
#include "mifare/mad.h"
#include "mifare/ndef.h"
#include "cliparser/cliparser.h"
#include "emv/dump.h"
#include "mifare/mifaredefault.h"
#include "util_posix.h"
#include "fileutils.h"

static const uint8_t DefaultKey[16] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

uint16_t CardAddresses[] = {0x9000, 0x9001, 0x9002, 0x9003, 0x9004, 0xA000, 0xA001, 0xA080, 0xA081, 0xC000, 0xC001};

static int CmdHelp(const char *Cmd);

static int CmdHFMFPInfo(const char *Cmd) {

    if (Cmd && strlen(Cmd) > 0)
        PrintAndLogEx(WARNING, "command don't have any parameters.\n");

    // info about 14a part
    infoHF14A(false, false, false);

    // Mifare Plus info
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_NO_DISCONNECT, 0, 0, NULL, 0);

    PacketResponseNG resp;
    WaitForResponse(CMD_ACK, &resp);

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision

    if (select_status == 1 || select_status == 2) {
        PrintAndLogEx(NORMAL, "----------------------------------------------");
        PrintAndLogEx(NORMAL, "Mifare Plus info:");

        // MIFARE Type Identification Procedure
        // https://www.nxp.com/docs/en/application-note/AN10833.pdf
        uint16_t ATQA = card.atqa[0] + (card.atqa[1] << 8);
        if (ATQA == 0x0004) PrintAndLogEx(INFO, "ATQA: Mifare Plus 2k 4bUID");
        if (ATQA == 0x0002) PrintAndLogEx(INFO, "ATQA: Mifare Plus 4k 4bUID");
        if (ATQA == 0x0044) PrintAndLogEx(INFO, "ATQA: Mifare Plus 2k 7bUID");
        if (ATQA == 0x0042) PrintAndLogEx(INFO, "ATQA: Mifare Plus 4k 7bUID");

        uint8_t SLmode = 0xff;
        if (card.sak == 0x08) {
            PrintAndLogEx(INFO, "SAK: Mifare Plus 2k 7bUID");
            if (select_status == 2) SLmode = 1;
        }
        if (card.sak == 0x18) {
            PrintAndLogEx(INFO, "SAK: Mifare Plus 4k 7bUID");
            if (select_status == 2) SLmode = 1;
        }
        if (card.sak == 0x10) {
            PrintAndLogEx(INFO, "SAK: Mifare Plus 2k");
            if (select_status == 2) SLmode = 2;
        }
        if (card.sak == 0x11) {
            PrintAndLogEx(INFO, "SAK: Mifare Plus 4k");
            if (select_status == 2) SLmode = 2;
        }
        if (card.sak == 0x20) {
            PrintAndLogEx(INFO, "SAK: Mifare Plus SL0/SL3 or Mifare desfire");
            if (card.ats_len > 0) {
                SLmode = 3;

                // check SL0
                uint8_t data[250] = {0};
                int datalen = 0;
                // https://github.com/Proxmark/proxmark3/blob/master/client/luascripts/mifarePlus.lua#L161
                uint8_t cmd[3 + 16] = {0xa8, 0x90, 0x90, 0x00};
                int res = ExchangeRAW14a(cmd, sizeof(cmd), false, false, data, sizeof(data), &datalen, false);
                if (!res && datalen > 1 && data[0] == 0x09) {
                    SLmode = 0;
                }
            }
        }

        if (SLmode != 0xff)
            PrintAndLogEx(INFO, "Mifare Plus SL mode: SL%d", SLmode);
        else
            PrintAndLogEx(WARNING, "Mifare Plus SL mode: unknown(");
    } else {
        PrintAndLogEx(INFO, "Mifare Plus info not available.");
    }

    DropField();

    return PM3_SUCCESS;
}

static int CmdHFMFPWritePerso(const char *Cmd) {
    uint8_t keyNum[64] = {0};
    int keyNumLen = 0;
    uint8_t key[64] = {0};
    int keyLen = 0;

    CLIParserInit("hf mfp wrp",
                  "Executes Write Perso command. Can be used in SL0 mode only.",
                  "Usage:\n\thf mfp wrp 4000 000102030405060708090a0b0c0d0e0f -> write key (00..0f) to key number 4000 \n"
                  "\thf mfp wrp 4000 -> write default key(0xff..0xff) to key number 4000");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose", "show internal data."),
        arg_str1(NULL,  NULL,      "<HEX key number (2b)>", NULL),
        arg_strx0(NULL,  NULL,     "<HEX key (16b)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    CLIGetHexWithReturn(2, keyNum, &keyNumLen);
    CLIGetHexWithReturn(3, key, &keyLen);
    CLIParserFree();

    mfpSetVerboseMode(verbose);

    if (!keyLen) {
        memmove(key, DefaultKey, 16);
        keyLen = 16;
    }

    if (keyNumLen != 2) {
        PrintAndLogEx(ERR, "Key number length must be 2 bytes instead of: %d", keyNumLen);
        return 1;
    }
    if (keyLen != 16) {
        PrintAndLogEx(ERR, "Key length must be 16 bytes instead of: %d", keyLen);
        return 1;
    }

    uint8_t data[250] = {0};
    int datalen = 0;

    int res = MFPWritePerso(keyNum, key, true, false, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "Exchange error: %d", res);
        return res;
    }

    if (datalen != 3) {
        PrintAndLogEx(ERR, "Command must return 3 bytes instead of: %d", datalen);
        return 1;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "Command error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return 1;
    }
    PrintAndLogEx(INFO, "Write OK.");

    return PM3_SUCCESS;
}

static int CmdHFMFPInitPerso(const char *Cmd) {
    int res;
    uint8_t key[256] = {0};
    int keyLen = 0;
    uint8_t keyNum[2] = {0};
    uint8_t data[250] = {0};
    int datalen = 0;

    CLIParserInit("hf mfp initp",
                  "Executes Write Perso command for all card's keys. Can be used in SL0 mode only.",
                  "Usage:\n\thf mfp initp 000102030405060708090a0b0c0d0e0f -> fill all the keys with key (00..0f)\n"
                  "\thf mfp initp -vv -> fill all the keys with default key(0xff..0xff) and show all the data exchange");

    void *argtable[] = {
        arg_param_begin,
        arg_litn("vV",  "verbose", 0, 2, "show internal data."),
        arg_strx0(NULL,  NULL,      "<HEX key (16b)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    bool verbose2 = arg_get_lit(1) > 1;
    CLIGetHexWithReturn(2, key, &keyLen);
    CLIParserFree();

    if (keyLen && keyLen != 16) {
        PrintAndLogEx(ERR, "Key length must be 16 bytes instead of: %d", keyLen);
        return 1;
    }

    if (!keyLen)
        memmove(key, DefaultKey, 16);

    mfpSetVerboseMode(verbose2);
    for (uint16_t sn = 0x4000; sn < 0x4050; sn++) {
        keyNum[0] = sn >> 8;
        keyNum[1] = sn & 0xff;
        res = MFPWritePerso(keyNum, key, (sn == 0x4000), true, data, sizeof(data), &datalen);
        if (!res && (datalen == 3) && data[0] == 0x09) {
            PrintAndLogEx(INFO, "2k card detected.");
            break;
        }
        if (res || (datalen != 3) || data[0] != 0x90) {
            PrintAndLogEx(ERR, "Write error on address %04x", sn);
            break;
        }
    }

    mfpSetVerboseMode(verbose);
    for (int i = 0; i < ARRAYLEN(CardAddresses); i++) {
        keyNum[0] = CardAddresses[i] >> 8;
        keyNum[1] = CardAddresses[i] & 0xff;
        res = MFPWritePerso(keyNum, key, false, true, data, sizeof(data), &datalen);
        if (!res && (datalen == 3) && data[0] == 0x09) {
            PrintAndLogEx(WARNING, "Skipped[%04x]...", CardAddresses[i]);
        } else {
            if (res || (datalen != 3) || data[0] != 0x90) {
                PrintAndLogEx(ERR, "Write error on address %04x", CardAddresses[i]);
                break;
            }
        }
    }

    DropField();

    if (res)
        return res;

    PrintAndLogEx(INFO, "Done.");

    return PM3_SUCCESS;
}

static int CmdHFMFPCommitPerso(const char *Cmd) {
    CLIParserInit("hf mfp commitp",
                  "Executes Commit Perso command. Can be used in SL0 mode only.",
                  "Usage:\n\thf mfp commitp ->  \n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose", "show internal data."),
        arg_int0(NULL,  NULL,      "SL mode", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    CLIParserFree();

    mfpSetVerboseMode(verbose);

    uint8_t data[250] = {0};
    int datalen = 0;

    int res = MFPCommitPerso(true, false, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "Exchange error: %d", res);
        return res;
    }

    if (datalen != 3) {
        PrintAndLogEx(ERR, "Command must return 3 bytes instead of: %d", datalen);
        return 1;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "Command error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return 1;
    }
    PrintAndLogEx(INFO, "Switch level OK.");

    return PM3_SUCCESS;
}

static int CmdHFMFPAuth(const char *Cmd) {
    uint8_t keyn[250] = {0};
    int keynlen = 0;
    uint8_t key[250] = {0};
    int keylen = 0;

    CLIParserInit("hf mfp auth",
                  "Executes AES authentication command for Mifare Plus card",
                  "Usage:\n\thf mfp auth 4000 000102030405060708090a0b0c0d0e0f -> executes authentication\n"
                  "\thf mfp auth 9003 FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -v -> executes authentication and shows all the system data\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose", "show internal data."),
        arg_str1(NULL,  NULL,     "<Key Num (HEX 2 bytes)>", NULL),
        arg_str1(NULL,  NULL,     "<Key Value (HEX 16 bytes)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    CLIGetHexWithReturn(2, keyn, &keynlen);
    CLIGetHexWithReturn(3, key, &keylen);
    CLIParserFree();

    if (keynlen != 2) {
        PrintAndLogEx(ERR, "ERROR: <Key Num> must be 2 bytes long instead of: %d", keynlen);
        return 1;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "ERROR: <Key Value> must be 16 bytes long instead of: %d", keylen);
        return 1;
    }

    return MifareAuth4(NULL, keyn, key, true, false, true, verbose, false);
}

static int CmdHFMFPRdbl(const char *Cmd) {
    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;

    CLIParserInit("hf mfp rdbl",
                  "Reads several blocks from Mifare Plus card.",
                  "Usage:\n\thf mfp rdbl 0 000102030405060708090a0b0c0d0e0f -> executes authentication and read block 0 data\n"
                  "\thf mfp rdbl 1 -v -> executes authentication and shows sector 1 data with default key 0xFF..0xFF and some additional data\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose", "show internal data."),
        arg_int0("nN",  "count",   "blocks count (by default 1).", NULL),
        arg_lit0("bB",  "keyb",    "use key B (by default keyA)."),
        arg_lit0("pP",  "plain",   "plain communication mode between reader and card."),
        arg_int1(NULL,  NULL,      "<Block Num (0..255)>", NULL),
        arg_str0(NULL,  NULL,      "<Key Value (HEX 16 bytes)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    bool verbose = arg_get_lit(1);
    int blocksCount = arg_get_int_def(2, 1);
    bool keyB = arg_get_lit(3);
    int plain = arg_get_lit(4);
    uint32_t blockn = arg_get_int(5);
    CLIGetHexWithReturn(6, key, &keylen);
    CLIParserFree();

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, DefaultKey, 16);
        keylen = 16;
    }

    if (blockn > 255) {
        PrintAndLogEx(ERR, "<Block Num> must be in range [0..255] instead of: %d", blockn);
        return 1;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<Key Value> must be 16 bytes long instead of: %d", keylen);
        return 1;
    }

    // 3 blocks - wo iso14443-4 chaining
    if (blocksCount > 3) {
        PrintAndLogEx(ERR, "blocks count must be less than 3 instead of: %d", blocksCount);
        return 1;
    }

    if (blocksCount > 1 && mfIsSectorTrailer(blockn)) {
        PrintAndLogEx(WARNING, "WARNING: trailer!");
    }

    uint8_t sectorNum = mfSectorNum(blockn & 0xff);
    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--block:%d sector[%d]:%02x key:%04x", blockn, mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Authentication error: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPReadBlock(&mf4session, plain, blockn & 0xff, blocksCount, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "Read error: %d", res);
        return res;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "Card read error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        return 6;
    }

    if (datalen != 1 + blocksCount * 16 + 8 + 2) {
        PrintAndLogEx(ERR, "Error return length:%d", datalen);
        return 5;
    }

    int indx = blockn;
    for (int i = 0; i < blocksCount; i++)  {
        PrintAndLogEx(INFO, "data[%03d]: %s", indx, sprint_hex(&data[1 + i * 16], 16));
        indx++;
        if (mfIsSectorTrailer(indx) && i != blocksCount - 1) {
            PrintAndLogEx(INFO, "data[%03d]: ------------------- trailer -------------------", indx);
            indx++;
        }
    }

    if (memcmp(&data[blocksCount * 16 + 1], mac, 8)) {
        PrintAndLogEx(WARNING, "WARNING: mac not equal...");
        PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[blocksCount * 16 + 1], 8));
        PrintAndLogEx(WARNING, "MAC reader: %s", sprint_hex(mac, 8));
    } else {
        if (verbose)
            PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[blocksCount * 16 + 1], 8));
    }

    return 0;
}

static int CmdHFMFPRdsc(const char *Cmd) {
    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;

    CLIParserInit("hf mfp rdsc",
                  "Reads one sector from Mifare Plus card.",
                  "Usage:\n\thf mfp rdsc 0 000102030405060708090a0b0c0d0e0f -> executes authentication and read sector 0 data\n"
                  "\thf mfp rdsc 1 -v -> executes authentication and shows sector 1 data with default key 0xFF..0xFF and some additional data\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose", "show internal data."),
        arg_lit0("bB",  "keyb",    "use key B (by default keyA)."),
        arg_lit0("pP",  "plain",   "plain communication mode between reader and card."),
        arg_int1(NULL,  NULL,      "<Sector Num (0..255)>", NULL),
        arg_str0(NULL,  NULL,      "<Key Value (HEX 16 bytes)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    bool verbose = arg_get_lit(1);
    bool keyB = arg_get_lit(2);
    bool plain = arg_get_lit(3);
    uint32_t sectorNum = arg_get_int(4);
    CLIGetHexWithReturn(5, key, &keylen);
    CLIParserFree();

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, DefaultKey, 16);
        keylen = 16;
    }

    if (sectorNum > 39) {
        PrintAndLogEx(ERR, "<Sector Num> must be in range [0..39] instead of: %d", sectorNum);
        return 1;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<Key Value> must be 16 bytes long instead of: %d", keylen);
        return 1;
    }

    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--sector[%d]:%02x key:%04x", mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Authentication error: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    for (int n = mfFirstBlockOfSector(sectorNum); n < mfFirstBlockOfSector(sectorNum) + mfNumBlocksPerSector(sectorNum); n++) {
        res = MFPReadBlock(&mf4session, plain, n & 0xff, 1, false, true, data, sizeof(data), &datalen, mac);
        if (res) {
            PrintAndLogEx(ERR, "Read error: %d", res);
            DropField();
            return res;
        }

        if (datalen && data[0] != 0x90) {
            PrintAndLogEx(ERR, "Card read error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
            DropField();
            return 6;
        }
        if (datalen != 1 + 16 + 8 + 2) {
            PrintAndLogEx(ERR, "Error return length:%d", datalen);
            DropField();
            return 5;
        }

        PrintAndLogEx(INFO, "data[%03d]: %s", n, sprint_hex(&data[1], 16));

        if (memcmp(&data[1 + 16], mac, 8)) {
            PrintAndLogEx(WARNING, "WARNING: mac on block %d not equal...", n);
            PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1 + 16], 8));
            PrintAndLogEx(WARNING, "MAC reader: %s", sprint_hex(mac, 8));
        } else {
            if (verbose)
                PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1 + 16], 8));
        }
    }
    DropField();

    return PM3_SUCCESS;
}

static int CmdHFMFPWrbl(const char *Cmd) {
    uint8_t keyn[2] = {0};
    uint8_t key[250] = {0};
    int keylen = 0;
    uint8_t datain[250] = {0};
    int datainlen = 0;

    CLIParserInit("hf mfp wrbl",
                  "Writes one block to Mifare Plus card.",
                  "Usage:\n\thf mfp wrbl 1 ff0000000000000000000000000000ff 000102030405060708090a0b0c0d0e0f -> writes block 1 data\n"
                  "\thf mfp wrbl 2 ff0000000000000000000000000000ff -v -> writes block 2 data with default key 0xFF..0xFF and some additional data\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose", "show internal data."),
        arg_lit0("bB",  "keyb",    "use key B (by default keyA)."),
        arg_int1(NULL,  NULL,      "<Block Num (0..255)>", NULL),
        arg_str1(NULL,  NULL,      "<Data (HEX 16 bytes)>", NULL),
        arg_str0(NULL,  NULL,      "<Key (HEX 16 bytes)>", NULL),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, false);

    bool verbose = arg_get_lit(1);
    bool keyB = arg_get_lit(2);
    uint32_t blockNum = arg_get_int(3);
    CLIGetHexWithReturn(4, datain, &datainlen);
    CLIGetHexWithReturn(5, key, &keylen);
    CLIParserFree();

    mfpSetVerboseMode(verbose);

    if (!keylen) {
        memmove(key, DefaultKey, 16);
        keylen = 16;
    }

    if (blockNum > 255) {
        PrintAndLogEx(ERR, "<Block Num> must be in range [0..255] instead of: %d", blockNum);
        return 1;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "<Key> must be 16 bytes long instead of: %d", keylen);
        return 1;
    }

    if (datainlen != 16) {
        PrintAndLogEx(ERR, "<Data> must be 16 bytes long instead of: %d", datainlen);
        return 1;
    }

    uint8_t sectorNum = mfSectorNum(blockNum & 0xff);
    uint16_t uKeyNum = 0x4000 + sectorNum * 2 + (keyB ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--block:%d sector[%d]:%02x key:%04x", blockNum & 0xff, mfNumBlocksPerSector(sectorNum), sectorNum, uKeyNum);

    mf4Session_t mf4session;
    int res = MifareAuth4(&mf4session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Authentication error: %d", res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    res = MFPWriteBlock(&mf4session, blockNum & 0xff, datain, false, false, data, sizeof(data), &datalen, mac);
    if (res) {
        PrintAndLogEx(ERR, "Write error: %d", res);
        DropField();
        return res;
    }

    if (datalen != 3 && (datalen != 3 + 8)) {
        PrintAndLogEx(ERR, "Error return length:%d", datalen);
        DropField();
        return 5;
    }

    if (datalen && data[0] != 0x90) {
        PrintAndLogEx(ERR, "Card write error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        DropField();
        return 6;
    }

    if (memcmp(&data[1], mac, 8)) {
        PrintAndLogEx(WARNING, "WARNING: mac not equal...");
        PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1], 8));
        PrintAndLogEx(WARNING, "MAC reader: %s", sprint_hex(mac, 8));
    } else {
        if (verbose)
            PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1], 8));
    }

    DropField();
    PrintAndLogEx(INFO, "Write OK.");
    return PM3_SUCCESS;
}

#define AES_KEY_LEN        16
#define MAX_KEYS_LIST_LEN  1024

int MFPKeyCheck(uint8_t startSector, uint8_t endSector, uint8_t startKeyAB, uint8_t endKeyAB,
                uint8_t keyList[MAX_KEYS_LIST_LEN][AES_KEY_LEN], size_t keyListLen, uint8_t foundKeys[2][64][AES_KEY_LEN + 1],
                bool verbose) {
    int res;
    bool selectCard = true;
    uint8_t keyn[2] = {0};

    // sector number from 0
    for (uint8_t sector = startSector; sector <= endSector; sector++) {
        // 0-keyA 1-keyB
        for (uint8_t keyAB = startKeyAB; keyAB <= endKeyAB; keyAB++) {
            // main cycle with key check
            for (int i = 0; i < keyListLen; i++) {
                if (i % 10 == 0) {
                    if (!verbose)
                        printf(".");
                    if (kbd_enter_pressed()) {
                        PrintAndLogEx(WARNING, "\nAborted via keyboard!\n");
                        DropField();
                        return PM3_EOPABORTED;
                    }
                }

                uint16_t uKeyNum = 0x4000 + sector * 2 + keyAB;
                keyn[0] = uKeyNum >> 8;
                keyn[1] = uKeyNum & 0xff;

                for (int retry = 0; retry < 4; retry++) {
                    res =  MifareAuth4(NULL, keyn, keyList[i], selectCard, true, false, false, true);
                    if (res != 2)
                        break;

                    if (verbose)
                        PrintAndLogEx(WARNING, "retried[%d]...", retry);
                    else
                        printf("R");

                    DropField();
                    selectCard = true;
                    msleep(100);
                }

                if (verbose)
                    PrintAndLogEx(WARNING, "sector %02d key %d [%s] res: %d", sector, keyAB, sprint_hex_inrow(keyList[i], 16), res);

                // key for [sector,keyAB] found
                if (res == 0) {
                    if (verbose)
                        PrintAndLogEx(INFO, "Found key for sector %d key %s [%s]", sector, keyAB == 0 ? "A" : "B", sprint_hex_inrow(keyList[i], 16));
                    else
                        printf("+");
                    foundKeys[keyAB][sector][0] = 0x01;
                    memcpy(&foundKeys[keyAB][sector][1], keyList[i], AES_KEY_LEN);
                    DropField();
                    selectCard = true;
                    msleep(50);
                    break;
                }

                // 5 - auth error (rnd not equal)
                if (res != 5) {
                    if (verbose)
                        PrintAndLogEx(ERR, "Exchange error. Aborted.");
                    else
                        printf("E");
                    DropField();
                    return PM3_ECARDEXCHANGE;
                }

                selectCard = false;
            }
        }
    }

    DropField();
    return PM3_SUCCESS;
}

void Fill2bPattern(uint8_t keyList[MAX_KEYS_LIST_LEN][AES_KEY_LEN], size_t *keyListLen, uint32_t *startPattern) {
    for (uint32_t pt = *startPattern; pt < 0x10000; pt++) {
        keyList[*keyListLen][0] = (pt >> 8) & 0xff;
        keyList[*keyListLen][1] = pt & 0xff;
        memcpy(&keyList[*keyListLen][2], &keyList[*keyListLen][0], 2);
        memcpy(&keyList[*keyListLen][4], &keyList[*keyListLen][0], 4);
        memcpy(&keyList[*keyListLen][8], &keyList[*keyListLen][0], 8);
        (*keyListLen)++;
        *startPattern = pt;
        if (*keyListLen == MAX_KEYS_LIST_LEN)
            break;
    }
    (*startPattern)++;
}

static int CmdHFMFPChk(const char *Cmd) {
    int res;
    uint8_t keyList[MAX_KEYS_LIST_LEN][AES_KEY_LEN] = {{0}};
    size_t keyListLen = 0;
    uint8_t foundKeys[2][64][AES_KEY_LEN + 1] = {{{0}}};

    CLIParserInit("hf mfp chk",
                  "Checks keys with Mifare Plus card.",
                  "Usage:\n"
                  "    hf mfp chk -k 000102030405060708090a0b0c0d0e0f -> check key on sector 0 as key A and B\n"
                  "    hf mfp chk -s 2 -a -> check default key list on sector 2, key A\n"
                  "    hf mfp chk -d mfp_default_keys -s0 -e6 -> check keys from dictionary against sectors 0-6\n"
                  "    hf mfp chk --pattern1b -j keys -> check all 1-byte keys pattern and save found keys to json\n"
                  "    hf mfp chk --pattern2b --startp2b FA00 -> check all 2-byte keys pattern. Start from key FA00FA00...FA00\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("aA",  "keya",      "check only key A (by default check all keys)."),
        arg_lit0("bB",  "keyb",      "check only key B (by default check all keys)."),
        arg_int0("sS",  "startsec",  "Start sector Num (0..255)", NULL),
        arg_int0("eE",  "endsec",    "End sector Num (0..255)", NULL),
        arg_str0("kK",  "key",       "<Key>", "Key for checking (HEX 16 bytes)"),
        arg_str0("dD",  "dict",      "<file>", "file with keys dictionary"),
        arg_lit0(NULL,  "pattern1b", "check all 1-byte combinations of key (0000...0000, 0101...0101, 0202...0202, ...)"),
        arg_lit0(NULL,  "pattern2b", "check all 2-byte combinations of key (0000...0000, 0001...0001, 0002...0002, ...)"),
        arg_str0(NULL,  "startp2b",  "<Pattern>", "Start key (2-byte HEX) for 2-byte search (use with `--pattern2b`)"),
        arg_str0("jJ",  "json",      "<file>",  "json file to save keys"),
        arg_lit0("vV",  "verbose",   "verbose mode."),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool keyA = arg_get_lit(1);
    bool keyB = arg_get_lit(2);
    uint8_t startSector = arg_get_int_def(3, 0);
    uint8_t endSector = arg_get_int_def(4, 0);

    uint8_t vkey[16] = {0};
    int vkeylen = 0;
    CLIGetHexWithReturn(5, vkey, &vkeylen);
    if (vkeylen > 0) {
        if (vkeylen == 16) {
            memcpy(&keyList[keyListLen], vkey, 16);
            keyListLen++;
        } else {
            PrintAndLogEx(ERR, "Specified key must have 16 bytes length.");
            CLIParserFree();
            return PM3_EINVARG;
        }
    }

    uint8_t dict_filename[FILE_PATH_SIZE + 2] = {0};
    int dict_filenamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(6), dict_filename, FILE_PATH_SIZE, &dict_filenamelen)) {
        PrintAndLogEx(FAILED, "File name too long or invalid.");
        CLIParserFree();
        return PM3_EINVARG;
    }

    bool pattern1b = arg_get_lit(7);
    bool pattern2b = arg_get_lit(8);

    if (pattern1b && pattern2b) {
        PrintAndLogEx(ERR, "Pattern search mode must be 2-byte or 1-byte only.");
        CLIParserFree();
        return PM3_EINVARG;
    }

    if (dict_filenamelen && (pattern1b || pattern2b)) {
        PrintAndLogEx(ERR, "Pattern search mode and dictionary mode can't be used in one command.");
        CLIParserFree();
        return PM3_EINVARG;
    }

    uint32_t startPattern = 0x0000;
    uint8_t vpattern[2];
    int vpatternlen = 0;
    CLIGetHexWithReturn(9, vpattern, &vpatternlen);
    if (vpatternlen > 0) {
        if (vpatternlen > 0 && vpatternlen <= 2) {
            startPattern = (vpattern[0] << 8) + vpattern[1];
        } else {
            PrintAndLogEx(ERR, "Pattern must be 2-byte length.");
            CLIParserFree();
            return PM3_EINVARG;
        }
        if (!pattern2b)
            PrintAndLogEx(WARNING, "Pattern entered, but search mode not is 2-byte search.");
    }

    uint8_t jsonname[250] = {0};
    int jsonnamelen = 0;
    if (CLIParamStrToBuf(arg_get_str(10), jsonname, sizeof(jsonname), &jsonnamelen)) {
        PrintAndLogEx(ERR, "Invalid json name.");
        CLIParserFree();
        return PM3_EINVARG;
    }
    jsonname[jsonnamelen] = 0;

    bool verbose = arg_get_lit(11);

    CLIParserFree();

    uint8_t startKeyAB = 0;
    uint8_t endKeyAB = 1;
    if (keyA && !keyB)
        endKeyAB = 0;
    if (!keyA && keyB)
        startKeyAB = 1;

    if (endSector < startSector)
        endSector = startSector;

    // 1-byte pattern search mode
    if (pattern1b) {
        for (int i = 0; i < 0x100; i++)
            memset(keyList[i], i, 16);

        keyListLen = 0x100;
    }

    // 2-byte pattern search mode
    if (pattern2b)
        Fill2bPattern(keyList, &keyListLen, &startPattern);

    // dictionary mode
    size_t endFilePosition = 0;
    if (dict_filenamelen) {
        uint16_t keycnt = 0;
        res = loadFileDICTIONARYEx((char *)dict_filename, keyList, sizeof(keyList), NULL, 16, &keycnt, 0, &endFilePosition, true);
        keyListLen = keycnt;
        if (endFilePosition)
            PrintAndLogEx(SUCCESS, "First part of dictionary successfully loaded.");
    }

    if (keyListLen == 0) {
        for (int i = 0; i < g_mifare_plus_default_keys_len; i++) {
            if (hex_to_bytes(g_mifare_plus_default_keys[i], keyList[keyListLen], 16) != 16)
                break;

            keyListLen++;
        }
    }

    if (keyListLen == 0) {
        PrintAndLogEx(ERR, "Key list is empty. Nothing to check.");
        return PM3_EINVARG;
    }

    if (!verbose)
        printf("Search keys:");
    while (true) {
        res = MFPKeyCheck(startSector, endSector, startKeyAB, endKeyAB, keyList, keyListLen, foundKeys, verbose);
        if (res == PM3_EOPABORTED)
            break;
        if (pattern2b && startPattern < 0x10000) {
            if (!verbose)
                printf("p");
            keyListLen = 0;
            Fill2bPattern(keyList, &keyListLen, &startPattern);
            continue;
        }
        if (dict_filenamelen && endFilePosition) {
            if (!verbose)
                printf("d");
            uint16_t keycnt = 0;
            res = loadFileDICTIONARYEx((char *)dict_filename, keyList, sizeof(keyList), NULL, 16, &keycnt, endFilePosition, &endFilePosition, false);
            keyListLen = keycnt;
            continue;
        }
        break;
    }
    if (!verbose)
        printf("\n");

    // print result
    bool printedHeader = false;
    for (uint8_t sector = startSector; sector <= endSector; sector++) {
        if (foundKeys[0][sector][0] || foundKeys[1][sector][0]) {
            if (!printedHeader) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, ".------.--------------------------------.--------------------------------.");
                PrintAndLogEx(INFO, "|sector|            key A               |            key B               |");
                PrintAndLogEx(INFO, "|------|--------------------------------|--------------------------------|");
                printedHeader = true;
            }
            PrintAndLogEx(INFO, "|  %02d  |%32s|%32s|",
                          sector,
                          (foundKeys[0][sector][0] == 0) ? "------              " : sprint_hex_inrow(&foundKeys[0][sector][1], AES_KEY_LEN),
                          (foundKeys[1][sector][0] == 0) ? "------              " : sprint_hex_inrow(&foundKeys[1][sector][1], AES_KEY_LEN));
        }
    }
    if (!printedHeader)
        PrintAndLogEx(INFO, "No keys found(");
    else
        PrintAndLogEx(INFO, "'------'--------------------------------'--------------------------------'\n");

    // save keys to json
    if ((jsonnamelen > 0) && printedHeader) {
        // Mifare Plus info
        SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);

        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);

        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

        uint64_t select_status = resp.oldarg[0]; // 0: couldn't read, 1: OK, with ATS, 2: OK, no ATS, 3: proprietary Anticollision

        uint8_t data[10 + 1 + 2 + 1 + 256 + 2 * 64 * (AES_KEY_LEN + 1)] = {0};
        uint8_t atslen = 0;
        if (select_status == 1 || select_status == 2) {
            memcpy(data, card.uid, card.uidlen);
            data[10] = card.sak;
            data[11] = card.atqa[1];
            data[12] = card.atqa[0];
            atslen = card.ats_len;
            data[13] = atslen;
            memcpy(&data[14], card.ats, atslen);
        }

        // length: UID(10b)+SAK(1b)+ATQA(2b)+ATSlen(1b)+ATS(atslen)+foundKeys[2][64][AES_KEY_LEN + 1]
        memcpy(&data[14 + atslen], foundKeys, 2 * 64 * (AES_KEY_LEN + 1));
        saveFileJSON((char *)jsonname, jsfMfPlusKeys, data, 64);
    }

    return PM3_SUCCESS;
}

static int CmdHFMFPMAD(const char *Cmd) {

    CLIParserInit("hf mfp mad",
                  "Checks and prints Mifare Application Directory (MAD)",
                  "Usage:\n\thf mfp mad -> shows MAD if exists\n"
                  "\thf mfp mad -a 03e1 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows NDEF data if exists\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("vV",  "verbose",  "show technical data"),
        arg_str0("aA",  "aid",      "print all sectors with aid", NULL),
        arg_str0("kK",  "key",      "key for printing sectors", NULL),
        arg_lit0("bB",  "keyb",     "use key B for access printing sectors (by default: key A)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(3, key, &keylen);
    bool keyB = arg_get_lit(4);

    CLIParserFree();

    if (aidlen != 2 && keylen > 0) {
        PrintAndLogEx(WARNING, "do not need a key without aid.");
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector10[16 * 4] = {0};

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, verbose)) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(ERR, "read sector 0 error. card don't have MAD or don't have MAD on default keys.");
        return 2;
    }

    if (verbose) {
        for (int i = 0; i < 4; i ++)
            PrintAndLogEx(NORMAL, "[%d] %s", i, sprint_hex(&sector0[i * 16], 16));
    }

    bool haveMAD2 = false;
    MAD1DecodeAndPrint(sector0, verbose, &haveMAD2);

    if (haveMAD2) {
        if (mfpReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector10, verbose)) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(ERR, "read sector 0x10 error. card don't have MAD or don't have MAD on default keys.");
            return 2;
        }

        MAD2DecodeAndPrint(sector10, verbose);
    }

    if (aidlen == 2) {
        uint16_t aaid = (aid[0] << 8) + aid[1];
        PrintAndLogEx(NORMAL, "\n-------------- AID 0x%04x ---------------", aaid);

        uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
        size_t madlen = 0;
        if (MADDecode(sector0, sector10, mad, &madlen)) {
            PrintAndLogEx(ERR, "can't decode mad.");
            return 10;
        }

        uint8_t akey[16] = {0};
        memcpy(akey, g_mifarep_ndef_key, 16);
        if (keylen == 16) {
            memcpy(akey, key, 16);
        }

        for (int i = 0; i < madlen; i++) {
            if (aaid == mad[i]) {
                uint8_t vsector[16 * 4] = {0};
                if (mfpReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector, false)) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(ERR, "read sector %d error.", i + 1);
                    return 2;
                }

                for (int j = 0; j < (verbose ? 4 : 3); j ++)
                    PrintAndLogEx(NORMAL, " [%03d] %s", (i + 1) * 4 + j, sprint_hex(&vsector[j * 16], 16));
            }
        }
    }

    return PM3_SUCCESS;
}

static int CmdHFMFPNDEF(const char *Cmd) {

    CLIParserInit("hf mfp ndef",
                  "Prints NFC Data Exchange Format (NDEF)",
                  "Usage:\n\thf mfp ndef -> shows NDEF data\n"
                  "\thf mfp ndef -a 03e1 -k d3f7d3f7d3f7d3f7d3f7d3f7d3f7d3f7 -> shows NDEF data with custom AID and key\n");

    void *argtable[] = {
        arg_param_begin,
        arg_litn("vV",  "verbose",  0, 2, "show technical data"),
        arg_str0("aA",  "aid",      "replace default aid for NDEF", NULL),
        arg_str0("kK",  "key",      "replace default key for NDEF", NULL),
        arg_lit0("bB",  "keyb",     "use key B for access sectors (by default: key A)"),
        arg_param_end
    };
    CLIExecWithReturn(Cmd, argtable, true);

    bool verbose = arg_get_lit(1);
    bool verbose2 = arg_get_lit(1) > 1;
    uint8_t aid[2] = {0};
    int aidlen;
    CLIGetHexWithReturn(2, aid, &aidlen);
    uint8_t key[16] = {0};
    int keylen;
    CLIGetHexWithReturn(3, key, &keylen);
    bool keyB = arg_get_lit(4);

    CLIParserFree();

    uint16_t ndefAID = 0x03e1;
    if (aidlen == 2)
        ndefAID = (aid[0] << 8) + aid[1];

    uint8_t ndefkey[16] = {0};
    memcpy(ndefkey, g_mifarep_ndef_key, 16);
    if (keylen == 16) {
        memcpy(ndefkey, key, 16);
    }

    uint8_t sector0[16 * 4] = {0};
    uint8_t sector10[16 * 4] = {0};
    uint8_t data[4096] = {0};
    int datalen = 0;

    PrintAndLogEx(NORMAL, "");

    if (mfpReadSector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector0, verbose)) {
        PrintAndLogEx(ERR, "read sector 0 error. card don't have MAD or don't have MAD on default keys.");
        return 2;
    }

    bool haveMAD2 = false;
    int res = MADCheck(sector0, NULL, verbose, &haveMAD2);
    if (res) {
        PrintAndLogEx(ERR, "MAD error %d.", res);
        return res;
    }

    if (haveMAD2) {
        if (mfpReadSector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifarep_mad_key, sector10, verbose)) {
            PrintAndLogEx(ERR, "read sector 0x10 error. card don't have MAD or don't have MAD on default keys.");
            return 2;
        }
    }

    uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
    size_t madlen = 0;
    if (MADDecode(sector0, (haveMAD2 ? sector10 : NULL), mad, &madlen)) {
        PrintAndLogEx(ERR, "can't decode mad.");
        return 10;
    }

    printf("data reading:");
    for (int i = 0; i < madlen; i++) {
        if (ndefAID == mad[i]) {
            uint8_t vsector[16 * 4] = {0};
            if (mfpReadSector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, ndefkey, vsector, false)) {
                PrintAndLogEx(ERR, "read sector %d error.", i + 1);
                return 2;
            }

            memcpy(&data[datalen], vsector, 16 * 3);
            datalen += 16 * 3;

            printf(".");
        }
    }
    printf(" OK\n");

    if (!datalen) {
        PrintAndLogEx(ERR, "no NDEF data.");
        return 11;
    }

    if (verbose2) {
        PrintAndLogEx(NORMAL, "NDEF data:");
        dump_buffer(data, datalen, stdout, 1);
    }

    NDEFDecodeAndPrint(data, datalen, verbose);

    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",             CmdHelp,                 AlwaysAvailable, "This help"},
    {"info",             CmdHFMFPInfo,            IfPm3Iso14443a,  "Info about Mifare Plus tag"},
    {"wrp",              CmdHFMFPWritePerso,      IfPm3Iso14443a,  "Write Perso command"},
    {"initp",            CmdHFMFPInitPerso,       IfPm3Iso14443a,  "Fills all the card's keys"},
    {"commitp",          CmdHFMFPCommitPerso,     IfPm3Iso14443a,  "Move card to SL1 or SL3 mode"},
    {"auth",             CmdHFMFPAuth,            IfPm3Iso14443a,  "Authentication"},
    {"rdbl",             CmdHFMFPRdbl,            IfPm3Iso14443a,  "Read blocks"},
    {"rdsc",             CmdHFMFPRdsc,            IfPm3Iso14443a,  "Read sectors"},
    {"wrbl",             CmdHFMFPWrbl,            IfPm3Iso14443a,  "Write blocks"},
    {"chk",              CmdHFMFPChk,             IfPm3Iso14443a,  "Check keys"},
    {"mad",              CmdHFMFPMAD,             IfPm3Iso14443a,  "Checks and prints MAD"},
    {"ndef",             CmdHFMFPNDEF,            IfPm3Iso14443a,  "Prints NDEF records from card"},
    {NULL,               NULL,                    0, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMFP(const char *Cmd) {
    (void)WaitForResponseTimeout(CMD_ACK, NULL, 100);
    return CmdsParse(CommandTable, Cmd);
}

