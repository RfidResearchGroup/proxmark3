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
// Low frequency EM4x70 commands
//-----------------------------------------------------------------------------

#include "cmdlfem4x70.h"
#include <ctype.h>
#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "fileutils.h"
#include "commonutil.h"
#include "em4x70.h"

#define LOCKBIT_0 BITMASK(6)
#define LOCKBIT_1 BITMASK(7)

#define INDEX_TO_BLOCK(x) (((32-x)/2)-1)

static int CmdHelp(const char *Cmd);

static void print_info_result(const uint8_t *data) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "Block |   data   | info");
    PrintAndLogEx(INFO, "------+----------+-----------------------------");

    // Print out each section as memory map in datasheet

    // Start with UM2
    for (int i = 0; i < 8; i += 2) {
        PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  UM2", INDEX_TO_BLOCK(i), data[31 - i], data[31 - i - 1]);
    }
    PrintAndLogEx(INFO, "------+----------+-----------------------------");

    // Print PIN  (will never have data)
    for (int i = 8; i < 12; i += 2) {
        PrintAndLogEx(INFO, " %2d   |   -- --  |  PIN write only", INDEX_TO_BLOCK(i));
    }
    PrintAndLogEx(INFO, "------+----------+-----------------------------");

    // Print Crypt Key (will never have data)
    for (int i = 12; i < 24; i += 2) {
        PrintAndLogEx(INFO, " %2d   |   -- --  |  KEY write-only", INDEX_TO_BLOCK(i));
    }
    PrintAndLogEx(INFO, "------+----------+-----------------------------");

    // Print ID
    for (int i = 24; i < 28; i += 2) {
        PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  ID", INDEX_TO_BLOCK(i), data[31 - i], data[31 - i - 1]);
    }
    PrintAndLogEx(INFO, "------+----------+-----------------------------");

    // Print UM1
    for (int i = 28; i < 32; i += 2) {
        PrintAndLogEx(INFO, " %2d   |   %02X %02X  |  UM1", INDEX_TO_BLOCK(i), data[31 - i], data[31 - i - 1]);
    }
    PrintAndLogEx(INFO, "------+----------+-----------------------------");

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "Tag ID:    %02X %02X %02X %02X", data[7], data[6], data[5], data[4]);
    PrintAndLogEx(INFO, "Lockbit 0: %d", (data[3] & LOCKBIT_0) ? 1 : 0);
    PrintAndLogEx(INFO, "Lockbit 1: %d", (data[3] & LOCKBIT_1) ? 1 : 0);
    PrintAndLogEx(INFO, "Tag is %s.", (data[3] & LOCKBIT_0) ? _RED_("LOCKED") : _GREEN_("UNLOCKED"));
    PrintAndLogEx(NORMAL, "");

}

int em4x70_info(void) {

    em4x70_data_t edata = {
        .parity = false // TODO: try both? or default to true
    };

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_INFO, (uint8_t *)&edata, sizeof(edata));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "(em4x70) Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        return PM3_SUCCESS;
    }

    return PM3_ESOFT;
}

//quick test for EM4x70 tag
bool detect_4x70_block(void) {

    return em4x70_info() == PM3_SUCCESS;
}

int CmdEM4x70Info(const char *Cmd) {

    // envoke reading of a EM4x70 tag which has to be on the antenna because
    // decoding is done by the device (not on client side)

    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 info",
                  "Tag Information EM4x70\n"
                  "  Tag variants include ID48 automotive transponder.\n"
                  "  ID48 does not use command parity (default).\n"
                  "  V4070 and EM4170 do require parity bit.",
                  "lf em 4x70 info\n"
                  "lf em 4x70 info --par -> adds parity bit to command\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);
    etd.parity = arg_get_lit(ctx, 0);
    CLIParserFree(ctx);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_INFO, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_INFO, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Reading " _RED_("Failed"));
    return PM3_ESOFT;
}

int CmdEM4x70Write(const char *Cmd) {

    // write one block/word (16 bits) to the tag at given block address (0-15)
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 write",
                  "Write EM4x70\n",
                  "lf em 4x70 write -b 15 -d c0de       -> write 'c0de' to block 15\n"
                  "lf em 4x70 write -b 15 -d c0de --par -> adds parity bit to commands\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par",    "Add parity bit when sending commands"),
        arg_int1("b",  "block",  "<dec>", "block/word address, dec"),
        arg_str1("d",  "data",   "<hex>", "data, 2 bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int addr = arg_get_int_def(ctx, 2, 1);

    int word_len = 0;
    uint8_t word[2] = {0x0};
    CLIGetHexWithReturn(ctx, 3, word, &word_len);

    CLIParserFree(ctx);

    if (addr < 0 || addr >= EM4X70_NUM_BLOCKS) {
        PrintAndLogEx(FAILED, "block has to be within range [0, 15] got: %d", addr);
        return PM3_EINVARG;
    }

    if (word_len != 2) {
        PrintAndLogEx(FAILED, "word/data length must be 2 bytes. got: %d", word_len);
        return PM3_EINVARG;
    }

    etd.address = (uint8_t) addr;
    etd.word = BYTES2UINT16(word);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITE, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITE, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Writing " _RED_("Failed"));
    return PM3_ESOFT;
}

int CmdEM4x70Brute(const char *Cmd) {

    // From paper "Dismantling Megamos Crypto", Roel Verdult, Flavio D. Garcia and Barıs¸ Ege.
    // Partial Key-Update Attack (optimized version)
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 brute",
                  "Optimized partial key-update attack of 16-bit key block 7, 8 or 9 of an EM4x70\n"
                  "This attack does NOT write anything to the tag.\n"
                  "Before starting this attack, 0000 must be written to the 16-bit key block: 'lf em 4x70 write -b 9 -d 0000'.\n"
                  "After success, the 16-bit key block have to be restored with the key found: 'lf em 4x70 write -b 9 -d c0de'\n",
                  "lf em 4x70 brute -b 9 --rnd 45F54ADA252AAC --frn 4866BB70    --> bruteforcing key bits k95...k80\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_int1("b",  "block",  "<dec>", "block/word address, dec"),
        arg_str1(NULL, "rnd", "<hex>", "Random 56-bit"),
        arg_str1(NULL, "frn", "<hex>", "F(RN) 28-bit as 4 hex bytes"),
        arg_str0("s", "start", "<hex>", "Start bruteforce enumeration from this key value"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int addr = arg_get_int_def(ctx, 2, 0);
    if (addr < 7 || addr > 9) {
        PrintAndLogEx(FAILED, "block has to be within range [7, 9] got: %d", addr);
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    etd.address = (uint8_t) addr;

    int rnd_len = 7;
    CLIGetHexWithReturn(ctx, 3, etd.rnd, &rnd_len);

    int frnd_len = 4;
    CLIGetHexWithReturn(ctx, 4, etd.frnd, &frnd_len);

    uint32_t start_key = 0;
    int res = arg_get_u32_hexstr_def_nlen(ctx, 5, 0, &start_key, 2, true);
    if (res == 2) {
        PrintAndLogEx(WARNING, "start key parameter must be in range [0, FFFF]");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    etd.start_key = start_key;

    CLIParserFree(ctx);

    if (rnd_len != 7) {
        PrintAndLogEx(FAILED, "Random number length must be 7 bytes instead of %d", rnd_len);
        return PM3_EINVARG;
    }

    if (frnd_len != 4) {
        PrintAndLogEx(FAILED, "F(RN) length must be 4 bytes instead of %d", frnd_len);
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "click " _GREEN_("pm3 button") " or press " _GREEN_("Enter") " to exit");
    clearCommandBuffer();
    PacketResponseNG resp;
    SendCommandNG(CMD_LF_EM4X70_BRUTE, (uint8_t *)&etd, sizeof(etd));

    uint32_t timeout = 0;
    for (;;) {

        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(DEBUG, "User aborted");
            break;
        }

        if (WaitForResponseTimeout(CMD_LF_EM4X70_BRUTE, &resp, TIMEOUT)) {
            if (resp.status) {
                // Response is 16-bit partial key
                PrintAndLogEx(INFO, "Partial Key Response: %02X %02X", resp.data.asBytes[0], resp.data.asBytes[1]);
                return PM3_SUCCESS;
            }
            break;
        }

        // should be done in about 60 minutes.
        if (timeout > ((60 * 60000) / TIMEOUT)) {
            PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
            break;
        }
        timeout++;
    }

    PrintAndLogEx(FAILED, "Bruteforce of partial key " _RED_("failed"));
    return PM3_ESOFT;
}

int CmdEM4x70Unlock(const char *Cmd) {

    // send pin code to device, unlocking it for writing
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 unlock",
                  "Unlock EM4x70 by sending PIN\n"
                  "Default pin may be:\n"
                  " AAAAAAAA\n"
                  " 00000000\n",
                  "lf em 4x70 unlock -p 11223344 -> Unlock with PIN\n"
                  "lf em 4x70 unlock -p 11223344 --par -> Unlock with PIN using parity commands\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1("p",  "pin", "<hex>", "pin, 4 bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int pin_len = 0;
    uint8_t pin[4] = {0x0};

    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);

    CLIParserFree(ctx);

    if (pin_len != 4) {
        PrintAndLogEx(FAILED, "PIN length must be 4 bytes instead of %d", pin_len);
        return PM3_EINVARG;
    }

    etd.pin = BYTES2UINT32(pin);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_UNLOCK, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_UNLOCK, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Unlocking tag " _RED_("failed"));
    return PM3_ESOFT;
}

int CmdEM4x70Auth(const char *Cmd) {

    // Authenticate transponder
    // Send 56-bit random number + pre-computed f(rnd, k) to transponder.
    // Transponder will respond with a response
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 auth",
                  "Authenticate against an EM4x70 by sending random number (RN) and F(RN)\n"
                  "  If F(RN) is incorrect based on the tag crypt key, the tag will not respond",
                  "lf em 4x70 auth --rnd 45F54ADA252AAC --frn 4866BB70 --> Test authentication, tag will respond if successful\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1(NULL, "rnd", "<hex>", "Random 56-bit"),
        arg_str1(NULL, "frn", "<hex>", "F(RN) 28-bit as 4 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int rnd_len = 7;
    CLIGetHexWithReturn(ctx, 2, etd.rnd, &rnd_len);

    int frnd_len = 4;
    CLIGetHexWithReturn(ctx, 3, etd.frnd, &frnd_len);

    CLIParserFree(ctx);

    if (rnd_len != 7) {
        PrintAndLogEx(FAILED, "Random number length must be 7 bytes instead of %d", rnd_len);
        return PM3_EINVARG;
    }

    if (frnd_len != 4) {
        PrintAndLogEx(FAILED, "F(RN) length must be 4 bytes instead of %d", frnd_len);
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_AUTH, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_AUTH, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        // Response is 20-bit from tag
        PrintAndLogEx(INFO, "Tag Auth Response: %02X %02X %02X", resp.data.asBytes[2], resp.data.asBytes[1], resp.data.asBytes[0]);
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "TAG Authentication " _RED_("Failed"));
    return PM3_ESOFT;
}

int CmdEM4x70WritePIN(const char *Cmd) {

    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 writepin",
                  "Write PIN\n",
                  "lf em 4x70 writepin -p 11223344 -> Write PIN\n"
                  "lf em 4x70 writepin -p 11223344 --par -> Write PIN using parity commands\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1("p",  "pin", "<hex>", "pin, 4 bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int pin_len = 0;
    uint8_t pin[4] = {0x0};

    CLIGetHexWithReturn(ctx, 2, pin, &pin_len);

    CLIParserFree(ctx);

    if (pin_len != 4) {
        PrintAndLogEx(FAILED, "PIN length must be 4 bytes instead of %d", pin_len);
        return PM3_EINVARG;
    }

    etd.pin = BYTES2UINT32(pin);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITEPIN, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEPIN, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        print_info_result(resp.data.asBytes);
        PrintAndLogEx(INFO, "Writing new PIN: " _GREEN_("SUCCESS"));
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Writing new PIN: " _RED_("FAILED"));
    return PM3_ESOFT;
}

int CmdEM4x70WriteKey(const char *Cmd) {

    // Write new crypt key to tag
    em4x70_data_t etd = {0};

    CLIParserContext *ctx;

    CLIParserInit(&ctx, "lf em 4x70 writekey",
                  "Write new 96-bit key to tag\n",
                  "lf em 4x70 writekey -k F32AA98CF5BE4ADFA6D3480B\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "par", "Add parity bit when sending commands"),
        arg_str1("k",  "key", "<hex>", "Crypt Key as 12 hex bytes"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, Cmd, argtable, true);

    etd.parity = arg_get_lit(ctx, 1);

    int key_len = 12;
    CLIGetHexWithReturn(ctx, 2, etd.crypt_key, &key_len);

    CLIParserFree(ctx);

    if (key_len != 12) {
        PrintAndLogEx(FAILED, "Crypt key length must be 12 bytes instead of %d", key_len);
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_LF_EM4X70_WRITEKEY, (uint8_t *)&etd, sizeof(etd));

    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEKEY, &resp, TIMEOUT)) {
        PrintAndLogEx(WARNING, "Timeout while waiting for reply.");
        return PM3_ETIMEOUT;
    }

    if (resp.status) {
        PrintAndLogEx(INFO, "Writing new crypt key: " _GREEN_("SUCCESS"));
        return PM3_SUCCESS;
    }

    PrintAndLogEx(FAILED, "Writing new crypt key: " _RED_("FAILED"));
    return PM3_ESOFT;
}

static command_t CommandTable[] = {
    {"help",     CmdHelp,           AlwaysAvailable, "This help"},
    {"brute",    CmdEM4x70Brute,    IfPm3EM4x70,     "Bruteforce EM4X70 to find partial Crypt Key"},
    {"info",     CmdEM4x70Info,     IfPm3EM4x70,     "Tag information EM4x70"},
    {"write",    CmdEM4x70Write,    IfPm3EM4x70,     "Write EM4x70"},
    {"unlock",   CmdEM4x70Unlock,   IfPm3EM4x70,     "Unlock EM4x70 for writing"},
    {"auth",     CmdEM4x70Auth,     IfPm3EM4x70,     "Authenticate EM4x70"},
    {"writepin", CmdEM4x70WritePIN, IfPm3EM4x70,     "Write PIN"},
    {"writekey", CmdEM4x70WriteKey, IfPm3EM4x70,     "Write Crypt Key"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFEM4X70(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
