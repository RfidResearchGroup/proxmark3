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

bool g_Extensive_EM4x70_AuthBranch_Debug = false;





static int CmdHelp(const char *Cmd);

static command_t CommandTable[] = {
    {"help",       CmdHelp,             AlwaysAvailable, "This help"},
    {"brute",      CmdEM4x70Brute,      IfPm3EM4x70,     "Bruteforce EM4X70 to find partial Crypt Key"},
    {"info",       CmdEM4x70Info,       IfPm3EM4x70,     "Tag information EM4x70"},
    {"write",      CmdEM4x70Write,      IfPm3EM4x70,     "Write EM4x70"},
    {"unlock",     CmdEM4x70Unlock,     IfPm3EM4x70,     "Unlock EM4x70 for writing"},
    {"auth",       CmdEM4x70Auth,       IfPm3EM4x70,     "Authenticate EM4x70"},
    {"authbranch", CmdEM4x70AuthBranch, IfPm3EM4x70,     "Branch from known-good {k, rnd, frn} set"},
    {"authvars",   CmdEM4x70AuthVars,   IfPm3EM4x70,     "Show trivial variations from known-good {k, rnd, frn} set"},
    {"writepin",   CmdEM4x70WritePIN,   IfPm3EM4x70,     "Write PIN"},
    {"writekey",   CmdEM4x70WriteKey,   IfPm3EM4x70,     "Write Crypt Key"},
    {"debug",      CmdEM4x70DebugLevel, IfPm3EM4x70,     "Set EM4x70 specific debug options"},
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

// file-local function prototypes
static void InitializeAuthBranchData(em4x70_authbranch_t *data, em4x70_authbranch_phase_t phase);
static void dump_authbranch_data(logLevel_t level, const em4x70_authbranch_t *data, bool dumpAll);
/*
static uint8_t CountOfTrailingZeroBits32(uint32_t v) {
    static const uint8_t MultiplyDeBruijnBitPosition32[32] = {
         0,  1, 28,  2,   29, 14, 24,  3,   30, 22, 20, 15,   25, 17,  4,  8,
        31, 27, 13, 23,   21, 19, 16,  7,   26, 12, 18,  6,   11,  5, 10,  9,
    };
    if (v == 0) {
        return 32;
    }
    // (v & -v)    --> extracts the least significant bit
    v &= -v;
    // 0x077CB531  --> a de Bruijn sequence; unique top 5 bits for each one-bit multiplier
    // >> 27       --> take only those top 5 bits from the result
    // array index --> convert to count of trailing zeros
    return MultiplyDeBruijnBitPosition32[((uint32_t)(v * 0x077CB531u)) >> 27];
}
static uint8_t CountOfTrailingOneBits32(uint32_t v) {
    uint8_t result = 0;
    while (v & 0x1) {
        result++;
        v >>= 1;
    }
    return result;
}
*/

static void OutputProgress(logLevel_t level, uint32_t min, uint32_t max, uint32_t current) {
    double n = current - min;
    double d = max - min;
    double p = (n * 100) / d;
    PrintAndLogEx(level, "Progress [%08" PRIX32 "..%08" PRIX32 "], Current: %08" PRIX32 " (~%0.2f%%)", min, max, current, p);
}

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

    PrintAndLogEx(FAILED, "Writing " _RED_("Failed") " status %" PRId16 "\n", resp.status);
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



typedef struct TRIVIAL_VARIATIONS_OUTPUT {
    uint32_t native_ac[32];
} trivial_variations_output_t;
static int16_t get_trivial_auth_variations(const em4x70_data_t *etd_orig, trivial_variations_output_t *results) {
    memset(results, 0, sizeof(trivial_variations_output_t));

    PacketResponseNG resp;
    for (uint8_t i = 0; i < 32; ++i) {

        em4x70_data_t etd;
        memcpy(&etd, etd_orig, sizeof(em4x70_data_t));

        // 1. write new key
        etd.crypt_key[11] = (etd.crypt_key[11] & 0xE0) | i; // clear lowest 5 bits and set to loop index
        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X70_WRITEKEY, (uint8_t *)&etd, sizeof(em4x70_data_t));

        memset(&resp, 0, sizeof(PacketResponseNG));
        if (!WaitForResponseTimeout(CMD_LF_EM4X70_WRITEKEY, &resp, TIMEOUT)) {
            PrintAndLogEx(WARNING, "Timeout while writing equivalent key idx %" PRId8, i);
            return PM3_ETIMEOUT;
        }
        if (!(resp.status)) {
            PrintAndLogEx(FAILED, "Writing new equivalent crypt key %" PRId8 ": " _RED_("FAILED"), i);
            return PM3_ESOFT;
        }

        // 2. perform authentication
        clearCommandBuffer();
        SendCommandNG(CMD_LF_EM4X70_AUTH, (uint8_t *)&etd, sizeof(etd));
        memset(&resp, 0, sizeof(PacketResponseNG));
        if (!WaitForResponseTimeout(CMD_LF_EM4X70_AUTH, &resp, TIMEOUT)) {
            PrintAndLogEx(WARNING, "Timeout while waiting for auth reply equivalent key idx %" PRId8 ".", i);
            return PM3_ETIMEOUT;
        }
        if (!(resp.status)) {
            PrintAndLogEx(FAILED, "TAG Authentication equivalent key %" PRId8 ": " _RED_("Failed"), i);
            return PM3_ESOFT;
        }

        // 3. store auth results in parameter's array
        results->native_ac[i] = MemLeToUint3byte(&(resp.data.asBytes[0]));
    }
    return PM3_SUCCESS;
}

// Longest returned string: "1 (req)  Verify Starting Values" == 31 chars
//                           ....-....1....-....2....-....3....-
static const char *sprint_authbranch_phase(em4x70_authbranch_phase_t phase) {
    switch (phase) {
        case EM4X70_AUTHBRANCH_PHASE0_UNINITIALIZED:
            return "0 (uninitialized)";
        case EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES:
            return "1 (req)  Verify Starting Values";
        case EM4X70_AUTHBRANCH_PHASE1_COMPLETED_VERIFY_STARTING_VALUES:
            return "1 (resp) Verify Starting Values";
        case EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY:
            return "2 (req)  Write Branched Key";
        case EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY:
            return "2 (resp) Write Branched Key";
        case EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE:
            return "3 (req)  Brute Force FRN";
        case EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE:
            return "3 (resp) Brute Force FRN";
    }
    // default
    static char buf[20]; // "Invalid: " is 9 chars, + 8 for hex digits + null + 1 extra
    memset(buf, 0, sizeof(buf));
    snprintf(buf, sizeof(buf) - 1, "Invalid: %08" PRIX32, phase);
    return (const char *)buf;
}

// wishing for C++ templates....
static char *sprint_abd_phase1_input_useParity(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT     = sizeof(data->phase1_input.useParity) };
    const uint8_t *p = (const uint8_t *)(&data->phase1_input.useParity);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase1_input_be_rnd(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase1_input.be_rnd) };
    const uint8_t *p = (const   uint8_t *)(&data->phase1_input.be_rnd);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase1_input_be_key(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase1_input.be_key) };
    const uint8_t *p = (const   uint8_t *)(&data->phase1_input.be_key);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase1_input_be_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase1_input.be_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase1_input.be_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase1_input_be_start_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase1_input.be_start_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase1_input.be_start_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase1_input_be_xormask(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase1_input.be_xormask) };
    const uint8_t *p = (const   uint8_t *)(&data->phase1_input.be_xormask);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase2_input_be_xormask(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase2_input.be_xormask) };
    const uint8_t *p = (const   uint8_t *)(&data->phase2_input.be_xormask);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase2_output_be_key(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase2_output.be_key) };
    const uint8_t *p = (const   uint8_t *)(&data->phase2_output.be_key);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase2_output_be_min_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =        sizeof(data->phase2_output.be_min_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase2_output.be_min_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase2_output_be_max_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =        sizeof(data->phase2_output.be_max_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase2_output.be_max_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase2_output_be_max_iterations(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase2_output.be_max_iterations) };
    const uint8_t *p = (const   uint8_t *)(&data->phase2_output.be_max_iterations);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase3_input_be_starting_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase3_input.be_starting_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase3_input.be_starting_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase3_input_be_max_iterations(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase3_input.be_max_iterations) };
    const uint8_t *p = (const   uint8_t *)(&data->phase3_input.be_max_iterations);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase3_output_found_working_value(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =        sizeof(data->phase3_output.found_working_value) };
    const uint8_t *p = (const   uint8_t *)(&data->phase3_output.found_working_value);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase3_output_be_next_start_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase3_output.be_next_start_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase3_output.be_next_start_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase3_output_be_successful_frn(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase3_output.be_successful_frn) };
    const uint8_t *p = (const   uint8_t *)(&data->phase3_output.be_successful_frn);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static char *sprint_abd_phase3_output_be_successful_ac(const em4x70_authbranch_t *data) {
    enum { LOCAL_BYTE_COUNT =       sizeof(data->phase3_output.be_successful_ac) };
    const uint8_t *p = (const   uint8_t *)(&data->phase3_output.be_successful_ac);

    static uint8_t buf[(2 * LOCAL_BYTE_COUNT) + 1] = {0};
    memset(buf, 0x00, sizeof(buf));
    hex_to_buffer((uint8_t *)buf, p, LOCAL_BYTE_COUNT, sizeof(buf) - 1, 0, 0, true);
    return (char *)buf;
}
static void DumpAuthBranchSeparator(logLevel_t level) {
    PrintAndLogEx(level, "+------------------+----------------------------+");
}
static void DumpAuthBranchPhase1Inputs(logLevel_t level, const em4x70_authbranch_t *data) {
    PrintAndLogEx(level, "| Phase 1 Inputs   |                            |");
    PrintAndLogEx(level, "+------------------+----------------------------+");
    PrintAndLogEx(level, "| %15s  |  %24s  |", "useParity",    sprint_abd_phase1_input_useParity(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "be_rnd",       sprint_abd_phase1_input_be_rnd(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "be_key",       sprint_abd_phase1_input_be_key(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "be_xormask",   sprint_abd_phase1_input_be_xormask(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "be_frn",       sprint_abd_phase1_input_be_frn(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "be_start_frn", sprint_abd_phase1_input_be_start_frn(data));
    PrintAndLogEx(level, "+------------------+----------------------------+");
}
static void DumpAuthBranchPhase2Inputs(logLevel_t level, const em4x70_authbranch_t *data) {
    PrintAndLogEx(level, "| Phase 2 Inputs   |                            |");
    PrintAndLogEx(level, "+------------------+----------------------------+");
    PrintAndLogEx(level, "| %15s  |  %24s  |", "key xormask", sprint_abd_phase2_input_be_xormask(data));
    PrintAndLogEx(level, "+------------------+----------------------------+");
}
static void DumpAuthBranchPhase2Outputs(logLevel_t level, const em4x70_authbranch_t *data) {
    PrintAndLogEx(level, "| Phase 2 Outputs  |                            |");
    PrintAndLogEx(level, "+------------------+----------------------------+");
    PrintAndLogEx(level, "| %15s  |  %24s  |", "key",            sprint_abd_phase2_output_be_key(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "min_frn",        sprint_abd_phase2_output_be_min_frn(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "max_frn",        sprint_abd_phase2_output_be_max_frn(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "max_iterations", sprint_abd_phase2_output_be_max_iterations(data));
    PrintAndLogEx(level, "+------------------+----------------------------+");
}
static void DumpAuthBranchPhase3Inputs(logLevel_t level, const em4x70_authbranch_t *data) {
    PrintAndLogEx(level, "| Phase 3 Inputs   |                            |");
    PrintAndLogEx(level, "+------------------+----------------------------+");
    PrintAndLogEx(level, "| %15s  |  %24s  |", "starting_frn",   sprint_abd_phase3_input_be_starting_frn(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "max_iterations", sprint_abd_phase3_input_be_max_iterations(data));
    PrintAndLogEx(level, "+------------------+----------------------------+");
}
static void DumpAuthBranchPhase3Outputs(logLevel_t level, const em4x70_authbranch_t *data) {
    PrintAndLogEx(level, "| Phase 3 Outputs  |                            |");
    PrintAndLogEx(level, "+------------------+----------------------------+");
    PrintAndLogEx(level, "| %15s  |  %24s  |", "found Ac",       sprint_abd_phase3_output_found_working_value(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "next_start_frn", sprint_abd_phase3_output_be_next_start_frn(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "successful_frn", sprint_abd_phase3_output_be_successful_frn(data));
    PrintAndLogEx(level, "| %15s  |  %24s  |", "successful_ac",  sprint_abd_phase3_output_be_successful_ac(data));
    PrintAndLogEx(level, "+------------------+----------------------------+");
}
static void dump_authbranch_data(logLevel_t level, const em4x70_authbranch_t *data, bool dumpAll) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(level, "+============ " _CYAN_("AuthBranch Parameters") " ============+");
    em4x70_authbranch_phase_t phase = MemBeToUint4byte(&(data->be_phase[0]));
    PrintAndLogEx(level, "| Phase: %-37s  |", sprint_authbranch_phase(phase));
    PrintAndLogEx(level, "+==================+============================+");
    if (
        (phase == EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES) ||
        (phase == EM4X70_AUTHBRANCH_PHASE1_COMPLETED_VERIFY_STARTING_VALUES) ||
        (phase == EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY) ||
        (phase == EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) ||
        dumpAll
    ) {
        DumpAuthBranchPhase1Inputs(level, data);
    }
    if (
        (phase == EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY) ||
        (phase == EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) ||
        dumpAll
    ) {
        DumpAuthBranchPhase2Inputs(level, data);
    }
    if (
        (phase == EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) ||
        dumpAll
    ) {
        DumpAuthBranchPhase2Outputs(level, data);
    }
    if (
        (phase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) ||
        (phase == EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) ||
        dumpAll
    ) {
        DumpAuthBranchPhase3Inputs(level, data);
    }
    if (
        (phase == EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) ||
        dumpAll
    ) {
        DumpAuthBranchPhase3Outputs(level, data);
    }
}
static void SetInvalidPhase1Data(em4x70_authbranch_t *data) {
    // set invalid values, to help find code paths where the values are
    // used without proper initialization ... makes easier to debug.
    Uint4byteToMemBe(&(data->phase1_input.be_rnd[0]), UINT32_C(0x1abe1edF)); // labeledF...
    Uint3byteToMemBe(&(data->phase1_input.be_rnd[4]), UINT32_C(0x001066ed)); //      ...logged
    Uint4byteToMemBe(&(data->phase1_input.be_key[0]), UINT32_C(0xDeadF00d)); // deadfood
    Uint4byteToMemBe(&(data->phase1_input.be_key[4]), UINT32_C(0xCafeBabe)); // cafebabe
    Uint4byteToMemBe(&(data->phase1_input.be_key[8]), UINT32_C(0xBaadF00d)); // baadfood
    Uint4byteToMemBe(&(data->phase1_input.be_frn[0]), UINT32_C(0xF1055a6e)); // flossage
    // Uint4byteToMemBe(&(data->phase1_input.be_start_frn[0]), UINT32_C(0x00000000)); // safe default
    Uint4byteToMemBe(&(data->phase1_input.be_xormask[0]), UINT32_C(0)); // zero is the invalid value
}
static void SetInvalidPhase2Data(em4x70_authbranch_t *data) {
    // set invalid values, to help find code paths where the values are
    // used without proper initialization ... makes easier to debug.
    Uint4byteToMemBe(&(data->phase2_input.be_xormask[0]),          UINT32_C(0x00000000)); // the only invalid value
    Uint4byteToMemBe(&(data->phase2_output.be_key[0]),             UINT32_C(0xF1a7f007)); // flatfoot
    Uint4byteToMemBe(&(data->phase2_output.be_key[4]),             UINT32_C(0xCafeBabe)); // cafebabe
    Uint4byteToMemBe(&(data->phase2_output.be_key[8]),             UINT32_C(0x1eaf1e75)); // leaflets
    Uint4byteToMemBe(&(data->phase2_output.be_min_frn[0]),         UINT32_C(0xBa5eba11)); // baseball
    Uint4byteToMemBe(&(data->phase2_output.be_max_iterations[0]),  UINT32_C(0xdecea5ed)); // deceased
}
static void SetInvalidPhase3Data(em4x70_authbranch_t *data) {
    // set invalid values, to help find code paths where the values are
    // used without proper initialization ... makes easier to debug.
    Uint4byteToMemBe(&(data->phase3_input.be_max_iterations[0]),   UINT32_C(0xFEEDBEEF)); // feedbeef
    Uint4byteToMemBe(&(data->phase3_input.be_starting_frn[0]),     UINT32_C(0xFee1Baad)); // feelbaad
    Uint4byteToMemBe(&(data->phase3_output.be_next_start_frn[0]),  UINT32_C(0xF100Fee5)); // FlooFees
    Uint4byteToMemBe(&(data->phase3_output.be_successful_frn[0]),  UINT32_C(0xc011a7ed)); // collated
    Uint3byteToMemBe(&(data->phase3_output.be_successful_ac[0]),   UINT32_C(0x00000000)); // all-zero is unlikely to be valid
}
// At phase 1, invalidates all fields except phase
// At phase 2, invalidates phase2_input onwards
// At phase 3, invalidates phase3_input onwards
// Finally, automatically sets ->phase to reflect the new phase for this structure
static void InitializeAuthBranchData(em4x70_authbranch_t *data, em4x70_authbranch_phase_t phase) {

    // ensure these are constants by using in enum
    enum {
        OFFSET_PHASE1 = offsetof(em4x70_authbranch_t, phase1_input),
        OFFSET_PHASE2 = offsetof(em4x70_authbranch_t, phase2_input),
        OFFSET_PHASE3 = offsetof(em4x70_authbranch_t, phase3_input),
    };
    enum {
        REMAINING_BYTE_COUNT_PHASE1 = sizeof(em4x70_authbranch_t) - OFFSET_PHASE1,
        REMAINING_BYTE_COUNT_PHASE2 = sizeof(em4x70_authbranch_t) - OFFSET_PHASE2,
        REMAINING_BYTE_COUNT_PHASE3 = sizeof(em4x70_authbranch_t) - OFFSET_PHASE3,
    };

    if (phase == EM4X70_AUTHBRANCH_PHASE0_UNINITIALIZED) {
        memset(data, 0, sizeof(em4x70_authbranch_t));
    } else if (phase == EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES) {
        memset(&(data->phase1_input), 0, REMAINING_BYTE_COUNT_PHASE1);
        SetInvalidPhase1Data(data);
        SetInvalidPhase2Data(data);
        SetInvalidPhase3Data(data);
        data->phase1_input.useParity = 0x00;
    } else if (phase == EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY) {
        // prior phase must be either Phase1 or Phase3
        em4x70_authbranch_phase_t priorPhase = MemBeToUint4byte(&(data->be_phase[0]));
        if (
            (priorPhase != EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES) &&
            (priorPhase != EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE)) {
            PrintAndLogEx(FAILED, "InitializeAuthBranchData() called for phase 2, but prior phase was %08" PRIX32, priorPhase);
        }
        // reset phase 2 and phase 3 -- zero then set invalid data
        memset(&(data->phase2_input), 0, REMAINING_BYTE_COUNT_PHASE2);
        SetInvalidPhase2Data(data);
        SetInvalidPhase3Data(data);
    } else if (phase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) {
        // reset phase 3 -- zero then set invalid data
        memset(&(data->phase3_input), 0, REMAINING_BYTE_COUNT_PHASE3);
        SetInvalidPhase3Data(data);
    } else {
        PrintAndLogEx(WARNING, "InitializeAuthBranchData() called with unsupported requested phase %08" PRIX32 " (%" PRId32 ")", phase, phase);
        memset(data, 0, sizeof(em4x70_authbranch_t));
        phase = 0;
    }
    // ensure the phase is updated
    Uint4byteToMemBe(&(data->be_phase[0]), phase);
}
// static void CopyPhase1Outputs(const em4x70_authbranch_t *response, em4x70_authbranch_t *request) {
//     // this does nothing, but included here to allow code to reflect future changes
//     if ((response == NULL) || (request == NULL)) {
//         PrintAndLogEx(ERR, _BRIGHT_RED_("Request to copy phase %c to/from null"), '1');
//     }
// }
// static void CopyPhase2Outputs(const em4x70_authbranch_t *response, em4x70_authbranch_t *request) {
//     if ((response == NULL) || (request == NULL)) {
//         PrintAndLogEx(ERR, _BRIGHT_RED_("Request to copy phase %c to/from null"), '2');
//     }
//     enum { OFFSET    = offsetof(em4x70_authbranch_t,  phase2_output) };
//     enum { BYTECOUNT = sizeof(              response->phase2_output) };
//     uint8_t* dest = (uint8_t*)(&(            request->phase2_output));
//     const uint8_t* src = (const uint8_t*)(&(response->phase2_output));
//     memcpy(dest, src, BYTECOUNT);
// }
// static void CopyPhase3Outputs(const em4x70_authbranch_t *response, em4x70_authbranch_t *request) {
//     if ((response == NULL) || (request == NULL)) {
//         PrintAndLogEx(ERR, _BRIGHT_RED_("Request to copy phase %c to/from null"), '3');
//     }
//     enum { OFFSET    = offsetof(em4x70_authbranch_t,  phase3_output) };
//     enum { BYTECOUNT = sizeof(              response->phase3_output) };
//     uint8_t* dest = (uint8_t*)(&(            request->phase3_output));
//     const uint8_t* src = (const uint8_t*)(&(response->phase3_output));
//     memcpy(dest, src, BYTECOUNT);
// }

static int16_t get_variations_and_dump_output(const em4x70_authbranch_t *data) {

    em4x70_data_t etd;
    memset(&etd, 0, sizeof(em4x70_data_t));

    uint64_t rnd      = MemBeToUint7byte(&(data->phase1_input.be_rnd[0]));
    uint64_t k_high64 = MemBeToUint8byte(&(data->phase2_output.be_key[0]));
    uint32_t k_low32  = MemBeToUint4byte(&(data->phase2_output.be_key[8]));
    uint32_t frn      = MemBeToUint4byte(&(data->phase3_output.be_successful_frn[0]));

    Uint7byteToMemBe(&(etd.rnd[0]), rnd);
    Uint8byteToMemBe(&(etd.crypt_key[0]), k_high64);
    Uint4byteToMemBe(&(etd.crypt_key[8]), k_low32);
    Uint4byteToMemBe(&(etd.frnd[0]), frn);

    trivial_variations_output_t x = {0};
    int16_t status = get_trivial_auth_variations(&etd, &x);

    if (status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Getting trivial auth variations failed: " _BRIGHT_RED_("%" PRId16), status);
        return status;
    }
    PrintAndLogEx(SUCCESS,
                  "{ \"N\": \"%014" PRIX64 "\","
                  " \"K\": \"%016"  PRIX64 "%08" PRIX32 "\","
                  " \"Ac\": \"%08"  PRIX32 "\","
                  " \"At\": ["
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\"] }",
                  rnd, k_high64, k_low32, frn,
                  x.native_ac[ 0], x.native_ac[ 1], x.native_ac[ 2], x.native_ac[ 3],
                  x.native_ac[ 4], x.native_ac[ 5], x.native_ac[ 6], x.native_ac[ 7],
                  x.native_ac[ 8], x.native_ac[ 9], x.native_ac[10], x.native_ac[11],
                  x.native_ac[12], x.native_ac[13], x.native_ac[14], x.native_ac[15],
                  x.native_ac[16], x.native_ac[17], x.native_ac[18], x.native_ac[19],
                  x.native_ac[20], x.native_ac[21], x.native_ac[22], x.native_ac[23],
                  x.native_ac[24], x.native_ac[25], x.native_ac[26], x.native_ac[27],
                  x.native_ac[28], x.native_ac[29], x.native_ac[30], x.native_ac[31]
                 );
    return PM3_SUCCESS;
}

static bool Parse_CmdEM4x70AuthBranch(const char *Cmd, em4x70_authbranch_t *data) {
    bool failedArgsParsing = false;
    InitializeAuthBranchData(data, EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES);

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x70 auth_branch",
                  "Given a valid key, rnd, and frn, this function finds\n"
                  "other valid { key, rnd, frn } values.\n"
                  "This function OVERWRITES any existing key on the tag.\n"
                  "Before starting, the tag MUST be unlocked.\n"
                  "After running, the private key is left in an INDETERMINATE state.\n"
                  "It is the responsiblity of the user to restore any desired private key.\n",
                  "Example to diverge the key by 13 bits from sample key/fnd/frnd\n"
                  "lf em 4x70 auth_branch -k F32AA98CF5BE4ADFA6D3480B --rnd 45F54ADA252AAC --frn 4866BB70 -d 13\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_litn(NULL, "par",                 0, 1, "Add parity bit when sending commands"),                                 // 1
        arg_str1(NULL, "rnd",        "<hex>",       "Random 56-bit"),                                                        // 2
        arg_str1("k",  "key",        "<hex>",       "Crypt Key as 24 hex characters"),                                       // 3
        arg_str1(NULL, "frn",        "<hex>",       "F(RN) 28-bit as 8 hex characters (last character is padding of zero)"), // 4
        arg_intn("d",  "divergence", "<dec>", 0, 1, "Set key divergence to specified count of bits (5..31)"),                // 5
        arg_strn("x",  "xormask",    "<hex>", 0, 1, "Set 32-bit hex mask to apply as divergence XOR value"),                 // 6
        arg_strn("s",  "start",      "<hex>", 0, 1, "Start bruteforce from this hex frn value (with padding zero)"),         // 7
        arg_param_end
    };

    if (CLIParserParseString(ctx, Cmd, argtable, arg_getsize(argtable), true)) {
        failedArgsParsing = true;
    } else {

        data->phase1_input.useParity = arg_get_lit(ctx, 1);

        int rnd_len = 7;
        if (CLIParamHexToBuf(arg_get_str(ctx, 2), &(data->phase1_input.be_rnd[0]), 7, &rnd_len)) {
            // parse failed (different than non-existent parameter)
            // mandatory parameter, so mark as failure
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "rnd parameter is a mandatory hex string");
        } else if (rnd_len != 7) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "rnd parameter must be 7 bytes (got %d)", rnd_len);
        }

        int key_len = 12;
        if (CLIParamHexToBuf(arg_get_str(ctx, 3), &(data->phase1_input.be_key[0]), 12, &key_len)) {
            // parse failed (different than non-existent parameter)
            // mandatory parameter, so mark as failure
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "key parameter is a mandatory hex string");
        } else if (key_len != 12) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "key parameter must be 12 bytes (got %d)", key_len);
        }

        int frn_len = 4;
        if (CLIParamHexToBuf(arg_get_str(ctx, 4), &(data->phase1_input.be_frn[0]), 4, &frn_len)) {
            // parse failed (different than non-existent parameter)
            // mandatory parameter, so mark as failure
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "frn parameter is a mandatory hex string");
        } else if (frn_len != 4) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "frn parameter must be 4 bytes (got %d)", frn_len);
        }

        uint32_t native_xormask = 0x00010000;
        // divergence is option with default value (16)
        int divergence = arg_get_int_def(ctx, 5, 16);
        if ((divergence > EM4X70_MAXIMUM_KEY_DIVERGENCE_BITS) || (divergence < EM4X70_MINIMUM_KEY_DIVERGENCE_BITS)) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED,
                          "divergence parameter must be in range [%" PRId32 " .. %" PRId32 "], got %d",
                          EM4X70_MINIMUM_KEY_DIVERGENCE_BITS, EM4X70_MAXIMUM_KEY_DIVERGENCE_BITS, divergence);
        } else {
            native_xormask = UINT32_C(1) << divergence;
        }

        // xor mask, if provided, overrides divergence
        int xormask_len = 4;
        // xormask is optional ... use divergence (which has default value) if this isn't provided
        // since it's a string argument type, length == 0 means caller did not provide the value
        if (CLIParamHexToBuf(arg_get_str(ctx, 6), &(data->phase1_input.be_xormask[0]), 4, &xormask_len)) {
            // parse failed (different than non-existent parameter)
            failedArgsParsing = true;
        } else if (xormask_len == 0) {
            // optional parameter was not provided, so overwrite with divergence-based xormask
            Uint4byteToMemBe(&(data->phase1_input.be_xormask[0]), native_xormask);
        } else if (xormask_len != 4) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "xormask must be 4 bytes (got %d)", xormask_len);
        }

        int start_frnd_len = 4;
        // start_frn is an entirely optional parameter
        // since it's a string argument type, length == 0 means caller did not provide the value
        if (CLIParamHexToBuf(arg_get_str(ctx, 7), &(data->phase1_input.be_start_frn[0]), 4, &start_frnd_len)) {
            // parse failed (different than non-existent parameter)
            failedArgsParsing = true;
        } else if (start_frnd_len == 0) {
            // optional parameter, so use default of no special offset by setting to invalid value
            Uint4byteToMemBe(&(data->phase1_input.be_start_frn[0]), UINT32_C(0));
        } else if (start_frnd_len != 4) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "start_frnd_len must be 4 bytes (got %d)", start_frnd_len);
        }
    }
    // always need to free the ctx
    CLIParserFree(ctx);

    return failedArgsParsing ? false : true;
}
int CmdEM4x70AuthBranch(const char *Cmd) {

    if (false) { // unused functions ... to quiet the compiler warnings
        DumpAuthBranchSeparator(ERR);
        // CopyPhase1Outputs(NULL, NULL);
        // CopyPhase2Outputs(NULL, NULL);
        // CopyPhase3Outputs(NULL, NULL);
    }

    enum {
        MAX_TIMEOUT_CYCLES_PHASE1 =     8,  //   16  seconds: phase 1 writes the original key, and does an initial authentication
        MAX_TIMEOUT_CYCLES_PHASE2 =     6,  //   12  seconds: phase 2 writes the branched key
        MAX_TIMEOUT_CYCLES_PHASE3 =  0x10,  //   16  seconds: depends on next value ... how many frnd to attempt at one go?
        FRN_ITERATIONS_PER_UPDATE =  0x40,  //   64 attempts: affects selection of timeout for phase3
    };

    // Kudos to paper "Dismantling Megamos Crypto", Roel Verdult, Flavio D. Garcia and Barıs¸ Ege.
    // Given a working { private key, rnd, frnd }, this function branches out
    em4x70_authbranch_t abd = {0};
    InitializeAuthBranchData(&abd, EM4X70_AUTHBRANCH_PHASE0_UNINITIALIZED);
    if (g_Extensive_EM4x70_AuthBranch_Debug) {
        dump_authbranch_data(NORMAL, &abd, false);
    }
    // if arguments parse successfully, we have everything needed, and phase1 is ready to launch
    if (!Parse_CmdEM4x70AuthBranch(Cmd, &abd)) {
        return PM3_EINVARG;
    }
    if (g_Extensive_EM4x70_AuthBranch_Debug) {
        dump_authbranch_data(NORMAL, &abd, false);
    }

    int status = PM3_SUCCESS;
    bool sendAdditionalCommand = true;
    int32_t remainingTimeoutsThisPhase = MAX_TIMEOUT_CYCLES_PHASE1;

    for (uint32_t i = 0; true; ++i) { // only exit is via failure

        em4x70_authbranch_phase_t requestPhase = MemBeToUint4byte(&(abd.be_phase[0]));

        // each loop, must send a command to the device...
        if (sendAdditionalCommand) {
            clearCommandBuffer();

            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                PrintAndLogEx(WARNING, "Sending phase %s", sprint_authbranch_phase(requestPhase));
                dump_authbranch_data(WARNING, &abd, true);
            }

            SendCommandNG(CMD_LF_EM4X70_AUTHBRANCH, (uint8_t *)&abd, sizeof(em4x70_authbranch_t));
            sendAdditionalCommand = false;
        }

        // use might abort at any time...
        if (kbd_enter_pressed()) {
            SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, _BRIGHT_RED_("User aborted"));
            if (requestPhase == EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) {
                uint32_t lastRequestedFrn = MemBeToUint4byte(&(abd.phase3_input.be_starting_frn[0]));
                uint32_t min_frn = MemBeToUint4byte(&(abd.phase2_output.be_min_frn[0]));
                uint32_t max_frn = MemBeToUint4byte(&(abd.phase2_output.be_max_frn[0]));
                OutputProgress(NORMAL, min_frn, max_frn, lastRequestedFrn);
                PrintAndLogEx(NORMAL, "To resume:");
                PrintAndLogEx(NORMAL,
                              "lf em 4x70 authbranch --rnd %014" PRIX64
                              " -k %016" PRIX64 "%08" PRIX32
                              " --frn %08" PRIX32
                              " --xormask %08" PRIX32
                              " --start %08" PRIX32,
                              MemBeToUint7byte(&(abd.phase1_input.be_rnd[0])),
                              MemBeToUint8byte(&(abd.phase1_input.be_key[0])), MemBeToUint4byte(&(abd.phase1_input.be_key[8])),
                              MemBeToUint4byte(&(abd.phase1_input.be_frn[0])),
                              MemBeToUint4byte(&(abd.phase1_input.be_xormask[0])),
                              lastRequestedFrn
                             );
            }
            status = PM3_EOPABORTED;
            break;
        }

        PacketResponseNG resp;
        if (WaitForResponseTimeoutW(CMD_LF_EM4X70_AUTHBRANCH, &resp, TIMEOUT, false)) {
            const em4x70_authbranch_t *results = (const em4x70_authbranch_t *)(&(resp.data.asBytes[0]));
            em4x70_authbranch_phase_t responsePhase = MemBeToUint4byte(&(results->be_phase[0]));

            if (g_Extensive_EM4x70_AuthBranch_Debug) {
                PrintAndLogEx(INFO, "WaitForResponseTimeout succeeded with cmd %" PRId16 ", status %" PRId16, resp.cmd, resp.status);
                PrintAndLogEx(WARNING, "Received phase %s", sprint_authbranch_phase(responsePhase));
                dump_authbranch_data(WARNING, results, true);
            }


            if (requestPhase == EM4X70_AUTHBRANCH_PHASE1_REQUESTED_VERIFY_STARTING_VALUES) {
                if (resp.status != PM3_SUCCESS) {
                    PrintAndLogEx(ERR, "Non-successful response status %04" PRId16 " for request phase %08" PRId32, resp.status, requestPhase);
                    status = resp.status;
                    break; // out of infinite loop
                } else if (responsePhase != EM4X70_AUTHBRANCH_PHASE1_COMPLETED_VERIFY_STARTING_VALUES) {
                    PrintAndLogEx(ERR, "Phase mismatch: Requested %08" PRIX32 ", Response %08" PRIX32, requestPhase, responsePhase);
                    status = PM3_ESOFT;
                    break; // out of infinite loop
                }
                // prepare to send phase 2 request
                InitializeAuthBranchData(&abd, EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY);
                uint32_t xormask = MemBeToUint4byte(&(abd.phase1_input.be_xormask[0]));
                Uint4byteToMemBe(&(abd.phase2_input.be_xormask[0]), xormask);
                remainingTimeoutsThisPhase = MAX_TIMEOUT_CYCLES_PHASE2;
                sendAdditionalCommand = true;
                // continue loop
            } else if (requestPhase == EM4X70_AUTHBRANCH_PHASE2_REQUESTED_WRITE_BRANCHED_KEY) {
                if (resp.status != PM3_SUCCESS) {
                    PrintAndLogEx(ERR, "Non-successful response status %04" PRId16 " for request phase %08" PRId32, resp.status, requestPhase);
                    status = resp.status;
                    break; // out of infinite loop
                } else if (responsePhase != EM4X70_AUTHBRANCH_PHASE2_COMPLETED_WRITE_BRANCHED_KEY) {
                    PrintAndLogEx(ERR, "Phase mismatch: Requested %08" PRIX32 ", Response %08" PRIX32, requestPhase, responsePhase);
                    status = PM3_ESOFT;
                    break; // out of infinite loop
                }

                // prepare to send first phase 3 request
                memcpy(&(abd.phase2_output), &(results->phase2_output), sizeof(results->phase2_output));
                InitializeAuthBranchData(&abd, EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE);
                uint32_t max_iterations = MemBeToUint4byte(results->phase2_output.be_max_iterations);
                uint32_t min_frn   = MemBeToUint4byte(&(abd.phase2_output.be_min_frn[0]));
                uint32_t max_frn   = MemBeToUint4byte(&(abd.phase2_output.be_max_frn[0]));

                // if user provided a start frn, use it ... else use the minimum frn to start from the beginning
                uint32_t start_frn = MemBeToUint4byte(&(abd.phase1_input.be_start_frn[0]));
                if (start_frn == 0) {
                    start_frn = min_frn;
                }

                // do we need to limit the number of iterations?
                uint32_t frn_offset = start_frn - min_frn;
                uint32_t remaining_iterations = max_iterations - frn_offset;
                uint32_t next_iterations = (remaining_iterations < FRN_ITERATIONS_PER_UPDATE) ? remaining_iterations : FRN_ITERATIONS_PER_UPDATE;
                Uint4byteToMemBe(&(abd.phase3_input.be_max_iterations[0]), next_iterations);
                Uint4byteToMemBe(&(abd.phase3_input.be_starting_frn[0]),   start_frn);

                OutputProgress(INPLACE, min_frn, max_frn, start_frn);

                remainingTimeoutsThisPhase = MAX_TIMEOUT_CYCLES_PHASE3;
                sendAdditionalCommand = true;
                // continue loop
            } else if (requestPhase == EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE) {
                if ((resp.status != PM3_SUCCESS) && (resp.status != PM3_EOPABORTED)) {
                    PrintAndLogEx(ERR, "Non-successful response status %04" PRId16 " for request phase %08" PRId32, resp.status, requestPhase);
                    status = resp.status;
                    break; // out of infinite loop
                } else if (responsePhase != EM4X70_AUTHBRANCH_PHASE3_COMPLETED_BRUTE_FORCE) {
                    PrintAndLogEx(ERR, "Phase mismatch: Requested %08" PRIX32 ", Response %08" PRIX32, requestPhase, responsePhase);
                    status = PM3_ESOFT;
                    break; // out of infinite loop
                }

                uint32_t p3o_next_frn = MemBeToUint4byte(results->phase3_output.be_next_start_frn);
                uint32_t p2o_min_frn = MemBeToUint4byte(&(abd.phase2_output.be_min_frn[0]));
                uint32_t p2o_max_frn = MemBeToUint4byte(&(abd.phase2_output.be_max_frn[0]));

                uint32_t prior_start_frn  = MemBeToUint4byte(&(abd.phase3_input.be_starting_frn[0]));
                uint32_t prior_iterations = MemBeToUint4byte(&(abd.phase3_input.be_max_iterations[0]));

                uint32_t expected_next_frn = prior_start_frn + (prior_iterations << 4); // low 4 bits are unused, so each iteration is +0x10
                OutputProgress(INPLACE, p2o_min_frn, p2o_max_frn, p3o_next_frn);

                // Handle two exit conditions: abort and found value
                if (resp.status == PM3_EOPABORTED) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(NORMAL, "To resume:");
                    PrintAndLogEx(NORMAL,
                                  "lf em 4x70 authbranch --rnd %014" PRIX64
                                  " -k %016" PRIX64 "%08" PRIX32
                                  " --frn %08" PRIX32
                                  " --xormask %08" PRIX32
                                  " --start %08" PRIX32,
                                  MemBeToUint7byte(&(abd.phase1_input.be_rnd[0])),
                                  MemBeToUint8byte(&(abd.phase1_input.be_key[0])), MemBeToUint4byte(&(abd.phase1_input.be_key[8])),
                                  MemBeToUint4byte(&(abd.phase1_input.be_frn[0])),
                                  MemBeToUint4byte(&(abd.phase1_input.be_xormask[0])),
                                  p3o_next_frn
                                 );
                    return PM3_EOPABORTED;
                }

                if (results->phase3_output.found_working_value) {
                    PrintAndLogEx(NORMAL, ""); // saves last line's output
                    return get_variations_and_dump_output(results);
                }

                // validate expectations ... if something is amiss, output information to help understand
                if ((p3o_next_frn < p2o_min_frn) || (p3o_next_frn > p2o_max_frn)) {
                    PrintAndLogEx(ERR, "Device responded with a next_frn of %08" PRIX32 ", which is outside range [%08" PRIX32 " .. %08" PRIX32 "] -- aborting",
                                  p3o_next_frn, p2o_min_frn, p2o_max_frn);
                    status = PM3_ESOFT;
                    break; // out of infinite loop
                }
                if (p3o_next_frn != expected_next_frn) {
                    PrintAndLogEx(WARNING, "Device responded with a next_frn of %08" PRIX32 ", expected %08" PRIX32 " based on prior inputs:",
                                  p3o_next_frn, expected_next_frn);
                    status = PM3_ESOFT;
                    break; // out of infinite loop
                }
                if (p3o_next_frn < prior_start_frn) {
                    PrintAndLogEx(ERR, "Device responded with a next_frn of %08" PRIX32 ", which is less than prior start frn %08" PRIX32 " -- aborting",
                                  p3o_next_frn, prior_start_frn);
                    status = PM3_ESOFT;
                    break; // out of infinite loop
                }

                uint32_t remaining_iterations = (p2o_max_frn - p3o_next_frn) >> 4; // low 4 bits are unused, so each iteration is +0x10
                if (remaining_iterations == 0) {
                    OutputProgress(INPLACE, p2o_min_frn, p2o_max_frn, p3o_next_frn);
                    PrintAndLogEx(NORMAL, "");
                    if (g_Extensive_EM4x70_AuthBranch_Debug) {
                        PrintAndLogEx(ERR, "Reached end of search space.  Inputs:");
                        DumpAuthBranchSeparator(ERR);
                        DumpAuthBranchPhase1Inputs(ERR, &abd);
                        DumpAuthBranchPhase2Inputs(ERR, &abd);
                        DumpAuthBranchPhase3Inputs(ERR, &abd);
                        PrintAndLogEx(ERR, "");
                        PrintAndLogEx(ERR, "Outputs:");
                        DumpAuthBranchSeparator(ERR);
                        DumpAuthBranchPhase2Outputs(ERR, &abd);
                        DumpAuthBranchPhase3Outputs(ERR, &abd);
                        DumpAuthBranchPhase3Outputs(ERR, results);
                    }
                    status = PM3_EFAILED;
                    break; // out of infinite loop
                }


                // Log if this is ever NOT the expected value.
                uint32_t prior_max_iterations = MemBeToUint4byte(&(abd.phase3_input.be_max_iterations[0]));
                uint32_t expected_frn   = prior_start_frn + (prior_max_iterations << 4); // low 4 bits are unused, so each iteration is +0x10...
                if (expected_frn != p3o_next_frn) {
                    PrintAndLogEx(WARNING, "Unexpected next FRN from device, expected %08" PRIX32 ", got %08" PRIX32, expected_frn, p3o_next_frn);
                }

                // prepare to send the next possible request
                InitializeAuthBranchData(&abd, EM4X70_AUTHBRANCH_PHASE3_REQUESTED_BRUTE_FORCE);
                uint32_t next_iterations = (remaining_iterations < FRN_ITERATIONS_PER_UPDATE) ? remaining_iterations : FRN_ITERATIONS_PER_UPDATE;
                Uint4byteToMemBe(&(abd.phase3_input.be_max_iterations[0]), next_iterations);
                Uint4byteToMemBe(&(abd.phase3_input.be_starting_frn[0]),   p3o_next_frn);
                remainingTimeoutsThisPhase = MAX_TIMEOUT_CYCLES_PHASE3;
                sendAdditionalCommand = true;
            } else {
                status = resp.status;
                PrintAndLogEx(ERR, "Unknown response phase: %" PRId32 " for request phase %" PRId32 " with status %d at file %s, line %d", responsePhase, requestPhase, status, __FILE__, __LINE__);
                break; // out of infinite loop
            }
        } else {
            --remainingTimeoutsThisPhase;
            if (remainingTimeoutsThisPhase <= 0) {
                status = PM3_EOPABORTED;
                PrintAndLogEx(WARNING, "\nNo response from Proxmark3. Aborting...");
                break; // out of infinite loop
            }
        }
    }

    if (status == PM3_SUCCESS) {
        PrintAndLogEx(ERR, "INTERNAL ERROR: Unexpectedly reached end of function with PM3_SUCCESS status code!?");
        if (g_Extensive_EM4x70_AuthBranch_Debug) {
            dump_authbranch_data(NORMAL, &abd, true);
        }
    } else if (status == PM3_ENOTIMPL) {
        PrintAndLogEx(WARNING, "Reach end of implemented features (PM3_ENOTIMPL), which is a type of success.");
    } else {
        if (g_Extensive_EM4x70_AuthBranch_Debug) {
            dump_authbranch_data(NORMAL, &abd, true);
        }
    }
    return PM3_ESOFT;
}

static bool Parse_CmdEM4x70AuthVars(const char *Cmd, em4x70_data_t *etd) {
    bool failedArgsParsing = false;
    memset(etd, 0, sizeof(em4x70_data_t));

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x70 auth_branch",
                  "Given a valid rnd, key, and frn, this function will\n"
                  "show the 32 trivial variations of { rnd, key, frn } values.\n"
                  "The rnd and frn values remains the same.\n"
                  "The low five bits of the key are set to to 0x00 .. 0x1F.\n"
                  "NOTE 1: This function OVERWRITES any existing key on the tag.\n"
                  "NOTE 2: Before starting, the tag MUST be unlocked.\n"
                  "NOTE 3: After running, the private key is left in an INDETERMINATE state.\n"
                  "It is the responsiblity of the user to restore any desired private key.\n",
                  "lf em 4x70 authvar -k F32AA98CF5BE4ADFA6D3480B --rnd 45F54ADA252AAC --frn 4866BB70\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_litn(NULL, "par",                 0, 1, "Add parity bit when sending commands"),                                 // 1
        arg_str1(NULL, "rnd",        "<hex>",       "Random 56-bit"),                                                        // 2
        arg_str1("k",  "key",        "<hex>",       "Crypt Key as 24 hex characters"),                                       // 3
        arg_str1(NULL, "frn",        "<hex>",       "F(RN) 28-bit as 8 hex characters (last character is padding of zero)"), // 4
        arg_param_end
    };

    if (CLIParserParseString(ctx, Cmd, argtable, arg_getsize(argtable), true)) {
        failedArgsParsing = true;
    } else {

        etd->parity = arg_get_lit(ctx, 1);

        int rnd_len = 7;
        if (CLIParamHexToBuf(arg_get_str(ctx, 2), &(etd->rnd[0]), 7, &rnd_len)) {
            // parse failed (different than non-existent parameter)
            // mandatory parameter, so mark as failure
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "rnd parameter is a mandatory hex string");
        } else if (rnd_len != 7) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "rnd parameter must be 7 bytes (got %d)", rnd_len);
        }

        int key_len = 12;
        if (CLIParamHexToBuf(arg_get_str(ctx, 3), &(etd->crypt_key[0]), 12, &key_len)) {
            // parse failed (different than non-existent parameter)
            // mandatory parameter, so mark as failure
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "key parameter is a mandatory hex string");
        } else if (key_len != 12) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "key parameter must be 12 bytes (got %d)", key_len);
        }

        int frn_len = 4;
        if (CLIParamHexToBuf(arg_get_str(ctx, 4), &(etd->frnd[0]), 4, &frn_len)) {
            // parse failed (different than non-existent parameter)
            // mandatory parameter, so mark as failure
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "frn parameter is a mandatory hex string");
        } else if (frn_len != 4) {
            failedArgsParsing = true;
            PrintAndLogEx(FAILED, "frn parameter must be 4 bytes (got %d)", frn_len);
        }
    }
    // always need to free the ctx
    CLIParserFree(ctx);
    return failedArgsParsing ? false : true;
}

int CmdEM4x70AuthVars(const char *Cmd) {

    // Authenticate transponder
    // Send 56-bit random number + pre-computed f(rnd, k) to transponder.
    // Transponder will respond with a response
    em4x70_data_t etd = {0};

    if (!Parse_CmdEM4x70AuthVars(Cmd, &etd)) {
        return PM3_EINVARG;
    }

    uint64_t rnd      = MemBeToUint7byte(&(etd.rnd[0]));
    uint64_t k_high64 = MemBeToUint8byte(&(etd.crypt_key[0]));
    uint32_t k_low32  = MemBeToUint4byte(&(etd.crypt_key[8]));
    uint32_t frn      = MemBeToUint4byte(&(etd.frnd[0]));

    trivial_variations_output_t x = {0};
    int16_t status = get_trivial_auth_variations(&etd, &x);

    if (status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Getting trivial auth variations failed: " _BRIGHT_RED_("%" PRId16), status);
        return status;
    }
    PrintAndLogEx(SUCCESS,
                  "{ \"N\": \"%014" PRIX64 "\","
                  " \"K\": \"%016"  PRIX64 "%08" PRIX32 "\","
                  " \"Ac\": \"%08"  PRIX32 "\","
                  " \"At\": ["
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", "
                  " \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\", \"%06" PRIX32 "\" ] },",
                  rnd, k_high64, k_low32, frn,
                  x.native_ac[ 0], x.native_ac[ 1], x.native_ac[ 2], x.native_ac[ 3],
                  x.native_ac[ 4], x.native_ac[ 5], x.native_ac[ 6], x.native_ac[ 7],
                  x.native_ac[ 8], x.native_ac[ 9], x.native_ac[10], x.native_ac[11],
                  x.native_ac[12], x.native_ac[13], x.native_ac[14], x.native_ac[15],
                  x.native_ac[16], x.native_ac[17], x.native_ac[18], x.native_ac[19],
                  x.native_ac[20], x.native_ac[21], x.native_ac[22], x.native_ac[23],
                  x.native_ac[24], x.native_ac[25], x.native_ac[26], x.native_ac[27],
                  x.native_ac[28], x.native_ac[29], x.native_ac[30], x.native_ac[31]
                 );

//         { "N": "3FFE1FB6CC513F", "K": "A090A0A02080000000000000", "Ac": "F355F1A0", "Ats": [ "609D60", "645270", "609990", "6451C0",  "69DA70", "6F90D0", "69DD20", "6F92D0",  "65A9D0", "60A360", "65ADD0", "60A540",  "6C29F0", "6BE610", "6C2CF0", "6BE0A0",  "6101F0", "65FAD0", "610310", "65FA60",  "68CBF0", "6E0FB0", "68CBA0", "6E0AB0",  "6DDA00", "69B130", "6DDA00", "69B030",  "649C10", "629790", "649DD0", "629790"] },
    return PM3_SUCCESS;
}

// trivial_variations_t tv = {0};
// memcpy(&(tv.be_key[0]), &(abd.phase2_output.be_key[0]), 12);
// tv.useParity = abd.phase1_input.useParity;
// memcpy(&(tv.be_rnd[0]), &(abd.phase1_input.be_rnd[0]), 7);
// memcpy(&(tv.be_frn[0]), &(results->phase3_output.be_successful_frn[0]), 4);

// status = TrivialVariations_CmdEM4x70AuthBranch(&tv);
// if (status == PM3_SUCCESS) {
//     PrintAndLogEx(SUCCESS,
//         " = ["
//         "%08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         ",  %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32 ", %08" PRIX32
//         " ] },",
//         tv.ac[ 0], tv.ac[ 1], tv.ac[ 2], tv.ac[ 3],
//         tv.ac[ 4], tv.ac[ 5], tv.ac[ 6], tv.ac[ 7],
//         tv.ac[ 8], tv.ac[ 9], tv.ac[10], tv.ac[11],
//         tv.ac[12], tv.ac[13], tv.ac[14], tv.ac[15],
//         tv.ac[16], tv.ac[17], tv.ac[18], tv.ac[19],
//         tv.ac[20], tv.ac[21], tv.ac[22], tv.ac[23],
//         tv.ac[24], tv.ac[25], tv.ac[26], tv.ac[27],
//         tv.ac[28], tv.ac[29], tv.ac[30], tv.ac[31]
//     );
//     return PM3_SUCCESS;
// } else {
//     PrintAndLogEx(ERR, "Trivial 32x authentications failed %" PRId16, status);
//     return status;
// }

static bool Parse_CmdEM4x70DebugLevel(const char *Cmd, em4x70_debug_options_t *debug_options) {
    bool failedArgsParsing = false;
    memset(debug_options, 0, sizeof(em4x70_debug_options_t));

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf em 4x70 debug",
                  "Sets em4x70 specific debug options.\n"
                  "NOTE: Command 0x0263 == CMD_LF_EM4X70_AUTH\n"
                  "NOTE: Flags 0x8000 == Function Entry / Function Exit\n"
                  "\n",
                  "lf em 4x70 debug -l 0 -f 0\n"
                  "lf em 4x70 debug -l 5 -c 0263\n"
                  "lf em 4x70 debug --level 5 --command 0263\n"
                  "lf em 4x70 debug --level 3 --flags 8000\n"
                  "lf em 4x70 debug --level 2 --flags 8000 --command 0263\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1("l", "level",        "<hex>",       "Set debug level (hex value)"),             // 1
        arg_str1("f", "flags",        "<hex>",       "Set flags (e.g., which parts to debug)"),  // 2
        arg_str1("c", "command",      "<hex>",       "Use settings only for specified command"), // 3
        arg_lit0("t", "timings",                     "Dump recent timings"),                     // 4
        arg_param_end
    };

    if (CLIParserParseString(ctx, Cmd, argtable, arg_getsize(argtable), true)) {
        failedArgsParsing = true;
    } else {
        bool at_least_one_option_exists = false;
        if (true) { // level   -- Essentially CLIParamHexToBuf_BigEndian, allowing variable-length hex from client
            enum {
                option_index = 1,  // where is "level" in the argtable?
                max_length = 4,    // how many bytes for this buffer?
            };
            int parameter_bytes = 0;  // how many bytes converted from hex?
            uint8_t* buffer = &(debug_options->be_level[0]);

            // since it's a string argument type, length == 0 means caller did not provide the value
            if (CLIParamHexToBuf(arg_get_str(ctx, option_index), buffer, max_length, &parameter_bytes)) {
                // parse failed (different than non-existent parameter)
                failedArgsParsing = true;
            } else if (parameter_bytes == 0) {
                // optional parameter was *not* provided
            } else if (parameter_bytes > max_length) {
                failedArgsParsing = true; // should never occur
            } else {
                // some hex bytes provided ... shift the result and zero-fill so it's a single big-endian value
                // first, copy/align existing bytes to end of buffer
                // memmove() handles potentially overlapping buffers (and equal pointers too)
                memmove(&(buffer[max_length-parameter_bytes]), &(buffer[0]), parameter_bytes);
                // then, zero-fill the starting bytes (memset() can be called with size of zero)
                memset(&(buffer[0]), 0, max_length - parameter_bytes);

                debug_options->is_setting_level = 1;
                at_least_one_option_exists = true;
            }
        }
        if (true) { // flags   -- Essentially CLIParamHexToBuf_BigEndian, allowing variable-length hex from client
            enum {
                option_index = 2,  // where is "flags" in the argtable?
                max_length = 4,    // how many bytes for this buffer?
            };
            int parameter_bytes = 0;  // how many bytes converted from hex?
            uint8_t* buffer = &(debug_options->be_flags[0]);

            // since it's a string argument type, length == 0 means caller did not provide the value
            if (CLIParamHexToBuf(arg_get_str(ctx, option_index), buffer, max_length, &parameter_bytes)) {
                // parse failed (different than non-existent parameter)
                failedArgsParsing = true;
            } else if (parameter_bytes == 0) {
                // optional parameter was *not* provided
            } else if (parameter_bytes > max_length) {
                failedArgsParsing = true; // should never occur
            } else {
                // some hex bytes provided ... shift the result and zero-fill so it's a single big-endian value
                // first, copy/align existing bytes to end of buffer
                // memmove() handles potentially overlapping buffers (and equal pointers too)
                memmove(&(buffer[max_length-parameter_bytes]), &(buffer[0]), parameter_bytes);
                // then, zero-fill the starting bytes (memset() can be called with size of zero)
                memset(&(buffer[0]), 0, max_length - parameter_bytes);

                debug_options->is_setting_flags = 1;
                at_least_one_option_exists = true;
            }
        }
        if (true) { // command -- Essentially CLIParamHexToBuf_BigEndian, allowing variable-length hex from client
            enum {
                option_index = 1,  // where is "level" in the argtable?
                max_length = 2,    // how many bytes for this buffer?
            };
            int parameter_bytes = 0;  // how many bytes converted from hex?
            uint8_t* buffer = &(debug_options->be_single_command_code[0]);

            // since it's a string argument type, length == 0 means caller did not provide the value
            if (CLIParamHexToBuf(arg_get_str(ctx, option_index), buffer, max_length, &parameter_bytes)) {
                // parse failed (different than non-existent parameter)
                failedArgsParsing = true;
            } else if (parameter_bytes == 0) {
                // optional parameter was *not* provided
            } else if (parameter_bytes > max_length) {
                failedArgsParsing = true; // should never occur
            } else {
                // some hex bytes provided ... shift the result and zero-fill so it's a single big-endian value
                // first, copy/align existing bytes to end of buffer
                // memmove() handles potentially overlapping buffers (and equal pointers too)
                memmove(&(buffer[max_length-parameter_bytes]), &(buffer[0]), parameter_bytes);
                // then, zero-fill the starting bytes (memset() can be called with size of zero)
                memset(&(buffer[0]), 0, max_length - parameter_bytes);

                debug_options->is_only_for_single_command_code = 1;
                at_least_one_option_exists = true;
            }
        }
        if (true) { // timings -- Essentially just checks if arg was provided
            int count = arg_get_lit(ctx, 4);
            if (count != 0) {
                debug_options->is_request_to_dump_recent_timings = 1;
                at_least_one_option_exists = true;
            }
        }
        if (!at_least_one_option_exists) {
            failedArgsParsing = true;
        }
    }
    // always need to free the ctx
    CLIParserFree(ctx);
    
    return failedArgsParsing ? false : true;
}

int CmdEM4x70DebugLevel(const char *Cmd) {
    em4x70_debug_options_t debug_options;
    if (!Parse_CmdEM4x70DebugLevel(Cmd, &debug_options)) {
        return PM3_EINVARG;
    }
    // TODO: send to ProxMark3 device
    return PM3_ENOTIMPL;
}