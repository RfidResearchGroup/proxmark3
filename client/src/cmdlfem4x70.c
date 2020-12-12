//-----------------------------------------------------------------------------
// Copyright (C) 2020 sirloins
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

#define BYTES2UINT16(x) ((x[1] << 8) | (x[0]))
#define BYTES2UINT32(x) ((x[3] << 24) | (x[2] << 16) | (x[1] << 8) | (x[0]))


static int CmdHelp(const char *Cmd);

static void print_info_result(uint8_t *data) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Tag Information") " ---------------------------");
    PrintAndLogEx(INFO, "-------------------------------------------------------------");

    // data section
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, _YELLOW_("EM4x70 data:"));

    for (int i = 1; i <= 32; i += 2) {
        PrintAndLogEx(NORMAL, "%02X %02X", data[32 - i], data[32 - i - 1]);
    }
    PrintAndLogEx(NORMAL, "Tag ID: %02X %02X %02X %02X", data[7], data[6], data[5], data[4]);
    PrintAndLogEx(NORMAL, "Lockbit 0: %d %s", (data[3] & 0x40) ? 1 : 0, (data[3] & 0x40) ? "LOCKED" : "UNLOCKED");
    PrintAndLogEx(NORMAL, "Lockbit 1: %d", (data[3] & 0x80) ? 1 : 0);
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
        PrintAndLogEx(WARNING, "(em4x70) timeout while waiting for reply.");
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
                  "lf em 4x70 write -b 15 -d c0de -> write 'c0de' to block 15\n"
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

    int addr = arg_get_int(ctx, 2);

    int word_len = 0;
    uint8_t word[2] = {0x0};
    CLIGetHexWithReturn(ctx, 3, word, &word_len);

    CLIParserFree(ctx);

    if (addr < 0 || addr >= EM4X70_NUM_BLOCKS) {
        PrintAndLogEx(FAILED, "block has to be within range [0, 15]");
        return PM3_EINVARG;
    }

    if (word_len != 2) {
        PrintAndLogEx(FAILED, "word/data length must be 2 bytes instead of %d", word_len);
        return PM3_EINVARG;
    }

    etd.address = (uint8_t) addr;
    etd.word = BYTES2UINT16(word);;

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

static command_t CommandTable[] = {
    {"help",   CmdHelp,         AlwaysAvailable, "This help"},
    {"info",   CmdEM4x70Info,   IfPm3EM4x70,     "Tag information EM4x70"},
    {"write",  CmdEM4x70Write,  IfPm3EM4x70,     "Write EM4x70"},
    {"unlock", CmdEM4x70Unlock, IfPm3EM4x70,     "Unlock EM4x70 for writing"},
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
