//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency FDX-A FECAVA Destron tag commands
//-----------------------------------------------------------------------------
#include "cmdlfdestron.h"

#include <ctype.h>          //tolower
#include <string.h>         // memcpy
#include "commonutil.h"     // ARRAYLEN
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"    // preamble test
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..
#include "cmdlf.h"      // cmdlfconfig
#include "cliparser.h" // cli parse input
#include "parity.h"

#define DESTRON_FRAME_SIZE 96
#define DESTRON_PREAMBLE_SIZE 16

static int CmdHelp(const char *Cmd);

int demodDestron(bool verbose) {
    (void) verbose; // unused so far
    //PSK1
    if (FSKrawDemod(0, 0, 0, 0, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: FSK Demod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectDestron(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, DESTRON_FRAME_SIZE, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    uint8_t bits[DESTRON_FRAME_SIZE - DESTRON_PREAMBLE_SIZE] = {0};
    size_t bitlen = DESTRON_FRAME_SIZE - DESTRON_PREAMBLE_SIZE;
    memcpy(bits, DemodBuffer + 16, DESTRON_FRAME_SIZE - DESTRON_PREAMBLE_SIZE);

    uint8_t alignPos = 0;
    uint16_t errCnt = manrawdecode(bits, &bitlen, 0, &alignPos);
    if (errCnt > 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: Manchester decoding errors: %d", ans);
        return PM3_ESOFT;
    }

    uint8_t data[5] = {0};
    uint8_t parity_err = 0;
    for (int i = 0; i < sizeof(data); i++) {
        data[i] = bytebits_to_byte(bits + i * 8, 8);
        parity_err += oddparity8(data[i]);
        data[i] &= 0x7F;
    }
    if (parity_err > 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Destron: parity errors: %d", parity_err);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "FDX-A FECAVA Destron: " _GREEN_("%02X%02X%02X%02X%02X"), data[0], data[1], data[2], data[3], data[4]);
    return PM3_SUCCESS;
}

static int CmdDestronDemod(const char *Cmd) {
    (void)Cmd;
    return demodDestron(true);
}

static int CmdDestronRead(const char *Cmd) {
    lf_read(false, 16000);
    return demodDestron(true);
}

static int CmdDestronClone(const char *Cmd) {

    uint32_t blocks[4] = {0};
    uint8_t data[8];
    int datalen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf destron clone",
                  "Enables cloning of Destron card with specified uid onto T55x7",
                  "lf destron clone 1A2B3C4D5E"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx1(NULL, NULL, "<uid (hex)>", NULL),
        arg_param_end
    };

    //TODO add selection of chip for Q5 or T55x7
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    CLIGetHexWithReturn(ctx, 1, data, &datalen);
    CLIParserFree(ctx);

    uint8_t data_ex[12 + 24] = {0}; // ManchesterEncode need extra room
    for (int i = 0; i < datalen; i++) {
        data_ex[i + 1] = ~(data [i] | (oddparity8(data[i]) << 7));
    }
    for (int i = 0; i < 3; i++) {
        blocks[i + 1] = manchesterEncode2Bytes((data_ex[i * 2] << 8) + data_ex[i * 2 + 1]);
    }
    // inject preamble
    blocks[1] = (blocks[1] & 0xFFFF) | 0xAAE20000;

    PrintAndLogEx(INFO, "Preparing to clone Destron tag with ID: %s", sprint_hex(data, datalen));
    blocks[0] = T55x7_BITRATE_RF_50 | T55x7_MODULATION_FSK2 | 3 << T55x7_MAXBLOCK_SHIFT;

    print_blocks(blocks, ARRAYLEN(blocks));
    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf Destron read`") " to verify");
    return res;
}

static int CmdDestronSim(const char *Cmd) {

    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdDestronDemod,  AlwaysAvailable, "Demodulate an Destron tag from the GraphBuffer"},
    {"read",  CmdDestronRead,   IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdDestronClone,  IfPm3Lf,         "Clone Destron tag to T55x7"},
    {"sim",   CmdDestronSim,    IfPm3Lf,         "Simulate Destron tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFDestron(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find Destron preamble in already demoded data
int detectDestron(uint8_t *dest, size_t *size) {

    //make sure buffer has data
    if (*size < 64)
        return -1;

    size_t found_size = *size;
    size_t start_idx = 0;

    uint8_t preamble[DESTRON_PREAMBLE_SIZE] =  {1, 0, 1, 0, 1, 0, 1, 0, 1, 1, 1, 0, 0, 0, 1, 0};

    // preamble not found
    if (!preambleSearch(dest, preamble, sizeof(preamble), &found_size, &start_idx)) {
        return -2;
    }
    PrintAndLogEx(DEBUG, "DEBUG: detectDestron FSK found preamble");

    *size = found_size;
    // wrong demoded size
    if (*size != 96)
        return -3;

    return (int)start_idx;
}

int readDestronUid(void) {
    return (CmdDestronRead("") == PM3_SUCCESS);
}
