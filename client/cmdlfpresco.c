//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------

#include "cmdlfpresco.h"

#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest
#include "cmdlft55xx.h" // verifywrite

static int CmdHelp(const char *Cmd);

static int usage_lf_presco_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Presco tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf presco clone [h] d <Card-ID> c <hex-ID> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h             : this help");
    PrintAndLogEx(NORMAL, "  d <Card-ID>   : 9 digit presco card ID");
    PrintAndLogEx(NORMAL, "  c <hex-ID>    : 8 digit hex card number");
    PrintAndLogEx(NORMAL, "  <Q5>          : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf presco clone d 123456789");
    return PM3_SUCCESS;
}

static int usage_lf_presco_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of presco card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "Per presco format, the card number is 9 digit number and can contain *# chars. Larger values are truncated.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf presco sim [h] d <Card-ID> or c <hex-ID>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h             : this help");
    PrintAndLogEx(NORMAL, "  d <Card-ID>   : 9 digit presco card number");
    PrintAndLogEx(NORMAL, "  c <hex-ID>    : 8 digit hex card number");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf presco sim d 123456789");
    return PM3_SUCCESS;
}

//see ASKDemod for what args are accepted
static int CmdPrescoDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    bool st = true;
    if (ASKDemod_ext("32 0 0 0 0 a", false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error Presco ASKDemod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectPresco(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: ans: %d", ans);
        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 128, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);
    uint32_t raw4 = bytebits_to_byte(DemodBuffer + 96, 32);
    uint32_t cardid = raw4;
    PrintAndLogEx(SUCCESS, "Presco Tag Found: Card ID %08X, Raw: %08X%08X%08X%08X", cardid, raw1, raw2, raw3, raw4);

    uint32_t sitecode = 0, usercode = 0, fullcode = 0;
    bool Q5 = false;
    char cmd[12] = {0};
    sprintf(cmd, "H %08X", cardid);
    getWiegandFromPresco(cmd, &sitecode, &usercode, &fullcode, &Q5);
    PrintAndLogEx(SUCCESS, "SiteCode %u, UserCode %u, FullCode, %08X", sitecode, usercode, fullcode);
    return PM3_SUCCESS;
}

//see ASKDemod for what args are accepted
static int CmdPrescoRead(const char *Cmd) {
    // Presco Number: 123456789 --> Sitecode 30 | usercode 8665
    lf_read(false, 12000);
    return CmdPrescoDemod(Cmd);
}

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
static int CmdPrescoClone(const char *Cmd) {

    bool Q5 = false;
    uint32_t sitecode = 0, usercode = 0, fullcode = 0;
    uint32_t blocks[5] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT | T55x7_ST_TERMINATOR, 0, 0, 0, 0};

    // get wiegand from printed number.
    if (getWiegandFromPresco(Cmd, &sitecode, &usercode, &fullcode, &Q5) == PM3_EINVARG) return usage_lf_presco_clone();

    if (Q5)
        blocks[0] = T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(32) | 4 << T5555_MAXBLOCK_SHIFT | T5555_ST_TERMINATOR;

    if ((sitecode & 0xFF) != sitecode) {
        sitecode &= 0xFF;
        PrintAndLogEx(INFO, "Facility-Code Truncated to 8-bits (Presco): %u", sitecode);
    }

    if ((usercode & 0xFFFF) != usercode) {
        usercode &= 0xFFFF;
        PrintAndLogEx(INFO, "Card Number Truncated to 16-bits (Presco): %u", usercode);
    }

    blocks[1] = 0x10D00000; //preamble
    blocks[2] = 0x00000000;
    blocks[3] = 0x00000000;
    blocks[4] = fullcode;

    PrintAndLogEx(INFO, "Preparing to clone Presco to T55x7 with SiteCode: %u, UserCode: %u, FullCode: %08x", sitecode, usercode, fullcode);
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
static int CmdPrescoSim(const char *Cmd) {
    uint32_t sitecode = 0, usercode = 0, fullcode = 0;
    bool Q5 = false;
    // get wiegand from printed number.
    if (getWiegandFromPresco(Cmd, &sitecode, &usercode, &fullcode, &Q5) == PM3_EINVARG)
        return usage_lf_presco_sim();

    PrintAndLogEx(SUCCESS, "Simulating Presco - SiteCode: %u, UserCode: %u, FullCode: %08X", sitecode, usercode, fullcode);

    uint8_t bs[128];
    getPrescoBits(fullcode, bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 1;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "This help"},
    {"read",    CmdPrescoRead,  IfPm3Lf,         "Attempt to read and Extract tag data"},
    {"clone",   CmdPrescoClone, IfPm3Lf,         "clone presco tag to T55x7 (or to q5/T5555)"},
    {"sim",     CmdPrescoSim,   IfPm3Lf,         "simulate presco tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFPresco(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find presco preamble 0x10D in already demoded data
int detectPresco(uint8_t *dest, size_t *size) {
    if (*size < 128 * 2) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 0, 0, 1, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

// convert base 12 ID to sitecode & usercode & 8 bit other unknown code
int getWiegandFromPresco(const char *Cmd, uint32_t *sitecode, uint32_t *usercode, uint32_t *fullcode, bool *Q5) {

    bool hex = false, errors = false;
    uint8_t cmdp = 0;
    char id[11];
    int stringlen = 0;
    memset(id, 0x00, sizeof(id));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return PM3_EINVARG;
            case 'c':
                hex = true;
                //get hex
                *fullcode = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'd':
                //param get string int param_getstr(const char *line, int paramnum, char * str)
                stringlen = param_getstr(Cmd, cmdp + 1, id, sizeof(id));
                if (stringlen < 2) return PM3_EINVARG;
                cmdp += 2;
                break;
            case 'q':
                *Q5 = true;
                cmdp++;
                break;
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = 1;
                break;
        }
    }
    //Validations
    if (errors || cmdp == 0) return PM3_EINVARG;

    if (!hex) {
        uint8_t val = 0;
        for (int index = 0; index < strlen(id); ++index) {
            // Get value from number string.
            if (id[index] == '*')
                val = 10;
            if (id[index] == '#')
                val = 11;
            if (id[index] >= 0x30 && id[index] <= 0x39)
                val = id[index] - 0x30;

            *fullcode += val;

            // last digit is only added, not multipled.
            if (index < strlen(id) - 1)
                *fullcode *= 12;
        }
    }

    *usercode = *fullcode & 0x0000FFFF; //% 65566
    *sitecode = (*fullcode >> 24) & 0x000000FF;  // /= 16777216;
    return PM3_SUCCESS;
}

// calc not certain - intended to get bitstream for programming / sim
int getPrescoBits(uint32_t fullcode, uint8_t *prescoBits) {
    num_to_bytebits(0x10D00000, 32, prescoBits);
    num_to_bytebits(0x00000000, 32, prescoBits + 32);
    num_to_bytebits(0x00000000, 32, prescoBits + 64);
    num_to_bytebits(fullcode, 32, prescoBits + 96);
    return PM3_SUCCESS;
}

int demodPresco(void) {
    return CmdPrescoDemod("");
}

