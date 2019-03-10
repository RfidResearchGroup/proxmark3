//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Presco tag commands
//-----------------------------------------------------------------------------

#include "cmdlfpresco.h"
static int CmdHelp(const char *Cmd);

int usage_lf_presco_clone(void) {
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
    return 0;
}

int usage_lf_presco_sim(void) {
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
    return 0;
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
int GetWiegandFromPresco(const char *Cmd, uint32_t *sitecode, uint32_t *usercode, uint32_t *fullcode, bool *Q5) {

    uint8_t val = 0;
    bool hex = false, errors = false;
    uint8_t cmdp = 0;
    char id[11];
    int stringlen = 0;
    memset(id, 0x00, sizeof(id));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return -1;
            case 'c':
                hex = true;
                //get hex
                *fullcode = param_get32ex(Cmd, cmdp + 1, 0, 16);
                cmdp += 2;
                break;
            case 'd':
                //param get string int param_getstr(const char *line, int paramnum, char * str)
                stringlen = param_getstr(Cmd, cmdp + 1, id, sizeof(id));
                if (stringlen < 2) return -1;
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
    if (errors || cmdp == 0) return -1;

    if (!hex) {
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
    return 0;
}

// calc not certain - intended to get bitstream for programming / sim
int GetPrescoBits(uint32_t fullcode, uint8_t *prescoBits) {
    num_to_bytebits(0x10D00000, 32, prescoBits);
    num_to_bytebits(0x00000000, 32, prescoBits + 32);
    num_to_bytebits(0x00000000, 32, prescoBits + 64);
    num_to_bytebits(fullcode, 32, prescoBits + 96);
    return 1;
}

//see ASKDemod for what args are accepted
int CmdPrescoDemod(const char *Cmd) {
    bool st = true;
    if (!ASKDemod_ext("32 0 0 0 0 a", false, false, 1, &st)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error Presco ASKDemod failed");
        return 0;
    }
    size_t size = DemodBufferLen;
    int ans = detectPresco(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: Size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Presco: ans: %d", ans);
        return 0;
    }
    setDemodBuf(DemodBuffer, 128, ans);
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
    GetWiegandFromPresco(cmd, &sitecode, &usercode, &fullcode, &Q5);
    PrintAndLogEx(SUCCESS, "SiteCode %u, UserCode %u, FullCode, %08X", sitecode, usercode, fullcode);
    return 1;
}

//see ASKDemod for what args are accepted
int CmdPrescoRead(const char *Cmd) {
    // Presco Number: 123456789 --> Sitecode 30 | usercode 8665
    lf_read(true, 12000);
    return CmdPrescoDemod(Cmd);
}

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
int CmdPrescoClone(const char *Cmd) {

    bool Q5 = false;
    uint32_t sitecode = 0, usercode = 0, fullcode = 0;
    uint32_t blocks[5] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT | T55x7_ST_TERMINATOR, 0, 0, 0, 0};

    // get wiegand from printed number.
    if (GetWiegandFromPresco(Cmd, &sitecode, &usercode, &fullcode, &Q5) == -1) return usage_lf_presco_clone();

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
    print_blocks(blocks, 5);

    UsbCommand resp;
    UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0, 0, 0}};

    for (uint8_t i = 0; i < 5; i++) {
        c.arg[0] = blocks[i];
        c.arg[1] = i;
        clearCommandBuffer();
        SendCommand(&c);
        if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)) {
            PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
            return -1;
        }
    }
    return 0;
}

// takes base 12 ID converts to hex
// Or takes 8 digit hex ID
int CmdPrescoSim(const char *Cmd) {
    uint32_t sitecode = 0, usercode = 0, fullcode = 0;
    bool Q5 = false;
    // get wiegand from printed number.
    if (GetWiegandFromPresco(Cmd, &sitecode, &usercode, &fullcode, &Q5) == -1) return usage_lf_presco_sim();

    uint8_t clk = 32, encoding = 1, separator = 1, invert = 0;
    uint16_t arg1, arg2;
    size_t size = 128;
    arg1 = clk << 8 | encoding;
    arg2 = invert << 8 | separator;

    PrintAndLogEx(SUCCESS, "Simulating Presco - SiteCode: %u, UserCode: %u, FullCode: %08X", sitecode, usercode, fullcode);

    UsbCommand c = {CMD_ASK_SIM_TAG, {arg1, arg2, size}};
    GetPrescoBits(fullcode, c.d.asBytes);
    clearCommandBuffer();
    SendCommand(&c);
    return 0;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        1, "This help"},
    {"read",    CmdPrescoRead,  0, "Attempt to read and Extract tag data"},
    {"clone",   CmdPrescoClone, 0, "clone presco tag"},
    {"sim",     CmdPrescoSim,   0, "simulate presco tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFPresco(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
