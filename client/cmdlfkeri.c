//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency KERI tag commands
// PSK1, RF/128, RF/2, 64 bits long
//-----------------------------------------------------------------------------
#include "cmdlfkeri.h"

static int CmdHelp(const char *Cmd);

int usage_lf_keri_clone(void) {
    PrintAndLogEx(NORMAL, "clone a KERI tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf keri clone [h] <id> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <id>       : Keri Internal ID");
    PrintAndLogEx(NORMAL, "      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf keri clone 112233");
    return 0;
}

int usage_lf_keri_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of KERI card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf keri sim [h] <id>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <id>       : Keri Internal ID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf keri sim 112233");
    return 0;
}

// find KERI preamble in already demoded data
int detectKeri(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};
    uint8_t preamble_i[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};

    // sanity check.
    if (*size < sizeof(preamble) + 100) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx)) {

        // if didn't find preamble try again inverting
        if (!preambleSearch(DemodBuffer, preamble_i, sizeof(preamble_i), size, &startIdx))
            return -2;

        *invert ^= 1;
    }

    if (*size != 64) return -3; //wrong demoded size

    return (int)startIdx;
}

int CmdKeriDemod(const char *Cmd) {

    if (!PSKDemod("", false)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: PSK1 Demod failed");
        return 0;
    }
    bool invert = false;
    size_t size = DemodBufferLen;
    int idx = detectKeri(DemodBuffer, &size, &invert);
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: too few bits found");
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: preamble not found");
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: Size not correct: 64 != %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: ans: %d", idx);

        return 0;
    }
    setDemodBuf(DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);

    //get internal id
    uint32_t ID = bytebits_to_byte(DemodBuffer + 29, 32);
    ID &= 0x7FFFFFFF;

    /*
        000000000000000000000000000001XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX111
        ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^1###############################^^^
        Preamble block 29 bits of ZEROS
        32 bit Internal ID  (First bit always 1)
        3 bit of 1s in the end

        How this is decoded to Facility ID, Card number is unknown
        Facility ID =  0-31  (indicates 5 bits)
        Card number = up to 10 digits

        Might be a hash of FC & CN to generate Internal ID
    */

    PrintAndLogEx(SUCCESS, "KERI Tag Found -- Internal ID: %u", ID);
    PrintAndLogEx(SUCCESS, "Raw: %08X%08X", raw1, raw2);

    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably KERI");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;

        CmdPrintDemodBuff("x");
    }
    return 1;
}

int CmdKeriRead(const char *Cmd) {
    lf_read(true, 10000);
    return CmdKeriDemod(Cmd);
}

int CmdKeriClone(const char *Cmd) {

    uint32_t internalid = 0;
    uint32_t blocks[3] = {
        T55x7_TESTMODE_DISABLED |
        T55x7_X_MODE |
        T55x7_MODULATION_PSK1 |
        T55x7_PSKCF_RF_2 |
        2 << T55x7_MAXBLOCK_SHIFT,
          0,
          0
    };

    // dynamic bitrate used
    blocks[0] |= 0xF << 18;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_keri_clone();

    internalid = param_get32ex(Cmd, 0, 0, 10);

    //Q5
    if (tolower(param_getchar(Cmd, 1)) == 'q') {
        blocks[0] =
            T5555_MODULATION_PSK1 |
            T5555_SET_BITRATE(128) |
            T5555_PSK_RF_2 |
            2 << T5555_MAXBLOCK_SHIFT;
    }


    // MSB is ONE
    internalid |= 0x80000000;

    // 3 LSB is ONE
    uint64_t data = ((uint64_t)internalid << 3) + 7;

    //
    blocks[1] = data >> 32;
    blocks[2] = data & 0xFFFFFFFF;

    PrintAndLogEx(INFO, "Preparing to clone KERI to T55x7 with Internal Id: %u", internalid);
    print_blocks(blocks, 3);


    UsbCommand resp;
    UsbCommand c = {CMD_T55XX_WRITE_BLOCK, {0, 0, 0}};


    for (uint8_t i = 0; i < 3; i++) {
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

int CmdKeriSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_keri_sim();

    uint64_t internalid = param_get32ex(Cmd, 0, 0, 10);
    internalid |= 0x80000000;
    internalid <<= 3;
    internalid += 7;

    uint8_t bits[64] = {0x00};
    // loop to bits
    uint8_t j = 0;
    for (int8_t i = 63; i >= 0; --i) {
        bits[j++] = ((internalid >> i) & 1);
    }

    uint8_t clk = 32, carrier = 2, invert = 0;
    uint16_t arg1, arg2;
    size_t size = 64;
    arg1 = clk << 8 | carrier;
    arg2 = invert;

    PrintAndLogEx(SUCCESS, "Simulating KERI - Internal Id: %u", internalid);

    UsbCommand c = {CMD_PSK_SIM_TAG, {arg1, arg2, size}};
    memcpy(c.d.asBytes, bits, size);
    clearCommandBuffer();
    SendCommand(&c);

    return 0;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,      1, "This help"},
    {"demod", CmdKeriDemod, 1, "Demodulate an KERI tag from the GraphBuffer"},
    {"read",  CmdKeriRead,  0, "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdKeriClone, 0, "clone KERI to T55x7"},
    {"sim",   CmdKeriSim,   0, "simulate KERI tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFKeri(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
