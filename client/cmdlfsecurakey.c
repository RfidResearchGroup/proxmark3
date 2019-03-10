//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Securakey tag commands
// ASK/Manchester, RF/40, 96 bits long (unknown cs)
//-----------------------------------------------------------------------------
#include "cmdlfsecurakey.h"

static int CmdHelp(const char *Cmd);

// by marshmellow
// find Securakey preamble in already demoded data
int detectSecurakey(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

//see ASKDemod for what args are accepted
int CmdSecurakeyDemod(const char *Cmd) {

    //ASK / Manchester
    bool st = false;
    if (!ASKDemod_ext("40 0 0", false, false, 1, &st)) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: ASK/Manchester Demod failed");
        return 0;
    }
    if (st) return 0;
    size_t size = DemodBufferLen;
    int ans = detectSecurakey(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: Size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: ans: %d", ans);
        return 0;
    }
    setDemodBuf(DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);

    // 26 bit format
    // preamble     ??bitlen   reserved        EPx   xxxxxxxy   yyyyyyyy   yyyyyyyOP  CS?        CS2?
    // 0111111111 0 01011010 0 00000000 0 00000010 0 00110110 0 00111110 0 01100010 0 00001111 0 01100000 0 00000000 0 0000

    // 32 bit format
    // preamble     ??bitlen   reserved  EPxxxxxxx   xxxxxxxy   yyyyyyyy   yyyyyyyOP  CS?        CS2?
    // 0111111111 0 01100000 0 00000000 0 10000100 0 11001010 0 01011011 0 01010110 0 00010110 0 11100000 0 00000000 0 0000

    // x = FC?
    // y = card #
    // standard wiegand parities.
    // unknown checksum 11 bits? at the end
    uint8_t bits_no_spacer[85];
    memcpy(bits_no_spacer, DemodBuffer + 11, 85);

    // remove marker bits (0's every 9th digit after preamble) (pType = 3 (always 0s))
    size = removeParity(bits_no_spacer, 0, 9, 3, 85);
    if (size != 85 - 9) {
        PrintAndLogEx(DEBUG, "DEBUG: Error removeParity: %d", size);
        return 0;
    }

    uint8_t bitLen = (uint8_t)bytebits_to_byte(bits_no_spacer + 2, 6);
    uint32_t fc = 0, lWiegand = 0, rWiegand = 0;
    if (bitLen > 40) { //securakey's max bitlen is 40 bits...
        PrintAndLogEx(DEBUG, "DEBUG: Error bitLen too long: %u", bitLen);
        return 0;
    }
    // get left 1/2 wiegand & right 1/2 wiegand (for parity test and wiegand print)
    lWiegand = bytebits_to_byte(bits_no_spacer + 48 - bitLen, bitLen / 2);
    rWiegand = bytebits_to_byte(bits_no_spacer + 48 - bitLen + bitLen / 2, bitLen / 2);
    // get FC
    fc = bytebits_to_byte(bits_no_spacer + 49 - bitLen, bitLen - 2 - 16);

    // test bitLen
    if (bitLen != 26 && bitLen != 32)
        PrintAndLogEx(NORMAL, "***unknown securakey bitLen - share with forum***");

    uint32_t cardid = bytebits_to_byte(bits_no_spacer + 8 + 23, 16);
    // test parities - evenparity32 looks to add an even parity returns 0 if already even...
    bool parity = !evenparity32(lWiegand) && !oddparity32(rWiegand);

    PrintAndLogEx(SUCCESS, "Securakey Tag Found--BitLen: %u, Card ID: %u, FC: 0x%X, Raw: %08X%08X%08X", bitLen, cardid, fc, raw1, raw2, raw3);
    if (bitLen <= 32)
        PrintAndLogEx(SUCCESS, "Wiegand: %08X, Parity: %s", (lWiegand << (bitLen / 2)) | rWiegand, parity ? "Passed" : "Failed");
    PrintAndLogEx(INFO, "\nHow the FC translates to printed FC is unknown");
    PrintAndLogEx(INFO, "How the checksum is calculated is unknown");
    PrintAndLogEx(INFO, "Help the community identify this format further\n by sharing your tag on the pm3 forum or with forum members");
    return 1;
}

int CmdSecurakeyRead(const char *Cmd) {
    lf_read(true, 8000);
    return CmdSecurakeyDemod(Cmd);
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,          1, "This help"},
    {"demod", CmdSecurakeyDemod, 1, "Demodulate an Securakey tag from the GraphBuffer"},
    {"read",  CmdSecurakeyRead, 0, "Attempt to read and extract tag data from the antenna"},
    //{"clone", CmdSecurakeyClone,0, "clone Securakey tag"},
    //{"sim",   CmdSecurakeydSim, 0, "simulate Securakey tag"},
    {NULL, NULL, 0, NULL}
};

int CmdLFSecurakey(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}
