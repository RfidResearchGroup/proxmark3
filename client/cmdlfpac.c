//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Stanley/PAC tag commands
// NRZ, RF/32, 128 bits long (unknown cs)
//-----------------------------------------------------------------------------
#include "cmdlfpac.h"

static int CmdHelp(const char *Cmd);

//see NRZDemod for what args are accepted
static int CmdPacDemod(const char *Cmd) {

    //NRZ
    if (NRZrawDemod(Cmd, false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: NRZ Demod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectPac(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: Size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - PAC: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 128, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);
    uint32_t raw4 = bytebits_to_byte(DemodBuffer + 96, 32);

    // preamble     then appears to have marker bits of "10"                                                                                                                                       CS?
    // 11111111001000000 10 01001100 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 00001101 10 10001100 10 100000001
    // unknown checksum 9 bits at the end

    PrintAndLogEx(NORMAL, "PAC/Stanley Tag Found -- Raw: %08X%08X%08X%08X", raw1, raw2, raw3, raw4);
    PrintAndLogEx(NORMAL, "\nHow the Raw ID is translated by the reader is unknown");
    return PM3_SUCCESS;
}

static int CmdPacRead(const char *Cmd) {
    lf_read(true, 4096 * 2 + 20);
    return CmdPacDemod(Cmd);
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,     AlwaysAvailable, "This help"},
    {"demod", CmdPacDemod, AlwaysAvailable, "Demodulate an PAC tag from the GraphBuffer"},
    {"read",  CmdPacRead,  IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFPac(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by marshmellow
// find PAC preamble in already demoded data
int detectPac(uint8_t *dest, size_t *size) {
    if (*size < 128) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 128) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodPac(void) {
    return CmdPacDemod("");
}

