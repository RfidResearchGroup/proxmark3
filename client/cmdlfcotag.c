//-----------------------------------------------------------------------------
// Authored by Iceman
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency COTAG commands
//-----------------------------------------------------------------------------
#include "cmdlfcotag.h"  // COTAG function declarations

static int CmdHelp(const char *Cmd);

static int usage_lf_cotag_read(void) {
    PrintAndLogEx(NORMAL, "Usage: lf COTAG read [h] <signaldata>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <0|1|2>    : 0 - HIGH/LOW signal; maxlength bigbuff");
    PrintAndLogEx(NORMAL, "                 : 1 - translation of HI/LO into bytes with manchester 0,1");
    PrintAndLogEx(NORMAL, "                 : 2 - raw signal; maxlength bigbuff");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Example:");
    PrintAndLogEx(NORMAL, "        lf cotag read 0");
    PrintAndLogEx(NORMAL, "        lf cotag read 1");
    return PM3_SUCCESS;
}

// COTAG demod should be able to use GraphBuffer,
// when data load samples
static int CmdCOTAGDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    uint8_t bits[COTAG_BITS] = {0};
    size_t bitlen = COTAG_BITS;
    memcpy(bits, DemodBuffer, COTAG_BITS);

    uint8_t alignPos = 0;
    uint16_t err = manrawdecode(bits, &bitlen, 1, &alignPos);
    if (err > 50) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - COTAG too many errors: %d", err);
        return PM3_ESOFT;
    }

    setDemodBuff(bits, bitlen, 0);

    //got a good demod
    uint16_t cn = bytebits_to_byteLSBF(bits + 1, 16);
    uint32_t fc = bytebits_to_byteLSBF(bits + 1 + 16, 8);

    uint32_t raw1 = bytebits_to_byteLSBF(bits, 32);
    uint32_t raw2 = bytebits_to_byteLSBF(bits + 32, 32);
    uint32_t raw3 = bytebits_to_byteLSBF(bits + 64, 32);
    uint32_t raw4 = bytebits_to_byteLSBF(bits + 96, 32);

    /*
    fc 161:   1010 0001 -> LSB 1000 0101
    cn 33593  1000 0011 0011 1001 -> LSB 1001 1100 1100 0001
        cccc cccc cccc cccc                     ffffffff
      0 1001 1100 1100 0001 1000 0101 0000 0000 100001010000000001111011100000011010000010000000000000000000000000000000000000000000000000000000100111001100000110000101000
        1001 1100 1100 0001                     10000101
    */
    PrintAndLogEx(SUCCESS, "COTAG Found: FC %u, CN: %u Raw: %08X%08X%08X%08X", fc, cn, raw1, raw2, raw3, raw4);
    return PM3_SUCCESS;
}

// When reading a COTAG.
// 0 = HIGH/LOW signal - maxlength bigbuff
// 1 = translation for HI/LO into bytes with manchester 0,1 - length 300
// 2 = raw signal -  maxlength bigbuff
static int CmdCOTAGRead(const char *Cmd) {

    if (Cmd[0] == 'h' || Cmd[0] == 'H') return usage_lf_cotag_read();

    uint32_t rawsignal = 1;
    sscanf(Cmd, "%u", &rawsignal);

    clearCommandBuffer();
    SendCommandMIX(CMD_COTAG, rawsignal, 0, 0, NULL, 0);
    if (!WaitForResponseTimeout(CMD_ACK, NULL, 7000)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    switch (rawsignal) {
        case 0:
        case 2: {
            CmdPlot("");
            CmdGrid("384");
            getSamples(0, true);
            break;
        }
        case 1: {

            if (!GetFromDevice(BIG_BUF, DemodBuffer, COTAG_BITS, 0, NULL, 1000, false)) {
                PrintAndLogEx(WARNING, "timeout while waiting for reply.");
                return PM3_ETIMEOUT;
            }
            DemodBufferLen = COTAG_BITS;
            return CmdCOTAGDemod("");
        }
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",      CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",     CmdCOTAGDemod,   AlwaysAvailable, "Tries to decode a COTAG signal"},
    {"read",      CmdCOTAGRead,    IfPm3Lf,         "Attempt to read and extract tag data"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFCOTAG(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int demodCOTAG(void) {
    return CmdCOTAGDemod("");
}

int readCOTAGUid(void) {
    return (CmdCOTAGRead("") == PM3_SUCCESS);
}
