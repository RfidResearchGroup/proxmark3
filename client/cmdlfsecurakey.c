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

#include <string.h>         // memcpy
#include <ctype.h>          // tolower

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"      // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"    // preamble test
#include "parity.h"     // for wiegand parity test
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..

static int CmdHelp(const char *Cmd);

static int usage_lf_securakey_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Securakey tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf securakey clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf securakey clone 7FCB400001ADEA5344300000");
    return PM3_SUCCESS;
}

//see ASKDemod for what args are accepted
static int CmdSecurakeyDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    //ASK / Manchester
    bool st = false;
    if (ASKDemod_ext("40 0 0", false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: ASK/Manchester Demod failed");
        return PM3_ESOFT;
    }
    if (st)
        return PM3_ESOFT;

    size_t size = DemodBufferLen;
    int ans = detectSecurakey(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Securakey: ans: %d", ans);
        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 96, ans);
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
        PrintAndLogEx(DEBUG, "DEBUG: Error removeParity: %zu", size);
        return 0;
    }

    uint8_t bitLen = (uint8_t)bytebits_to_byte(bits_no_spacer + 2, 6);
    uint32_t fc = 0, lWiegand = 0, rWiegand = 0;
    if (bitLen > 40) { //securakey's max bitlen is 40 bits...
        PrintAndLogEx(DEBUG, "DEBUG: Error bitLen too long: %u", bitLen);
        return PM3_ESOFT;
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
    return PM3_SUCCESS;
}

static int CmdSecurakeyRead(const char *Cmd) {
    lf_read(false, 8000);
    return CmdSecurakeyDemod(Cmd);
}

static int CmdSecurakeyClone(const char *Cmd) {

    uint32_t blocks[4];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_securakey_clone();
            case 'b': {
                // skip first block,  3*4 = 12 bytes left
                uint8_t rawhex[12] = {0};
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &datalen);
                if (res != 0)
                    errors = true;

                for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
                    blocks[i] = bytes_to_num(rawhex + ((i - 1) * 4), sizeof(uint32_t));
                }
                cmdp += 2;
                break;
            }
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_lf_securakey_clone();

    //Securakey - compat mode, ASK/Man, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_40 | 3 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone Securakey to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdSecurakeySim(const char *Cmd) {
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdSecurakeyDemod, AlwaysAvailable, "Demodulate an Securakey tag from the GraphBuffer"},
    {"read",  CmdSecurakeyRead,  IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdSecurakeyClone, IfPm3Lf,         "clone Securakey tag to T55x7"},
    {"sim",   CmdSecurakeySim,   IfPm3Lf,         "simulate Securakey tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFSecurakey(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

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

int demodSecurakey(void) {
    return CmdSecurakeyDemod("");
}

