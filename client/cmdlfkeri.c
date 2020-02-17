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

#include <string.h>
#include <inttypes.h>

#include <ctype.h>
#include <stdlib.h>

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // preamble test
#include "cmdlft55xx.h" // verifywrite

static int CmdHelp(const char *Cmd);

static int usage_lf_keri_clone(void) {
    PrintAndLogEx(NORMAL, "clone a KERI tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf keri clone [h] <id> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <id>       : Keri Internal ID");
    PrintAndLogEx(NORMAL, "      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf keri clone 112233");
    return PM3_SUCCESS;
}

static int usage_lf_keri_sim(void) {
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
    return PM3_SUCCESS;
}

typedef enum  {Scramble = 0,Descramble = 1} KeriMSScramble_t;

static int CmdKeriMSScramble (KeriMSScramble_t Action, uint32_t *FC, uint32_t *ID, uint32_t *CardID)
{
    uint8_t CardToID [] = { 0xff,0xff,0xff,0xff,0x0d,0x0c,0x11,0x05,0xff,0x06,0xff,0x12,0x08,0xff,0x00,0x07,
                            0x0a,0xff,0xff,0x0b,0x04,0x01,0xff,0x13,0xff,0x14,0x02,0xff,0x03,0x09,0xff,0xff };
    uint8_t CardToFC [] = { 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                            0xff,0xff,0x02,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0x01,0xff };

    uint8_t IDToCard [] = { 0x0e,0x15,0x1a,0x1c,0x14,0x07,0x09,0x0f,0x0c,0x1d,0x10,0x13,0x05,0x04,0xff,0xff,
                            0xff,0x06,0x0b,0x17,0x19,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };
    uint8_t FCToCard [] = { 0xff,0x1e,0x12,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
                            0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff };

    uint8_t CardIdx; // 0 - 31
    bool BitState;
    int idx;

    if (Action == Descramble) {
        char IDDecodeState[33] = {0x00};
        char FCDecodeState[33] = {0x00};

        memset (IDDecodeState,'-',32);
        memset (FCDecodeState,'-',32);

        *FC = 0;
        *ID = 0;

        for (CardIdx = 0; CardIdx < 32; CardIdx++) {
            // Get Bit State
            BitState = (*CardID >> CardIdx) & 1;
            //if (BitState) { // its a 1   
            idx = CardToID[CardIdx];
            if ((idx >= 0) && (idx <= 32)) {
                if (BitState)
                    *ID = *ID | (1 << idx);
                IDDecodeState[31-idx] = '0'+BitState;
            }

            idx = CardToFC[CardIdx];
            if ((idx >= 0) && (idx <= 32)) {
                if (BitState)
                    *FC = *FC | (1 << idx);
                FCDecodeState[31-idx] = '0'+BitState;
            }
        }

        // Patch for bit order group unknown
        // Reverse order for easy mapping for unknowns
        // I know that these bit groups are a in the correct location, unknown order.
        if (IDDecodeState[31-17] == '1') IDDecodeState[31-17] = '?';
        if (IDDecodeState[31-18] == '1') IDDecodeState[31-18] = '?';
        if (IDDecodeState[31-19] == '1') IDDecodeState[31-19] = '?';
        if (IDDecodeState[31-20] == '1') IDDecodeState[31-20] = '?';
    
        if (FCDecodeState[31- 1] == '1') FCDecodeState[31- 1] = '?';
        if (FCDecodeState[31- 2] == '1') FCDecodeState[31- 2] = '?';

        PrintAndLogEx(SUCCESS, "BitState ID : %s",IDDecodeState);
        PrintAndLogEx(SUCCESS, "BitState FC : %s",FCDecodeState);
    }
    if (Action == Scramble)
    {
        // PrintAndLogEx(SUCCESS, "Scramble FC : %d - ID %d",*FC,*ID);
        *CardID = 0; // set to 0

        for (CardIdx = 0; CardIdx < 32; CardIdx++) 
        {
            // Card ID 
            BitState = (*ID >> CardIdx) & 1;
            if (BitState) {
                idx = IDToCard[CardIdx];
                if ((idx >= 0) && (idx <= 32)) {
                    *CardID |= (1 << idx);
                }
            }
            // FC 
            BitState = (*FC >> CardIdx) & 1;
            if (BitState) {
                idx = FCToCard[CardIdx];
                if ((idx >= 0) && (idx <= 32)) {
                    *CardID |= (1 << idx);
                }
            }
        }
        // Fixed bits
        /*
            Add Parity and Fixed bits
            Bit  3 - Note Used/Fixed 1
            Bit 31 - 1 Fixed
            Bit  0,1 - 2 Bit Parity
        */
        *CardID |= (1 <<  3);
        // Check/Parity Bits
        int Parity = 1;
        for (CardIdx = 4; CardIdx <= 31; CardIdx += 2) {
            Parity = Parity ^ ((*CardID >> CardIdx) & 11);
        }
        *CardID = *CardID | Parity;

        // Bit 31 was fixed but not in check/parity bits
        *CardID |= (1 << 31); 
    
        PrintAndLogEx(SUCCESS, "Scrambled FC : %d - Card ID : %d to RAW : E0000000%08X",*FC,*ID,*CardID);
    }
    return PM3_SUCCESS;
}

static int CmdKeriDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    if (PSKDemod("", false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: PSK1 Demod failed");
        return PM3_ESOFT;
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
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: Size not correct: 64 != %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: ans: %d", idx);

        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, size, idx);
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
/*
    Descramble Data.
*/
    uint32_t fc = 0;
    uint32_t cardid = 0;

    // Just need to the low 32 bits without the 111 trailer
    CmdKeriMSScramble (Descramble,&fc,&cardid,&raw2);

    PrintAndLogEx (SUCCESS,"Descrambled MS : FC %d - Card ID %d\n",fc,cardid);
    
    uint32_t testCard = 0;
    CmdKeriMSScramble (Scramble,&fc,&cardid,&testCard);
// End Descramble test

    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably KERI");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;

        CmdPrintDemodBuff("x");
    }
    return PM3_SUCCESS;
}

static int CmdKeriRead(const char *Cmd) {
    lf_read(false, 10000);
    return CmdKeriDemod(Cmd);
}

static int CmdKeriClone(const char *Cmd) {

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
    PrintAndLogEx(INFO, "Preparing to clone KERI to T55x7 with Internal Id: %" PRIx32, internalid);

    blocks[1] = data >> 32;
    blocks[2] = data & 0xFFFFFFFF;

    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdKeriSim(const char *Cmd) {

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h')
        return usage_lf_keri_sim();

    uint64_t internalid = param_get32ex(Cmd, 0, 0, 10);
    internalid |= 0x80000000;
    internalid <<= 3;
    internalid += 7;

    uint8_t bs[64] = {0x00};
    // loop to bits
    uint8_t j = 0;
    for (int8_t i = 63; i >= 0; --i) {
        bs[j++] = ((internalid >> i) & 1);
    }

    PrintAndLogEx(SUCCESS, "Simulating KERI - Internal Id: %" PRIu64, internalid);

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier =  2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    PrintAndLogEx(INFO, "Simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_LF_PSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_PSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,      AlwaysAvailable, "This help"},
    {"demod", CmdKeriDemod, AlwaysAvailable, "Demodulate an KERI tag from the GraphBuffer"},
    {"read",  CmdKeriRead,  IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdKeriClone, IfPm3Lf,         "clone KERI tag to T55x7 (or to q5/T5555)"},
    {"sim",   CmdKeriSim,   IfPm3Lf,         "simulate KERI tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFKeri(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find KERI preamble in already demoded data
int detectKeri(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[] = {1, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

    // sanity check.
    if (*size < sizeof(preamble) + 100) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx)) {

        // if didn't find preamble try again inverting
        uint8_t preamble_i[] = {0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
        if (!preambleSearch(DemodBuffer, preamble_i, sizeof(preamble_i), size, &startIdx))
            return -2;

        *invert ^= 1;
    }

    if (*size != 64) return -3; //wrong demoded size

    return (int)startIdx;
}

int demodKeri(void) {
    return CmdKeriDemod("");
}

