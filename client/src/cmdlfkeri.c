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
#include "commonutil.h"   // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "cliparser.h"
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"    // for T55xx config register definitions
#include "lfdemod.h"      // preamble test
#include "cmdlft55xx.h"   // verifywrite
#include "cmdlfem4x05.h"  // 

static int CmdHelp(const char *Cmd);
typedef enum  {Scramble = 0, Descramble = 1} KeriMSScramble_t;

static int CmdKeriMSScramble(KeriMSScramble_t Action, uint32_t *FC, uint32_t *ID, uint32_t *CardID) {
    // 255 = Not used/Unknown other values are the bit offset in the ID/FC values
    uint8_t CardToID [] = { 255, 255, 255, 255, 13, 12, 20,  5, 16,  6, 21, 17,  8, 255,  0,  7,
                            10, 15, 255, 11,  4,  1, 255, 18, 255, 19,  2, 14,  3,  9, 255, 255
                          };

    uint8_t CardToFC [] = { 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255, 255,  0, 255, 255,
                            255, 255,  2, 255, 255, 255,  3, 255,  4, 255, 255, 255, 255, 255,  1, 255
                          };

    uint8_t CardIdx; // 0 - 31
    bool BitState;

    if (Action == Descramble) {
        *FC = 0;
        *ID = 0;
        for (CardIdx = 0; CardIdx < 32; CardIdx++) {
            // Get Bit State
            BitState = (*CardID >> CardIdx) & 1;
            // Card ID
            if (CardToID[CardIdx] < 32) {
                *ID = *ID | (BitState << CardToID[CardIdx]);
            }
            // Card FC
            if (CardToFC[CardIdx] < 32) {
                *FC = *FC | (BitState << CardToFC[CardIdx]);
            }
        }
    }

    if (Action == Scramble) {
        *CardID = 0; // set to 0

        for (CardIdx = 0; CardIdx < 32; CardIdx++) {
            // Card ID
            if (CardToID[CardIdx] < 32) {
                if ((*ID & (1 << CardToID[CardIdx])) > 0)
                    *CardID |= (1 << CardIdx);
            }
            // Card FC
            if (CardToFC[CardIdx] < 32) {
                if ((*FC & (1 << CardToFC[CardIdx])) > 0)
                    *CardID |= (1 << CardIdx);
            }
        }

        // Fixed bits and parity/check bits
        /*
            Add Parity and Fixed bits
            Bit  3 - Note Used/Fixed 1 - TBC
            Bit 31 - 1 Fixed Not in check/parity
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
        *CardID |= 1UL << 31;

        PrintAndLogEx(SUCCESS, "Scrambled MS - FC: " _GREEN_("%d") " Card: " _GREEN_("%d") ", Raw: E0000000%08X", *FC, *ID, *CardID);
    }
    return PM3_SUCCESS;
}

int demodKeri(bool verbose) {
    (void) verbose; // unused so far

    if (PSKDemod(0, 0, 100, false) != PM3_SUCCESS) {
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


    /*
        Descramble Data.
    */
    uint32_t fc = 0;
    uint32_t cardid = 0;
    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);

    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably KERI");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;

        raw1 = bytebits_to_byte(DemodBuffer, 32);
        raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    
        CmdPrintDemodBuff("x");
    }

    //get internal id
    // uint32_t ID = bytebits_to_byte(DemodBuffer + 29, 32);
    // Due to the 3 sync bits being at the start of the capture
    // We can take the last 32bits as the internal ID.
    uint32_t ID = raw2;
    ID &= 0x7FFFFFFF;

    PrintAndLogEx(SUCCESS, "KERI - Internal ID: " _GREEN_("%u") ", Raw: %08X%08X", ID, raw1, raw2);
    
    // Just need to the low 32 bits without the 111 trailer
    CmdKeriMSScramble(Descramble, &fc, &cardid, &raw2);

    PrintAndLogEx(SUCCESS, "Descrambled MS - FC: " _GREEN_("%d") " Card: " _GREEN_("%d"), fc, cardid);
    return PM3_SUCCESS;
}

static int CmdKeriDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return demodKeri(true);
}

static int CmdKeriRead(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    lf_read(false, 10000);
    return demodKeri(true);
}

static int CmdKeriClone(const char *Cmd) {

    bool q5 = false, em = false;

    uint8_t keritype[2] = {'i'}; // default to internalid
    int typeLen = 0;
    uint32_t fc = 0;
    uint32_t cid = 0;
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

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf keri clone",
                  "clone a KERI tag to a T55x7, Q5/T5555 or EM4305/4469 tag",
                  "lf keri clone -t i --id 12345\n"
                  "lf keri clone -t m --fc 6 --id 12345\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("q",  "q5",            "specify writing to Q5/T5555 tag"),
        arg_str0("t",  "type", "<m|i>", "Type m - MS, i - Internal ID"),
        arg_int0(NULL, "fc",   "<dec>", "Facility Code"),
        arg_int1(NULL, "id",   "<dec>", "Keri ID"),
        arg_lit0(NULL,  "em",           "specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    char cardtype[16] = {"T55x7"};
    if (arg_get_lit(ctx, 1)) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_PSK1 | T5555_SET_BITRATE(32) | T5555_PSK_RF_2 | 2 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype) ,"Q5/T5555");
        q5 = true;
    }
    if (arg_get_lit(ctx, 5)) {
        blocks[0] = EM4305_KERI_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype) ,"EM4305/4469");
        em = true;
    }

    typeLen = sizeof(keritype);
    CLIGetStrWithReturn(ctx, 2, keritype, &typeLen);

    fc = arg_get_int_def(ctx, 3, 0);
    cid = arg_get_int_def(ctx, 4, 0);
    CLIParserFree(ctx);
    
    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    // Setup card data/build internal id
    switch (keritype[0]) {
        case 'i' : // Internal ID
            // MSB is ONE
            internalid = cid | 0x80000000;
            break;
        case 'm' : // MS
            CmdKeriMSScramble(Scramble, &fc, &cid, &internalid);
            break;
        default  :
            PrintAndLogEx(ERR, "Invalid type");
            return PM3_EINVARG;
    }

    // Prepare and write to card
    // 3 LSB is ONE
    uint64_t data = ((uint64_t)internalid << 3) + 7;
    PrintAndLogEx(INFO, "Preparing to clone KERI to " _YELLOW_("%s") " with Internal Id " _YELLOW_("%" PRIx32), cardtype, internalid);

    blocks[1] = data >> 32;
    blocks[2] = data & 0xFFFFFFFF;

    print_blocks(blocks,  ARRAYLEN(blocks));

    int res;
    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf keri read`") " to verify");
    return res;
}

static int CmdKeriSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf keri sim",
                  "Enables simulation of KERI card with card number.",
                  "lf keri sim --id 112233"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "id", "<dec>", "KERI Internal ID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint64_t internalid = arg_get_int_def(ctx, 1, 0);

    CLIParserFree(ctx);

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
    {"clone", CmdKeriClone, IfPm3Lf,         "clone KERI tag to T55x7 or Q5/T5555"},
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
    if (*size < sizeof(preamble)) return -1;

    size_t startIdx = 0;
    size_t found_size = *size;

    if (!preambleSearch(dest, preamble, sizeof(preamble), &found_size, &startIdx)) {

        found_size = *size;
        // if didn't find preamble try again inverting
        uint8_t preamble_i[] = {0, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
        if (!preambleSearch(DemodBuffer, preamble_i, sizeof(preamble_i), &found_size, &startIdx))
            return -2;

        *invert ^= 1;
    }

    if (found_size < 64) return -3; //wrong demoded size

    *size = found_size;

    return (int)startIdx;
}

