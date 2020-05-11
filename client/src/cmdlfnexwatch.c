//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Honeywell NexWatch tag commands
// PSK1 RF/16, RF/2, 128 bits long (known)
//-----------------------------------------------------------------------------

#include "cmdlfnexwatch.h"
#include <inttypes.h>       // PRIu
#include <string.h>
#include <ctype.h>          // tolower
#include <stdlib.h>         // free, alloc

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"      // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"        // preamblesearch
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"      // t55xx defines
#include "cmdlft55xx.h"     // clone..

static int CmdHelp(const char *Cmd);

static int usage_lf_nexwatch_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Nexwatch tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf nexwatch clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h             : this help");
    PrintAndLogEx(NORMAL, "      r <raw hex>   : raw hex data. 16 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nexwatch clone r 5600000000213C9F8F150C");
    return PM3_SUCCESS;
}

static int usage_lf_nexwatch_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Nexwatch card");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf nexwatch sim [h] <r raw hex>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h            : this help");
    PrintAndLogEx(NORMAL, "      r <raw hex>  : raw hex data. 16 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf nexwatch sim r 5600000000213C9F8F150C");
    return PM3_SUCCESS;
}
/*
static inline uint32_t bitcount(uint32_t a) {
#if defined __GNUC__
   return __builtin_popcountl(a);
#else
   a = a - ((a >> 1) & 0x55555555);
   a = (a & 0x33333333) + ((a >> 2) & 0x33333333);
   return (((a + (a >> 4)) & 0x0f0f0f0f) * 0x01010101) >> 24;
#endif
}
*/
int demodNexWatch(void) {
    if (PSKDemod("", false) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch can't demod signal");
        return PM3_ESOFT;
    }
    bool invert = false;
    size_t size = DemodBufferLen;
    int idx = detectNexWatch(DemodBuffer, &size, &invert);
    if (idx <= 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch not enough samples");
        // else if (idx == -2)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch only noise found");
        // else if (idx == -3)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch problem during PSK demod");
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch preamble not found");
        // else if (idx == -5)
        // PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch size not correct: %d", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - NexWatch error %d", idx);

        return PM3_ESOFT;
    }

    // skip the 4 first bits from the nexwatch preamble identification (we use 4 extra zeros..)
    idx += 4;
    
    setDemodBuff(DemodBuffer, size, idx);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (idx * g_DemodClock));
    
    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably NexKey");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;
    }

    // get rawid
    uint32_t rawid = 0;
    for (uint8_t k = 0; k < 4; k++) {
        for (uint8_t m = 0; m < 8; m++) {
            rawid = (rawid << 1) | DemodBuffer[m + k + (m * 4)];
        }
    }

    /*
    Descrambled id    
    
    ref::  http://www.proxmark.org/forum/viewtopic.php?pid=14662#p14662
    
    32bit UID:     00100100011001000011111100010010

    bits numbered from left (MSB):
    1234 5678 9012 34567 8901234567890 12
    0010 0100 0110 0100 00111111000100 10

    descramble:
    b1 b5 b9 b13   b17 b21 b25 b29   b2 b6 b10 b14   b18 b22 b26 b30   b3 b7 b11 b15   b19 b23 b27 b31   b4 b8 b12 b16   b20 b24 b28 b32

    gives:
    0000 0100 0111 0100 1010 1101 0000 1110  =  74755342
    */

// Since the description is not zero indexed we adjust.
#define DOFFSET  8 + 32 - 1
    
    // descrambled id
    uint32_t d_id = 0;
    // b1 b5 b9 b13 
    d_id |= DemodBuffer[DOFFSET + 1] << 31;
    d_id |= DemodBuffer[DOFFSET + 5] << 30;
    d_id |= DemodBuffer[DOFFSET + 9] << 29;
    d_id |= DemodBuffer[DOFFSET + 13] << 28;

    // b17 b21 b25 b29
    d_id |= DemodBuffer[DOFFSET + 17] << 27;
    d_id |= DemodBuffer[DOFFSET + 21] << 26;
    d_id |= DemodBuffer[DOFFSET + 25] << 25;
    d_id |= DemodBuffer[DOFFSET + 29] << 24;

    // b2 b6 b10 b14
    d_id |= DemodBuffer[DOFFSET + 2] << 23;
    d_id |= DemodBuffer[DOFFSET + 6] << 22;
    d_id |= DemodBuffer[DOFFSET + 10] << 21;
    d_id |= DemodBuffer[DOFFSET + 14] << 20;

    // b18 b22 b26 b30 
    d_id |= DemodBuffer[DOFFSET + 18] << 19;
    d_id |= DemodBuffer[DOFFSET + 22] << 18;
    d_id |= DemodBuffer[DOFFSET + 26] << 17;
    d_id |= DemodBuffer[DOFFSET + 30] << 16;

    // b3 b7 b11 b15  
    d_id |= DemodBuffer[DOFFSET + 3] << 15;
    d_id |= DemodBuffer[DOFFSET + 7] << 14;
    d_id |= DemodBuffer[DOFFSET + 11] << 13;
    d_id |= DemodBuffer[DOFFSET + 15] << 12;

    // b19 b23 b27 b31
    d_id |= DemodBuffer[DOFFSET + 19] << 11;
    d_id |= DemodBuffer[DOFFSET + 23] << 10;
    d_id |= DemodBuffer[DOFFSET + 27] << 9;
    d_id |= DemodBuffer[DOFFSET + 31] << 8;

    // b4 b8 b12 b16
    d_id |= DemodBuffer[DOFFSET + 4] << 7;
    d_id |= DemodBuffer[DOFFSET + 8] << 6;
    d_id |= DemodBuffer[DOFFSET + 12] << 5;
    d_id |= DemodBuffer[DOFFSET + 16] << 4;
    
    // b20 b24 b28 b32
    d_id |= DemodBuffer[DOFFSET + 20] << 3;
    d_id |= DemodBuffer[DOFFSET + 24] << 2;
    d_id |= DemodBuffer[DOFFSET + 28] << 1;
    d_id |= DemodBuffer[DOFFSET + 32];

    uint8_t mode = bytebits_to_byte(DemodBuffer + 72, 4);
    
    // parity check 
    // from 32 hex id, 4 mode,  descramble par (1234) -> (4231)
    uint8_t xor_par = 0;
    for (uint8_t i = 40; i < 76; i +=4) {
        xor_par ^= bytebits_to_byte(DemodBuffer + i, 4);
    }
    
    uint8_t calc_parity ;   
    calc_parity =  (((xor_par >> 3 ) & 1) );
    calc_parity |= (((xor_par >> 1 ) & 1) << 1);
    calc_parity |= (((xor_par >> 2 ) & 1) << 2);
    calc_parity |=  ((xor_par & 1) << 3);
    
    uint8_t parity = bytebits_to_byte(DemodBuffer + 76, 4);

    /*
    Checksum:::
        1. Subtract every byte from ID field using an unsigned, one byte register:
           1F - 15 - A5 - 6D = 0xF6

        2. Subtract BE from the result:
           0xF6 - 0xBE  = 3A

        3. Reverse the bits of a parity nibble:
           5(0101) -> (1010) A

        4. Subtract the reversed parity from the result:
           3A - A = 30 -> 00110000


        5. Reverse the bits:
           00001100 -> 0C
    */
    
    /*
    uint8_t calc;
    calc = ((d_id >> 24) & 0xFF);
    calc -= ((d_id >> 16) & 0xFF);
    calc -= ((d_id >> 8) & 0xFF);
    calc -= (d_id & 0xFF);
    
    PrintAndLogEx(NORMAL, "Sum:  0x%02x", calc);

     uint8_t a[] = {0xbe, 0xbc, 0x88, 0x86 };
    for (uint8_t c=0; c < ARRAYLEN(a); c++) {
        uint8_t b = calc;
        b -= a[c];
        PrintAndLogEx(NORMAL, "Subtract [0x%02X] : 0x%02X", a[c], b);
        b -= revpar;
        PrintAndLogEx(NORMAL, "Subtract revpar   : 0x%02X", b);
        PrintAndLogEx(NORMAL, "reversed          : 0x%02X", reflect8(b));
    }

    calc -= 0xBE;
    PrintAndLogEx(NORMAL, "--after 0xBE:  %02x", calc);
    calc -= revpar;
    PrintAndLogEx(NORMAL, "--before reverse:  %02x", calc);
    calc = reflect8(calc);
    */
        
//    uint8_t chk = bytebits_to_byte(DemodBuffer + 80, 8);


    // output
    PrintAndLogEx(SUCCESS, " NexWatch raw id : " _YELLOW_("0x%"PRIx32) , rawid);
    PrintAndLogEx(SUCCESS, "        88bit id : " _YELLOW_("%"PRIu32) " "  _YELLOW_("0x%"PRIx32), d_id, d_id);
    PrintAndLogEx(SUCCESS, "            mode : %x", mode);  
    PrintAndLogEx(SUCCESS, "          parity : %s  [%X == %X]", (parity == calc_parity) ? _GREEN_("ok") : _RED_("fail"), parity, calc_parity);
//    PrintAndLogEx(NORMAL,  "        checksum : %02x == %02x", calc, chk);

    // bits to hex  (output used for SIM/CLONE cmd)
     CmdPrintDemodBuff("x");
//    PrintAndLogEx(INFO, "Raw: %s", sprint_hex_inrow(DemodBuffer, size));
    return PM3_SUCCESS;
}

static int CmdNexWatchDemod(const char *Cmd) {
    (void)Cmd;
    return demodNexWatch();
}

//by marshmellow
//see ASKDemod for what args are accepted
static int CmdNexWatchRead(const char *Cmd) {
    lf_read(false, 20000);
    return CmdNexWatchDemod(Cmd);
}

static int CmdNexWatchClone(const char *Cmd) {

    // 56000000 00213C9F 8F150C00 00000000
    uint32_t blocks[5];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_nexwatch_clone();
            case 'r': {
                // skip first block,  4*4 = 16 bytes left
                uint8_t rawhex[16] = {0};
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

    if (errors || cmdp == 0) return usage_lf_nexwatch_clone();

    //Nexwatch - compat mode, PSK, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_PSK1 | T55x7_BITRATE_RF_32 | 4 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone NexWatch to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf nexwatch read`") " to verify");
    return res;
}

static int CmdNexWatchSim(const char *Cmd) {

    uint8_t cmdp = 0;
    bool errors = false;
    int rawlen = 0;
    uint8_t rawhex[16] = {0};
    uint32_t rawblocks[4];
    uint8_t bs[128];
    memset(bs, 0, sizeof(bs));

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_nexwatch_clone();
            case 'r': {
                int res = param_gethex_to_eol(Cmd, cmdp + 1, rawhex, sizeof(rawhex), &rawlen);
                if (res != 0)
                    errors = true;

                cmdp += 2;
                break;
            }
            default:
                PrintAndLogEx(WARNING, "Unknown parameter '%c'", param_getchar(Cmd, cmdp));
                errors = true;
                break;
        }
    }

    if (errors || cmdp == 0) return usage_lf_nexwatch_sim();

    // hex to bits.
    for (size_t i = 0; i < ARRAYLEN(rawblocks); i++) {
        rawblocks[i] = bytes_to_num(rawhex + (i * sizeof(uint32_t)), sizeof(uint32_t));
        num_to_bytebits(rawblocks[i], sizeof(uint32_t) * 8, bs + (i * sizeof(uint32_t) * 8));
    }

    PrintAndLogEx(SUCCESS, "Simulating NexWatch - raw: %s", sprint_hex_inrow(rawhex, rawlen));

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier = 2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

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
    {"help",  CmdHelp,           AlwaysAvailable, "This help"},
    {"demod", CmdNexWatchDemod,  AlwaysAvailable, "Demodulate a NexWatch tag (nexkey, quadrakey) from the GraphBuffer"},
    {"read",  CmdNexWatchRead,   IfPm3Lf,         "Attempt to Read and Extract tag data from the antenna"},
    {"clone", CmdNexWatchClone,  IfPm3Lf,         "clone NexWatch tag to T55x7"},
    {"sim",   CmdNexWatchSim,    IfPm3Lf,         "simulate NexWatch tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNEXWATCH(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int detectNexWatch(uint8_t *dest, size_t *size, bool *invert) {

    uint8_t preamble[28]   = {0, 0, 0, 0, 0, 1, 0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    // sanity check.
    if (*size < sizeof(preamble) + 100) return -1;

    size_t startIdx = 0;

    if (!preambleSearch(DemodBuffer, preamble, sizeof(preamble), size, &startIdx)) {
        // if didn't find preamble try again inverting
        uint8_t preamble_i[28] = {1, 1, 1, 1, 1, 0, 1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
        if (!preambleSearch(DemodBuffer, preamble_i, sizeof(preamble_i), size, &startIdx)) return -4;
        *invert ^= 1;
    }

    // size tests?
    return (int) startIdx;
}
