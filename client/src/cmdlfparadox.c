//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Paradox tag commands
// FSK2a, rf/50, 96 bits (completely known)
// Below section is edited by jumpycalm, last modified date 20200712
// Example of raw 
// Block0 = 0x00107060 (Always use this for Paradox)
// Block1 = 0x0F555555 = 0000 1111 0101 0101 0101 0101 0101 0101
// Manchester demod                                          0 0
//                       [Premble 14 bits-----------------] [Start of FC 8 bit
// Block2 = 0x5666A9AA = 0101 0110 0110 0110 1010 1001 1010 1010
// Manchester demod       0 0  0 1  0 1  0 1  1 1  1 0  1 1  1 1
//                    End of FC 8 bits] [Start of CN 16 bits
// Block3 = 0xA6A5AA6A = 1010 0110 1010 0101 1010 1010 0110 1010
// Manchester demod       1 1  0 1  1 1  0 0  1 1  1 1  0 1
//                   End of CN 16 bits] [Checksum 8 bits--] [End, always 1010]
// In the above example, FC is 0x05 or 5n, CN is 0x7BF7 or 31735n Checksum is 0x3D
// Therefore the Paradox ID is 0x057BF73D [FC 8 bit][CN 16 bit][Checksum 8 bit]
// As of today (20200712), there's no public known way to calculate the 8 bit
// Check sum based on the 8 bit FC and 16 bit CN
//-----------------------------------------------------------------------------
#include "cmdlfparadox.h"

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>

#include "commonutil.h"     // ARRAYLEN
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "protocols.h"  // t55xx defines
#include "cmdlft55xx.h" // clone..

#define PARADOX_RAW_FULL_LEN 96
uint8_t paradox_preamble[] = {0, 0, 0, 0, 1, 1, 1, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1, 0, 1};

static int CmdHelp(const char *Cmd);

static int usage_lf_paradox_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Paradox tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage: lf paradox clone [h] [b <raw hex>]");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  b <raw hex>     : raw hex data. 12 bytes max");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       lf paradox clone b 0f55555695596a6a9999a59a"));
    return PM3_SUCCESS;
}

/*
static int usage_lf_paradox_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Paradox card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "The facility-code is 8-bit and the card number is 16-bit.  Larger values are truncated.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf paradox sim [h] <Facility-Code> <Card-Number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  h               : this help");
    PrintAndLogEx(NORMAL, "  <Facility-Code> :  8-bit value facility code");
    PrintAndLogEx(NORMAL, "  <Card Number>   : 16-bit value card number");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("       lf paradox sim 123 11223"));
    return PM3_SUCCESS;
}
*/


static int CmdParadoxDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    return demodParadox();
}

//by marshmellow, jumpycalm
//Paradox Prox demod - FSK2a RF/50 with preamble of 0000 1111 0101 0101 0101 0101 0101 (then manchester encoded)
//print full Paradox Prox ID and some bit format details if found
int demodParadox(void) {
    //raw fsk demod no manchester decoding no start bit finding just get binary from wave
    uint8_t bits[MAX_GRAPH_TRACE_LEN] = {0};
    size_t size = getFromGraphBuf(bits);
    if (size == 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox not enough samples");
        return PM3_ESOFT;
    }

    //get binary from fsk wave
    uint64_t paradox_id_hi_temp = 0; // Not used for Paradox
    uint64_t paradox_id_lo_temp = 0;
    int wave_idx = 0;
    int idx = DemodManchesterFSK(bits, &size, &paradox_id_hi_temp, &paradox_id_lo_temp, &wave_idx, paradox_preamble, PARADOX_RAW_FULL_LEN, sizeof(paradox_preamble));
    if (idx < 0) {
        if (idx == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox programming error, check your source code"));
        else if (idx == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox not enough samples"));
        else if (idx == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox just noise detected"));
        else if (idx == -4)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox problem during FSK demod"));
        else if (idx == -5)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox preamble not found"));
        else if (idx == -6)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox wrong size after finding preamble"));
        else if (idx == -7)
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox error in Manchester data, size %zu"), size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - " _RED_("Paradox error demoding fsk %d"), idx);

        return PM3_ESOFT;
    }

    // Last 2 bits of demoded Paradox is always 11, strip the last 2 bits to get the actual Paradox ID
    uint32_t paradox_id = (uint32_t)(paradox_id_lo_temp >> 2);
   
    setDemodBuff(bits, size, idx);
    setClockGrid(50, wave_idx + (idx * 50));

    if (!paradox_id) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Paradox no value found");
        return PM3_ESOFT;
    }

    uint8_t fc = (uint8_t)(paradox_id >> 24);
    uint16_t cn = (uint16_t)((paradox_id & 0xFFFFFF) >> 8);
    uint8_t chksum = (uint8_t)(paradox_id & 0xFF);

    uint32_t rawLo = bytebits_to_byte(bits + idx + 64, 32);
    uint32_t rawHi = bytebits_to_byte(bits + idx + 32, 32);
    uint32_t rawHi2 = bytebits_to_byte(bits + idx, 32);

    PrintAndLogEx(INFO, "Paradox - ID: "_GREEN_("%08x")" FC: "_GREEN_("%d")" CN: "_GREEN_("%d")", Checksum: "_GREEN_("%02x")", Raw: "_GREEN_("%08x%08x%08x")"",
                  paradox_id,
                  fc,
                  cn,
                  chksum,
                  rawHi2, rawHi, rawLo
                  );

    PrintAndLogEx(DEBUG, "DEBUG: Paradox idx: %d, len: %zu, Printing Demod Buffer:", idx, size);
    if (g_debugMode)
        printDemodBuff();

    return PM3_SUCCESS;
}

//by marshmellow
//see ASKDemod for what args are accepted
static int CmdParadoxRead(const char *Cmd) {
    lf_read(false, 10000);
    return CmdParadoxDemod(Cmd);
}

static int CmdParadoxClone(const char *Cmd) {

    uint32_t blocks[4];
    bool errors = false;
    uint8_t cmdp = 0;
    int datalen = 0;

    while (param_getchar(Cmd, cmdp) != 0x00 && !errors) {
        switch (tolower(param_getchar(Cmd, cmdp))) {
            case 'h':
                return usage_lf_paradox_clone();
            case 'b': {
                // skip first block,  3*4 =12 bytes left
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

    if (errors || cmdp == 0) return usage_lf_paradox_clone();

    //Securakey - compat mode, ASK/Man, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_FSK2a | T55x7_BITRATE_RF_50 | 3 << T55x7_MAXBLOCK_SHIFT;

    PrintAndLogEx(INFO, "Preparing to clone Paradox to T55x7 with raw hex");
    print_blocks(blocks,  ARRAYLEN(blocks));

    int res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf paradox read`") " to verify");
    return res;
}

static int CmdParadoxSim(const char *Cmd) {
    PrintAndLogEx(INFO, " To be implemented, feel free to contribute!");
    return PM3_SUCCESS;
}
/*
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_paradox_sim();

    uint32_t facilitycode = 0, cardnumber = 0, fc = 0, cn = 0;

    uint8_t bs[96];
    memset(bs, 0x00, sizeof(bs));

    // Paradox uses:  fcHigh: 10, fcLow: 8, clk: 50, invert: 1  FSK2a
    uint8_t clk = 50, invert = 1, high = 10, low = 8;

    if (sscanf(Cmd, "%u %u", &fc, &cn) != 2) return usage_lf_paradox_sim();

    facilitycode = (fc & 0x000000FF);
    cardnumber = (cn & 0x0000FFFF);

    // if ( GetParadoxBits(facilitycode, cardnumber, bs) != PM3_SUCCESS) {
    // PrintAndLogEx(ERR, "Error with tag bitstream generation.");
    // return 1;
    // }

    PrintAndLogEx(NORMAL, "Simulating Paradox - Facility Code: %u, CardNumber: %u", facilitycode, cardnumber);

    lf_fsksim_t *payload = calloc(1, sizeof(lf_fsksim_t) + sizeof(bs));
    payload->fchigh = high;
    payload->fclow =  low;
    payload->separator = invert;
    payload->clock = clk;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_FSK_SIMULATE, (uint8_t *)payload,  sizeof(lf_fsksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_FSK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}
*/
static command_t CommandTable[] = {
    {"help",  CmdHelp,          AlwaysAvailable, "This help"},
    {"demod", CmdParadoxDemod,  AlwaysAvailable, "Demodulate a Paradox FSK tag from the GraphBuffer"},
    {"read",  CmdParadoxRead,   IfPm3Lf,         "Attempt to read and Extract tag data from the antenna"},
    {"clone", CmdParadoxClone,  IfPm3Lf,         "clone paradox tag to T55x7"},
    {"sim",   CmdParadoxSim,    IfPm3Lf,         "simulate paradox tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFParadox(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}


