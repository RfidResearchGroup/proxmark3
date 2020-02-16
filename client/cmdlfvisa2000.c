//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency visa 2000 tag commands
// by iceman
// ASK/Manchester, RF/64, STT, 96 bits (complete)
//-----------------------------------------------------------------------------

#include "cmdlfvisa2000.h"

#include <string.h>
#include <ctype.h>
#include <stdlib.h>
#include <inttypes.h>

#include "commonutil.h"     // ARRAYLEN
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "graph.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest
#include "cmdlft55xx.h"    // write verify

#define BL0CK1 0x56495332

static int CmdHelp(const char *Cmd);

static int usage_lf_visa2k_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Visa2000 tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf visa2000 clone [h] <card ID> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <card ID>  : Visa2k card ID");
    PrintAndLogEx(NORMAL, "      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "      lf visa2000 clone 112233");
    return PM3_SUCCESS;
}

static int usage_lf_visa2k_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of visa2k card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf visa2000 sim [h] <card ID>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <card ID>  : Visa2k card ID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "        lf visa2000 sim 112233");
    return PM3_SUCCESS;
}

static uint8_t visa_chksum(uint32_t id) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < 32; i += 4)
        sum ^= (id >> i) & 0xF;
    return sum & 0xF;
}

static uint8_t visa_parity(uint32_t id) {
    // 4bit parity LUT
    uint8_t par_lut[] = {
        0, 1, 1, 0
        , 1, 0, 0, 1
        , 1, 0, 0, 1
        , 0, 1, 1, 0
    };
    uint8_t par = 0;
    par |= par_lut[(id >> 28) & 0xF ] << 7;
    par |= par_lut[(id >> 24) & 0xF ] << 6;
    par |= par_lut[(id >> 20) & 0xF ] << 5;
    par |= par_lut[(id >> 16) & 0xF ] << 4;
    par |= par_lut[(id >> 12) & 0xF ] << 3;
    par |= par_lut[(id >>  8) & 0xF ] << 2;
    par |= par_lut[(id >>  4) & 0xF ] << 1;
    par |= par_lut[(id & 0xF) ];
    return par;
}

/**
*
* 56495332 00096ebd 00000077 —> tag id 618173
* aaaaaaaa iiiiiiii -----ppc
*
* a = fixed value  ascii 'VIS2'
* i = card id
* p = even parity bit for each nibble in card id.
* c = checksum  (xor of card id)
*
**/
//see ASKDemod for what args are accepted
static int CmdVisa2kDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    save_restoreGB(GRAPH_SAVE);

    //CmdAskEdgeDetect("");

    //ASK / Manchester
    bool st = true;
    if (ASKDemod_ext("64 0 0", false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: ASK/Manchester Demod failed");
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectVisa2k(DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - Visa2k: ans: %d", ans);

        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);

    // chksum
    uint8_t calc = visa_chksum(raw2);
    uint8_t chk = raw3 & 0xF;

    // test checksums
    if (chk != calc) {
        PrintAndLogEx(DEBUG, "DEBUG: error: Visa2000 checksum failed %x - %x\n", chk, calc);
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    // parity
    uint8_t calc_par = visa_parity(raw2);
    uint8_t chk_par = (raw3 & 0xFF0) >> 4;
    if (calc_par != chk_par) {
        PrintAndLogEx(DEBUG, "DEBUG: error: Visa2000 parity failed %x - %x\n", chk_par, calc_par);
        save_restoreGB(GRAPH_RESTORE);
        return PM3_ESOFT;
    }
    PrintAndLogEx(SUCCESS, "Visa2000 Tag Found: Card ID %u,  Raw: %08X%08X%08X", raw2,  raw1, raw2, raw3);
    return PM3_SUCCESS;
}

// 64*96*2=12288 samples just in case we just missed the first preamble we can still catch 2 of them
static int CmdVisa2kRead(const char *Cmd) {
    lf_read(false, 20000);
    return CmdVisa2kDemod(Cmd);
}

static int CmdVisa2kClone(const char *Cmd) {

    uint64_t id = 0;
    uint32_t blocks[4] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_64 | T55x7_ST_TERMINATOR | 3 << T55x7_MAXBLOCK_SHIFT, BL0CK1, 0};

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h')
        return usage_lf_visa2k_clone();

    id = param_get32ex(Cmd, 0, 0, 10);

    //Q5
    if (tolower(param_getchar(Cmd, 1)) == 'q')
        blocks[0] = T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(64) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;

    blocks[2] = id;
    blocks[3] = (visa_parity(id) << 4) | visa_chksum(id);

    PrintAndLogEx(INFO, "Preparing to clone Visa2000 to T55x7 with CardId: %"PRIu64, id);
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdVisa2kSim(const char *Cmd) {

    uint32_t id = 0;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h')
        return usage_lf_visa2k_sim();

    id = param_get32ex(Cmd, 0, 0, 10);

    PrintAndLogEx(SUCCESS, "Simulating Visa2000 - CardId: %u", id);

    uint32_t blocks[3] = { BL0CK1, id, (visa_parity(id) << 4) | visa_chksum(id) };

    uint8_t bs[96];
    for (int i = 0; i < 3; ++i)
        num_to_bytebits(blocks[i], 32, bs + i * 32);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding =  1;
    payload->invert = 0;
    payload->separator = 1;
    payload->clock = 64;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,        AlwaysAvailable, "This help"},
    {"demod",   CmdVisa2kDemod, AlwaysAvailable, "demodulate an VISA2000 tag from the GraphBuffer"},
    {"read",    CmdVisa2kRead,  IfPm3Lf,         "attempt to read and extract tag data from the antenna"},
    {"clone",   CmdVisa2kClone, IfPm3Lf,         "clone Visa2000 tag to T55x7 (or to q5/T5555)"},
    {"sim",     CmdVisa2kSim,   IfPm3Lf,         "simulate Visa2000 tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFVisa2k(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// by iceman
// find Visa2000 preamble in already demoded data
int detectVisa2k(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {0, 1, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 0, 1, 0, 1, 0, 0, 1, 1, 0, 0, 1, 1, 0, 0, 1, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}

int demodVisa2k(void) {
    return CmdVisa2kDemod("");
}

