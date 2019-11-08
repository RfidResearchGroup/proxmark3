//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Jablotron tag commands
// Differential Biphase, RF/64, 64 bits long (complete)
//-----------------------------------------------------------------------------

#include "cmdlfjablotron.h"

#include <string.h>
#include <inttypes.h>
#include <math.h>
#include <stdlib.h>
#include <ctype.h>

#include "cmdparser.h"    // command_t
#include "comms.h"
#include "commonutil.h" // ARRAYLEN
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "protocols.h"  // for T55xx config register definitions
#include "lfdemod.h"    // parityTest
#include "cmdlft55xx.h" // verifywrite

#define JABLOTRON_ARR_LEN 64

static int CmdHelp(const char *Cmd);

static int usage_lf_jablotron_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Jablotron tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf jablotron clone [h] <card ID> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <card ID>  : jablotron card ID");
    PrintAndLogEx(NORMAL, "      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf jablotron clone 112233");
    return PM3_SUCCESS;
}

static int usage_lf_jablotron_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of jablotron card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf jablotron sim [h] <card ID>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <card ID>  : jablotron card ID");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf jablotron sim 112233");
    return PM3_SUCCESS;
}

static uint8_t jablontron_chksum(uint8_t *bits) {
    uint8_t chksum = 0;
    for (int i = 16; i < 56; i += 8) {
        chksum += bytebits_to_byte(bits + i, 8);
    }
    chksum ^= 0x3A;
    return chksum;
}

static uint64_t getJablontronCardId(uint64_t rawcode) {
    uint64_t id = 0;
    uint8_t bytes[] = {0, 0, 0, 0, 0};
    num_to_bytes(rawcode, 5, bytes);
    for (int i = 4, j = 0; i > -1;  --i, j += 2) {
        id += NIBBLE_LOW(bytes[i]) * (int)pow(10, j);
        id += NIBBLE_HIGH(bytes[i]) * (int)pow(10, j + 1);
    }
    return id;
}

//see ASKDemod for what args are accepted
static int CmdJablotronDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    //Differential Biphase / di-phase (inverted biphase)
    //get binary from ask wave
    if (ASKbiphaseDemod("0 64 1 0", false) != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Jablotron ASKbiphaseDemod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectJablotron(DemodBuffer, &size);
    if (ans < 0) {
        if (g_debugMode) {
            if (ans == -1)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Jablotron too few bits found");
            else if (ans == -2)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Jablotron preamble not found");
            else if (ans == -3)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Jablotron size not correct: %zu", size);
            else if (ans == -5)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Jablotron checksum failed");
            else
                PrintAndLogEx(DEBUG, "DEBUG: Error - Jablotron ans: %d", ans);
        }
        return PM3_ESOFT;
    }

    setDemodBuff(DemodBuffer, JABLOTRON_ARR_LEN, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);

    // bytebits_to_byte - uint32_t
    uint64_t rawid = ((uint64_t)(bytebits_to_byte(DemodBuffer + 16, 8) & 0xff) << 32) | bytebits_to_byte(DemodBuffer + 24, 32);
    uint64_t id = getJablontronCardId(rawid);

    PrintAndLogEx(SUCCESS, "Jablotron Tag Found: Card ID: %"PRIx64" :: Raw: %08X%08X", id, raw1, raw2);

    uint8_t chksum = raw2 & 0xFF;
    bool isok = (chksum == jablontron_chksum(DemodBuffer));

    PrintAndLogEx(isok ? SUCCESS : INFO,
                  "Checksum: %02X [ %s]",
                  chksum,
                  isok ? _GREEN_("OK") : _RED_("Fail")
                 );

    id = DEC2BCD(id);
    // Printed format: 1410-nn-nnnn-nnnn
    PrintAndLogEx(SUCCESS, "Printed: 1410-%02X-%04X-%04X",
                  (uint8_t)(id >> 32) & 0xFF,
                  (uint16_t)(id >> 16) & 0xFFFF,
                  (uint16_t)id & 0xFFFF
                 );
    return PM3_SUCCESS;
}

static int CmdJablotronRead(const char *Cmd) {
    lf_read(true, 10000);
    return CmdJablotronDemod(Cmd);
}

static int CmdJablotronClone(const char *Cmd) {

    uint64_t fullcode = 0;
    uint32_t blocks[3] = {T55x7_MODULATION_DIPHASE | T55x7_BITRATE_RF_64 | 2 << T55x7_MAXBLOCK_SHIFT, 0, 0};

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_jablotron_clone();

    fullcode = param_get64ex(Cmd, 0, 0, 16);

    //Q5
    if (tolower(param_getchar(Cmd, 1)) == 'q')
        blocks[0] = T5555_MODULATION_BIPHASE | T5555_INVERT_OUTPUT | T5555_SET_BITRATE(64) | 2 << T5555_MAXBLOCK_SHIFT;

    // clearing the topbit needed for the preambl detection.
    if ((fullcode & 0x7FFFFFFFFF) != fullcode) {
        fullcode &= 0x7FFFFFFFFF;
        PrintAndLogEx(INFO, "Card Number Truncated to 39bits: %"PRIx64, fullcode);
    }

    uint8_t *bits = calloc(JABLOTRON_ARR_LEN, sizeof(uint8_t));
    if (bits == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    if (getJablotronBits(fullcode, bits) != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);

    free(bits);

    PrintAndLogEx(INFO, "Preparing to clone Jablotron to T55x7 with FullCode: %"PRIx64, fullcode);
    print_blocks(blocks,  ARRAYLEN(blocks));

    return clone_t55xx_tag(blocks, ARRAYLEN(blocks));
}

static int CmdJablotronSim(const char *Cmd) {
    uint64_t fullcode = 0;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_jablotron_sim();

    fullcode = param_get64ex(Cmd, 0, 0, 16);

    // clearing the topbit needed for the preambl detection.
    if ((fullcode & 0x7FFFFFFFFF) != fullcode) {
        fullcode &= 0x7FFFFFFFFF;
        PrintAndLogEx(INFO, "Card Number Truncated to 39bits: %"PRIx64, fullcode);
    }

    PrintAndLogEx(SUCCESS, "Simulating Jablotron - FullCode: %"PRIx64, fullcode);

    uint8_t *bs = calloc(JABLOTRON_ARR_LEN, sizeof(uint8_t));
    if (bs == NULL) {
        PrintAndLogEx(WARNING, "Failed to allocate memory");
        return PM3_EMALLOC;
    }

    getJablotronBits(fullcode, bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + JABLOTRON_ARR_LEN);
    payload->encoding =  2;
    payload->invert = 1;
    payload->separator = 0;
    payload->clock = 64;
    memcpy(payload->data, bs, JABLOTRON_ARR_LEN);

    free(bs);

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + JABLOTRON_ARR_LEN);
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_LF_ASK_SIMULATE, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,            AlwaysAvailable, "This help"},
    {"demod",   CmdJablotronDemod,  AlwaysAvailable, "Demodulate an Jablotron tag from the GraphBuffer"},
    {"read",    CmdJablotronRead,   IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone",   CmdJablotronClone,  IfPm3Lf,         "clone jablotron tag to T55x7 (or to q5/T5555)"},
    {"sim",     CmdJablotronSim,    IfPm3Lf,         "simulate jablotron tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFJablotron(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int getJablotronBits(uint64_t fullcode, uint8_t *bits) {
    //preamp
    num_to_bytebits(0xFFFF, 16, bits);

    //fullcode
    num_to_bytebits(fullcode, 40, bits + 16);

    //chksum byte
    uint8_t chksum = jablontron_chksum(bits);
    num_to_bytebits(chksum, 8, bits + 56);
    return PM3_SUCCESS;
}

// ASK/Diphase fc/64 (inverted Biphase)
// Note: this is not a demod, this is only a detection
// the parameter *bits needs to be demoded before call
// 0xFFFF preamble, 64bits
int detectJablotron(uint8_t *bits, size_t *size) {
    if (*size < JABLOTRON_ARR_LEN * 2) return -1; //make sure buffer has enough data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0};
    if (preambleSearch(bits, preamble, sizeof(preamble), size, &startIdx) == 0)
        return -2; //preamble not found
    if (*size != JABLOTRON_ARR_LEN) return -3; // wrong demoded size

    uint8_t checkchksum = jablontron_chksum(bits + startIdx);
    uint8_t crc = bytebits_to_byte(bits + startIdx + 56, 8);
    if (checkchksum != crc) return -5;
    return (int)startIdx;
}

int demodJablotron(void) {
    return CmdJablotronDemod("");
}
