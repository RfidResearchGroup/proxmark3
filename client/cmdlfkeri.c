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
            PrintAndLogEx(DEBUG, "DEBUG: Error - KERI: Size not correct: 64 != %d", size);
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

    if (invert) {
        PrintAndLogEx(INFO, "Had to Invert - probably KERI");
        for (size_t i = 0; i < size; i++)
            DemodBuffer[i] ^= 1;

        CmdPrintDemodBuff("x");
    }
    return PM3_SUCCESS;
}

static int CmdKeriRead(const char *Cmd) {
    lf_read(true, 10000);
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
    PrintAndLogEx(INFO, "Preparing to clone KERI to T55x7 with Internal Id: %" PRIx64, internalid);

    //
    blocks[1] = data >> 32;
    blocks[2] = data & 0xFFFFFFFF;
    print_blocks(blocks, 3);

    PacketResponseNG resp;

    // fast push mode
    conn.block_after_ACK = true;
    for (uint8_t i = 0; i < 3; i++) {
        if (i == 2) {
            // Disable fast mode on last packet
            conn.block_after_ACK = false;
        }
        clearCommandBuffer();

        t55xx_write_block_t ng;
        ng.data = blocks[i];
        ng.pwd = 0;
        ng.blockno = i;
        ng.flags = 0;

        SendCommandNG(CMD_T55XX_WRITE_BLOCK, (uint8_t *)&ng, sizeof(ng));
        if (!WaitForResponseTimeout(CMD_T55XX_WRITE_BLOCK, &resp, T55XX_WRITE_TIMEOUT)) {
            PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
            return PM3_ETIMEOUT;
        }
    }

    return PM3_SUCCESS;
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

    PrintAndLogEx(SUCCESS, "Simulating KERI - Internal Id: %u", internalid);

    lf_psksim_t *payload = calloc(1, sizeof(lf_psksim_t) + sizeof(bs));
    payload->carrier =  2;
    payload->invert = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    PrintAndLogEx(INFO, "Simulating");

    clearCommandBuffer();
    SendCommandNG(CMD_PSK_SIM_TAG, (uint8_t *)payload,  sizeof(lf_psksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_PSK_SIM_TAG, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",  CmdHelp,      AlwaysAvailable, "This help"},
    {"demod", CmdKeriDemod, AlwaysAvailable, "Demodulate an KERI tag from the GraphBuffer"},
    {"read",  CmdKeriRead,  IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone", CmdKeriClone, IfPm3Lf,         "clone KERI to T55x7"},
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

