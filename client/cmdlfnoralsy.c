//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Noralsy tag commands
// ASK/Manchester, STT, RF/32, 96 bits long (some bits unknown)
//-----------------------------------------------------------------------------
#include "cmdlfnoralsy.h"

static int CmdHelp(const char *Cmd);

static int usage_lf_noralsy_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Noralsy tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf noralsy clone [h] <card id> <year> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <card id>  : Noralsy card ID");
    PrintAndLogEx(NORMAL, "      <year>     : Tag allocation year");
    PrintAndLogEx(NORMAL, "      <Q5>       : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf noralsy clone 112233");
    return PM3_SUCCESS;
}

static int usage_lf_noralsy_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of Noralsy card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf noralsy sim [h] <card id> <year>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h          : This help");
    PrintAndLogEx(NORMAL, "      <card id>  : Noralsy card ID");
    PrintAndLogEx(NORMAL, "      <year>     : Tag allocation year");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf noralsy sim 112233");
    return PM3_SUCCESS;
}

static uint8_t noralsy_chksum(uint8_t *bits, uint8_t len) {
    uint8_t sum = 0;
    for (uint8_t i = 0; i < len; i += 4)
        sum ^= bytebits_to_byte(bits + i, 4);
    return sum & 0x0F ;
}

//see ASKDemod for what args are accepted
static int CmdNoralsyDemod(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far

    //ASK / Manchester
    bool st = true;
    if (ASKDemod_ext("32 0 0", false, false, 1, &st) != PM3_SUCCESS) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: ASK/Manchester Demod failed");
        return PM3_ESOFT;
    }
    if (!st) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: sequence terminator not found");
        return PM3_ESOFT;
    }

    size_t size = DemodBufferLen;
    int ans = detectNoralsy(DemodBuffer, &size);
    if (ans < 0) {
        if (g_debugMode) {
            if (ans == -1)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: too few bits found");
            else if (ans == -2)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: preamble not found");
            else if (ans == -3)
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: Size not correct: %d", size);
            else
                PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: ans: %d", ans);
        }
        return PM3_ESOFT;
    }
    setDemodBuff(DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(DemodBuffer + 64, 32);

    uint32_t cardid = ((raw2 & 0xFFF00000) >> 20) << 16;
    cardid |= (raw2 & 0xFF) << 8;
    cardid |= ((raw3 & 0xFF000000) >> 24);
    cardid = BCD2DEC(cardid);

    uint16_t year = (raw2 & 0x000ff000) >> 12;
    year = BCD2DEC(year);
    year += (year > 60) ? 1900 : 2000;

    // calc checksums
    uint8_t calc1 = noralsy_chksum(DemodBuffer + 32, 40);
    uint8_t calc2 = noralsy_chksum(DemodBuffer, 76);
    uint8_t chk1 = 0, chk2 = 0;
    chk1 = bytebits_to_byte(DemodBuffer + 72, 4);
    chk2 = bytebits_to_byte(DemodBuffer + 76, 4);
    // test checksums
    if (chk1 != calc1) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: checksum 1 failed %x - %x\n", chk1, calc1);
        return PM3_ESOFT;
    }
    if (chk2 != calc2) {
        if (g_debugMode) PrintAndLogEx(DEBUG, "DEBUG: Error - Noralsy: checksum 2 failed %x - %x\n", chk2, calc2);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Noralsy Tag Found: Card ID %u, Year: %u Raw: %08X%08X%08X", cardid, year, raw1, raw2, raw3);
    if (raw1 != 0xBB0214FF) {
        PrintAndLogEx(WARNING, "Unknown bits set in first block! Expected 0xBB0214FF, Found: 0x%08X", raw1);
        PrintAndLogEx(WARNING, "Please post this output in forum to further research on this format");
    }
    return PM3_SUCCESS;
}

static int CmdNoralsyRead(const char *Cmd) {
    lf_read(true, 8000);
    return CmdNoralsyDemod(Cmd);
}

static int CmdNoralsyClone(const char *Cmd) {

    uint16_t year = 0;
    uint32_t id = 0;
    uint32_t blocks[4] = {T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | T55x7_ST_TERMINATOR | 3 << T55x7_MAXBLOCK_SHIFT, 0, 0};
    uint8_t bits[96];
    memset(bits, 0, sizeof(bits));

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H') return usage_lf_noralsy_clone();

    id = param_get32ex(Cmd, 0, 0, 10);
    year = param_get32ex(Cmd, 1, 2000, 10);

    //Q5
    if (param_getchar(Cmd, 2) == 'Q' || param_getchar(Cmd, 2) == 'q')
        blocks[0] = T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(32) | T5555_ST_TERMINATOR | 3 << T5555_MAXBLOCK_SHIFT;

    if (getnoralsyBits(id, year, bits) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    //
    blocks[1] = bytebits_to_byte(bits, 32);
    blocks[2] = bytebits_to_byte(bits + 32, 32);
    blocks[3] = bytebits_to_byte(bits + 64, 32);

    PrintAndLogEx(INFO, "Preparing to clone Noralsy to T55x7 with CardId: %u", id);
    print_blocks(blocks, 4);

    PacketResponseNG resp;

    // fast push mode
    conn.block_after_ACK = true;
    for (uint8_t i = 0; i < 4; i++) {
        if (i == 3) {
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

static int CmdNoralsySim(const char *Cmd) {

    uint8_t bs[96];
    memset(bs, 0, sizeof(bs));

    uint16_t year = 0;
    uint32_t id = 0;

    char cmdp = param_getchar(Cmd, 0);
    if (strlen(Cmd) == 0 || cmdp == 'h' || cmdp == 'H')
        return usage_lf_noralsy_sim();

    id = param_get32ex(Cmd, 0, 0, 10);
    year = param_get32ex(Cmd, 1, 2000, 10);

    if (getnoralsyBits(id, year, bs) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "Error with tag bitstream generation.");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Simulating Noralsy - CardId: %u", id);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 1;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_ASK_SIM_TAG, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    PacketResponseNG resp;
    WaitForResponse(CMD_ASK_SIM_TAG, &resp);

    PrintAndLogEx(INFO, "Done");
    if (resp.status != PM3_EOPABORTED)
        return resp.status;
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,         AlwaysAvailable, "This help"},
    {"demod",   CmdNoralsyDemod, AlwaysAvailable, "Demodulate an Noralsy tag from the GraphBuffer"},
    {"read",    CmdNoralsyRead,  IfPm3Lf,         "Attempt to read and extract tag data from the antenna"},
    {"clone",   CmdNoralsyClone, IfPm3Lf,         "clone Noralsy to T55x7"},
    {"sim",     CmdNoralsySim,   IfPm3Lf,         "simulate Noralsy tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFNoralsy(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

int getnoralsyBits(uint32_t id, uint16_t year, uint8_t *bits) {
    //preamp
    num_to_bytebits(0xBB0214FF, 32, bits);  // --> Have seen 0xBB0214FF / 0xBB0314FF  UNKNOWN

    //convert ID into BCD-format
    id = DEC2BCD(id);
    year = DEC2BCD(year);
    year &= 0xFF;

    uint16_t sub1 = (id & 0xFFF0000) >> 16;
    uint8_t sub2 = (id & 0x000FF00) >> 8;
    uint8_t sub3 = (id & 0x00000FF);

    num_to_bytebits(sub1, 12, bits + 32);
    num_to_bytebits(year, 8, bits + 44);
    num_to_bytebits(0, 4, bits + 52); // --> UNKNOWN. Flag?

    num_to_bytebits(sub2, 8, bits + 56);
    num_to_bytebits(sub3, 8, bits + 64);

    //chksum byte
    uint8_t chksum = noralsy_chksum(bits + 32, 40);
    num_to_bytebits(chksum, 4, bits + 72);
    chksum = noralsy_chksum(bits, 76);
    num_to_bytebits(chksum, 4, bits + 76);
    return PM3_SUCCESS;
}

// by iceman
// find Noralsy preamble in already demoded data
int detectNoralsy(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 0, 1, 1, 1, 0, 1, 1, 0, 0, 0, 0};
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found
    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}
/*
*
* 2520116 | BB0214FF2529900116360000 | 10111011 00000011 00010100 11111111 00100101 00101001 10010000 00000001 00010110 00110110 00000000 00000000
*           aaa*aaaaiiiYY*iiiicc----                ****                   iiiiiiii iiiiYYYY YYYY**** iiiiiiii iiiiiiii cccccccc
*
* a = fixed value BB0*14FF
* i = printed id, BCD-format
* Y = year
* c = checksum
* * = unknown
*
**/

int demodNoralsy(void) {
    return CmdNoralsyDemod("");
}
