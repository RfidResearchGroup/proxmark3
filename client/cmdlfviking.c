//-----------------------------------------------------------------------------
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Viking tag commands (AKA FDI Matalec Transit)
// ASK/Manchester, RF/32, 64 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfviking.h"

static int CmdHelp(const char *Cmd);

static int usage_lf_viking_clone(void) {
    PrintAndLogEx(NORMAL, "clone a Viking AM tag to a T55x7 tag.");
    PrintAndLogEx(NORMAL, "Usage: lf viking clone <Card ID - 8 hex digits> <Q5>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  <Card Number>  : 8 digit hex viking card number");
    PrintAndLogEx(NORMAL, "  <Q5>           : specify write to Q5 (t5555 instead of t55x7)");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf viking clone 1A337 Q5");
    return PM3_SUCCESS;
}

static int usage_lf_viking_sim(void) {
    PrintAndLogEx(NORMAL, "Enables simulation of viking card with specified card number.");
    PrintAndLogEx(NORMAL, "Simulation runs until the button is pressed or another USB command is issued.");
    PrintAndLogEx(NORMAL, "Per viking format, the card number is 8 digit hex number.  Larger values are truncated.");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Usage:  lf viking sim <Card-Number>");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "  <Card Number>   : 8 digit hex viking card number");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, "       lf viking sim 1A337");
    return PM3_SUCCESS;
}

//by marshmellow
//see ASKDemod for what args are accepted
static int CmdVikingDemod(const char *Cmd) {
    if (ASKDemod(Cmd, false, false, 1) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Viking ASKDemod failed");
        return PM3_ESOFT;
    }
    size_t size = DemodBufferLen;
    int ans = detectViking(DemodBuffer, &size);
    if (ans < 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Viking Demod %d %s", ans, (ans == -5) ? _RED_("[chksum error]") : "");
        return PM3_ESOFT;
    }
    //got a good demod
    uint32_t raw1 = bytebits_to_byte(DemodBuffer + ans, 32);
    uint32_t raw2 = bytebits_to_byte(DemodBuffer + ans + 32, 32);
    uint32_t cardid = bytebits_to_byte(DemodBuffer + ans + 24, 32);
    uint8_t  checksum = bytebits_to_byte(DemodBuffer + ans + 32 + 24, 8);
    PrintAndLogEx(SUCCESS, "Viking Tag Found: Card ID " _YELLOW_("%08X")" checksum "_YELLOW_("%02X"), cardid, checksum);
    PrintAndLogEx(SUCCESS, "Raw hex: %08X%08X", raw1, raw2);
    setDemodBuff(DemodBuffer, 64, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));
    return PM3_SUCCESS;
}

//by marshmellow
//see ASKDemod for what args are accepted
static int CmdVikingRead(const char *Cmd) {
    lf_read(true, 10000);
    return CmdVikingDemod(Cmd);
}

static int CmdVikingClone(const char *Cmd) {
    uint32_t id = 0;
    uint64_t rawID = 0;
    bool Q5 = false;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_viking_clone();

    id = param_get32ex(Cmd, 0, 0, 16);
    if (id == 0) return usage_lf_viking_clone();

    cmdp = param_getchar(Cmd, 1);
    if (cmdp == 'Q' || cmdp == 'q')
        Q5 = true;

    rawID = getVikingBits(id);

    PrintAndLogEx(INFO, "Preparing to clone Viking tag - ID " _YELLOW_("%08X")" raw " _YELLOW_("%08X%08X"), id, (uint32_t)(rawID >> 32), (uint32_t)(rawID & 0xFFFFFFFF));

    clearCommandBuffer();
    SendCommandMIX(CMD_VIKING_CLONE_TAG, rawID >> 32, rawID & 0xFFFFFFFF, Q5, NULL, 0);
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_ACK, &resp, T55XX_WRITE_TIMEOUT)) {
        PrintAndLogEx(WARNING, "Error occurred, device did not respond during write operation.");
        return PM3_ETIMEOUT;
    }
    return PM3_SUCCESS;
}

static int CmdVikingSim(const char *Cmd) {
    uint32_t id = 0;
    uint64_t rawID = 0;
    char cmdp = tolower(param_getchar(Cmd, 0));
    if (strlen(Cmd) == 0 || cmdp == 'h') return usage_lf_viking_sim();

    id = param_get32ex(Cmd, 0, 0, 16);
    if (id == 0) return usage_lf_viking_sim();

    rawID = getVikingBits(id);

    PrintAndLogEx(SUCCESS, "Simulating Viking - ID " _YELLOW_("%08X")" raw "_YELLOW_("%08X%08X"), id, (uint32_t)(rawID >> 32), (uint32_t)(rawID & 0xFFFFFFFF));

    uint8_t bs[64];
    num_to_bytebits(rawID, sizeof(bs), bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 0;
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
    {"help",    CmdHelp,        AlwaysAvailable, "This help"},
    {"demod",   CmdVikingDemod, AlwaysAvailable, "Demodulate a Viking tag from the GraphBuffer"},
    {"read",    CmdVikingRead,  IfPm3Lf,         "Attempt to read and Extract tag data from the antenna"},
    {"clone",   CmdVikingClone, IfPm3Lf,         "<8 digit ID number> clone viking tag"},
    {"sim",     CmdVikingSim,   IfPm3Lf,         "<8 digit ID number> simulate viking tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFViking(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// calc checksum
uint64_t getVikingBits(uint32_t id) {
    uint8_t checksum = ((id >> 24) & 0xFF) ^ ((id >> 16) & 0xFF) ^ ((id >> 8) & 0xFF) ^ (id & 0xFF) ^ 0xF2 ^ 0xA8;
    uint64_t ret = (uint64_t)0xF2 << 56;
    ret |= (uint64_t)id << 8;
    ret |= checksum;
    return ret;
}
// by marshmellow
// find viking preamble 0xF200 in already demoded data
int detectViking(uint8_t *src, size_t *size) {
    //make sure buffer has data
    if (*size < 64) return -2;
    size_t startIdx = 0;
    uint8_t preamble[] = {1, 1, 1, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    if (!preambleSearch(src, preamble, sizeof(preamble), size, &startIdx))
        return -4; //preamble not found

    uint32_t checkCalc = bytebits_to_byte(src + startIdx, 8) ^
                         bytebits_to_byte(src + startIdx + 8, 8) ^
                         bytebits_to_byte(src + startIdx + 16, 8) ^
                         bytebits_to_byte(src + startIdx + 24, 8) ^
                         bytebits_to_byte(src + startIdx + 32, 8) ^
                         bytebits_to_byte(src + startIdx + 40, 8) ^
                         bytebits_to_byte(src + startIdx + 48, 8) ^
                         bytebits_to_byte(src + startIdx + 56, 8);

    if (checkCalc != 0xA8) return -5;
    if (*size != 64) return -6;
    //return start position
    return (int)startIdx;
}

int demodViking(void) {
    return CmdVikingDemod("");
}

