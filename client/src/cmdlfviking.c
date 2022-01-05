//-----------------------------------------------------------------------------
// Marshmellow,
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency Viking tag commands (AKA FDI Matalec Transit)
// ASK/Manchester, RF/32, 64 bits (complete)
//-----------------------------------------------------------------------------
#include "cmdlfviking.h"
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "common.h"
#include "cmdparser.h"    // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"
#include "commonutil.h"     // num_to_bytes
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

//see ASKDemod for what args are accepted
int demodViking(bool verbose) {
    (void) verbose; // unused so far

    bool st = false;
    if (ASKDemod_ext(0, 0, 100, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Viking ASKDemod failed");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectViking(g_DemodBuffer, &size);
    if (ans < 0) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - Viking Demod %d %s", ans, (ans == -5) ? _RED_("[chksum error]") : "");
        return PM3_ESOFT;
    }

    //got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer + ans, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + ans + 32, 32);
    uint32_t cardid = bytebits_to_byte(g_DemodBuffer + ans + 24, 32);
    uint8_t  checksum = bytebits_to_byte(g_DemodBuffer + ans + 32 + 24, 8);
    PrintAndLogEx(SUCCESS, "Viking - Card " _GREEN_("%08X") ", Raw: %08X%08X", cardid, raw1, raw2);
    PrintAndLogEx(DEBUG, "Checksum: %02X", checksum);
    setDemodBuff(g_DemodBuffer, 64, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));
    return PM3_SUCCESS;
}

static int CmdVikingDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf viking demod",
                  "Try to find Viking AM preamble, if found decode / descramble data",
                  "lf viking demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodViking(true);
}

//see ASKDemod for what args are accepted
static int CmdVikingReader(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf viking reader",
                  "read a Viking AM tag",
                  "lf viking reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 10000);
        demodViking(true);
    } while (cm && !kbd_enter_pressed());

    return PM3_SUCCESS;
}

static int CmdVikingClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf viking clone",
                  "clone a Viking AM tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf viking clone --cn 01A337\n"
                  "lf viking clone --cn 01A337 --q5   -> encode for Q5/T5555 tag\n"
                  "lf viking clone --cn 112233 --em   -> encode for EM4305/4469"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "cn", "<hex>", "8 digit hex viking card number"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[4] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    uint32_t id = bytes_to_num(raw, raw_len);
    if (id == 0) {
        PrintAndLogEx(ERR, "Cardnumber can't be zero");
        return PM3_EINVARG;
    }

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    uint64_t rawID = getVikingBits(id);

    struct p {
        bool Q5;
        bool EM;
        uint8_t blocks[8];
    } PACKED payload;
    payload.Q5 = q5;
    payload.EM = em;

    num_to_bytes(rawID, 8, &payload.blocks[0]);

    char cardtype[16] = {"T55x7"};
    if (q5)
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    else if (em)
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");

    PrintAndLogEx(INFO, "Preparing to clone Viking tag on " _YELLOW_("%s") " - ID " _YELLOW_("%08X")" raw " _YELLOW_("%s")
                  , cardtype
                  , id
                  , sprint_hex(payload.blocks, sizeof(payload.blocks))
                 );

    clearCommandBuffer();

    SendCommandNG(CMD_LF_VIKING_CLONE, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (!WaitForResponseTimeout(CMD_LF_VIKING_CLONE, &resp, T55XX_WRITE_TIMEOUT)) {
        PrintAndLogEx(ERR, "Error occurred, device did not respond during write operation.");
        return PM3_ETIMEOUT;
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf viking reader`") " to verify");
    return resp.status;
}

static int CmdVikingSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf viking sim",
                  "Enables simulation of viking card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n"
                  "Per viking format, the card number is 8 digit hex number.  Larger values are truncated.",
                  "lf viking sim --cn 01A337"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "cn", "<hex>", "8 digit hex viking card number"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    uint8_t raw[4] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);

    uint32_t id = bytes_to_num(raw, raw_len);
    if (id == 0) {
        PrintAndLogEx(ERR, "Cardnumber can't be zero");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }
    CLIParserFree(ctx);

    uint64_t rawID = getVikingBits(id);

    PrintAndLogEx(SUCCESS, "Simulating Viking - ID " _YELLOW_("%08X") " raw " _YELLOW_("%08X%08X"), id, (uint32_t)(rawID >> 32), (uint32_t)(rawID & 0xFFFFFFFF));

    uint8_t bs[64];
    num_to_bytebits(rawID, sizeof(bs), bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 32;
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
    {"demod",   CmdVikingDemod, AlwaysAvailable, "demodulate a Viking tag from the GraphBuffer"},
    {"reader",  CmdVikingReader,  IfPm3Lf,       "attempt to read and extract tag data"},
    {"clone",   CmdVikingClone, IfPm3Lf,         "clone Viking tag to T55x7 or Q5/T5555"},
    {"sim",     CmdVikingSim,   IfPm3Lf,         "simulate Viking tag"},
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


