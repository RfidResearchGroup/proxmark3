//-----------------------------------------------------------------------------
// Copyright (C) 2012 Frederik Möllers
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Commands related to the German electronic Identification Card
//-----------------------------------------------------------------------------
#include "cmdhfepa.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdlib.h>
#include <ctype.h>        // tolower
#include "cliparser.h"
#include "cmdparser.h"    // command_t
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"        // clearCommandBuffer
#include "ui.h"
#include "util_posix.h"

static int CmdHelp(const char *Cmd);

// Perform (part of) the PACE protocol
static int CmdHFEPACollectPACENonces(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf epa cnonces",
                  "Tries to collect nonces when doing part of PACE protocol.",
                  "hf epa cnonces --size 4 --num 4 --delay 1");

    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "size", "<dec>", "nonce size"),
        arg_int1(NULL, "num", "<dec>", "number of nonces to collect"),
        arg_int1("d", "delay", "<dec>", "delay between attempts"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);


    int m = arg_get_int_def(ctx, 1, 0);
    int n = arg_get_int_def(ctx, 2, 0);
    int d = arg_get_int_def(ctx, 3, 0);

    CLIParserFree(ctx);

    // values are expected to be > 0
    m = m > 0 ? m : 1;
    n = n > 0 ? n : 1;

    PrintAndLogEx(SUCCESS, "Collecting %u %u byte nonces", n, m);
    PrintAndLogEx(SUCCESS, "Start: %" PRIu64, msclock() / 1000);

    struct p {
        uint32_t m;
    } PACKED payload;
    payload.m = m;

    for (uint32_t i = 0; i < n; i++) {
        // execute PACE

        PacketResponseNG resp;
        clearCommandBuffer();
        SendCommandNG(CMD_HF_EPA_COLLECT_NONCE, (uint8_t *)&payload, sizeof(payload));

        WaitForResponse(CMD_HF_EPA_COLLECT_NONCE, &resp);

        // check if command failed
        if (resp.oldarg[0] != 0) {
            PrintAndLogEx(FAILED, "Error in step %" PRId64 ", Return code: %" PRId64, resp.oldarg[0], resp.oldarg[1]);
        } else {
            size_t nonce_length = resp.oldarg[1];
            char *nonce = (char *) calloc(2 * nonce_length + 1, sizeof(uint8_t));
            for (int j = 0; j < nonce_length; j++) {
                sprintf(nonce + (2 * j), "%02X", resp.data.asBytes[j]);
            }
            // print nonce
            PrintAndLogEx(SUCCESS, "Length: %zu, Nonce: %s", nonce_length, nonce);
            free(nonce);
        }
        if (i < n - 1) {
            sleep(d);
        }
    }

    PrintAndLogEx(SUCCESS, "End: %" PRIu64, msclock() / 1000);
    return PM3_SUCCESS;
}

// perform the PACE protocol by replaying APDUs
static int CmdHFEPAPACEReplay(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf epa preplay",
                  "Perform PACE protocol by replaying given APDUs",
                  "hf epa preplay --mse 0022C1A4 --get 1068000000 --map 1086000002 --pka 1234ABCDEF --ma 1A2B3C4D");

    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "mse", "<hex>", "msesa APDU"),
        arg_str1(NULL, "get", "<hex>", "gn APDU"),
        arg_str1(NULL, "map", "<hex>", "map APDU"),
        arg_str1(NULL, "pka", "<hex>", "pka APDU"),
        arg_str1(NULL, "ma", "<hex>", "ma APDU"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int msesa_len = 0;
    uint8_t msesa_apdu[41] = {0};
    CLIGetHexWithReturn(ctx, 1, msesa_apdu, &msesa_len);

    int gn_len = 0;
    uint8_t gn_apdu[8] = {0};
    CLIGetHexWithReturn(ctx, 2, gn_apdu, &gn_len);

    int map_len = 0;
    uint8_t map_apdu[75] = {0};
    CLIGetHexWithReturn(ctx, 3, map_apdu, &map_len);

    int pka_len = 0;
    uint8_t pka_apdu[75] = {0};
    CLIGetHexWithReturn(ctx, 4, pka_apdu, &pka_len);

    int ma_len = 0;
    uint8_t ma_apdu[18] = {0};
    CLIGetHexWithReturn(ctx, 5, ma_apdu, &ma_len);

    CLIParserFree(ctx);

    uint8_t apdu_lengths[5] = {msesa_len, gn_len, map_len, pka_len, ma_len};
    // pointers to the arrays to be able to iterate
    uint8_t *apdus[] = {msesa_apdu, gn_apdu, map_apdu, pka_apdu, ma_apdu};

    // Proxmark response
    PacketResponseNG resp;

    // transfer the APDUs to the Proxmark
    uint8_t data[PM3_CMD_DATA_SIZE];
    // fast push mode
    conn.block_after_ACK = true;
    for (int i = 0; i < ARRAYLEN(apdu_lengths); i++) {
        // transfer the APDU in several parts if necessary
        for (int j = 0; j * sizeof(data) < apdu_lengths[i]; j++) {
            // amount of data in this packet
            int packet_length = apdu_lengths[i] - (j * sizeof(data));
            if (packet_length > sizeof(data)) {
                packet_length = sizeof(data);
            }
            if ((i == ARRAYLEN(apdu_lengths) - 1) && (j * sizeof(data) >= apdu_lengths[i] - 1)) {
                // Disable fast mode on last packet
                conn.block_after_ACK = false;
            }
            memcpy(data, // + (j * sizeof(data)),
                   apdus[i] + (j * sizeof(data)),
                   packet_length);

            clearCommandBuffer();
            // arg0: APDU number
            // arg1: offset into the APDU
            SendCommandOLD(CMD_HF_EPA_REPLAY, i + 1, j * sizeof(data), packet_length, data, packet_length);
            WaitForResponse(CMD_ACK, &resp);
            if (resp.oldarg[0] != 0) {
                PrintAndLogEx(WARNING, "Transfer of APDU #%d Part %d failed!", i, j);
                return PM3_ESOFT;
            }
        }
    }

    // now perform the replay
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_EPA_REPLAY, 0, 0, 0, NULL, 0);
    WaitForResponse(CMD_ACK, &resp);

    if (resp.oldarg[0] != 0) {
        PrintAndLogEx(SUCCESS, "\nPACE replay failed in step %u!", (uint32_t)resp.oldarg[0]);
        PrintAndLogEx(SUCCESS, "Measured times:");
        PrintAndLogEx(SUCCESS, "MSE Set AT: %u us", resp.data.asDwords[0]);
        PrintAndLogEx(SUCCESS, "GA Get Nonce: %u us", resp.data.asDwords[1]);
        PrintAndLogEx(SUCCESS, "GA Map Nonce: %u us", resp.data.asDwords[2]);
        PrintAndLogEx(SUCCESS, "GA Perform Key Agreement: %u us", resp.data.asDwords[3]);
        PrintAndLogEx(SUCCESS, "GA Mutual Authenticate: %u us", resp.data.asDwords[4]);
    } else {
        PrintAndLogEx(SUCCESS, "PACE replay successful!");
        PrintAndLogEx(SUCCESS, "MSE Set AT: %u us", resp.data.asDwords[0]);
        PrintAndLogEx(SUCCESS, "GA Get Nonce: %u us", resp.data.asDwords[1]);
        PrintAndLogEx(SUCCESS, "GA Map Nonce: %u us", resp.data.asDwords[2]);
        PrintAndLogEx(SUCCESS, "GA Perform Key Agreement: %u us", resp.data.asDwords[3]);
        PrintAndLogEx(SUCCESS, "GA Mutual Authenticate: %u us", resp.data.asDwords[4]);
    }
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,                   AlwaysAvailable, "This help"},
    {"cnonces", CmdHFEPACollectPACENonces, IfPm3Iso14443,   "Acquire encrypted PACE nonces of specific size"},
    {"preplay", CmdHFEPAPACEReplay,        IfPm3Iso14443,   "Perform PACE protocol by replaying given APDUs"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFEPA(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
