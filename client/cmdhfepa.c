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

#include "cmdparser.h"    // command_t
#include "commonutil.h"   // ARRAYLEN
#include "comms.h"        // clearCommandBuffer
#include "ui.h"
#include "util_posix.h"

static int CmdHelp(const char *Cmd);

// Perform (part of) the PACE protocol
static int CmdHFEPACollectPACENonces(const char *Cmd) {
    // requested nonce size
    uint32_t m = 0;
    // requested number of Nonces
    uint32_t n = 0;
    // delay between requests
    uint32_t d = 0;

    sscanf(Cmd, "%u %u %u", &m, &n, &d);

    // values are expected to be > 0
    m = m > 0 ? m : 1;
    n = n > 0 ? n : 1;

    PrintAndLogEx(SUCCESS, "Collecting %u %u byte nonces", n, m);
    PrintAndLogEx(SUCCESS, "Start: %" PRIu64, msclock() / 1000);
    // repeat n times
    for (uint32_t i = 0; i < n; i++) {
        // execute PACE
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_EPA_COLLECT_NONCE, (int)m, 0, 0, NULL, 0);
        PacketResponseNG resp;
        WaitForResponse(CMD_ACK, &resp);

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
    // the 4 APDUs which are replayed + their lengths
    uint8_t msesa_apdu[41] = {0}, gn_apdu[8] = {0}, map_apdu[75] = {0};
    uint8_t pka_apdu[75] = {0}, ma_apdu[18] = {0}, apdu_lengths[5] = {0};
    // pointers to the arrays to be able to iterate
    uint8_t *apdus[] = {msesa_apdu, gn_apdu, map_apdu, pka_apdu, ma_apdu};

    // usage message
    static const char *usage_msg =
        "Please specify 5 APDUs separated by spaces. "
        "Example:\n preplay 0022C1A4 1068000000 1086000002 1234ABCDEF 1A2B3C4D";

    // Proxmark response
    PacketResponseNG resp;

    int skip = 0, skip_add = 0, scan_return;
    // for each APDU
    for (int i = 0; i < ARRAYLEN(apdu_lengths); i++) {
        // scan to next space or end of string
        while (Cmd[skip] != ' ' && Cmd[skip] != '\0') {
            // convert
            scan_return = sscanf(Cmd + skip,
                                 "%2X%n",
                                 (unsigned int *)(apdus[i] + apdu_lengths[i]),
                                 &skip_add
                                );

            if (scan_return < 1) {
                PrintAndLogEx(INFO, (char *)usage_msg);
                PrintAndLogEx(WARNING, "Not enough APDUs! Try again!");
                return PM3_SUCCESS;
            }
            skip += skip_add;
            apdu_lengths[i]++;
        }

        // break on EOF
        if (Cmd[skip] == '\0') {
            if (i < ARRAYLEN(apdu_lengths) - 1) {

                PrintAndLogEx(INFO, (char *)usage_msg);
                return PM3_SUCCESS;
            }
            break;
        }
        // skip the space
        skip++;
    }

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
    {"cnonces", CmdHFEPACollectPACENonces, IfPm3Iso14443,   "<m> <n> <d> Acquire n>0 encrypted PACE nonces of size m>0 with d sec pauses"},
    {"preplay", CmdHFEPAPACEReplay,        IfPm3Iso14443,   "<mse> <get> <map> <pka> <ma> Perform PACE protocol by replaying given APDUs"},
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
