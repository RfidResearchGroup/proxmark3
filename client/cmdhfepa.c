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

static int CmdHelp(const char *Cmd);

// Perform (part of) the PACE protocol
int CmdHFEPACollectPACENonces(const char *Cmd) {
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

    PrintAndLogEx(NORMAL, "Collecting %u %u byte nonces", n, m);
    PrintAndLogEx(NORMAL, "Start: %" PRIu64, msclock() / 1000);
    // repeat n times
    for (uint32_t i = 0; i < n; i++) {
        // execute PACE
        UsbCommand c = {CMD_EPA_PACE_COLLECT_NONCE, {(int)m, 0, 0}};
        clearCommandBuffer();
        SendCommand(&c);
        UsbCommand resp;
        WaitForResponse(CMD_ACK, &resp);

        // check if command failed
        if (resp.arg[0] != 0) {
            PrintAndLogEx(FAILED, "Error in step %d, Return code: %d", resp.arg[0], (int)resp.arg[1]);
        } else {
            size_t nonce_length = resp.arg[1];
            char *nonce = (char *) calloc(2 * nonce_length + 1, sizeof(uint8_t));
            for (int j = 0; j < nonce_length; j++) {
                sprintf(nonce + (2 * j), "%02X", resp.d.asBytes[j]);
            }
            // print nonce
            PrintAndLogEx(NORMAL, "Length: %d, Nonce: %s", nonce_length, nonce);
            free(nonce);
        }
        if (i < n - 1) {
            sleep(d);
        }
    }
    PrintAndLogEx(NORMAL, "End: %" PRIu64, msclock() / 1000);
    return 1;
}

// perform the PACE protocol by replaying APDUs
int CmdHFEPAPACEReplay(const char *Cmd) {
    // the 4 APDUs which are replayed + their lengths
    uint8_t msesa_apdu[41], gn_apdu[8], map_apdu[75];
    uint8_t pka_apdu[75], ma_apdu[18], apdu_lengths[5] = {0};
    // pointers to the arrays to be able to iterate
    uint8_t *apdus[] = {msesa_apdu, gn_apdu, map_apdu, pka_apdu, ma_apdu};

    // usage message
    static const char *usage_msg =
        "Please specify 5 APDUs separated by spaces. "
        "Example:\n preplay 0022C1A4 1068000000 1086000002 1234ABCDEF 1A2B3C4D";

    // Proxmark response
    UsbCommand resp;

    int skip = 0, skip_add = 0, scan_return = 0;
    // for each APDU
    for (int i = 0; i < sizeof(apdu_lengths); i++) {
        // scan to next space or end of string
        while (Cmd[skip] != ' ' && Cmd[skip] != '\0') {
            // convert
            scan_return = sscanf(Cmd + skip, "%2X%n",
                                 (unsigned int *)(apdus[i] + apdu_lengths[i]),
                                 &skip_add);
            if (scan_return < 1) {
                PrintAndLogEx(NORMAL, (char *)usage_msg);
                PrintAndLogEx(WARNING, "Not enough APDUs! Try again!");
                return 0;
            }
            skip += skip_add;
            apdu_lengths[i]++;
        }

        // break on EOF
        if (Cmd[skip] == '\0') {
            if (i < sizeof(apdu_lengths) - 1) {

                PrintAndLogEx(NORMAL, (char *)usage_msg);
                return 0;
            }
            break;
        }
        // skip the space
        skip++;
    }

    // transfer the APDUs to the Proxmark
    UsbCommand usb_cmd;
    usb_cmd.cmd = CMD_EPA_PACE_REPLAY;
    for (int i = 0; i < sizeof(apdu_lengths); i++) {
        // APDU number
        usb_cmd.arg[0] = i + 1;
        // transfer the APDU in several parts if necessary
        for (int j = 0; j * sizeof(usb_cmd.d.asBytes) < apdu_lengths[i]; j++) {
            // offset into the APDU
            usb_cmd.arg[1] = j * sizeof(usb_cmd.d.asBytes);
            // amount of data in this packet
            int packet_length = apdu_lengths[i] - (j * sizeof(usb_cmd.d.asBytes));
            if (packet_length > sizeof(usb_cmd.d.asBytes)) {
                packet_length = sizeof(usb_cmd.d.asBytes);
            }
            usb_cmd.arg[2] = packet_length;

            memcpy(usb_cmd.d.asBytes, // + (j * sizeof(usb_cmd.d.asBytes)),
                   apdus[i] + (j * sizeof(usb_cmd.d.asBytes)),
                   packet_length);

            clearCommandBuffer();
            SendCommand(&usb_cmd);
            WaitForResponse(CMD_ACK, &resp);
            if (resp.arg[0] != 0) {
                PrintAndLogEx(WARNING, "Transfer of APDU #%d Part %d failed!", i, j);
                return 0;
            }
        }
    }

    // now perform the replay
    usb_cmd.arg[0] = 0;
    clearCommandBuffer();
    SendCommand(&usb_cmd);
    WaitForResponse(CMD_ACK, &resp);
    if (resp.arg[0] != 0) {
        PrintAndLogEx(NORMAL, "\nPACE replay failed in step %u!", (uint32_t)resp.arg[0]);
        PrintAndLogEx(NORMAL, "Measured times:");
        PrintAndLogEx(NORMAL, "MSE Set AT: %u us", resp.d.asDwords[0]);
        PrintAndLogEx(NORMAL, "GA Get Nonce: %u us", resp.d.asDwords[1]);
        PrintAndLogEx(NORMAL, "GA Map Nonce: %u us", resp.d.asDwords[2]);
        PrintAndLogEx(NORMAL, "GA Perform Key Agreement: %u us", resp.d.asDwords[3]);
        PrintAndLogEx(NORMAL, "GA Mutual Authenticate: %u us", resp.d.asDwords[4]);
    } else {
        PrintAndLogEx(NORMAL, "PACE replay successfull!");
        PrintAndLogEx(NORMAL, "MSE Set AT: %u us", resp.d.asDwords[0]);
        PrintAndLogEx(NORMAL, "GA Get Nonce: %u us", resp.d.asDwords[1]);
        PrintAndLogEx(NORMAL, "GA Map Nonce: %u us", resp.d.asDwords[2]);
        PrintAndLogEx(NORMAL, "GA Perform Key Agreement: %u us", resp.d.asDwords[3]);
        PrintAndLogEx(NORMAL, "GA Mutual Authenticate: %u us", resp.d.asDwords[4]);
    }
    return 1;
}

static command_t CommandTable[] = {
    {"help",    CmdHelp,                   1, "This help"},
    {"cnonces", CmdHFEPACollectPACENonces, 0, "<m> <n> <d> Acquire n>0 encrypted PACE nonces of size m>0 with d sec pauses"},
    {"preplay", CmdHFEPAPACEReplay,        0, "<mse> <get> <map> <pka> <ma> Perform PACE protocol by replaying given APDUs"},
    {NULL, NULL, 0, NULL}
};

int CmdHelp(const char *Cmd) {
    CmdsHelp(CommandTable);
    return 0;
}

int CmdHFEPA(const char *Cmd) {
    clearCommandBuffer();
    CmdsParse(CommandTable, Cmd);
    return 0;
}
