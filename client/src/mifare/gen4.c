//-----------------------------------------------------------------------------
// Copyright (C) Proxmark3 contributors. See AUTHORS.md for details.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// See LICENSE.txt for the text of the license.
//-----------------------------------------------------------------------------
// Common functionality for low/high-frequency GALLAGHER tag encoding & decoding.
//-----------------------------------------------------------------------------
#include "gen4.h"

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "commonutil.h"
#include "util.h"
#include "ui.h"
#include "mifaredefault.h"
#include "comms.h"
#include "cmdhf14a.h"
#include "protocols.h"
#include "mfkey.h"
#include "util_posix.h"
#include "cmdparser.h"

static int mfG4ExCommand(uint8_t cmd, uint8_t *pwd, uint8_t *data, size_t datalen, uint8_t *response, size_t *responselen, bool verbose) {
    struct p {
        uint8_t cmdheader;
        uint8_t pwd[4];
        uint8_t command;
        uint8_t data[32];
    } PACKED payload;
    memset(&payload, 0, sizeof(payload));

    if (datalen > sizeof(payload.data)) {
        return PM3_EINVARG;
    }

    payload.cmdheader = 0xCF;
    payload.command = cmd;

    if (pwd != NULL) {
        memcpy(payload.pwd, pwd, sizeof(payload.pwd));
    }

    if (data != NULL && datalen > 0) {
        memcpy(payload.data, data, datalen);
    }

    int resplen = 0;

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT | ISO14A_RAW | ISO14A_NO_RATS | ISO14A_APPEND_CRC, 6 + datalen, 0, (uint8_t *)&payload, 6 + datalen);

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        if (resp.oldarg[0] != 2) {
            if (verbose) PrintAndLogEx(ERR, "No card in the field.");
            return PM3_ETIMEOUT;
        }

        iso14a_card_select_t card;
        memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));
        if (verbose) {
            PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
            PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02X %02X"), card.atqa[1], card.atqa[0]);
            PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02X [%" PRIu64 "]"), card.sak, resp.oldarg[0]);
        }
    } else {
        if (verbose) PrintAndLogEx(ERR, "No card in the field.");
        return PM3_ETIMEOUT;
    }

    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
        resplen = resp.oldarg[0];

        if (!resplen) {
            if (verbose) PrintAndLogEx(ERR, "No card response.");
            return PM3_EFAILED;
        }

        resplen = resplen - 2; // 14A CRC
        if (resplen < 0)
            resplen = 0;

        if (resplen > 40) {
            if (verbose) PrintAndLogEx(ERR, "Buffer too small(%d).", resplen);
            return PM3_EOVFLOW;
        }

        if (response != NULL)
            memcpy(response, resp.data.asBytes, resplen);

        if (responselen != NULL)
            *responselen = resplen;

        return PM3_SUCCESS;
    } else {
        if (verbose) PrintAndLogEx(ERR, "Reply timeout.");
        return PM3_ETIMEOUT;
    }
}

int mfG4GetConfig(uint8_t *pwd, uint8_t *data, size_t *datalen, bool verbose) {
    uint8_t resp[40] = {0};
    size_t resplen = 0;

    int res = mfG4ExCommand(GEN4_CMD_DUMP_CONFIG, pwd, NULL, 0, resp, &resplen, verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (data != NULL) {
        memcpy(data, resp, resplen);
    }

    if (datalen != NULL) {
        *datalen = resplen;
    }

    return PM3_SUCCESS;
}

int mfG4GetFactoryTest(uint8_t *pwd, uint8_t *data, size_t *datalen, bool verbose) {
    uint8_t resp[40] = {0};
    size_t resplen = 0;

    int res = mfG4ExCommand(GEN4_CMD_FACTORY_TEST, pwd, NULL, 0, resp, &resplen, verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (data != NULL) {
        memcpy(data, resp, resplen);
    }

    if (datalen != NULL) {
        *datalen = resplen;
    }

    return PM3_SUCCESS;
}

int mfG4ChangePassword(uint8_t *pwd, uint8_t *newpwd, bool verbose) {
    uint8_t resp[40] = {0};
    size_t resplen = 0;

    int res = mfG4ExCommand(GEN4_CMD_CHANGE_PASSWORD, pwd, newpwd, 4, resp, &resplen, verbose);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (resplen != 2 || resp[0] != 0x90 || resp[1] != 0x00) {
        return PM3_EAPDU_FAIL;
    }

    return PM3_SUCCESS;
}

int mfG4GetBlock(uint8_t *pwd, uint8_t blockno, uint8_t *data, uint8_t workFlags) {
    struct p {
        uint8_t blockno;
        uint8_t pwd[4];
        uint8_t workFlags;
    } PACKED payload;
    payload.blockno = blockno;
    memcpy(payload.pwd, pwd, sizeof(payload.pwd));
    payload.workFlags = workFlags;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_G4_RDBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_G4_RDBL, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        return PM3_EUNDEF;
    }

    memcpy(data, resp.data.asBytes, MFBLOCK_SIZE);
    return PM3_SUCCESS;
}

int mfG4SetBlock(uint8_t *pwd, uint8_t blockno, uint8_t *data, uint8_t workFlags) {
    struct p {
        uint8_t blockno;
        uint8_t pwd[4];
        uint8_t data[MFBLOCK_SIZE];
        uint8_t workFlags;
    } PACKED payload;
    payload.blockno = blockno;
    memcpy(payload.pwd, pwd, sizeof(payload.pwd));
    memcpy(payload.data, data, sizeof(payload.data));
    payload.workFlags = workFlags;

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_G4_WRBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_G4_WRBL, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        return PM3_EUNDEF;
    }

    return PM3_SUCCESS;
}
