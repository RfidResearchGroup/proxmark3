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
// iso14443-4 mifare commands
//-----------------------------------------------------------------------------

#include "mifare4.h"
#include <string.h>
#include "commonutil.h"  // ARRAYLEN
#include "comms.h" // DropField
#include "cmdhf14a.h"
#include "ui.h"
#include "crypto/libpcrypto.h"

static bool g_verbose_mode = false;
void mfpSetVerboseMode(bool verbose) {
    g_verbose_mode = verbose;
}

static const PlusErrorsElm_t PlusErrors[] = {
    {0xFF, ""},
    {0x00, "Transfer cannot be granted within the current authentication."},
    {0x06, "Access Conditions not fulfilled. Block does not exist, block is not a value block."},
    {0x07, "Too many read or write commands in the session or in the transaction."},
    {0x08, "Invalid MAC in command or response"},
    {0x09, "Block Number is not valid"},
    {0x0a, "Invalid block number, not existing block number"},
    {0x0b, "The current command code not available at the current card state."},
    {0x0c, "Length error"},
    {0x0f, "General Manipulation Error. Failure in the operation of the PICC (cannot write to the data block), etc."},
    {0x90, "OK"},
};

const char *mfpGetErrorDescription(uint8_t errorCode) {
    for (int i = 0; i < ARRAYLEN(PlusErrors); i++)
        if (errorCode == PlusErrors[i].Code)
            return PlusErrors[i].Description;

    return PlusErrors[0].Description;
}

AccessConditions_t MFAccessConditions[] = {
    {0x00, "read AB; write AB; increment AB; decrement transfer restore AB", "transport config"},
    {0x01, "read AB; decrement transfer restore AB", "value block"},
    {0x02, "read AB", "read/write block"},
    {0x03, "read B; write B", "read/write block"},
    {0x04, "read AB; write B", "read/write block"},
    {0x05, "read B", "read/write block"},
    {0x06, "read AB; write B; increment B; decrement transfer restore AB", "value block"},
    {0x07, "none", "read/write block"}
};

AccessConditions_t MFAccessConditionsTrailer[] = {
    {0x00, "read A by A; read ACCESS by A; read/write B by A", ""},
    {0x01, "write A by A; read/write ACCESS by A; read/write B by A", ""},
    {0x02, "read ACCESS by A; read B by A", ""},
    {0x03, "write A by B; read ACCESS by AB; write ACCESS by B; write B by B", ""},
    {0x04, "write A by B; read ACCESS by AB; write B by B", ""},
    {0x05, "read ACCESS by AB; write ACCESS by B", ""},
    {0x06, "read ACCESS by AB", ""},
    {0x07, "read ACCESS by AB", ""}
};

bool mfValidateAccessConditions(const uint8_t *data) {
    uint8_t nd1 = NIBBLE_LOW(data[0]);
    uint8_t nd2 = NIBBLE_HIGH(data[0]);
    uint8_t nd3 = NIBBLE_LOW(data[1]);
    uint8_t d1  = NIBBLE_HIGH(data[1]);
    uint8_t d2  = NIBBLE_LOW(data[2]);
    uint8_t d3  = NIBBLE_HIGH(data[2]);

    return ((nd1 == (d1 ^ 0xF)) && (nd2 == (d2 ^ 0xF)) && (nd3 == (d3 ^ 0xF)));
}

bool mfReadOnlyAccessConditions(uint8_t blockn, const uint8_t *data) {

    uint8_t d1  = NIBBLE_HIGH(data[1]) >> blockn;
    uint8_t d2  = NIBBLE_LOW(data[2]) >> blockn;
    uint8_t d3  = NIBBLE_HIGH(data[2]) >> blockn;
    uint8_t cond = (d1 & 0x01) << 2 | (d2 & 0x01) << 1 | (d3 & 0x01);

    if (blockn == 3) {
        if ((cond == 0x02) || (cond == 0x06) || (cond == 0x07)) return true;
    } else {
        if ((cond == 0x02) || (cond == 0x05)) return true;
    }
    return false;
}

const char *mfGetAccessConditionsDesc(uint8_t blockn, const uint8_t *data) {
    uint8_t d1 = NIBBLE_HIGH(data[1]) >> blockn;
    uint8_t d2 = NIBBLE_LOW(data[2]) >> blockn;
    uint8_t d3 = NIBBLE_HIGH(data[2]) >> blockn;

    uint8_t cond = (d1 & 0x01) << 2 | (d2 & 0x01) << 1 | (d3 & 0x01);

    if (blockn == 3) {
        for (int i = 0; i < ARRAYLEN(MFAccessConditionsTrailer); i++)
            if (MFAccessConditionsTrailer[i].cond == cond) {
                return MFAccessConditionsTrailer[i].description;
            }
    } else {
        for (int i = 0; i < ARRAYLEN(MFAccessConditions); i++)
            if (MFAccessConditions[i].cond == cond) {
                return MFAccessConditions[i].description;
            }
    };

    static char none[] = "none";
    return none;
}

uint8_t mf_get_accesscondition(uint8_t blockn, const uint8_t *data) {
    uint8_t d1 = NIBBLE_HIGH(data[1]) >> blockn;
    uint8_t d2 = NIBBLE_LOW(data[2]) >> blockn;
    uint8_t d3 = NIBBLE_HIGH(data[2]) >> blockn;
    return (d1 & 0x01) << 2 | (d2 & 0x01) << 1 | (d3 & 0x01);
}

/*
static int CalculateEncIVCommand(mf4Session_t *mf4session, uint8_t *iv, bool verbose) {
    memcpy(&iv[0], &mf4session->TI, 4);
    memcpy(&iv[4], &mf4session->R_Ctr, 2);
    memcpy(&iv[6], &mf4session->W_Ctr, 2);
    memcpy(&iv[8], &mf4session->R_Ctr, 2);
    memcpy(&iv[10], &mf4session->W_Ctr, 2);
    memcpy(&iv[12], &mf4session->R_Ctr, 2);
    memcpy(&iv[14], &mf4session->W_Ctr, 2);

    return 0;
}

static int CalculateEncIVResponse(mf4Session *mf4session, uint8_t *iv, bool verbose) {
    memcpy(&iv[0], &mf4session->R_Ctr, 2);
    memcpy(&iv[2], &mf4session->W_Ctr, 2);
    memcpy(&iv[4], &mf4session->R_Ctr, 2);
    memcpy(&iv[6], &mf4session->W_Ctr, 2);
    memcpy(&iv[8], &mf4session->R_Ctr, 2);
    memcpy(&iv[10], &mf4session->W_Ctr, 2);
    memcpy(&iv[12], &mf4session->TI, 4);

    return 0;
}
*/

int CalculateMAC(mf4Session_t *mf4session, MACType_t mtype, uint8_t blockNum, uint8_t blockCount, uint8_t *data, int datalen, uint8_t *mac, bool verbose) {
    if (!mf4session || !mf4session->Authenticated || !mac || !data || !datalen)
        return 1;

    memset(mac, 0x00, 8);

    uint16_t ctr = mf4session->R_Ctr;
    switch (mtype) {
        case mtypWriteCmd:
        case mtypWriteResp:
            ctr = mf4session->W_Ctr;
            break;
        case mtypReadCmd:
        case mtypReadResp:
            break;
    }

    uint8_t macdata[2049] = {data[0], (ctr & 0xFF), (ctr >> 8), 0};
    int macdatalen = datalen;
    memcpy(&macdata[3], mf4session->TI, 4);

    switch (mtype) {
        case mtypReadCmd:
            memcpy(&macdata[7], &data[1], datalen - 1);
            macdatalen = datalen + 6;
            break;
        case mtypReadResp:
            macdata[7] = blockNum;
            macdata[8] = 0;
            macdata[9] = blockCount;
            memcpy(&macdata[10], &data[1], datalen - 1);
            macdatalen = datalen + 9;
            break;
        case mtypWriteCmd:
            memcpy(&macdata[7], &data[1], datalen - 1);
            macdatalen = datalen + 6;
            break;
        case mtypWriteResp:
            macdatalen = 1 + 6;
            break;
    }

    if (verbose)
        PrintAndLogEx(INFO, "MAC data[%d]: %s", macdatalen, sprint_hex(macdata, macdatalen));

    return aes_cmac8(NULL, mf4session->Kmac, macdata, mac, macdatalen);
}

int MifareAuth4(mf4Session_t *mf4session, uint8_t *keyn, uint8_t *key, bool activateField, bool leaveSignalON, bool dropFieldIfError, bool verbose, bool silentMode) {
    uint8_t data[257] = {0};
    int datalen = 0;

    uint8_t RndA[17] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
    uint8_t RndB[17] = {0};

    if (silentMode)
        verbose = false;

    if (mf4session)
        mf4session->Authenticated = false;

    uint8_t cmd1[] = {0x70, keyn[1], keyn[0], 0x00};
    int res = ExchangeRAW14a(cmd1, sizeof(cmd1), activateField, true, data, sizeof(data), &datalen, silentMode);
    if (res) {
        if (!silentMode) PrintAndLogEx(ERR, "Exchange raw error: %d", res);
        if (dropFieldIfError) DropField();
        return PM3_ERFTRANS;
    }

    if (verbose)
        PrintAndLogEx(INFO, "<phase1: %s", sprint_hex(data, datalen));

    if (datalen < 1) {
        if (!silentMode) PrintAndLogEx(ERR, "Card response wrong length: %d", datalen);
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    if (data[0] != 0x90) {
        if (!silentMode) PrintAndLogEx(ERR, "Card response error: %02x %s", data[0], mfpGetErrorDescription(data[0]));
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    if (datalen != 19) { // code 1b + 16b + crc 2b
        if (!silentMode) PrintAndLogEx(ERR, "Card response must be 19 bytes long instead of: %d", datalen);
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    aes_decode(NULL, key, &data[1], RndB, 16);
    RndB[16] = RndB[0];
    if (verbose)
        PrintAndLogEx(INFO, "RndB: %s", sprint_hex(RndB, 16));

    uint8_t cmd2[33] = {0};
    cmd2[0] = 0x72;

    uint8_t raw[32] = {0};
    memmove(raw, RndA, 16);
    memmove(&raw[16], &RndB[1], 16);

    aes_encode(NULL, key, raw, &cmd2[1], 32);
    if (verbose)
        PrintAndLogEx(INFO, ">phase2: %s", sprint_hex(cmd2, 33));

    res = ExchangeRAW14a(cmd2, sizeof(cmd2), false, true, data, sizeof(data), &datalen, silentMode);
    if (res) {
        if (!silentMode) PrintAndLogEx(ERR, "Exchange raw error: %d", res);
        if (dropFieldIfError) DropField();
        return PM3_ERFTRANS;
    }

    if (verbose)
        PrintAndLogEx(INFO, "<phase2: %s", sprint_hex(data, datalen));

    aes_decode(NULL, key, &data[1], raw, 32);

    if (verbose) {
        PrintAndLogEx(INFO, "res: %s", sprint_hex(raw, 32));
        PrintAndLogEx(INFO, "RndA`: %s", sprint_hex(&raw[4], 16));
    }

    if (memcmp(&raw[4], &RndA[1], 16)) {
        if (!silentMode) PrintAndLogEx(ERR, "\nAuthentication FAILED. rnd is not equal");
        if (verbose) {
            PrintAndLogEx(ERR, "RndA reader: %s", sprint_hex(&RndA[1], 16));
            PrintAndLogEx(ERR, "RndA   card: %s", sprint_hex(&raw[4], 16));
        }
        if (dropFieldIfError) DropField();
        return PM3_EWRONGANSWER;
    }

    if (verbose) {
        PrintAndLogEx(INFO, " TI: %s", sprint_hex(raw, 4));
        PrintAndLogEx(INFO, "pic: %s", sprint_hex(&raw[20], 6));
        PrintAndLogEx(INFO, "pcd: %s", sprint_hex(&raw[26], 6));
    }

    uint8_t kenc[16] = {0};
    memcpy(&kenc[0], &RndA[11], 5);
    memcpy(&kenc[5], &RndB[11], 5);
    for (int i = 0; i < 5; i++) {
        kenc[10 + i] = RndA[4 + i] ^ RndB[4 + i];
    }
    kenc[15] = 0x11;

    aes_encode(NULL, key, kenc, kenc, 16);
    if (verbose) {
        PrintAndLogEx(INFO, "kenc: %s", sprint_hex(kenc, 16));
    }

    uint8_t kmac[16] = {0};
    memcpy(&kmac[0], &RndA[7], 5);
    memcpy(&kmac[5], &RndB[7], 5);
    for (int i = 0; i < 5; i++) {
        kmac[10 + i] = RndA[0 + i] ^ RndB[0 + i];
    }
    kmac[15] = 0x22;

    aes_encode(NULL, key, kmac, kmac, 16);
    if (verbose) {
        PrintAndLogEx(INFO, "kmac: %s", sprint_hex(kmac, 16));
    }

    if (!leaveSignalON)
        DropField();

    if (verbose)
        PrintAndLogEx(NORMAL, "");

    if (mf4session) {
        mf4session->Authenticated = true;
        mf4session->R_Ctr = 0;
        mf4session->W_Ctr = 0;
        mf4session->KeyNum = keyn[1] + (keyn[0] << 8);
        memmove(mf4session->RndA, RndA, 16);
        memmove(mf4session->RndB, RndB, 16);
        memmove(mf4session->Key, key, 16);
        memmove(mf4session->TI, raw, 4);
        memmove(mf4session->PICCap2, &raw[20], 6);
        memmove(mf4session->PCDCap2, &raw[26], 6);
        memmove(mf4session->Kenc, kenc, 16);
        memmove(mf4session->Kmac, kmac, 16);
    }

    if (verbose)
        PrintAndLogEx(INFO, "Authentication OK");

    return PM3_SUCCESS;
}

static int intExchangeRAW14aPlus(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    if (g_verbose_mode)
        PrintAndLogEx(INFO, ">>> %s", sprint_hex(datain, datainlen));

    int res = ExchangeRAW14a(datain, datainlen, activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen, false);

    if (g_verbose_mode)
        PrintAndLogEx(INFO, "<<< %s", sprint_hex(dataout, *dataoutlen));

    return res;
}

int MFPWritePerso(uint8_t *keyNum, uint8_t *key, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t rcmd[3 + 16] = {0xa8, keyNum[1], keyNum[0], 0x00};
    memmove(&rcmd[3], key, 16);

    return intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
}

int MFPCommitPerso(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t rcmd[1] = {0xaa};

    return intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
}

int MFPReadBlock(mf4Session_t *mf4session, bool plain, uint8_t blockNum, uint8_t blockCount, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac) {
    uint8_t rcmd[4 + 8] = {(plain ? (0x37) : (0x33)), blockNum, 0x00, blockCount};
    if (!plain && mf4session)
        CalculateMAC(mf4session, mtypReadCmd, blockNum, blockCount, rcmd, 4, &rcmd[4], g_verbose_mode);

    int res = intExchangeRAW14aPlus(rcmd, plain ? 4 : sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
    if (res)
        return res;

    if (mf4session)
        mf4session->R_Ctr++;

    if (mf4session && mac && *dataoutlen > 11)
        CalculateMAC(mf4session, mtypReadResp, blockNum, blockCount, dataout, *dataoutlen - 8 - 2, mac, g_verbose_mode);

    return 0;
}

int MFPWriteBlock(mf4Session_t *mf4session, uint8_t blockNum, uint8_t *data, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac) {
    uint8_t rcmd[1 + 2 + 16 + 8] = {0xA3, blockNum, 0x00};
    memmove(&rcmd[3], data, 16);
    if (mf4session)
        CalculateMAC(mf4session, mtypWriteCmd, blockNum, 1, rcmd, 19, &rcmd[19], g_verbose_mode);

    int res = intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
    if (res)
        return res;

    if (mf4session)
        mf4session->W_Ctr++;

    if (mf4session && mac && *dataoutlen > 3)
        CalculateMAC(mf4session, mtypWriteResp, blockNum, 1, dataout, *dataoutlen, mac, g_verbose_mode);

    return 0;
}

int mfpReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *dataout, bool verbose) {
    uint8_t keyn[2] = {0};
    bool plain = false;

    uint16_t uKeyNum = 0x4000 + sectorNo * 2 + (keyType ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--sector[%u]:%02x key:%04x", mfNumBlocksPerSector(sectorNo), sectorNo, uKeyNum);

    mf4Session_t _session;
    int res = MifareAuth4(&_session, keyn, key, true, true, true, verbose, false);
    if (res) {
        PrintAndLogEx(ERR, "Sector %u authentication error: %d", sectorNo, res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    uint8_t firstBlockNo = mfFirstBlockOfSector(sectorNo);
    for (int n = firstBlockNo; n < firstBlockNo + mfNumBlocksPerSector(sectorNo); n++) {
        res = MFPReadBlock(&_session, plain, n & 0xff, 1, false, true, data, sizeof(data), &datalen, mac);
        if (res) {
            PrintAndLogEx(ERR, "Sector %u read error: %d", sectorNo, res);
            DropField();
            return res;
        }

        if (datalen && data[0] != 0x90) {
            PrintAndLogEx(ERR, "Sector %u card read error: %02x %s", sectorNo, data[0], mfpGetErrorDescription(data[0]));
            DropField();
            return 5;
        }
        if (datalen != 1 + 16 + 8 + 2) {
            PrintAndLogEx(ERR, "Sector %u error returned data length:%d", sectorNo, datalen);
            DropField();
            return 6;
        }

        memcpy(&dataout[(n - firstBlockNo) * 16], &data[1], 16);

        if (verbose)
            PrintAndLogEx(INFO, "data[%03d]: %s", n, sprint_hex(&data[1], 16));

        if (memcmp(&data[1 + 16], mac, 8)) {
            PrintAndLogEx(WARNING, "WARNING: mac on block %d not equal...", n);
            PrintAndLogEx(WARNING, "MAC   card: %s", sprint_hex(&data[1 + 16], 8));
            PrintAndLogEx(WARNING, "MAC reader: %s", sprint_hex(mac, 8));

            if (!verbose)
                return 7;
        } else {
            if (verbose)
                PrintAndLogEx(INFO, "MAC: %s", sprint_hex(&data[1 + 16], 8));
        }
    }
    DropField();

    return 0;
}

int MFPGetSignature(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t c[] = {0x3c, 0x00};
    return intExchangeRAW14aPlus(c, sizeof(c), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
}

int MFPGetVersion(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    uint8_t tmp[20] = {0};
    uint8_t c[] = {0x60};
    int res = intExchangeRAW14aPlus(c, sizeof(c), activateField, true, tmp, maxdataoutlen, dataoutlen);
    if (res != 0) {
        DropField();
        *dataoutlen = 0;
        return res;
    }

    memcpy(dataout, tmp + 1, (*dataoutlen - 3));

    *dataoutlen = 0;
    // MFDES_ADDITIONAL_FRAME
    if (tmp[0] == 0xAF) {
        c[0] = 0xAF;
        res = intExchangeRAW14aPlus(c, sizeof(c), false, true, tmp, maxdataoutlen, dataoutlen);
        if (res == 0) {

            memcpy(dataout + 7, tmp + 1, (*dataoutlen - 3));

            // MFDES_ADDITIONAL_FRAME
            res = intExchangeRAW14aPlus(c, sizeof(c), false, false, tmp, maxdataoutlen, dataoutlen);
            if (res == 0) {
                if (tmp[0] == 0x90) {
                    memcpy(dataout + 7 + 7, tmp + 1, (*dataoutlen - 3));
                    *dataoutlen = 28;
                }
            }
        }
    }
    DropField();
    return res;
}

// Mifare Memory Structure: up to 32 Sectors with 4 blocks each (1k and 2k cards),
// plus evtl. 8 sectors with 16 blocks each (4k cards)
uint8_t mfNumBlocksPerSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return 4;
    } else {
        return 16;
    }
}

uint8_t mfFirstBlockOfSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return sectorNo * 4;
    } else {
        return 32 * 4 + (sectorNo - 32) * 16;
    }
}

uint8_t mfSectorTrailerOfSector(uint8_t sectorNo) {
    if (sectorNo < 32) {
        return (sectorNo * 4) | 0x03;
    } else {
        return (32 * 4 + (sectorNo - 32) * 16) | 0x0f;
    }
}

// assumes blockno is 0-255..
uint8_t mfSectorTrailer(uint16_t blockNo) {
    if (blockNo < 32 * 4) {
        return (blockNo | 0x03);
    } else {
        return (blockNo | 0x0F);
    }
}

// assumes blockno is 0-255..
bool mfIsSectorTrailer(uint16_t blockNo) {
    return (blockNo == mfSectorTrailer(blockNo));
}

// assumes blockno is 0-255..
uint8_t mfSectorNum(uint16_t blockNo) {
    if (blockNo < 32 * 4)
        return (blockNo / 4);
    else
        return (32 + (blockNo - 32 * 4) / 16);

}

bool mfIsSectorTrailerBasedOnBlocks(uint8_t sectorno, uint16_t blockno) {
    if (sectorno < 32) {
        return ((blockno | 0x03) == blockno);
    } else {
        return ((blockno | 0x0F) == blockno);
    }
}
