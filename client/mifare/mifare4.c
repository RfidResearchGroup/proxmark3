//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
// Copyright (C) 2018 drHatson
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// iso14443-4 mifare commands
//-----------------------------------------------------------------------------

#include "mifare4.h"
#include <ctype.h>
#include <string.h>
#include "cmdhf14a.h"
#include "util.h"
#include "ui.h"
#include "crypto/libpcrypto.h"

static bool VerboseMode = false;
void mfpSetVerboseMode(bool verbose) {
    VerboseMode = verbose;
}

typedef struct {
    uint8_t Code;
    const char *Description;
} PlusErrorsElm;

static const PlusErrorsElm PlusErrors[] = {
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
int PlusErrorsLen = sizeof(PlusErrors) / sizeof(PlusErrorsElm);

const char *mfpGetErrorDescription(uint8_t errorCode) {
    for (int i = 0; i < PlusErrorsLen; i++)
        if (errorCode == PlusErrors[i].Code)
            return PlusErrors[i].Description;

    return PlusErrors[0].Description;
}

AccessConditions_t MFAccessConditions[] = {
    {0x00, "rdAB wrAB incAB dectrAB"},
    {0x01, "rdAB dectrAB"},
    {0x02, "rdAB"},
    {0x03, "rdB wrB"},
    {0x04, "rdAB wrB"},
    {0x05, "rdB"},
    {0x06, "rdAB wrB incB dectrAB"},
    {0x07, "none"}
};

AccessConditions_t MFAccessConditionsTrailer[] = {
    {0x00, "rdAbyA rdCbyA rdBbyA wrBbyA"},
    {0x01, "wrAbyA rdCbyA wrCbyA rdBbyA wrBbyA"},
    {0x02, "rdCbyA rdBbyA"},
    {0x03, "wrAbyB rdCbyAB wrCbyB wrBbyB"},
    {0x04, "wrAbyB rdCbyAB wrBbyB"},
    {0x05, "rdCbyAB wrCbyB"},
    {0x06, "rdCbyAB"},
    {0x07, "rdCbyAB"}
};

char *mfGetAccessConditionsDesc(uint8_t blockn, uint8_t *data) {
    static char StaticNone[] = "none";

    uint8_t data1 = ((data[1] >> 4) & 0x0f) >> blockn;
    uint8_t data2 = ((data[2]) & 0x0f) >> blockn;
    uint8_t data3 = ((data[2] >> 4) & 0x0f) >> blockn;

    uint8_t cond = (data1 & 0x01) << 2 | (data2 & 0x01) << 1 | (data3 & 0x01);

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

    return StaticNone;
};

int CalculateEncIVCommand(mf4Session *session, uint8_t *iv, bool verbose) {
    memcpy(&iv[0], session->TI, 4);
    memcpy(&iv[4], &session->R_Ctr, 2);
    memcpy(&iv[6], &session->W_Ctr, 2);
    memcpy(&iv[8], &session->R_Ctr, 2);
    memcpy(&iv[10], &session->W_Ctr, 2);
    memcpy(&iv[12], &session->R_Ctr, 2);
    memcpy(&iv[14], &session->W_Ctr, 2);

    return 0;
}

int CalculateEncIVResponse(mf4Session *session, uint8_t *iv, bool verbose) {
    memcpy(&iv[0], &session->R_Ctr, 2);
    memcpy(&iv[2], &session->W_Ctr, 2);
    memcpy(&iv[4], &session->R_Ctr, 2);
    memcpy(&iv[6], &session->W_Ctr, 2);
    memcpy(&iv[8], &session->R_Ctr, 2);
    memcpy(&iv[10], &session->W_Ctr, 2);
    memcpy(&iv[12], session->TI, 4);

    return 0;
}


int CalculateMAC(mf4Session *session, MACType_t mtype, uint8_t blockNum, uint8_t blockCount, uint8_t *data, int datalen, uint8_t *mac, bool verbose) {
    if (!session || !session->Authenticated || !mac || !data || !datalen || datalen < 1)
        return 1;

    memset(mac, 0x00, 8);

    uint16_t ctr = session->R_Ctr;
    switch (mtype) {
        case mtypWriteCmd:
        case mtypWriteResp:
            ctr = session->W_Ctr;
            break;
        case mtypReadCmd:
        case mtypReadResp:
            break;
    }

    uint8_t macdata[2049] = {data[0], (ctr & 0xFF), (ctr >> 8), 0};
    int macdatalen = datalen;
    memcpy(&macdata[3], session->TI, 4);

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
        PrintAndLog("MAC data[%d]: %s", macdatalen, sprint_hex(macdata, macdatalen));

    return aes_cmac8(NULL, session->Kmac, macdata, mac, macdatalen);
}

int MifareAuth4(mf4Session *session, uint8_t *keyn, uint8_t *key, bool activateField, bool leaveSignalON, bool verbose) {
    uint8_t data[257] = {0};
    int datalen = 0;

    uint8_t RndA[17] = {0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x00};
    uint8_t RndB[17] = {0};

    if (session)
        session->Authenticated = false;

    uint8_t cmd1[] = {0x70, keyn[1], keyn[0], 0x00};
    int res = ExchangeRAW14a(cmd1, sizeof(cmd1), activateField, true, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "Exchande raw error: %d", res);
        DropField();
        return 2;
    }

    if (verbose)
        PrintAndLogEx(INFO, "<phase1: %s", sprint_hex(data, datalen));

    if (datalen < 1) {
        PrintAndLogEx(ERR, "Card response wrong length: %d", datalen);
        DropField();
        return 3;
    }

    if (data[0] != 0x90) {
        PrintAndLogEx(ERR, "Card response error: %02x", data[2]);
        DropField();
        return 3;
    }

    if (datalen != 19) { // code 1b + 16b + crc 2b
        PrintAndLogEx(ERR, "Card response must be 19 bytes long instead of: %d", datalen);
        DropField();
        return 3;
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

    res = ExchangeRAW14a(cmd2, sizeof(cmd2), false, true, data, sizeof(data), &datalen);
    if (res) {
        PrintAndLogEx(ERR, "Exchande raw error: %d", res);
        DropField();
        return 4;
    }

    if (verbose)
        PrintAndLogEx(INFO, "<phase2: %s", sprint_hex(data, datalen));

    aes_decode(NULL, key, &data[1], raw, 32);

    if (verbose) {
        PrintAndLogEx(INFO, "res: %s", sprint_hex(raw, 32));
        PrintAndLogEx(INFO, "RndA`: %s", sprint_hex(&raw[4], 16));
    }

    if (memcmp(&raw[4], &RndA[1], 16)) {
        PrintAndLogEx(ERR, "\nAuthentication FAILED. rnd not equal");
        if (verbose) {
            PrintAndLogEx(ERR, "RndA reader: %s", sprint_hex(&RndA[1], 16));
            PrintAndLogEx(ERR, "RndA   card: %s", sprint_hex(&raw[4], 16));
        }
        DropField();
        return 5;
    }

    if (verbose) {
        PrintAndLogEx(INFO, " TI: %s", sprint_hex(raw, 4));
        PrintAndLogEx(INFO, "pic: %s", sprint_hex(&raw[20], 6));
        PrintAndLogEx(INFO, "pcd: %s", sprint_hex(&raw[26], 6));
    }

    uint8_t kenc[16] = {0};
    memcpy(&kenc[0], &RndA[11], 5);
    memcpy(&kenc[5], &RndB[11], 5);
    for (int i = 0; i < 5; i++)
        kenc[10 + i] = RndA[4 + i] ^ RndB[4 + i];
    kenc[15] = 0x11;

    aes_encode(NULL, key, kenc, kenc, 16);
    if (verbose) {
        PrintAndLogEx(INFO, "kenc: %s", sprint_hex(kenc, 16));
    }

    uint8_t kmac[16] = {0};
    memcpy(&kmac[0], &RndA[7], 5);
    memcpy(&kmac[5], &RndB[7], 5);
    for (int i = 0; i < 5; i++)
        kmac[10 + i] = RndA[0 + i] ^ RndB[0 + i];
    kmac[15] = 0x22;

    aes_encode(NULL, key, kmac, kmac, 16);
    if (verbose) {
        PrintAndLogEx(INFO, "kmac: %s", sprint_hex(kmac, 16));
    }

    if (!leaveSignalON)
        DropField();

    if (verbose)
        PrintAndLog("");

    if (session) {
        session->Authenticated = true;
        session->R_Ctr = 0;
        session->W_Ctr = 0;
        session->KeyNum = keyn[1] + (keyn[0] << 8);
        memmove(session->RndA, RndA, 16);
        memmove(session->RndB, RndB, 16);
        memmove(session->Key, key, 16);
        memmove(session->TI, raw, 4);
        memmove(session->PICCap2, &raw[20], 6);
        memmove(session->PCDCap2, &raw[26], 6);
        memmove(session->Kenc, kenc, 16);
        memmove(session->Kmac, kmac, 16);
    }

    if (verbose)
        PrintAndLogEx(INFO, "Authentication OK");

    return 0;
}

int intExchangeRAW14aPlus(uint8_t *datain, int datainlen, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen) {
    if (VerboseMode)
        PrintAndLogEx(INFO, ">>> %s", sprint_hex(datain, datainlen));

    int res = ExchangeRAW14a(datain, datainlen, activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);

    if (VerboseMode)
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

int MFPReadBlock(mf4Session *session, bool plain, uint8_t blockNum, uint8_t blockCount, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac) {
    uint8_t rcmd[4 + 8] = {(plain ? (0x37) : (0x33)), blockNum, 0x00, blockCount};
    if (!plain && session)
        CalculateMAC(session, mtypReadCmd, blockNum, blockCount, rcmd, 4, &rcmd[4], VerboseMode);

    int res = intExchangeRAW14aPlus(rcmd, plain ? 4 : sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
    if (res)
        return res;

    if (session)
        session->R_Ctr++;

    if (session && mac && *dataoutlen > 11)
        CalculateMAC(session, mtypReadResp, blockNum, blockCount, dataout, *dataoutlen - 8 - 2, mac, VerboseMode);

    return 0;
}

int MFPWriteBlock(mf4Session *session, uint8_t blockNum, uint8_t *data, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac) {
    uint8_t rcmd[1 + 2 + 16 + 8] = {0xA3, blockNum, 0x00};
    memmove(&rcmd[3], data, 16);
    if (session)
        CalculateMAC(session, mtypWriteCmd, blockNum, 1, rcmd, 19, &rcmd[19], VerboseMode);

    int res = intExchangeRAW14aPlus(rcmd, sizeof(rcmd), activateField, leaveSignalON, dataout, maxdataoutlen, dataoutlen);
    if (res)
        return res;

    if (session)
        session->W_Ctr++;

    if (session && mac && *dataoutlen > 3)
        CalculateMAC(session, mtypWriteResp, blockNum, 1, dataout, *dataoutlen, mac, VerboseMode);

    return 0;
}

int mfpReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *dataout, bool verbose) {
    uint8_t keyn[2] = {0};
    bool plain = false;

    uint16_t uKeyNum = 0x4000 + sectorNo * 2 + (keyType ? 1 : 0);
    keyn[0] = uKeyNum >> 8;
    keyn[1] = uKeyNum & 0xff;
    if (verbose)
        PrintAndLogEx(INFO, "--sector[%d]:%02x key:%04x", mfNumBlocksPerSector(sectorNo), sectorNo, uKeyNum);

    mf4Session session;
    int res = MifareAuth4(&session, keyn, key, true, true, verbose);
    if (res) {
        PrintAndLogEx(ERR, "Sector %d authentication error: %d", sectorNo, res);
        return res;
    }

    uint8_t data[250] = {0};
    int datalen = 0;
    uint8_t mac[8] = {0};
    uint8_t firstBlockNo = mfFirstBlockOfSector(sectorNo);
    for (int n = firstBlockNo; n < firstBlockNo + mfNumBlocksPerSector(sectorNo); n++) {
        res = MFPReadBlock(&session, plain, n & 0xff, 1, false, true, data, sizeof(data), &datalen, mac);
        if (res) {
            PrintAndLogEx(ERR, "Sector %d read error: %d", sectorNo, res);
            DropField();
            return res;
        }

        if (datalen && data[0] != 0x90) {
            PrintAndLogEx(ERR, "Sector %d card read error: %02x %s", sectorNo, data[0], mfpGetErrorDescription(data[0]));
            DropField();
            return 5;
        }
        if (datalen != 1 + 16 + 8 + 2) {
            PrintAndLogEx(ERR, "Sector %d error returned data length:%d", sectorNo, datalen);
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

// Mifare Memory Structure: up to 32 Sectors with 4 blocks each (1k and 2k cards),
// plus evtl. 8 sectors with 16 blocks each (4k cards)
uint8_t mfNumBlocksPerSector(uint8_t sectorNo) {
    if (sectorNo < 32)
        return 4;
    else
        return 16;
}

uint8_t mfFirstBlockOfSector(uint8_t sectorNo) {
    if (sectorNo < 32)
        return sectorNo * 4;
    else
        return 32 * 4 + (sectorNo - 32) * 16;
}

uint8_t mfSectorTrailer(uint8_t blockNo) {
    if (blockNo < 32 * 4) {
        return (blockNo | 0x03);
    } else {
        return (blockNo | 0x0f);
    }
}

bool mfIsSectorTrailer(uint8_t blockNo) {
    return (blockNo == mfSectorTrailer(blockNo));
}

uint8_t mfSectorNum(uint8_t blockNo) {
    if (blockNo < 32 * 4)
        return blockNo / 4;
    else
        return 32 + (blockNo - 32 * 4) / 16;

}
