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

#ifndef MIFARE4_H
#define MIFARE4_H

#include "common.h"

typedef struct {
    bool Authenticated;
    uint8_t Key[16];
    uint16_t KeyNum;
    uint8_t RndA[16];
    uint8_t RndB[16];
    uint8_t TI[4];
    uint8_t PICCap2[6];
    uint8_t PCDCap2[6];
    uint8_t Kenc[16];
    uint8_t Kmac[16];
    uint16_t R_Ctr;
    uint16_t W_Ctr;
} mf4Session_t;

typedef enum {
    mtypReadCmd,
    mtypReadResp,
    mtypWriteCmd,
    mtypWriteResp,
} MACType_t;

typedef struct {
    uint8_t cond;
    const char *description;
    const char *application;
} AccessConditions_t;


typedef struct {
    uint8_t Code;
    const char *Description;
} PlusErrorsElm_t;

void mfpSetVerboseMode(bool verbose);
const char *mfpGetErrorDescription(uint8_t errorCode);

int CalculateMAC(mf4Session_t *mf4session, MACType_t mtype, uint8_t blockNum, uint8_t blockCount, uint8_t *data, int datalen, uint8_t *mac, bool verbose);
int MifareAuth4(mf4Session_t *mf4session, uint8_t *keyn, uint8_t *key, bool activateField, bool leaveSignalON, bool dropFieldIfError, bool verbose, bool silentMode);

int MFPWritePerso(uint8_t *keyNum, uint8_t *key, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
int MFPCommitPerso(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
int MFPReadBlock(mf4Session_t *mf4session, bool plain, uint8_t blockNum, uint8_t blockCount, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac);
int MFPWriteBlock(mf4Session_t *mf4session, uint8_t blockNum, uint8_t *data, bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen, uint8_t *mac);
int mfpReadSector(uint8_t sectorNo, uint8_t keyType, uint8_t *key, uint8_t *dataout, bool verbose);

int MFPGetSignature(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);
int MFPGetVersion(bool activateField, bool leaveSignalON, uint8_t *dataout, int maxdataoutlen, int *dataoutlen);

bool mfValidateAccessConditions(const uint8_t *data);
bool mfReadOnlyAccessConditions(uint8_t blockn, const uint8_t *data);
const char *mfGetAccessConditionsDesc(uint8_t blockn, const uint8_t *data);
uint8_t mf_get_accesscondition(uint8_t blockn, const uint8_t *data);

uint8_t mfNumBlocksPerSector(uint8_t sectorNo);
uint8_t mfFirstBlockOfSector(uint8_t sectorNo);
uint8_t mfSectorTrailerOfSector(uint8_t sectorNo);
uint8_t mfSectorTrailer(uint16_t blockNo);
bool mfIsSectorTrailer(uint16_t blockNo);
bool mfIsSectorTrailerBasedOnBlocks(uint8_t sectorno, uint16_t blockno);
uint8_t mfSectorNum(uint16_t blockNo);


#endif // mifare4.h
