//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// CIPURSE transport cards data and commands
//-----------------------------------------------------------------------------

#ifndef __CIPURSECORE_H__
#define __CIPURSECORE_H__

#include "common.h"
#include "emv/apduinfo.h"


#include <jansson.h>
#include "emv/apduinfo.h" // sAPDU

int CIPURSESelect(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);

int CIPURSEChallenge(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);
int CIPURSEMutalAuthenticate(uint8_t keyIndex, uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw);

int CIPURSECreateFile(uint16_t fileID, uint8_t *fileAttr);
int CIPURSEDeleteFile(uint16_t fileID);

int CIPURSESelectFile(uint16_t fileID);
int CIPURSEReadFileAttributes(uint8_t *data, uint16_t *datalen);
int CIPURSEReadBinary(uint16_t offset, uint8_t *data, uint16_t *datalen);
int CIPURSEUpdateBinary(uint16_t offset, uint8_t *data, uint16_t datalen);

#endif /* __CIPURSECORE_H__ */
