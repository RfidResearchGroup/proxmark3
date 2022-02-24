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
// CIPURSE transport cards data and commands
//-----------------------------------------------------------------------------

#ifndef __CIPURSECORE_H__
#define __CIPURSECORE_H__

#include <jansson.h>
#include <stdbool.h>
#include "common.h"
#include "../iso7816/apduinfo.h"       // sAPDU_t
#include "cipurse/cipursecrypto.h"


#define CIPURSE_DEFAULT_KEY {0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73, 0x73}
#define CIPURSE_DEFAULT_AID {0x41, 0x44, 0x20, 0x46, 0x31}

void CIPURSEPrintInfoFile(uint8_t *data, size_t len);

int CIPURSESelect(bool activate_field, bool leave_field_on, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSESelectAID(bool activate_field, bool leave_field_on, uint8_t *aid, size_t aidlen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

int CIPURSEChallenge(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEMutualAuthenticate(uint8_t keyindex, uint8_t *params, uint8_t paramslen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

int CIPURSECreateFile(uint8_t *attr, uint16_t attrlen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEDeleteFile(uint16_t fileid, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEDeleteFileAID(uint8_t *aid, size_t aidLen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

int CIPURSEFormatAll(uint16_t *sw);

int CIPURSESelectFileEx(bool activate_field, bool leave_field_on, uint16_t fileid, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSESelectFile(uint16_t fileid, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSESelectMFDefaultFileEx(bool activate_field, bool leave_field_on, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSESelectMFDefaultFile(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSESelectMFEx(bool activate_field, bool leave_field_on, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSESelectMF(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

int CIPURSEReadFileAttributes(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEUpdateFileAttributes(uint8_t *data, uint16_t datalen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEReadBinary(uint16_t offset, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEUpdateBinary(uint16_t offset, uint8_t *data, uint16_t datalen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

int CIPURSEUpdateKey(uint8_t encrypt_key_num, uint8_t key_num, uint8_t *key, uint16_t key_len, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);
int CIPURSEUpdateKeyAttrib(uint8_t key_num, uint8_t key_attrib, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw);

int CIPURSECommitTransaction(uint16_t *sw);
int CIPURSECancelTransaction(uint16_t *sw);

bool CIPURSEChannelAuthenticate(uint8_t keyindex, uint8_t *key, bool verbose);
void CIPURSECSetActChannelSecurityLevels(CipurseChannelSecurityLevel req, CipurseChannelSecurityLevel resp);

const char *CIPURSEGetSMR(uint8_t smr);
void CIPURSEPrintSMR(const uint8_t *smrrec);
void CIPURSEPrintART(const uint8_t *artrec, size_t artlen);
void CIPURSEPrintEFFileAttr(uint8_t *attr, size_t len);
void CIPURSEPrintFileAttrEx(uint8_t *attr, size_t len, bool isDGI);
void CIPURSEPrintFileAttr(uint8_t *attr, size_t len);
void CIPURSEPrintFileUpdateAttr(uint8_t *attr, size_t len);
void CIPURSEPrintFileDescriptor(uint8_t desc);
void CIPURSEPrintDGIArray(uint8_t *dgi, size_t dgilen);
void CIPURSEPrintDGI(uint8_t *dgi, size_t dgilen);
void CIPURSEPrintKeySecurityAttributes(uint8_t attr);

#endif /* __CIPURSECORE_H__ */
