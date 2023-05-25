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
// NFC Data Exchange Format (NDEF) functions
//-----------------------------------------------------------------------------

#ifndef _NDEF_H_
#define _NDEF_H_

#include <stdbool.h>
#include "common.h"

#define NDEF_MFC_AID    0xE103

typedef enum {
    tnfEmptyRecord          = 0x00,
    tnfWellKnownRecord      = 0x01,
    tnfMIMEMediaRecord      = 0x02,
    tnfAbsoluteURIRecord    = 0x03,
    tnfExternalRecord       = 0x04,
    tnfUnknownRecord        = 0x05,
    tnfUnchangedRecord      = 0x06,
    tnfReservedRecord       = 0x07,
} TypeNameFormat_t;

typedef enum {
    stNotPresent              = 0x00,
    stRSASSA_PSS_SHA_1        = 0x01,
    stRSASSA_PKCS1_v1_5_WITH_SHA_1 = 0x02,
    stDSA_1024                = 0x03,
    stECDSA_P192              = 0x04,
    stRSASSA_PSS_2048         = 0x05,
    stRSASSA_PKCS1_v1_5_2048  = 0x06,
    stDSA_2048                = 0x07,
    stECDSA_P224              = 0x08,
    stECDSA_K233              = 0x09,
    stECDSA_B233              = 0x0a,
    stECDSA_P256              = 0x0b,
    stNA                      = 0x0c
} ndefSigType_t;

typedef enum {
    sfX_509 = 0x00,
    sfX9_68 = 0x01,
    sfNA    = 0x02
} ndefCertificateFormat_t;

typedef struct {
    bool MessageBegin;
    bool MessageEnd;
    bool ChunkFlag;
    bool ShortRecordBit;
    bool IDLenPresent;
    TypeNameFormat_t TypeNameFormat;
    size_t TypeLen;
    size_t PayloadLen;
    size_t IDLen;
    size_t len;
    size_t RecLen;
    uint8_t *Type;
    uint8_t *Payload;
    uint8_t *ID;
} NDEFHeader_t;

int NDEFDecodeAndPrint(uint8_t *ndef, size_t ndefLen, bool verbose);
int NDEFRecordsDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen, bool verbose);

#endif // _NDEF_H_
