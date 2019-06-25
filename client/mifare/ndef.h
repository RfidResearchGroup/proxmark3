//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// NFC Data Exchange Format (NDEF) functions
//-----------------------------------------------------------------------------

#ifndef _NDEF_H_
#define _NDEF_H_

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

typedef enum {
    tnfEmptyRecord          = 0x00,
    tnfWellKnownRecord      = 0x01,
    tnfMIMEMediaRecord      = 0x02,
    tnfAbsoluteURIRecord    = 0x03,
    tnfExternalRecord       = 0x04,
    tnfUnknownRecord        = 0x05,
    tnfUnchangedRecord      = 0x06
} TypeNameFormat_t;

typedef enum {
    stNotPresent            = 0x00,
    stRSASSA_PSS_SHA_1      = 0x01,
    stRSASSA_PKCS1_v1_5_WITH_SHA_1 = 0x02,
    stDSA                   = 0x03,
    stECDSA                 = 0x04,
    stNA                    = 0x05
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

#endif // _NDEF_H_
