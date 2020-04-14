//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Tools for work with COSE (CBOR Object Signing and Encryption) rfc8152
// https://tools.ietf.org/html/rfc8152
//-----------------------------------------------------------------------------
//

#ifndef __COSE_H__
#define __COSE_H__

#include "common.h"

const char *GetCOSEAlgName(int id);
const char *GetCOSEAlgDescription(int id);
const char *GetCOSEktyDescription(int id);
const char *GetCOSECurveDescription(int id);

int COSEGetECDSAKey(uint8_t *data, size_t datalen, bool verbose, uint8_t *public_key);

#endif /* __COSE_H__ */
