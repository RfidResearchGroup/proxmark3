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
// Tools for work with COSE (CBOR Object Signing and Encryption) rfc8152
// https://tools.ietf.org/html/rfc8152
//-----------------------------------------------------------------------------

#ifndef __COSE_H__
#define __COSE_H__

#include "common.h"

const char *GetCOSEAlgName(int id);
const char *GetCOSEAlgDescription(int id);
const char *GetCOSEktyDescription(int id);
const char *GetCOSECurveDescription(int id);

int COSEGetECDSAKey(uint8_t *data, size_t datalen, bool verbose, uint8_t *public_key);

#endif /* __COSE_H__ */
