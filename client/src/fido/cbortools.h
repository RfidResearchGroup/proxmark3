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
// Tools for work with CBOR format http://cbor.io/spec.html
// via Intel tinycbor (https://github.com/intel/tinycbor) library
//-----------------------------------------------------------------------------

#ifndef __CBORTOOLS_H__
#define __CBORTOOLS_H__

#include "common.h"
#include <jansson.h>
#include <cbor.h>

#define cbor_check_if(r) if ((r) != CborNoError) {return r;} else
#define cbor_check(r) if ((r) != CborNoError) return r;

int TinyCborPrintFIDOPackage(uint8_t cmdCode, bool isResponse, uint8_t *data, size_t length);
int JsonToCbor(json_t *elm, CborEncoder *encoder);

int CborMapGetKeyById(CborParser *parser, CborValue *map, uint8_t *data, size_t dataLen, int key);
CborError CborGetArrayBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen);
CborError CborGetArrayBinStringValueEx(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen, uint8_t *delimiter, size_t delimiterlen);
CborError CborGetBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen);
CborError CborGetArrayStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen, char *delimiter);
CborError CborGetStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen);
CborError CborGetStringValueBuf(CborValue *elm);

int CBOREncodeElm(json_t *root, const char *rootElmId, CborEncoder *encoder);
CborError CBOREncodeClientDataHash(json_t *root, CborEncoder *encoder);

#endif /* __CBORTOOLS_H__ */
