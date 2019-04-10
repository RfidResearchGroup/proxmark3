//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Tools for work with CBOR format http://cbor.io/spec.html
// via Intel tinycbor (https://github.com/intel/tinycbor) library
//-----------------------------------------------------------------------------
//

#ifndef __CBORTOOLS_H__
#define __CBORTOOLS_H__

#include <stddef.h>
#include <stdint.h>
#include <jansson.h>
#include <cbor.h>

#define cbor_check_if(r) if ((r) != CborNoError) {return r;} else
#define cbor_check(r) if ((r) != CborNoError) return r;

int TinyCborPrintFIDOPackage(uint8_t cmdCode, bool isResponse, uint8_t *data, size_t length);
int JsonToCbor(json_t *elm, CborEncoder *encoder);

int CborMapGetKeyById(CborParser *parser, CborValue *map, uint8_t *data, size_t dataLen, int key);
CborError CborGetArrayBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen);
CborError CborGetArrayBinStringValueEx(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen, uint8_t *delimeter, size_t delimeterlen);
CborError CborGetBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen);
CborError CborGetArrayStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen, char *delimeter);
CborError CborGetStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen);
CborError CborGetStringValueBuf(CborValue *elm);

int CBOREncodeElm(json_t *root, const char *rootElmId, CborEncoder *encoder);
CborError CBOREncodeClientDataHash(json_t *root, CborEncoder *encoder);

#endif /* __CBORTOOLS_H__ */
