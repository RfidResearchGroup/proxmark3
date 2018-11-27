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

extern int TinyCborPrintFIDOPackage(uint8_t cmdCode, bool isResponse, uint8_t *data, size_t length);
extern int JsonToCbor(json_t *elm, CborEncoder *encoder);

extern int CborMapGetKeyById(CborParser *parser, CborValue *map, uint8_t *data, size_t dataLen, int key);
extern CborError CborGetArrayBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen);
extern CborError CborGetArrayBinStringValueEx(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen, uint8_t *delimeter, size_t delimeterlen);
extern CborError CborGetBinStringValue(CborValue *elm, uint8_t *data, size_t maxdatalen, size_t *datalen);
extern CborError CborGetArrayStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen, char *delimeter);
extern CborError CborGetStringValue(CborValue *elm, char *data, size_t maxdatalen, size_t *datalen);
extern CborError CborGetStringValueBuf(CborValue *elm);

extern int CBOREncodeElm(json_t *root, char *rootElmId, CborEncoder *encoder);
extern CborError CBOREncodeClientDataHash(json_t *root, CborEncoder *encoder);

#endif /* __CBORTOOLS_H__ */
