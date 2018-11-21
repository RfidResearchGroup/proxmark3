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

extern int TinyCborPrintFIDOPackage(uint8_t cmdCode, uint8_t *data, size_t length);
extern int JsonToCbor(json_t *elm, CborEncoder *encoder);

#endif /* __CBORTOOLS_H__ */
