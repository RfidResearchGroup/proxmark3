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

extern int TinyCborPrintFIDOPackage(uint8_t cmdCode, uint8_t *data, size_t length);

#endif /* __CBORTOOLS_H__ */
