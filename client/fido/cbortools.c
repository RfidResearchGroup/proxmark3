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

#include "cbortools.h"
#include "cbor.h"


int TinyCborParser(uint8_t *data, size_t length, CborValue *cb) {
	CborParser parser;
	CborError err = cbor_parser_init(data, length, 0, &parser, cb);
   // if (!err)
	 //   err = dumprecursive(cb, 0);

	if (err) {
		fprintf(stderr, "CBOR parsing failure at offset %d: %s\n",
				cb->ptr - data, cbor_error_string(err));
		return 1;
	}	
	
	return 0;
}

int TinyCborPrintFIDOPackage(uint8_t *data, size_t length) {
	CborValue cb;
	int res;
	res = TinyCborParser(data, length, &cb);
	if (res)
		return res;
	
	return 0;
}

