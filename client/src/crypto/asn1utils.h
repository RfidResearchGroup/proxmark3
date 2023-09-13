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
// asn.1 utils
//-----------------------------------------------------------------------------

#ifndef ASN1UTILS_H
#define ASN1UTILS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

int asn1_print(uint8_t *asn1buf, size_t asn1buflen, const char *indent);
int ecdsa_asn1_get_signature(uint8_t *signature, size_t signaturelen, uint8_t *rval, uint8_t *sval);
int asn1_selftest(void);

#endif /* asn1utils.h */
