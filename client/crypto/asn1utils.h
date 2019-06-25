//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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

#endif /* asn1utils.h */
