//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// asn.1 dumping
//-----------------------------------------------------------------------------
#ifndef ASN1DUMP_H
#define ASN1DUMP_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include "emv/tlv.h"

bool asn1_tag_dump(const struct tlv *tlv, FILE *f, int level, bool *candump);

#endif /* asn1utils.h */
