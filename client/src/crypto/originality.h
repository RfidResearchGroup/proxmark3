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
// originality checks with known pk
//-----------------------------------------------------------------------------

#ifndef ORIGINALITY_H
#define ORIGINALITY_H

#include "common.h"
#include "commonutil.h"
#include "libpcrypto.h"
#include <mbedtls/pk.h>
#include <mbedtls/ecp.h>

typedef enum {PK_MFC, PK_MFUL, PK_MFULAES, PK_MFP, PK_MFDES, PK_ST25TA, PK_ST25TN, PK_ST25TV, PK_15, PK_MIK, PK_ALL} pk_type_t;

typedef struct {
    const pk_type_t type;
    const mbedtls_ecp_group_id grp_id;
    const uint8_t keylen;
    const char *desc;
    const char *value;
} ecdsa_publickey_ng_t;

int originality_check_verify(uint8_t *data, uint8_t data_len, uint8_t *signature, uint8_t signature_len, pk_type_t type);
int originality_check_verify_ex(uint8_t *data, uint8_t data_len, uint8_t *signature, uint8_t signature_len, pk_type_t type, bool reverse, bool hash);
int originality_check_print(uint8_t *signature, int signature_len, int index);

#endif /* originality.h */
