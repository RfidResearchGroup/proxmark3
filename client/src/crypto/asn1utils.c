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

#include "asn1utils.h"
#include <ctype.h>
#include <stdlib.h>
#include <mbedtls/asn1.h>
#include <string.h>     // memcpy
#include "ui.h"         // Print...
#include "emv/tlv.h"
#include "asn1dump.h"
#include "util.h"


int ecdsa_asn1_get_signature(uint8_t *signature, size_t signaturelen, uint8_t *rval, uint8_t *sval) {

    if (!signature || !signaturelen || !rval || !sval) {
        return PM3_EINVARG;
    }

    uint8_t *p = calloc(sizeof(uint8_t), signaturelen);
    if (p == NULL) {
        return PM3_EMALLOC;
    }

    memcpy(p, signature, signaturelen);
    uint8_t *p_tmp = p;
    const uint8_t *end = p + signaturelen;

    int res = PM3_SUCCESS;
    size_t len = 0;
    mbedtls_mpi xmpi;

    if ((res = mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE)) == 0) {
        mbedtls_mpi_init(&xmpi);
        res = mbedtls_asn1_get_mpi(&p, end, &xmpi);
        if (res) {
            mbedtls_mpi_free(&xmpi);
            goto exit;
        }

        res = mbedtls_mpi_write_binary(&xmpi, rval, 32);
        mbedtls_mpi_free(&xmpi);
        if (res)
            goto exit;

        mbedtls_mpi_init(&xmpi);
        res = mbedtls_asn1_get_mpi(&p, end, &xmpi);
        if (res) {
            mbedtls_mpi_free(&xmpi);
            goto exit;
        }

        res = mbedtls_mpi_write_binary(&xmpi, sval, 32);
        mbedtls_mpi_free(&xmpi);
        if (res)
            goto exit;

        // check size
        if (end != p) {
            free(p_tmp);
            end = NULL;
            return PM3_ESOFT;
        }
    }

exit:
    free(p_tmp);
    end = NULL;
    return res;
}

static void asn1_print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    bool candump = true;
    asn1_tag_dump(tlv, level, &candump);
    if (is_leaf && candump) {
        print_buffer(tlv->value, tlv->len, level + 1);
    }
}

int asn1_print(uint8_t *asn1buf, size_t asn1buflen, const char *indent) {

    struct tlvdb *t = tlvdb_parse_multi(asn1buf, asn1buflen);
    if (t) {
        tlvdb_visit(t, asn1_print_cb, NULL, 0);
        tlvdb_free(t);
    } else {
        PrintAndLogEx(ERR, "Can't parse data as TLV tree");
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}


