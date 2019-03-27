//-----------------------------------------------------------------------------
// Copyright (C) 2018 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// asn.1 utils
//-----------------------------------------------------------------------------

#include "asn1utils.h"
#include <ctype.h>
#include <stdlib.h>
#include <mbedtls/asn1.h>
#include "emv/tlv.h"
#include "emv/dump.h"
#include "asn1dump.h"
#include "util.h"

int ecdsa_asn1_get_signature(uint8_t *signature, size_t signaturelen, uint8_t *rval, uint8_t *sval) {
    if (!signature || !signaturelen || !rval || !sval)
        return 1;

    int res = 0;
    unsigned char *p = signature;
    const unsigned char *end = p + signaturelen;
    size_t len;
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
        if (end != p)
            return 2;
    }

exit:
    return res;
}

static bool print_cb(void *data, const struct tlv *tlv, int level, bool is_leaf) {
    bool candump = true;
    asn1_tag_dump(tlv, stdout, level, &candump);
    if (is_leaf && candump) {
        dump_buffer(tlv->value, tlv->len, stdout, level);
    }

    return true;
}

int asn1_print(uint8_t *asn1buf, size_t asn1buflen, char *indent) {

    struct tlvdb *t = tlvdb_parse_multi(asn1buf, asn1buflen);
    if (t) {
        tlvdb_visit(t, print_cb, NULL, 0);
        tlvdb_free(t);
    } else {
        PrintAndLogEx(ERR, "Can't parse data as TLV tree.");
        return 1;
    }

    return 0;
}


