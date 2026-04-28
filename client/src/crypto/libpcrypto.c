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
// crypto commands
//-----------------------------------------------------------------------------

#include "crypto/libpcrypto.h"
#include "crypto/asn1utils.h"
#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <ctype.h>
#include <mbedtls/asn1.h>
#include <mbedtls/des.h>
#include <mbedtls/aes.h>
#include <mbedtls/cmac.h>
#include <mbedtls/pk.h>
#include <mbedtls/base64.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/sha1.h>
#include <mbedtls/sha256.h>
#include <mbedtls/sha512.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/blowfish.h>
#include "libpcrypto.h"
#include "util.h"
#include "ui.h"
#include "fileutils.h"
#include "math.h"

#define PCRYPTO_MAX_KEY_INPUT 8192
#define PCRYPTO_MAX_KEY_FILE_BYTES (64 * 1024)

int pcrypto_rng_init(pcrypto_rng_t *rng, const uint8_t *personalization, size_t personalization_len) {
    if (rng == NULL || (personalization_len > 0 && personalization == NULL)) {
        return PM3_EINVARG;
    }

    memset(rng, 0, sizeof(*rng));
    mbedtls_entropy_init(&rng->entropy);
    mbedtls_ctr_drbg_init(&rng->ctr_drbg);

    int ret = mbedtls_ctr_drbg_seed(&rng->ctr_drbg, mbedtls_entropy_func, &rng->entropy,
                                    personalization, personalization_len);
    if (ret != 0) {
        PrintAndLogEx(ERR, "Failed to initialize random generator (mbedtls: %d)", ret);
        mbedtls_ctr_drbg_free(&rng->ctr_drbg);
        mbedtls_entropy_free(&rng->entropy);
        return PM3_ESOFT;
    }

    rng->seeded = true;
    return PM3_SUCCESS;
}

void pcrypto_rng_free(pcrypto_rng_t *rng) {
    if (rng == NULL) {
        return;
    }

    mbedtls_ctr_drbg_free(&rng->ctr_drbg);
    mbedtls_entropy_free(&rng->entropy);
    rng->seeded = false;
}

int pcrypto_rng_fill(pcrypto_rng_t *rng, uint8_t *out, size_t out_len) {
    if (rng == NULL || out == NULL || rng->seeded == false) {
        return PM3_EINVARG;
    }
    if (out_len == 0) {
        return PM3_SUCCESS;
    }

    return (mbedtls_ctr_drbg_random(&rng->ctr_drbg, out, out_len) == 0) ? PM3_SUCCESS : PM3_ESOFT;
}

int pcrypto_rng_fill_oneshot(uint8_t *out, size_t out_len, const char *personalization) {
    if (out == NULL || personalization == NULL) {
        return PM3_EINVARG;
    }

    pcrypto_rng_t rng = {0};
    int res = pcrypto_rng_init(&rng, (const uint8_t *)personalization, strlen(personalization));
    if (res != PM3_SUCCESS) {
        pcrypto_rng_free(&rng);
        return res;
    }

    res = pcrypto_rng_fill(&rng, out, out_len);
    pcrypto_rng_free(&rng);
    return res;
}

static void pcrypto_trim_ascii_inplace(char *text) {
    if (text == NULL) {
        return;
    }

    size_t start = 0;
    size_t len = strlen(text);
    while (start < len && isspace((unsigned char)text[start])) {
        start++;
    }
    while (len > start && isspace((unsigned char)text[len - 1])) {
        len--;
    }

    if (start > 0) {
        memmove(text, text + start, len - start);
    }
    text[len - start] = '\0';
}

static void pcrypto_unescape_newlines_inplace(char *text) {
    if (text == NULL) {
        return;
    }

    size_t read_pos = 0;
    size_t write_pos = 0;
    size_t len = strlen(text);
    while (read_pos < len) {
        if (text[read_pos] == '\\' && (read_pos + 1) < len) {
            char esc = text[read_pos + 1];
            if (esc == 'n') {
                text[write_pos++] = '\n';
                read_pos += 2;
                continue;
            }
            if (esc == 'r') {
                text[write_pos++] = '\r';
                read_pos += 2;
                continue;
            }
            if (esc == 't') {
                text[write_pos++] = '\t';
                read_pos += 2;
                continue;
            }
        }
        text[write_pos++] = text[read_pos++];
    }
    text[write_pos] = '\0';
}

static int pcrypto_copy_without_whitespace(const char *src, char *dst, size_t dst_size, size_t *dst_len) {
    if (src == NULL || dst == NULL || dst_len == NULL || dst_size == 0) {
        return PM3_EINVARG;
    }

    size_t out = 0;
    for (size_t i = 0; src[i] != '\0'; i++) {
        if (isspace((unsigned char)src[i])) {
            continue;
        }
        if ((out + 1) >= dst_size) {
            return PM3_EOVFLOW;
        }
        dst[out++] = src[i];
    }
    dst[out] = '\0';
    *dst_len = out;
    return PM3_SUCCESS;
}

static int pcrypto_extract_priv_scalar_from_pk(const mbedtls_pk_context *pkctx,
                                               mbedtls_ecp_group_id curveid,
                                               uint8_t *out_priv, size_t out_priv_len) {
    if (pkctx == NULL || out_priv == NULL || out_priv_len == 0) {
        return PM3_EINVARG;
    }

    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(pkctx);
    if (!(pk_type == MBEDTLS_PK_ECKEY || pk_type == MBEDTLS_PK_ECKEY_DH)) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pkctx);
    if (ec == NULL || ec->grp.id != curveid) {
        return PM3_EINVARG;
    }
    if (mbedtls_mpi_bitlen(&ec->d) > (out_priv_len * 8U)) {
        return PM3_EINVARG;
    }
    if (mbedtls_ecp_check_privkey(&ec->grp, &ec->d) != 0) {
        return PM3_EINVARG;
    }
    if (mbedtls_mpi_write_binary(&ec->d, out_priv, out_priv_len) != 0) {
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int pcrypto_validate_raw_scalar(const uint8_t *scalar, size_t scalar_len, mbedtls_ecp_group_id curveid);

static int pcrypto_parse_ec_private_blob(const uint8_t *blob, size_t blob_len,
                                         mbedtls_ecp_group_id curveid,
                                         uint8_t *out_priv, size_t out_priv_len) {
    if (blob == NULL || out_priv == NULL || blob_len == 0 || out_priv_len == 0) {
        return PM3_EINVARG;
    }

    mbedtls_pk_context pkctx;
    mbedtls_pk_init(&pkctx);

    int ret = mbedtls_pk_parse_key(&pkctx, blob, blob_len, NULL, 0);
    if (ret != 0) {
        uint8_t *nul_terminated = calloc(blob_len + 1, sizeof(uint8_t));
        if (nul_terminated == NULL) {
            mbedtls_pk_free(&pkctx);
            return PM3_EMALLOC;
        }
        memcpy(nul_terminated, blob, blob_len);
        ret = mbedtls_pk_parse_key(&pkctx, nul_terminated, blob_len + 1, NULL, 0);
        free(nul_terminated);
    }

    if (ret != 0) {
        mbedtls_pk_free(&pkctx);
        return PM3_EINVARG;
    }

    int res = pcrypto_extract_priv_scalar_from_pk(&pkctx, curveid, out_priv, out_priv_len);
    mbedtls_pk_free(&pkctx);
    return res;
}

static int pcrypto_parse_ec_private_scalar_or_blob(const uint8_t *blob, size_t blob_len,
                                                   mbedtls_ecp_group_id curveid,
                                                   uint8_t *out_priv, size_t out_priv_len) {
    if (blob == NULL || out_priv == NULL || blob_len == 0 || out_priv_len == 0) {
        return PM3_EINVARG;
    }

    if (blob_len == out_priv_len &&
            pcrypto_validate_raw_scalar(blob, blob_len, curveid) == PM3_SUCCESS) {
        memcpy(out_priv, blob, out_priv_len);
        return PM3_SUCCESS;
    }

    return pcrypto_parse_ec_private_blob(blob, blob_len, curveid, out_priv, out_priv_len);
}

static int pcrypto_parse_ec_private_base64(const char *input,
                                           mbedtls_ecp_group_id curveid,
                                           uint8_t *out_priv, size_t out_priv_len) {
    if (input == NULL || out_priv == NULL || out_priv_len == 0) {
        return PM3_EINVARG;
    }

    char compact[PCRYPTO_MAX_KEY_INPUT] = {0};
    size_t compact_len = 0;
    int res = pcrypto_copy_without_whitespace(input, compact, sizeof(compact), &compact_len);
    if (res != PM3_SUCCESS || compact_len == 0) {
        return PM3_EINVARG;
    }

    size_t decoded_capacity = ((compact_len * 3) / 4) + 4;
    uint8_t *decoded = calloc(decoded_capacity, sizeof(uint8_t));
    if (decoded == NULL) {
        return PM3_EMALLOC;
    }

    size_t decoded_len = 0;
    int b64_res = mbedtls_base64_decode(decoded, decoded_capacity, &decoded_len,
                                        (const unsigned char *)compact, compact_len);
    if (b64_res != 0 || decoded_len == 0) {
        free(decoded);
        return PM3_EINVARG;
    }

    res = pcrypto_parse_ec_private_scalar_or_blob(decoded, decoded_len, curveid, out_priv, out_priv_len);
    free(decoded);
    return res;
}

static int pcrypto_validate_raw_scalar(const uint8_t *scalar, size_t scalar_len, mbedtls_ecp_group_id curveid) {
    if (scalar == NULL || scalar_len == 0) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_mpi d;
    mbedtls_ecp_group_init(&grp);
    mbedtls_mpi_init(&d);

    int status = PM3_ESOFT;
    if (mbedtls_ecp_group_load(&grp, curveid) != 0) {
        goto out;
    }
    if (mbedtls_mpi_read_binary(&d, scalar, scalar_len) != 0) {
        status = PM3_EINVARG;
        goto out;
    }
    if (mbedtls_ecp_check_privkey(&grp, &d) != 0) {
        status = PM3_EINVARG;
        goto out;
    }
    status = PM3_SUCCESS;

out:
    mbedtls_mpi_free(&d);
    mbedtls_ecp_group_free(&grp);
    return status;
}

static int pcrypto_parse_ec_private_text(const char *input, bool allow_file_path,
                                         mbedtls_ecp_group_id curveid,
                                         uint8_t *out_priv, size_t out_priv_len);

static int pcrypto_parse_ec_private_file(const char *path,
                                         mbedtls_ecp_group_id curveid,
                                         uint8_t *out_priv, size_t out_priv_len) {
    if (path == NULL || out_priv == NULL || out_priv_len == 0) {
        return PM3_EINVARG;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return PM3_EFILE;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return PM3_EFILE;
    }
    long file_len_l = ftell(f);
    if (file_len_l < 0) {
        fclose(f);
        return PM3_EFILE;
    }
    if ((size_t)file_len_l > PCRYPTO_MAX_KEY_FILE_BYTES) {
        fclose(f);
        return PM3_EOVFLOW;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return PM3_EFILE;
    }

    size_t file_len = (size_t)file_len_l;
    uint8_t *data = calloc(file_len + 1, sizeof(uint8_t));
    if (data == NULL) {
        fclose(f);
        return PM3_EMALLOC;
    }
    size_t read_len = fread(data, 1, file_len, f);
    fclose(f);
    if (read_len != file_len) {
        free(data);
        return PM3_EFILE;
    }

    int res = pcrypto_parse_ec_private_scalar_or_blob(data, file_len, curveid, out_priv, out_priv_len);
    if (res == PM3_SUCCESS) {
        free(data);
        return PM3_SUCCESS;
    }

    char *text = calloc(file_len + 1, sizeof(char));
    if (text == NULL) {
        free(data);
        return PM3_EMALLOC;
    }
    memcpy(text, data, file_len);
    text[file_len] = '\0';
    free(data);

    res = pcrypto_parse_ec_private_text(text, false, curveid, out_priv, out_priv_len);
    free(text);
    return res;
}

static int pcrypto_parse_ec_private_text(const char *input, bool allow_file_path,
                                         mbedtls_ecp_group_id curveid,
                                         uint8_t *out_priv, size_t out_priv_len) {
    if (input == NULL || out_priv == NULL || out_priv_len == 0) {
        return PM3_EINVARG;
    }

    char normalized[PCRYPTO_MAX_KEY_INPUT] = {0};
    size_t input_len = strlen(input);
    if (input_len >= sizeof(normalized)) {
        return PM3_EOVFLOW;
    }
    memcpy(normalized, input, input_len + 1);
    pcrypto_trim_ascii_inplace(normalized);

    if (normalized[0] == '\0') {
        return PM3_EINVARG;
    }

    if (allow_file_path) {
        char *resolved_path = NULL;
        if (searchFile(&resolved_path, RESOURCES_SUBDIR, normalized, "", true) == PM3_SUCCESS) {
            int res = pcrypto_parse_ec_private_file(resolved_path, curveid, out_priv, out_priv_len);
            free(resolved_path);
            return res;
        }
    }

    // Only unescape after path resolution fails, to avoid mutating valid paths
    // (for example Windows paths containing '\t', '\n' or '\r').
    pcrypto_unescape_newlines_inplace(normalized);

    uint8_t decoded[PCRYPTO_MAX_KEY_INPUT] = {0};
    int decoded_len = -1;
    char compact[PCRYPTO_MAX_KEY_INPUT] = {0};
    size_t compact_len = 0;
    if (pcrypto_copy_without_whitespace(normalized, compact, sizeof(compact), &compact_len) == PM3_SUCCESS &&
            compact_len > 0) {
        decoded_len = hex_to_bytes(compact, decoded, sizeof(decoded));
    }
    if (decoded_len > 0) {
        int res = pcrypto_parse_ec_private_scalar_or_blob(decoded, (size_t)decoded_len, curveid, out_priv, out_priv_len);
        if (res == PM3_SUCCESS) {
            return PM3_SUCCESS;
        }
    }

    int res = pcrypto_parse_ec_private_blob((const uint8_t *)normalized, strlen(normalized),
                                            curveid, out_priv, out_priv_len);
    if (res == PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    return pcrypto_parse_ec_private_base64(normalized, curveid, out_priv, out_priv_len);
}

int ensure_ec_private_key(const char *input_or_path, mbedtls_ecp_group_id curveid, uint8_t *out_priv, size_t out_priv_len) {
    return pcrypto_parse_ec_private_text(input_or_path, true, curveid, out_priv, out_priv_len);
}

// ============================================================================
// EC Public Key Loading
// ============================================================================
//
// Output format: uncompressed point 04 || X || Y
// For P-256 this is 65 bytes.
//
// Accepted input formats:
//   - Raw uncompressed point bytes:   04 || X || Y  (e.g. 65 bytes for P-256)
//   - Raw X || Y coordinates:         X || Y        (e.g. 64 bytes for P-256)
//   - Compressed point:               02/03 || X    (e.g. 33 bytes for P-256)
//   - DER-encoded SubjectPublicKeyInfo blob
//   - PEM-encoded public key (-----BEGIN PUBLIC KEY-----)
//   - Hex string of any of the above
//   - Base64-encoded blob of any of the above
//   - File path (PEM or DER)

static int pcrypto_extract_pub_point_from_pk(const mbedtls_pk_context *pkctx,
                                             mbedtls_ecp_group_id curveid,
                                             uint8_t *out_pub, size_t out_pub_len) {
    if (pkctx == NULL || out_pub == NULL || out_pub_len == 0) {
        return PM3_EINVARG;
    }

    mbedtls_pk_type_t pk_type = mbedtls_pk_get_type(pkctx);
    if (!(pk_type == MBEDTLS_PK_ECKEY || pk_type == MBEDTLS_PK_ECKEY_DH || pk_type == MBEDTLS_PK_ECDSA)) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(*pkctx);
    if (ec == NULL || ec->grp.id != curveid) {
        return PM3_EINVARG;
    }

    size_t coord_len = (ec->grp.nbits + 7) / 8;
    size_t expected_len = 1 + 2 * coord_len;
    if (out_pub_len < expected_len) {
        return PM3_EOVFLOW;
    }

    size_t written = 0;
    int ret = mbedtls_ecp_point_write_binary(&ec->grp, &ec->Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                             &written, out_pub, out_pub_len);
    if (ret != 0 || written != expected_len) {
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

// Decompress a compressed EC point (02/03 || X) to uncompressed (04 || X || Y).
// Bundled mbedtls does not support reading compressed points.
// Based on https://github.com/mwarning/mbedtls-ecp-compression
static int pcrypto_decompress_ec_point(const uint8_t *compressed, size_t comp_len,
                                       const mbedtls_ecp_group *grp,
                                       uint8_t *out, size_t out_len) {
    size_t coord_len = (grp->nbits + 7) / 8;
    if (comp_len != 1 + coord_len || (compressed[0] != 0x02 && compressed[0] != 0x03)) {
        return PM3_EINVARG;
    }
    if (out_len < 1 + 2 * coord_len) {
        return PM3_EOVFLOW;
    }

    // Solve y = sqrt(x^3 + ax + b) mod p, using y = rhs^((p+1)/4) mod p (valid for p ≡ 3 mod 4).
    // Factor as: r = x(x^2 + a) + b to save one multiplication.
    mbedtls_mpi r, x, n;
    mbedtls_mpi_init(&r); mbedtls_mpi_init(&x); mbedtls_mpi_init(&n);

    // Copy X coordinate and output prefix
    memcpy(out, compressed, comp_len);
    out[0] = 0x04;

    int ok = (mbedtls_mpi_read_binary(&x, compressed + 1, coord_len) == 0);
    // r = x^2
    ok = ok && (mbedtls_mpi_mul_mpi(&r, &x, &x) == 0);
    // r = x^2 + a (A.p == NULL means implicit a = -3 for NIST curves)
    if (ok && grp->A.p == NULL) {
        ok = (mbedtls_mpi_sub_int(&r, &r, 3) == 0);
    } else {
        ok = ok && (mbedtls_mpi_add_mpi(&r, &r, &grp->A) == 0);
    }
    // r = x(x^2 + a)
    ok = ok && (mbedtls_mpi_mul_mpi(&r, &r, &x) == 0);
    // r = x(x^2 + a) + b
    ok = ok && (mbedtls_mpi_add_mpi(&r, &r, &grp->B) == 0);
    // n = (p + 1) / 4
    ok = ok && (mbedtls_mpi_add_int(&n, &grp->P, 1) == 0);
    ok = ok && (mbedtls_mpi_shift_r(&n, 2) == 0);
    // r = r^((p+1)/4) mod p
    ok = ok && (mbedtls_mpi_exp_mod(&r, &r, &n, &grp->P, NULL) == 0);
    // Fix parity: 02 = even y, 03 = odd y
    if (ok && ((compressed[0] == 0x03) != mbedtls_mpi_get_bit(&r, 0))) {
        ok = (mbedtls_mpi_sub_mpi(&r, &grp->P, &r) == 0);
    }
    // Write Y coordinate
    ok = ok && (mbedtls_mpi_write_binary(&r, out + 1 + coord_len, coord_len) == 0);

    mbedtls_mpi_free(&r); mbedtls_mpi_free(&x); mbedtls_mpi_free(&n);
    return ok ? PM3_SUCCESS : PM3_ESOFT;
}

static int pcrypto_validate_raw_ec_point(const uint8_t *point, size_t point_len,
                                         mbedtls_ecp_group_id curveid,
                                         uint8_t *out_pub, size_t out_pub_len) {
    if (point == NULL || out_pub == NULL || point_len == 0 || out_pub_len == 0) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_group grp;
    mbedtls_ecp_point Q;
    mbedtls_ecp_group_init(&grp);
    mbedtls_ecp_point_init(&Q);

    int status = PM3_ESOFT;
    if (mbedtls_ecp_group_load(&grp, curveid) != 0) {
        goto out;
    }

    size_t coord_len = (grp.nbits + 7) / 8;
    size_t expected_uncompressed = 1 + 2 * coord_len;

    // Build a properly-formatted point for mbedtls
    uint8_t buf[133]; // max for P-521: 1 + 2*66
    size_t buf_len = 0;

    if (point_len == expected_uncompressed && point[0] == 0x04) {
        // Already uncompressed: 04 || X || Y
        memcpy(buf, point, point_len);
        buf_len = point_len;
    } else if (point_len == 2 * coord_len) {
        // Raw X || Y, add 0x04 prefix
        buf[0] = 0x04;
        memcpy(buf + 1, point, point_len);
        buf_len = 1 + point_len;
    } else if (point_len == 1 + coord_len && (point[0] == 0x02 || point[0] == 0x03)) {
        // Compressed point: decompress (bundled mbedtls lacks read support)
        if (pcrypto_decompress_ec_point(point, point_len, &grp, buf, sizeof(buf)) != PM3_SUCCESS) {
            status = PM3_EINVARG;
            goto out;
        }
        buf_len = expected_uncompressed;
    } else {
        status = PM3_EINVARG;
        goto out;
    }

    if (mbedtls_ecp_point_read_binary(&grp, &Q, buf, buf_len) != 0) {
        status = PM3_EINVARG;
        goto out;
    }

    if (mbedtls_ecp_check_pubkey(&grp, &Q) != 0) {
        status = PM3_EINVARG;
        goto out;
    }

    // Write out as uncompressed
    if (out_pub_len < expected_uncompressed) {
        status = PM3_EOVFLOW;
        goto out;
    }

    size_t written = 0;
    if (mbedtls_ecp_point_write_binary(&grp, &Q, MBEDTLS_ECP_PF_UNCOMPRESSED,
                                       &written, out_pub, out_pub_len) != 0) {
        status = PM3_ESOFT;
        goto out;
    }

    status = PM3_SUCCESS;

out:
    mbedtls_ecp_point_free(&Q);
    mbedtls_ecp_group_free(&grp);
    return status;
}

static int pcrypto_parse_ec_public_blob(const uint8_t *blob, size_t blob_len,
                                        mbedtls_ecp_group_id curveid,
                                        uint8_t *out_pub, size_t out_pub_len) {
    if (blob == NULL || out_pub == NULL || blob_len == 0 || out_pub_len == 0) {
        return PM3_EINVARG;
    }

    // Try as raw EC point first (uncompressed, X||Y, or compressed)
    int res = pcrypto_validate_raw_ec_point(blob, blob_len, curveid, out_pub, out_pub_len);
    if (res == PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    // Try as DER/PEM SubjectPublicKeyInfo via mbedtls pk parser
    mbedtls_pk_context pkctx;
    mbedtls_pk_init(&pkctx);

    int ret = mbedtls_pk_parse_public_key(&pkctx, blob, blob_len);
    if (ret != 0) {
        // mbedtls_pk_parse_public_key requires NUL-terminated PEM
        uint8_t *nul_terminated = calloc(blob_len + 1, sizeof(uint8_t));
        if (nul_terminated == NULL) {
            mbedtls_pk_free(&pkctx);
            return PM3_EMALLOC;
        }
        memcpy(nul_terminated, blob, blob_len);
        ret = mbedtls_pk_parse_public_key(&pkctx, nul_terminated, blob_len + 1);
        free(nul_terminated);
    }

    if (ret != 0) {
        mbedtls_pk_free(&pkctx);
        return PM3_EINVARG;
    }

    res = pcrypto_extract_pub_point_from_pk(&pkctx, curveid, out_pub, out_pub_len);
    mbedtls_pk_free(&pkctx);
    return res;
}

static int pcrypto_parse_ec_public_text(const char *input, bool allow_file_path,
                                        mbedtls_ecp_group_id curveid,
                                        uint8_t *out_pub, size_t out_pub_len);

static int pcrypto_parse_ec_public_file(const char *path,
                                        mbedtls_ecp_group_id curveid,
                                        uint8_t *out_pub, size_t out_pub_len) {
    if (path == NULL || out_pub == NULL || out_pub_len == 0) {
        return PM3_EINVARG;
    }

    FILE *f = fopen(path, "rb");
    if (f == NULL) {
        return PM3_EFILE;
    }

    if (fseek(f, 0, SEEK_END) != 0) {
        fclose(f);
        return PM3_EFILE;
    }
    long file_len_l = ftell(f);
    if (file_len_l < 0) {
        fclose(f);
        return PM3_EFILE;
    }
    if ((size_t)file_len_l > PCRYPTO_MAX_KEY_FILE_BYTES) {
        fclose(f);
        return PM3_EOVFLOW;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return PM3_EFILE;
    }

    size_t file_len = (size_t)file_len_l;
    uint8_t *data = calloc(file_len + 1, sizeof(uint8_t));
    if (data == NULL) {
        fclose(f);
        return PM3_EMALLOC;
    }
    size_t read_len = fread(data, 1, file_len, f);
    fclose(f);
    if (read_len != file_len) {
        free(data);
        return PM3_EFILE;
    }

    int res = pcrypto_parse_ec_public_blob(data, file_len, curveid, out_pub, out_pub_len);
    if (res == PM3_SUCCESS) {
        free(data);
        return PM3_SUCCESS;
    }

    char *text = calloc(file_len + 1, sizeof(char));
    if (text == NULL) {
        free(data);
        return PM3_EMALLOC;
    }
    memcpy(text, data, file_len);
    text[file_len] = '\0';
    free(data);

    res = pcrypto_parse_ec_public_text(text, false, curveid, out_pub, out_pub_len);
    free(text);
    return res;
}

static int pcrypto_parse_ec_public_base64(const char *input,
                                          mbedtls_ecp_group_id curveid,
                                          uint8_t *out_pub, size_t out_pub_len) {
    if (input == NULL || out_pub == NULL || out_pub_len == 0) {
        return PM3_EINVARG;
    }

    char compact[PCRYPTO_MAX_KEY_INPUT] = {0};
    size_t compact_len = 0;
    int res = pcrypto_copy_without_whitespace(input, compact, sizeof(compact), &compact_len);
    if (res != PM3_SUCCESS || compact_len == 0) {
        return PM3_EINVARG;
    }

    size_t decoded_capacity = ((compact_len * 3) / 4) + 4;
    uint8_t *decoded = calloc(decoded_capacity, sizeof(uint8_t));
    if (decoded == NULL) {
        return PM3_EMALLOC;
    }

    size_t decoded_len = 0;
    int b64_res = mbedtls_base64_decode(decoded, decoded_capacity, &decoded_len,
                                        (const unsigned char *)compact, compact_len);
    if (b64_res != 0 || decoded_len == 0) {
        free(decoded);
        return PM3_EINVARG;
    }

    res = pcrypto_parse_ec_public_blob(decoded, decoded_len, curveid, out_pub, out_pub_len);
    free(decoded);
    return res;
}

static int pcrypto_parse_ec_public_text(const char *input, bool allow_file_path,
                                        mbedtls_ecp_group_id curveid,
                                        uint8_t *out_pub, size_t out_pub_len) {
    if (input == NULL || out_pub == NULL || out_pub_len == 0) {
        return PM3_EINVARG;
    }

    char normalized[PCRYPTO_MAX_KEY_INPUT] = {0};
    size_t input_len = strlen(input);
    if (input_len >= sizeof(normalized)) {
        return PM3_EOVFLOW;
    }
    memcpy(normalized, input, input_len + 1);
    pcrypto_trim_ascii_inplace(normalized);

    if (normalized[0] == '\0') {
        return PM3_EINVARG;
    }

    if (allow_file_path) {
        char *resolved_path = NULL;
        if (searchFile(&resolved_path, RESOURCES_SUBDIR, normalized, "", true) == PM3_SUCCESS) {
            int res = pcrypto_parse_ec_public_file(resolved_path, curveid, out_pub, out_pub_len);
            free(resolved_path);
            return res;
        }
    }

    // Only unescape after path resolution fails
    pcrypto_unescape_newlines_inplace(normalized);

    // Try as hex string
    uint8_t decoded[PCRYPTO_MAX_KEY_INPUT] = {0};
    int decoded_len = -1;
    char compact[PCRYPTO_MAX_KEY_INPUT] = {0};
    size_t compact_len = 0;
    if (pcrypto_copy_without_whitespace(normalized, compact, sizeof(compact), &compact_len) == PM3_SUCCESS &&
            compact_len > 0) {
        decoded_len = hex_to_bytes(compact, decoded, sizeof(decoded));
    }
    if (decoded_len > 0) {
        int res = pcrypto_parse_ec_public_blob(decoded, (size_t)decoded_len, curveid, out_pub, out_pub_len);
        if (res == PM3_SUCCESS) {
            return PM3_SUCCESS;
        }
    }

    // Try as raw blob (PEM)
    int res = pcrypto_parse_ec_public_blob((const uint8_t *)normalized, strlen(normalized),
                                           curveid, out_pub, out_pub_len);
    if (res == PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    // Try as base64
    return pcrypto_parse_ec_public_base64(normalized, curveid, out_pub, out_pub_len);
}

int ensure_ec_public_key(const char *input_or_path, mbedtls_ecp_group_id curveid, uint8_t *out_pub, size_t out_pub_len) {
    return pcrypto_parse_ec_public_text(input_or_path, true, curveid, out_pub, out_pub_len);
}

void des_encrypt(void *out, const void *in, const void *key) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

void des_decrypt(void *out, const void *in, const void *key) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_ecb(&ctx, in, out);
    mbedtls_des_free(&ctx);
}

void des_encrypt_ecb(void *out, const void *in, const int length, const void *key) {
    for (int i = 0; i < length; i += 8) {
        des_encrypt((uint8_t *)out + i, (uint8_t *)in + i, key);
    }
}

void des_decrypt_ecb(void *out, const void *in, const int length, const void *key) {
    for (int i = 0; i < length; i += 8) {
        des_decrypt((uint8_t *)out + i, (uint8_t *)in + i, key);
    }
}

void des_encrypt_cbc(void *out, const void *in, const int length, const void *key, uint8_t *iv) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_enc(&ctx, key);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_ENCRYPT, length, iv, in, out);
}

void des_decrypt_cbc(void *out, const void *in, const int length, const void *key, uint8_t *iv) {
    mbedtls_des_context ctx;
    mbedtls_des_setkey_dec(&ctx, key);
    mbedtls_des_crypt_cbc(&ctx, MBEDTLS_DES_DECRYPT, length, iv, in, out);
}

void des3_encrypt(void *out, const void *in, const void *key, uint8_t keycount) {
    switch (keycount) {
        case 1:
            des_encrypt(out, in, key);
            break;
        case 2: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set2key_enc(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        case 3: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set3key_enc(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        default:
            break;
    }
}

void des3_decrypt(void *out, const void *in, const void *key, uint8_t keycount) {
    switch (keycount) {
        case 1:
            des_encrypt(out, in, key);
            break;
        case 2: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set2key_dec(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        case 3: {
            mbedtls_des3_context ctx3;
            mbedtls_des3_set3key_dec(&ctx3, key);
            mbedtls_des3_crypt_ecb(&ctx3, in, out);
            mbedtls_des3_free(&ctx3);
            break;
        }
        default:
            break;
    }
}

// NIST Special Publication 800-38A — Recommendation for block cipher modes of operation: methods and techniques, 2001.
int aes_encode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0};
    if (iv) {
        memcpy(iiv, iv, sizeof(iiv));
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 128)) {
        return 1;
    }
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iiv, input, output)) {
        return 2;
    }
    mbedtls_aes_free(&aes);
    return PM3_SUCCESS;
}

int aes_decode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0};
    if (iv) {
        memcpy(iiv, iv, 16);
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_dec(&aes, key, 128)) {
        return 1;
    }
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iiv, input, output)) {
        return 2;
    }
    mbedtls_aes_free(&aes);
    return PM3_SUCCESS;
}

// NIST Special Publication 800-38A — Recommendation for block cipher modes of operation: methods and techniques, 2001.
int aes256_encode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0};
    if (iv) {
        memcpy(iiv, iv, sizeof(iiv));
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_enc(&aes, key, 256)) {
        return 1;
    }
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, length, iiv, input, output)) {
        return 2;
    }
    mbedtls_aes_free(&aes);
    return PM3_SUCCESS;
}


int aes256_decode(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0};
    if (iv) {
        memcpy(iiv, iv, 16);
    }

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);
    if (mbedtls_aes_setkey_dec(&aes, key, 256)) {
        return 1;
    }
    if (mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, length, iiv, input, output)) {
        return 2;
    }
    mbedtls_aes_free(&aes);
    return PM3_SUCCESS;
}


// NIST Special Publication 800-38B — Recommendation for block cipher modes of operation: The CMAC mode for authentication.
// https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_CMAC.pdf
int aes_cmac(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
    memset(mac, 0x00, 16);

    //  NIST 800-38B
    return mbedtls_aes_cmac_prf_128(key, MBEDTLS_AES_BLOCK_SIZE, input, length, mac);
}

int aes_cmac8(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *mac, int length) {
    uint8_t cmac_tmp[16] = {0};
    memset(mac, 0x00, 8);

    int res = aes_cmac(iv, key, input, cmac_tmp, length);
    if (res) {
        return res;
    }

    for (int i = 0; i < 8; i++) {
        mac[i] = cmac_tmp[i * 2 + 1];
    }
    return PM3_SUCCESS;
}

static uint8_t fixed_rand_value[250] = {0};
static int fixed_rand(void *rng_state, unsigned char *output, size_t len) {
    if (len <= 250) {
        memcpy(output, fixed_rand_value, len);
    } else {
        memset(output, 0x00, len);
    }

    return PM3_SUCCESS;
}

int sha1hash(uint8_t *input, int length, uint8_t *hash) {
    if (!hash || !input) {
        return 1;
    }

    mbedtls_sha1(input, length, hash);

    return PM3_SUCCESS;
}

int sha256hash(uint8_t *input, int length, uint8_t *hash) {
    if (!hash || !input) {
        return 1;
    }

    mbedtls_sha256_context sctx;
    mbedtls_sha256_init(&sctx);
    mbedtls_sha256_starts(&sctx, 0); // SHA-256, not 224
    mbedtls_sha256_update(&sctx, input, length);
    mbedtls_sha256_finish(&sctx, hash);
    mbedtls_sha256_free(&sctx);

    return PM3_SUCCESS;
}

int sha512hash(uint8_t *input, int length, uint8_t *hash) {
    if (!hash || !input) {
        return 1;
    }

    mbedtls_sha512_context sctx;
    mbedtls_sha512_init(&sctx);
    mbedtls_sha512_starts(&sctx, 0); //SHA-512, not 384
    mbedtls_sha512_update(&sctx, input, length);
    mbedtls_sha512_finish(&sctx, hash);
    mbedtls_sha512_free(&sctx);

    return PM3_SUCCESS;
}

static int ecdsa_init_str(mbedtls_ecdsa_context *ctx,  mbedtls_ecp_group_id curveid, const char *key_d, const char *key_x, const char *key_y) {
    if (!ctx) {
        return 1;
    }

    mbedtls_ecdsa_init(ctx);
    int res = mbedtls_ecp_group_load(&ctx->grp, curveid);
    if (res) {
        return res;
    }

    if (key_d) {
        res = mbedtls_mpi_read_string(&ctx->d, 16, key_d);
        if (res) {
            return res;
        }
    }

    if (key_x && key_y) {
        res = mbedtls_ecp_point_read_string(&ctx->Q, 16, key_x, key_y);
        if (res) {
            return res;
        }
    }

    return PM3_SUCCESS;
}

static int ecdsa_init(mbedtls_ecdsa_context *ctx, mbedtls_ecp_group_id curveid, uint8_t *key_d, uint8_t *key_xy) {
    if (!ctx)
        return 1;

    int res;

    mbedtls_ecdsa_init(ctx);
    res = mbedtls_ecp_group_load(&ctx->grp, curveid);
    if (res)
        return res;

    size_t keylen = (ctx->grp.nbits + 7) / 8;
    if (key_d) {
        res = mbedtls_mpi_read_binary(&ctx->d, key_d, keylen);
        if (res)
            return res;
    }

    if (key_xy) {
        res = mbedtls_ecp_point_read_binary(&ctx->grp, &ctx->Q, key_xy, keylen * 2 + 1);
        if (res)
            return res;
    }

    return PM3_SUCCESS;
}

int ecdsa_key_create(mbedtls_ecp_group_id curveid, uint8_t *key_d, uint8_t *key_xy) {
    int res;
    mbedtls_ecdsa_context ctx;
    res = ecdsa_init(&ctx, curveid, NULL, NULL);
    if (res)
        goto exit;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsaproxmark";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (res)
        goto exit;

    res = mbedtls_ecdsa_genkey(&ctx, curveid, mbedtls_ctr_drbg_random, &ctr_drbg);
    if (res)
        goto exit;

    size_t keylen = (ctx.grp.nbits + 7) / 8;
    res = mbedtls_mpi_write_binary(&ctx.d, key_d, keylen);
    if (res)
        goto exit;

    size_t public_keylen = 0;
    uint8_t public_key[200] = {0};
    res = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &public_keylen, public_key, sizeof(public_key));
    if (res)
        goto exit;

    if (public_keylen != 1 + 2 * keylen) { // 0x04 <key x><key y>
        res = 1;
        goto exit;
    }
    memcpy(key_xy, public_key, public_keylen);

exit:
    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ctx);
    return res;
}

char *ecdsa_get_error(int ret) {
    static char retstr[300];
    memset(retstr, 0x00, sizeof(retstr));
    mbedtls_strerror(ret, retstr, sizeof(retstr));
    return retstr;
}

int ecdsa_public_key_from_pk(mbedtls_pk_context *pk,  mbedtls_ecp_group_id curveid, uint8_t *key, size_t keylen) {
    int res = 0;
    size_t realkeylen = 0;

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);

    res = mbedtls_ecp_group_load(&ctx.grp, curveid);
    if (res)
        goto exit;

    size_t private_keylen = (ctx.grp.nbits + 7) / 8;
    if (keylen < 1 + 2 * private_keylen) {
        res = 1;
        goto exit;
    }

    res = mbedtls_ecdsa_from_keypair(&ctx, mbedtls_pk_ec(*pk));
    if (res)
        goto exit;

    res = mbedtls_ecp_point_write_binary(&ctx.grp, &ctx.Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &realkeylen, key, keylen);
    if (realkeylen != 1 + 2 * private_keylen)
        res = 2;
exit:
    mbedtls_ecdsa_free(&ctx);
    return res;
}

int ecdsa_signature_create(mbedtls_ecp_group_id curveid, uint8_t *key_d, uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen, bool hash) {
    int res;
    *signaturelen = 0;

    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "ecdsaproxmark";

    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);

    res = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy, (const unsigned char *)pers, strlen(pers));
    if (res)
        goto exit;

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init(&ctx, curveid, key_d, key_xy);
    if (res)
        goto exit;

    res = mbedtls_ecdsa_write_signature(
              &ctx,
              MBEDTLS_MD_SHA256,
              hash ? shahash : input,
              hash ? sizeof(shahash) : length,
              signature,
              signaturelen,
              mbedtls_ctr_drbg_random,
              &ctr_drbg
          );


exit:
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_ecdsa_free(&ctx);
    return res;
}

static int ecdsa_signature_create_test(mbedtls_ecp_group_id curveid, const char *key_d, const char *key_x, const char *key_y, const char *random, uint8_t *input, int length, uint8_t *signature, size_t *signaturelen) {
    int res;
    *signaturelen = 0;

    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    int rndlen = 0;
    param_gethex_to_eol(random, 0, fixed_rand_value, sizeof(fixed_rand_value), &rndlen);

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init_str(&ctx, curveid, key_d, key_x, key_y);
    if (res)
        return res;

    res = mbedtls_ecdsa_write_signature(&ctx, MBEDTLS_MD_SHA256, shahash, sizeof(shahash), signature, signaturelen, fixed_rand, NULL);

    mbedtls_ecdsa_free(&ctx);
    return res;
}

static int ecdsa_signature_verify_keystr(mbedtls_ecp_group_id curveid, const char *key_x, const char *key_y, uint8_t *input, int length, uint8_t *signature, size_t signaturelen, bool hash) {
    int res;
    uint8_t shahash[32] = {0};
    res = sha256hash(input, length, shahash);
    if (res)
        return res;

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init_str(&ctx, curveid, NULL, key_x, key_y);
    if (res)
        return res;

    res = mbedtls_ecdsa_read_signature(
              &ctx,
              hash ? shahash : input,
              hash ? sizeof(shahash) : length,
              signature,
              signaturelen
          );

    mbedtls_ecdsa_free(&ctx);
    return res;
}

int ecdsa_signature_verify(mbedtls_ecp_group_id curveid, uint8_t *key_xy, uint8_t *input, int length, uint8_t *signature, size_t signaturelen, bool hash) {
    int res;
    uint8_t shahash[32] = {0};
    if (hash) {
        res = sha256hash(input, length, shahash);
        if (res) {
            return res;
        }
    }

    mbedtls_ecdsa_context ctx;
    res = ecdsa_init(&ctx, curveid, NULL, key_xy);
    if (res) {
        return res;
    }

    res = mbedtls_ecdsa_read_signature(
              &ctx,
              hash ? shahash : input,
              hash ? sizeof(shahash) : length,
              signature,
              signaturelen
          );

    mbedtls_ecdsa_free(&ctx);
    return res;
}

// take signature bytes,  converts to ASN1 signature and tries to verify
int ecdsa_signature_r_s_verify(mbedtls_ecp_group_id curveid, uint8_t *key_xy, uint8_t *input, int length, uint8_t *r_s, size_t r_s_len, bool hash) {
    uint8_t signature[MBEDTLS_ECDSA_MAX_LEN] = {0};
    size_t signature_len = 0;

    // convert r & s to ASN.1 signature
    mbedtls_mpi r, s;
    mbedtls_mpi_init(&r);
    mbedtls_mpi_init(&s);
    mbedtls_mpi_read_binary(&r, r_s, r_s_len / 2);
    mbedtls_mpi_read_binary(&s, r_s + r_s_len / 2, r_s_len / 2);

    int res = ecdsa_signature_to_asn1(&r, &s, signature, &signature_len);
    if (res < 0) {
        return res;
    }

    res = ecdsa_signature_verify(curveid, key_xy, input, length, signature, signature_len, hash);
    mbedtls_mpi_free(&r);
    mbedtls_mpi_free(&s);
    return res;
}


#define T_PRIVATE_KEY "C477F9F65C22CCE20657FAA5B2D1D8122336F851A508A1ED04E479C34985BF96"
#define T_Q_X         "B7E08AFDFE94BAD3F1DC8C734798BA1C62B3A0AD1E9EA2A38201CD0889BC7A19"
#define T_Q_Y         "3603F747959DBF7A4BB226E41928729063ADC7AE43529E61B563BBC606CC5E09"
#define T_K           "7A1A7E52797FC8CAAA435D2A4DACE39158504BF204FBE19F14DBB427FAEE50AE"
#define T_R           "2B42F576D07F4165FF65D1F3B1500F81E44C316F1F0B3EF57325B69ACA46104F"
#define T_S           "DC42C2122D6392CD3E3A993A89502A8198C1886FE69D262C4B329BDB6B63FAF1"

int ecdsa_nist_test(bool verbose) {
    int res;
    uint8_t input[] = "Example of ECDSA with P-256";
    mbedtls_ecp_group_id curveid = MBEDTLS_ECP_DP_SECP256R1;
    int length = strlen((char *)input);
    uint8_t signature[300] = {0};
    size_t siglen = 0;

    // NIST ecdsa test
    if (verbose) {
        PrintAndLogEx(INFO, "ECDSA NIST test " NOLF);
    }
    // make signature
    res = ecdsa_signature_create_test(curveid, T_PRIVATE_KEY, T_Q_X, T_Q_Y, T_K, input, length, signature, &siglen);
// PrintAndLogEx(INFO, "res: %x signature[%x]: %s", (res < 0)? -res : res, siglen, sprint_hex(signature, siglen));
    if (res != PM3_SUCCESS)
        goto exit;

    // check vectors
    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};
    res = ecdsa_asn1_get_signature(signature, siglen, rval, sval);
    if (res)
        goto exit;

    int slen = 0;
    uint8_t rval_s[33] = {0};
    param_gethex_to_eol(T_R, 0, rval_s, sizeof(rval_s), &slen);
    uint8_t sval_s[33] = {0};
    param_gethex_to_eol(T_S, 0, sval_s, sizeof(sval_s), &slen);
    if (strncmp((char *)rval, (char *)rval_s, 32) || strncmp((char *)sval, (char *)sval_s, 32)) {
        PrintAndLogEx(NORMAL, "( " _RED_("R or S check error") " )");
        res = 100;
        goto exit;
    }

    // verify signature
    res = ecdsa_signature_verify_keystr(curveid, T_Q_X, T_Q_Y, input, length, signature, siglen, true);
    if (res) {
        goto exit;
    }

    // verify wrong signature
    input[0] ^= 0xFF;
    res = ecdsa_signature_verify_keystr(curveid, T_Q_X, T_Q_Y, input, length, signature, siglen, true);
    if (res == false) {
        res = 1;
        goto exit;
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");
        PrintAndLogEx(INFO, "ECDSA binary signature create/check test " NOLF);
    }

    // random ecdsa test
    uint8_t key_d[32] = {0};
    uint8_t key_xy[32 * 2 + 2] = {0};
    memset(signature, 0x00, sizeof(signature));
    siglen = 0;

    res = ecdsa_key_create(curveid, key_d, key_xy);
    if (res)
        goto exit;

    res = ecdsa_signature_create(curveid, key_d, key_xy, input, length, signature, &siglen, true);
    if (res)
        goto exit;

    res = ecdsa_signature_verify(curveid, key_xy, input, length, signature, siglen, true);
    if (res)
        goto exit;

    input[0] ^= 0xFF;
    res = ecdsa_signature_verify(curveid, key_xy, input, length, signature, siglen, true);
    if (!res)
        goto exit;

    if (verbose)
        PrintAndLogEx(NORMAL, "( " _GREEN_("ok") " )");

    return PM3_SUCCESS;
exit:
    if (verbose)
        PrintAndLogEx(NORMAL, "( " _RED_("fail") " )");
    return res;
}


// iceman:  todo,  remove and use xor in commonutil.c
void bin_xor(uint8_t *d1, const uint8_t *d2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        d1[i] = d1[i] ^ d2[i];
    }
}

void AddISO9797M2Padding(uint8_t *ddata, size_t *ddatalen, uint8_t *sdata, size_t sdatalen, size_t blocklen) {
    *ddatalen = sdatalen + 1;
    *ddatalen += blocklen - *ddatalen % blocklen;
    memset(ddata, 0, *ddatalen);
    memcpy(ddata, sdata, sdatalen);
    ddata[sdatalen] = ISO9797_M2_PAD_BYTE;
}

size_t FindISO9797M2PaddingDataLen(const uint8_t *data, size_t datalen) {
    for (int i = datalen; i > 0; i--) {
        if (data[i - 1] == 0x80)
            return i - 1;
        if (data[i - 1] != 0x00)
            return 0;
    }
    return 0;
}


int blowfish_decrypt(uint8_t *iv, uint8_t *key, uint8_t *input, uint8_t *output, int length) {
    uint8_t iiv[16] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    if (iv)
        memcpy(iiv, iv, 16);

    mbedtls_blowfish_context blow;
    mbedtls_blowfish_init(&blow);
    if (mbedtls_blowfish_setkey(&blow, key, 64))
        return 1;

    if (mbedtls_blowfish_crypt_cbc(&blow, MBEDTLS_BLOWFISH_DECRYPT, length, iiv, input, output))
        return 2;

    mbedtls_blowfish_free(&blow);

    return 0;
}

// Implementation from http://www.secg.org/sec1-v2.pdf#subsubsection.3.6.1
int ansi_x963_sha256(uint8_t *sharedSecret, size_t sharedSecretLen, uint8_t *sharedInfo, size_t sharedInfoLen, size_t keyDataLen, uint8_t *keyData) {
    // sha256 hash has (practically) no max input len, so skipping that step

    if (keyDataLen >= 32 * (pow(2, 32) - 1)) {
        return 1;
    }

    uint32_t counter = 0x00000001;

    for (int i = 0; i < (keyDataLen / 32); ++i) {

        uint8_t *hashMaterial = calloc(4 + sharedSecretLen + sharedInfoLen, sizeof(uint8_t));
        if (hashMaterial == NULL) {
            PrintAndLogEx(WARNING, "Failed to allocate memory");
            return 2;
        }

        memcpy(hashMaterial, sharedSecret, sharedSecretLen);
        hashMaterial[sharedSecretLen] = (counter >> 24);
        hashMaterial[sharedSecretLen + 1] = (counter >> 16) & 0xFF;
        hashMaterial[sharedSecretLen + 2] = (counter >> 8) & 0xFF;
        hashMaterial[sharedSecretLen + 3] = counter & 0xFF;
        memcpy(hashMaterial + sharedSecretLen + 4, sharedInfo, sharedInfoLen);

        uint8_t hash[32] = {0};
        sha256hash(hashMaterial, 4 + sharedSecretLen + sharedInfoLen, hash);

        free(hashMaterial);

        memcpy(keyData + (32 * i), hash, 32);

        counter++;
    }

    return 0;
}
