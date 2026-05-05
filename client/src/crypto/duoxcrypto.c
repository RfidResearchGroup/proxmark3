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
// MIFARE DUOX certificate crypto helpers
//-----------------------------------------------------------------------------

#include "crypto/duoxcrypto.h"

#include <ctype.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <mbedtls/asn1.h>
#include <mbedtls/ecdsa.h>
#include <mbedtls/ecp.h>
#include <mbedtls/md.h>
#include <mbedtls/pk.h>

#include "common.h"
#include "commonutil.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "fileutils.h"
#include "ui.h"
#include "util.h"
#include "x509_crt.h"

#define DUOX_CERTIFICATE_ANCHOR_INPUT_LEN 8192

static int duox_cert_info_from_x509_crt(const mbedtls_x509_crt *cert, duox_cert_info_t *out);

const char *duox_certificate_format_name(duox_certificate_format_t format) {
    switch (format) {
        case DUOX_CERTIFICATE_FORMAT_X509:
            return "X.509";
        case DUOX_CERTIFICATE_FORMAT_GP_VDE:
            return "GP VDE";
        case DUOX_CERTIFICATE_FORMAT_UNKNOWN:
        default:
            return "unknown";
    }
}

const char *duox_cert_info_format_name(const duox_cert_info_t *cert) {
    if (cert == NULL) {
        return duox_certificate_format_name(DUOX_CERTIFICATE_FORMAT_UNKNOWN);
    }
    return duox_certificate_format_name(cert->format);
}

static void duox_trim_ascii_inplace(char *text) {
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

static int duox_copy_without_whitespace(const char *src, char *dst, size_t dst_size, size_t *dst_len) {
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

static bool duox_path_is_directory(const char *path) {
    if (path == NULL) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISDIR(st.st_mode) != 0;
}

static bool duox_path_is_regular_file(const char *path) {
    if (path == NULL) {
        return false;
    }
    struct stat st;
    if (stat(path, &st) != 0) {
        return false;
    }
    return S_ISREG(st.st_mode) != 0;
}

static const char *duox_path_basename(const char *path) {
    if (path == NULL) {
        return "";
    }

    const char *base = strrchr(path, '/');
    const char *base_win = strrchr(path, '\\');
    if (base == NULL || (base_win != NULL && base_win > base)) {
        base = base_win;
    }
    return (base == NULL) ? path : (base + 1);
}

static void duox_path_basename_without_ext(const char *path, char *out, size_t out_len) {
    if (out == NULL || out_len == 0) {
        return;
    }
    out[0] = '\0';

    const char *base = duox_path_basename(path);
    if (base[0] == '\0') {
        return;
    }

    snprintf(out, out_len, "%s", base);
    char *dot = strrchr(out, '.');
    if (dot != NULL && dot != out) {
        *dot = '\0';
    }
}

static int duox_qsort_path_cmp(const void *a, const void *b) {
    const char *pa = (const char *)a;
    const char *pb = (const char *)b;
    return strcmp(pa, pb);
}

static int duox_collect_certificate_anchor_paths_recursive(const char *dirpath,
                                                           char paths[][DUOX_CERTIFICATE_ANCHOR_PATH_LEN],
                                                           size_t max_paths, size_t *count) {
    if (dirpath == NULL || paths == NULL || count == NULL) {
        return PM3_EINVARG;
    }

    DIR *dir = opendir(dirpath);
    if (dir == NULL) {
        return PM3_EFILE;
    }

    struct dirent *entry = NULL;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0 || entry->d_name[0] == '.') {
            continue;
        }

        char fullpath[DUOX_CERTIFICATE_ANCHOR_PATH_LEN] = {0};
        if (snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name) >= (int)sizeof(fullpath)) {
            continue;
        }

        if (duox_path_is_directory(fullpath)) {
            int res = duox_collect_certificate_anchor_paths_recursive(fullpath, paths, max_paths, count);
            if (res != PM3_SUCCESS) {
                closedir(dir);
                return res;
            }
            continue;
        }

        if (!duox_path_is_regular_file(fullpath)) {
            continue;
        }
        if (*count >= max_paths) {
            closedir(dir);
            return PM3_EOVFLOW;
        }

        snprintf(paths[*count], DUOX_CERTIFICATE_ANCHOR_PATH_LEN, "%s", fullpath);
        (*count)++;
    }

    closedir(dir);
    return PM3_SUCCESS;
}

static int duox_collect_certificate_anchor_paths(const char *anchor_store_dir,
                                                 char paths[][DUOX_CERTIFICATE_ANCHOR_PATH_LEN],
                                                 size_t max_paths, size_t *count) {
    if (anchor_store_dir == NULL || anchor_store_dir[0] == '\0' || paths == NULL || count == NULL) {
        return PM3_EINVARG;
    }

    char *rootdir = NULL;
    int res = searchFile(&rootdir, RESOURCES_SUBDIR, anchor_store_dir, "", true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (!duox_path_is_directory(rootdir)) {
        free(rootdir);
        return PM3_EFILE;
    }

    *count = 0;
    res = duox_collect_certificate_anchor_paths_recursive(rootdir, paths, max_paths, count);
    free(rootdir);
    if (res != PM3_SUCCESS) {
        return res;
    }

    qsort(paths, *count, sizeof(paths[0]), duox_qsort_path_cmp);
    return PM3_SUCCESS;
}

int duox_certificate_anchor_public_key(const duox_certificate_anchor_t *anchor,
                                       mbedtls_ecp_group_id *curveid,
                                       const uint8_t **pubkey, size_t *pubkey_len) {
    if (anchor == NULL || curveid == NULL || pubkey == NULL || pubkey_len == NULL) {
        return PM3_EINVARG;
    }

    switch (anchor->type) {
        case DUOX_CERTIFICATE_ANCHOR_MATERIAL_NONE:
            return PM3_EINVARG;
        case DUOX_CERTIFICATE_ANCHOR_MATERIAL_PUBLIC_KEY:
            *curveid = anchor->material.key.curveid;
            *pubkey = anchor->material.key.pubkey;
            *pubkey_len = anchor->material.key.pubkey_len;
            break;
        case DUOX_CERTIFICATE_ANCHOR_MATERIAL_CERT:
            *curveid = anchor->material.cert.curveid;
            *pubkey = anchor->material.cert.pubkey;
            *pubkey_len = anchor->material.cert.pubkey_len;
            break;
        default:
            return PM3_EINVARG;
    }

    return (*curveid != MBEDTLS_ECP_DP_NONE && *pubkey != NULL && *pubkey_len > 0) ? PM3_SUCCESS : PM3_EINVARG;
}

const char *duox_certificate_anchor_subject(const duox_certificate_anchor_t *anchor) {
    if (anchor == NULL || anchor->type != DUOX_CERTIFICATE_ANCHOR_MATERIAL_CERT) {
        return "";
    }
    return anchor->material.cert.subject;
}

const char *duox_certificate_anchor_display_name(const duox_certificate_anchor_t *anchor) {
    if (anchor == NULL) {
        return "unknown certificate anchor";
    }
    if (anchor->name[0] != '\0') {
        return anchor->name;
    }
    if (anchor->source[0] != '\0') {
        return anchor->source;
    }
    if (anchor->type == DUOX_CERTIFICATE_ANCHOR_MATERIAL_PUBLIC_KEY) {
        return "provided public key";
    }
    return "provided certificate";
}

static int duox_load_x509_certificate_input(const char *input, mbedtls_x509_crt *cert) {
    if (input == NULL || cert == NULL) {
        return PM3_EINVARG;
    }

    char normalized[DUOX_CERTIFICATE_ANCHOR_INPUT_LEN] = {0};
    size_t input_len = strlen(input);
    if (input_len >= sizeof(normalized)) {
        return PM3_EOVFLOW;
    }
    memcpy(normalized, input, input_len + 1);
    duox_trim_ascii_inplace(normalized);
    if (normalized[0] == '\0') {
        return PM3_EINVARG;
    }

    char *resolved_path = NULL;
    if (searchFile(&resolved_path, RESOURCES_SUBDIR, normalized, "", true) == PM3_SUCCESS) {
        int ret = mbedtls_x509_crt_parse_file(cert, resolved_path);
        free(resolved_path);
        if (ret == 0) {
            return PM3_SUCCESS;
        }
    }

    if (mbedtls_x509_crt_parse(cert, (const unsigned char *)normalized, strlen(normalized) + 1) == 0) {
        return PM3_SUCCESS;
    }

    char compact[DUOX_CERTIFICATE_ANCHOR_INPUT_LEN] = {0};
    size_t compact_len = 0;
    if (duox_copy_without_whitespace(normalized, compact, sizeof(compact), &compact_len) != PM3_SUCCESS || compact_len == 0) {
        return PM3_EINVARG;
    }

    size_t der_capacity = (compact_len / 2) + 1;
    uint8_t *der = calloc(der_capacity, sizeof(uint8_t));
    if (der == NULL) {
        return PM3_EMALLOC;
    }

    int der_len = hex_to_bytes(compact, der, der_capacity);
    int res = (der_len > 0 && mbedtls_x509_crt_parse_der(cert, der, (size_t)der_len) == 0) ? PM3_SUCCESS : PM3_EINVARG;
    free(der);
    return res;
}

static int duox_load_certificate_anchor_from_certificate_input(const char *input, const char *name_hint,
                                                               const char *source, duox_certificate_anchor_t *anchor) {
    if (input == NULL || anchor == NULL) {
        return PM3_EINVARG;
    }

    duox_certificate_anchor_t candidate = {0};
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int res = duox_load_x509_certificate_input(input, &cert);
    if (res == PM3_SUCCESS) {
        res = duox_cert_info_from_x509_crt(&cert, &candidate.material.cert);
    }
    mbedtls_x509_crt_free(&cert);
    if (res != PM3_SUCCESS) {
        return res;
    }

    candidate.type = DUOX_CERTIFICATE_ANCHOR_MATERIAL_CERT;
    if (source != NULL && source[0] != '\0') {
        str_copy(candidate.source, sizeof(candidate.source), source);
    }
    if (name_hint != NULL && name_hint[0] != '\0') {
        str_copy(candidate.name, sizeof(candidate.name), name_hint);
    } else if (candidate.material.cert.subject[0] != '\0') {
        str_copy(candidate.name, sizeof(candidate.name), candidate.material.cert.subject);
    } else {
        str_copy(candidate.name, sizeof(candidate.name), "x509 certificate anchor");
    }

    *anchor = candidate;
    return PM3_SUCCESS;
}

static int duox_load_certificate_anchor_from_pubkey_input(const char *input, const char *name_hint,
                                                          const char *source, duox_certificate_anchor_t *anchor) {
    if (input == NULL || anchor == NULL) {
        return PM3_EINVARG;
    }

    static const mbedtls_ecp_group_id curves[] = {
        MBEDTLS_ECP_DP_SECP256R1,
        MBEDTLS_ECP_DP_SECP384R1,
        MBEDTLS_ECP_DP_SECP521R1,
        MBEDTLS_ECP_DP_SECP224R1,
        MBEDTLS_ECP_DP_SECP192R1,
        MBEDTLS_ECP_DP_BP256R1,
        MBEDTLS_ECP_DP_SECP256K1,
    };

    for (size_t i = 0; i < ARRAYLEN(curves); i++) {
        const mbedtls_ecp_curve_info *curve_info = mbedtls_ecp_curve_info_from_grp_id(curves[i]);
        if (curve_info == NULL) {
            continue;
        }

        duox_certificate_anchor_t candidate = {0};
        candidate.type = DUOX_CERTIFICATE_ANCHOR_MATERIAL_PUBLIC_KEY;
        if (source != NULL && source[0] != '\0') {
            str_copy(candidate.source, sizeof(candidate.source), source);
        }
        if (name_hint != NULL && name_hint[0] != '\0') {
            str_copy(candidate.name, sizeof(candidate.name), name_hint);
        } else {
            str_copy(candidate.name, sizeof(candidate.name), "provided public key");
        }

        size_t coord_len = (curve_info->bit_size + 7) / 8;
        size_t pubkey_len = 1 + (2 * coord_len);
        if (pubkey_len > sizeof(candidate.material.key.pubkey)) {
            continue;
        }

        if (ensure_ec_public_key(input, curves[i], candidate.material.key.pubkey, pubkey_len) == PM3_SUCCESS) {
            candidate.material.key.curveid = curves[i];
            candidate.material.key.pubkey_len = pubkey_len;
            *anchor = candidate;
            return PM3_SUCCESS;
        }
    }

    return PM3_EINVARG;
}

static int duox_load_certificate_anchor_from_file_path(const char *filepath, duox_certificate_anchor_t *anchor) {
    if (filepath == NULL || anchor == NULL) {
        return PM3_EINVARG;
    }

    char filename_anchor_name[DUOX_CERTIFICATE_ANCHOR_NAME_LEN] = {0};
    duox_path_basename_without_ext(filepath, filename_anchor_name, sizeof(filename_anchor_name));
    if (filename_anchor_name[0] == '\0') {
        return PM3_EINVARG;
    }

    int res = duox_load_certificate_anchor_from_certificate_input(filepath, filename_anchor_name, filepath, anchor);
    if (res == PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    return duox_load_certificate_anchor_from_pubkey_input(filepath, filename_anchor_name, filepath, anchor);
}

static int duox_load_named_certificate_anchor_from_store(const char *token, const char *anchor_store_dir,
                                                         duox_certificate_anchor_t *anchor) {
    if (token == NULL || anchor_store_dir == NULL || anchor == NULL) {
        return PM3_EINVARG;
    }

    char paths[DUOX_CERTIFICATE_ANCHOR_MAX_PATHS][DUOX_CERTIFICATE_ANCHOR_PATH_LEN] = {{0}};
    size_t path_count = 0;
    int res = duox_collect_certificate_anchor_paths(anchor_store_dir, paths, ARRAYLEN(paths), &path_count);
    if (res != PM3_SUCCESS) {
        return res;
    }

    for (size_t i = 0; i < path_count; i++) {
        char filename_anchor_name[DUOX_CERTIFICATE_ANCHOR_NAME_LEN] = {0};
        duox_path_basename_without_ext(paths[i], filename_anchor_name, sizeof(filename_anchor_name));
        if (filename_anchor_name[0] == '\0') {
            continue;
        }
        if (!str_equal_case_insensitive(token, filename_anchor_name)) {
            continue;
        }
        return duox_load_certificate_anchor_from_file_path(paths[i], anchor);
    }

    const char *matched_path = NULL;
    for (size_t i = 0; i < path_count; i++) {
        char filename_anchor_name[DUOX_CERTIFICATE_ANCHOR_NAME_LEN] = {0};
        duox_path_basename_without_ext(paths[i], filename_anchor_name, sizeof(filename_anchor_name));
        if (filename_anchor_name[0] == '\0' || !str_startswith_case_insensitive(filename_anchor_name, token)) {
            continue;
        }
        if (matched_path != NULL) {
            return PM3_EOVFLOW;
        }
        matched_path = paths[i];
    }

    if (matched_path != NULL) {
        return duox_load_certificate_anchor_from_file_path(matched_path, anchor);
    }

    return PM3_EINVARG;
}

int duox_load_certificate_anchor_from_input(const char *input, const char *anchor_store_dir,
                                            duox_certificate_anchor_t *anchor) {
    if (input == NULL || anchor == NULL) {
        return PM3_EINVARG;
    }

    char normalized[DUOX_CERTIFICATE_ANCHOR_INPUT_LEN] = {0};
    snprintf(normalized, sizeof(normalized), "%s", input);
    duox_trim_ascii_inplace(normalized);
    if (normalized[0] == '\0') {
        return PM3_EINVARG;
    }

    char *resolved_path = NULL;
    if (searchFile(&resolved_path, RESOURCES_SUBDIR, normalized, "", true) == PM3_SUCCESS) {
        int res = PM3_EINVARG;
        if (duox_path_is_regular_file(resolved_path)) {
            res = duox_load_certificate_anchor_from_file_path(resolved_path, anchor);
        }
        free(resolved_path);
        if (res == PM3_SUCCESS) {
            return PM3_SUCCESS;
        }
    }

    if (anchor_store_dir != NULL && anchor_store_dir[0] != '\0') {
        int res = duox_load_named_certificate_anchor_from_store(normalized, anchor_store_dir, anchor);
        if (res == PM3_SUCCESS) {
            return PM3_SUCCESS;
        }
    }

    int res = duox_load_certificate_anchor_from_certificate_input(normalized, NULL, "inline certificate", anchor);
    if (res == PM3_SUCCESS) {
        return PM3_SUCCESS;
    }

    return duox_load_certificate_anchor_from_pubkey_input(normalized, NULL, "inline public key", anchor);
}

int duox_load_certificate_anchors_from_store(const char *anchor_store_dir,
                                             duox_certificate_anchor_t *anchors,
                                             size_t max_anchors, size_t *out_count) {
    if (anchor_store_dir == NULL || anchors == NULL || out_count == NULL) {
        return PM3_EINVARG;
    }

    char paths[DUOX_CERTIFICATE_ANCHOR_MAX_PATHS][DUOX_CERTIFICATE_ANCHOR_PATH_LEN] = {{0}};
    size_t path_count = 0;
    int res = duox_collect_certificate_anchor_paths(anchor_store_dir, paths, ARRAYLEN(paths), &path_count);
    if (res != PM3_SUCCESS) {
        return res;
    }
    if (path_count == 0) {
        return PM3_EFILE;
    }

    size_t count = 0;
    for (size_t i = 0; i < path_count && count < max_anchors; i++) {
        res = duox_load_certificate_anchor_from_file_path(paths[i], &anchors[count]);
        if (res == PM3_SUCCESS) {
            count++;
        }
    }

    if (count == 0) {
        return PM3_EFILE;
    }

    *out_count = count;
    return PM3_SUCCESS;
}

static int duox_asn1_seq_full_length(const uint8_t *data, size_t datalen, size_t *fulllen) {
    if (data == NULL || fulllen == NULL || datalen < 2) {
        return PM3_EINVARG;
    }

    unsigned char *p = (unsigned char *)data;
    const unsigned char *end = data + datalen;
    size_t body_len = 0;
    int res = mbedtls_asn1_get_tag(&p, end, &body_len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE);
    if (res != 0 || body_len > (size_t)(end - p)) {
        return PM3_ESOFT;
    }

    *fulllen = (size_t)(p - data) + body_len;
    return PM3_SUCCESS;
}

static int duox_parse_x509_der_crt(const uint8_t *data, size_t data_len, bool verbose, mbedtls_x509_crt *cert) {
    if (data == NULL || data_len == 0 || cert == NULL) {
        return PM3_EINVARG;
    }

    size_t detected_len = 0;
    if (duox_asn1_seq_full_length(data, data_len, &detected_len) != PM3_SUCCESS || detected_len != data_len) {
        return PM3_ENODATA;
    }

    int xres = mbedtls_x509_crt_parse_der(cert, data, data_len);
    if (xres == 0) {
        return PM3_SUCCESS;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "X.509 parser rejected certificate data (0x%x)",
                      (xres < 0) ? -xres : xres);
    }
    return PM3_ENODATA;
}

static int duox_x509_public_key_from_cert(const mbedtls_x509_crt *cert,
                                          mbedtls_ecp_group_id *curveid,
                                          uint8_t *out_pub, size_t out_pub_capacity, size_t *out_pub_len) {
    if (cert == NULL || out_pub == NULL || out_pub_len == NULL || out_pub_capacity == 0) {
        return PM3_EINVARG;
    }

    if (!mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_ECKEY) &&
            !mbedtls_pk_can_do(&cert->pk, MBEDTLS_PK_ECDSA)) {
        return PM3_ENOTIMPL;
    }

    mbedtls_ecp_keypair *ec = mbedtls_pk_ec(cert->pk);
    if (ec == NULL) {
        return PM3_ESOFT;
    }

    size_t coord_len = (ec->grp.nbits + 7) / 8;
    size_t expected_len = 1 + (2 * coord_len);
    if (expected_len > out_pub_capacity) {
        return PM3_EOVFLOW;
    }

    size_t written = 0;
    if (mbedtls_ecp_point_write_binary(&ec->grp, &ec->Q, MBEDTLS_ECP_PF_UNCOMPRESSED, &written, out_pub, out_pub_capacity) != 0 ||
            written != expected_len) {
        return PM3_ESOFT;
    }

    if (curveid != NULL) {
        *curveid = ec->grp.id;
    }
    *out_pub_len = written;
    return PM3_SUCCESS;
}

static int duox_cert_info_from_x509_crt(const mbedtls_x509_crt *cert, duox_cert_info_t *out) {
    if (cert == NULL || out == NULL) {
        return PM3_EINVARG;
    }

    duox_cert_info_t info = {0};
    info.format = DUOX_CERTIFICATE_FORMAT_X509;
    mbedtls_x509_dn_gets(info.issuer, sizeof(info.issuer), &cert->issuer);
    mbedtls_x509_dn_gets(info.subject, sizeof(info.subject), &cert->subject);
    snprintf(info.serial, sizeof(info.serial), "%s", sprint_hex_inrow(cert->serial.p, cert->serial.len));
    snprintf(info.valid_from, sizeof(info.valid_from), "%04d-%02d-%02d %02d:%02d:%02d",
             cert->valid_from.year, cert->valid_from.mon, cert->valid_from.day,
             cert->valid_from.hour, cert->valid_from.min, cert->valid_from.sec);
    snprintf(info.valid_to, sizeof(info.valid_to), "%04d-%02d-%02d %02d:%02d:%02d",
             cert->valid_to.year, cert->valid_to.mon, cert->valid_to.day,
             cert->valid_to.hour, cert->valid_to.min, cert->valid_to.sec);

    int res = duox_x509_public_key_from_cert(cert, &info.curveid, info.pubkey, sizeof(info.pubkey), &info.pubkey_len);
    *out = info;
    return res;
}

int duox_parse_x509_certificate(const uint8_t *data, size_t data_len,
                                bool verbose, duox_cert_info_t *out) {
    if (data == NULL || data_len == 0 || out == NULL) {
        return PM3_EINVARG;
    }

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int res = duox_parse_x509_der_crt(data, data_len, verbose, &cert);
    if (res == PM3_SUCCESS) {
        res = (duox_cert_info_from_x509_crt(&cert, out) == PM3_SUCCESS) ? PM3_SUCCESS : PM3_ECRYPTO;
    }
    mbedtls_x509_crt_free(&cert);
    return res;
}

static int duox_verify_x509_signature_with_public_key(const mbedtls_x509_crt *cert,
                                                      mbedtls_ecp_group_id signer_curveid,
                                                      const uint8_t *signer_pubkey, size_t signer_pubkey_len,
                                                      bool verbose) {
    if (cert == NULL || signer_pubkey == NULL || signer_pubkey_len == 0 ||
            signer_curveid == MBEDTLS_ECP_DP_NONE) {
        return PM3_EINVARG;
    }
    if (cert->sig_md == MBEDTLS_MD_NONE || mbedtls_md_info_from_type(cert->sig_md) == NULL) {
        if (verbose) {
            PrintAndLogEx(WARNING, "Unsupported X.509 signature hash");
        }
        return PM3_ENOTIMPL;
    }
    if (cert->sig_pk != MBEDTLS_PK_ECDSA) {
        if (verbose) {
            PrintAndLogEx(WARNING, "Unsupported X.509 signature public key type (need ECDSA)");
        }
        return PM3_ENOTIMPL;
    }

    const mbedtls_md_info_t *md_info = mbedtls_md_info_from_type(cert->sig_md);
    uint8_t digest[MBEDTLS_MD_MAX_SIZE] = {0};
    size_t digest_len = mbedtls_md_get_size(md_info);
    if (digest_len == 0 || digest_len > sizeof(digest) ||
            mbedtls_md(md_info, cert->tbs.p, cert->tbs.len, digest) != 0) {
        return PM3_ESOFT;
    }

    mbedtls_ecdsa_context ctx;
    mbedtls_ecdsa_init(&ctx);
    int status = PM3_ESOFT;
    if (mbedtls_ecp_group_load(&ctx.grp, signer_curveid) != 0) {
        goto out;
    }
    size_t expected_key_len = 1 + 2 * ((ctx.grp.nbits + 7) / 8);
    if (signer_pubkey_len != expected_key_len ||
            mbedtls_ecp_point_read_binary(&ctx.grp, &ctx.Q, signer_pubkey, signer_pubkey_len) != 0 ||
            mbedtls_ecp_check_pubkey(&ctx.grp, &ctx.Q) != 0) {
        status = PM3_EINVARG;
        goto out;
    }

    status = (mbedtls_ecdsa_read_signature(&ctx, digest, digest_len, cert->sig.p, cert->sig.len) == 0) ? PM3_SUCCESS : PM3_ESOFT;

out:
    mbedtls_ecdsa_free(&ctx);
    return status;
}

static int duox_verify_x509_signature_with_anchor(const mbedtls_x509_crt *cert,
                                                  const duox_certificate_anchor_t *anchor,
                                                  bool verbose) {
    if (cert == NULL || anchor == NULL) {
        return PM3_EINVARG;
    }

    mbedtls_ecp_group_id curveid = MBEDTLS_ECP_DP_NONE;
    const uint8_t *pubkey = NULL;
    size_t pubkey_len = 0;
    int res = duox_certificate_anchor_public_key(anchor, &curveid, &pubkey, &pubkey_len);
    if (res != PM3_SUCCESS) {
        return res;
    }

    return duox_verify_x509_signature_with_public_key(cert, curveid, pubkey, pubkey_len, verbose);
}

int duox_verify_x509_certificate_with_anchors(const uint8_t *data, size_t data_len,
                                              const duox_certificate_anchor_t *anchors, size_t anchor_count,
                                              bool verbose, duox_cert_info_t *out,
                                              size_t *matched_index) {
    if (data == NULL || data_len == 0 || anchors == NULL || anchor_count == 0 ||
            anchor_count > DUOX_MAX_CERTIFICATE_ANCHORS || out == NULL) {
        return PM3_EINVARG;
    }

    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    int res = duox_parse_x509_der_crt(data, data_len, verbose, &cert);
    if (res != PM3_SUCCESS) {
        mbedtls_x509_crt_free(&cert);
        return res;
    }

    duox_cert_info_t info = {0};
    res = duox_cert_info_from_x509_crt(&cert, &info);
    *out = info;
    if (res != PM3_SUCCESS) {
        mbedtls_x509_crt_free(&cert);
        return PM3_ECRYPTO;
    }

    bool tried[DUOX_MAX_CERTIFICATE_ANCHORS] = {0};
    int verify_res = PM3_ECRYPTO;
    if (info.issuer[0] != '\0') {
        for (size_t i = 0; i < anchor_count; i++) {
            const char *subject = duox_certificate_anchor_subject(&anchors[i]);
            if (subject[0] == '\0' || !str_contains_case_insensitive(info.issuer, subject)) {
                continue;
            }

            tried[i] = true;
            if (duox_verify_x509_signature_with_anchor(&cert, &anchors[i], verbose) == PM3_SUCCESS) {
                if (matched_index != NULL) {
                    *matched_index = i;
                }
                verify_res = PM3_SUCCESS;
                goto out;
            }
        }
    }

    for (size_t i = 0; i < anchor_count; i++) {
        if (tried[i]) {
            continue;
        }

        if (duox_verify_x509_signature_with_anchor(&cert, &anchors[i], verbose) == PM3_SUCCESS) {
            if (matched_index != NULL) {
                *matched_index = i;
            }
            verify_res = PM3_SUCCESS;
            goto out;
        }
    }

out:
    mbedtls_x509_crt_free(&cert);
    return verify_res;
}

static bool duox_format_bcd_date(const uint8_t *data, size_t data_len, char *out, size_t out_len) {
    if (data == NULL || data_len != 4 || out == NULL || out_len < 11) {
        return false;
    }
    for (size_t i = 0; i < data_len; i++) {
        if ((data[i] >> 4) > 9 || (data[i] & 0x0F) > 9) {
            return false;
        }
    }
    snprintf(out, out_len, "%02X%02X-%02X-%02X", data[0], data[1], data[2], data[3]);
    return true;
}

typedef struct {
    uint32_t tag;
    size_t tl_offset;
    size_t value_offset;
    size_t len;
    size_t total_len;
    const uint8_t *value;
} duox_gp_vde_tlv_t;

static int duox_gp_vde_parse_tlv(const uint8_t *data, size_t data_len, size_t *offset, duox_gp_vde_tlv_t *tlv) {
    if (data == NULL || offset == NULL || tlv == NULL || *offset >= data_len) {
        return PM3_ENODATA;
    }

    size_t idx = *offset;
    uint32_t tag = data[idx++];
    if ((tag & 0x1F) == 0x1F) {
        do {
            if (idx >= data_len || tag > 0x00FFFFFFU) {
                return PM3_ENODATA;
            }
            uint8_t b = data[idx++];
            tag = (tag << 8) | b;
            if ((b & 0x80) == 0) {
                break;
            }
        } while (true);
    }

    size_t len = 0;
    if (idx >= data_len || data[idx] == 0x80 ||
            ((data[idx] & 0x80) != 0 && (data[idx] & 0x7F) > sizeof(size_t))) {
        return PM3_ENODATA;
    }
    if (asn1_get_tag_length(data, &len, &idx, data_len) != 0 || len > data_len - idx) {
        return PM3_ENODATA;
    }

    tlv->tag = tag;
    tlv->tl_offset = *offset;
    tlv->value_offset = idx;
    tlv->len = len;
    tlv->total_len = (idx - *offset) + len;
    tlv->value = data + idx;
    *offset = idx + len;
    return PM3_SUCCESS;
}

static int duox_verify_gp_vde_signature(const uint8_t *signed_data, size_t signed_data_len,
                                        const uint8_t signature_rs[DUOX_VDE_SIG_LEN],
                                        const uint8_t *ca_id, size_t ca_id_len,
                                        const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                        bool verbose, size_t *matched_index) {
    if (signed_data == NULL || signed_data_len == 0 || signature_rs == NULL ||
            ca_anchors == NULL || ca_anchor_count == 0 || ca_anchor_count > DUOX_MAX_CERTIFICATE_ANCHORS) {
        return PM3_EINVARG;
    }

    char ca_id_hex[32] = {0};
    snprintf(ca_id_hex, sizeof(ca_id_hex), "%s", sprint_hex_inrow(ca_id, ca_id_len));

    bool tried[DUOX_MAX_CERTIFICATE_ANCHORS] = {0};
    for (int pass = 0; pass < 2; pass++) {
        for (size_t i = 0; i < ca_anchor_count; i++) {
            if (tried[i]) {
                continue;
            }
            if (pass == 0 && ca_id_hex[0] != '\0' &&
                    strstr(duox_certificate_anchor_subject(&ca_anchors[i]), ca_id_hex) == NULL) {
                continue;
            }

            mbedtls_ecp_group_id curveid = MBEDTLS_ECP_DP_NONE;
            const uint8_t *pubkey = NULL;
            size_t pubkey_len = 0;
            if (duox_certificate_anchor_public_key(&ca_anchors[i], &curveid, &pubkey, &pubkey_len) != PM3_SUCCESS ||
                    curveid != MBEDTLS_ECP_DP_BP256R1 || pubkey_len != 65) {
                continue;
            }

            tried[i] = true;
            int res = ecdsa_signature_r_s_verify(MBEDTLS_ECP_DP_BP256R1,
                      (uint8_t *)pubkey,
                      (uint8_t *)signed_data,
                      (int)signed_data_len,
                      (uint8_t *)signature_rs,
                      DUOX_VDE_SIG_LEN,
                      true);
            if (res == PM3_SUCCESS) {
                if (matched_index != NULL) {
                    *matched_index = i;
                }
                return PM3_SUCCESS;
            }
            if (verbose) {
                PrintAndLogEx(INFO, "GP VDE signature did not verify with %s", duox_certificate_anchor_display_name(&ca_anchors[i]));
            }
        }
    }

    return PM3_ECRYPTO;
}

int duox_parse_gp_vde_certificate(const uint8_t *data, size_t data_len,
                                  const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                  bool verify_signature,
                                  bool verbose, duox_cert_info_t *out, size_t *matched_index) {
    if (data == NULL || data_len == 0 || out == NULL) {
        return PM3_EINVARG;
    }
    if (verify_signature && (ca_anchors == NULL || ca_anchor_count == 0)) {
        return PM3_EINVARG;
    }

    size_t offset = 0;
    duox_gp_vde_tlv_t outer = {0};
    int res = duox_gp_vde_parse_tlv(data, data_len, &offset, &outer);
    if (res != PM3_SUCCESS || outer.tag != 0x7F21) {
        return PM3_ENODATA;
    }

    size_t cert_end = outer.value_offset + outer.len;
    const uint8_t *ca_id = NULL;
    size_t ca_id_len = 0;
    const uint8_t *serial_uid = NULL;
    size_t serial_uid_len = 0;
    const uint8_t *subject_id = NULL;
    size_t subject_id_len = 0;
    const uint8_t *signature_rs = NULL;
    const uint8_t *public_key = NULL;
    size_t signed_start = SIZE_MAX;
    size_t signed_end = 0;
    bool curve_ok = false;
    char valid_from[DUOX_CERT_TEXT_LEN] = {0};
    char valid_to[DUOX_CERT_TEXT_LEN] = {0};

    offset = outer.value_offset;
    while (offset < cert_end) {
        duox_gp_vde_tlv_t tlv = {0};
        res = duox_gp_vde_parse_tlv(data, cert_end, &offset, &tlv);
        if (res != PM3_SUCCESS) {
            return res;
        }

        switch (tlv.tag) {
            case 0x93:
                serial_uid = tlv.value;
                serial_uid_len = tlv.len;
                signed_start = tlv.tl_offset;
                break;
            case 0x42:
                ca_id = tlv.value;
                ca_id_len = tlv.len;
                break;
            case 0x5F20:
                subject_id = tlv.value;
                subject_id_len = tlv.len;
                break;
            case 0x5F25:
                duox_format_bcd_date(tlv.value, tlv.len, valid_from, sizeof(valid_from));
                break;
            case 0x5F24:
                duox_format_bcd_date(tlv.value, tlv.len, valid_to, sizeof(valid_to));
                break;
            case 0x7F49: {
                size_t pki_end = tlv.value_offset + tlv.len;
                size_t pki_offset = tlv.value_offset;
                while (pki_offset < pki_end) {
                    duox_gp_vde_tlv_t ktlv = {0};
                    res = duox_gp_vde_parse_tlv(data, pki_end, &pki_offset, &ktlv);
                    if (res != PM3_SUCCESS) {
                        return res;
                    }
                    if (ktlv.tag == 0xB0 && ktlv.len == 65 && ktlv.value[0] == 0x04) {
                        public_key = ktlv.value;
                    } else if (ktlv.tag == 0xF0 && ktlv.len == 1 && ktlv.value[0] == 0x03) {
                        curve_ok = true;
                    }
                }
                signed_end = tlv.tl_offset + tlv.total_len;
                break;
            }
            case 0x5F37:
                if (tlv.len == DUOX_VDE_SIG_LEN) {
                    signature_rs = tlv.value;
                }
                break;
            default:
                break;
        }
    }

    if (signed_start == SIZE_MAX || signed_end <= signed_start || public_key == NULL || !curve_ok ||
            signature_rs == NULL || ca_id == NULL || subject_id == NULL) {
        return PM3_ENODATA;
    }

    duox_cert_info_t info = {0};
    info.format = DUOX_CERTIFICATE_FORMAT_GP_VDE;
    info.curveid = MBEDTLS_ECP_DP_BP256R1;
    memcpy(info.pubkey, public_key, 65);
    info.pubkey_len = 65;

    char ca_id_hex[32] = {0};
    char serial_hex[32] = {0};
    char subject_hex[32] = {0};
    snprintf(ca_id_hex, sizeof(ca_id_hex), "%s", sprint_hex_inrow(ca_id, ca_id_len));
    snprintf(serial_hex, sizeof(serial_hex), "%s", sprint_hex_inrow(serial_uid, serial_uid_len));
    snprintf(subject_hex, sizeof(subject_hex), "%s", sprint_hex_inrow(subject_id, subject_id_len));
    snprintf(info.issuer, sizeof(info.issuer), "CA ID %s", ca_id_hex);
    snprintf(info.subject, sizeof(info.subject), "Subject ID %s", subject_hex);
    snprintf(info.serial, sizeof(info.serial), "%s", serial_hex);
    snprintf(info.valid_from, sizeof(info.valid_from), "%s", valid_from);
    snprintf(info.valid_to, sizeof(info.valid_to), "%s", valid_to);
    snprintf(info.certificate_profile_note, sizeof(info.certificate_profile_note), "VDE CA ID %s", ca_id_hex);
    *out = info;

    if (!verify_signature) {
        return PM3_SUCCESS;
    }

    return duox_verify_gp_vde_signature(data + signed_start, signed_end - signed_start,
                                        signature_rs, ca_id, ca_id_len,
                                        ca_anchors, ca_anchor_count,
                                        verbose, matched_index);
}

static int duox_parse_or_verify_x509_payload(const uint8_t *data, size_t data_len,
                                             const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                             bool verify_signature,
                                             bool verbose, duox_cert_info_t *out, size_t *matched_index) {
    return verify_signature
           ? duox_verify_x509_certificate_with_anchors(data, data_len,
                   ca_anchors, ca_anchor_count,
                   verbose, out, matched_index)
           : duox_parse_x509_certificate(data, data_len, verbose, out);
}

static int duox_verify_x509_certificate_variants(const uint8_t *data, size_t data_len,
                                                 const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                                 bool verify_signature,
                                                 bool verbose, duox_cert_info_t *out, size_t *matched_index) {
    if (data == NULL || data_len == 0 || out == NULL) {
        return PM3_EINVARG;
    }

    int res = duox_parse_or_verify_x509_payload(data, data_len,
                                                ca_anchors, ca_anchor_count,
                                                verify_signature,
                                                verbose, out, matched_index);
    if (res != PM3_ENODATA) {
        return res;
    }

    size_t payload_len = 0;
    if (data_len > 3) {
        payload_len = (size_t)data[0] | ((size_t)data[1] << 8) | ((size_t)data[2] << 16);
        if (payload_len > 0 && payload_len <= data_len - 3) {
            if (verbose) {
                PrintAndLogEx(INFO, "Trying 3-byte length-prefixed X.509 payload (%zu bytes)", payload_len);
            }
            res = duox_parse_or_verify_x509_payload(data + 3, payload_len,
                                                    ca_anchors, ca_anchor_count,
                                                    verify_signature,
                                                    verbose, out, matched_index);
            if (res != PM3_ENODATA) {
                return res;
            }
        }
    }

    if (data_len > 2 && data[0] == 0x30) {
        size_t asn1_len = 0;
        size_t asn1_offset = 1;
        if (asn1_get_tag_length(data, &asn1_len, &asn1_offset, data_len) == 0 &&
                asn1_len <= data_len - asn1_offset) {
            payload_len = asn1_offset + asn1_len;
        }
    }
    if (payload_len > 0 && payload_len < data_len) {
        if (verbose) {
            PrintAndLogEx(INFO, "Trying zero-padded X.509 payload (%zu bytes)", payload_len);
        }
        return duox_parse_or_verify_x509_payload(data, payload_len,
                ca_anchors, ca_anchor_count,
                verify_signature,
                verbose, out, matched_index);
    }

    return PM3_ENODATA;
}

int duox_parse_or_verify_certificate_variants(const uint8_t *data, size_t data_len,
                                              const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                              bool verify_signature,
                                              bool verbose, duox_cert_info_t *out, size_t *matched_index) {
    int x509_res = duox_verify_x509_certificate_variants(data, data_len,
                   ca_anchors, ca_anchor_count,
                   verify_signature,
                   verbose, out, matched_index);
    if (x509_res != PM3_ENODATA) {
        return x509_res;
    }

    int gp_res = duox_parse_gp_vde_certificate(data, data_len,
                 ca_anchors, ca_anchor_count,
                 verify_signature,
                 verbose, out, matched_index);
    if (gp_res != PM3_ENODATA) {
        return gp_res;
    }

    return PM3_ENODATA;
}
