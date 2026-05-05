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

#ifndef DUOXCRYPTO_H
#define DUOXCRYPTO_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <mbedtls/ecp.h>

#define DUOX_DEFAULT_CA_DIR                        "duox_trust"
#define DUOX_EC_PUBKEY_MAX_LEN                     133
#define DUOX_MAX_CERTIFICATE_ANCHORS               16
#define DUOX_CERTIFICATE_ANCHOR_NAME_LEN           96
#define DUOX_CERTIFICATE_ANCHOR_MAX_PATHS          128
#define DUOX_CERTIFICATE_ANCHOR_PATH_LEN           1024
#define DUOX_CERT_TEXT_LEN                         256
#define DUOX_VDE_CHALLENGE_LEN                     32
#define DUOX_VDE_SIG_LEN                           64

typedef enum {
    DUOX_CERTIFICATE_FORMAT_UNKNOWN = 0,
    DUOX_CERTIFICATE_FORMAT_X509,
    DUOX_CERTIFICATE_FORMAT_GP_VDE,
} duox_certificate_format_t;

typedef struct {
    duox_certificate_format_t format;
    mbedtls_ecp_group_id curveid;
    uint8_t pubkey[DUOX_EC_PUBKEY_MAX_LEN];
    size_t pubkey_len;
    char issuer[DUOX_CERT_TEXT_LEN];
    char subject[DUOX_CERT_TEXT_LEN];
    char serial[DUOX_CERT_TEXT_LEN];
    char valid_from[DUOX_CERT_TEXT_LEN];
    char valid_to[DUOX_CERT_TEXT_LEN];
    char certificate_profile_note[DUOX_CERT_TEXT_LEN];
} duox_cert_info_t;

typedef struct {
    mbedtls_ecp_group_id curveid;
    uint8_t pubkey[DUOX_EC_PUBKEY_MAX_LEN];
    size_t pubkey_len;
} duox_ec_public_key_t;

typedef enum {
    DUOX_CERTIFICATE_ANCHOR_MATERIAL_NONE = 0,
    DUOX_CERTIFICATE_ANCHOR_MATERIAL_PUBLIC_KEY,
    DUOX_CERTIFICATE_ANCHOR_MATERIAL_CERT,
} duox_certificate_anchor_material_type_t;

typedef struct {
    char name[DUOX_CERTIFICATE_ANCHOR_NAME_LEN];
    char source[DUOX_CERTIFICATE_ANCHOR_PATH_LEN];
    duox_certificate_anchor_material_type_t type;
    union {
        duox_ec_public_key_t key;
        duox_cert_info_t cert;
    } material;
} duox_certificate_anchor_t;

const char *duox_certificate_format_name(duox_certificate_format_t format);
int duox_certificate_anchor_public_key(const duox_certificate_anchor_t *anchor,
                                       mbedtls_ecp_group_id *curveid,
                                       const uint8_t **pubkey, size_t *pubkey_len);
const char *duox_certificate_anchor_subject(const duox_certificate_anchor_t *anchor);
const char *duox_certificate_anchor_display_name(const duox_certificate_anchor_t *anchor);
int duox_load_certificate_anchor_from_input(const char *input, const char *anchor_store_dir,
                                            duox_certificate_anchor_t *anchor);
int duox_load_certificate_anchors_from_store(const char *anchor_store_dir,
                                             duox_certificate_anchor_t *anchors,
                                             size_t max_anchors, size_t *out_count);
int duox_parse_x509_certificate(const uint8_t *data, size_t data_len,
                                bool verbose, duox_cert_info_t *out);
int duox_verify_x509_certificate_with_anchors(const uint8_t *data, size_t data_len,
                                              const duox_certificate_anchor_t *anchors, size_t anchor_count,
                                              bool verbose, duox_cert_info_t *out,
                                              size_t *matched_index);
int duox_parse_gp_vde_certificate(const uint8_t *data, size_t data_len,
                                  const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                  bool verify_signature,
                                  bool verbose, duox_cert_info_t *out, size_t *matched_index);
int duox_parse_or_verify_certificate_variants(const uint8_t *data, size_t data_len,
                                              const duox_certificate_anchor_t *ca_anchors, size_t ca_anchor_count,
                                              bool verify_signature,
                                              bool verbose, duox_cert_info_t *out, size_t *matched_index);

#endif /* DUOXCRYPTO_H */
