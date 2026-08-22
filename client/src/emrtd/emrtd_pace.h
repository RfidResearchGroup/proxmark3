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
// PACE (Password Authenticated Connection Establishment) primitives for eMRTD
//
// ICAO Doc 9303 Part 11, section 4.4 and BSI TR-03110 part 3, section 3.2.
// Everything in here is pure crypto / parsing so that it can be regression
// tested offline by `hf emrtd test` without a card on the reader.
//-----------------------------------------------------------------------------

#ifndef EMRTD_PACE_H__
#define EMRTD_PACE_H__

#include "common.h"
#include <mbedtls/ecp.h>

// Longest OID body (the bytes after the 06 <len> header) we know about
#define EMRTD_PACE_OID_MAXLEN       10
// AES-256
#define EMRTD_SM_MAX_KEY_LEN        32
// AES block, and the SSC length for AES secure messaging
#define EMRTD_SM_MAX_BLOCK_LEN      16
// Uncompressed EC point of the largest curve we support (P-521): 04 || X || Y
#define EMRTD_EC_POINT_MAXLEN       (1 + (2 * 66))
// Largest raw secret fed to the KDF (a P-521 x-coordinate)
#define EMRTD_PACE_SECRET_MAXLEN    66
// Number of SecurityInfos we keep out of EF_CardAccess
#define EMRTD_PACE_MAX_INFOS        16

typedef enum {
    EMRTD_PACE_KA_DH = 0,
    EMRTD_PACE_KA_ECDH,
} emrtd_pace_ka_t;

typedef enum {
    EMRTD_PACE_MAP_GM = 0,      // Generic Mapping
    EMRTD_PACE_MAP_IM,          // Integrated Mapping
    EMRTD_PACE_MAP_CAM,         // Chip Authentication Mapping
} emrtd_pace_map_t;

typedef enum {
    EMRTD_PACE_CIPHER_3DES = 0,
    EMRTD_PACE_CIPHER_AES128,
    EMRTD_PACE_CIPHER_AES192,
    EMRTD_PACE_CIPHER_AES256,
} emrtd_pace_cipher_t;

typedef struct emrtd_pacealg_s {
    const char *name;
    emrtd_pace_ka_t ka;
    emrtd_pace_map_t mapping;
    emrtd_pace_cipher_t cipher;
    size_t keylen;                          // 16 / 24 / 32
    size_t oidlen;
    const uint8_t oid[EMRTD_PACE_OID_MAXLEN];
} emrtd_pacealg_t;

// Standardized Domain Parameters, TR-03110 part 3, table A.2
typedef struct emrtd_pacesdp_s {
    uint8_t id;
    const char *name;
    size_t size;
    bool is_ec;
    // MBEDTLS_ECP_DP_NONE when the curve is not compiled into our mbedtls
    mbedtls_ecp_group_id curve;
} emrtd_pacesdp_t;

// One parsed SecurityInfo out of EF_CardAccess
typedef struct {
    const emrtd_pacealg_t *alg;             // NULL when the OID is unknown to us
    uint8_t oid[EMRTD_PACE_OID_MAXLEN];
    size_t oidlen;
    uint32_t version;
    bool has_param;
    uint8_t param_id;
    const emrtd_pacesdp_t *sdp;             // NULL when param_id is unknown/absent
    bool supported;
    const char *reason;                     // why not supported, NULL when it is
} emrtd_paceinfo_t;

typedef struct {
    emrtd_paceinfo_t infos[EMRTD_PACE_MAX_INFOS];
    size_t count;
    int best;                               // index into infos[], -1 when none usable
} emrtd_cardaccess_t;

typedef enum {
    EMRTD_SM_NONE = 0,
    EMRTD_SM_3DES,
    EMRTD_SM_AES,
} emrtd_sm_t;

// State captured during a PACE run with Chip Authentication Mapping, verified
// once the LDS applet is readable and EF_DG14 can be fetched.
typedef struct {
    bool negotiated;                        // PACE-CAM was the chosen protocol
    mbedtls_ecp_group_id curve;
    uint8_t enc_data[EMRTD_EC_POINT_MAXLEN];    // DO'8A' as returned by the chip
    size_t enc_datalen;
    // our own mapping private key. PACE-CAM reuses it as the terminal side of
    // an ECDH with the chip's static Chip Authentication key, which is what
    // makes the chip prove itself without any extra round trip.
    uint8_t sk_map_ifd[EMRTD_PACE_SECRET_MAXLEN];
    size_t sk_map_ifdlen;
    uint8_t sk_dh_ifd[EMRTD_PACE_SECRET_MAXLEN];    // the step 3 key, over G'
    size_t sk_dh_ifdlen;
    uint8_t pk_map_ic[EMRTD_EC_POINT_MAXLEN];   // the chip's step 2 mapping key
    size_t pk_map_iclen;
    uint8_t pk_dh_ic[EMRTD_EC_POINT_MAXLEN];    // the chip's step 3 agreement key
    size_t pk_dh_iclen;
} emrtd_cam_t;

typedef struct {
    emrtd_sm_t type;
    uint8_t ks_enc[EMRTD_SM_MAX_KEY_LEN];
    uint8_t ks_mac[EMRTD_SM_MAX_KEY_LEN];
    size_t keylen;
    uint8_t ssc[EMRTD_SM_MAX_BLOCK_LEN];
    size_t ssclen;                          // 8 for 3DES, 16 for AES
    bool pace;                              // session was established with PACE
    const char *pace_alg;                   // algorithm name, for reporting
    const char *pace_curve;                 // domain parameter name, for reporting
    emrtd_cam_t cam;
} emrtd_session_t;

//-----------------------------------------------------------------------------
// Shared 3DES / ISO 9797-1 helpers (also used by the BAC path)
//-----------------------------------------------------------------------------
void emrtd_des3_encrypt_cbc(uint8_t *iv, const uint8_t *key, const uint8_t *input, size_t inputlen, uint8_t *output);
void emrtd_des3_decrypt_cbc(uint8_t *iv, const uint8_t *key, const uint8_t *input, size_t inputlen, uint8_t *output);

// ISO 9797-1 padding method 2
size_t emrtd_pad_block(const uint8_t *input, size_t inputlen, size_t blocksize, uint8_t *output);

// ISO 9797-1 MAC algorithm 3 with padding method 2 ("retail MAC")
int emrtd_retail_mac(const uint8_t *key, const uint8_t *input, size_t inputlen, uint8_t *output);

//-----------------------------------------------------------------------------
// Table lookups
//-----------------------------------------------------------------------------
const emrtd_pacealg_t *emrtd_pace_alg_by_oid(const uint8_t *oid, size_t oidlen);
const emrtd_pacesdp_t *emrtd_pace_sdp_by_id(uint8_t id);
const char *emrtd_pace_cipher_name(emrtd_pace_cipher_t cipher);

//-----------------------------------------------------------------------------
// Secure messaging session
//-----------------------------------------------------------------------------
void emrtd_sm_clear(emrtd_session_t *ssn);
int emrtd_sm_setup(emrtd_session_t *ssn, emrtd_pace_cipher_t cipher, const uint8_t *ks_enc, const uint8_t *ks_mac);
size_t emrtd_sm_blocksize(const emrtd_session_t *ssn);
void emrtd_sm_bump_ssc(emrtd_session_t *ssn);
int emrtd_sm_mac(const emrtd_session_t *ssn, const uint8_t *input, size_t inputlen, uint8_t *mac);
int emrtd_sm_encrypt(const emrtd_session_t *ssn, const uint8_t *input, size_t inputlen, uint8_t *output);
int emrtd_sm_decrypt(const emrtd_session_t *ssn, const uint8_t *input, size_t inputlen, uint8_t *output);

//-----------------------------------------------------------------------------
// BER-TLV
//-----------------------------------------------------------------------------
// Reads one TLV starting at *cur. On success *cur is advanced past it.
bool emrtd_tlv_next(const uint8_t **cur, const uint8_t *end, uint32_t *tag, const uint8_t **value, size_t *valuelen);
// Writes tag (1 or 2 bytes, big endian) + length, returns bytes written, 0 on overflow
size_t emrtd_tlv_write_header(uint8_t *out, size_t outlen, uint32_t tag, size_t len);

//-----------------------------------------------------------------------------
// EF_CardAccess
//-----------------------------------------------------------------------------
int emrtd_pace_parse_cardaccess(const uint8_t *data, size_t datalen, emrtd_cardaccess_t *out);
// Higher is better, 0 means unusable. Used to order the algorithms we try.
int emrtd_pace_rank(const emrtd_paceinfo_t *info);

//-----------------------------------------------------------------------------
// PACE key derivation
//-----------------------------------------------------------------------------
// MRZ check digit, ICAO 9303-3 4.9. Returns the digit as a value 0-9, not ASCII.
char emrtd_calculate_check_digit(const char *data);

// The MRZ information string that BAC and PACE both hash: docnr||cd||dob||cd||exp||cd
int emrtd_pace_kmrz(const char *documentnumber, const char *dob, const char *expiry, char *out, size_t outlen);
// K for the MRZ password: SHA-1 of the above
int emrtd_pace_password_mrz(const char *documentnumber, const char *dob, const char *expiry, uint8_t *k, size_t *klen);
// K for the CAN password: the CAN as raw ASCII
int emrtd_pace_password_can(const char *can, uint8_t *k, size_t *klen);
// TR-03110 part 3, A.2.3
int emrtd_pace_kdf(emrtd_pace_cipher_t cipher, const uint8_t *k, size_t klen, uint32_t counter, uint8_t *out, size_t *outlen);

// s = D(Kpi, z), zero IV
int emrtd_pace_decrypt_nonce(emrtd_pace_cipher_t cipher, const uint8_t *kpi, const uint8_t *z, size_t zlen, uint8_t *s);

//-----------------------------------------------------------------------------
// ECDH with Generic Mapping
//-----------------------------------------------------------------------------
size_t emrtd_pace_ec_pointlen(mbedtls_ecp_group_id curve);

// Public key for a caller supplied private scalar over a caller supplied base point.
// base may be NULL to use the nominal generator of the curve.
int emrtd_pace_ec_pubkey(mbedtls_ecp_group_id curve, const uint8_t *base, size_t baselen,
                         const uint8_t *priv, size_t privlen, uint8_t *pub, size_t *publen);

// Fresh ephemeral keypair over base (NULL == nominal generator)
int emrtd_pace_ec_keygen(mbedtls_ecp_group_id curve, const uint8_t *base, size_t baselen,
                         uint8_t *priv, size_t *privlen, uint8_t *pub, size_t *publen);

// G' = s*G + (priv * pk_ic)
int emrtd_pace_ec_gm(mbedtls_ecp_group_id curve, const uint8_t *s, size_t slen,
                     const uint8_t *priv, size_t privlen, const uint8_t *pk_ic, size_t pk_ic_len,
                     uint8_t *mapped, size_t *mappedlen);

// x-coordinate of priv * pk_ic
int emrtd_pace_ec_shared_x(mbedtls_ecp_group_id curve, const uint8_t *priv, size_t privlen,
                           const uint8_t *pk_ic, size_t pk_ic_len, uint8_t *out, size_t *outlen);

// T = MAC(ks_mac, 7F49 || 06 <oid> || 86 <pubkey>) truncated to 8 bytes
int emrtd_pace_token(const emrtd_pacealg_t *alg, const uint8_t *ks_mac,
                     const uint8_t *pubkey, size_t pubkeylen, uint8_t *token);

//-----------------------------------------------------------------------------
// Chip Authentication Mapping
//-----------------------------------------------------------------------------
// Pulls the index'th EC ChipAuthenticationPublicKey out of a SET of
// SecurityInfos, i.e. out of the body of EF_DG14 or the eContent of
// EF_CardSecurity. A document may publish more than one.
int emrtd_pace_find_ca_pubkey(const uint8_t *data, size_t datalen, size_t index, uint8_t *pub, size_t *publen);

// Prints everything a failed CAM check depends on, so it can be reported
void emrtd_pace_cam_dump(const emrtd_session_t *ssn, const uint8_t *pk_icc, size_t pk_icc_len);

// Recovers the Chip Authentication Data out of the DO'8A' the chip returns and
// checks it against the ECDH the terminal can do for itself. Returns
// PM3_SUCCESS when the document has proven it holds the CA private key.
int emrtd_pace_cam_verify(const emrtd_session_t *ssn, const uint8_t *pk_icc, size_t pk_icc_len,
                          const char **mode);

#endif /* emrtd_pace.h */
