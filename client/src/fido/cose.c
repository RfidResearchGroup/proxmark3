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
// Tools for work with COSE (CBOR Object Signing and Encryption) rfc8152
// https://tools.ietf.org/html/rfc8152
//-----------------------------------------------------------------------------

#include "cose.h"

#include "cbortools.h"
#include "commonutil.h"  // ARRAYLEN
#include "ui.h" // Print...
#include "util.h"

static const char COSEEmptyStr[] = "";

typedef struct {
    int Value;
    const char *Name;
    const char *Description;
} COSEValueNameDesc_t;

typedef struct {
    int Value;
    const char *Type;
    const char *Name;
    const char *Description;
} COSEValueTypeNameDesc_t;

// kty - Key Type Values
COSEValueNameDesc_t COSEKeyTypeValueDesc[] = {
    {0, "Reserved",  "Reserved"},
    {1, "OKP",       "Octet Key Pair"},
    {2, "EC2",       "Elliptic Curve Key w/ x- and y-coordinate pair"},
    {4, "Symmetric", "Symmetric Key"},
};

static COSEValueNameDesc_t *GetCOSEktyElm(int id) {
    for (size_t i = 0; i < ARRAYLEN(COSEKeyTypeValueDesc); i++)
        if (COSEKeyTypeValueDesc[i].Value == id)
            return &COSEKeyTypeValueDesc[i];
    return NULL;
}

const char *GetCOSEktyDescription(int id) {
    COSEValueNameDesc_t *elm = GetCOSEktyElm(id);
    if (elm)
        return elm->Description;
    return COSEEmptyStr;
}

// keys
COSEValueTypeNameDesc_t COSECurvesDesc[] = {
    {1, "EC2", "P-256",    "NIST P-256 also known as secp256r1"},
    {2, "EC2", "P-384",    "NIST P-384 also known as secp384r1"},
    {3, "EC2", "P-521",    "NIST P-521 also known as secp521r1"},
    {4, "OKP", "X25519",   "X25519 for use w/ ECDH only"},
    {5, "OKP", "X448",     "X448 for use w/ ECDH only"},
    {6, "OKP", "Ed25519",  "Ed25519 for use w/ EdDSA only"},
    {7, "OKP", "Ed448",    "Ed448 for use w/ EdDSA only"},
};

static COSEValueTypeNameDesc_t *GetCOSECurveElm(int id) {
    for (size_t i = 0; i < ARRAYLEN(COSECurvesDesc); i++)
        if (COSECurvesDesc[i].Value == id)
            return &COSECurvesDesc[i];
    return NULL;
}

const char *GetCOSECurveDescription(int id) {
    COSEValueTypeNameDesc_t *elm = GetCOSECurveElm(id);
    if (elm)
        return elm->Description;
    return COSEEmptyStr;
}

// RFC8152 https://www.iana.org/assignments/cose/cose.xhtml#algorithms
COSEValueNameDesc_t COSEAlg[] = {
    { -65536,    "Unassigned",               "Unassigned"},
    { -65535,    "RS1",                      "RSASSA-PKCS1-v1_5 w/ SHA-1"},
    { -259,      "RS512",                    "RSASSA-PKCS1-v1_5 w/ SHA-512"},
    { -258,      "RS384",                    "RSASSA-PKCS1-v1_5 w/ SHA-384"},
    { -257,      "RS256",                    "RSASSA-PKCS1-v1_5 w/ SHA-256"},
    { -42,       "RSAES-OAEP w/ SHA-512",    "RSAES-OAEP w/ SHA-512"},
    { -41,       "RSAES-OAEP w/ SHA-256",    "RSAES-OAEP w/ SHA-256"},
    { -40,       "RSAES-OAEP w/ RFC 8017 def param",    "RSAES-OAEP w/ SHA-1"},
    { -39,       "PS512",                    "RSASSA-PSS w/ SHA-512"},
    { -38,       "PS384",                    "RSASSA-PSS w/ SHA-384"},
    { -37,       "PS256",                    "RSASSA-PSS w/ SHA-256"},
    { -36,       "ES512",                    "ECDSA w/ SHA-512"},
    { -35,       "ES384",                    "ECDSA w/ SHA-384"},
    { -34,       "ECDH-SS + A256KW",         "ECDH SS w/ Concat KDF and AES Key Wrap w/ 256-bit key"},
    { -33,       "ECDH-SS + A192KW",         "ECDH SS w/ Concat KDF and AES Key Wrap w/ 192-bit key"},
    { -32,       "ECDH-SS + A128KW",         "ECDH SS w/ Concat KDF and AES Key Wrap w/ 128-bit key"},
    { -31,       "ECDH-ES + A256KW",         "ECDH ES w/ Concat KDF and AES Key Wrap w/ 256-bit key"},
    { -30,       "ECDH-ES + A192KW",         "ECDH ES w/ Concat KDF and AES Key Wrap w/ 192-bit key"},
    { -29,       "ECDH-ES + A128KW",         "ECDH ES w/ Concat KDF and AES Key Wrap w/ 128-bit key"},
    { -28,       "ECDH-SS + HKDF-512",       "ECDH SS w/ HKDF - generate key directly"},
    { -27,       "ECDH-SS + HKDF-256",       "ECDH SS w/ HKDF - generate key directly"},
    { -26,       "ECDH-ES + HKDF-512",       "ECDH ES w/ HKDF - generate key directly"},
    { -25,       "ECDH-ES + HKDF-256",       "ECDH ES w/ HKDF - generate key directly"},
    { -13,       "direct+HKDF-AES-256",      "Shared secret w/ AES-MAC 256-bit key"},
    { -12,       "direct+HKDF-AES-128",      "Shared secret w/ AES-MAC 128-bit key"},
    { -11,       "direct+HKDF-SHA-512",      "Shared secret w/ HKDF and SHA-512"},
    { -10,       "direct+HKDF-SHA-256",      "Shared secret w/ HKDF and SHA-256"},
    { -8,        "EdDSA",                    "EdDSA"},
    { -7,        "ES256",                    "ECDSA w/ SHA-256"},
    { -6,        "direct",                   "Direct use of CEK"},
    { -5,        "A256KW",                   "AES Key Wrap w/ 256-bit key"},
    { -4,        "A192KW",                   "AES Key Wrap w/ 192-bit key"},
    { -3,        "A128KW",                   "AES Key Wrap w/ 128-bit key"},
    {0,         "Reserved",                 "Reserved"},
    {1,         "A128GCM",                  "AES-GCM mode w/ 128-bit key, 128-bit tag"},
    {2,         "A192GCM",                  "AES-GCM mode w/ 192-bit key, 128-bit tag"},
    {3,         "A256GCM",                  "AES-GCM mode w/ 256-bit key, 128-bit tag"},
    {4,         "HMAC 256/64",              "HMAC w/ SHA-256 truncated to 64 bits"},
    {5,         "HMAC 256/256",             "HMAC w/ SHA-256"},
    {6,         "HMAC 384/384",             "HMAC w/ SHA-384"},
    {7,         "HMAC 512/512",             "HMAC w/ SHA-512"},
    {10,        "AES-CCM-16-64-128",        "AES-CCM mode 128-bit key, 64-bit tag, 13-byte nonce"},
    {11,        "AES-CCM-16-64-256",        "AES-CCM mode 256-bit key, 64-bit tag, 13-byte nonce"},
    {12,        "AES-CCM-64-64-128",        "AES-CCM mode 128-bit key, 64-bit tag, 7-byte nonce"},
    {13,        "AES-CCM-64-64-256",        "AES-CCM mode 256-bit key, 64-bit tag, 7-byte nonce"},
    {14,        "AES-MAC 128/64",           "AES-MAC 128-bit key, 64-bit tag"},
    {15,        "AES-MAC 256/64",           "AES-MAC 256-bit key, 64-bit tag"},
    {24,        "ChaCha20/Poly1305",        "ChaCha20/Poly1305 w/ 256-bit key, 128-bit tag"},
    {25,        "AES-MAC 128/128",          "AES-MAC 128-bit key, 128-bit tag"},
    {26,        "AES-MAC 256/128",          "AES-MAC 256-bit key, 128-bit tag"},
    {30,        "AES-CCM-16-128-128",       "AES-CCM mode 128-bit key, 128-bit tag, 13-byte nonce"},
    {31,        "AES-CCM-16-128-256",       "AES-CCM mode 256-bit key, 128-bit tag, 13-byte nonce"},
    {32,        "AES-CCM-64-128-128",       "AES-CCM mode 128-bit key, 128-bit tag, 7-byte nonce"},
    {33,        "AES-CCM-64-128-256",       "AES-CCM mode 256-bit key, 128-bit tag, 7-byte nonce"}
};

static COSEValueNameDesc_t *GetCOSEAlgElm(int id) {
    for (size_t i = 0; i < ARRAYLEN(COSEAlg); i++)
        if (COSEAlg[i].Value == id)
            return &COSEAlg[i];
    return NULL;
}

const char *GetCOSEAlgName(int id) {
    COSEValueNameDesc_t *elm = GetCOSEAlgElm(id);
    if (elm)
        return elm->Name;
    return COSEEmptyStr;
}

const char *GetCOSEAlgDescription(int id) {
    COSEValueNameDesc_t *elm = GetCOSEAlgElm(id);
    if (elm)
        return elm->Description;
    return COSEEmptyStr;
}

int COSEGetECDSAKey(uint8_t *data, size_t datalen, bool verbose, uint8_t *public_key) {
    CborParser parser;
    CborValue map;
    int64_t i64;
    size_t len;

    if (verbose)
        PrintAndLogEx(NORMAL, "----------- CBOR decode ----------------");

    // kty
    int res = CborMapGetKeyById(&parser, &map, data, datalen, 1);
    if (!res) {
        cbor_value_get_int64(&map, &i64);
        if (verbose)
            PrintAndLogEx(SUCCESS, "kty [%lld] %s", (long long)i64, GetCOSEktyDescription(i64));
        if (i64 != 2)
            PrintAndLogEx(ERR, "ERROR: kty must be 2.");
    }

    // algorithm
    res = CborMapGetKeyById(&parser, &map, data, datalen, 3);
    if (!res) {
        cbor_value_get_int64(&map, &i64);
        if (verbose)
            PrintAndLogEx(SUCCESS, "algorithm [%lld] %s", (long long)i64, GetCOSEAlgDescription(i64));
        if (i64 != -7)
            PrintAndLogEx(ERR, "ERROR: algorithm must be -7.");
    }

    // curve
    res = CborMapGetKeyById(&parser, &map, data, datalen, -1);
    if (!res) {
        cbor_value_get_int64(&map, &i64);
        if (verbose)
            PrintAndLogEx(SUCCESS, "curve [%lld] %s", (long long)i64, GetCOSECurveDescription(i64));
        if (i64 != 1)
            PrintAndLogEx(ERR, "ERROR: curve must be 1.");
    }

    // plain key
    public_key[0] = 0x04;

    // x - coordinate
    res = CborMapGetKeyById(&parser, &map, data, datalen, -2);
    if (!res) {
        res = CborGetBinStringValue(&map, &public_key[1], 32, &len);
        cbor_check(res);
        if (verbose)
            PrintAndLogEx(SUCCESS, "x - coordinate [%zu]: %s", len, sprint_hex(&public_key[1], 32));
        if (len != 32)
            PrintAndLogEx(ERR, "ERROR: x - coordinate length must be 32.");
    }

    // y - coordinate
    res = CborMapGetKeyById(&parser, &map, data, datalen, -3);
    if (!res) {
        res = CborGetBinStringValue(&map, &public_key[33], 32, &len);
        cbor_check(res);
        if (verbose)
            PrintAndLogEx(SUCCESS, "y - coordinate [%zu]: %s", len, sprint_hex(&public_key[33], 32));
        if (len != 32)
            PrintAndLogEx(ERR, "ERROR: y - coordinate length must be 32.");
    }

    // d - private key
    res = CborMapGetKeyById(&parser, &map, data, datalen, -4);
    if (!res) {
        uint8_t private_key[128] = {0};
        res = CborGetBinStringValue(&map, private_key, sizeof(private_key), &len);
        cbor_check(res);
        if (verbose)
            PrintAndLogEx(SUCCESS, "d - private key [%zu]: %s", len, sprint_hex(private_key, len));
    }

    if (verbose)
        PrintAndLogEx(NORMAL, "----------- CBOR decode ----------------");

    return 0;
}


