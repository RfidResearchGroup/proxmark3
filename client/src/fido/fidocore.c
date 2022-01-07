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
// FIDO2 authenticators core data and commands
// https://fidoalliance.org/specs/fido-v2.0-id-20180227/fido-client-to-authenticator-protocol-v2.0-id-20180227.html
//-----------------------------------------------------------------------------

#include "fidocore.h"

#include "commonutil.h"  // ARRAYLEN

#include "iso7816/iso7816core.h"
#include "emv/emvjson.h"
#include "cbortools.h"
#include "x509_crt.h"
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "additional_ca.h"
#include "cose.h"
#include "ui.h"
#include "util.h"

typedef struct {
    uint8_t ErrorCode;
    const char *ShortDescription;
    const char *Description;
} fido2Error_t;

fido2Error_t fido2Errors[] = {
    {0xFF, "n/a",                               "n/a"},
    {0x00, "CTAP1_ERR_SUCCESS",                 "Indicates successful response."},
    {0x01, "CTAP1_ERR_INVALID_COMMAND",         "The command is not a valid CTAP command."},
    {0x02, "CTAP1_ERR_INVALID_PARAMETER",       "The command included an invalid parameter."},
    {0x03, "CTAP1_ERR_INVALID_LENGTH",          "Invalid message or item length."},
    {0x04, "CTAP1_ERR_INVALID_SEQ",             "Invalid message sequencing."},
    {0x05, "CTAP1_ERR_TIMEOUT",                 "Message timed out."},
    {0x06, "CTAP1_ERR_CHANNEL_BUSY",            "Channel busy."},
    {0x0A, "CTAP1_ERR_LOCK_REQUIRED",           "Command requires channel lock."},
    {0x0B, "CTAP1_ERR_INVALID_CHANNEL",         "Command not allowed on this cid."},
    {0x10, "CTAP2_ERR_CBOR_PARSING",            "Error while parsing CBOR."},
    {0x11, "CTAP2_ERR_CBOR_UNEXPECTED_TYPE",    "Invalid/unexpected CBOR error."},
    {0x12, "CTAP2_ERR_INVALID_CBOR",            "Error when parsing CBOR."},
    {0x13, "CTAP2_ERR_INVALID_CBOR_TYPE",       "Invalid or unexpected CBOR type."},
    {0x14, "CTAP2_ERR_MISSING_PARAMETER",       "Missing non-optional parameter."},
    {0x15, "CTAP2_ERR_LIMIT_EXCEEDED",          "Limit for number of items exceeded."},
    {0x16, "CTAP2_ERR_UNSUPPORTED_EXTENSION",   "Unsupported extension."},
    {0x17, "CTAP2_ERR_TOO_MANY_ELEMENTS",       "Limit for number of items exceeded."},
    {0x18, "CTAP2_ERR_EXTENSION_NOT_SUPPORTED", "Unsupported extension."},
    {0x19, "CTAP2_ERR_CREDENTIAL_EXCLUDED",     "Valid credential found in the exludeList."},
    {0x20, "CTAP2_ERR_CREDENTIAL_NOT_VALID",    "Credential not valid for authenticator."},
    {0x21, "CTAP2_ERR_PROCESSING",              "Processing (Lengthy operation is in progress)."},
    {0x22, "CTAP2_ERR_INVALID_CREDENTIAL",      "Credential not valid for the authenticator."},
    {0x23, "CTAP2_ERR_USER_ACTION_PENDING",     "Authentication is waiting for user interaction."},
    {0x24, "CTAP2_ERR_OPERATION_PENDING",       "Processing, lengthy operation is in progress."},
    {0x25, "CTAP2_ERR_NO_OPERATIONS",           "No request is pending."},
    {0x26, "CTAP2_ERR_UNSUPPORTED_ALGORITHM",   "Authenticator does not support requested algorithm."},
    {0x27, "CTAP2_ERR_OPERATION_DENIED",        "Not authorized for requested operation."},
    {0x28, "CTAP2_ERR_KEY_STORE_FULL",          "Internal key storage is full."},
    {0x29, "CTAP2_ERR_NOT_BUSY",                "Authenticator cannot cancel as it is not busy."},
    {0x2A, "CTAP2_ERR_NO_OPERATION_PENDING",    "No outstanding operations."},
    {0x2B, "CTAP2_ERR_UNSUPPORTED_OPTION",      "Unsupported option."},
    {0x2C, "CTAP2_ERR_INVALID_OPTION",          "Unsupported option."},
    {0x2D, "CTAP2_ERR_KEEPALIVE_CANCEL",        "Pending keep alive was cancelled."},
    {0x2E, "CTAP2_ERR_NO_CREDENTIALS",          "No valid credentials provided."},
    {0x2F, "CTAP2_ERR_USER_ACTION_TIMEOUT",     "Timeout waiting for user interaction."},
    {0x30, "CTAP2_ERR_NOT_ALLOWED",             "Continuation command, such as, authenticatorGetNextAssertion not allowed."},
    {0x31, "CTAP2_ERR_PIN_INVALID",             "PIN Blocked."},
    {0x32, "CTAP2_ERR_PIN_BLOCKED",             "PIN Blocked."},
    {0x33, "CTAP2_ERR_PIN_AUTH_INVALID",        "PIN authentication,pinAuth, verification failed."},
    {0x34, "CTAP2_ERR_PIN_AUTH_BLOCKED",        "PIN authentication,pinAuth, blocked. Requires power recycle to reset."},
    {0x35, "CTAP2_ERR_PIN_NOT_SET",             "No PIN has been set."},
    {0x36, "CTAP2_ERR_PIN_REQUIRED",            "PIN is required for the selected operation."},
    {0x37, "CTAP2_ERR_PIN_POLICY_VIOLATION",    "PIN policy violation. Currently only enforces minimum length."},
    {0x38, "CTAP2_ERR_PIN_TOKEN_EXPIRED",       "pinToken expired on authenticator."},
    {0x39, "CTAP2_ERR_REQUEST_TOO_LARGE",       "Authenticator cannot handle this request due to memory constraints."},
    {0x7F, "CTAP1_ERR_OTHER",                   "Other unspecified error."},
    {0xDF, "CTAP2_ERR_SPEC_LAST",               "CTAP 2 spec last error."},
};

typedef struct {
    fido2Commands Command;
    fido2PacketType PckType;
    int MemberNumber;
    const char *Description;
} fido2Desc_t;

fido2Desc_t fido2CmdGetInfoRespDesc[] = {
    {fido2CmdMakeCredential,    ptResponse, 0x01, "fmt"},
    {fido2CmdMakeCredential,    ptResponse, 0x02, "authData"},
    {fido2CmdMakeCredential,    ptResponse, 0x03, "attStmt"},

    {fido2CmdMakeCredential,    ptQuery,    0x01, "clientDataHash"},
    {fido2CmdMakeCredential,    ptQuery,    0x02, "rp"},
    {fido2CmdMakeCredential,    ptQuery,    0x03, "user"},
    {fido2CmdMakeCredential,    ptQuery,    0x04, "pubKeyCredParams"},
    {fido2CmdMakeCredential,    ptQuery,    0x05, "excludeList"},
    {fido2CmdMakeCredential,    ptQuery,    0x06, "extensions"},
    {fido2CmdMakeCredential,    ptQuery,    0x07, "options"},
    {fido2CmdMakeCredential,    ptQuery,    0x08, "pinAuth"},
    {fido2CmdMakeCredential,    ptQuery,    0x09, "pinProtocol"},

    {fido2CmdGetAssertion,      ptResponse, 0x01, "credential"},
    {fido2CmdGetAssertion,      ptResponse, 0x02, "authData"},
    {fido2CmdGetAssertion,      ptResponse, 0x03, "signature"},
    {fido2CmdGetAssertion,      ptResponse, 0x04, "publicKeyCredentialUserEntity"},
    {fido2CmdGetAssertion,      ptResponse, 0x05, "numberOfCredentials"},

    {fido2CmdGetAssertion,      ptQuery,    0x01, "rpId"},
    {fido2CmdGetAssertion,      ptQuery,    0x02, "clientDataHash"},
    {fido2CmdGetAssertion,      ptQuery,    0x03, "allowList"},
    {fido2CmdGetAssertion,      ptQuery,    0x04, "extensions"},
    {fido2CmdGetAssertion,      ptQuery,    0x05, "options"},
    {fido2CmdGetAssertion,      ptQuery,    0x06, "pinAuth"},
    {fido2CmdGetAssertion,      ptQuery,    0x07, "pinProtocol"},

    {fido2CmdGetNextAssertion,  ptResponse, 0x01, "credential"},
    {fido2CmdGetNextAssertion,  ptResponse, 0x02, "authData"},
    {fido2CmdGetNextAssertion,  ptResponse, 0x03, "signature"},
    {fido2CmdGetNextAssertion,  ptResponse, 0x04, "publicKeyCredentialUserEntity"},

    {fido2CmdGetInfo,           ptResponse, 0x01, "versions"},
    {fido2CmdGetInfo,           ptResponse, 0x02, "extensions"},
    {fido2CmdGetInfo,           ptResponse, 0x03, "aaguid"},
    {fido2CmdGetInfo,           ptResponse, 0x04, "options"},
    {fido2CmdGetInfo,           ptResponse, 0x05, "maxMsgSize"},
    {fido2CmdGetInfo,           ptResponse, 0x06, "pinProtocols"},

    {fido2CmdClientPIN,         ptResponse, 0x01, "keyAgreement"},
    {fido2CmdClientPIN,         ptResponse, 0x02, "pinToken"},
    {fido2CmdClientPIN,         ptResponse, 0x03, "retries"},

    {fido2CmdClientPIN,         ptQuery,    0x01, "pinProtocol"},
    {fido2CmdClientPIN,         ptQuery,    0x02, "subCommand"},
    {fido2CmdClientPIN,         ptQuery,    0x03, "keyAgreement"},
    {fido2CmdClientPIN,         ptQuery,    0x04, "pinAuth"},
    {fido2CmdClientPIN,         ptQuery,    0x05, "newPinEnc"},
    {fido2CmdClientPIN,         ptQuery,    0x06, "pinHashEnc"},
    {fido2CmdClientPIN,         ptQuery,    0x07, "getKeyAgreement"},
    {fido2CmdClientPIN,         ptQuery,    0x08, "getRetries"},

    {fido2COSEKey,              ptResponse, 0x01, "kty"},
    {fido2COSEKey,              ptResponse, 0x03, "alg"},
    {fido2COSEKey,              ptResponse,   -1, "crv"},
    {fido2COSEKey,              ptResponse,   -2, "x - coordinate"},
    {fido2COSEKey,              ptResponse,   -3, "y - coordinate"},
    {fido2COSEKey,              ptResponse,   -4, "d - private key"},
};

const char *fido2GetCmdErrorDescription(uint8_t errorCode) {
    for (size_t i = 0; i < ARRAYLEN(fido2Errors); i++)
        if (fido2Errors[i].ErrorCode == errorCode)
            return fido2Errors[i].Description;

    return fido2Errors[0].Description;
}

const char *fido2GetCmdMemberDescription(uint8_t cmdCode, bool isResponse, int memberNum) {
    for (size_t i = 0; i < ARRAYLEN(fido2CmdGetInfoRespDesc); i++)
        if (fido2CmdGetInfoRespDesc[i].Command == cmdCode &&
                fido2CmdGetInfoRespDesc[i].PckType == (isResponse ? ptResponse : ptQuery) &&
                fido2CmdGetInfoRespDesc[i].MemberNumber == memberNum)
            return fido2CmdGetInfoRespDesc[i].Description;

    return NULL;
}

int FIDOSelect(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[] = {0xA0, 0x00, 0x00, 0x06, 0x47, 0x2F, 0x00, 0x01};

    return Iso7816Select(CC_CONTACTLESS, ActivateField, LeaveFieldON, data, sizeof(data), Result, MaxResultLen, ResultLen, sw);
}

int FIDOExchange(sAPDU_t apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    int res = Iso7816Exchange(CC_CONTACTLESS, true, apdu, Result, MaxResultLen, ResultLen, sw);
    if (res == 5) // apdu result (sw) not a 0x9000
        res = 0;
    // software chaining
    while (!res && (*sw >> 8) == 0x61) {
        size_t oldlen = *ResultLen;
        res = Iso7816Exchange(CC_CONTACTLESS, true, (sAPDU_t) {0x00, 0xC0, 0x00, 0x00, 0x00, NULL}, &Result[oldlen], MaxResultLen - oldlen, ResultLen, sw);
        if (res == 5) // apdu result (sw) not a 0x9000
            res = 0;

        *ResultLen += oldlen;
        if (*ResultLen > MaxResultLen)
            return 100;
    }
    return res;
}

int FIDORegister(uint8_t *params, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return FIDOExchange((sAPDU_t) {0x00, 0x01, 0x03, 0x00, 64, params}, Result, MaxResultLen, ResultLen, sw);
}

int FIDOAuthentication(uint8_t *params, uint8_t paramslen, uint8_t controlb, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return FIDOExchange((sAPDU_t) {0x00, 0x02, controlb, 0x00, paramslen, params}, Result, MaxResultLen, ResultLen, sw);
}

int FIDO2GetInfo(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[] = {fido2CmdGetInfo};
    return FIDOExchange((sAPDU_t) {0x80, 0x10, 0x00, 0x00, sizeof(data), data}, Result, MaxResultLen, ResultLen, sw);
}

int FIDO2MakeCredential(uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[paramslen + 1];
    data[0] = fido2CmdMakeCredential;
    memcpy(&data[1], params, paramslen);
    return FIDOExchange((sAPDU_t) {0x80, 0x10, 0x00, 0x00, sizeof(data), data}, Result, MaxResultLen, ResultLen, sw);
}

int FIDO2GetAssertion(uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[paramslen + 1];
    data[0] = fido2CmdGetAssertion;
    memcpy(&data[1], params, paramslen);
    return FIDOExchange((sAPDU_t) {0x80, 0x10, 0x00, 0x00, sizeof(data), data}, Result, MaxResultLen, ResultLen, sw);
}

int FIDOCheckDERAndGetKey(uint8_t *der, size_t derLen, bool verbose, uint8_t *publicKey, size_t publicKeyMaxLen) {
    int res;

    // load CA's
    mbedtls_x509_crt cacert;
    mbedtls_x509_crt_init(&cacert);
    res = mbedtls_x509_crt_parse(&cacert, (const unsigned char *) additional_ca_pem, additional_ca_pem_len);
    if (res < 0) {
        PrintAndLogEx(ERR, "ERROR: CA parse certificate returned -0x%x - %s", -res, ecdsa_get_error(res));
    }
    if (verbose)
        PrintAndLogEx(SUCCESS, "CA load OK. %d skipped", res);

    // load DER certificate from authenticator's data
    mbedtls_x509_crt cert;
    mbedtls_x509_crt_init(&cert);
    res = mbedtls_x509_crt_parse_der(&cert, der, derLen);
    if (res) {
        PrintAndLogEx(ERR, "ERROR: DER parse returned 0x%x - %s", (res < 0) ? -res : res, ecdsa_get_error(res));
    }

    // get certificate info
    char linfo[300] = {0};
    if (verbose) {
        mbedtls_x509_crt_info(linfo, sizeof(linfo), "  ", &cert);
        PrintAndLogEx(SUCCESS, "DER certificate info:\n%s", linfo);
    }

    // verify certificate
    uint32_t verifyflags = 0;
    res = mbedtls_x509_crt_verify(&cert, &cacert, NULL, NULL, &verifyflags, NULL, NULL);
    if (res) {
        PrintAndLogEx(ERR, "ERROR: DER verify returned 0x%x - %s\n", (res < 0) ? -res : res, ecdsa_get_error(res));
    } else {
        PrintAndLogEx(SUCCESS, "Certificate ( " _GREEN_("ok") " )\n");
    }

    if (verbose) {
        memset(linfo, 0x00, sizeof(linfo));
        mbedtls_x509_crt_verify_info(linfo, sizeof(linfo), "  ", verifyflags);
        PrintAndLogEx(SUCCESS, "Verification info:\n%s", linfo);
    }

    // get public key
    res = ecdsa_public_key_from_pk(&cert.pk, MBEDTLS_ECP_DP_SECP256R1, publicKey, publicKeyMaxLen);
    if (res) {
        PrintAndLogEx(ERR, "ERROR: getting public key from certificate 0x%x - %s", (res < 0) ? -res : res, ecdsa_get_error(res));
    } else {
        if (verbose)
            PrintAndLogEx(SUCCESS, "Got a public key from certificate:\n%s", sprint_hex_inrow(publicKey, 65));
    }

    if (verbose)
        PrintAndLogEx(INFO, "------------------DER-------------------");

    mbedtls_x509_crt_free(&cert);
    mbedtls_x509_crt_free(&cacert);

    return 0;
}

#define fido_check_if(r) if ((r) != CborNoError) {return r;} else
#define fido_check(r) if ((r) != CborNoError) return r;

int FIDO2CreateMakeCredentionalReq(json_t *root, uint8_t *data, size_t maxdatalen, size_t *datalen) {
    if (datalen)
        *datalen = 0;
    if (!root || !data || !maxdatalen)
        return 1;

    int res;
    CborEncoder encoder;
    CborEncoder map;

    cbor_encoder_init(&encoder, data, maxdatalen, 0);

    // create main map
    res = cbor_encoder_create_map(&encoder, &map, 5);
    fido_check_if(res) {
        // clientDataHash
        res = cbor_encode_uint(&map, 1);
        fido_check_if(res) {
            res = CBOREncodeClientDataHash(root, &map);
            fido_check(res);
        }

        // rp
        res = cbor_encode_uint(&map, 2);
        fido_check_if(res) {
            res = CBOREncodeElm(root, "RelyingPartyEntity", &map);
            fido_check(res);
        }

        // user
        res = cbor_encode_uint(&map, 3);
        fido_check_if(res) {
            res = CBOREncodeElm(root, "UserEntity", &map);
            fido_check(res);
        }

        // pubKeyCredParams
        res = cbor_encode_uint(&map, 4);
        fido_check_if(res) {
            res = CBOREncodeElm(root, "pubKeyCredParams", &map);
            fido_check(res);
        }

        // options
        res = cbor_encode_uint(&map, 7);
        fido_check_if(res) {
            res = CBOREncodeElm(root, "MakeCredentialOptions", &map);
            fido_check(res);
        }
    }
    res = cbor_encoder_close_container(&encoder, &map);
    fido_check(res);

    size_t len = cbor_encoder_get_buffer_size(&encoder, data);
    if (datalen)
        *datalen = len;

    return 0;
}

bool CheckrpIdHash(json_t *json, uint8_t *hash) {
    char hashval[300] = {0};
    uint8_t hash2[32] = {0};

    JsonLoadStr(json, "$.RelyingPartyEntity.id", hashval);
    int res = sha256hash((uint8_t *)hashval, strlen(hashval), hash2);
    if (res)
        return false;

    return !memcmp(hash, hash2, 32);
}

// check ANSI X9.62 format ECDSA signature (on P-256)
static int FIDO2CheckSignature(json_t *root, uint8_t *publickey, uint8_t *sign, size_t signLen, uint8_t *authData, size_t authDataLen, bool verbose) {

    uint8_t rval[300] = {0};
    uint8_t sval[300] = {0};

    int res = ecdsa_asn1_get_signature(sign, signLen, rval, sval);
    if (res == PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(INFO, "  r: %s", sprint_hex(rval, 32));
            PrintAndLogEx(INFO, "  s: %s", sprint_hex(sval, 32));
        }

        uint8_t clientDataHash[32] = {0};
        size_t clientDataHashLen = 0;
        res = JsonLoadBufAsHex(root, "$.ClientDataHash", clientDataHash, sizeof(clientDataHash), &clientDataHashLen);
        if (res || clientDataHashLen != 32) {
            PrintAndLogEx(ERR, "ERROR: Can't get clientDataHash from json!");
            return 2;
        }

        uint8_t xbuf[4096] = {0};
        size_t xbuflen = 0;
        res = FillBuffer(xbuf, sizeof(xbuf), &xbuflen,
                         authData, authDataLen,  // rpIdHash[32] + flags[1] + signCount[4]
                         clientDataHash, 32,     // Hash of the serialized client data. "$.ClientDataHash" from json
                         NULL, 0);
        PrintAndLogEx(DEBUG, "--xbuf(%d)[%zu]: %s", res, xbuflen, sprint_hex(xbuf, xbuflen));

        res = ecdsa_signature_verify(MBEDTLS_ECP_DP_SECP256R1, publickey, xbuf, xbuflen, sign, signLen, true);
        if (res) {
            if (res == MBEDTLS_ERR_ECP_VERIFY_FAILED) {
                PrintAndLogEx(WARNING, "Signature is ( " _RED_("not valid") " )");
            } else {
                PrintAndLogEx(WARNING, "Other signature check error: %x %s", (res < 0) ? -res : res, ecdsa_get_error(res));
            }
            return res;
        } else {
            PrintAndLogEx(SUCCESS, "Signature is ( " _GREEN_("ok") " )");
        }
    } else {
        PrintAndLogEx(ERR, "Invalid signature. res = %d.", res);
        return res;
    }

    return 0;
}

int FIDO2MakeCredentionalParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool verbose2, bool showCBOR, bool showDERTLV) {
    CborParser parser;
    CborValue map, mapsmt;
    int res;
    char *buf;
    uint8_t *ubuf;
    size_t n;

    // fmt
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 1);
    if (res)
        return res;

    res = cbor_value_dup_text_string(&map, &buf, &n, &map);
    cbor_check(res);
    PrintAndLogEx(INFO, "format: %s", buf);
    free(buf);

    // authData
    uint8_t authData[400] = {0};
    size_t authDataLen = 0;
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 2);
    if (res)
        return res;
    res = cbor_value_dup_byte_string(&map, &ubuf, &n, &map);
    cbor_check(res);

    authDataLen = n;
    memcpy(authData, ubuf, authDataLen);

    if (verbose2) {
        PrintAndLogEx(INFO, "authData[%zu]: %s", n, sprint_hex_inrow(authData, authDataLen));
    } else {
        PrintAndLogEx(INFO, "authData[%zu]: %s...", n, sprint_hex(authData, MIN(authDataLen, 16)));
    }

    PrintAndLogEx(INFO, "RP ID Hash: %s", sprint_hex(ubuf, 32));

    // check RP ID Hash
    if (CheckrpIdHash(root, ubuf)) {
        PrintAndLogEx(SUCCESS, "rpIdHash ( " _GREEN_("ok")" )");
    } else {
        PrintAndLogEx(ERR, "rpIdHash " _RED_("ERROR!!"));
    }

    PrintAndLogEx(INFO, "Flags 0x%02x:", ubuf[32]);
    if (!ubuf[32])
        PrintAndLogEx(SUCCESS, "none");
    if (ubuf[32] & 0x01)
        PrintAndLogEx(SUCCESS, "up - user presence result");
    if (ubuf[32] & 0x04)
        PrintAndLogEx(SUCCESS, "uv - user verification (fingerprint scan or a PIN or ...) result");
    if (ubuf[32] & 0x40)
        PrintAndLogEx(SUCCESS, "at - attested credential data included");
    if (ubuf[32] & 0x80)
        PrintAndLogEx(SUCCESS, "ed - extension data included");

    uint32_t cntr = (uint32_t)bytes_to_num(&ubuf[33], 4);
    PrintAndLogEx(SUCCESS, "Counter: %d", cntr);
    JsonSaveInt(root, "$.AppData.Counter", cntr);

    // attestation data
    PrintAndLogEx(SUCCESS, "AAGUID: %s", sprint_hex(&ubuf[37], 16));
    JsonSaveBufAsHexCompact(root, "$.AppData.AAGUID", &ubuf[37], 16);

    // Credential ID
    uint8_t cridlen = (uint16_t)bytes_to_num(&ubuf[53], 2);
    PrintAndLogEx(SUCCESS, "Credential id[%d]: %s", cridlen, sprint_hex_inrow(&ubuf[55], cridlen));
    JsonSaveInt(root, "$.AppData.CredentialIdLen", cridlen);
    JsonSaveBufAsHexCompact(root, "$.AppData.CredentialId", &ubuf[55], cridlen);

    //Credentional public key (COSE_KEY)
    uint8_t coseKey[65] = {0};
    uint16_t cplen = n - 55 - cridlen;
    if (verbose2) {
        PrintAndLogEx(SUCCESS, "Credentional public key (COSE_KEY)[%d]: %s", cplen, sprint_hex_inrow(&ubuf[55 + cridlen], cplen));
    } else {
        PrintAndLogEx(SUCCESS, "Credentional public key (COSE_KEY)[%d]: %s...", cplen, sprint_hex(&ubuf[55 + cridlen], MIN(cplen, 16)));
    }
    JsonSaveBufAsHexCompact(root, "$.AppData.COSE_KEY", &ubuf[55 + cridlen], cplen);

    if (showCBOR) {
        PrintAndLogEx(INFO, "COSE structure:");
        PrintAndLogEx(INFO, "---------------- CBOR ------------------");
        TinyCborPrintFIDOPackage(fido2COSEKey, true, &ubuf[55 + cridlen], cplen);
        PrintAndLogEx(INFO, "---------------- CBOR ------------------");
    }

    res = COSEGetECDSAKey(&ubuf[55 + cridlen], cplen, verbose, coseKey);
    if (res) {
        PrintAndLogEx(ERR, "ERROR: Can't get COSE_KEY.");
    } else {
        PrintAndLogEx(SUCCESS, "COSE public key: %s", sprint_hex_inrow(coseKey, sizeof(coseKey)));
        JsonSaveBufAsHexCompact(root, "$.AppData.COSEPublicKey", coseKey, sizeof(coseKey));
    }

    free(ubuf);

    // attStmt - we are check only as DER certificate
    int64_t alg = 0;
    uint8_t sign[128] = {0};
    size_t signLen = 0;
    uint8_t der[4097] = {0};
    size_t derLen = 0;

    res = CborMapGetKeyById(&parser, &map, data, dataLen, 3);
    if (res)
        return res;

    res = cbor_value_enter_container(&map, &mapsmt);
    cbor_check(res);

    while (!cbor_value_at_end(&mapsmt)) {
        char key[100] = {0};
        res = CborGetStringValue(&mapsmt, key, sizeof(key), &n);
        cbor_check(res);
        if (!strcmp(key, "alg")) {
            cbor_value_get_int64(&mapsmt, &alg);
            PrintAndLogEx(INFO, "Alg [%lld] %s", (long long)alg, GetCOSEAlgDescription(alg));
            res = cbor_value_advance_fixed(&mapsmt);
            cbor_check(res);
        }

        if (!strcmp(key, "sig")) {
            res = CborGetBinStringValue(&mapsmt, sign, sizeof(sign), &signLen);
            cbor_check(res);
            if (verbose2) {
                PrintAndLogEx(INFO, "signature [%zu]: %s", signLen, sprint_hex_inrow(sign, signLen));
            } else {
                PrintAndLogEx(INFO, "signature [%zu]: %s...", signLen, sprint_hex(sign, MIN(signLen, 16)));
            }
        }

        if (!strcmp(key, "x5c")) {
            res = CborGetArrayBinStringValue(&mapsmt, der, sizeof(der), &derLen);
            cbor_check(res);
            if (verbose2) {
                PrintAndLogEx(INFO, "DER certificate[%zu]:", derLen);
                PrintAndLogEx(INFO, "------------------DER-------------------");
                PrintAndLogEx(INFO, "%s", sprint_hex(der, derLen));
                PrintAndLogEx(INFO, "----------------DER---------------------");
            } else {
                PrintAndLogEx(INFO, "DER [%zu]: %s...", derLen, sprint_hex(der, MIN(derLen, 16)));
            }
            JsonSaveBufAsHexCompact(root, "$.AppData.DER", der, derLen);
        }
    }
    res = cbor_value_leave_container(&map, &mapsmt);
    cbor_check(res);

    uint8_t public_key[65] = {0};

    // print DER certificate in TLV view
    if (showDERTLV) {
        PrintAndLogEx(INFO, "----------------DER TLV-----------------");
        asn1_print(der, derLen, "  ");
        PrintAndLogEx(INFO, "----------------DER TLV-----------------");
    }
    FIDOCheckDERAndGetKey(der, derLen, verbose, public_key, sizeof(public_key));
    JsonSaveBufAsHexCompact(root, "$.AppData.DERPublicKey", public_key, sizeof(public_key));

    // check ANSI X9.62 format ECDSA signature (on P-256)
    FIDO2CheckSignature(root, public_key, sign, signLen, authData, authDataLen, verbose);

    return 0;
}

int FIDO2CreateGetAssertionReq(json_t *root, uint8_t *data, size_t maxdatalen, size_t *datalen, bool createAllowList) {
    if (datalen)
        *datalen = 0;
    if (!root || !data || !maxdatalen)
        return 1;

    int res;
    CborEncoder encoder;
    CborEncoder map, array, mapint;

    cbor_encoder_init(&encoder, data, maxdatalen, 0);

    // create main map
    res = cbor_encoder_create_map(&encoder, &map, createAllowList ? 4 : 3);
    fido_check_if(res) {
        // rpId
        res = cbor_encode_uint(&map, 1);
        fido_check_if(res) {
            res = CBOREncodeElm(root, "$.RelyingPartyEntity.id", &map);
            fido_check(res);
        }

        // clientDataHash
        res = cbor_encode_uint(&map, 2);
        fido_check_if(res) {
            res = CBOREncodeClientDataHash(root, &map);
            fido_check(res);
        }

        // allowList
        if (createAllowList) {
            res = cbor_encode_uint(&map, 3);
            fido_check_if(res) {
                res = cbor_encoder_create_array(&map, &array, 1);
                fido_check_if(res) {
                    res = cbor_encoder_create_map(&array, &mapint, 2);
                    fido_check_if(res) {
                        res = cbor_encode_text_stringz(&mapint, "type");
                        fido_check(res);

                        res = cbor_encode_text_stringz(&mapint, "public-key");
                        fido_check(res);

                        res = cbor_encode_text_stringz(&mapint, "id");
                        fido_check(res);

                        res = CBOREncodeElm(root, "$.AppData.CredentialId", &mapint);
                        fido_check(res);
                    }
                    res = cbor_encoder_close_container(&array, &mapint);
                    fido_check(res);
                }
                res = cbor_encoder_close_container(&map, &array);
                fido_check(res);
            }
        }

        // options
        res = cbor_encode_uint(&map, 5);
        fido_check_if(res) {
            res = CBOREncodeElm(root, "GetAssertionOptions", &map);
            fido_check(res);
        }
    }
    res = cbor_encoder_close_container(&encoder, &map);
    fido_check(res);

    size_t len = cbor_encoder_get_buffer_size(&encoder, data);
    if (datalen)
        *datalen = len;

    return 0;
}

int FIDO2GetAssertionParseRes(json_t *root, uint8_t *data, size_t dataLen, bool verbose, bool verbose2, bool showCBOR) {
    CborParser parser;
    CborValue map, mapint;
    int res;
    uint8_t *ubuf;
    size_t n;

    // credential
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 1);
    if (res)
        return res;

    res = cbor_value_enter_container(&map, &mapint);
    cbor_check(res);

    while (!cbor_value_at_end(&mapint)) {
        char key[100] = {0};
        res = CborGetStringValue(&mapint, key, sizeof(key), &n);
        cbor_check(res);

        if (!strcmp(key, "type")) {
            char ctype[200] = {0};
            res = CborGetStringValue(&mapint, ctype, sizeof(ctype), &n);
            cbor_check(res);
            PrintAndLogEx(SUCCESS, "credential type: %s", ctype);
        }

        if (!strcmp(key, "id")) {
            uint8_t cid[200] = {0};
            res = CborGetBinStringValue(&mapint, cid, sizeof(cid), &n);
            cbor_check(res);
            PrintAndLogEx(SUCCESS, "credential id [%zu]: %s", n, sprint_hex(cid, n));
        }
    }
    res = cbor_value_leave_container(&map, &mapint);
    cbor_check(res);

    // authData
    uint8_t authData[400] = {0};
    size_t authDataLen = 0;
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 2);
    if (res)
        return res;
    res = cbor_value_dup_byte_string(&map, &ubuf, &n, &map);
    cbor_check(res);

    authDataLen = n;
    memcpy(authData, ubuf, authDataLen);

    if (verbose2) {
        PrintAndLogEx(INFO, "authData[%zu]: %s", n, sprint_hex_inrow(authData, authDataLen));
    } else {
        PrintAndLogEx(INFO, "authData[%zu]: %s...", n, sprint_hex(authData, MIN(authDataLen, 16)));
    }

    PrintAndLogEx(INFO, "RP ID Hash: %s", sprint_hex(ubuf, 32));

    // check RP ID Hash
    if (CheckrpIdHash(root, ubuf)) {
        PrintAndLogEx(SUCCESS, "rpIdHash ( " _GREEN_("ok")" )");
    } else {
        PrintAndLogEx(ERR, "rpIdHash " _RED_("ERROR!!"));
    }

    PrintAndLogEx(INFO, "Flags 0x%02x:", ubuf[32]);
    if (!ubuf[32])
        PrintAndLogEx(SUCCESS, "none");
    if (ubuf[32] & 0x01)
        PrintAndLogEx(SUCCESS, "up - user presence result");
    if (ubuf[32] & 0x04)
        PrintAndLogEx(SUCCESS, "uv - user verification (fingerprint scan or a PIN or ...) result");
    if (ubuf[32] & 0x40)
        PrintAndLogEx(SUCCESS, "at - attested credential data included");
    if (ubuf[32] & 0x80)
        PrintAndLogEx(SUCCESS, "ed - extension data included");

    uint32_t cntr = (uint32_t)bytes_to_num(&ubuf[33], 4);
    PrintAndLogEx(SUCCESS, "Counter: %d", cntr);
    JsonSaveInt(root, "$.AppData.Counter", cntr);

    free(ubuf);

    // publicKeyCredentialUserEntity
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 4);
    if (res) {
        PrintAndLogEx(SUCCESS, "UserEntity n/a");
    } else {
        res = cbor_value_enter_container(&map, &mapint);
        cbor_check(res);

        while (!cbor_value_at_end(&mapint)) {
            char key[100] = {0};
            res = CborGetStringValue(&mapint, key, sizeof(key), &n);
            cbor_check(res);

            if (!strcmp(key, "name") || !strcmp(key, "displayName")) {
                char cname[200] = {0};
                res = CborGetStringValue(&mapint, cname, sizeof(cname), &n);
                cbor_check(res);
                PrintAndLogEx(SUCCESS, "UserEntity %s: %s", key, cname);
            }

            if (!strcmp(key, "id")) {
                uint8_t cid[200] = {0};
                res = CborGetBinStringValue(&mapint, cid, sizeof(cid), &n);
                cbor_check(res);
                PrintAndLogEx(SUCCESS, "UserEntity id [%zu]: %s", n, sprint_hex(cid, n));

                // check
                uint8_t idbuf[100] = {0};
                size_t idbuflen;

                JsonLoadBufAsHex(root, "$.UserEntity.id", idbuf, sizeof(idbuf), &idbuflen);

                if (idbuflen == n && !memcmp(idbuf, cid, idbuflen)) {
                    PrintAndLogEx(SUCCESS, "UserEntity id ( " _GREEN_("ok") " )");
                } else {
                    PrintAndLogEx(ERR, "ERROR: Wrong UserEntity id (from json: %s)", sprint_hex(idbuf, idbuflen));
                }
            }
        }
        res = cbor_value_leave_container(&map, &mapint);
        cbor_check(res);
    }


    // signature
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 3);
    if (res)
        return res;
    res = cbor_value_dup_byte_string(&map, &ubuf, &n, &map);
    cbor_check(res);

    uint8_t *sign = ubuf;
    size_t signLen = n;

    cbor_check(res);
    if (verbose2) {
        PrintAndLogEx(SUCCESS, "signature [%zu]: %s", signLen, sprint_hex_inrow(sign, signLen));
    } else {
        PrintAndLogEx(SUCCESS, "signature [%zu]: %s...", signLen, sprint_hex(sign, MIN(signLen, 16)));
    }

    // get public key from json
    uint8_t PublicKey[65] = {0};
    size_t PublicKeyLen = 0;
    JsonLoadBufAsHex(root, "$.AppData.COSEPublicKey", PublicKey, 65, &PublicKeyLen);

    // check ANSI X9.62 format ECDSA signature (on P-256)
    FIDO2CheckSignature(root, PublicKey, sign, signLen, authData, authDataLen, verbose);

    free(ubuf);

    // numberOfCredentials
    res = CborMapGetKeyById(&parser, &map, data, dataLen, 5);
    if (res) {
        PrintAndLogEx(SUCCESS, "numberOfCredentials: 1 by default");
    } else {
        int64_t numberOfCredentials = 0;
        cbor_value_get_int64(&map, &numberOfCredentials);
        PrintAndLogEx(SUCCESS, "numberOfCredentials: %lld", (long long)numberOfCredentials);
    }

    return 0;
}
