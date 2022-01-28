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
// NFC Data Exchange Format (NDEF) functions
//-----------------------------------------------------------------------------

#include "ndef.h"

#include <string.h>
#include <stdlib.h>

#include "ui.h"
#include "util.h"                // sprint_hex
#include "crypto/asn1utils.h"
#include "crypto/libpcrypto.h"
#include "ecp.h"
#include "commonutil.h"         // ARRAYLEN
#include "pm3_cmd.h"
#include "proxgui.h"            // Base64 Picture Window

#define STRBOOL(p) ((p) ? "1" : "0")

#define NDEF_WIFIAPPL   "application/vnd.wfa"
#define NDEF_BLUEAPPL   "application/vnd.bluetooth"
#define NDEF_JSONAPPL   "application/json"
#define NDEF_VCARDTEXT  "text/vcard"
#define NDEF_XVCARDTEXT "text/x-vcard"


static const char *TypeNameFormat_s[] = {
    "Empty Record",
    "Well Known Record",
    "MIME Media Record",
    "Absolute URI Record",
    "External Record",
    "Unknown Record",
    "Unchanged Record",
    "n/a"
};

static const char *ndefSigType_s[] = {
    "Not present",                   // No signature present
    "RSASSA_PSS_SHA_1 (1024)",              // PKCS_1
    "RSASSA_PKCS1_v1_5_WITH_SHA_1 (1024)",  // PKCS_1
    "DSA-1024",
    "ECDSA-P192",
    "RSASSA-PSS-2048",
    "RSASSA-PKCS1-v1_5-2048",
    "DSA-2048",
    "ECDSA-P224",
    "ECDSA-K233",
    "ECDSA-B233",
    "ECDSA-P256",
    "n/a"
};

static const char *ndefCertificateFormat_s[] = {
    "X_509",
    "X9_68 (M2M)",
    "n/a"
};

static const char *URI_s[] = {
    "",                           // 0x00
    "http://www.",                // 0x01
    "https://www.",               // 0x02
    "http://",                    // 0x03
    "https://",                   // 0x04
    "tel:",                       // 0x05
    "mailto:",                    // 0x06
    "ftp://anonymous:anonymous@", // 0x07
    "ftp://ftp.",                 // 0x08
    "ftps://",                    // 0x09
    "sftp://",                    // 0x0A
    "smb://",                     // 0x0B
    "nfs://",                     // 0x0C
    "ftp://",                     // 0x0D
    "dav://",                     // 0x0E
    "news:",                      // 0x0F
    "telnet://",                  // 0x10
    "imap:",                      // 0x11
    "rtsp://",                    // 0x12
    "urn:",                       // 0x13
    "pop:",                       // 0x14
    "sip:",                       // 0x15
    "sips:",                      // 0x16
    "tftp:",                      // 0x17
    "btspp://",                   // 0x18
    "btl2cap://",                 // 0x19
    "btgoep://",                  // 0x1A
    "tcpobex://",                 // 0x1B
    "irdaobex://",                // 0x1C
    "file://",                    // 0x1D
    "urn:epc:id:",                // 0x1E
    "urn:epc:tag:",               // 0x1F
    "urn:epc:pat:",               // 0x20
    "urn:epc:raw:",               // 0x21
    "urn:epc:",                   // 0x22
    "urn:nfc:"                    // 0x23
};

static int ndefRecordDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen);
static int ndefDecodePayload(NDEFHeader_t *ndef);

static uint16_t ndefTLVGetLength(const uint8_t *data, size_t *indx) {
    uint16_t len = 0;
    if (data[0] == 0xff) {
        len = (data[1] << 8) + data[2];
        *indx += 3;
    } else {
        len = data[0];
        *indx += 1;
    }

    return len;
}

static int ndefDecodeHeader(uint8_t *data, size_t datalen, NDEFHeader_t *header) {
    header->Type = NULL;
    header->Payload = NULL;
    header->ID = NULL;

    header->MessageBegin    = data[0] & 0x80;
    header->MessageEnd      = data[0] & 0x40;
    header->ChunkFlag       = data[0] & 0x20;
    header->ShortRecordBit  = data[0] & 0x10;
    header->IDLenPresent    = data[0] & 0x08;
    header->TypeNameFormat  = data[0] & 0x07;
    header->len             = 1 + 1 + (header->ShortRecordBit ? 1 : 4) + (header->IDLenPresent ? 1 : 0); // header + typelen + payloadlen + idlen
    if (header->len > datalen)
        return PM3_ESOFT;

    header->TypeLen = data[1];
    header->Type = data + header->len;

    header->PayloadLen = (header->ShortRecordBit ? (data[2]) : ((data[2] << 24) + (data[3] << 16) + (data[4] << 8) + data[5]));

    if (header->IDLenPresent) {
        header->IDLen = (header->ShortRecordBit ? (data[3]) : (data[6]));
        header->ID = data + header->len + header->TypeLen;
    } else {
        header->IDLen = 0;
    }

    header->Payload = header->Type + header->TypeLen + header->IDLen;

    header->RecLen = header->len + header->TypeLen + header->PayloadLen + header->IDLen;

    if (header->RecLen > datalen)
        return PM3_ESOFT;

    return PM3_SUCCESS;
}

static int ndefPrintHeader(NDEFHeader_t *header) {
    PrintAndLogEx(INFO, _CYAN_("Header info"));

    PrintAndLogEx(SUCCESS, "  %s ....... Message begin", STRBOOL(header->MessageBegin));
    PrintAndLogEx(SUCCESS, "   %s ...... Message end", STRBOOL(header->MessageEnd));
    PrintAndLogEx(SUCCESS, "    %s ..... Chunk flag", STRBOOL(header->ChunkFlag));
    PrintAndLogEx(SUCCESS, "     %s .... Short record bit", STRBOOL(header->ShortRecordBit));
    PrintAndLogEx(SUCCESS, "      %s ... ID Len present", STRBOOL(header->IDLenPresent));
    PrintAndLogEx(SUCCESS, "");

    PrintAndLogEx(SUCCESS, " Header length...... %zu", header->len);
    PrintAndLogEx(SUCCESS, " Type length........ %zu", header->TypeLen);
    PrintAndLogEx(SUCCESS, " Payload length..... %zu", header->PayloadLen);
    PrintAndLogEx(SUCCESS, " ID length.......... %zu", header->IDLen);
    PrintAndLogEx(SUCCESS, " Record length...... %zu", header->RecLen);

    PrintAndLogEx(SUCCESS, " Type name format... [ 0x%02x ] " _YELLOW_("%s"), header->TypeNameFormat, TypeNameFormat_s[header->TypeNameFormat]);
    return PM3_SUCCESS;
}

static const char *get_curve_name(mbedtls_ecp_group_id grp_id) {
    switch (grp_id) {
        case MBEDTLS_ECP_DP_NONE:
            return "";
        case MBEDTLS_ECP_DP_SECP192R1:
            return "SECP192R1";     // Domain parameters for the 192-bit curve defined by FIPS 186-4 and SEC1
        case MBEDTLS_ECP_DP_SECP224R1:
            return "SECP224R1";     // Domain parameters for the 224-bit curve defined by FIPS 186-4 and SEC1
        case MBEDTLS_ECP_DP_SECP256R1:
            return "SECP256R1";     // Domain parameters for the 256-bit curve defined by FIPS 186-4 and SEC1
        case MBEDTLS_ECP_DP_SECP384R1:
            return "SECP384R1";     // Domain parameters for the 384-bit curve defined by FIPS 186-4 and SEC1
        case MBEDTLS_ECP_DP_SECP521R1:
            return "SECP521R1";     // Domain parameters for the 521-bit curve defined by FIPS 186-4 and SEC1
        case MBEDTLS_ECP_DP_BP256R1:
            return "BP256R1";         // Domain parameters for 256-bit Brainpool curve
        case MBEDTLS_ECP_DP_BP384R1:
            return "BP384R1";         // Domain parameters for 384-bit Brainpool curve
        case MBEDTLS_ECP_DP_BP512R1:
            return "BP512R1";         // Domain parameters for 512-bit Brainpool curve
        case MBEDTLS_ECP_DP_CURVE25519:
            return "CURVE25519";   // Domain parameters for Curve25519
        case MBEDTLS_ECP_DP_SECP192K1:
            return "SECP192K1";     // Domain parameters for 192-bit "Koblitz" curve
        case MBEDTLS_ECP_DP_SECP224K1:
            return "SECP224K1";     // Domain parameters for 224-bit "Koblitz" curve
        case MBEDTLS_ECP_DP_SECP256K1:
            return "SECP256K1";     // Domain parameters for 256-bit "Koblitz" curve
        case MBEDTLS_ECP_DP_CURVE448:
            return "CURVE448";       // Domain parameters for Curve448
        case MBEDTLS_ECP_DP_SECP128R1:
            return "SECP128R1";     // Domain parameters for the 128-bit curve used for NXP originality check
        default :
            return "";
    }
    return "";
}

typedef struct {
    mbedtls_ecp_group_id grp_id;
    uint8_t keylen;
    const char *desc;
    const char *value;
} ndef_publickey_t;

static int ndef_print_signature(uint8_t *data, uint8_t data_len, uint8_t *signature, uint8_t sign_len) {

    const ndef_publickey_t ndef_public_keys[] = {
        { MBEDTLS_ECP_DP_SECP256R1, 65, "Minecraft Earth", "04760200b60315f31ff7951d0892b87930c34967dfbf57763afc775fc56a22b601f7b8fd9e47519524505322435b07d0782463f39400a39a9dbc06bab2225c082a"},
    };

    uint8_t i;
    int reason = 0;
    bool is_valid = false;
    for (i = 0; i < ARRAYLEN(ndef_public_keys); i++) {

        int dl = 0;
        uint8_t key[ndef_public_keys[i].keylen];
        param_gethex_to_eol(ndef_public_keys[i].value, 0, key, ndef_public_keys[i].keylen, &dl);

        int res = ecdsa_signature_r_s_verify(ndef_public_keys[i].grp_id, key, data, data_len, signature, sign_len, false);
        is_valid = (res == 0);
        if (is_valid) {
            reason = 1;
            break;
        }

        // try with sha256
        res = ecdsa_signature_r_s_verify(ndef_public_keys[i].grp_id, key, data, data_len, signature, sign_len, true);
        is_valid = (res == 0);
        if (is_valid) {
            reason = 2;
            break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("NDEF Signature"));
    if (is_valid == false || i == ARRAYLEN(ndef_public_keys)) {
        PrintAndLogEx(INFO, "               NDEF Signature: %s", sprint_hex_inrow(signature, 32));
        PrintAndLogEx(SUCCESS, "       Signature verification: " _RED_("failed"));
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, " IC signature public key name: %s", ndef_public_keys[i].desc);
    PrintAndLogEx(INFO, "IC signature public key value: %s", ndef_public_keys[i].value);
    PrintAndLogEx(INFO, "    Elliptic curve parameters: %s", get_curve_name(ndef_public_keys[i].grp_id));
    PrintAndLogEx(INFO, "               NDEF Signature: %s", sprint_hex_inrow(signature, 32));
    PrintAndLogEx(SUCCESS, "       Signature verification: " _GREEN_("successful"));
    switch (reason) {
        case 1:
            PrintAndLogEx(INFO, "                  Params used: signature, plain");
            break;
        case 2:
            PrintAndLogEx(INFO, "                  Params used: signature, SHA256");
            break;
    }
    return PM3_SUCCESS;
}

static int ndefDecodeSig1(uint8_t *sig, size_t siglen) {
    size_t indx = 1;

    uint8_t sigType = sig[indx] & 0x7f;
    bool sigURI = sig[indx] & 0x80;

    PrintAndLogEx(SUCCESS, "\tsignature type: %s", ((sigType < stNA) ? ndefSigType_s[sigType] : ndefSigType_s[stNA]));
    PrintAndLogEx(SUCCESS, "\tsignature uri: %s", (sigURI ? "present" : "not present"));

    size_t intsiglen = (sig[indx + 1] << 8) + sig[indx + 2];
    // ecdsa 0x04
    if (sigType == stECDSA_P192 || sigType == stECDSA_P256) {
        indx += 3;
        int slen = 24;
        if (sigType == stECDSA_P256)
            slen = 32;
        PrintAndLogEx(SUCCESS, "\tsignature [%zu]: %s", intsiglen, sprint_hex_inrow(&sig[indx], intsiglen));

        uint8_t rval[300] = {0};
        uint8_t sval[300] = {0};
        int res = ecdsa_asn1_get_signature(&sig[indx], intsiglen, rval, sval);
        if (res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "\t\tr: %s", sprint_hex(rval + 32 - slen, slen));
            PrintAndLogEx(SUCCESS, "\t\ts: %s", sprint_hex(sval + 32 - slen, slen));
        }
    }
    indx += intsiglen;

    if (sigURI) {
        size_t intsigurilen = (sig[indx] << 8) + sig[indx + 1];
        indx += 2;
        PrintAndLogEx(SUCCESS, "\tsignature uri [%zu]: %.*s", intsigurilen, (int)intsigurilen, &sig[indx]);
        indx += intsigurilen;
    }

    uint8_t certFormat = (sig[indx] >> 4) & 0x07;
    uint8_t certCount = sig[indx] & 0x0f;
    bool certURI = sig[indx] & 0x80;

    PrintAndLogEx(SUCCESS, "\tcertificate format: %s", ((certFormat < sfNA) ? ndefCertificateFormat_s[certFormat] : ndefCertificateFormat_s[sfNA]));
    PrintAndLogEx(SUCCESS, "\tcertificates count: %d", certCount);

    // print certificates
    indx++;
    for (int i = 0; i < certCount; i++) {
        size_t intcertlen = (sig[indx + 1] << 8) + sig[indx + 2];
        indx += 2;

        PrintAndLogEx(SUCCESS, "\tcertificate %d [%zu]: %s", i + 1, intcertlen, sprint_hex_inrow(&sig[indx], intcertlen));
        indx += intcertlen;
    }

    // have certificate uri
    if ((indx <= siglen) && certURI) {
        size_t inturilen = (sig[indx] << 8) + sig[indx + 1];
        indx += 2;
        PrintAndLogEx(SUCCESS, "\tcertificate uri [%zu]: %.*s", inturilen, (int)inturilen, &sig[indx]);
    }

    return PM3_SUCCESS;
}

// https://github.com/nfcpy/ndeflib/blob/master/src/ndef/signature.py#L292
static int ndefDecodeSig2(uint8_t *sig, size_t siglen) {
    size_t indx = 1;

    uint8_t sigType = sig[indx] & 0x7f;
    bool sigURI = sig[indx] & 0x80;
    indx++;

    uint8_t hashType = sig[indx];
    indx++;

    PrintAndLogEx(SUCCESS, "\tsignature type :\t" _GREEN_("%s"), ((sigType < stNA) ? ndefSigType_s[sigType] : ndefSigType_s[stNA]));
    PrintAndLogEx(SUCCESS, "\tsignature uri :\t\t%s", (sigURI ? "present" : "not present"));
    PrintAndLogEx(SUCCESS, "\thash type :\t\t%s", ((hashType == 0x02) ? _GREEN_("SHA-256") : _RED_("unknown")));

    size_t intsiglen = (sig[indx] << 8) + sig[indx + 1];
    indx += 2;

    if (sigURI) {
        indx += 2;
        PrintAndLogEx(SUCCESS, "\tsignature uri [%zu]: %.*s", intsiglen, (int)intsiglen, &sig[indx]);
        indx += intsiglen;
    } else {
        PrintAndLogEx(SUCCESS, "\tsignature [%zu]: %s", intsiglen, sprint_hex_inrow(&sig[indx], intsiglen));
        if (sigType == stECDSA_P192 || sigType == stECDSA_P256) {
            int slen = intsiglen / 2;
            if (slen == 24 || slen == 32) {
                PrintAndLogEx(SUCCESS, "\tsignature : " _GREEN_("ECDSA-%d"), slen * 8);
                PrintAndLogEx(SUCCESS, "\t\tr: %s", sprint_hex(&sig[indx], slen));
                PrintAndLogEx(SUCCESS, "\t\ts: %s", sprint_hex(&sig[indx + slen], slen));

                ndef_print_signature(NULL, 0, NULL, 0);
            }
        } else {
            PrintAndLogEx(INFO, "\tsignature: unknown type");
        }
        indx += intsiglen;
    }

    uint8_t certFormat = (sig[indx] >> 4) & 0x07;
    uint8_t certCount = sig[indx] & 0x0f;
    bool certURI = sig[indx] & 0x80;

    PrintAndLogEx(SUCCESS, "\tcertificate format : " _GREEN_("%s"), ((certFormat < sfNA) ? ndefCertificateFormat_s[certFormat] : ndefCertificateFormat_s[sfNA]));
    PrintAndLogEx(SUCCESS, "\tcertificates count : %d", certCount);

    // print certificates
    indx++;
    for (int i = 0; i < certCount; i++) {
        size_t intcertlen = (sig[indx + 1] << 8) + sig[indx + 2];
        indx += 2;

        PrintAndLogEx(SUCCESS, "\tcertificate %d [%zu]: %s", i + 1, intcertlen, sprint_hex_inrow(&sig[indx], intcertlen));
        indx += intcertlen;
    }

    // have certificate uri
    if ((indx <= siglen) && certURI) {
        size_t inturilen = (sig[indx] << 8) + sig[indx + 1];
        indx += 2;
        PrintAndLogEx(SUCCESS, "\tcertificate uri [%zu]: %.*s", inturilen, (int)inturilen, &sig[indx]);
    }

    return PM3_SUCCESS;
}

static int ndefDecodeSig(uint8_t *sig, size_t siglen) {
    PrintAndLogEx(SUCCESS, "\tsignature version : \t" _GREEN_("0x%02x"), sig[0]);
    if (sig[0] != 0x01 && sig[0] != 0x20) {
        PrintAndLogEx(ERR, "signature version unknown.");
        return PM3_ESOFT;
    }

    if (sig[0] == 0x01)
        return ndefDecodeSig1(sig, siglen);

    if (sig[0] == 0x20)
        return ndefDecodeSig2(sig, siglen);

    return PM3_ESOFT;
}

static int ndefDecodePayloadDeviceInfo(uint8_t *payload, size_t len) {
    if (payload == NULL)
        return PM3_EINVARG;
    if (len < 1)
        return PM3_EINVARG;

    PrintAndLogEx(INFO, _CYAN_("Device information"));
    uint8_t *p = payload;
    p++;
    uint8_t n = *(p++);
    PrintAndLogEx(INFO, "Vendor........ " _YELLOW_("%.*s"), n, p);
    p += n + 1;
    n = *(p++);
    PrintAndLogEx(INFO, "Model......... " _YELLOW_("%.*s"), n, p);
    p += n + 1;
    n = *(p++);
    PrintAndLogEx(INFO, "Unique name... " _YELLOW_("%.*s"), n, p);
    p += n + 1;
    p++;
    //uuid string
    // record.uuid_string = '123e4567-e89b-12d3-a456-426655440000'
    //  8-4-4-4-12
    char uuid[37] = {0};
    sprintf(uuid, "%s-", sprint_hex_inrow(p, 4));
    p += 4;
    sprintf(uuid + strlen(uuid), "%s-", sprint_hex_inrow(p, 2));
    p += 2;
    sprintf(uuid + strlen(uuid), "%s-", sprint_hex_inrow(p, 2));
    p += 2;
    sprintf(uuid + strlen(uuid), "%s-", sprint_hex_inrow(p, 2));
    p += 2;
    sprintf(uuid + strlen(uuid), "%s", sprint_hex_inrow(p, 6));
    p += 6;
    PrintAndLogEx(INFO, "UUID.......... " _YELLOW_("%s"), uuid);
    p++;
    n = *(p++);
    PrintAndLogEx(INFO, "Version....... " _YELLOW_("%.*s"), n, p);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int ndefDecodePayloadSmartPoster(uint8_t *ndef, size_t ndeflen, bool print, bool verbose) {
    if (print) {
        PrintAndLogEx(INFO, _YELLOW_("Well Known Record - Smartposter {"));
    }

    NDEFHeader_t NDEFHeader = {0};
    int res = ndefDecodeHeader(ndef, ndeflen, &NDEFHeader);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "decode header failed..");
        return res;
    }

    if (verbose) {
        ndefPrintHeader(&NDEFHeader);
    }

    if (NDEFHeader.TypeLen && NDEFHeader.PayloadLen) {
        ndefDecodePayload(&NDEFHeader);
    }

    if (NDEFHeader.TypeLen) {
        PrintAndLogEx(INFO, "Type data");
        print_buffer(NDEFHeader.Type, NDEFHeader.TypeLen, 1);
    }
    if (NDEFHeader.IDLen) {
        PrintAndLogEx(INFO, "ID data");
        print_buffer(NDEFHeader.ID, NDEFHeader.IDLen, 1);
    }
    if (NDEFHeader.PayloadLen) {
        PrintAndLogEx(INFO, "Payload data");
        print_buffer(NDEFHeader.Payload, NDEFHeader.PayloadLen, 1);
    }
    // recursive
    if (NDEFHeader.MessageEnd == false) {
        ndefDecodePayloadSmartPoster(ndef + NDEFHeader.RecLen, ndeflen - NDEFHeader.RecLen, false, false);
    }

    if (print) {
        PrintAndLogEx(INFO, _YELLOW_("}"));
    }
    return PM3_SUCCESS;
}

static int ndefDecodeMime_wifi(NDEFHeader_t *ndef) {
    PrintAndLogEx(INFO, _CYAN_("WiFi details"));
    if (ndef->PayloadLen > 1) {
        PrintAndLogEx(INFO, ">>> decorder, to be implemented <<<");
    }
    return PM3_SUCCESS;
}

static int ndefDecodeMime_vcard(NDEFHeader_t *ndef) {
    if (ndef->PayloadLen == 0) {
        PrintAndLogEx(INFO, "no payload");
        return PM3_SUCCESS;
    }
    PrintAndLogEx(INFO, _CYAN_("VCARD details"));
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "%.*s", (int)ndef->PayloadLen, ndef->Payload);

    char *s = strstr((char *)ndef->Payload, "PHOTO");
    if (s) {
        s = strtok(s, ";");
        while (s) {
            char *tmp = s;
            if (strncmp(tmp, "ENCODING", 8) == 0) {
            } else if (strncmp(tmp, "TYPE", 4) == 0) {

                char *part = strtok(tmp + 4, ":");
                while (part) {

                    if (strncmp(part, "=image/", 7) == 0) {
                    } else if (strncmp(part, "VCARD", 5) == 0) {
                    } else  {
                        // should be in the BASE64 data part now.
                        ShowBase64PictureWindow(part);
                    }
                    part = strtok(NULL, ":");
                }
            }
            s = strtok(NULL, ";");
        }
    }
    return PM3_SUCCESS;
}
static int ndefDecodeMime_json(NDEFHeader_t *ndef) {
    PrintAndLogEx(INFO, _CYAN_("JSON details"));
    if (ndef->PayloadLen > 1) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, _GREEN_("%.*s"), (int)ndef->PayloadLen, ndef->Payload);
    }
    return PM3_SUCCESS;
}

static int ndefDecodeMime_bt(NDEFHeader_t *ndef) {
    PrintAndLogEx(INFO, "Type............ " _YELLOW_("%.*s"), (int)ndef->TypeLen, ndef->Type);
    if (ndef->PayloadLen > 1) {
        uint16_t ooblen = (ndef->Payload[1] << 8 | ndef->Payload[0]);
        PrintAndLogEx(INFO, "OOB data len.... %u", ooblen);
        PrintAndLogEx(INFO, "BT MAC.......... " _YELLOW_("%s"), sprint_hex(ndef->Payload + 2, 6));
        // Let's check payload[8]. Tells us a bit about the UUID's. If 0x07 then it tells us a service UUID is 128bit
        switch (ndef->Payload[8]) {
            case 0x02:
                PrintAndLogEx(INFO, "Optional Data... incomplete list 16-bit UUID's");
                break;
            case 0x03:
                PrintAndLogEx(INFO, "Optional Data... complete list 16-bit UUID's");
                break;
            case 0x04:
                PrintAndLogEx(INFO, "Optional Data... incomplete list 32-bit UUID's");
                break;
            case 0x05:
                PrintAndLogEx(INFO, "Optional Data... complete list 32-bit UUID's");
                break;
            case 0x06:
                PrintAndLogEx(INFO, "Optional Data... incomplete list 128-bit UUID's");
                break;
            case 0x07:
                PrintAndLogEx(INFO, "Optional Data... complete list 128-bit UUID's");
                break;
            default:
                PrintAndLogEx(INFO, "Optional Data... [ %02x ]", ndef->Payload[8]);
                break;
        }
        // Let's check payload[9]. If 0x08 then SHORT_NAME or if 0x09 then COMPLETE_NAME
        if (ndef->Payload[9] == 0x08) {
            PrintAndLogEx(INFO, "Short name...... " _YELLOW_("%.*s"), (int)(ndef->PayloadLen - 10), ndef->Payload + 10);
        } else if (ndef->Payload[9] == 0x09) {
            PrintAndLogEx(INFO, "Complete name... " _YELLOW_("%.*s"), (int)(ndef->PayloadLen - 10), ndef->Payload + 10);
        } else {
            PrintAndLogEx(INFO, "[ %02x ]", ndef->Payload[9]);
        }
        PrintAndLogEx(NORMAL, "");
    }
    return PM3_SUCCESS;
}

static int ndefDecodePayload(NDEFHeader_t *ndef) {

    PrintAndLogEx(INFO, "");
    switch (ndef->TypeNameFormat) {
        case tnfEmptyRecord:
            PrintAndLogEx(INFO, "Empty Record");
            if (ndef->TypeLen != 0 || ndef->IDLen != 0 || ndef->PayloadLen != 0) {
                PrintAndLogEx(FAILED, "unexpected data in TNF_EMPTY record");
                break;
            }
            break;
        case tnfWellKnownRecord:

            if (!strncmp((char *)ndef->Type, "T", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("Text"));
                uint8_t utf8 = (ndef->Payload[0] >> 7);
                uint8_t lc_len = ndef->Payload[0] & 0x3F;
                PrintAndLogEx(INFO,
                              "    UTF %d... " _GREEN_("%.*s") ", " _GREEN_("%.*s"),
                              (utf8 == 0) ? 8 : 16,
                              lc_len,
                              ndef->Payload + 1,
                              (int)ndef->PayloadLen - 1 - lc_len,
                              ndef->Payload + 1 + lc_len
                             );
            }

            if (!strncmp((char *)ndef->Type, "U", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("URL"));
                PrintAndLogEx(INFO
                              , "    uri... " _GREEN_("%s%.*s")
                              , (ndef->Payload[0] <= 0x23 ? URI_s[ndef->Payload[0]] : "[err]")
                              , (int)(ndef->PayloadLen - 1)
                              , &ndef->Payload[1]
                             );
            }

            if (!strncmp((char *)ndef->Type, "Sig", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("Signature"));
                ndefDecodeSig(ndef->Payload, ndef->PayloadLen);
            }

            if (!strncmp((char *)ndef->Type, "Sp", ndef->TypeLen)) {
                ndefDecodePayloadSmartPoster(ndef->Payload, ndef->PayloadLen, true, false);
            }

            if (!strncmp((char *)ndef->Type, "Di", ndef->TypeLen)) {
                ndefDecodePayloadDeviceInfo(ndef->Payload, ndef->PayloadLen);
            }

            if (!strncmp((char *)ndef->Type, "Hc", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("Handover carrier"));
                PrintAndLogEx(INFO, "- decoder to be impl -");
            }

            if (!strncmp((char *)ndef->Type, "Hr", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("Handover request"));
                PrintAndLogEx(INFO, "- decoder to be impl -");
            }

            if (!strncmp((char *)ndef->Type, "Hs", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("Handover select"));
                PrintAndLogEx(INFO, "- decoder to be impl -");
            }

            if (!strncmp((char *)ndef->Type, "ac", ndef->TypeLen)) {
                PrintAndLogEx(INFO, _CYAN_("Alternative carrier"));
                PrintAndLogEx(INFO, "- decoder to be impl -");
            }
            break;
        case tnfMIMEMediaRecord: {
            PrintAndLogEx(INFO, "MIME Media Record");
            if (ndef->TypeLen == 0)  {
                PrintAndLogEx(INFO, "type length is zero");
                break;
            }

            char *begin = calloc(ndef->TypeLen + 1, sizeof(char));
            memcpy(begin, ndef->Type, ndef->TypeLen);
            str_lower(begin);

            if (str_startswith(begin, NDEF_WIFIAPPL)) {
                ndefDecodeMime_wifi(ndef);
            }
            if (str_startswith(begin, NDEF_VCARDTEXT) || str_startswith(begin, NDEF_XVCARDTEXT)) {
                ndefDecodeMime_vcard(ndef);
            }
            if (str_startswith(begin, NDEF_BLUEAPPL)) {
                ndefDecodeMime_bt(ndef);
            }
            if (str_startswith(begin, NDEF_JSONAPPL)) {
                ndefDecodeMime_json(ndef);
            }

            free(begin);
            begin = NULL;
            break;
        }
        case tnfAbsoluteURIRecord:
            PrintAndLogEx(INFO, "Absolute URI Record");
            PrintAndLogEx(INFO, "    payload : %.*s", (int)ndef->PayloadLen, ndef->Payload);
            break;
        case tnfExternalRecord:
            PrintAndLogEx(INFO, "External Record");
            PrintAndLogEx(INFO, "- decoder to be impl -");
            break;
        case tnfUnknownRecord:
            PrintAndLogEx(INFO, "Unknown Record");
            PrintAndLogEx(INFO, "- decoder to be impl -");
            break;
        case tnfUnchangedRecord:
            PrintAndLogEx(INFO, "Unchanged Record");
            PrintAndLogEx(INFO, "- decoder to be impl -");
            break;
    }
    PrintAndLogEx(INFO, "");
    return PM3_SUCCESS;
}

static int ndefRecordDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
    NDEFHeader_t NDEFHeader = {0};
    int res = ndefDecodeHeader(ndefRecord, ndefRecordLen, &NDEFHeader);
    if (res != PM3_SUCCESS)
        return res;

    ndefPrintHeader(&NDEFHeader);
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_("Payload info"));

    if (NDEFHeader.TypeLen) {
        PrintAndLogEx(INFO, "Type data");
        print_buffer(NDEFHeader.Type, NDEFHeader.TypeLen, 1);
    }
    if (NDEFHeader.IDLen) {
        PrintAndLogEx(INFO, "ID data");
        print_buffer(NDEFHeader.ID, NDEFHeader.IDLen, 1);
    }
    if (NDEFHeader.PayloadLen) {
        PrintAndLogEx(INFO, "Payload data");
        print_buffer(NDEFHeader.Payload, NDEFHeader.PayloadLen, 1);
    }
    if (NDEFHeader.TypeLen && NDEFHeader.PayloadLen) {
        ndefDecodePayload(&NDEFHeader);
    }

    return PM3_SUCCESS;
}

int NDEFRecordsDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
    bool firstRec = true;
    size_t len = 0;
    size_t counter = 0;

    while (len < ndefRecordLen) {
        counter++;

        NDEFHeader_t NDEFHeader = {0};
        int res = ndefDecodeHeader(&ndefRecord[len], ndefRecordLen - len, &NDEFHeader);
        if (res != PM3_SUCCESS)
            return res;

        if (firstRec) {
            if (!NDEFHeader.MessageBegin) {
                PrintAndLogEx(ERR, "NDEF first record have MessageBegin = false!");
                return PM3_ESOFT;
            }
            firstRec = false;
        }

        if (NDEFHeader.MessageEnd && len + NDEFHeader.RecLen != ndefRecordLen) {
            PrintAndLogEx(ERR, "NDEF records have wrong length. Must be %zu, calculated %zu", ndefRecordLen, len + NDEFHeader.RecLen);
            return PM3_ESOFT;
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, _CYAN_("Record") " " _YELLOW_("%zu"), counter);
        PrintAndLogEx(INFO, "-----------------------------------------------------");
        ndefRecordDecodeAndPrint(&ndefRecord[len], NDEFHeader.RecLen);

        len += NDEFHeader.RecLen;

        if (NDEFHeader.MessageEnd)
            break;
    }

    return PM3_SUCCESS;
}

// http://apps4android.org/nfc-specifications/NFCForum-TS-Type-2-Tag_1.1.pdf
int NDEFDecodeAndPrint(uint8_t *ndef, size_t ndefLen, bool verbose) {

    size_t indx = 0;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("NDEF parsing") " ----------------");
    while (indx < ndefLen) {
        switch (ndef[indx]) {
            case 0x00: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(SUCCESS, "--- " _CYAN_("NDEF NULL block") " ---");
                if (len)
                    PrintAndLogEx(WARNING, "NDEF NULL block size must be 0, got %d bytes", len);
                indx += len;
                break;
            }
            case 0x01: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(SUCCESS, "--- " _CYAN_("NDEF Lock Control") " ---");
                if (len != 3) {
                    PrintAndLogEx(WARNING, "NDEF Lock Control block size must be 3 instead of %d.", len);
                } else {
                    uint8_t pages_addr = (ndef[indx] >> 4) & 0x0f;
                    uint8_t byte_offset = ndef[indx] & 0x0f;
                    uint8_t Size = ndef[indx + 1];
                    uint8_t BytesLockedPerLockBit = (ndef[indx + 2] >> 4) & 0x0f;
                    uint8_t bytes_per_page = ndef[indx + 2] & 0x0f;
                    PrintAndLogEx(SUCCESS, " Pages addr (number of pages)... %d", pages_addr);
                    PrintAndLogEx(SUCCESS, "Byte offset (number of bytes)... %d", byte_offset);
                    PrintAndLogEx(SUCCESS, "Size in bits of the lock area %d. bytes approx %d", Size, Size / 8);
                    PrintAndLogEx(SUCCESS, "       Number of bytes / page... %d", bytes_per_page);
                    PrintAndLogEx(SUCCESS, "Bytes Locked Per LockBit");
                    PrintAndLogEx(SUCCESS, "   number of bytes that each dynamic lock bit is able to lock: %d", BytesLockedPerLockBit);
                }
                indx += len;
                break;
            }
            case 0x02: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(SUCCESS, "--- " _CYAN_("NDEF Memory Control") " ---");
                if (len != 3) {
                    PrintAndLogEx(WARNING, "NDEF Memory Control block size must be 3 instead of %d.", len);
                } else {
                    uint8_t pages_addr = (ndef[indx] >> 4) & 0x0f;
                    uint8_t byte_offset = ndef[indx] & 0x0f;
                    uint8_t Size = ndef[indx + 1];
                    uint8_t bytes_per_page = ndef[indx + 2] & 0x0f;
                    PrintAndLogEx(SUCCESS, " Pages addr (number of pages) : %d", pages_addr);
                    PrintAndLogEx(SUCCESS, "Byte offset (number of bytes) : %d", byte_offset);
                    PrintAndLogEx(SUCCESS, "Size in bits of the reserved area : %d. bytes approx: %d", Size, Size / 8);
                    PrintAndLogEx(SUCCESS, "       Number of bytes / page : %d", bytes_per_page);
                }
                indx += len;
                break;
            }
            case 0x03: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(SUCCESS, "--- " _CYAN_("NDEF Message") " ---");
                if (len == 0) {
                    PrintAndLogEx(SUCCESS, "Found NDEF message w zero length");
                } else {
                    PrintAndLogEx(SUCCESS, "Found NDEF message (%d bytes)", len);

                    int res = NDEFRecordsDecodeAndPrint(&ndef[indx], len);
                    if (res != PM3_SUCCESS)
                        return res;
                }

                indx += len;
                break;
            }
            case 0xfd: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(SUCCESS, "--- " _CYAN_("Proprietary info") " ---");
                PrintAndLogEx(SUCCESS, "  Can't decode, skipping %d bytes", len);
                indx += len;
                break;
            }
            case 0xfe: {
                PrintAndLogEx(SUCCESS, "NDEF Terminator detected");
                return PM3_SUCCESS;
            }
            default: {
                if (verbose)
                    PrintAndLogEx(ERR, "unknown tag 0x%02x", ndef[indx]);

                return PM3_ESOFT;
            }
        }
    }
    return PM3_SUCCESS;
}
