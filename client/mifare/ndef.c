//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// NFC Data Exchange Format (NDEF) functions
//-----------------------------------------------------------------------------

#include "ndef.h"
#include "ui.h"
#include "emv/dump.h"
#include "crypto/asn1utils.h"

#define STRBOOL(p) ((p) ? "+" : "-")

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
    "RSASSA_PSS_SHA_1",              // PKCS_1
    "RSASSA_PKCS1_v1_5_WITH_SHA_1",  // PKCS_1
    "DSA",
    "ECDSA",
    "n/a"
};

static const char *ndefCertificateFormat_s[] = {
    "X_509",
    "X9_68",
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

static uint16_t ndefTLVGetLength(uint8_t *data, size_t *indx) {
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
        return 1;

    header->TypeLen = data[1];
    header->Type = data + header->len;

    header->PayloadLen = (header->ShortRecordBit ? (data[2]) : ((data[2] << 24) + (data[3] << 16) + (data[4] << 8) + data[5]));

    if (header->IDLenPresent) {
        header->IDLen = (header->ShortRecordBit ? (data[3]) : (data[6]));
    } else {
        header->IDLen = 0;
    }

    header->Payload = header->Type + header->TypeLen + header->IDLen;

    header->RecLen = header->len + header->TypeLen + header->PayloadLen + header->IDLen;

    if (header->RecLen > datalen)
        return 3;

    return 0;
}

static int ndefPrintHeader(NDEFHeader_t *header) {
    PrintAndLogEx(INFO, "Header:");

    PrintAndLogEx(NORMAL, "\tMessage Begin:    %s", STRBOOL(header->MessageBegin));
    PrintAndLogEx(NORMAL, "\tMessage End:      %s", STRBOOL(header->MessageEnd));
    PrintAndLogEx(NORMAL, "\tChunk Flag:       %s", STRBOOL(header->ChunkFlag));
    PrintAndLogEx(NORMAL, "\tShort Record Bit: %s", STRBOOL(header->ShortRecordBit));
    PrintAndLogEx(NORMAL, "\tID Len Present:   %s", STRBOOL(header->IDLenPresent));
    PrintAndLogEx(NORMAL, "\tType Name Format: [0x%02x] %s", header->TypeNameFormat, TypeNameFormat_s[header->TypeNameFormat]);

    PrintAndLogEx(NORMAL, "\tHeader length    : %d", header->len);
    PrintAndLogEx(NORMAL, "\tType length      : %d", header->TypeLen);
    PrintAndLogEx(NORMAL, "\tPayload length   : %d", header->PayloadLen);
    PrintAndLogEx(NORMAL, "\tID length        : %d", header->IDLen);
    PrintAndLogEx(NORMAL, "\tRecord length    : %d", header->RecLen);

    return 0;
}

static int ndefDecodeSig(uint8_t *sig, size_t siglen) {
    size_t indx = 0;
    PrintAndLogEx(NORMAL, "\tsignature version: 0x%02x", sig[0]);
    if (sig[0] != 0x01) {
        PrintAndLogEx(ERR, "signature version unknown.");
        return 1;
    }
    indx++;

    uint8_t sigType = sig[indx] & 0x7f;
    bool sigURI = sig[indx] & 0x80;

    PrintAndLogEx(NORMAL, "\tsignature type: %s", ((sigType < stNA) ? ndefSigType_s[sigType] : ndefSigType_s[stNA]));
    PrintAndLogEx(NORMAL, "\tsignature uri: %s", (sigURI ? "present" : "not present"));

    size_t intsiglen = (sig[indx + 1] << 8) + sig[indx + 2];
    // ecdsa 0x04
    if (sigType == stECDSA) {
        indx += 3;
        PrintAndLogEx(NORMAL, "\tsignature [%d]: %s", intsiglen, sprint_hex_inrow(&sig[indx], intsiglen));

        uint8_t rval[300] = {0};
        uint8_t sval[300] = {0};
        int res = ecdsa_asn1_get_signature(&sig[indx], intsiglen, rval, sval);
        if (!res) {
            PrintAndLogEx(NORMAL, "\t\tr: %s", sprint_hex(rval, 32));
            PrintAndLogEx(NORMAL, "\t\ts: %s", sprint_hex(sval, 32));
        }
    }
    indx += intsiglen;

    if (sigURI) {
        size_t intsigurilen = (sig[indx] << 8) + sig[indx + 1];
        indx += 2;
        PrintAndLogEx(NORMAL, "\tsignature uri [%d]: %.*s", intsigurilen, intsigurilen, &sig[indx]);
        indx += intsigurilen;
    }

    uint8_t certFormat = (sig[indx] >> 4) & 0x07;
    uint8_t certCount = sig[indx] & 0x0f;
    bool certURI = sig[indx] & 0x80;

    PrintAndLogEx(NORMAL, "\tcertificate format: %s", ((certFormat < sfNA) ? ndefCertificateFormat_s[certFormat] : ndefCertificateFormat_s[sfNA]));
    PrintAndLogEx(NORMAL, "\tcertificates count: %d", certCount);

    // print certificates
    indx++;
    for (int i = 0; i < certCount; i++) {
        size_t intcertlen = (sig[indx + 1] << 8) + sig[indx + 2];
        indx += 2;

        PrintAndLogEx(NORMAL, "\tcertificate %d [%d]: %s", i + 1, intcertlen, sprint_hex_inrow(&sig[indx], intcertlen));
        indx += intcertlen;
    }

    // have certificate uri
    if ((indx <= siglen) && certURI) {
        size_t inturilen = (sig[indx] << 8) + sig[indx + 1];
        indx += 2;
        PrintAndLogEx(NORMAL, "\tcertificate uri [%d]: %.*s", inturilen, inturilen, &sig[indx]);
    }

    return 0;
};

static int ndefDecodePayload(NDEFHeader_t *ndef) {

    switch (ndef->TypeNameFormat) {
        case tnfWellKnownRecord:
            PrintAndLogEx(INFO, "Well Known Record");
            PrintAndLogEx(NORMAL, "\ttype:    %.*s", ndef->TypeLen, ndef->Type);

            if (!strncmp((char *)ndef->Type, "T", ndef->TypeLen)) {
                PrintAndLogEx(NORMAL, "\ttext   : %.*s", ndef->PayloadLen, ndef->Payload);
            }

            if (!strncmp((char *)ndef->Type, "U", ndef->TypeLen)) {
                PrintAndLogEx(NORMAL
                              , "\turi    : %s%.*s"
                              , (ndef->Payload[0] <= 0x23 ? URI_s[ndef->Payload[0]] : "[err]")
                              , ndef->PayloadLen - 1
                              , &ndef->Payload[1]
                             );
            }

            if (!strncmp((char *)ndef->Type, "Sig", ndef->TypeLen)) {
                ndefDecodeSig(ndef->Payload, ndef->PayloadLen);
            }

            break;
        case tnfAbsoluteURIRecord:
            PrintAndLogEx(INFO, "Absolute URI Record");
            PrintAndLogEx(NORMAL, "\ttype:    %.*s", ndef->TypeLen, ndef->Type);
            PrintAndLogEx(NORMAL, "\tpayload: %.*s", ndef->PayloadLen, ndef->Payload);
            break;
        case tnfEmptyRecord:
        case tnfMIMEMediaRecord:
        case tnfExternalRecord:
        case tnfUnchangedRecord:
        case tnfUnknownRecord:
            break;
    }
    return 0;
}

static int ndefRecordDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
    NDEFHeader_t NDEFHeader = {0};
    int res = ndefDecodeHeader(ndefRecord, ndefRecordLen, &NDEFHeader);
    if (res)
        return res;

    ndefPrintHeader(&NDEFHeader);

    if (NDEFHeader.TypeLen) {
        PrintAndLogEx(INFO, "Type data:");
        dump_buffer(NDEFHeader.Type, NDEFHeader.TypeLen, stdout, 1);
    }
    if (NDEFHeader.IDLen) {
        PrintAndLogEx(INFO, "ID data:");
        dump_buffer(NDEFHeader.ID, NDEFHeader.IDLen, stdout, 1);
    }
    if (NDEFHeader.PayloadLen) {
        PrintAndLogEx(INFO, "Payload data:");
        dump_buffer(NDEFHeader.Payload, NDEFHeader.PayloadLen, stdout, 1);
        if (NDEFHeader.TypeLen)
            ndefDecodePayload(&NDEFHeader);
    }

    return 0;
}

static int ndefRecordsDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
    bool firstRec = true;
    size_t len = 0;

    while (len < ndefRecordLen) {
        NDEFHeader_t NDEFHeader = {0};
        int res = ndefDecodeHeader(&ndefRecord[len], ndefRecordLen - len, &NDEFHeader);
        if (res)
            return res;

        if (firstRec) {
            if (!NDEFHeader.MessageBegin) {
                PrintAndLogEx(ERR, "NDEF first record have MessageBegin=false!");
                return 1;
            }
            firstRec = false;
        }

        if (NDEFHeader.MessageEnd && len + NDEFHeader.RecLen != ndefRecordLen) {
            PrintAndLogEx(ERR, "NDEF records have wrong length. Must be %d, calculated %d", ndefRecordLen, len + NDEFHeader.RecLen);
            return 1;
        }

        ndefRecordDecodeAndPrint(&ndefRecord[len], NDEFHeader.RecLen);

        len += NDEFHeader.RecLen;

        if (NDEFHeader.MessageEnd)
            break;
    }

    return 0;
}

int NDEFDecodeAndPrint(uint8_t *ndef, size_t ndefLen, bool verbose) {

    size_t indx = 0;

    PrintAndLogEx(INFO, "NDEF decoding:");
    while (indx < ndefLen) {
        switch (ndef[indx]) {
            case 0x00: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(INFO, "-- NDEF NULL block.");
                if (len)
                    PrintAndLogEx(WARNING, "NDEF NULL block size must be 0 instead of %d.", len);
                indx += len;
                break;
            }
            case 0x03: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(INFO, "-- NDEF message. len: %d", len);

                int res = ndefRecordsDecodeAndPrint(&ndef[indx], len);
                if (res)
                    return res;

                indx += len;
                break;
            }
            case 0xfd: {
                indx++;
                uint16_t len = ndefTLVGetLength(&ndef[indx], &indx);
                PrintAndLogEx(INFO, "-- NDEF proprietary info. Skipped %d bytes.", len);
                indx += len;
                break;
            }
            case 0xfe: {
                PrintAndLogEx(INFO, "-- NDEF Terminator. Done.");
                return 0;
            }
            default: {
                PrintAndLogEx(ERR, "unknown tag 0x%02x", ndef[indx]);
                return 1;
            }
        }
    }
    return 0;
}
