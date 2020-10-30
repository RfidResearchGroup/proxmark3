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

#include <string.h>

#include "ui.h"
#include "util.h" // sprint_hex...
#include "emv/dump.h"
#include "crypto/asn1utils.h"
#include "pm3_cmd.h"

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
    PrintAndLogEx(INFO, "Header:");

    PrintAndLogEx(SUCCESS, "\tMessage Begin:    %s", STRBOOL(header->MessageBegin));
    PrintAndLogEx(SUCCESS, "\tMessage End:      %s", STRBOOL(header->MessageEnd));
    PrintAndLogEx(SUCCESS, "\tChunk Flag:       %s", STRBOOL(header->ChunkFlag));
    PrintAndLogEx(SUCCESS, "\tShort Record Bit: %s", STRBOOL(header->ShortRecordBit));
    PrintAndLogEx(SUCCESS, "\tID Len Present:   %s", STRBOOL(header->IDLenPresent));
    PrintAndLogEx(SUCCESS, "\tType Name Format: [0x%02x] %s", header->TypeNameFormat, TypeNameFormat_s[header->TypeNameFormat]);

    PrintAndLogEx(SUCCESS, "\tHeader length    : %zu", header->len);
    PrintAndLogEx(SUCCESS, "\tType length      : %zu", header->TypeLen);
    PrintAndLogEx(SUCCESS, "\tPayload length   : %zu", header->PayloadLen);
    PrintAndLogEx(SUCCESS, "\tID length        : %zu", header->IDLen);
    PrintAndLogEx(SUCCESS, "\tRecord length    : %zu", header->RecLen);
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
        if (!res) {
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

static int ndefDecodePayload(NDEFHeader_t *ndef) {

    switch (ndef->TypeNameFormat) {
        case tnfWellKnownRecord:
            PrintAndLogEx(INFO, "Well Known Record");
            PrintAndLogEx(INFO, "\ttype\t: %.*s", (int)ndef->TypeLen, ndef->Type);

            if (!strncmp((char *)ndef->Type, "T", ndef->TypeLen)) {
                uint8_t utf8 = (ndef->Payload[0] >> 7);
                uint8_t lc_len = ndef->Payload[0] & 0x3F;
                PrintAndLogEx(INFO,
                              "\tUTF %d\t: " _GREEN_("%.*s") ", " _GREEN_("%.*s"),
                              (utf8 == 0) ? 8 : 16,
                              lc_len,
                              ndef->Payload + 1,
                              (int)ndef->PayloadLen - 1 - lc_len,
                              ndef->Payload + 1 + lc_len
                             );
            }

            if (!strncmp((char *)ndef->Type, "U", ndef->TypeLen)) {
                PrintAndLogEx(INFO
                              , "\turi\t: " _GREEN_("%s%.*s")
                              , (ndef->Payload[0] <= 0x23 ? URI_s[ndef->Payload[0]] : "[err]")
                              , (int)(ndef->PayloadLen - 1)
                              , &ndef->Payload[1]
                             );
            }

            if (!strncmp((char *)ndef->Type, "Sig", ndef->TypeLen)) {
                ndefDecodeSig(ndef->Payload, ndef->PayloadLen);
            }

            break;
        case tnfAbsoluteURIRecord:
            PrintAndLogEx(INFO, "Absolute URI Record");
            PrintAndLogEx(INFO, "\ttype    : %.*s", (int)ndef->TypeLen, ndef->Type);
            PrintAndLogEx(INFO, "\tpayload : %.*s", (int)ndef->PayloadLen, ndef->Payload);
            break;
        case tnfEmptyRecord:
            PrintAndLogEx(INFO, "Empty Record");
            PrintAndLogEx(INFO, "\t -to be impl-");
            break;
        case tnfMIMEMediaRecord:
            PrintAndLogEx(INFO, "MIME Media Record");
            PrintAndLogEx(INFO, "\t -to be impl-");
            break;
        case tnfExternalRecord:
            PrintAndLogEx(INFO, "External Record");
            PrintAndLogEx(INFO, "\t -to be impl-");
            break;
        case tnfUnchangedRecord:
            PrintAndLogEx(INFO, "Unchanged Record");
            PrintAndLogEx(INFO, "\t -to be impl-");
            break;
        case tnfUnknownRecord:
            PrintAndLogEx(INFO, "Unknown Record");
            PrintAndLogEx(INFO, "\t -to be impl-");
            break;
    }
    return PM3_SUCCESS;
}

static int ndefRecordDecodeAndPrint(uint8_t *ndefRecord, size_t ndefRecordLen) {
    NDEFHeader_t NDEFHeader = {0};
    int res = ndefDecodeHeader(ndefRecord, ndefRecordLen, &NDEFHeader);
    if (res != PM3_SUCCESS)
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

        PrintAndLogEx(INFO, "-----------------------------------------------------");
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
                    PrintAndLogEx(SUCCESS, " Pages addr (number of pages) : %d", pages_addr);
                    PrintAndLogEx(SUCCESS, "Byte offset (number of bytes) : %d", byte_offset);
                    PrintAndLogEx(SUCCESS, "Size in bits of the lock area : %d. bytes approx: %d", Size, Size / 8);
                    PrintAndLogEx(SUCCESS, "       Number of bytes / page : %d", bytes_per_page);
                    PrintAndLogEx(SUCCESS, "Bytes Locked Per LockBit.");
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
