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
// CIPURSE transport cards data and commands
//-----------------------------------------------------------------------------

#include "cipursecore.h"
#include <string.h>                 // memcpy memset
#include "commonutil.h"             // ARRAYLEN
#include "comms.h"                  // DropField
#include "util_posix.h"             // msleep
#include "cmdhf14a.h"
#include "../emv/emvcore.h"
#include "../emv/emvjson.h"
#include "../iso7816/apduinfo.h"    // sAPDU_t
#include "ui.h"
#include "util.h"
#include "protocols.h"              // ISO7816 APDU return codes

// context for secure channel
CipurseContext_t cipurseContext;

static int CIPURSEExchangeEx(bool activate_field, bool leave_field_on, sAPDU_t apdu, bool include_le,
                             uint16_t le, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {

    if (result_len == NULL) {
        PrintAndLogEx(FAILED, "CIPURSEExchangeEx, result_len is NULL");
        return PM3_EINVARG;
    }

    *result_len = 0;

    if (sw) {
        *sw = 0;
    }
    uint16_t isw = 0;
    int res = 0;

    if (activate_field) {
        DropField();
        msleep(50);
    }

    // long messages is not allowed
    if (apdu.Lc > 228)
        return 20;

    // COMPUTE APDU
    int datalen = 0;
    uint16_t xle = include_le ? 0x100 : 0x00;
    if (xle == 0x100 && le != 0) {
        xle = le;
    }

    sAPDU_t secapdu;
    uint8_t securedata[APDU_RES_LEN] = {0};
    CipurseCAPDUReqEncode(&cipurseContext, &apdu, &secapdu, securedata, include_le, le);

    uint8_t data[APDU_RES_LEN] = {0};
    if (APDUEncodeS(&secapdu, false, xle, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return 201;
    }

    if (GetAPDULogging()) {
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));
    }

    res = ExchangeAPDU14a(data, datalen, activate_field, leave_field_on, result, (int)max_result_len, (int *)result_len);
    if (res) {
        return res;
    }

    if (GetAPDULogging()) {
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(result, *result_len));
    }

    if (*result_len < 2) {
        return 200;
    }

    size_t rlen = 0;
    if (*result_len == 2) {
        if (cipurseContext.RequestSecurity == CPSMACed || cipurseContext.RequestSecurity == CPSEncrypted) {
            CipurseCClearContext(&cipurseContext);
        }

        isw = result[0] * 0x0100 + result[1];

    } else {
        CipurseCAPDURespDecode(&cipurseContext, result, *result_len, securedata, &rlen, &isw);
        memcpy(result, securedata, rlen);
    }

    if (result_len != NULL) {
        *result_len = rlen;
    }

    if (sw != NULL) {
        *sw = isw;
    }

    if (isw != ISO7816_OK) {
        if (GetAPDULogging()) {
            if (*sw >> 8 == 0x61) {
                PrintAndLogEx(ERR, "APDU chaining len:%02x -->", *sw & 0xff);
            } else {
                PrintAndLogEx(ERR, "APDU(%02x%02x) ERROR: [%4X] %s", apdu.CLA, apdu.INS, isw, GetAPDUCodeDescription(*sw >> 8, *sw & 0xff));
                return 5;
            }
        }
    }

    return PM3_SUCCESS;
}

static int CIPURSEExchange(sAPDU_t apdu, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, apdu, true, 0, result, max_result_len, result_len, sw);
}

int CIPURSESelectAID(bool activate_field, bool leave_field_on, uint8_t *aid, size_t aidlen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    CipurseCClearContext(&cipurseContext);

    return EMVSelect(CC_CONTACTLESS, activate_field, leave_field_on, aid, aidlen, result, max_result_len, result_len, sw, NULL);
}

int CIPURSESelect(bool activate_field, bool leave_field_on, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    uint8_t aid[] = {0x41, 0x44, 0x20, 0x46, 0x31};

    return CIPURSESelectAID(activate_field, leave_field_on, aid, sizeof(aid), result, max_result_len, result_len, sw);
}

int CIPURSEChallenge(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x00, 0x84, 0x00, 0x00, 0x00, NULL}, true, 0x16, result, max_result_len, result_len, sw);
}

int CIPURSEMutualAuthenticate(uint8_t keyindex, uint8_t *params, uint8_t paramslen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x00, 0x82, 0x00, keyindex, paramslen, params}, true, 0x10, result, max_result_len, result_len, sw);
}

int CIPURSECreateFile(uint8_t *attr, uint16_t attrlen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x00, 0xe0, 0x00, 0x00, attrlen, attr}, false, 0, result, max_result_len, result_len, sw);
}

int CIPURSEDeleteFile(uint16_t fileid, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    uint8_t fileIdBin[] = {fileid >> 8, fileid & 0xff};
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x00, 0xe4, 0x00, 0x00, 02, fileIdBin}, false, 0, result, max_result_len, result_len, sw);
}

int CIPURSEDeleteFileAID(uint8_t *aid, size_t aidLen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x00, 0xe4, 0x04, 0x00, aidLen, aid}, false, 0, result, max_result_len, result_len, sw);
}

int CIPURSESelectMFEx(bool activate_field, bool leave_field_on, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSESelectFileEx(activate_field, leave_field_on, 0x3f00, result, max_result_len, result_len, sw);
}

int CIPURSESelectMF(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSESelectMFEx(false, true, result, max_result_len, result_len, sw);
}

int CIPURSEFormatAll(uint16_t *sw) {
    uint8_t result[APDU_RES_LEN] = {0};
    size_t result_len = 0;
    return CIPURSEExchange((sAPDU_t) {0x80, 0xfc, 0x00, 0x00, 7, (uint8_t *)"ConfirM"}, result, sizeof(result), &result_len, sw);
}

int CIPURSESelectFileEx(bool activate_field, bool leave_field_on, uint16_t fileid, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    CipurseCClearContext(&cipurseContext);
    uint8_t fileIdBin[] = {fileid >> 8, fileid & 0xff};
    return CIPURSEExchangeEx(activate_field, leave_field_on, (sAPDU_t) {0x00, 0xa4, 0x00, 0x00, 02, fileIdBin}, true, 0, result, max_result_len, result_len, sw);
}

int CIPURSESelectFile(uint16_t fileid, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSESelectFileEx(false, true, fileid, result, max_result_len, result_len, sw);
}

int CIPURSESelectMFDefaultFileEx(bool activate_field, bool leave_field_on, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    CipurseCClearContext(&cipurseContext);
    return CIPURSEExchangeEx(activate_field, leave_field_on, (sAPDU_t) {0x00, 0xa4, 0x00, 0x00, 0, NULL}, true, 0, result, max_result_len, result_len, sw);
}
int CIPURSESelectMFDefaultFile(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSESelectMFDefaultFileEx(false, true, result, max_result_len, result_len, sw);
}

int CIPURSEReadFileAttributes(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x80, 0xce, 0x00, 0x00, 0, NULL}, result, max_result_len, result_len, sw);
}

int CIPURSEUpdateFileAttributes(uint8_t *data, uint16_t datalen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x80, 0xde, 0x00, 0x00, datalen, data}, result, max_result_len, result_len, sw);
}

int CIPURSEReadBinary(uint16_t offset, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x00, 0xb0, (offset >> 8) & 0x7f, offset & 0xff, 0, NULL}, result, max_result_len, result_len, sw);
}

int CIPURSEUpdateBinary(uint16_t offset, uint8_t *data, uint16_t datalen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x00, 0xd6, (offset >> 8) & 0x7f, offset & 0xff, datalen, data}, result, max_result_len, result_len, sw);
}

int CIPURSEUpdateKeyAttrib(uint8_t key_num, uint8_t key_attrib, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x80, 0x4e, 0x00, key_num, 1, &key_attrib}, false, 0, result, max_result_len, result_len, sw);
}

int CIPURSEUpdateKey(uint8_t encrypt_key_num, uint8_t key_num, uint8_t *key, uint16_t key_len, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU_t) {0x80, 0x52, encrypt_key_num, key_num, key_len, key}, false, 0, result, max_result_len, result_len, sw);
}

int CIPURSECommitTransaction(uint16_t *sw) {
    uint8_t result[APDU_RES_LEN] = {0};
    size_t result_len = 0;
    return CIPURSEExchange((sAPDU_t) {0x80, 0x7e, 0x00, 0x00, 0, NULL}, result, sizeof(result), &result_len, sw);
}

int CIPURSECancelTransaction(uint16_t *sw) {
    uint8_t result[APDU_RES_LEN] = {0};
    size_t result_len = 0;
    return CIPURSEExchange((sAPDU_t) {0x80, 0x7c, 0x00, 0x00, 0, NULL}, result, sizeof(result), &result_len, sw);
}

bool CIPURSEChannelAuthenticate(uint8_t keyindex, uint8_t *key, bool verbose) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    CipurseContext_t cpc = {0};
    CipurseCSetKey(&cpc, keyindex, key);

    // get RP, rP
    int res = CIPURSEChallenge(buf, sizeof(buf), &len, &sw);
    if (res != 0 || len != 0x16) {
        if (verbose) {
            PrintAndLogEx(ERR, "Cipurse get challenge ( " _RED_("fail") " ). Card returns 0x%04x", sw);
        }
        return false;
    }
    CipurseCSetRandomFromPICC(&cpc, buf);

    // make auth data
    uint8_t authparams[16 + 16 + 6] = {0};
    CipurseCAuthenticateHost(&cpc, authparams);

    // authenticate
    res = CIPURSEMutualAuthenticate(keyindex, authparams, sizeof(authparams), buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != ISO7816_OK || len != 16) {
        if (sw == 0x6988) {
            if (verbose) {
                PrintAndLogEx(WARNING, "Authentication ( " _RED_("fail") " ). Wrong key");
            }
        } else if (sw == 0x6A88) {
            if (verbose) {
                PrintAndLogEx(WARNING, "Authentication ( " _RED_("fail") " ). Wrong key number");
            }
        } else {
            if (verbose) {
                PrintAndLogEx(WARNING, "Authentication ( " _RED_("fail") " ). Card returns 0x%04x", sw);
            }
        }

        CipurseCClearContext(&cipurseContext);
        return false;
    }

    if (CipurseCCheckCT(&cpc, buf)) {
        if (verbose) {
            PrintAndLogEx(SUCCESS, "Authentication ( " _GREEN_("ok") " )");
        }

        CipurseCChannelSetSecurityLevels(&cpc, CPSMACed, CPSMACed);
        memcpy(&cipurseContext, &cpc, sizeof(CipurseContext_t));
        return true;
    } else {
        if (verbose) {
            PrintAndLogEx(WARNING, "Authentication ( " _RED_("fail") " ) card returned wrong CT");
        }

        CipurseCClearContext(&cipurseContext);
        return false;
    }
}

void CIPURSECSetActChannelSecurityLevels(CipurseChannelSecurityLevel req, CipurseChannelSecurityLevel resp) {
    CipurseCChannelSetSecurityLevels(&cipurseContext, req, resp);
}

static void CIPURSEPrintPersoMode(uint8_t data) {
    if ((data & 0x01) == 0x01)
        PrintAndLogEx(INFO, "Perso.......... " _YELLOW_("filesystem"));
    if ((data & 0x02) == 0x02)
        PrintAndLogEx(INFO, "Perso.......... " _YELLOW_("EMV"));
    if ((data & 0x04) == 0x04)
        PrintAndLogEx(INFO, "Perso.......... " _YELLOW_("transaction supported"));
}

// 2021 iceman: what is the description text of profile L,S,T ?
static void CIPURSEPrintProfileInfo(uint8_t data) {

    PrintAndLogEx(INFO, "Profile........" NOLF);
    if ((data & 0x01) == 0x01)
        PrintAndLogEx(NORMAL, " L" NOLF);
    if ((data & 0x02) == 0x02)
        PrintAndLogEx(NORMAL, ", S" NOLF);
    if ((data & 0x04) == 0x04)
        PrintAndLogEx(NORMAL, ", T" NOLF);
    PrintAndLogEx(NORMAL, "");
}

static void CIPURSEPrintManufacturerInfo(uint8_t data) {
    if (data == 0)
        PrintAndLogEx(INFO, "Manufacturer... n/a");
    else
        PrintAndLogEx(INFO, "Manufacturer... %s", getTagInfo(data)); // getTagInfo from cmfhf14a.h
}

void CIPURSEPrintInfoFile(uint8_t *data, size_t len) {
    if (len < 2) {
        PrintAndLogEx(FAILED, "Info file length too short");
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("CIPURSE Information") "---------------------");
    PrintAndLogEx(INFO, "Version........ " _YELLOW_("v%d.%d"), data[0], data[1]);

    if (len >= 3)
        CIPURSEPrintPersoMode(data[2]);

    if (len >= 4)
        CIPURSEPrintProfileInfo(data[3]);

    if (len >= 9)
        CIPURSEPrintManufacturerInfo(data[8]);
}

void CIPURSEPrintFileDescriptor(uint8_t desc) {
    if (desc == 0x01)
        PrintAndLogEx(INFO, "Binary file");
    else if (desc == 0x11)
        PrintAndLogEx(INFO, "Binary file with transactions");
    else if (desc == 0x02)
        PrintAndLogEx(INFO, "Linear record file");
    else if (desc == 0x12)
        PrintAndLogEx(INFO, "Linear record file with transactions");
    else if (desc == 0x06)
        PrintAndLogEx(INFO, "Cyclic record file");
    else if (desc == 0x16)
        PrintAndLogEx(INFO, "Cyclic record file with transactions");
    else if (desc == 0x1E)
        PrintAndLogEx(INFO, "Linear value-record file");
    else if (desc == 0x1F)
        PrintAndLogEx(INFO, "Linear value-record file with transactions");
    else
        PrintAndLogEx(INFO, "Unknown file 0x%02x", desc);
}

void CIPURSEPrintDGIArray(uint8_t *dgi, size_t dgilen) {
    if (dgilen < 3) {
        PrintAndLogEx(WARNING, "DGI too small. Length: %zu", dgilen);
        return;
    }

    uint8_t *dgiptr = dgi;
    size_t reslen = 0;
    while (dgilen > reslen + 2) {
        uint8_t len = dgiptr[2];
        CIPURSEPrintDGI(dgiptr, len + 3);

        dgiptr += len + 3;
        reslen += len + 3;
    }
}

void CIPURSEPrintDGI(uint8_t *dgi, size_t dgilen) {
    if (dgilen < 3) {
        PrintAndLogEx(WARNING, "DGI too small. Length: %zu", dgilen);
        return;
    }

    uint8_t len = dgi[2];
    if (len + 3 != dgilen) {
        PrintAndLogEx(ERR, "DGI size does not match with record size. Length of record: %zu, DGI size: %d", dgilen, len);
        return;
    }

    // check DGI
    if (dgi[0] == 0x92 && dgi[1] == 0x00) {
        PrintAndLogEx(INFO, "DGI 9200 - ADF file attributes");
        CIPURSEPrintFileAttrEx(&dgi[3], len, true);

    } else if (dgi[0] == 0x92 && dgi[1] == 0x01) {
        PrintAndLogEx(INFO, "DGI 9201 - EF file attributes");
        CIPURSEPrintFileAttrEx(&dgi[3], len, true);

    } else if (dgi[0] == 0xa0 && dgi[1] == 0x0f) {
        PrintAndLogEx(INFO, "DGI a00f - All key values");

        if (len % 20 != 0) {
            PrintAndLogEx(ERR, "Key values size must be array of 20-bite record. ADF size: %d", len);
            return;
        }

        for (int i = 0; i < len / 20; i++) {

            uint8_t kvv[CIPURSE_KVV_LENGTH] = {0};
            uint8_t aeskey[16] = {0};
            memcpy(aeskey, &dgi[3 + i * 20 + 0], sizeof(aeskey));

            PrintAndLogEx(INFO, "Key[%d]............ %s", i + 1, sprint_hex_inrow(aeskey, sizeof(aeskey)));
            PrintAndLogEx(INFO, " Additional info.. 0x%02x", dgi[3 + i * 20 + 16]);
            CipurseCGetKVV(aeskey, kvv);
            bool kvvvalid = (memcmp(kvv, &dgi[3 + i * 20 + 17], 3) == 0);
            PrintAndLogEx(INFO, " KVV.............. %s (%s)", sprint_hex_inrow(&dgi[3 + i * 20 + 17], 3), (kvvvalid) ? _GREEN_("valid") : _RED_("invalid"));
        }
        PrintAndLogEx(NORMAL, "");

    } else {
        PrintAndLogEx(WARNING, "Unknown DGI %02x%02x", dgi[0], dgi[1]);
    }
}

void CIPURSEPrintKeySecurityAttributes(uint8_t attr) {
    PrintAndLogEx(INFO, " Update right:              %s", (attr & 0x01) ? "self" : "any");
    PrintAndLogEx(INFO, " Change key and rights:     %s", (attr & 0x02) ? "ok" : "frozen");
    PrintAndLogEx(INFO, " Use as key encryption key: %s", (attr & 0x04) ? "blocked" : "ok");
    PrintAndLogEx(INFO, " Key validity:              %s", (attr & 0x80) ? "invalid" : "valid");
}

static void CIPURSEPrintKeyAttrib(uint8_t *attr) {
    PrintAndLogEx(INFO, "--- " _CYAN_("Key Attributes") "---------------------");
    PrintAndLogEx(INFO, "Additional info... 0x%02x", attr[0]);
    PrintAndLogEx(INFO, "Key length........ %d", attr[1]);
    PrintAndLogEx(INFO, "Algorithm ID...... 0x%02x (%s)", attr[2], (attr[2] == 0x09) ? "AES" : "unknown");
    PrintAndLogEx(INFO, "Security attr..... 0x%02x", attr[3]);
    CIPURSEPrintKeySecurityAttributes(attr[3]);
    PrintAndLogEx(INFO, "KVV............... 0x%02x%02x%02x", attr[4], attr[5], attr[6]);
    PrintAndLogEx(NORMAL, "");
}

static void CIPURSEPrintKeyAttribDGI(uint8_t *attr) {
    PrintAndLogEx(INFO, "--- " _CYAN_("DGI Key Attributes") "---------------------");
    PrintAndLogEx(INFO, "Security attr..... 0x%02x", attr[0]);
    CIPURSEPrintKeySecurityAttributes(attr[0]);
    PrintAndLogEx(INFO, "Key length........ %d", attr[1]);
    PrintAndLogEx(INFO, "Algorithm ID...... 0x%02x (%s)", attr[2], (attr[2] == 0x09) ? "AES" : "unknown");
    PrintAndLogEx(NORMAL, "");
}

const char *CIPURSEGetSMR(uint8_t smr) {
    switch (smr) {
        case 0x00:
            return "plain";
        case 0x01:
            return "mac";
        case 0x02:
            return "enc";
        default:
            return "unknown";
    }
}

void CIPURSEPrintSMR(const uint8_t *smrrec) {
    PrintAndLogEx(INFO, "1. %s/%s", CIPURSEGetSMR((smrrec[0] >> 6) & 0x03), CIPURSEGetSMR((smrrec[0] >> 4) & 0x03));
    PrintAndLogEx(INFO, "2. %s/%s", CIPURSEGetSMR((smrrec[0] >> 2) & 0x03), CIPURSEGetSMR((smrrec[0] >> 0) & 0x03));
    PrintAndLogEx(INFO, "3. %s/%s", CIPURSEGetSMR((smrrec[1] >> 6) & 0x03), CIPURSEGetSMR((smrrec[1] >> 4) & 0x03));
    PrintAndLogEx(INFO, "4. %s/%s", CIPURSEGetSMR((smrrec[1] >> 2) & 0x03), CIPURSEGetSMR((smrrec[1] >> 0) & 0x03));
}

void CIPURSEPrintART(const uint8_t *artrec, size_t artlen) {
    if (artlen < 1 || artlen > 9)
        return;
    for (int i = 0; i < artlen; i++) {
        if (i == 0)
            PrintAndLogEx(INFO, "always: " NOLF);
        else
            PrintAndLogEx(INFO, "key %d : " NOLF, i);

        for (int n = 7; n >= 0; n--)
            if ((artrec[i] >> n) & 0x01)
                PrintAndLogEx(NORMAL, "%d " NOLF, n + 1);
            else
                PrintAndLogEx(NORMAL, "  " NOLF);

        PrintAndLogEx(NORMAL, "");
    }
}

void CIPURSEPrintEFFileAttr(uint8_t *attr, size_t len) {
    CIPURSEPrintFileDescriptor(attr[0]);

    if (attr[1] == 0)
        PrintAndLogEx(INFO, "SFI.... not assigned");
    else
        PrintAndLogEx(INFO, "SFI.... 0x%02x", attr[1]);

    PrintAndLogEx(INFO, "File ID... 0x%02x%02x", attr[2], attr[3]);

    if (attr[0] == 0x01 || attr[0] == 0x11)
        PrintAndLogEx(INFO, "File size... %d", (attr[4] << 8) + attr[5]);
    else
        PrintAndLogEx(INFO, "Record num " _YELLOW_("%d") " record size " _YELLOW_("%d"), attr[4], attr[5]);

    PrintAndLogEx(INFO, "Keys assigned... %d", attr[6]);

    if (len >= 9) {
        PrintAndLogEx(INFO, "SMR entries... %02x%02x", attr[7], attr[8]);
        CIPURSEPrintSMR(&attr[7]);
    }

    if (len >= 10) {
        PrintAndLogEx(INFO, "ART... %s", sprint_hex(&attr[9], len - 9));
        CIPURSEPrintART(&attr[9], len - 9);

        if (attr[6] + 1 != len - 9) {
            PrintAndLogEx(WARNING, "ART length is wrong");
        }
    }
}

void CIPURSEPrintFileAttrEx(uint8_t *attr, size_t len, bool isDGI) {
    if (len < 7) {
        PrintAndLogEx(FAILED, "Attributes length too short");
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("File Attributes") "---------------------");
    if (attr[0] == 0x38 || attr[0] == 0x3F) {
        PrintAndLogEx(INFO, "Type... MF, ADF");

        if (attr[1] == 0x00) {
            if (attr[0] == 0x3F)
                PrintAndLogEx(INFO, "Type... PxSE");
            else
                PrintAndLogEx(INFO, "Type... MF");
        } else {
            if ((attr[1] & 0xe0) == 0x00)
                PrintAndLogEx(INFO, "Type... Unknown");

            if ((attr[1] & 0xe0) == 0x20)
                PrintAndLogEx(INFO, "Type... CIPURSE L");

            if ((attr[1] & 0xe0) == 0x40)
                PrintAndLogEx(INFO, "Type... CIPURSE S");

            if ((attr[1] & 0xe0) == 0x60)
                PrintAndLogEx(INFO, "Type... CIPURSE T");

            if ((attr[1] & 0x02) == 0x00)
                PrintAndLogEx(INFO, "Autoselect on PxSE select OFF");
            else
                PrintAndLogEx(INFO, "Autoselect on PxSE select ON");

            if ((attr[1] & 0x01) == 0x00)
                PrintAndLogEx(INFO, "PxSE select returns FCPTemplate OFF");
            else
                PrintAndLogEx(INFO, "PxSE select returns FCPTemplate ON");
        }

        PrintAndLogEx(INFO, "File ID................... 0x%02x%02x", attr[2], attr[3]);
        PrintAndLogEx(INFO, "Maximum # custom EFs...... %d", attr[4]);
        PrintAndLogEx(INFO, "Maximum # EFs with SFID... %d", attr[5]);

        uint8_t keynum = attr[6];
        PrintAndLogEx(INFO, "Keys assigned... %d", keynum);

        int idx = 7;
        if (keynum > 0) {
            if (len >= idx + 2) {
                PrintAndLogEx(INFO, "SMR entries... %02x%02x", attr[idx], attr[idx + 1]);
                CIPURSEPrintSMR(&attr[idx]);
            }
            idx += 2;

            if (len >= idx + keynum + 1) {
                PrintAndLogEx(INFO, "ART... %s", sprint_hex(&attr[idx], keynum + 1));
                CIPURSEPrintART(&attr[idx], keynum + 1);
                PrintAndLogEx(NORMAL, "");
            }
            idx += keynum + 1;

            size_t reclen = (isDGI) ? 3 : 7;
            if (len >= idx + keynum * reclen) {
                for (int i = 0; i < keynum; i++) {
                    PrintAndLogEx(INFO, "Key %d Attributes... %s", i + 1, sprint_hex(&attr[idx + i * reclen], reclen));
                    if (isDGI)
                        CIPURSEPrintKeyAttribDGI(&attr[idx + i * reclen]);
                    else
                        CIPURSEPrintKeyAttrib(&attr[idx + i * reclen]);
                }
            }
            idx += keynum * reclen;
        }
        // FCP
        if (len >= idx + 1) {
            int xlen = len - idx;
            // for MF only
            if (attr[1] == 0x00 && attr[0] != 0x3F)
                xlen = xlen - 6;
            if (xlen > 0 && xlen < 200) {
                PrintAndLogEx(INFO, "TLV file control parameters... [%d] %s", xlen, sprint_hex(&attr[idx], xlen));
                TLVPrintFromBuffer(&attr[idx], xlen);
                PrintAndLogEx(NORMAL, "");
            }
        }
        // MF only
        if (attr[1] == 0x00 && attr[0] != 0x3F) {
            PrintAndLogEx(INFO, "Total memory size... %d", (attr[len - 6] << 16) + (attr[len - 5] << 8) + attr[len - 4]);
            PrintAndLogEx(INFO, "Free memory size.... %d", (attr[len - 3] << 16) + (attr[len - 2] << 8) + attr[len - 1]);

        }
    } else {
        PrintAndLogEx(INFO, "Type... EF");
        CIPURSEPrintEFFileAttr(attr, len);
        PrintAndLogEx(NORMAL, "");
    }

}

void CIPURSEPrintFileAttr(uint8_t *attr, size_t len) {
    return CIPURSEPrintFileAttrEx(attr, len, false);
}

void CIPURSEPrintFileUpdateAttr(uint8_t *attr, size_t len) {
    uint8_t keynum = attr[0];
    PrintAndLogEx(INFO, "Keys assigned... %d", keynum);

    size_t idx = 1;
    if (keynum > 0) {
        if (len >= idx + 2) {
            PrintAndLogEx(INFO, "SMR entries... %02x%02x", attr[idx], attr[idx + 1]);
            CIPURSEPrintSMR(&attr[idx]);
        }
        idx += 2;

        if (len >= idx + keynum + 1) {
            PrintAndLogEx(INFO, "ART... %s", sprint_hex(&attr[idx], keynum + 1));
            CIPURSEPrintART(&attr[idx], keynum + 1);
            PrintAndLogEx(NORMAL, "");
        }
        idx += keynum + 1;
    }

    // FCI
    if (len >= idx + 1) {
        int xlen = len - idx;
        if (xlen > 0 && xlen < 200) {
            PrintAndLogEx(INFO, "TLV file control parameters... [%d] %s", xlen, sprint_hex(&attr[idx], xlen));
            TLVPrintFromBuffer(&attr[idx], xlen);
            PrintAndLogEx(NORMAL, "");
        }
    }
}
