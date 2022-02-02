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

#include "commonutil.h"  // ARRAYLEN
#include "comms.h"       // DropField
#include "util_posix.h"  // msleep
#include <string.h>      // memcpy memset

#include "cmdhf14a.h"
#include "emv/emvcore.h"
#include "emv/emvjson.h"
#include "iso7816/apduinfo.h"
#include "ui.h"
#include "util.h"

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

    if (isw != 0x9000) {
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
    return CIPURSEExchangeEx(activate_field, leave_field_on, (sAPDU_t) {0x00, 0xa4, 0x00, 0x00, 0, NULL}, true, 0, result, max_result_len, result_len, sw);
}
int CIPURSESelectMFDefaultFile(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSESelectMFDefaultFileEx(false, true, result, max_result_len, result_len, sw);
}

int CIPURSEReadFileAttributes(uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x80, 0xce, 0x00, 0x00, 0, NULL}, result, max_result_len, result_len, sw);
}

int CIPURSEReadBinary(uint16_t offset, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x00, 0xb0, (offset >> 8) & 0x7f, offset & 0xff, 0, NULL}, result, max_result_len, result_len, sw);
}

int CIPURSEUpdateBinary(uint16_t offset, uint8_t *data, uint16_t datalen, uint8_t *result, size_t max_result_len, size_t *result_len, uint16_t *sw) {
    return CIPURSEExchange((sAPDU_t) {0x00, 0xd6, (offset >> 8) & 0x7f, offset & 0xff, datalen, data}, result, max_result_len, result_len, sw);
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
    if (res != 0 || sw != 0x9000 || len != 16) {
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
        PrintAndLogEx(INFO, "Perso... " _YELLOW_("filesystem"));
    if ((data & 0x02) == 0x02)
        PrintAndLogEx(INFO, "Perso... " _YELLOW_("EMV"));
    if ((data & 0x04) == 0x04)
        PrintAndLogEx(INFO, "Perso... " _YELLOW_("transaction supported"));
}

// 2021 iceman: what is the description text of profile L,S,T ?
static void CIPURSEPrintProfileInfo(uint8_t data) {
    if ((data & 0x01) == 0x01)
        PrintAndLogEx(INFO, "Profile... L");
    if ((data & 0x02) == 0x02)
        PrintAndLogEx(INFO, "Profile... S");
    if ((data & 0x04) == 0x04)
        PrintAndLogEx(INFO, "Profile... T");
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
    PrintAndLogEx(INFO, "version.... " _YELLOW_("%d"), data[0]);
    PrintAndLogEx(INFO, "revision... " _YELLOW_("%d"), data[1]);

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

static void CIPURSEPrintKeyAttrib(uint8_t *attr) {
    PrintAndLogEx(INFO, "--- " _CYAN_("Key Attributes") "---------------------");
    PrintAndLogEx(INFO, "Additional info... 0x%02x", attr[0]);
    PrintAndLogEx(INFO, "Key length........ %d", attr[1]);
    PrintAndLogEx(INFO, "Algorithm ID...... 0x%02x", attr[2]);
    PrintAndLogEx(INFO, "Security attr..... 0x%02x", attr[3]);
    PrintAndLogEx(INFO, "KVV............... 0x%02x%02x%02x", attr[4], attr[5], attr[6]);
    PrintAndLogEx(NORMAL, "");
}

const char *CIPURSEGetSMR(uint8_t smr) {
    switch (smr) {
        case 0x00: return "plain";
        case 0x01: return "mac";
        case 0x02: return "enc";
        default: return "unknown";
    }
    return "unknown";
}

void CIPURSEPrintSMR(uint8_t *smrrec) {
    PrintAndLogEx(INFO, "%s/%s/%s/%s", 
        CIPURSEGetSMR((smrrec[0] >> 8) & 0x03),
        CIPURSEGetSMR(smrrec[0] & 0x03),
        CIPURSEGetSMR((smrrec[1] >> 8) & 0x03),
        CIPURSEGetSMR(smrrec[1] & 0x03));
}

void CIPURSEPrintART(uint8_t *artrec, size_t artlen) {
    if (artlen < 1 || artlen > 9)
        return;
    for (int i = 0; i < artlen; i++) {
        if (i == 0)
            PrintAndLogEx(INFO, "always: " NOLF);
        else
            PrintAndLogEx(INFO, "key %d : " NOLF, i);

        for (int n = 0; n < 8; n++)
            if ((artrec[i] >> n) && 0x01)
                PrintAndLogEx(NORMAL, "%d " NOLF, n + 1);
            else
                PrintAndLogEx(NORMAL, "  " NOLF);

        PrintAndLogEx(NORMAL, "");
    }
}

void CIPURSEPrintFileAttr(uint8_t *attr, size_t len) {
    if (len < 7) {
        PrintAndLogEx(FAILED, "Attributes length too short");
        return;
    }

    PrintAndLogEx(INFO, "--- " _CYAN_("File Attributes") "---------------------");
    if (attr[0] == 0x38) {
        PrintAndLogEx(INFO, "Type... MF, ADF");

        if (attr[1] == 0x00) {
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

        if (len >= 9) {
            PrintAndLogEx(INFO, "SMR entries... %02x%02x", attr[7], attr[8]);
            CIPURSEPrintSMR(&attr[7]);
        }

        if (len >= 9 + keynum + 1) {
            PrintAndLogEx(INFO, "ART... %s", sprint_hex(&attr[9], keynum + 1));
            CIPURSEPrintART(&attr[9], keynum + 1);
            PrintAndLogEx(NORMAL, "");
        }

        if (len >= 9 + keynum + 1 + keynum * 7) {
            for (int i = 0; i < keynum; i++) {
                PrintAndLogEx(INFO, "Key %d Attributes... %s", i + 1, sprint_hex(&attr[9 + keynum + 1 + i * 7], 7));
                CIPURSEPrintKeyAttrib(&attr[9 + keynum + 1 + i * 7]);
            }
        }
        // MF + FCP
        if (attr[1] == 0x00 && len >= 9 + keynum + 1 + keynum * 7 + 1) {
            int xlen = len - (9 + keynum + 1 + keynum * 7) - 6;
            if (xlen > 0 && xlen < 200) {
                PrintAndLogEx(INFO, "FCP... [%d] %s", xlen, sprint_hex(&attr[9 + keynum + 1 + keynum * 7], xlen));
                TLVPrintFromBuffer(&attr[9 + keynum + 1 + keynum * 7], xlen);
                PrintAndLogEx(INFO, "");
            }
        }
        // MF
        if (attr[1] == 0x00) {
            PrintAndLogEx(INFO, "Total memory size... %d", (attr[len - 6] << 16) + (attr[len - 5] << 8) + attr[len - 4]);
            PrintAndLogEx(INFO, "Free memory size.... %d", (attr[len - 3] << 16) + (attr[len - 2] << 8) + attr[len - 1]);

        } else {
            int ptr = 11 + keynum + 1 + keynum * 7;
            if (len > ptr) {
                PrintAndLogEx(INFO, "TLV file control... %s", sprint_hex(&attr[ptr], len - ptr));
            }
        }
    } else {
        PrintAndLogEx(INFO, "Type... EF");
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


}


