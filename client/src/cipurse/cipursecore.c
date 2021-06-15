//-----------------------------------------------------------------------------
// Copyright (C) 2021 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
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
#include "ui.h"
#include "util.h"

// context for secure channel
CipurseContext cipurseContext;

static int CIPURSEExchangeEx(bool ActivateField, bool LeaveFieldON, sAPDU apdu, bool IncludeLe, uint16_t Le, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[APDU_RES_LEN] = {0};
    uint8_t securedata[APDU_RES_LEN] = {0};
    sAPDU secapdu;

    *ResultLen = 0;
    if (sw) *sw = 0;
    uint16_t isw = 0;
    int res = 0;

    if (ActivateField) {
        DropField();
        msleep(50);
    }

    // long messages is not allowed
    if (apdu.Lc > 228)
        return 20;

    // COMPUTE APDU
    int datalen = 0;
    uint16_t xle = IncludeLe ? 0x100 : 0x00;
    if (xle == 0x100 && Le != 0)
        xle = Le;

    CipurseCAPDUReqEncode(&cipurseContext, &apdu, &secapdu, securedata, IncludeLe, Le);

    if (APDUEncodeS(&secapdu, false, xle, data, &datalen)) {
        PrintAndLogEx(ERR, "APDU encoding error.");
        return 201;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, ">>>> %s", sprint_hex(data, datalen));

    res = ExchangeAPDU14a(data, datalen, ActivateField, LeaveFieldON, Result, (int)MaxResultLen, (int *)ResultLen);
    if (res) {
        return res;
    }

    if (GetAPDULogging())
        PrintAndLogEx(SUCCESS, "<<<< %s", sprint_hex(Result, *ResultLen));

    if (*ResultLen < 2) {
        return 200;
    }

    size_t rlen = 0;
    if (*ResultLen == 2) {
        if (cipurseContext.RequestSecurity == CPSMACed || cipurseContext.RequestSecurity == CPSEncrypted)
            CipurseCClearContext(&cipurseContext);

        isw = Result[0] * 0x0100 + Result[1];
    } else {
        CipurseCAPDURespDecode(&cipurseContext, Result, *ResultLen, securedata, &rlen, &isw);
        memcpy(Result, securedata, rlen);
    }

    if (ResultLen != NULL)
        *ResultLen = rlen;

    if (sw != NULL)
        *sw = isw;

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

static int CIPURSEExchange(sAPDU apdu, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, apdu, true, 0, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSESelect(bool ActivateField, bool LeaveFieldON, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t data[] = {0x41, 0x44, 0x20, 0x46, 0x31};
    CipurseCClearContext(&cipurseContext);

    return EMVSelect(CC_CONTACTLESS, ActivateField, LeaveFieldON, data, sizeof(data), Result, MaxResultLen, ResultLen, sw, NULL);
}

int CIPURSEChallenge(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0x84, 0x00, 0x00, 0x00, NULL}, true, 0x16, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSEMutalAuthenticate(uint8_t keyIndex, uint8_t *params, uint8_t paramslen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0x82, 0x00, keyIndex, paramslen, params}, true, 0x10, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSECreateFile(uint8_t *attr, uint16_t attrlen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0xe4, 0x00, 0x00, attrlen, attr}, false, 0, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSEDeleteFile(uint16_t fileID, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t fileIdBin[] = {fileID >> 8, fileID & 0xff};
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0xe4, 0x00, 0x00, 02, fileIdBin}, false, 0, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSESelectFile(uint16_t fileID, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    uint8_t fileIdBin[] = {fileID >> 8, fileID & 0xff};
    return CIPURSEExchange((sAPDU) {0x00, 0xa4, 0x00, 0x00, 02, fileIdBin}, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSESelectMFFile(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchange((sAPDU) {0x00, 0xa4, 0x00, 0x00, 0, NULL}, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSEReadFileAttributes(uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchange((sAPDU) {0x80, 0xce, 0x00, 0x00, 0, NULL}, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSEReadBinary(uint16_t offset, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchange((sAPDU) {0x00, 0xb0, (offset >> 8) & 0x7f, offset & 0xff, 0, NULL}, Result, MaxResultLen, ResultLen, sw);
}

int CIPURSEUpdateBinary(uint16_t offset, uint8_t *data, uint16_t datalen, uint8_t *Result, size_t MaxResultLen, size_t *ResultLen, uint16_t *sw) {
    return CIPURSEExchangeEx(false, true, (sAPDU) {0x00, 0xd6, (offset >> 8) & 0x7f, offset & 0xff, datalen, data}, true, 0, Result, MaxResultLen, ResultLen, sw);
}

bool CIPURSEChannelAuthenticate(uint8_t keyIndex, uint8_t *key, bool verbose) {
    uint8_t buf[APDU_RES_LEN] = {0};
    size_t len = 0;
    uint16_t sw = 0;

    CipurseContext cpc = {0};
    CipurseCSetKey(&cpc, keyIndex, key);

    // get RP, rP
    int res = CIPURSEChallenge(buf, sizeof(buf), &len, &sw);
    if (res != 0 || len != 0x16) {
        if (verbose)
            PrintAndLogEx(ERR, "Cipurse get challenge " _RED_("error") ". Card returns 0x%04x.", sw);

        return false;
    }
    CipurseCSetRandomFromPICC(&cpc, buf);

    // make auth data
    uint8_t authparams[16 + 16 + 6] = {0};
    CipurseCAuthenticateHost(&cpc, authparams);

    // authenticate
    res = CIPURSEMutalAuthenticate(keyIndex, authparams, sizeof(authparams), buf, sizeof(buf), &len, &sw);
    if (res != 0 || sw != 0x9000 || len != 16) {
        if (sw == 0x6988) {
            if (verbose)
                PrintAndLogEx(ERR, "Cipurse authentication " _RED_("error") ". Wrong key.");
        } else if (sw == 0x6A88) {
            if (verbose)
                PrintAndLogEx(ERR, "Cipurse authentication " _RED_("error") ". Wrong key number.");
        } else {
            if (verbose)
                PrintAndLogEx(ERR, "Cipurse authentication " _RED_("error") ". Card returns 0x%04x.", sw);
        }

        CipurseCClearContext(&cipurseContext);
        return false;
    }

    if (CipurseCCheckCT(&cpc, buf)) {
        if (verbose)
            PrintAndLogEx(INFO, "Authentication " _GREEN_("OK"));

        CipurseCChannelSetSecurityLevels(&cpc, CPSMACed, CPSMACed);
        memcpy(&cipurseContext, &cpc, sizeof(CipurseContext));
        return true;
    } else {
        if (verbose)
            PrintAndLogEx(ERR, "Authentication " _RED_("ERROR") " card returned wrong CT");

        CipurseCClearContext(&cipurseContext);
        return false;
    }
}

void CIPURSECSetActChannelSecurityLevels(CipurseChannelSecurityLevel req, CipurseChannelSecurityLevel resp) {
    CipurseCChannelSetSecurityLevels(&cipurseContext, req, resp);
}

static void CIPURSEPrintPersoMode(uint8_t data) {
    if (data & 0x01)
        PrintAndLogEx(INFO, "Perso: filesystem");
    if (data & 0x02)
        PrintAndLogEx(INFO, "Perso: EMV");
    if (data & 0x04)
        PrintAndLogEx(INFO, "Perso: transaction supported");
    
}
    
static void CIPURSEPrintProfileInfo(uint8_t data) {
    if (data & 0x01)
        PrintAndLogEx(INFO, "Profile: L");
    if (data & 0x02)
        PrintAndLogEx(INFO, "Profile: S");
    if (data & 0x04)
        PrintAndLogEx(INFO, "Profile: T");    
}

static void CIPURSEPrintManufacturerInfo(uint8_t data) {
        if (data == 0)
            PrintAndLogEx(INFO, "Manufacturer: n/a");
        else
            PrintAndLogEx(INFO, "Manufacturer: %s", getTagInfo(data)); // getTagInfo from cmfhf14a.h
}

void CIPURSEPrintInfoFile(uint8_t *data, size_t len) {
    if (len < 2) {
        PrintAndLogEx(ERR, "Info file length " _RED_("ERROR"));
        return;
    }

    PrintAndLogEx(INFO, "------------ INFO ------------");
    PrintAndLogEx(INFO, "CIPURSE version %d revision %d", data[0], data[1]);
    
    if (len >= 3)
        CIPURSEPrintPersoMode(data[2]);
    
    if (len >= 4)
        CIPURSEPrintProfileInfo(data[3]);
    
    if (len >= 9)
        CIPURSEPrintManufacturerInfo(data[8]);
}

static void CIPURSEPrintFileDescriptor(uint8_t desc) {
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
    PrintAndLogEx(INFO, "-------- KEY ATTRIBUTES --------");
    PrintAndLogEx(INFO, "Additional info: 0x%02x", attr[0]);
    PrintAndLogEx(INFO, "Key length: %d", attr[1]);
    PrintAndLogEx(INFO, "Algorithm ID: 0x%02x", attr[2]);
    PrintAndLogEx(INFO, "Security attr: 0x%02x", attr[3]);
    PrintAndLogEx(INFO, "KVV: 0x%02x%02x%02x", attr[4], attr[5], attr[6]);
    PrintAndLogEx(INFO, "-------------------------------");
}

void CIPURSEPrintFileAttr(uint8_t *fileAttr, size_t len) {
    if (len < 7) {
        PrintAndLogEx(ERR, "Attributes length " _RED_("ERROR"));
        return;
    }

    PrintAndLogEx(INFO, "--------- FILE ATTRIBUTES ---------");
    if (fileAttr[0] == 0x38) {
        PrintAndLogEx(INFO, "Type: MF, ADF");
        if (fileAttr[1] == 0x00) {
            PrintAndLogEx(INFO, "Type: MF");
        } else {
            if ((fileAttr[1] & 0xe0) == 0x00)
                PrintAndLogEx(INFO, "Type: Unknown");
            if ((fileAttr[1] & 0xe0) == 0x20)
                PrintAndLogEx(INFO, "Type: CIPURSE L");
            if ((fileAttr[1] & 0xe0) == 0x40)
                PrintAndLogEx(INFO, "Type: CIPURSE S");
            if ((fileAttr[1] & 0xe0) == 0x60)
                PrintAndLogEx(INFO, "Type: CIPURSE T");
            if ((fileAttr[1] & 0x02) == 0x00)
                PrintAndLogEx(INFO, "Autoselect on PxSE select OFF");
            else
                PrintAndLogEx(INFO, "Autoselect on PxSE select ON");
            if ((fileAttr[1] & 0x01) == 0x00)
                PrintAndLogEx(INFO, "PxSE select returns FCPTemplate OFF");
            else
                PrintAndLogEx(INFO, "PxSE select returns FCPTemplate ON");
        }

        PrintAndLogEx(INFO, "File ID: 0x%02x%02x", fileAttr[2], fileAttr[3]);

        PrintAndLogEx(INFO, "Maximum number of custom EFs: %d", fileAttr[4]);
        PrintAndLogEx(INFO, "Maximum number of EFs with SFID: %d", fileAttr[5]);
        uint8_t keyNum = fileAttr[6];
        PrintAndLogEx(INFO, "Keys assigned: %d", keyNum);

        if (len >= 9) {
            PrintAndLogEx(INFO, "SMR entries: %02x%02x", fileAttr[7], fileAttr[8]);
        }

        if (len >= 10 + keyNum + 1) {
            PrintAndLogEx(INFO, "ART: %s", sprint_hex(&fileAttr[9], keyNum + 1));
        }

        if (len >= 11 + keyNum + 1 + keyNum * 7) {
            for (int i = 0; i < keyNum; i++) {
                PrintAndLogEx(INFO, "Key %d Attributes: %s", i, sprint_hex(&fileAttr[11 + keyNum + 1 + i * 7], 7));
                CIPURSEPrintKeyAttrib(&fileAttr[11 + keyNum + 1 + i * 7]);
            }
        }
        // MF
        if (fileAttr[1] == 0x00) {
            PrintAndLogEx(INFO, "Total memory size: %d", (fileAttr[len - 6] << 16) + (fileAttr[len - 1] << 5) + fileAttr[len - 4]);
            PrintAndLogEx(INFO, "Free memory size: %d", (fileAttr[len - 3] << 16) + (fileAttr[len - 2] << 8) + fileAttr[len - 1]);

        } else {
            int ptr = 11 + keyNum + 1 + keyNum * 7;
            if (len > ptr)
                PrintAndLogEx(INFO, "TLV file control: %s", sprint_hex(&fileAttr[ptr], len - ptr));
        }
    } else {
        PrintAndLogEx(INFO, "Type: EF");
        CIPURSEPrintFileDescriptor(fileAttr[0]);
        if (fileAttr[1] == 0)
            PrintAndLogEx(INFO, "SFI: not assigned");
        else
            PrintAndLogEx(INFO, "SFI: 0x%02x", fileAttr[1]);

        PrintAndLogEx(INFO, "File ID: 0x%02x%02x", fileAttr[2], fileAttr[3]);

        if (fileAttr[0] == 0x01 || fileAttr[0] == 0x11)
            PrintAndLogEx(INFO, "File size: %d", (fileAttr[4] << 8) + fileAttr[5]);
        else
            PrintAndLogEx(INFO, "Record num: %d record size: %d", fileAttr[4], fileAttr[5]);

        PrintAndLogEx(INFO, "Keys assigned: %d", fileAttr[6]);

        if (len >= 9) {
            PrintAndLogEx(INFO, "SMR entries: %02x%02x", fileAttr[7], fileAttr[8]);
        }

        if (len >= 10) {
            PrintAndLogEx(INFO, "ART: %s", sprint_hex(&fileAttr[9], len - 9));
            if (fileAttr[6] + 1 != len - 9)
                PrintAndLogEx(WARNING, "ART length is wrong");
        }

    }


}


