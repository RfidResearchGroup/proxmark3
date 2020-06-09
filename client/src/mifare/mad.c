//-----------------------------------------------------------------------------
// Copyright (C) 2019 Merlok
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// MIFARE Application Directory (MAD) functions
//-----------------------------------------------------------------------------

#include "mad.h"
#include "ui.h"
#include "commonutil.h"  // ARRAYLEN
#include "pm3_cmd.h"
#include "crc.h"
#include "util.h"

// https://www.nxp.com/docs/en/application-note/AN10787.pdf
static madAIDDescr madKnownAIDs[] = {
    {0x0000, "free"},
    {0x0001, "defect, e.g. access keys are destroyed or unknown"},
    {0x0002, "reserved"},
    {0x0003, "contains additional directory info"},
    {0x0004, "contains card holder information in ASCII format."},
    {0x0005, "not applicable (above memory size)"},

    {0x03e1, "NDEF"},
};

static madAIDDescr madKnownClusterCodes[] = {
    {0x00, "cluster: card administration"},
    {0x01, "cluster: miscellaneous applications"},
    {0x02, "cluster: miscellaneous applications"},
    {0x03, "cluster: miscellaneous applications"},
    {0x04, "cluster: miscellaneous applications"},
    {0x05, "cluster: miscellaneous applications"},
    {0x06, "cluster: miscellaneous applications"},
    {0x07, "cluster: miscellaneous applications"},
    {0x08, "cluster: airlines"},
    {0x09, "cluster: ferry traffic"},
    {0x10, "cluster: railway services"},
    {0x11, "cluster: miscellaneous applications"},
    {0x12, "cluster: transport"},
    {0x14, "cluster: security solutions"},
    {0x18, "cluster: city traffic"},
    {0x19, "cluster: Czech Railways"},
    {0x20, "cluster: bus services"},
    {0x21, "cluster: multi modal transit"},
    {0x28, "cluster: taxi"},
    {0x30, "cluster: road toll"},
    {0x31, "cluster: generic transport"},
    {0x38, "cluster: company services"},
    {0x40, "cluster: city card services"},
    {0x47, "cluster: access control & security"},
    {0x48, "cluster: access control & security"},
    {0x49, "cluster: VIGIK"},
    {0x4A, "cluster: Ministry of Defence, Netherlands"},
    {0x4B, "cluster: Bosch Telecom, Germany"},
    {0x4C, "cluster: European Union Institutions"},
    {0x50, "cluster: ski ticketing"},
    {0x51, "cluster: access control & security"},
    {0x52, "cluster: access control & security"},
    {0x53, "cluster: access control & security"},
    {0x54, "cluster: access control & security"},
    {0x55, "cluster: SOAA standard for offline access standard"},
    {0x56, "cluster: access control & security"},
    {0x58, "cluster: academic services"},
    {0x60, "cluster: food"},
    {0x68, "cluster: non-food trade"},
    {0x70, "cluster: hotel"},
    {0x71, "cluster: loyalty"},
    {0x75, "cluster: airport services"},
    {0x78, "cluster: car rental"},
    {0x79, "cluster: Dutch government"},
    {0x80, "cluster: administration services"},
    {0x88, "cluster: electronic purse"},
    {0x90, "cluster: television"},
    {0x91, "cluster: cruise ship"},
    {0x95, "cluster: IOPTA"},
    {0x97, "cluster: metering"},
    {0x98, "cluster: telephone"},
    {0xA0, "cluster: health services"},
    {0xA8, "cluster: warehouse"},
    {0xB0, "cluster: electronic trade"},
    {0xB8, "cluster: banking"},
    {0xC0, "cluster: entertainment & sports"},
    {0xC8, "cluster: car parking"},
    {0xC9, "cluster: fleet management"},
    {0xD0, "cluster: fuel, gasoline"},
    {0xD8, "cluster: info services"},
    {0xE0, "cluster: press"},
    {0xE1, "cluster: NFC Forum"},
    {0xE8, "cluster: computer"},
    {0xF0, "cluster: mail"},
    {0xF8, "cluster: miscellaneous applications"},
};

static const char unknownAID[] = "";

static const char *GetAIDDescription(uint16_t AID) {
    for (int i = 0; i < ARRAYLEN(madKnownAIDs); i++)
        if (madKnownAIDs[i].AID == AID)
            return madKnownAIDs[i].Description;

    for (int i = 0; i < ARRAYLEN(madKnownClusterCodes); i++)
        if (madKnownClusterCodes[i].AID == (AID >> 8)) // high byte - cluster code
            return madKnownClusterCodes[i].Description;

    return unknownAID;
}

static int madCRCCheck(uint8_t *sector, bool verbose, int MADver) {
    if (MADver == 1) {
        uint8_t crc = CRC8Mad(&sector[16 + 1], 15 + 16);
        if (crc != sector[16]) {
            PrintAndLogEx(WARNING, _RED_("Wrong MAD %d CRC") " calculated: 0x%02x != 0x%02x", MADver, crc, sector[16]);
            return PM3_ESOFT;
        };
    } else {
        uint8_t crc = CRC8Mad(&sector[1], 15 + 16 + 16);
        if (crc != sector[0]) {
            PrintAndLogEx(WARNING,  _RED_("Wrong MAD %d CRC") " calculated: 0x%02x != 0x%02x", MADver, crc, sector[16]);
            return PM3_ESOFT;
        };
    }
    return PM3_SUCCESS;
}

static uint16_t madGetAID(uint8_t *sector, int MADver, int sectorNo) {
    if (MADver == 1)
        return (sector[16 + 2 + (sectorNo - 1) * 2 + 1] << 8) + (sector[16 + 2 + (sectorNo - 1) * 2]);
    else
        return (sector[2 + (sectorNo - 1) * 2 + 1] << 8) + (sector[2 + (sectorNo - 1) * 2]);
}

int MADCheck(uint8_t *sector0, uint8_t *sector10, bool verbose, bool *haveMAD2) {

    if (sector0 == NULL)
        return PM3_EINVARG;

    uint8_t GPB = sector0[3 * 16 + 9];
    if (verbose)
        PrintAndLogEx(INFO, "GPB: 0x%02x", GPB);

    // DA (MAD available)
    if (!(GPB & 0x80)) {
        PrintAndLogEx(ERR, "DA=0! MAD not available.");
        return PM3_ESOFT;
    }

    // MA (multi-application card)
    if (verbose) {
        if (GPB & 0x40)
            PrintAndLogEx(INFO, "Multi application card.");
        else
            PrintAndLogEx(INFO, "Single application card.");
    }

    uint8_t MADVer = GPB & 0x03;
    if (verbose)
        PrintAndLogEx(INFO, "MAD version: %d", MADVer);

    //  MAD version
    if ((MADVer != 0x01) && (MADVer != 0x02)) {
        PrintAndLogEx(ERR, "Wrong MAD version: 0x%02x", MADVer);
        return PM3_ESOFT;
    };

    if (haveMAD2)
        *haveMAD2 = (MADVer == 2);

    int res = madCRCCheck(sector0, true, 1);

    if (verbose && res == PM3_SUCCESS)
        PrintAndLogEx(INFO, "CRC8-MAD1 (%s)", _GREEN_("ok"));

    if (MADVer == 2 && sector10) {
        int res2 = madCRCCheck(sector10, true, 2);
        if (res == PM3_SUCCESS)
            res = res2;

        if (verbose && !res2)
            PrintAndLogEx(INFO, "CRC8-MAD2 (%)", _GREEN_("ok"));
    }

    return res;
}

int MADDecode(uint8_t *sector0, uint8_t *sector10, uint16_t *mad, size_t *madlen) {
    *madlen = 0;
    bool haveMAD2 = false;
    int res = MADCheck(sector0, sector10, false, &haveMAD2);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Not a valid MAD");
        return res;
    }

    for (int i = 1; i < 16; i++) {
        mad[*madlen] = madGetAID(sector0, 1, i);
        (*madlen)++;
    }

    if (haveMAD2) {
        // mad2 sector (0x10 == 16dec) here
        mad[*madlen] = 0x0005;
        (*madlen)++;

        for (int i = 1; i < 24; i++) {
            mad[*madlen] = madGetAID(sector10, 2, i);
            (*madlen)++;
        }
    }
    return PM3_SUCCESS;
}

int MAD1DecodeAndPrint(uint8_t *sector, bool verbose, bool *haveMAD2) {

    // check MAD1 only
    int res = MADCheck(sector, NULL, verbose, haveMAD2);
    if (verbose) {
        if (res == PM3_SUCCESS)
            PrintAndLogEx(INFO, "CRC8-MAD1 (%s)", _GREEN_("ok"));
        else
            PrintAndLogEx(INFO, "CRC8-MAD1 (%s)", _RED_("fail"));
    }

    // info byte
    uint8_t InfoByte = sector[16 + 1] & 0x3f;
    if (InfoByte) {
        PrintAndLogEx(INFO, "Card publisher sector: " _GREEN_("0x%02x"), InfoByte);
    } else {
        if (verbose)
            PrintAndLogEx(WARNING, "Card publisher sector not present");
    }
    if (InfoByte == 0x10 || InfoByte >= 0x28)
        PrintAndLogEx(WARNING, "Info byte error");

    PrintAndLogEx(INFO, " 00 MAD 1");
    for (int i = 1; i < 16; i++) {
        uint16_t AID = madGetAID(sector, 1, i);
        PrintAndLogEx(INFO, " %02d [%04X] %s", i, AID, GetAIDDescription(AID));
    }

    return PM3_SUCCESS;
}

int MAD2DecodeAndPrint(uint8_t *sector, bool verbose) {
    PrintAndLogEx(INFO, " 16 MAD 2");

    int res = madCRCCheck(sector, true, 2);
    if (verbose) {
        if (res == PM3_SUCCESS)
            PrintAndLogEx(INFO, "CRC8-MAD2 (%s)", _GREEN_("ok"));
        else
            PrintAndLogEx(INFO, "CRC8-MAD2 (%s)", _RED_("fail"));
    }

    uint8_t InfoByte = sector[1] & 0x3f;
    if (InfoByte) {
        PrintAndLogEx(INFO, "MAD2 Card publisher sector: " _GREEN_("0x%02x"), InfoByte);
    } else {
        if (verbose)
            PrintAndLogEx(WARNING, "Card publisher sector not present");
    }

    for (int i = 1; i < 8 + 8 + 7 + 1; i++) {
        uint16_t AID = madGetAID(sector, 2, i);
        PrintAndLogEx(INFO, "%02d [%04X] %s", i + 16, AID, GetAIDDescription(AID));
    }

    return PM3_SUCCESS;
}
