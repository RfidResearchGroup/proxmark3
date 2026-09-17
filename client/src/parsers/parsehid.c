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
// HID PACS parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parsehid.h"

#include <string.h>

#include "commonutil.h"
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow, hex_to_buffer
#include "protocols.h"          // MFBLOCK_SIZE
#include "mifare/mad.h"
#include "mifare/mifare4.h"      // mfFirstBlockOfSector
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"

// The PACS sector holds the credential in its three data blocks, tagged by a
// 0x02 marker at the head of the second one.
#define HID_PACS_MARKER     0x02

bool is_valid_hid_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < sizeof(mad1_sector_t)) {
        return false;
    }
    return (DetectHID((const mad1_sector_t *)dump, HID_MAD_AID) > -1);
}

int hid_parser_parse(const uint8_t *dump, size_t dumplen) {

    if (is_valid_hid_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    int sector = DetectHID((const mad1_sector_t *)dump, HID_MAD_AID);

    size_t pacs_off = mfFirstBlockOfSector(sector) * MFBLOCK_SIZE;
    uint8_t pacs_sector[MFBLOCK_SIZE * 3] = {0};
    if (pacs_off + sizeof(pacs_sector) > dumplen) {
        return PM3_EINVARG;
    }
    memcpy(pacs_sector, dump + pacs_off, sizeof(pacs_sector));

    if (pacs_sector[MFBLOCK_SIZE] != HID_PACS_MARKER) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "------------------------- " _CYAN_("Wiegand") " ---------------------------");
    PrintAndLogEx(INFO, _CYAN_("HID PACS detected"));

    PrintAndLogEx(SUCCESS, "Raw...... " _GREEN_("%s"), sprint_hex_inrow(pacs_sector + 24, 8));

    //todo:  remove preamble/sentinel
    uint32_t top = 0, mid = 0, bot = 0;
    char hexstr[16 + 1] = {0};
    hex_to_buffer((uint8_t *)hexstr, pacs_sector + 24, 8, sizeof(hexstr) - 1, 0, 0, true);
    hexstring_to_u96(&top, &mid, &bot, hexstr);

    char binstr[64 + 1];
    hextobinstring(binstr, hexstr);
    char *pbin = binstr;
    while (strlen(pbin) && *(++pbin) == '0');

    PrintAndLogEx(SUCCESS, "Binary... " _GREEN_("%s"), pbin);

    decode_wiegand(top, mid, bot, 0);
    return PM3_SUCCESS;
}
