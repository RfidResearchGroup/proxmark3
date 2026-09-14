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
// PROAC PACS parser for MIFARE Classic dumps
//-----------------------------------------------------------------------------

#include "parseproac.h"

#include <ctype.h>              // isprint
#include <string.h>

#include "commonutil.h"         // ARRAYLEN
#include "crc.h"                // CRC8Mad
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex_inrow, str_append, str_trim
#include "mifare/mad.h"
#include "mifare/mifaredefault.h"   // MFBLOCK_SIZE
#include "mifare/mifare4.h"     // mfFirstBlockOfSector

#define PROAC_SCHED_SECTOR_A    1
#define PROAC_SCHED_SECTOR_B    2
#define PROAC_SCHED_HEADER      4

#define PROAC_LOT_SECTOR        14
#define PROAC_LOT_BLOCK         1

#define PROAC_BLOB_SECTOR_A     12
#define PROAC_BLOB_SECTOR_B     13

#define PROAC_TAIL_SECTOR       15

// three data blocks per sector, both schedule sectors, less the header
#define PROAC_SCHED_MAX     ((2 * 3 * MFBLOCK_SIZE) - PROAC_SCHED_HEADER)

static const uint8_t *proac_block(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t block) {
    size_t off = (mfFirstBlockOfSector(sector) + block) * MFBLOCK_SIZE;
    if (off + MFBLOCK_SIZE > dumplen) {
        return NULL;
    }
    return dump + off;
}

bool is_valid_proac_card(const uint8_t *dump, size_t dumplen) {
    if (dump == NULL || dumplen < sizeof(mad1_sector_t)) {
        return false;
    }
    return (mad_find_aid((const mad1_sector_t *)dump, PROAC_MAD_AID) > -1);
}

static size_t proac_schedule(const uint8_t *dump, size_t dumplen, char *out, size_t outlen) {
    size_t n = 0;
    const uint8_t sectors[2] = { PROAC_SCHED_SECTOR_A, PROAC_SCHED_SECTOR_B };

    for (uint8_t s = 0; s < ARRAYLEN(sectors); s++) {

        for (uint8_t b = 0; b < 3; b++) {

            const uint8_t *p = proac_block(dump, dumplen, sectors[s], b);
            if (p == NULL) {
                return n;
            }

            uint8_t start = (s == 0 && b == 0) ? PROAC_SCHED_HEADER : 0;
            for (uint8_t k = start; k < MFBLOCK_SIZE; k++) {

                if (p[k] == 0x00) {
                    return n;
                }

                if (n + 1 >= outlen) {
                    return n;
                }
                out[n++] = isprint(p[k]) ? (char)p[k] : '.';
            }
        }
    }
    return n;
}

int proac_parser_parse(const uint8_t *dump, size_t dumplen) {

    if (is_valid_proac_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    const mad1_sector_t *s0 = (const mad1_sector_t *)dump;

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("PROAC") " detected --------------------");
    PrintAndLogEx(INFO, "MAD AID............ " _YELLOW_("0x%04X") " on %d of %d sectors",
                  PROAC_MAD_AID,
                  mad_count_aid(s0, PROAC_MAD_AID),
                  MAD1_NUM_AIDS
            );

    // The one card this was written against carries a MAD whose CRC was never
    // filled in, so a reader in this system cannot be validating it. Say so
    // rather than silently trusting the directory.
    uint8_t crc = CRC8Mad((uint8_t *)&s0->mad.info, sizeof(mad1_t) - 1);
    if (crc != s0->mad.crc) {
        PrintAndLogEx(INFO, "MAD CRC............ %02X, computed %02X  ( " _RED_("invalid") " )", s0->mad.crc, crc);
    }

    const uint8_t *hdr = proac_block(dump, dumplen, PROAC_SCHED_SECTOR_A, 0);
    if (hdr) {
        PrintAndLogEx(INFO, "Schedule header.... %s", sprint_hex_inrow(hdr, PROAC_SCHED_HEADER));
    }

    char sched[PROAC_SCHED_MAX + 1] = {0};
    if (proac_schedule(dump, dumplen, sched, sizeof(sched)) > 0) {
        PrintAndLogEx(INFO, "Schedule........... " _YELLOW_("%s"), sched);
        PrintAndLogEx(INFO, "                    written in clear, in a sector this card's own key can rewrite");
    }

    const uint8_t *lot = proac_block(dump, dumplen, PROAC_LOT_SECTOR, PROAC_LOT_BLOCK);
    if (lot && isprint(lot[0])) {
        char text[MFBLOCK_SIZE + 1] = {0};
        str_append(text, sizeof(text), "%.*s", MFBLOCK_SIZE, (const char *)lot);
        str_trim(text);
        PrintAndLogEx(INFO, "Lot................ " _YELLOW_("%s"), text);
    }

    PrintAndLogEx(INFO, "Payload............ sector %u and %u, 96 bytes, " _YELLOW_("not decoded"),
                  PROAC_BLOB_SECTOR_A, 
                  PROAC_BLOB_SECTOR_B
            );

    const uint8_t sectors[2] = { PROAC_BLOB_SECTOR_A, PROAC_BLOB_SECTOR_B };

    for (uint8_t s = 0; s < ARRAYLEN(sectors); s++) {
        for (uint8_t b = 0; b < 3; b++) {
            const uint8_t *p = proac_block(dump, dumplen, sectors[s], b);
            if (p) {
                PrintAndLogEx(INFO, "  sector %2u blk %u.. %s", sectors[s], b, sprint_hex_inrow(p, MFBLOCK_SIZE));
            }
        }
    }

    PrintAndLogEx(INFO, "Tail............... sector %u, " _YELLOW_("not decoded"), PROAC_TAIL_SECTOR);
    for (uint8_t b = 0; b < 3; b++) {
        const uint8_t *p = proac_block(dump, dumplen, PROAC_TAIL_SECTOR, b);
        if (p) {
            PrintAndLogEx(INFO, "  sector %2u blk %u.. %s", PROAC_TAIL_SECTOR, b, sprint_hex_inrow(p, MFBLOCK_SIZE));
        }
    }
    return PM3_SUCCESS;
}
