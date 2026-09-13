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
// Hexact / COGELEC / Intratone parser for MIFARE Classic dumps
//
// A VIGIK based residential access system, but one that carries no MAD, so the
// VIGIK structure parser cannot find anything on it. What the layout is, as far
// as it has been worked out against cards:
//
//   sector 0  block 2   8 byte per card identifier, then a constant tail
//   sector 9            48 bytes, differs completely between cards
//   sector 11           32 bytes, differs completely between cards
//   sector 15           the system text, the same on every card, and in block 2
//                       the number printed on the fob, little endian
//   sector 16, 17       MIFARE Classic EV1 signature, not application data
//
// The sector 9 and 11 payload is not decoded. It carries no structure in common
// between two cards, so it is enciphered with something not held here, and
// printing a guess at fields would be inventing them.
//-----------------------------------------------------------------------------

#include "parsehexact.h"

#include <string.h>

#include "commonutil.h"
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex
#include "mifare/mifaredefault.h"   // MFBLOCK_SIZE
#include "mifare/mifare4.h"     // mfFirstBlockOfSector

#define HEXACT_ID_SECTOR        15
#define HEXACT_DATA_SECTOR_A     9
#define HEXACT_DATA_SECTOR_B    11

// Sector 15 block 0 spells the system out and is identical on every card seen
static const uint8_t hexact_marker[] = {
    'h', 'E', 'x', 'a', 'c', 't', ' ', '-', ' ', 'C', 'O', 'G', 'E', 'L', 'E', 'C'
};

// Block 0 of these cards advertises SAK 0x88 while the tag itself answers 0x08.
// A magic card written with that block 0 answers 0x88 in anticollision too,
// which is how the readers spot a clone.
#define HEXACT_BLOCK0_SAK       0x88

static const uint8_t *hexact_sector(const uint8_t *dump, size_t dumplen, uint8_t sector, uint8_t block) {
    size_t off = (mfFirstBlockOfSector(sector) + block) * MFBLOCK_SIZE;
    if (off + MFBLOCK_SIZE > dumplen) {
        return NULL;
    }
    return dump + off;
}

bool is_valid_hexact_card(const uint8_t *dump, size_t dumplen) {
    const uint8_t *p = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 0);
    if (p == NULL) {
        return false;
    }
    return (memcmp(p, hexact_marker, sizeof(hexact_marker)) == 0);
}

int hexact_parser_parse(const uint8_t *dump, size_t dumplen) {

    if (is_valid_hexact_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_("Hexact / COGELEC / Intratone") " detected");

    const uint8_t *id0 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 0);
    const uint8_t *id1 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 1);
    const uint8_t *id2 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 2);

    // The sector spells the system out across its three blocks and it reads as
    // one line, so join them. Each block pads its text with spaces, and the
    // last one keeps four bytes of its own before the text starts.
    char system[16 + 16 + 12 + 3] = {0};
    str_append(system, sizeof(system), "%.16s", (const char *)id0);
    str_trim(system);

    if (id1) {
        str_append(system, sizeof(system), " %.16s", (const char *)id1);
        str_trim(system);
    }

    if (id2) {
        str_append(system, sizeof(system), " %.12s", (const char *)(id2 + 4));
        str_trim(system);
    }

    PrintAndLogEx(INFO, "System............. " _YELLOW_("%s"), system);

    // Sector 15 block 2 keeps the number engraved on the fob as a little endian
    // value in front of the INTRATONE text. Checked against the engraving on
    // four fobs, all four matched.
    if (id2) {
        PrintAndLogEx(INFO, "Printed serial..... " _YELLOW_("%u"), MemLeToUint4byte(id2));
    }

    // sector 0 block 2 holds a per card value followed by a tail that is the
    // same on every card
    const uint8_t *s0b2 = hexact_sector(dump, dumplen, 0, 2);
    if (s0b2) {
        PrintAndLogEx(INFO, "Card identifier.... %s", sprint_hex_inrow(s0b2, 8));
    }

    if (dumplen > 5 && dump[5] == HEXACT_BLOCK0_SAK) {
        PrintAndLogEx(INFO, "Block 0 SAK........ 0x%02X  ( " _YELLOW_("anti clone marker") " )", dump[5]);
        PrintAndLogEx(INFO, "                    the tag answers 0x08, a clone written with this block 0 answers 0x88");
    }

    const uint8_t *a = hexact_sector(dump, dumplen, HEXACT_DATA_SECTOR_A, 0);
    const uint8_t *b = hexact_sector(dump, dumplen, HEXACT_DATA_SECTOR_B, 0);
    if (a == NULL || b == NULL) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Payload............ sector %u and %u, " _YELLOW_("not decoded"),
                  HEXACT_DATA_SECTOR_A, HEXACT_DATA_SECTOR_B);
    for (uint8_t blk = 0; blk < 3; blk++) {
        PrintAndLogEx(INFO, "  sector %2u blk %u.. %s", HEXACT_DATA_SECTOR_A, blk, sprint_hex_inrow(a + (blk * MFBLOCK_SIZE), MFBLOCK_SIZE));
    }
    for (uint8_t blk = 0; blk < 3; blk++) {
        PrintAndLogEx(INFO, "  sector %2u blk %u.. %s", HEXACT_DATA_SECTOR_B, blk, sprint_hex_inrow(b + (blk * MFBLOCK_SIZE), MFBLOCK_SIZE));
    }
    return PM3_SUCCESS;
}
