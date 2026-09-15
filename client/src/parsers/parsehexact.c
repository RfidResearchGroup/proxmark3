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
//-----------------------------------------------------------------------------

#include "parsehexact.h"
#include <string.h>
#include <ctype.h>                  // tolower
#include "commonutil.h"
#include "ui.h"                     // PrintAndLogEx
#include "util.h"                   // sprint_hex
#include "mifare/mifaredefault.h"   // MFBLOCK_SIZE
#include "mifare/mifare4.h"         // mfFirstBlockOfSector

#define HEXACT_ID_SECTOR        15
#define HEXACT_DATA_SECTOR_A     9
#define HEXACT_DATA_SECTOR_B    11

// bytes 6..8 are skipped: the separator is " - " on most cards but byte 8 is
// 0x01 on at least one, and the published COGELEC fingerprints skip them too
static const uint8_t hexact_marker[] = {
    'h', 'e', 'x', 'a', 'c', 't', 0, 0, 0, 'c', 'o', 'g', 'e', 'l', 'e', 'c'
};

#define HEXACT_BLOCK0_SAK       0x88

#define HEXACT_SEED_BASE_A      0xB3
#define HEXACT_SEED_BASE_B      0x5C

static const struct {
    uint8_t sector;
    uint8_t blk;
} hexact_payload[] = {
    {HEXACT_DATA_SECTOR_A, 0}, {HEXACT_DATA_SECTOR_A, 1}, {HEXACT_DATA_SECTOR_A, 2},
    {HEXACT_DATA_SECTOR_B, 0}, {HEXACT_DATA_SECTOR_B, 1},
};
#define HEXACT_PAYLOAD_BLOCKS   ARRAYLEN(hexact_payload)

typedef enum {
    HX_ID,          // identifier[idx]
    HX_ID_SER,      // identifier[idx] ^ serial[idx]
    HX_ID_UID,      // identifier[idx] ^ uid[0] ^ uid[2]
} hexact_src_t;

typedef struct {
    uint8_t rec;
    uint8_t pos;
    hexact_src_t src;
    uint8_t idx;
    uint8_t xr;
} hexact_check_t;

static const hexact_check_t hexact_checks[] = {
    {0,  4, HX_ID,     4, 0xFE}, {0,  7, HX_ID_UID, 7, 0x00},
    {1,  1, HX_ID,     1, 0x00}, {1,  4, HX_ID,     4, 0x00},
    {1, 15, HX_ID_UID, 7, 0x00},
    {2,  0, HX_ID,     0, 0x00}, {2,  1, HX_ID,     1, 0x00},
    {2,  4, HX_ID,     4, 0x00}, {2,  7, HX_ID,     7, 0x00},
    {3,  7, HX_ID_UID, 7, 0x00}, {3, 13, HX_ID,     5, 0x00},
    {4,  1, HX_ID,     1, 0x00}, {4, 13, HX_ID,     5, 0x00},
    {4, 15, HX_ID_UID, 7, 0x00},
};

static uint8_t hexact_rotl(uint8_t v, uint8_t n) {
    n &= 7;
    if (n == 0) {
        return v;
    }
    return (uint8_t)((v << n) | (v >> (8 - n)));
}

static uint8_t hexact_seed(uint8_t sector, uint8_t blk) {
    uint8_t base = (sector == HEXACT_DATA_SECTOR_A) ? HEXACT_SEED_BASE_A : HEXACT_SEED_BASE_B;
    return base ^ (uint8_t)(2 * blk);
}

// Strip the keystream from one payload block
static void hexact_decrypt(const uint8_t *in, uint8_t sector, uint8_t blk, uint8_t *out) {
    uint8_t s = hexact_seed(sector, blk);
    for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
        out[k] = in[k] ^ hexact_rotl(s, k);
    }
}

static uint8_t hexact_expect(const hexact_check_t *c, const uint8_t *idn,
                             const uint8_t *uid, const uint8_t *ser) {
    uint8_t v = idn[c->idx] ^ c->xr;
    if (c->src == HX_ID_SER && c->idx < 4) {
        v ^= ser[c->idx];
    } else if (c->src == HX_ID_UID) {
        v ^= uid[0] ^ uid[2];
    }
    return v;
}


// Per installation offsets: the XOR of two positions holding the same class, so
// the mask cancels and what is left identifies the installation. The first seven
// need only sector 9, the last three sector 11 block 0.
#define HEXACT_SITE_NOPOS   0xFF

static const struct {
    uint8_t a_rec, a_pos;
    uint8_t b_rec, b_pos;       // b_rec HEXACT_SITE_NOPOS for none
    bool fold_uid1;
    int8_t idn;                 // identifier byte to fold, -1 for none
    int8_t ser;                 // serial byte to fold, -1 for none
} hexact_site[] = {
    {0, 2, 2, 2, false, -1, -1},
    {0, 3, 1, 3, false, -1, -1},
    {0, 5, 1, 5, false, -1, -1},
    {0, 12, 1, 12, false, -1, -1},
    {0, 13, 1, 13, false, -1, -1},
    {0, 14, 1, 14, false, -1, -1},
    {0, 15, 1, 7, true, -1, -1},
    {0, 0, HEXACT_SITE_NOPOS, 0, false, 0, 0},
    {0, 1, HEXACT_SITE_NOPOS, 0, false, 1, 1},
    {3, 0, HEXACT_SITE_NOPOS, 0, false, 0, -1},
    {3, 1, HEXACT_SITE_NOPOS, 0, false, 1, -1},
    {3, 15, 0, 15, false, -1, -1},
};
#define HEXACT_SITE_BYTES   ARRAYLEN(hexact_site)
#define HEXACT_SITE_S9      9       // how many of them sector 9 alone gives

// Installations already in the research corpus. Row 0 has four cards, the rest
// one each, so anything that is not row 0 is a card worth having.
static const uint8_t hexact_known_site[][HEXACT_SITE_S9] = {
    {0x9D, 0xFF, 0x00, 0x99, 0xCC, 0x20, 0xD0, 0xFF, 0xFF},
    {0x2C, 0x2F, 0x70, 0x21, 0xB5, 0x7F, 0x45, 0xDF, 0x10},
    {0xE1, 0x50, 0x00, 0xEC, 0x1D, 0x00, 0xF4, 0xE6, 0xF3},
    {0xAF, 0xB3, 0x00, 0xEC, 0x1D, 0x00, 0x03, 0xDC, 0x7D},
    {0xD4, 0x58, 0x7F, 0xA5, 0x67, 0xD4, 0x0D, 0x0C, 0x14},
};

// A blank block decrypts to the bare keystream, so a site byte is produced only
// when every block it reads was written.
static bool hexact_site_read(const uint8_t rec[][MFBLOCK_SIZE], const uint8_t *idn,
                             const uint8_t *uid, const uint8_t *ser,
                             const bool *written, size_t i, uint8_t *out) {
    if (written[hexact_site[i].a_rec] == false) {
        return false;
    }
    uint8_t v = rec[hexact_site[i].a_rec][hexact_site[i].a_pos];

    if (hexact_site[i].b_rec != HEXACT_SITE_NOPOS) {
        if (written[hexact_site[i].b_rec] == false) {
            return false;
        }
        v ^= rec[hexact_site[i].b_rec][hexact_site[i].b_pos];
    }
    if (hexact_site[i].fold_uid1) {
        v ^= uid[1];
    }
    if (hexact_site[i].idn >= 0) {
        v ^= idn[hexact_site[i].idn];
    }
    if (hexact_site[i].ser >= 0) {
        v ^= ser[hexact_site[i].ser];
    }
    *out = v;
    return true;
}

#define HEXACT_MAX_SHOWN    5

static uint8_t hexact_cross_check(const uint8_t rec[][MFBLOCK_SIZE], const uint8_t *idn,
                                  const uint8_t *uid, const uint8_t *ser,
                                  const bool *written, uint8_t *total, bool verbose) {
    uint8_t pass = 0, shown = 0;
    *total = 0;

    for (size_t i = 0; i < ARRAYLEN(hexact_checks); i++) {
        const hexact_check_t *c = &hexact_checks[i];
        if (written[c->rec] == false) {
            continue;
        }
        uint8_t want = hexact_expect(c, idn, uid, ser);
        (*total)++;
        if (rec[c->rec][c->pos] == want) {
            pass++;
        } else if (verbose && shown++ < HEXACT_MAX_SHOWN) {
            PrintAndLogEx(INFO, "  mismatch......... sector %2u blk %u byte %2u is %02X, expected %02X",
                          hexact_payload[c->rec].sector, hexact_payload[c->rec].blk,
                          c->pos, rec[c->rec][c->pos], want);
        }
    }

    // byte 7 repeats across two records in one of two phases; a card uses one
    if (written[1] && written[2]) {
        (*total)++;
        if (rec[2][15] == rec[1][7] || rec[2][7] == rec[1][15]) {
            pass++;
        } else if (verbose && shown++ < HEXACT_MAX_SHOWN) {
            PrintAndLogEx(INFO, "  mismatch......... record tie %02X/%02X matches neither phase",
                          rec[2][15], rec[2][7]);
        }
    }

    if (verbose && shown > HEXACT_MAX_SHOWN) {
        PrintAndLogEx(INFO, "  ................. and %u more", shown - HEXACT_MAX_SHOWN);
    }
    return pass;
}

static bool hexact_all_printable(const uint8_t *p, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (isprint(p[i]) == 0) {
            return false;
        }
    }
    return true;
}

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

    for (size_t i = 0; i < sizeof(hexact_marker); i++) {
        if (hexact_marker[i] == 0) {
            continue;
        }
        if (tolower(p[i]) != hexact_marker[i]) {
            return false;
        }
    }
    return true;
}

int hexact_parser_parse(const uint8_t *dump, size_t dumplen) {

    if (is_valid_hexact_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_("Hexact / COGELEC / Intratone") " detected");

    // sector 15 is written at the factory and then locked, so the case of the
    // marker cannot change on a card and dates it
    const uint8_t *mark = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 0);
    const uint8_t *spare = hexact_sector(dump, dumplen, HEXACT_DATA_SECTOR_B, 2);
    // erased is FF, not zero, so an unpersonalised card must not read as in use
    bool spare_used = false;
    if (spare) {
        for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
            if (spare[k] != 0x00 && spare[k] != 0xFF) {
                spare_used = true;
                break;
            }
        }
    }
    if (mark) {
        PrintAndLogEx(INFO, "Generation......... %.6s, variant byte %02X, sector %u block 2 %s  ( %s )",
                      (const char *)mark, mark[8], HEXACT_DATA_SECTOR_B,
                      spare_used ? "in use" : "unused",
                      (mark[0] == 'H') ? "older" : "Intratone / Hexact A");
    }

    if (dumplen > 5 && dump[5] == HEXACT_BLOCK0_SAK) {
        PrintAndLogEx(INFO, "Block 0 SAK........ 0x%02X  ( " _YELLOW_("anti clone marker") " )", dump[5]);
        PrintAndLogEx(INFO, "                    the tag answers 0x08, a clone written with this block 0 answers 0x88");
    }

    PrintAndLogEx(WARNING, _RED_("Anti clone counter measurements"));
    PrintAndLogEx(INFO, "This vendor is reported to count reader scans in sector " _YELLOW_("%u"), HEXACT_DATA_SECTOR_B);
    PrintAndLogEx(INFO, "Cloning or emulating a badge can desynchronise the original and lock you out");
    PrintAndLogEx(NORMAL, "");

    const uint8_t *id0 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 0);
    const uint8_t *id1 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 1);
    const uint8_t *id2 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 2);

    char system[16 + 16 + 16 + 3] = {0};
    str_append(system, sizeof(system), "%.16s", (const char *)id0);
    str_trim(system);

    if (id1) {
        str_append(system, sizeof(system), " %.16s", (const char *)id1);
        str_trim(system);
    }

    bool has_serial = (id2 != NULL) && (hexact_all_printable(id2, 4) == false);

    if (id2) {
        if (has_serial) {
            str_append(system, sizeof(system), " %.12s", (const char *)(id2 + 4));
        } else {
            str_append(system, sizeof(system), " %.16s", (const char *)id2);
        }
        str_trim(system);
    }

    PrintAndLogEx(INFO, "System............. " _YELLOW_("%s"), system);

    if (has_serial) {
        PrintAndLogEx(INFO, "Printed serial..... " _YELLOW_("%u"), MemLeToUint4byte(id2));
    }

    const uint8_t *s0b2 = hexact_sector(dump, dumplen, 0, 2);
    if (s0b2) {
        PrintAndLogEx(INFO, "Card identifier.... %s", sprint_hex_inrow(s0b2, 8));
    }

    if (s0b2 == NULL || id2 == NULL) {
        return PM3_SUCCESS;
    }

    uint8_t rec[HEXACT_PAYLOAD_BLOCKS][MFBLOCK_SIZE];
    bool written[HEXACT_PAYLOAD_BLOCKS] = {false};
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        const uint8_t *p = hexact_sector(dump, dumplen, hexact_payload[i].sector, hexact_payload[i].blk);
        if (p == NULL) {
            return PM3_SUCCESS;
        }
        hexact_decrypt(p, hexact_payload[i].sector, hexact_payload[i].blk, rec[i]);

        // an unwritten block decrypts to the bare keystream, not card data
        for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
            if (p[k] != 0x00 && p[k] != 0xFF) {
                written[i] = true;
                break;
            }
        }
    }

    bool all_zero = true, all_ff = true;
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {

        const uint8_t *p = hexact_sector(dump, dumplen, hexact_payload[i].sector, hexact_payload[i].blk);

        for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
            if (p[k] != 0x00) {
                all_zero = false;
            }

            if (p[k] != 0xFF) {
                all_ff = false;
            }
        }
    }

    if (all_zero || all_ff) {
        PrintAndLogEx(INFO, "Payload............ sector %u and %u, " _YELLOW_("%s"),
                      HEXACT_DATA_SECTOR_A, HEXACT_DATA_SECTOR_B,
                      all_ff ? "erased, card not personalised" : "not read"
                );
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Payload............ sector %u and %u, " _YELLOW_("mask removed"),
            HEXACT_DATA_SECTOR_A,
            HEXACT_DATA_SECTOR_B
        );

    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        char line[(2 * 16) + 4] = {0};
        str_append(line, sizeof(line), "%s  ", sprint_hex_inrow(rec[i], 8));
        str_append(line, sizeof(line), "%s", sprint_hex_inrow(rec[i] + 8, 8));
        PrintAndLogEx(INFO, "  sector %2u blk %u.. %s",
                    hexact_payload[i].sector,
                    hexact_payload[i].blk,
                    line
                );
    }

    const uint8_t *uid = dump;
    uint8_t ser[4];
    memcpy(ser, id2, sizeof(ser));

    // A card whose sector 0 block 2 has been wiped still carries identifier
    // bytes in the payload, so read them back instead of failing 21 checks.
    bool wiped = true;
    for (uint8_t k = 0; k < 8; k++) {
        if (s0b2[k]) {
            wiped = false;
            break;
        }
    }
    uint8_t idn[8] = {0};
    memcpy(idn, s0b2, sizeof(idn));

    if (wiped) {
        idn[0] = rec[2][0];
        idn[1] = rec[2][1];
        idn[4] = rec[2][4];
        idn[7] = rec[2][7];

        PrintAndLogEx(INFO, "Identifier......... " _YELLOW_("wiped") ", recovered from the payload:");
        PrintAndLogEx(INFO, "                    %02X %02X .. .. %02X .. .. %02X%s",
                      idn[0], idn[1], idn[4], idn[7],
                      (rec[1][1] == rec[2][1] && rec[1][4] == rec[2][4])
                      ? "   ( two sources agree )" : "   ( sources DISAGREE )");
    }

    uint8_t total = 0;
    uint8_t pass = 0;
    if (wiped == false) {
        pass = hexact_cross_check(rec, idn, uid, ser, written, &total, true);
    }

    if (spare_used) {
        uint8_t pt[MFBLOCK_SIZE];
        hexact_decrypt(spare, HEXACT_DATA_SECTOR_B, 2, pt);
        PrintAndLogEx(INFO, "  sector %2u blk 2.. %s  " _YELLOW_("( other generation )"),
                    HEXACT_DATA_SECTOR_B,
                    sprint_hex_inrow(pt, MFBLOCK_SIZE)
                );
    }

    if (wiped == false) {
        PrintAndLogEx(INFO, "Cross checks....... %u / %u  ( %s )", pass, total,
                      (pass == total) ? _GREEN_("bound bytes agree with sector 0, 15 and the UID")
                                      : _RED_("bound bytes disagree, see above")
                );
    }

    // two badges of one building carry the same row, two buildings never do
    char s9line[(3 * HEXACT_SITE_BYTES) + 1] = {0};
    char s11line[(3 * HEXACT_SITE_BYTES) + 1] = {0};
    uint16_t touched[HEXACT_PAYLOAD_BLOCKS] = {0};
    uint8_t srow[HEXACT_SITE_S9] = {0};
    uint8_t nrow = 0;

    for (size_t i = 0; i < HEXACT_SITE_BYTES; i++) {
        uint8_t v = 0;
        if (hexact_site_read(rec, idn, uid, ser, written, i, &v) == false) {
            continue;
        }
        touched[hexact_site[i].a_rec] |= (1 << hexact_site[i].a_pos);
        if (hexact_site[i].b_rec != HEXACT_SITE_NOPOS) {
            touched[hexact_site[i].b_rec] |= (1 << hexact_site[i].b_pos);
        }
        if (i < HEXACT_SITE_S9) {
            srow[i] = v;
            nrow++;
        }
        str_append((i < HEXACT_SITE_S9) ? s9line : s11line,
                   (3 * HEXACT_SITE_BYTES) + 1, "%02X ", v);
    }

    if (s9line[0]) {
        PrintAndLogEx(INFO, "Site constants..... %s ( " _YELLOW_("shared by every badge of one installation") " )", s9line);
    }
    if (s11line[0]) {
        PrintAndLogEx(INFO, "                    %s ( from sector %u block 0 )", s11line, HEXACT_DATA_SECTOR_B);
    }

    int inst = -1;
    if (nrow == HEXACT_SITE_S9) {
        for (size_t i = 0; i < ARRAYLEN(hexact_known_site); i++) {
            if (memcmp(srow, hexact_known_site[i], HEXACT_SITE_S9) == 0) {
                inst = (int)i;
                break;
            }
        }
    }

    bool want = false;
    if (nrow == HEXACT_SITE_S9 && inst < 0) {
        want = true;
    } else if (inst > 0) {
        want = true;
    } else if (spare_used) {
        want = true;
    }

    if (want) {
        PrintAndLogEx(HINT, "Hint: " _RED_("Report to Iceman!"));
    }

    if (wiped) {
        return PM3_SUCCESS;
    }

    for (size_t i = 0; i < ARRAYLEN(hexact_checks); i++) {
        if (written[hexact_checks[i].rec]) {
            touched[hexact_checks[i].rec] |= (1 << hexact_checks[i].pos);
        }
    }
    if (written[1] && written[2]) {
        touched[1] |= (1 << 7);
        touched[2] |= (1 << 15);
    }

    uint8_t nread = 0, npayload = 0;
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        if (written[i] == false) {
            continue;
        }
        npayload += MFBLOCK_SIZE;
        for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
            if (touched[i] & (1 << k)) {
                nread++;
            }
        }
    }

    PrintAndLogEx(INFO, "                    %u of %u payload bytes are issuer data, read by nothing",
                  npayload - nread, npayload);

    return PM3_SUCCESS;
}

static void hexact_build_selftest_card(uint8_t *dump, uint8_t v1) {
    static const uint8_t uid[4] = {0x1A, 0x2B, 0x3C, 0x61};
    static const uint8_t idn[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    static const uint8_t ser[4] = {0xD2, 0x04, 0x00, 0x00};       // 1234 little endian

    memcpy(dump, uid, sizeof(uid));
    dump[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    dump[5] = HEXACT_BLOCK0_SAK;
    dump[6] = 0x04;
    memcpy(dump + (2 * MFBLOCK_SIZE), idn, sizeof(idn));
    memcpy(dump + (mfFirstBlockOfSector(HEXACT_ID_SECTOR) * MFBLOCK_SIZE), hexact_marker, sizeof(hexact_marker));
    memcpy(dump + ((mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE), ser, sizeof(ser));

    uint8_t v3 = v1 ^ uid[1] ^ 0xD0;

    uint8_t rec[HEXACT_PAYLOAD_BLOCKS][MFBLOCK_SIZE];
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
            rec[i][k] = (uint8_t)(0xA0 + (i * MFBLOCK_SIZE) + k);   // filler
        }
    }

    for (size_t i = 0; i < ARRAYLEN(hexact_checks); i++) {
        const hexact_check_t *c = &hexact_checks[i];
        rec[c->rec][c->pos] = hexact_expect(c, idn, uid, ser);
    }

    rec[1][7]  = v1;
    rec[2][15] = v1;
    rec[4][7]  = v1;
    rec[0][15] = v3;
    rec[3][15] = v3 ^ 0xB1;

    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {

        uint8_t seed = hexact_seed(hexact_payload[i].sector, hexact_payload[i].blk);
        uint8_t *dst = dump + ((mfFirstBlockOfSector(hexact_payload[i].sector) + hexact_payload[i].blk) * MFBLOCK_SIZE);

        for (uint8_t k = 0; k < MFBLOCK_SIZE; k++) {
            dst[k] = rec[i][k] ^ hexact_rotl(seed, k);
        }
    }
}

int hexact_selftest(void) {

    PrintAndLogEx(INFO, "Testing Hexact payload mask and cross checks");

    uint8_t dump[MIFARE_1K_MAX_BYTES] = {0};
    hexact_build_selftest_card(dump, 0x5A);

    if (is_valid_hexact_card(dump, sizeof(dump)) == false) {
        PrintAndLogEx(FAILED, "  card not recognised ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    uint8_t rec[HEXACT_PAYLOAD_BLOCKS][MFBLOCK_SIZE];
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        hexact_decrypt(dump + ((mfFirstBlockOfSector(hexact_payload[i].sector) + hexact_payload[i].blk) * MFBLOCK_SIZE),
                    hexact_payload[i].sector,
                    hexact_payload[i].blk,
                    rec[i]
                );
    }

    bool written[HEXACT_PAYLOAD_BLOCKS];
    memset(written, true, sizeof(written));

    uint8_t total = 0;
    uint8_t pass = hexact_cross_check(
                        rec,
                        dump + (2 * MFBLOCK_SIZE),
                        dump,
                        dump + (mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE,
                        written,
                        &total,
                        false
                    );

    PrintAndLogEx(INFO, "  intact card........ %u / %u  ( %s )",
                pass,
                total,
                (pass == total) ? _GREEN_("ok") : _RED_("fail")
    );

    if (pass != total) {
        return PM3_ESOFT;
    }

    dump[0] ^= 0x01;
    uint8_t broken = hexact_cross_check(
                        rec,
                        dump + (2 * MFBLOCK_SIZE),
                        dump,
                        dump + (mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE,
                        written,
                        &total,
                        false
                );

    PrintAndLogEx(INFO, "  one UID bit flipped %u / %u  ( %s )"
                        , broken
                        , total
                        , (broken == total - 4) ? _GREEN_("ok") : _RED_("fail")
                );

    if (broken != total - 4) {
        return PM3_ESOFT;
    }

    dump[0] ^= 0x01;

    // the two offsets the builder knows, read back through the table
    uint8_t v3 = 0, v4 = 0;
    const uint8_t *sser = dump + ((mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE);
    bool ok = hexact_site_read(rec, dump + (2 * MFBLOCK_SIZE), dump, sser, written, 6, &v3);
    ok &= hexact_site_read(rec, dump + (2 * MFBLOCK_SIZE), dump, sser, written, 11, &v4);

    PrintAndLogEx(INFO, "  site constants..... %02X %02X  ( %s )", v3, v4,
                  (ok && v3 == 0xD0 && v4 == 0xB1) ? _GREEN_("ok") : _RED_("fail"));

    if (ok == false || v3 != 0xD0 || v4 != 0xB1) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Hexact self test " _GREEN_("passed"));
    return PM3_SUCCESS;
}
