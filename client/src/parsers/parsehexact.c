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
// The sector 9 and 11 payload is XORed with an estate wide keystream that is
// one seed byte per block rotated left by the byte index,
//
//     mask[k] = rotl(seed, k mod 8)       seed = base ^ (2 * block in sector)
//     base = 0xB3 for sector 9, 0x5C for sector 11
//
// so the whole eighty byte keystream comes from two bytes. Removing it leaves
// ten eight byte records. Eighteen of their eighty bytes are XOR combinations
// of data that is readable elsewhere on the card, and three more are fixed
// relations between the records themselves, which together make a consistency
// check: a card assembled from parts, or a payload copied onto a different
// UID, fails it. The other bytes are keyed issuer data and stay unexplained,
// so they are printed and not interpreted.
//-----------------------------------------------------------------------------

#include "parsehexact.h"

#include <string.h>
#include <ctype.h>                // tolower

#include "commonutil.h"
#include "ui.h"                 // PrintAndLogEx
#include "util.h"               // sprint_hex
#include "mifare/mifaredefault.h"   // MFBLOCK_SIZE
#include "mifare/mifare4.h"     // mfFirstBlockOfSector

#define HEXACT_ID_SECTOR        15
#define HEXACT_DATA_SECTOR_A     9
#define HEXACT_DATA_SECTOR_B    11

// Sector 15 block 0 spells the system out. The text is the same on every card
// but the case is not: factory blanks of an older generation carry
// "HEXACT - COGELEC" and the personalised fobs carry "hExact - COGELEC", so the
// compare has to ignore case or it misses half the cards. Sector 15 is written
// at the factory and then locked read only, which is why one card cannot have
// both spellings.
static const uint8_t hexact_marker[] = {
    'h', 'e', 'x', 'a', 'c', 't', ' ', '-', ' ', 'c', 'o', 'g', 'e', 'l', 'e', 'c'
};

// Block 0 of these cards advertises SAK 0x88 while the tag itself answers 0x08.
// A magic card written with that block 0 answers 0x88 in anticollision too,
// which is how the readers spot a clone.
#define HEXACT_BLOCK0_SAK       0x88

// The payload keystream. One seed byte per block, rotated left by the byte
// index, so it repeats every eight bytes and the whole eighty byte stream comes
// from the two base values below.
#define HEXACT_SEED_BASE_A      0xB3
#define HEXACT_SEED_BASE_B      0x5C

// The five payload blocks, in the order the cross checks below index them
static const struct {
    uint8_t sector;
    uint8_t blk;
} hexact_payload[] = {
    {HEXACT_DATA_SECTOR_A, 0}, {HEXACT_DATA_SECTOR_A, 1}, {HEXACT_DATA_SECTOR_A, 2},
    {HEXACT_DATA_SECTOR_B, 0}, {HEXACT_DATA_SECTOR_B, 1},
};
#define HEXACT_PAYLOAD_BLOCKS   ARRAYLEN(hexact_payload)

// Where a recovered byte has to come from. idx picks the identifier byte, and
// for HX_ID_SER the serial byte at the same index. The record adds a fixed
// constant on top, which is why xr is there.
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
    {0,  0, HX_ID_SER, 0, 0xFF}, {0,  1, HX_ID_SER, 1, 0xFF},
    {0,  4, HX_ID,     4, 0xFE}, {0,  7, HX_ID_UID, 7, 0x00},
    {1,  1, HX_ID,     1, 0x00}, {1,  4, HX_ID,     4, 0x00},
    {1, 15, HX_ID_UID, 7, 0x00},
    {2,  0, HX_ID,     0, 0x00}, {2,  1, HX_ID,     1, 0x00},
    {2,  4, HX_ID,     4, 0x00}, {2,  7, HX_ID,     7, 0x00},
    {3,  0, HX_ID,     0, 0x36}, {3,  1, HX_ID,     1, 0x80},
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


// Run the 21 checks. Eighteen tie a record byte to card data held elsewhere,
// three tie the records to each other. Returns how many passed.
#define HEXACT_MAX_SHOWN    5

static uint8_t hexact_cross_check(const uint8_t rec[][MFBLOCK_SIZE], const uint8_t *idn,
                                  const uint8_t *uid, const uint8_t *ser,
                                  uint8_t *total, bool verbose) {
    uint8_t pass = 0, shown = 0;
    *total = 0;

    for (size_t i = 0; i < ARRAYLEN(hexact_checks); i++) {
        const hexact_check_t *c = &hexact_checks[i];
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

    // byte 7 of the records is a lag two sliding window over two seeds, one of
    // them idn[7]; these three ties are what is left of it after the card data
    // checks above have taken the rest
    const uint8_t tie_got[3]  = { rec[2][15], rec[0][15], rec[3][15] };
    const uint8_t tie_want[3] = { rec[1][7],
                                  (uint8_t)(rec[1][7] ^ uid[1] ^ 0xD0),
                                  (uint8_t)(rec[0][15] ^ 0xB1) };
    for (size_t i = 0; i < ARRAYLEN(tie_got); i++) {
        (*total)++;
        if (tie_got[i] == tie_want[i]) {
            pass++;
        } else if (verbose && shown++ < HEXACT_MAX_SHOWN) {
            PrintAndLogEx(INFO, "  mismatch......... record tie %zu is %02X, expected %02X",
                          i, tie_got[i], tie_want[i]);
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

    const uint8_t *id0 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 0);
    const uint8_t *id1 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 1);
    const uint8_t *id2 = hexact_sector(dump, dumplen, HEXACT_ID_SECTOR, 2);

    // The sector spells the system out across its three blocks and it reads as
    // one line, so join them. Each block pads its text with spaces, and the
    // last one keeps four bytes of its own before the text starts.
    char system[16 + 16 + 16 + 3] = {0};
    str_append(system, sizeof(system), "%.16s", (const char *)id0);
    str_trim(system);

    if (id1) {
        str_append(system, sizeof(system), " %.16s", (const char *)id1);
        str_trim(system);
    }

    // Sector 15 block 2 holds the number engraved on the fob, little endian,
    // in front of the INTRATONE text. Checked against the engraving on four
    // fobs, all four matched. A card that was never personalised carries text
    // all the way across instead, and reading its first four bytes as a number
    // gives nonsense, so let the data say which shape this is.
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

    if (s0b2 == NULL || id2 == NULL) {
        return PM3_SUCCESS;
    }

    uint8_t rec[HEXACT_PAYLOAD_BLOCKS][MFBLOCK_SIZE];
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        const uint8_t *p = hexact_sector(dump, dumplen, hexact_payload[i].sector, hexact_payload[i].blk);
        if (p == NULL) {
            return PM3_SUCCESS;
        }
        hexact_decrypt(p, hexact_payload[i].sector, hexact_payload[i].blk, rec[i]);
    }

    // Two states are not a payload at all and decrypting them just prints the
    // keystream back with every check failing. All zero means the dump never
    // read those sectors. All FF means the card was never personalised: a
    // factory blank has its payload erased, and sector 15 block 2 says so.
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
                      all_ff ? "erased, card not personalised" : "not read");
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Payload............ sector %u and %u, " _YELLOW_("mask removed"),
                  HEXACT_DATA_SECTOR_A, HEXACT_DATA_SECTOR_B);
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        // the two eight byte records of the block, kept apart on the line.
        // sprint_hex_inrow hands back one static buffer, so the first half has
        // to be copied out before the second call overwrites it
        char line[(2 * 16) + 4] = {0};
        str_append(line, sizeof(line), "%s  ", sprint_hex_inrow(rec[i], 8));
        str_append(line, sizeof(line), "%s", sprint_hex_inrow(rec[i] + 8, 8));
        PrintAndLogEx(INFO, "  sector %2u blk %u.. %s",
                      hexact_payload[i].sector, hexact_payload[i].blk, line);
    }

    // Eighteen of those bytes have to equal card data held in sector 0 and
    // sector 15, and three more tie the records to each other. Together they
    // say whether the payload was issued for this fob: a payload copied onto
    // another UID breaks the uid terms, a rewritten sector 0 breaks the rest.
    const uint8_t *uid = dump;
    uint8_t ser[4];
    memcpy(ser, id2, sizeof(ser));

    uint8_t total = 0;
    uint8_t pass = hexact_cross_check(rec, s0b2, uid, ser, &total, true);

    // Say what this does and does not mean. The 21 checks read 22 of the 80
    // payload bytes, so a random single byte change anywhere in the payload is
    // caught 27.5% of the time, and a payload assembled from two fobs can pass.
    // Only uid1 and uid0^uid2 enter, so 2^16 of the 2^32 UIDs accept a copy of
    // this payload unaltered. It is an integrity check, not an authenticity one.
    PrintAndLogEx(INFO, "Cross checks....... %u / %u  ( %s )", pass, total,
                  (pass == total) ? _GREEN_("bound bytes agree with sector 0, 15 and the UID")
                                  : _RED_("bound bytes disagree, see above"));
    PrintAndLogEx(INFO, "                    %u of 80 payload bytes are issuer data and unchecked",
                  80 - 22);
    return PM3_SUCCESS;
}

// Build a card from the model rather than from a real fob: the record bytes
// that the checks look at are filled in from a made up UID, identifier and
// serial, the rest with a pattern, and the whole payload is then masked. No
// resident's credential goes into the tree. This exercises the mask and the
// cross check; the printing path is covered by running the parser on a dump.
static void hexact_build_selftest_card(uint8_t *dump, uint8_t v1) {
    static const uint8_t uid[4] = {0x1A, 0x2B, 0x3C, 0x61};
    static const uint8_t idn[8] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    static const uint8_t ser[4] = {0xD2, 0x04, 0x00, 0x00};       // 1234 little endian

    memcpy(dump, uid, sizeof(uid));
    dump[4] = uid[0] ^ uid[1] ^ uid[2] ^ uid[3];
    dump[5] = HEXACT_BLOCK0_SAK;
    dump[6] = 0x04;
    memcpy(dump + (2 * MFBLOCK_SIZE), idn, sizeof(idn));
    memcpy(dump + (mfFirstBlockOfSector(HEXACT_ID_SECTOR) * MFBLOCK_SIZE),
           hexact_marker, sizeof(hexact_marker));
    memcpy(dump + ((mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE),
           ser, sizeof(ser));

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
        uint8_t *dst = dump + ((mfFirstBlockOfSector(hexact_payload[i].sector)
                                + hexact_payload[i].blk) * MFBLOCK_SIZE);
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

    // the decoder has to recover the records the builder put in
    uint8_t rec[HEXACT_PAYLOAD_BLOCKS][MFBLOCK_SIZE];
    for (uint8_t i = 0; i < HEXACT_PAYLOAD_BLOCKS; i++) {
        hexact_decrypt(dump + ((mfFirstBlockOfSector(hexact_payload[i].sector)
                                + hexact_payload[i].blk) * MFBLOCK_SIZE),
                       hexact_payload[i].sector, hexact_payload[i].blk, rec[i]);
    }

    uint8_t total = 0;
    uint8_t pass = hexact_cross_check(rec, dump + (2 * MFBLOCK_SIZE), dump,
                                      dump + (mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE,
                                      &total, false);
    PrintAndLogEx(INFO, "  intact card........ %u / %u  ( %s )", pass, total,
                  (pass == total) ? _GREEN_("ok") : _RED_("fail"));
    if (pass != total) {
        return PM3_ESOFT;
    }

    // and a negative, so a decoder that always says yes cannot pass this test.
    // Flipping a bit in uid0 must break exactly the four positions that carry
    // uid0^uid2. uid1 enters only through a record tie, which reads the card's
    // own bytes and so is unaffected here.
    dump[0] ^= 0x01;
    uint8_t broken = hexact_cross_check(rec, dump + (2 * MFBLOCK_SIZE), dump,
                                        dump + (mfFirstBlockOfSector(HEXACT_ID_SECTOR) + 2) * MFBLOCK_SIZE,
                                        &total, false);
    PrintAndLogEx(INFO, "  one UID bit flipped %u / %u  ( %s )", broken, total,
                  (broken == total - 4) ? _GREEN_("ok") : _RED_("fail"));
    if (broken != total - 4) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Hexact self test " _GREEN_("passed"));
    return PM3_SUCCESS;
}
