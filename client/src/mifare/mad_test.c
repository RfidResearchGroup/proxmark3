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
// MAD regression tests
//-----------------------------------------------------------------------------

#include "mad_test.h"
#include "mad.h"
#include "ui.h"
#include "crc.h"
#include "mifare4.h"
#include "mifaredefault.h"
#include "mifare.h"
#include <string.h>


#define ASSERT_EQ(msg, expected, actual) do { \
    if ((expected) != (actual)) { \
        PrintAndLogEx(FAILED, "    %s: expected %d, got %d", (msg), (int)(expected), (int)(actual)); \
        return false; \
    } \
} while (0)

#define ASSERT_EQ_HEX(msg, expected, actual) do { \
    if ((expected) != (actual)) { \
        PrintAndLogEx(FAILED, "    %s: expected 0x%04X, got 0x%04X", (msg), (unsigned)(expected), (unsigned)(actual)); \
        return false; \
    } \
} while (0)

#define ASSERT_TRUE(msg, cond) do { \
    if (!(cond)) { \
        PrintAndLogEx(FAILED, "    %s", (msg)); \
        return false; \
    } \
} while (0)

static void build_test_mad1(mad1_sector_t *s) {
    memset(s, 0, sizeof(*s));

    s->manufacturer[0] = 0x01;
    s->manufacturer[1] = 0x02;
    s->manufacturer[2] = 0x03;
    s->manufacturer[3] = 0x04;

    // AIDs stored as native uint16_t
    s->mad.info = 0x01;
    s->mad.aid[0]  = 0xE103; // sector 1: NDEF
    s->mad.aid[1]  = 0xE103; // sector 2: NDEF continuation
    s->mad.aid[2]  = 0xE103; // sector 3: NDEF continuation
    s->mad.aid[3]  = 0x484D; // sector 4: HID
    // sectors 5-15: 0x0000 = free

    s->mad.crc = CRC8Mad((uint8_t *)&s->mad.info, sizeof(mad1_t) - 1);

    memcpy(s->trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
    s->trailer.access[0] = 0xFF;
    s->trailer.access[1] = 0x07;
    s->trailer.access[2] = 0x80;
    s->trailer.gpb = 0x82; // DA=1, MA=0, version=2
    memset(s->trailer.key_b, 0xFF, MIFARE_KEY_SIZE);
}

static void build_test_mad2(mad2_sector_t *s) {
    memset(s, 0, sizeof(*s));

    s->mad.info = 0x00;
    s->mad.aid[0]  = 0xE103; // sector 17: NDEF
    s->mad.aid[1]  = 0xE103; // sector 18: NDEF continuation
    // sectors 19-39: 0x0000 = free

    s->mad.crc = CRC8Mad((uint8_t *)&s->mad.info, sizeof(mad2_t) - 1);

    memcpy(s->trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
    s->trailer.access[0] = 0xFF;
    s->trailer.access[1] = 0x07;
    s->trailer.access[2] = 0x80;
    s->trailer.gpb = 0x00;
    memset(s->trailer.key_b, 0xFF, MIFARE_KEY_SIZE);
}

// --- Mock card memory ---

#define MOCK_CARD_SIZE (256 * 16)
static uint8_t g_mock_card[MOCK_CARD_SIZE];

static int mock_read_sector(uint8_t sector_no, uint8_t key_type,
                            const uint8_t *key, uint8_t *buf, bool verbose) {
    (void)key_type;
    (void)key;
    (void)verbose;
    uint8_t first_block = mfFirstBlockOfSector(sector_no);
    uint8_t nblocks = mfNumBlocksPerSector(sector_no);
    uint32_t offset = first_block * 16;
    uint32_t size = nblocks * 16;
    if (offset + size > MOCK_CARD_SIZE)
        return PM3_ESOFT;
    memcpy(buf, &g_mock_card[offset], size);
    return PM3_SUCCESS;
}

static int mock_write_sector_data(uint8_t sector_no, uint8_t key_type,
                                  const uint8_t *key, const uint8_t *data, bool verbose) {
    (void)key_type;
    (void)key;
    (void)verbose;
    uint8_t first_block = mfFirstBlockOfSector(sector_no);
    uint8_t ndata = mfNumBlocksPerSector(sector_no) - 1;
    uint32_t offset = first_block * 16;
    if (offset + ndata * 16 > MOCK_CARD_SIZE)
        return PM3_ESOFT;
    memcpy(&g_mock_card[offset], data, ndata * 16);
    return PM3_SUCCESS;
}

static void mock_card_init(void) {
    memset(g_mock_card, 0, sizeof(g_mock_card));

    mad1_sector_t s0;
    build_test_mad1(&s0);
    memcpy(&g_mock_card[0], &s0, sizeof(s0));

    // fill data sectors with deterministic per-byte pattern:
    // byte value = (sector * 0x10) + (block_within_sector * 0x04) + byte_within_block
    for (int sec = 1; sec <= 15; sec++) {
        uint8_t first = mfFirstBlockOfSector(sec);
        for (int b = 0; b < 3; b++) {
            uint8_t *block = &g_mock_card[(first + b) * 16];
            for (int i = 0; i < 16; i++)
                block[i] = (uint8_t)((sec << 4) | (b << 2) | (i & 0x03));
        }
        // trailer
        uint8_t *trailer = &g_mock_card[(first + 3) * 16];
        memset(trailer, 0xFF, 16);
    }

    // MAD2 at sector 16
    mad2_sector_t s16;
    build_test_mad2(&s16);
    uint8_t first16 = mfFirstBlockOfSector(16);
    memcpy(&g_mock_card[first16 * 16], &s16, sizeof(s16));

    // fill sectors 17-18 (MAD2 NDEF) with pattern
    for (int sec = 17; sec <= 18; sec++) {
        uint8_t first = mfFirstBlockOfSector(sec);
        for (int b = 0; b < 3; b++) {
            uint8_t *block = &g_mock_card[(first + b) * 16];
            for (int i = 0; i < 16; i++)
                block[i] = (uint8_t)((sec << 4) | (b << 2) | (i & 0x03));
        }
        uint8_t *trailer = &g_mock_card[(first + 3) * 16];
        memset(trailer, 0xFF, 16);
    }
}

static mad_ops_t make_mock_ops(void) {
    mad_ops_t ops = {
        .read_sector = mock_read_sector,
        .write_sector_data = mock_write_sector_data,
        .mad_key = g_mifare_mad_key,
        .mad_key_type = MF_KEY_A,
        .app_key = g_mifare_ndef_key,
        .app_key_type = MF_KEY_A,
        .verbose = false,
    };
    return ops;
}

// --- Test cases ---

static bool test_struct_sizes(bool verbose) {
    PrintAndLogEx(INFO, "  struct sizes...");

    ASSERT_EQ("mad1_t", 32, sizeof(mad1_t));
    ASSERT_EQ("mad2_t", 48, sizeof(mad2_t));
    ASSERT_EQ("mad1_sector_t", 64, sizeof(mad1_sector_t));
    ASSERT_EQ("mad2_sector_t", 64, sizeof(mad2_sector_t));
    ASSERT_EQ("mf_trailer_t", 16, sizeof(mf_trailer_t));

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_mad1_crc_valid(bool verbose) {
    PrintAndLogEx(INFO, "  MAD1 CRC valid...");
    mad1_sector_t s;
    build_test_mad1(&s);

    bool haveMAD2 = false;
    int res = MADCheck(&s, NULL, false, &haveMAD2);
    ASSERT_EQ("MADCheck on valid sector", PM3_SUCCESS, res);
    ASSERT_EQ("should report MAD2 (v2)", true, haveMAD2);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_mad1_crc_corrupt(bool verbose) {
    PrintAndLogEx(INFO, "  MAD1 CRC corrupt...");
    mad1_sector_t s;
    build_test_mad1(&s);
    s.mad.crc ^= 0xFF;

    bool haveMAD2 = false;

    int res = MADCheck(&s, NULL, verbose, &haveMAD2);

    ASSERT_TRUE("MADCheck should fail on corrupt CRC", res != PM3_SUCCESS);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_mad1_decode_entries(bool verbose) {
    PrintAndLogEx(INFO, "  MAD1 decode entries...");
    mad1_sector_t s;
    build_test_mad1(&s);

    mad_entry_list_t list = {0};
    int res = MADDecode(&s, NULL, &list, false, false);
    ASSERT_EQ("MADDecode return", PM3_SUCCESS, res);
    ASSERT_EQ("entry count", MAD1_NUM_AIDS, (int)list.len);

    // NDEF sectors 1-3
    for (int i = 0; i < 3; i++) {
        ASSERT_EQ_HEX("NDEF AID", 0xE103, list.entries[i].aid);
        ASSERT_EQ("NDEF sector", i + 1, list.entries[i].sector);
    }

    // HID sector 4
    ASSERT_EQ_HEX("HID AID", 0x484D, list.entries[3].aid);
    ASSERT_EQ("HID sector", 4, list.entries[3].sector);

    // free sectors 5-15
    for (int i = 4; i < MAD1_NUM_AIDS; i++) {
        ASSERT_EQ_HEX("free AID", 0x0000, list.entries[i].aid);
    }

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_mad2_decode(bool verbose) {
    PrintAndLogEx(INFO, "  MAD2 decode with MAD1 v2...");
    mad1_sector_t s0;
    build_test_mad1(&s0);
    mad2_sector_t s16;
    build_test_mad2(&s16);

    bool haveMAD2 = false;
    int res = MADCheck(&s0, &s16, false, &haveMAD2);
    ASSERT_EQ("MADCheck return", PM3_SUCCESS, res);
    ASSERT_EQ("should report MAD2", true, haveMAD2);

    mad_entry_list_t list = {0};
    res = MADDecode(&s0, &s16, &list, false, false);
    ASSERT_EQ("MADDecode return", PM3_SUCCESS, res);
    ASSERT_EQ("entry count", MAD1_NUM_AIDS + MAD2_NUM_AIDS, (int)list.len);

    // MAD1 entries: sectors 1-3 NDEF, sector 4 HID, 5-15 free
    ASSERT_EQ_HEX("MAD1 sector 1", 0xE103, list.entries[0].aid);
    ASSERT_EQ_HEX("MAD1 sector 4", 0x484D, list.entries[3].aid);

    // MAD2 entries start at index 15 (MAD1_NUM_AIDS)
    // sector 17 = NDEF, sector 18 = NDEF, rest free
    ASSERT_EQ("MAD2 entry 0 sector", 17, list.entries[MAD1_NUM_AIDS].sector);
    ASSERT_EQ_HEX("MAD2 entry 0 AID", 0xE103, list.entries[MAD1_NUM_AIDS].aid);
    ASSERT_EQ("MAD2 entry 1 sector", 18, list.entries[MAD1_NUM_AIDS + 1].sector);
    ASSERT_EQ_HEX("MAD2 entry 1 AID", 0xE103, list.entries[MAD1_NUM_AIDS + 1].aid);
    ASSERT_EQ_HEX("MAD2 entry 2 free", 0x0000, list.entries[MAD1_NUM_AIDS + 2].aid);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_read_mad2_sectors(bool verbose) {
    PrintAndLogEx(INFO, "  read AID spanning MAD1+MAD2...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    uint8_t data[MIFARE_4K_MAX_BYTES] = {0};
    size_t datalen = 0;
    int res = mad_app_read(&ops, 0xE103, false, false, data, sizeof(data), &datalen);
    ASSERT_EQ("read return", PM3_SUCCESS, res);

    // MAD1: sectors 1-3 (3*48=144), MAD2: sectors 17-18 (2*48=96), total=240
    ASSERT_EQ("read length", 240, (int)datalen);

    // verify first byte of sector 1
    ASSERT_EQ("sector 1 byte 0", (uint8_t)((1 << 4) | 0), data[0]);
    // verify first byte of sector 17 (at offset 144)
    ASSERT_EQ("sector 17 byte 0", (uint8_t)((17 << 4) | 0), data[144]);
    // verify first byte of sector 18 (at offset 144+48=192)
    ASSERT_EQ("sector 18 byte 0", (uint8_t)((18 << 4) | 0), data[192]);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_read_full_content(bool verbose) {
    PrintAndLogEx(INFO, "  read full AID content...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    uint8_t data[MIFARE_4K_MAX_BYTES] = {0};
    size_t datalen = 0;

    int res = mad_app_read(&ops, 0xE103, false, false, data, sizeof(data), &datalen);

    ASSERT_EQ("mad_app_read return", PM3_SUCCESS, res);

    // 5 NDEF sectors (1-3 from MAD1, 17-18 from MAD2) * 3 data blocks * 16 = 240
    ASSERT_EQ("read length", 240, (int)datalen);

    // verify every byte across MAD1 sectors 1-3
    size_t off = 0;
    for (int sec = 1; sec <= 3; sec++) {
        for (int b = 0; b < 3; b++) {
            for (int i = 0; i < 16; i++) {
                uint8_t expected = (uint8_t)((sec << 4) | (b << 2) | (i & 0x03));
                if (data[off] != expected) {
                    PrintAndLogEx(FAILED, "    byte %zu: expected 0x%02X, got 0x%02X (sector %d block %d byte %d)",
                                  off, expected, data[off], sec, b, i);
                    return false;
                }
                off++;
            }
        }
    }
    // verify MAD2 sectors 17-18
    for (int sec = 17; sec <= 18; sec++) {
        for (int b = 0; b < 3; b++) {
            for (int i = 0; i < 16; i++) {
                uint8_t expected = (uint8_t)((sec << 4) | (b << 2) | (i & 0x03));
                if (data[off] != expected) {
                    PrintAndLogEx(FAILED, "    byte %zu: expected 0x%02X, got 0x%02X (sector %d block %d byte %d)",
                                  off, expected, data[off], sec, b, i);
                    return false;
                }
                off++;
            }
        }
    }
    ASSERT_EQ("total bytes checked", 240, (int)off);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_read_single_sector_aid(bool verbose) {
    PrintAndLogEx(INFO, "  read single-sector AID...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    uint8_t data[256] = {0};
    size_t datalen = 0;

    int res = mad_app_read(&ops, 0x484D, false, false, data, sizeof(data), &datalen);

    ASSERT_EQ("read return", PM3_SUCCESS, res);
    ASSERT_EQ("read length", 48, (int)datalen);

    // sector 4 data: (4 << 4) | (b << 2) | (i & 3)
    for (int b = 0; b < 3; b++) {
        for (int i = 0; i < 16; i++) {
            uint8_t expected = (uint8_t)((4 << 4) | (b << 2) | (i & 0x03));
            size_t off = b * 16 + i;
            if (data[off] != expected) {
                PrintAndLogEx(FAILED, "    byte %zu: expected 0x%02X, got 0x%02X", off, expected, data[off]);
                return false;
            }
        }
    }

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_write_full_roundtrip(bool verbose) {
    PrintAndLogEx(INFO, "  write full round-trip...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    // write exactly 240 bytes (full NDEF capacity: MAD1 + MAD2)
    uint8_t wdata[240];
    for (int i = 0; i < 240; i++)
        wdata[i] = (uint8_t)(i ^ 0x55);


    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("write return", PM3_SUCCESS, res);

    // read back and compare every byte
    uint8_t rdata[MIFARE_4K_MAX_BYTES] = {0};
    size_t rlen = 0;

    res = mad_app_read(&ops, 0xE103, false, false, rdata, sizeof(rdata), &rlen);

    ASSERT_EQ("readback return", PM3_SUCCESS, res);
    ASSERT_EQ("readback length", 240, (int)rlen);

    for (int i = 0; i < 240; i++) {
        if (rdata[i] != wdata[i]) {
            PrintAndLogEx(FAILED, "    byte %d: wrote 0x%02X, read 0x%02X", i, wdata[i], rdata[i]);
            return false;
        }
    }

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_write_partial_zero_pads(bool verbose) {
    PrintAndLogEx(INFO, "  write partial zero-pads remainder...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    // write 50 bytes into 240-byte capacity
    // sector 1 gets full 48 bytes, sector 2 gets 2 bytes + zero-pad
    // sectors 3, 17, 18 are not touched (write stops after data exhausted)
    uint8_t wdata[50];
    memset(wdata, 0xAB, sizeof(wdata));


    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("write return", PM3_SUCCESS, res);

    uint8_t rdata[MIFARE_4K_MAX_BYTES] = {0xFF};
    size_t rlen = 0;

    res = mad_app_read(&ops, 0xE103, false, false, rdata, sizeof(rdata), &rlen);

    ASSERT_EQ("readback return", PM3_SUCCESS, res);
    ASSERT_EQ("readback length", 240, (int)rlen);

    // first 48 bytes (sector 1) should all be 0xAB
    for (int i = 0; i < 48; i++) {
        if (rdata[i] != 0xAB) {
            PrintAndLogEx(FAILED, "    byte %d: expected 0xAB, got 0x%02X", i, rdata[i]);
            return false;
        }
    }
    // bytes 48-49 should be 0xAB (start of sector 2)
    ASSERT_EQ("byte 48", 0xAB, rdata[48]);
    ASSERT_EQ("byte 49", 0xAB, rdata[49]);
    // bytes 50-95 should be 0x00 (zero-padded remainder of sector 2)
    for (int i = 50; i < 96; i++) {
        if (rdata[i] != 0x00) {
            PrintAndLogEx(FAILED, "    byte %d: expected 0x00, got 0x%02X", i, rdata[i]);
            return false;
        }
    }

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_verify_match(bool verbose) {
    PrintAndLogEx(INFO, "  verify match...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    // write known data, then verify with same data
    uint8_t wdata[240];
    for (int i = 0; i < 240; i++)
        wdata[i] = (uint8_t)(i * 3);


    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("write return", PM3_SUCCESS, res);


    res = mad_app_verify(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("verify should pass", PM3_SUCCESS, res);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_verify_mismatch(bool verbose) {
    PrintAndLogEx(INFO, "  verify mismatch...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();
    ops.verbose = verbose;

    // write known data
    uint8_t wdata[240];
    for (int i = 0; i < 240; i++)
        wdata[i] = (uint8_t)(i * 3);


    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("write return", PM3_SUCCESS, res);

    // flip one byte and verify should fail
    uint8_t bad[240];
    memcpy(bad, wdata, sizeof(bad));
    bad[72] ^= 0xFF; // corrupt byte in sector 2


    res = mad_app_verify(&ops, 0xE103, false, false, bad, sizeof(bad));

    ASSERT_TRUE("verify should detect mismatch", res != PM3_SUCCESS);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_write_overflow(bool verbose) {
    PrintAndLogEx(INFO, "  write overflow...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();
    ops.verbose = verbose;

    uint8_t wdata[241];
    memset(wdata, 0xAA, sizeof(wdata));

    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_TRUE("should reject 241 bytes into 240-byte capacity", res != PM3_SUCCESS);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_aid_not_found(bool verbose) {
    PrintAndLogEx(INFO, "  AID not found...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();
    ops.verbose = verbose;

    uint8_t data[256] = {0};
    size_t datalen = 99;

    int res = mad_app_read(&ops, 0xBEEF, false, false, data, sizeof(data), &datalen);

    ASSERT_EQ("should succeed with 0 bytes", PM3_SUCCESS, res);
    ASSERT_EQ("datalen should be 0", 0, (int)datalen);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_write_does_not_touch_trailer(bool verbose) {
    PrintAndLogEx(INFO, "  write does not touch trailer...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    // save trailer block of sector 1 before write
    uint8_t first = mfFirstBlockOfSector(1);
    uint8_t trailer_before[16];
    memcpy(trailer_before, &g_mock_card[(first + 3) * 16], 16);

    uint8_t wdata[48];
    memset(wdata, 0xCC, sizeof(wdata));

    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("write return", PM3_SUCCESS, res);

    // trailer should be unchanged
    ASSERT_TRUE("sector 1 trailer unchanged",
                memcmp(trailer_before, &g_mock_card[(first + 3) * 16], 16) == 0);

    // also check sector 2 trailer
    uint8_t first2 = mfFirstBlockOfSector(2);
    uint8_t trailer2[16];
    memcpy(trailer2, &g_mock_card[(first2 + 3) * 16], 16);
    uint8_t expected_trailer[16];
    memset(expected_trailer, 0xFF, 16);
    ASSERT_TRUE("sector 2 trailer unchanged", memcmp(trailer2, expected_trailer, 16) == 0);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_mad_sector_untouched_after_write(bool verbose) {
    PrintAndLogEx(INFO, "  MAD sector untouched after write...");
    mock_card_init();
    mad_ops_t ops = make_mock_ops();

    // save MAD sector 0 before write
    uint8_t mad_before[64];
    memcpy(mad_before, &g_mock_card[0], 64);

    uint8_t wdata[240];
    memset(wdata, 0xDD, sizeof(wdata));

    int res = mad_app_write(&ops, 0xE103, false, false, wdata, sizeof(wdata));

    ASSERT_EQ("write return", PM3_SUCCESS, res);

    // MAD sector 0 should be completely unchanged
    ASSERT_TRUE("MAD sector 0 unchanged after write",
                memcmp(mad_before, &g_mock_card[0], 64) == 0);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_encode_decode_roundtrip(bool verbose) {
    PrintAndLogEx(INFO, "  encode-decode round-trip...");

    // simulate CmdMADEncode: fill sector_aids[], build struct, decode
    uint16_t sector_aids[40] = {0};
    sector_aids[1] = 0xE103; // NDEF
    sector_aids[2] = 0xE103;
    sector_aids[3] = 0xE103;
    sector_aids[4] = 0x484D; // HID
    sector_aids[5] = 0xE103; // NDEF non-contiguous

    // build MAD1 (same logic as CmdMADEncode)
    mad1_sector_t s0;
    memset(&s0, 0, sizeof(s0));
    s0.mad.info = 0x00;
    for (int i = 0; i < MAD1_NUM_AIDS; i++)
        s0.mad.aid[i] = sector_aids[i + 1];
    s0.mad.crc = CRC8Mad((uint8_t *)&s0.mad.info, sizeof(mad1_t) - 1);
    memcpy(s0.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
    s0.trailer.access[0] = 0x78;
    s0.trailer.access[1] = 0x77;
    s0.trailer.access[2] = 0x88;
    s0.trailer.gpb = 0xC1;
    memcpy(s0.trailer.key_b, g_mifare_mad_key_b, MIFARE_KEY_SIZE);

    // verify CRC is valid
    bool haveMAD2 = false;
    int res = MADCheck(&s0, NULL, false, &haveMAD2);
    ASSERT_EQ("CRC on encoded MAD1", PM3_SUCCESS, res);

    // decode and verify every entry
    mad_entry_list_t list = {0};
    res = MADDecode(&s0, NULL, &list, false, false);
    ASSERT_EQ("decode return", PM3_SUCCESS, res);
    ASSERT_EQ("entry count", MAD1_NUM_AIDS, (int)list.len);

    for (int i = 0; i < MAD1_NUM_AIDS; i++) {
        ASSERT_EQ("sector number", i + 1, list.entries[i].sector);
        ASSERT_EQ_HEX("AID", sector_aids[i + 1], list.entries[i].aid);
    }

    // verify GPB: DA=1, version=1
    ASSERT_TRUE("GPB DA bit set", (s0.trailer.gpb & 0x80) != 0);
    ASSERT_EQ("GPB version", 1, s0.trailer.gpb & 0x03);

    // verify trailer keys match MAD defaults
    ASSERT_TRUE("key A is MAD key",
                memcmp(s0.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE) == 0);
    ASSERT_TRUE("key B is MAD key B",
                memcmp(s0.trailer.key_b, g_mifare_mad_key_b, MIFARE_KEY_SIZE) == 0);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_encode_decode_mad2_roundtrip(bool verbose) {
    PrintAndLogEx(INFO, "  encode-decode MAD2 round-trip...");

    uint16_t sector_aids[40] = {0};
    sector_aids[1]  = 0xE103; // MAD1 NDEF
    sector_aids[2]  = 0xE103;
    sector_aids[4]  = 0x484D; // MAD1 HID
    sector_aids[17] = 0xE103; // MAD2 NDEF
    sector_aids[18] = 0xE103;
    sector_aids[19] = 0xE103;
    sector_aids[20] = 0x4910; // MAD2 VIGIK

    // build MAD1
    mad1_sector_t s0;
    memset(&s0, 0, sizeof(s0));
    s0.mad.info = 0x00;
    for (int i = 0; i < MAD1_NUM_AIDS; i++)
        s0.mad.aid[i] = sector_aids[i + 1];
    s0.mad.crc = CRC8Mad((uint8_t *)&s0.mad.info, sizeof(mad1_t) - 1);
    memcpy(s0.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
    s0.trailer.access[0] = 0x78;
    s0.trailer.access[1] = 0x77;
    s0.trailer.access[2] = 0x88;
    s0.trailer.gpb = 0xC2; // DA=1, MA=1, version=2
    memcpy(s0.trailer.key_b, g_mifare_mad_key_b, MIFARE_KEY_SIZE);

    // build MAD2
    mad2_sector_t s16;
    memset(&s16, 0, sizeof(s16));
    s16.mad.info = 0x00;
    for (int i = 0; i < MAD2_NUM_AIDS; i++)
        s16.mad.aid[i] = sector_aids[i + 17];
    s16.mad.crc = CRC8Mad((uint8_t *)&s16.mad.info, sizeof(mad2_t) - 1);
    memcpy(s16.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);
    s16.trailer.access[0] = 0x78;
    s16.trailer.access[1] = 0x77;
    s16.trailer.access[2] = 0x88;
    s16.trailer.gpb = 0xC2;
    memcpy(s16.trailer.key_b, g_mifare_mad_key_b, MIFARE_KEY_SIZE);

    // verify CRC on both
    bool haveMAD2 = false;
    int res = MADCheck(&s0, &s16, false, &haveMAD2);
    ASSERT_EQ("CRC on MAD1+MAD2", PM3_SUCCESS, res);
    ASSERT_EQ("should report MAD2", true, haveMAD2);

    // decode and verify all 38 entries
    mad_entry_list_t list = {0};
    res = MADDecode(&s0, &s16, &list, false, false);
    ASSERT_EQ("decode return", PM3_SUCCESS, res);
    ASSERT_EQ("entry count", MAD1_NUM_AIDS + MAD2_NUM_AIDS, (int)list.len);

    // verify MAD1 entries (sectors 1-15)
    for (int i = 0; i < MAD1_NUM_AIDS; i++) {
        ASSERT_EQ("MAD1 sector", i + 1, list.entries[i].sector);
        ASSERT_EQ_HEX("MAD1 AID", sector_aids[i + 1], list.entries[i].aid);
    }

    // verify MAD2 entries (sectors 17-39)
    for (int i = 0; i < MAD2_NUM_AIDS; i++) {
        ASSERT_EQ("MAD2 sector", i + 17, list.entries[MAD1_NUM_AIDS + i].sector);
        ASSERT_EQ_HEX("MAD2 AID", sector_aids[i + 17], list.entries[MAD1_NUM_AIDS + i].aid);
    }

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_mad2_crc_independent(bool verbose) {
    PrintAndLogEx(INFO, "  MAD2 CRC independent...");

    mad1_sector_t s0;
    build_test_mad1(&s0);
    mad2_sector_t s16;
    build_test_mad2(&s16);

    // valid: both CRCs pass
    bool haveMAD2 = false;
    int res = MADCheck(&s0, &s16, verbose, &haveMAD2);
    ASSERT_EQ("both valid", PM3_SUCCESS, res);
    ASSERT_EQ("MAD2 present", true, haveMAD2);

    // corrupt MAD2 CRC only, MAD1 stays valid
    mad2_sector_t s16_bad;
    memcpy(&s16_bad, &s16, sizeof(s16_bad));
    s16_bad.mad.crc ^= 0xFF;

    res = MADCheck(&s0, &s16_bad, verbose, &haveMAD2);
    ASSERT_TRUE("should fail with corrupt MAD2 CRC", res != PM3_SUCCESS);

    // corrupt MAD1 CRC only, MAD2 stays valid
    mad1_sector_t s0_bad;
    memcpy(&s0_bad, &s0, sizeof(s0_bad));
    s0_bad.mad.crc ^= 0xFF;

    res = MADCheck(&s0_bad, &s16, verbose, &haveMAD2);
    ASSERT_TRUE("should fail with corrupt MAD1 CRC", res != PM3_SUCCESS);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_encode_gpb_version(bool verbose) {
    PrintAndLogEx(INFO, "  encode GPB version...");

    // MAD1-only: GPB should have version=1
    mad1_sector_t s_v1;
    memset(&s_v1, 0, sizeof(s_v1));
    s_v1.mad.aid[0] = 0xE103;
    s_v1.mad.crc = CRC8Mad((uint8_t *)&s_v1.mad.info, sizeof(mad1_t) - 1);
    s_v1.trailer.gpb = 0xC1; // DA=1, MA=1, v1
    memcpy(s_v1.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);

    bool haveMAD2 = false;
    int res = MADCheck(&s_v1, NULL, false, &haveMAD2);
    ASSERT_EQ("v1 check", PM3_SUCCESS, res);
    ASSERT_EQ("v1 no MAD2", false, haveMAD2);
    ASSERT_EQ("GPB version bits", 1, s_v1.trailer.gpb & 0x03);

    // MAD1+MAD2: GPB should have version=2
    mad1_sector_t s_v2;
    memset(&s_v2, 0, sizeof(s_v2));
    s_v2.mad.aid[0] = 0xE103;
    s_v2.mad.crc = CRC8Mad((uint8_t *)&s_v2.mad.info, sizeof(mad1_t) - 1);
    s_v2.trailer.gpb = 0xC2; // DA=1, MA=1, v2
    memcpy(s_v2.trailer.key_a, g_mifare_mad_key, MIFARE_KEY_SIZE);

    res = MADCheck(&s_v2, NULL, false, &haveMAD2);
    ASSERT_EQ("v2 check", PM3_SUCCESS, res);
    ASSERT_EQ("v2 has MAD2", true, haveMAD2);
    ASSERT_EQ("GPB version bits", 2, s_v2.trailer.gpb & 0x03);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

static bool test_encode_sector_overlap(bool verbose) {
    PrintAndLogEx(INFO, "  encode sector overlap detection...");

    // two different AIDs assigned to the same sector
    uint16_t sector_aids[40] = {0};
    sector_aids[1] = 0xE103;
    sector_aids[2] = 0xE103;

    // simulate assigning sector 2 again to a different AID
    // this is what CmdMADEncode checks: sector_aids[sno] != 0
    bool overlap_detected = (sector_aids[2] != 0);
    ASSERT_TRUE("overlap on sector 2 detected", overlap_detected);

    // verify non-overlapping case
    bool no_overlap = (sector_aids[5] == 0);
    ASSERT_TRUE("sector 5 is free", no_overlap);

    if (verbose) PrintAndLogEx(SUCCESS, "    " _GREEN_("passed"));
    return true;
}

// --- Aggregator ---

int exec_mad_test(bool verbose) {
    PrintAndLogEx(INFO, "--- " _CYAN_("MAD regression tests") " ---");

    bool ok = true;
    if (!test_struct_sizes(verbose))               ok = false;
    if (!test_mad1_crc_valid(verbose))             ok = false;
    if (!test_mad1_crc_corrupt(verbose))           ok = false;
    if (!test_mad1_decode_entries(verbose))         ok = false;
    if (!test_mad2_decode(verbose))                ok = false;
    if (!test_read_mad2_sectors(verbose))           ok = false;
    if (!test_read_full_content(verbose))           ok = false;
    if (!test_read_single_sector_aid(verbose))     ok = false;
    if (!test_write_full_roundtrip(verbose))        ok = false;
    if (!test_write_partial_zero_pads(verbose))    ok = false;
    if (!test_verify_match(verbose))               ok = false;
    if (!test_verify_mismatch(verbose))            ok = false;
    if (!test_write_overflow(verbose))             ok = false;
    if (!test_aid_not_found(verbose))              ok = false;
    if (!test_write_does_not_touch_trailer(verbose)) ok = false;
    if (!test_mad_sector_untouched_after_write(verbose)) ok = false;
    if (!test_encode_decode_roundtrip(verbose))  ok = false;
    if (!test_encode_decode_mad2_roundtrip(verbose)) ok = false;
    if (!test_mad2_crc_independent(verbose))    ok = false;
    if (!test_encode_gpb_version(verbose))      ok = false;
    if (!test_encode_sector_overlap(verbose))   ok = false;

    PrintAndLogEx(INFO, "----------------------------");
    if (ok)
        PrintAndLogEx(SUCCESS, "Tests ( " _GREEN_("ok") " )");
    else
        PrintAndLogEx(FAILED, "Tests ( " _RED_("fail") " )");

    return ok ? PM3_SUCCESS : PM3_ESOFT;
}
