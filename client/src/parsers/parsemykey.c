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
// MyKey / COGES parser for SRIX4K - ST25TB04K dumps
//-----------------------------------------------------------------------------

#include "parsemykey.h"

#include "commonutil.h"         // ARRAYLEN, MemBeToUint4byte, MemLeToUint4byte
#include "ui.h"                 // PrintAndLogEx

// Blocks below 0x10 are written by the chip maker and the key issuer
#define MYKEY_BLK_LOCKID        0x05    // lock id marker in the low byte
#define MYKEY_BLK_OTP           0x06    // count down counter, feeds the session key
#define MYKEY_BLK_KEYID         0x07    // key id, low three bytes
#define MYKEY_BLK_PRODUCED      0x08    // production date, BCD

// The application itself starts at 0x10 and keeps most fields in duplicate
#define MYKEY_BLK_APP_FIRST     0x10
#define MYKEY_BLK_ELAPSED       0x10    // key id top byte + days since 1995-01-01
#define MYKEY_BLK_KEYID_A       0x11    // mirror of block 7
#define MYKEY_BLK_OPS           0x12    // operations counter
#define MYKEY_BLK_KEYID_B       0x15    // mirror of block 7
#define MYKEY_BLK_VENDOR_HI     0x18
#define MYKEY_BLK_VENDOR_LO     0x19
#define MYKEY_BLK_CREDIT_A      0x21    // current credit, XORed with the session key
#define MYKEY_BLK_PREV_A        0x23    // credit before the last transaction
#define MYKEY_BLK_CREDIT_B      0x25
#define MYKEY_BLK_PREV_B        0x27
#define MYKEY_BLK_TXN_FIRST     0x34    // eight slot transaction ring
#define MYKEY_BLK_TXN_CNT       8
#define MYKEY_BLK_TXN_PTR       0x3C

// Vendor code a key carries when it is not bound to any vendor
#define MYKEY_VENDOR_RESET      0xFEDC0123
#define MYKEY_LOCKID_MARK       0x7F
#define MYKEY_BLANK             0xFFFFFFFF

static uint8_t mykey_bcd(uint8_t v) {
    return (NIBBLE_HIGH(v) * 10) + NIBBLE_LOW(v);
}

static uint32_t mykey_scramble(uint32_t block) {
    uint32_t res = 0;
    for (uint8_t i = 0; i < 16; i++) {
        uint8_t dst = ((i % 4) * 4) + (i / 4);
        res |= (uint32_t)CRUMB(block, i * 2) << (dst * 2);
    }
    return res;
}

static uint8_t mykey_crc(uint32_t block, uint8_t blockno) {
    uint8_t crc = 0xFF - blockno;
    for (uint8_t i = 0; i < 24; i += 4) {
        crc -= NIBBLE_LOW(block >> i);
    }
    return crc;
}

static bool mykey_crc_ok(uint32_t block, uint8_t blockno) {
    return (mykey_crc(block, blockno) == (block >> 24));
}

static uint32_t mykey_block(const uint8_t *dump, uint8_t blockno) {
    return MemBeToUint4byte(dump + (blockno * MYKEY_BLOCK_SIZE));
}

static uint32_t mykey_vendor(const uint8_t *dump) {
    uint32_t hi = mykey_scramble(mykey_block(dump, MYKEY_BLK_VENDOR_HI));
    uint32_t lo = mykey_scramble(mykey_block(dump, MYKEY_BLK_VENDOR_LO));
    return ((hi & 0xFFFF) << 16) | (lo & 0xFFFF);
}

static uint32_t mykey_session_key(const uint8_t *dump, const uint8_t *uid) {
    uint32_t otp = ~BSWAP_32(mykey_block(dump, MYKEY_BLK_OTP)) + 1;
    return MemLeToUint4byte(uid) * (mykey_vendor(dump) + 1) * otp;
}

bool is_valid_mykey_card(const uint8_t *dump, size_t dumplen) {

    if (dump == NULL || dumplen < MYKEY_BYTES) {
        return false;
    }

    uint32_t keyid = mykey_block(dump, MYKEY_BLK_KEYID);
    if (keyid == MYKEY_BLANK || keyid == 0) {
        return false;
    }

    const uint8_t mirrors[2] = { MYKEY_BLK_KEYID_A, MYKEY_BLK_KEYID_B };

    for (uint8_t i = 0; i < ARRAYLEN(mirrors); i++) {

        uint32_t b = mykey_block(dump, mirrors[i]);
        if ((b & 0x00FFFFFF) != (keyid & 0x00FFFFFF)) {
            return false;
        }

        if (mykey_crc_ok(b, mirrors[i]) == false) {
            return false;
        }
    }
    return true;
}

static int32_t mykey_credit(const uint8_t *dump, uint8_t blockno, uint32_t sk) {
    uint32_t v = mykey_scramble(mykey_block(dump, blockno) ^ sk);
    if (mykey_crc_ok(v, blockno) == false) {
        return PM3_ECRC;
    }
    return (int32_t)(v & 0xFFFF);
}

static uint16_t mykey_check_blocks(const uint8_t *dump, uint32_t sk, uint16_t *total) {

    uint16_t ok = 0;
    *total = 0;

    uint32_t keymask = mykey_block(dump, MYKEY_BLK_KEYID) & 0x00FFFFFF;

    for (uint16_t i = MYKEY_BLK_APP_FIRST; i < MYKEY_NUM_BLOCKS; i++) {

        uint32_t b = mykey_block(dump, i);
        if (b == MYKEY_BLANK) {
            continue;
        }

        if ((i >= MYKEY_BLK_TXN_FIRST) && (i < (MYKEY_BLK_TXN_FIRST + MYKEY_BLK_TXN_CNT))) {
            continue;
        }

        (*total)++;

        if (mykey_crc_ok(b, i) ||
                mykey_crc_ok(mykey_scramble(b), i) ||
                mykey_crc_ok(mykey_scramble(b ^ sk), i) ||
                mykey_crc_ok(mykey_scramble(b ^ keymask), i)) {
            ok++;
        }
    }
    return ok;
}

static void mykey_print_produced(uint32_t blk) {

    uint8_t day = mykey_bcd((blk >> 24) & 0xFF);
    uint8_t month = mykey_bcd((blk >> 16) & 0xFF);
    uint16_t year = (mykey_bcd(SWAP_NIBBLE(blk & 0xFF)) * 100) + mykey_bcd((blk >> 8) & 0xFF);

    PrintAndLogEx(INFO, "Produced........... " _YELLOW_("%04u-%02u-%02u"), year, month, day);
}

static void mykey_print_transactions(const uint8_t *dump) {

    uint32_t ptrblk = mykey_block(dump, MYKEY_BLK_TXN_PTR);
    int32_t ptr = -1;

    if (ptrblk != MYKEY_BLANK) {

        uint32_t v = mykey_scramble(ptrblk ^ (mykey_block(dump, MYKEY_BLK_KEYID) & 0x00FFFFFF));
        if (mykey_crc_ok(v, MYKEY_BLK_TXN_PTR)) {
            ptr = (int32_t)((v >> 16) & 0xFF);
        }

        if (ptr > (MYKEY_BLK_TXN_CNT - 1)) {
            ptr = -1;
        }
    }

    uint8_t used = 0;
    for (uint8_t i = 0; i < MYKEY_BLK_TXN_CNT; i++) {
        if (mykey_block(dump, MYKEY_BLK_TXN_FIRST + i) != MYKEY_BLANK) {
            used++;
        }
    }

    if (used == 0) {
        PrintAndLogEx(INFO, "Transactions....... " _YELLOW_("none"));
        return;
    }

    PrintAndLogEx(INFO, "Transactions....... %u of %u slots used", used, MYKEY_BLK_TXN_CNT);

    for (uint8_t i = 0; i < MYKEY_BLK_TXN_CNT; i++) {

        uint32_t t = mykey_block(dump, MYKEY_BLK_TXN_FIRST + i);
        if (t == MYKEY_BLANK) {
            continue;
        }

        PrintAndLogEx(INFO, "  %s slot %u........ %04u-%02u-%02u  " _GREEN_("%u.%02u") " EUR",
                      (i == ptr) ? ">" : " ",
                      i,
                      2000 + ((t >> 16) & 0x7F),
                      NIBBLE_LOW(t >> 23),
                      (t >> 27) & 0x1F,
                      (t & 0xFFFF) / 100,
                      (t & 0xFFFF) % 100
                     );
    }
}

int mykey_parser_parse(const uint8_t *dump, size_t dumplen, const uint8_t *uid) {

    if (is_valid_mykey_card(dump, dumplen) == false) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("MyKey / COGES") " ------------------------");

    PrintAndLogEx(INFO, "Key ID............. " _YELLOW_("%06X"), mykey_block(dump, MYKEY_BLK_KEYID) & 0x00FFFFFF);
    mykey_print_produced(mykey_block(dump, MYKEY_BLK_PRODUCED));

    uint32_t elapsed = mykey_block(dump, MYKEY_BLK_ELAPSED) & 0xFFFF;
    if (elapsed) {
        PrintAndLogEx(INFO, "Days since 1995.... %04X", elapsed);
    }

    uint32_t ops = mykey_block(dump, MYKEY_BLK_OPS);
    if (mykey_crc_ok(ops, MYKEY_BLK_OPS)) {
        PrintAndLogEx(INFO, "Operations......... " _YELLOW_("%u"), ops & 0x00FFFFFF);
    }

    uint32_t vendor = mykey_vendor(dump);
    if (vendor == MYKEY_VENDOR_RESET) {
        PrintAndLogEx(INFO, "Vendor............. " _YELLOW_("reset") ", not bound to a vendor");
    } else {
        PrintAndLogEx(INFO, "Vendor............. " _YELLOW_("%08X"), vendor);
    }

    bool lockid = ((mykey_block(dump, MYKEY_BLK_LOCKID) & 0xFF) == MYKEY_LOCKID_MARK);
    PrintAndLogEx(INFO, "Lock ID............ %s", lockid ? _RED_("yes") : _GREEN_("no"));

    bool have_uid = false;
    for (uint8_t i = 0; (uid != NULL) && (i < 8); i++) {
        if (uid[i]) {
            have_uid = true;
            break;
        }
    }

    if (have_uid == false) {
        PrintAndLogEx(INFO, "Session key........ " _YELLOW_("unknown") ", UID needed to decrypt the credit");
        PrintAndLogEx(INFO, "Credit............. %08X " _YELLOW_("still encrypted"), mykey_block(dump, MYKEY_BLK_CREDIT_A));
        mykey_print_transactions(dump);
        return PM3_SUCCESS;
    }

    uint32_t sk = mykey_session_key(dump, uid);
    PrintAndLogEx(INFO, "Session key........ " _YELLOW_("%08X"), sk);

    int32_t credit = mykey_credit(dump, MYKEY_BLK_CREDIT_A, sk);
    int32_t copy = mykey_credit(dump, MYKEY_BLK_CREDIT_B, sk);

    if (credit == PM3_ECRC) {
        PrintAndLogEx(INFO, "Credit............. " _RED_("checksum failed") ", wrong UID or unknown vendor");
    } else {
        PrintAndLogEx(INFO, "Credit............. " _GREEN_("%u.%02u") " EUR", credit / 100, credit % 100);
        if (copy != credit) {
            PrintAndLogEx(INFO, "                    block %02X disagrees, a torn write", MYKEY_BLK_CREDIT_B);
        }
    }

    // The previous credit is scrambled but not XORed with the session key
    int32_t prev = mykey_credit(dump, MYKEY_BLK_PREV_A, 0);
    int32_t prev_copy = mykey_credit(dump, MYKEY_BLK_PREV_B, 0);

    if (prev != PM3_ECRC) {
        PrintAndLogEx(INFO, "Previous credit.... " _GREEN_("%u.%02u") " EUR", prev / 100, prev % 100);
        if (prev_copy != prev) {
            PrintAndLogEx(INFO, "                    block %02X disagrees, a torn write", MYKEY_BLK_PREV_B);
        }
    }

    if (lockid && (credit == PM3_ECRC)) {
        PrintAndLogEx(WARNING, "Lock id set and the credit does not check out");
    }

    mykey_print_transactions(dump);

    uint16_t total = 0;
    uint16_t ok = mykey_check_blocks(dump, sk, &total);
    PrintAndLogEx(INFO, "Block checksums.... %u / %u ( %s )"
                  , ok
                  , total
                  , (ok == total) ? _GREEN_("ok") : _RED_("fail")
                 );

    return PM3_SUCCESS;
}

// A reset key read off an ST25TB04K. Every written block checksums, the vendor
// is the reset code and the credit is zero.
static const uint8_t mykey_selftest_uid[8] = { 0x56, 0x65, 0xB2, 0x3C, 0x67, 0x1F, 0x02, 0xD0 };

static const uint8_t mykey_selftest_dump[MYKEY_BYTES] = {
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0x64, 0x95, 0x43, 0x19, 0x27, 0x10, 0x21, 0x02,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xE5, 0x64, 0x00, 0x00, 0xCF, 0x95, 0x43, 0x19,
    0xEC, 0x00, 0x00, 0x01, 0xE4, 0x04, 0x00, 0x13, 0xE1, 0x64, 0x00, 0x00,
    0xCB, 0x95, 0x43, 0x19, 0xE8, 0x00, 0x00, 0x01, 0xE0, 0x04, 0x00, 0x13,
    0x8F, 0xCD, 0x0F, 0x48, 0xC0, 0x82, 0x00, 0x07, 0xC0, 0x80, 0x40, 0x40,
    0xC0, 0x80, 0x40, 0x00, 0x8F, 0x8D, 0xCF, 0x48, 0xC0, 0x42, 0xC0, 0x07,
    0xC0, 0x80, 0x00, 0x40, 0xC0, 0x80, 0x00, 0x00, 0xC0, 0x40, 0xC0, 0x90,
    0x65, 0x23, 0x56, 0x98, 0xC0, 0x66, 0x01, 0x13, 0xC0, 0x40, 0xC0, 0x00,
    0xC0, 0x40, 0x80, 0x90, 0x65, 0x23, 0x16, 0x98, 0xC0, 0x26, 0xC1, 0x13,
    0xC0, 0x40, 0x80, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xB6, 0x64, 0x00, 0x00, 0xA0, 0x95, 0x43, 0x19, 0xBD, 0x00, 0x00, 0x01,
    0xB5, 0x04, 0x00, 0x13, 0xB2, 0x64, 0x00, 0x00, 0x9C, 0x95, 0x43, 0x19,
    0xB9, 0x00, 0x00, 0x01, 0xB1, 0x04, 0x00, 0x13, 0x8F, 0x0D, 0x0F, 0x88,
    0x80, 0xC2, 0x00, 0x47, 0x80, 0xC0, 0x40, 0x80, 0x80, 0xC0, 0x40, 0x40,
    0x4F, 0xCD, 0xCF, 0x88, 0x80, 0x82, 0xC0, 0x47, 0x80, 0xC0, 0x00, 0x80,
    0x80, 0xC0, 0x00, 0x40, 0x80, 0x80, 0xC0, 0xD0, 0x80, 0x80, 0xC0, 0xC0,
    0x80, 0xA6, 0x01, 0x53, 0x80, 0x80, 0xC0, 0x40, 0x80, 0x80, 0x80, 0xD0,
    0x80, 0x80, 0x80, 0xC0, 0x80, 0x66, 0xC1, 0x53, 0x80, 0x80, 0x80, 0x40,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
};

static const struct {
    uint32_t enc;
    uint32_t dec;
} mykey_selftest_vectors[] = {
    { 0xC04F42C5, 0xD7003139 },
    { 0xC1484807, 0xD4002943 },
    { 0xC0C60848, 0xF1001A20 },
};

int mykey_selftest(void) {

    PrintAndLogEx(INFO, "Testing MyKey block scrambler and session key");

    for (uint8_t i = 0; i < ARRAYLEN(mykey_selftest_vectors); i++) {

        uint32_t enc = mykey_selftest_vectors[i].enc;
        uint32_t dec = mykey_selftest_vectors[i].dec;

        if (mykey_scramble(enc) != dec) {
            PrintAndLogEx(FAILED, "  %08X descrambled to %08X, expected %08X ( " _RED_("fail") " )"
                          , enc
                          , mykey_scramble(enc)
                          , dec
                         );
            return PM3_ESOFT;
        }

        if (mykey_scramble(dec) != enc) {
            PrintAndLogEx(FAILED, "  scrambler is not its own inverse on %08X ( " _RED_("fail") " )", dec);
            return PM3_ESOFT;
        }
    }
    PrintAndLogEx(INFO, "  scrambler.......... %u vectors, self inverse ( " _GREEN_("ok") " )", (unsigned)ARRAYLEN(mykey_selftest_vectors));

    if (is_valid_mykey_card(mykey_selftest_dump, sizeof(mykey_selftest_dump)) == false) {
        PrintAndLogEx(FAILED, "  known good dump not recognised ( " _RED_("fail") " )");
        return PM3_ESOFT;
    }

    uint32_t vendor = mykey_vendor(mykey_selftest_dump);
    if (vendor != MYKEY_VENDOR_RESET) {
        PrintAndLogEx(FAILED, "  vendor %08X, expected the reset code %08X ( " _RED_("fail") " )", vendor, MYKEY_VENDOR_RESET);
        return PM3_ESOFT;
    }

    uint32_t sk = mykey_session_key(mykey_selftest_dump, mykey_selftest_uid);
    PrintAndLogEx(INFO, "  session key........ %08X", sk);

    int32_t credit = mykey_credit(mykey_selftest_dump, MYKEY_BLK_CREDIT_A, sk);
    if (credit != 0) {
        PrintAndLogEx(FAILED, "  credit read back as %d, expected 0 ( " _RED_("fail") " )", credit);
        return PM3_ESOFT;
    }

    uint16_t total = 0;
    uint16_t ok = mykey_check_blocks(mykey_selftest_dump, sk, &total);
    if (ok != total || total == 0) {
        PrintAndLogEx(FAILED, "  %u of %u block checksums ( " _RED_("fail") " )", ok, total);
        return PM3_ESOFT;
    }
    PrintAndLogEx(INFO, "  block checksums.... %u / %u ( " _GREEN_("ok") " )", ok, total);

    PrintAndLogEx(SUCCESS, "MyKey parser selftest ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}
