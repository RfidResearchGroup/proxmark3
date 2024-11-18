//-----------------------------------------------------------------------------
// Copyright (C) Gerhard de Koning Gans - May 2008
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
// Mifare Classic Card Simulation
//-----------------------------------------------------------------------------

// Verbose Mode:
// DBG_NONE          0
// DBG_ERROR         1
// DBG_INFO          2
// DBG_DEBUG         3
// DBG_EXTENDED      4

//  /!\ Printing Debug message is disrupting emulation,
//  Only use with caution during debugging

#include "mifaresim.h"

#include <inttypes.h>

#include "iso14443a.h"
#include "BigBuf.h"
#include "string.h"
#include "mifareutil.h"
#include "fpgaloader.h"
#include "proxmark3_arm.h"
#include "cmd.h"
#include "protocols.h"
#include "appmain.h"
#include "util.h"
#include "commonutil.h"
#include "crc16.h"
#include "dbprint.h"
#include "ticks.h"
#include "parity.h"

static bool IsKeyBReadable(uint8_t blockNo) {
    uint8_t sector_trailer[16];
    emlGetMem(sector_trailer, SectorTrailer(blockNo), 1);
    uint8_t AC = ((sector_trailer[7] >> 5) & 0x04)
                 | ((sector_trailer[8] >> 2) & 0x02)
                 | ((sector_trailer[8] >> 7) & 0x01);
    return (AC == 0x00 || AC == 0x01 || AC == 0x02);
}

static bool IsTrailerAccessAllowed(uint8_t blockNo, uint8_t keytype, uint8_t action) {
    uint8_t sector_trailer[16];
    emlGetMem(sector_trailer, blockNo, 1);
    uint8_t AC = ((sector_trailer[7] >> 5) & 0x04)
                 | ((sector_trailer[8] >> 2) & 0x02)
                 | ((sector_trailer[8] >> 7) & 0x01);
    switch (action) {
        case AC_KEYA_READ: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsTrailerAccessAllowed: AC_KEYA_READ");
            return false;
        }
        case AC_KEYA_WRITE: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsTrailerAccessAllowed: AC_KEYA_WRITE");
            return ((keytype == AUTHKEYA && (AC == 0x00 || AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x04 || AC == 0x03)));
        }
        case AC_KEYB_READ: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsTrailerAccessAllowed: AC_KEYB_READ");
            return (keytype == AUTHKEYA && (AC == 0x00 || AC == 0x02 || AC == 0x01));
        }
        case AC_KEYB_WRITE: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsTrailerAccessAllowed: AC_KEYB_WRITE");
            return ((keytype == AUTHKEYA && (AC == 0x00 || AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x04 || AC == 0x03)));
        }
        case AC_AC_READ: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsTrailerAccessAllowed: AC_AC_READ");
            return ((keytype == AUTHKEYA)
                    || (keytype == AUTHKEYB && !(AC == 0x00 || AC == 0x02 || AC == 0x01)));
        }
        case AC_AC_WRITE: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsTrailerAccessAllowed: AC_AC_WRITE");
            return ((keytype == AUTHKEYA && (AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x03 || AC == 0x05)));
        }
        default:
            return false;
    }
}

static bool IsDataAccessAllowed(uint8_t blockNo, uint8_t keytype, uint8_t action) {

    uint8_t sector_trailer[16];
    emlGetMem(sector_trailer, SectorTrailer(blockNo), 1);

    uint8_t sector_block;
    if (blockNo <= MIFARE_2K_MAXBLOCK) {
        sector_block = blockNo & 0x03;
    } else {
        sector_block = (blockNo & 0x0f) / 5;
    }

    uint8_t AC;
    switch (sector_block) {
        case 0x00: {
            AC = ((sector_trailer[7] >> 2) & 0x04)
                 | ((sector_trailer[8] << 1) & 0x02)
                 | ((sector_trailer[8] >> 4) & 0x01);
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed: case 0x00 - %02x", AC);
            break;
        }
        case 0x01: {
            AC = ((sector_trailer[7] >> 3) & 0x04)
                 | ((sector_trailer[8] >> 0) & 0x02)
                 | ((sector_trailer[8] >> 5) & 0x01);
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed: case 0x01 - %02x", AC);
            break;
        }
        case 0x02: {
            AC = ((sector_trailer[7] >> 4) & 0x04)
                 | ((sector_trailer[8] >> 1) & 0x02)
                 | ((sector_trailer[8] >> 6) & 0x01);
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed: case 0x02  - %02x", AC);
            break;
        }
        default:
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed: Error");
            return false;
    }

    switch (action) {
        case AC_DATA_READ: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed - AC_DATA_READ: OK");
            return ((keytype == AUTHKEYA && !(AC == 0x03 || AC == 0x05 || AC == 0x07))
                    || (keytype == AUTHKEYB && !(AC == 0x07)));
        }
        case AC_DATA_WRITE: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed - AC_DATA_WRITE: OK");
            return ((keytype == AUTHKEYA && (AC == 0x00))
                    || (keytype == AUTHKEYB && (AC == 0x00 || AC == 0x04 || AC == 0x06 || AC == 0x03)));
        }
        case AC_DATA_INC: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("IsDataAccessAllowed - AC_DATA_INC: OK");
            return ((keytype == AUTHKEYA && (AC == 0x00))
                    || (keytype == AUTHKEYB && (AC == 0x00 || AC == 0x06)));
        }
        case AC_DATA_DEC_TRANS_REST: {
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("AC_DATA_DEC_TRANS_REST: OK");
            return ((keytype == AUTHKEYA && (AC == 0x00 || AC == 0x06 || AC == 0x01))
                    || (keytype == AUTHKEYB && (AC == 0x00 || AC == 0x06 || AC == 0x01)));
        }
    }

    return false;
}

static bool IsAccessAllowed(uint8_t blockNo, uint8_t keytype, uint8_t action) {
    if (IsSectorTrailer(blockNo)) {
        return IsTrailerAccessAllowed(blockNo, keytype, action);
    } else {
        return IsDataAccessAllowed(blockNo, keytype, action);
    }
}

static uint8_t MifareMaxSector(uint16_t flags) {
    if (IS_FLAG_MF_SIZE(flags, MIFARE_MINI_MAX_BYTES)) {
        return MIFARE_MINI_MAXSECTOR;
    } else if (IS_FLAG_MF_SIZE(flags, MIFARE_1K_MAX_BYTES)) {
        return MIFARE_1K_MAXSECTOR;
    } else if (IS_FLAG_MF_SIZE(flags, MIFARE_2K_MAX_BYTES)) {
        return MIFARE_2K_MAXSECTOR;
    } else if (IS_FLAG_MF_SIZE(flags, MIFARE_4K_MAX_BYTES)) {
        return MIFARE_4K_MAXSECTOR;
    } else {
        return MIFARE_4K_MAXSECTOR;
    }
}

static bool MifareSimInit(uint16_t flags, uint8_t *uid, uint16_t atqa, uint8_t sak, tag_response_info_t **responses, uint32_t *cuid, uint8_t *uid_len, uint8_t **rats, uint8_t *rats_len) {

    uint8_t uid_tmp[10] = {0};
    // SPEC: https://www.nxp.com/docs/en/application-note/AN10833.pdf
    // ATQA
    static uint8_t rATQA_Mini[]  = {0x04, 0x00};             // indicate Mifare classic Mini 4Byte UID
    static uint8_t rATQA_1k[]    = {0x04, 0x00};             // indicate Mifare classic 1k 4Byte UID
    static uint8_t rATQA_2k[]    = {0x04, 0x00};             // indicate Mifare classic 2k 4Byte UID
    static uint8_t rATQA_4k[]    = {0x02, 0x00};             // indicate Mifare classic 4k 4Byte UID

    // SAK
    static uint8_t rSAK_Mini = 0x09;    // mifare Mini
    static uint8_t rSAK_1k   = 0x08;    // mifare 1k
    static uint8_t rSAK_2k   = 0x08;    // mifare 2k with RATS support
    static uint8_t rSAK_4k   = 0x18;    // mifare 4k

    static uint8_t rUIDBCC1[]   = {0x00, 0x00, 0x00, 0x00, 0x00};   // UID 1st cascade level
    static uint8_t rUIDBCC1b4[] = {0x00, 0x00, 0x00, 0x00};         // UID 1st cascade level, last 4 bytes
    static uint8_t rUIDBCC1b3[] = {0x00, 0x00, 0x00};               // UID 1st cascade level, last 3 bytes
    static uint8_t rUIDBCC1b2[] = {0x00, 0x00};                     // UID 1st cascade level, last 2 bytes
    static uint8_t rUIDBCC1b1[] = {0x00};                           // UID 1st cascade level, last byte
    static uint8_t rUIDBCC2[]   = {0x00, 0x00, 0x00, 0x00, 0x00};   // UID 2nd cascade level
    static uint8_t rUIDBCC2b4[] = {0x00, 0x00, 0x00, 0x00};         // UID 2st cascade level, last 4 bytes
    static uint8_t rUIDBCC2b3[] = {0x00, 0x00, 0x00};               // UID 2st cascade level, last 3 bytes
    static uint8_t rUIDBCC2b2[] = {0x00, 0x00};                     // UID 2st cascade level, last 2 bytes
    static uint8_t rUIDBCC2b1[] = {0x00};                           // UID 2st cascade level, last byte
    static uint8_t rUIDBCC3[]   = {0x00, 0x00, 0x00, 0x00, 0x00};   // UID 3nd cascade level
    static uint8_t rUIDBCC3b4[] = {0x00, 0x00, 0x00, 0x00};         // UID 3st cascade level, last 4 bytes
    static uint8_t rUIDBCC3b3[] = {0x00, 0x00, 0x00};               // UID 3st cascade level, last 3 bytes
    static uint8_t rUIDBCC3b2[] = {0x00, 0x00};                     // UID 3st cascade level, last 2 bytes
    static uint8_t rUIDBCC3b1[] = {0x00};                           // UID 3st cascade level, last byte

    static uint8_t rATQA[]     = {0x00, 0x00};             // Current ATQA
    static uint8_t rSAK[]      = {0x00, 0x00, 0x00};       // Current SAK, CRC
    static uint8_t rSAKuid[]   = {0x04, 0xda, 0x17};       // UID incomplete cascade bit, CRC

    // RATS answer for 2K NXP mifare classic (with CRC)
    static uint8_t rRATS[]     = {0x0c, 0x75, 0x77, 0x80, 0x02, 0xc1, 0x05, 0x2f, 0x2f, 0x01, 0xbc, 0xd6, 0x60, 0xd3};

    *uid_len = 0;

    // By default use 1K tag
    memcpy(rATQA, rATQA_1k, sizeof(rATQA));
    rSAK[0] = rSAK_1k;

    //by default RATS not supported
    *rats_len = 0;
    *rats = NULL;

    // -- Determine the UID
    // Can be set from emulator memory or incoming data
    // Length: 4,7,or 10 bytes

    if (IS_FLAG_UID_IN_EMUL(flags)) {
        if (uid == NULL) {
            uid = uid_tmp;
        }
        // Get UID, SAK, ATQA from EMUL
        uint8_t block0[16];
        emlGet(block0, 0, 16);
        // Check for 4 bytes uid: bcc corrected and single size uid bits in ATQA
        if ((block0[0] ^ block0[1] ^ block0[2] ^ block0[3]) == block0[4] && (block0[6] & 0xc0) == 0) {
            FLAG_SET_UID_IN_DATA(flags, 4);
            memcpy(uid, block0, 4);
            rSAK[0] = block0[5];
            memcpy(rATQA, &block0[6], sizeof(rATQA));
        }
        // Check for 7 bytes UID: double size uid bits in ATQA
        else if ((block0[8] & 0xc0) == 0x40) {
            FLAG_SET_UID_IN_DATA(flags, 7);
            memcpy(uid, block0, 7);
            rSAK[0] = block0[7];
            memcpy(rATQA, &block0[8], sizeof(rATQA));
        } else {
            Dbprintf("ERROR: " _RED_("Invalid dump. UID/SAK/ATQA not found"));
            return false;
        }
    } else {
        if (uid == NULL) {
            Dbprintf("ERROR: " _RED_("Missing UID"));
            return false;
        }
    }

    // Tune tag type, if defined directly
    // Otherwise use defined by default or extracted from EMUL
    if (IS_FLAG_MF_SIZE(flags, MIFARE_MINI_MAX_BYTES)) {
        memcpy(rATQA, rATQA_Mini, sizeof(rATQA));
        rSAK[0] = rSAK_Mini;
        if (g_dbglevel > DBG_NONE) Dbprintf("Enforcing Mifare Mini ATQA/SAK");
    } else if (IS_FLAG_MF_SIZE(flags, MIFARE_1K_MAX_BYTES)) {
        memcpy(rATQA, rATQA_1k, sizeof(rATQA));
        rSAK[0] = rSAK_1k;
        if (g_dbglevel > DBG_NONE) Dbprintf("Enforcing Mifare 1K ATQA/SAK");
    } else if (IS_FLAG_MF_SIZE(flags, MIFARE_2K_MAX_BYTES)) {
        memcpy(rATQA, rATQA_2k, sizeof(rATQA));
        rSAK[0] = rSAK_2k;
        *rats = rRATS;
        *rats_len = sizeof(rRATS);
        if (g_dbglevel > DBG_NONE) Dbprintf("Enforcing Mifare 2K ATQA/SAK with RATS support");
    } else if (IS_FLAG_MF_SIZE(flags, MIFARE_4K_MAX_BYTES)) {
        memcpy(rATQA, rATQA_4k, sizeof(rATQA));
        rSAK[0] = rSAK_4k;
        if (g_dbglevel > DBG_NONE) Dbprintf("Enforcing Mifare 4K ATQA/SAK");
    }

    // Prepare UID arrays
    if (IS_FLAG_UID_IN_DATA(flags, 4)) {
        memcpy(rUIDBCC1, uid, 4);
        *uid_len = 4;
        // save CUID
        *cuid = bytes_to_num(rUIDBCC1, 4);
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        if (g_dbglevel >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - Flags: %04X - BCC1: %02X", flags, rUIDBCC1[4]);
        if (g_dbglevel > DBG_NONE) {
            Dbprintf("4B UID: %02x%02x%02x%02x", rUIDBCC1[0], rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3]);
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f); // single size uid
    } else if (IS_FLAG_UID_IN_DATA(flags, 7)) {
        memcpy(&rUIDBCC1[1], uid, 3);
        memcpy(rUIDBCC2, uid + 3, 4);
        *uid_len = 7;
        // save CUID
        *cuid = bytes_to_num(rUIDBCC2, 4);
        // CascadeTag, CT
        rUIDBCC1[0] = MIFARE_SELECT_CT;
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        if (g_dbglevel >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - Flags: %04X - BCC1: %02X - BCC2: %02X", flags, rUIDBCC1[4], rUIDBCC2[4]);
        if (g_dbglevel > DBG_NONE) {
            Dbprintf("7B UID: %02x %02x %02x %02x %02x %02x %02x",
                     rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3], rUIDBCC2[0], rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3]);
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x40; // double size uid
    } else if (IS_FLAG_UID_IN_DATA(flags, 10)) {
        memcpy(&rUIDBCC1[1], uid,   3);
        memcpy(&rUIDBCC2[1], uid + 3, 3);
        memcpy(rUIDBCC3,    uid + 6, 4);
        *uid_len = 10;
        // save CUID
        *cuid = bytes_to_num(rUIDBCC3, 4);
        // CascadeTag, CT
        rUIDBCC1[0] = MIFARE_SELECT_CT;
        rUIDBCC2[0] = MIFARE_SELECT_CT;
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3];
        if (g_dbglevel >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - Flags: %04X - BCC1: %02X - BCC2: %02X - BCC3: %02X", flags, rUIDBCC1[4], rUIDBCC2[4], rUIDBCC3[4]);
        if (g_dbglevel > DBG_NONE) {
            Dbprintf("10B UID: %02x %02x %02x %02x %02x %02x %02x %02x %02x %02x",
                     rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3],
                     rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3],
                     rUIDBCC3[0], rUIDBCC3[1], rUIDBCC3[2], rUIDBCC3[3]
                    );
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x80; // triple size uid
    } else {
        Dbprintf("ERROR: " _RED_("UID size not defined"));
        return false;
    }
    if (flags & FLAG_ATQA_IN_DATA) {
        rATQA[0] = atqa >> 8;
        rATQA[1] = atqa & 0xff;
    }
    if (flags & FLAG_SAK_IN_DATA) {
        rSAK[0] = sak;
    }
    if (g_dbglevel > DBG_NONE) {
        Dbprintf("ATQA  : %02X %02X", rATQA[1], rATQA[0]);
        Dbprintf("SAK   : %02X", rSAK[0]);
    }

    // clone UIDs for byte-frame anti-collision multiple tag selection procedure
    memcpy(rUIDBCC1b4, &rUIDBCC1[1], 4);
    memcpy(rUIDBCC1b3, &rUIDBCC1[2], 3);
    memcpy(rUIDBCC1b2, &rUIDBCC1[3], 2);
    memcpy(rUIDBCC1b1, &rUIDBCC1[4], 1);
    if (*uid_len >= 7) {
        memcpy(rUIDBCC2b4, &rUIDBCC2[1], 4);
        memcpy(rUIDBCC2b3, &rUIDBCC2[2], 3);
        memcpy(rUIDBCC2b2, &rUIDBCC2[3], 2);
        memcpy(rUIDBCC2b1, &rUIDBCC2[4], 1);
    }
    if (*uid_len == 10) {
        memcpy(rUIDBCC3b4, &rUIDBCC3[1], 4);
        memcpy(rUIDBCC3b3, &rUIDBCC3[2], 3);
        memcpy(rUIDBCC3b2, &rUIDBCC3[3], 2);
        memcpy(rUIDBCC3b1, &rUIDBCC3[4], 1);
    }

    // Calculate actual CRC
    AddCrc14A(rSAK, sizeof(rSAK) - 2);

#define TAG_RESPONSE_COUNT 18
    static tag_response_info_t responses_init[TAG_RESPONSE_COUNT] = {
        { .response = rATQA,     .response_n = sizeof(rATQA)     },     // Answer to request - respond with card type
        { .response = rSAK,      .response_n = sizeof(rSAK)      },     //
        { .response = rSAKuid,   .response_n = sizeof(rSAKuid)   },     //
        // Do not reorder. Block used via relative index of rUIDBCC1
        { .response = rUIDBCC1,  .response_n = sizeof(rUIDBCC1)  },     // Anticollision cascade1 - respond with first part of uid
        { .response = rUIDBCC1b4, .response_n = sizeof(rUIDBCC1b4)},
        { .response = rUIDBCC1b3, .response_n = sizeof(rUIDBCC1b3)},
        { .response = rUIDBCC1b2, .response_n = sizeof(rUIDBCC1b2)},
        { .response = rUIDBCC1b1, .response_n = sizeof(rUIDBCC1b1)},
        // Do not reorder. Block used via relative index of rUIDBCC2
        { .response = rUIDBCC2,  .response_n = sizeof(rUIDBCC2)  },     // Anticollision cascade2 - respond with 2nd part of uid
        { .response = rUIDBCC2b4, .response_n = sizeof(rUIDBCC2b4)},
        { .response = rUIDBCC2b3, .response_n = sizeof(rUIDBCC2b3)},
        { .response = rUIDBCC2b2, .response_n = sizeof(rUIDBCC2b2)},
        { .response = rUIDBCC2b1, .response_n = sizeof(rUIDBCC2b1)},
        // Do not reorder. Block used via relative index of rUIDBCC3
        { .response = rUIDBCC3,  .response_n = sizeof(rUIDBCC3)  },     // Anticollision cascade3 - respond with 3th part of uid
        { .response = rUIDBCC3b4, .response_n = sizeof(rUIDBCC3b4)},
        { .response = rUIDBCC3b3, .response_n = sizeof(rUIDBCC3b3)},
        { .response = rUIDBCC3b2, .response_n = sizeof(rUIDBCC3b2)},
        { .response = rUIDBCC3b1, .response_n = sizeof(rUIDBCC3b1)}
    };

    // Prepare ("precompile") the responses of the anticollision phase.
    // There will be not enough time to do this at the moment the reader sends its REQA or SELECT
    // There are 18 predefined responses with a total of 53 bytes data to transmit.
    // Coded responses need one byte per bit to transfer (data, parity, start, stop, correction)
    // 53 * 8 data bits, 53 * 1 parity bits, 18 start bits, 18 stop bits, 18 correction bits  ->   need 571 bytes buffer
#define ALLOCATED_TAG_MODULATION_BUFFER_SIZE 571

    uint8_t *free_buffer = BigBuf_malloc(ALLOCATED_TAG_MODULATION_BUFFER_SIZE);
    // modulation buffer pointer and current buffer free space size
    uint8_t *free_buffer_pointer = free_buffer;
    size_t free_buffer_size = ALLOCATED_TAG_MODULATION_BUFFER_SIZE;

    for (size_t i = 0; i < TAG_RESPONSE_COUNT; i++) {
        if (prepare_allocated_tag_modulation(&responses_init[i], &free_buffer_pointer, &free_buffer_size) == false) {
            Dbprintf("Not enough modulation buffer size, exit after %d elements", i);
            return false;
        }
    }

    *responses = responses_init;

    // indices into responses array:
#define ATQA     0
#define SAK      1
#define SAKuid   2
#define UIDBCC1  3
#define UIDBCC2  8
#define UIDBCC3  13

    return true;
}

/**
*MIFARE 1K simulate.
*
*@param flags: See pm3_cmd.h for the full definitions
*@param exitAfterNReads, exit simulation after n blocks have been read, 0 is infinite ...
* (unless reader attack mode enabled then it runs util it gets enough nonces to recover all keys attempted)
*/
void Mifare1ksim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *uid, uint16_t atqa, uint8_t sak) {
    tag_response_info_t *responses;
    uint8_t cardSTATE = MFEMUL_NOFIELD;
    uint8_t uid_len = 0; // 4, 7, 10
    uint32_t cuid = 0, selTimer = 0, authTimer = 0;
    uint32_t nr, ar;
    uint8_t blockNo;
    bool encrypted_data;

    uint8_t cardWRBL = 0;
    uint8_t cardAUTHSC = 0;
    uint8_t cardMaxSEC = MifareMaxSector(flags);
    uint8_t cardAUTHKEY = AUTHKEYNONE;  // no authentication
    uint32_t cardRr = 0;
    uint32_t ans = 0;
    uint32_t cardINTREG = 0;
    uint8_t cardINTBLOCK = 0;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    uint32_t numReads = 0; //Counts numer of times reader reads a block
    uint8_t receivedCmd[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_dec[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
    uint16_t receivedCmd_len;

    uint8_t response[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t response_par[MAX_MIFARE_PARITY_SIZE] = {0x00};

    uint8_t *rats = NULL;
    uint8_t rats_len = 0;


    //Here, we collect UID,sector,keytype,NT,AR,NR,NT2,AR2,NR2
    // This will be used in the reader-only attack.

    //allow collecting up to 16 sets of nonces to allow recovery of up to 16 keys
#define ATTACK_KEY_COUNT 16
    nonces_t ar_nr_resp[ATTACK_KEY_COUNT]; // for moebius attack type
    memset(ar_nr_resp, 0x00, sizeof(ar_nr_resp));

    // Authenticate response - nonce
    uint8_t rAUTH_NT[4] = {0, 0, 0, 1};
    uint8_t rAUTH_NT_keystream[4];
    uint32_t nonce = 0;

    const tUart14a *uart = GetUart14a();

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    if (MifareSimInit(flags, uid, atqa, sak, &responses, &cuid, &uid_len, &rats, &rats_len) == false) {
        BigBuf_free_keep_EM();
        return;
    }

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    // clear trace
    clear_trace();
    set_tracing(true);
    LED_D_ON();
    ResetSspClk();

    uint8_t *p_em = BigBuf_get_EM_addr();
    uint8_t cve_flipper = 0;

    int counter = 0;
    bool finished = false;
    bool running_nested_auth_attack = false;
    bool button_pushed = BUTTON_PRESS();
    while ((button_pushed == false) && (finished == false)) {

        WDT_HIT();

        if (counter == 1000) {
            if (data_available()) {
                Dbprintf("----------- " _GREEN_("BREAKING") " ----------");
                break;
            }
            counter = 0;
        } else {
            counter++;
        }

        /*
                // find reader field
                if (cardSTATE == MFEMUL_NOFIELD) {

                    vHf = (MAX_ADC_HF_VOLTAGE * SumAdc(ADC_CHAN_HF, 32)) >> 15;

                    if (vHf > MF_MINFIELDV) {
                        cardSTATE_TO_IDLE();
                        LED_A_ON();
                    }
                    button_pushed = BUTTON_PRESS();
                    continue;
                }
                */

        FpgaEnableTracing();
        //Now, get data
        int res = EmGetCmd(receivedCmd, sizeof(receivedCmd), &receivedCmd_len, receivedCmd_par);

        if (res == 2) { //Field is off!
            //FpgaDisableTracing();
            if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {
                p_em[1] = 0x21;
                cve_flipper = 0;
            }
            LEDsoff();
            cardSTATE = MFEMUL_NOFIELD;
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("cardSTATE = MFEMUL_NOFIELD");
            continue;
        } else if (res == 1) { // button pressed
            FpgaDisableTracing();
            button_pushed = true;
            if (g_dbglevel >= DBG_EXTENDED)
                Dbprintf("Button pressed");
            break;
        }

        // WUPA in HALTED state or REQA or WUPA in any other state
        if (receivedCmd_len == 1 && ((receivedCmd[0] == ISO14443A_CMD_REQA && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == ISO14443A_CMD_WUPA)) {
            selTimer = GetTickCount();
            if (g_dbglevel >= DBG_EXTENDED) {
                //Dbprintf("EmSendPrecompiledCmd(&responses[ATQA]);");
            }
            EmSendPrecompiledCmd(&responses[ATQA]);

            FpgaDisableTracing();

            // init crypto block
            crypto1_deinit(pcs);
            cardAUTHKEY = AUTHKEYNONE;
            nonce = prng_successor(selTimer, 32);
            // prepare NT for nested authentication
            num_to_bytes(nonce, 4, rAUTH_NT);
            num_to_bytes(cuid ^ nonce, 4, rAUTH_NT_keystream);

            LED_B_OFF();
            LED_C_OFF();
            cardSTATE = MFEMUL_SELECT;

            if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {
                p_em[1] = 0x21;
                cve_flipper = 0;
            }
            continue;
        }

        switch (cardSTATE) {
            case MFEMUL_NOFIELD: {
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_NOFIELD");
                break;
            }
            case MFEMUL_HALTED: {
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_HALTED");
                break;
            }
            case MFEMUL_IDLE: {
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_IDLE");
                break;
            }

            // The anti-collision sequence, which is a mandatory part of the card activation sequence.
            // It auto with 4-byte UID (= Single Size UID),
            // 7 -byte UID (= Double Size UID) or 10-byte UID (= Triple Size UID).
            // For details see chapter 2 of AN10927.pdf
            //
            // This case is used for all Cascade Levels, because:
            // 1) Any devices (under Android for example) after full select procedure completed,
            //    when UID is known, uses "fast-selection" method. In this case reader ignores
            //    first cascades and tries to select tag by last bytes of UID of last cascade
            // 2) Any readers (like ACR122U) uses bit oriented anti-collision frames during selectin,
            //    same as multiple tags. For details see chapter 6.1.5.3 of ISO/IEC 14443-3
            case MFEMUL_SELECT: {
                int uid_index = -1;
                // Extract cascade level
                if (receivedCmd_len >= 2) {
                    switch (receivedCmd[0]) {
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT:
                            uid_index = UIDBCC1;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_2:
                            uid_index = UIDBCC2;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_3:
                            uid_index = UIDBCC3;
                            break;
                    }
                }
                if (uid_index < 0) {
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    cardSTATE_TO_IDLE();
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Incorrect cascade level received");
                    break;
                }

                // Incoming SELECT ALL for any cascade level
                if (receivedCmd_len == 2 && receivedCmd[1] == 0x20) {
                    EmSendPrecompiledCmd(&responses[uid_index]);
                    FpgaDisableTracing();

                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("SELECT ALL - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                    break;
                }

                // Incoming SELECT CLx for any cascade level
                if (receivedCmd_len == 9 && receivedCmd[1] == 0x70) {
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, 4) == 0) {
                        bool cl_finished = (uid_len == 4  && uid_index == UIDBCC1) ||
                                           (uid_len == 7  && uid_index == UIDBCC2) ||
                                           (uid_len == 10 && uid_index == UIDBCC3);
                        EmSendPrecompiledCmd(&responses[cl_finished ? SAK : SAKuid]);
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("SELECT CLx %02x%02x%02x%02x received", receivedCmd[2], receivedCmd[3], receivedCmd[4], receivedCmd[5]);
                        if (cl_finished) {
                            LED_B_ON();
                            cardSTATE = MFEMUL_WORK;
                            if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_WORK");
                        }
                    } else {
                        // IDLE, not our UID
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }
                    break;
                }

                // Incoming anti-collision frame
                // receivedCmd[1] indicates number of byte and bit collision, supports only for bit collision is zero
                if (receivedCmd_len >= 3 && receivedCmd_len <= 6 && (receivedCmd[1] & 0x0f) == 0) {
                    // we can process only full-byte frame anti-collision procedure
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, receivedCmd_len - 2) == 0) {
                        // response missing part of UID via relative array index
                        EmSendPrecompiledCmd(&responses[uid_index + receivedCmd_len - 2]);
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                    } else {
                        // IDLE, not our UID or split-byte frame anti-collision (not supports)
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }
                    break;
                }

                // Unknown selection procedure
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                cardSTATE_TO_IDLE();
                if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Unknown selection procedure");
                break;
            }

            // WORK
            case MFEMUL_WORK: {

                if (g_dbglevel >= DBG_EXTENDED) {
                    // Dbprintf("[MFEMUL_WORK] Enter in case");
                }

                if (receivedCmd_len == 0) {
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] NO CMD received");
                    break;
                }

                encrypted_data = (cardAUTHKEY != AUTHKEYNONE);
                if (encrypted_data) {
                    // decrypt seqence
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, receivedCmd_dec);
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Decrypt sequence");
                } else {
                    // Data in clear
                    memcpy(receivedCmd_dec, receivedCmd, receivedCmd_len);
                }

                // all commands must have a valid CRC
                if (CheckCrc14A(receivedCmd_dec, receivedCmd_len) == false) {
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    FpgaDisableTracing();

                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] All commands must have a valid CRC %02X (%d)", receivedCmd_dec, receivedCmd_len);
                    break;
                }

                if (receivedCmd_len == 4 && (receivedCmd_dec[0] == MIFARE_AUTH_KEYA || receivedCmd_dec[0] == MIFARE_AUTH_KEYB)) {

                    // Reader asks for AUTH: 6X XX
                    // RCV: 60 XX => Using KEY A
                    // RCV: 61 XX => Using KEY B
                    // XX: Block number

                    authTimer = GetTickCount();

                    // received block num -> sector
                    // Example: 6X  [00]
                    // 4K tags have 16 blocks per sector 32..39
                    cardAUTHSC = MifareBlockToSector(receivedCmd_dec[1]);

                    // cardAUTHKEY: 60 => Auth use Key A
                    // cardAUTHKEY: 61 => Auth use Key B
                    cardAUTHKEY = receivedCmd_dec[0] & 0x01;

                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] KEY %c: %012" PRIx64, (cardAUTHKEY == 0) ? 'A' : 'B', emlGetKey(cardAUTHSC, cardAUTHKEY));

                    // sector out of range - do not respond
                    if (cardAUTHSC >= cardMaxSEC) {
                        cardAUTHKEY = AUTHKEYNONE; // not authenticated
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Out of range sector %d(0x%02x)", cardAUTHSC, cardAUTHSC);
                        break;
                    }

                    // first authentication
                    crypto1_deinit(pcs);

                    // Load key into crypto
                    crypto1_init(pcs, emlGetKey(cardAUTHSC, cardAUTHKEY));
                    running_nested_auth_attack = false;
                    if (!encrypted_data) {
                        // Receive Cmd in clear txt
                        // Update crypto state (UID ^ NONCE)
                        crypto1_word(pcs, cuid ^ nonce, 0);
                        // rAUTH_NT contains prepared nonce for authenticate
                        EmSendCmd(rAUTH_NT, sizeof(rAUTH_NT));
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_EXTENDED) {
                            Dbprintf("[MFEMUL_WORK] Reader authenticating for block %d (0x%02x) with key %c - nonce: %08X - cuid: %08X",
                                     receivedCmd_dec[1],
                                     receivedCmd_dec[1],
                                     (cardAUTHKEY == 0) ? 'A' : 'B',
                                     nonce,
                                     cuid
                                    );
                        }
                    } else {
                        // nested authentication
                        /*
                        ans = nonce ^ crypto1_word(pcs, cuid ^ nonce, 0);
                        num_to_bytes(ans, 4, rAUTH_AT);
                        */

                        // if key not known and FLAG_NESTED_AUTH_ATTACK and we have nt/nt_enc/parity, send recorded nt_enc and parity
                        if ((flags & FLAG_NESTED_AUTH_ATTACK) == FLAG_NESTED_AUTH_ATTACK) {
                            if (emlGetKey(cardAUTHSC, cardAUTHKEY) == 0) {
                                uint8_t buf[16] = {0};
                                emlGetMem(buf, (CARD_MEMORY_RF08S_OFFSET / MIFARE_BLOCK_SIZE) + cardAUTHSC, 1);
                                if (buf[(cardAUTHKEY * 8) + 3] == 0xAA) { // extra check to tell we have nt/nt_enc/par_err
                                    running_nested_auth_attack = true;
                                    // nt
                                    nonce = bytes_to_num(buf + (cardAUTHKEY * 8), 2);
                                    nonce = nonce << 16 | prng_successor(nonce, 16);
                                    // nt_enc
                                    memcpy(response, buf + (cardAUTHKEY * 8) + 4, 4);
                                    uint8_t nt_par_err = buf[(cardAUTHKEY * 8) + 2];
                                    uint32_t nt_enc = bytes_to_num(response, 4);
                                    response_par[0] = ((((nt_par_err >> 3) & 1) ^ oddparity8((nt_enc >> 24) & 0xFF)) << 7 |
                                                       (((nt_par_err >> 2) & 1) ^ oddparity8((nt_enc >> 16) & 0xFF)) << 6 |
                                                       (((nt_par_err >> 1) & 1) ^ oddparity8((nt_enc >> 8) & 0xFF)) << 5 |
                                                       (((nt_par_err >> 0) & 1) ^ oddparity8((nt_enc >> 0) & 0xFF)) << 4);
                                    ar_nr_resp[0].cuid = cuid;
                                    ar_nr_resp[0].sector = cardAUTHSC;
                                    ar_nr_resp[0].keytype = cardAUTHKEY;
                                    ar_nr_resp[0].nonce = nonce;
                                    ar_nr_resp[0].nonce2 = nt_enc;
                                };
                            }
                        }
                        if (running_nested_auth_attack == false) {
                            // rAUTH_NT, rAUTH_NT_keystream contains prepared nonce and keystream for nested authentication
                            // we need calculate parity bits for non-encrypted sequence
                            mf_crypto1_encryptEx(pcs, rAUTH_NT, rAUTH_NT_keystream, response, 4, response_par);
                        }
                        EmSendCmdPar(response, 4, response_par);
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_EXTENDED) {
                            Dbprintf("[MFEMUL_WORK] Reader doing nested authentication for block %d (0x%02x) with key %c",
                                     receivedCmd_dec[1],
                                     receivedCmd_dec[1],
                                     (cardAUTHKEY == 0) ? 'A' : 'B'
                                    );
                        }
                    }

                    cardSTATE = MFEMUL_AUTH1;
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_AUTH1 - rAUTH_NT: %02X", rAUTH_NT);
                    break;
                }

                // rule 13 of 7.5.3. in ISO 14443-4. chaining shall be continued
                // BUT... ACK --> NACK
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_ACK) {
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    FpgaDisableTracing();
                    break;
                }

                // rule 12 of 7.5.3. in ISO 14443-4. R(NAK) --> R(ACK)
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_NACK_NA) {
                    EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_ACK) : CARD_ACK);
                    FpgaDisableTracing();
                    break;
                }

                // case MFEMUL_WORK => if Cmd is Read, Write, Inc, Dec, Restore, Transfer
                if (receivedCmd_len == 4 && (receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK
                                             || receivedCmd_dec[0] == ISO14443A_CMD_WRITEBLOCK
                                             || receivedCmd_dec[0] == MIFARE_CMD_INC
                                             || receivedCmd_dec[0] == MIFARE_CMD_DEC
                                             || receivedCmd_dec[0] == MIFARE_CMD_RESTORE
                                             || receivedCmd_dec[0] == MIFARE_CMD_TRANSFER)) {
                    // all other commands must be encrypted (authenticated)
                    if (!encrypted_data) {
                        EmSend4bit(CARD_NACK_NA);
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] Commands must be encrypted (authenticated)");
                        break;
                    }

                    // iceman,   u8 can never be larger the  MIFARE_4K_MAXBLOCK (256)
                    // Check if Block num is not too far
                    /*
                    if (receivedCmd_dec[1] > MIFARE_4K_MAXBLOCK) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        FpgaDisableTracing();
                        if (g_dbglevel >= DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate (0x%02x) on out of range block: %d (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], receivedCmd_dec[1]);
                        break;
                    }
                    */
                    blockNo = receivedCmd_dec[1];
                    if (MifareBlockToSector(blockNo) != cardAUTHSC) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        FpgaDisableTracing();

                        if (g_dbglevel >= DBG_ERROR)
                            Dbprintf("[MFEMUL_WORK] Reader tried to operate (0x%02x) on block (0x%02x) not authenticated for (0x%02x), nacking", receivedCmd_dec[0], receivedCmd_dec[1], cardAUTHSC);
                        break;
                    }

                    // Compliance of MIFARE Classic EV1 1K Datasheet footnote of Table 8
                    // If access bits show that key B is Readable, any subsequent memory access will be refused.
                    // Some cards don't respect it so we can also skip it with FLAG_MF_USE_READ_KEYB
                    if ((flags & FLAG_MF_USE_READ_KEYB) != FLAG_MF_USE_READ_KEYB) {
                        if (cardAUTHKEY == AUTHKEYB && IsKeyBReadable(blockNo)) {
                            EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                            FpgaDisableTracing();

                            if (g_dbglevel >= DBG_ERROR)
                                Dbprintf("[MFEMUL_WORK] Access denied: Reader tried to access memory on authentication with key B while key B is readable in sector (0x%02x)", cardAUTHSC);
                            break;
                        }
                    }
                }

                // case MFEMUL_WORK => CMD READ block
                if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK) {
                    blockNo = receivedCmd_dec[1];
                    if (g_dbglevel >= DBG_EXTENDED)
                        Dbprintf("[MFEMUL_WORK] Reader reading block %d (0x%02x)", blockNo, blockNo);

                    // android CVE 2021_0430
                    // Simulate a MFC 1K,  with a NDEF message.
                    // these values uses the standard LIBNFC NDEF message
                    //
                    // In short,  first a value read of block 4,
                    // update the length byte before second read of block 4.
                    // on iphone etc there might even be 3 reads of block 4.
                    // fiddling with when to flip the byte or not,  has different effects
                    if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {

                        // first block
                        if (blockNo == 4) {

                            p_em += blockNo * 16;
                            // TLV in NDEF, flip length between
                            //  4 | 03 21 D1 02 1C 53 70 91 01 09 54 02 65 6E 4C 69
                            // 0xFF means long length
                            // 0xFE mean max short length

                            // We could also have a go at message len byte at p_em[4]...
                            if (p_em[1] == 0x21 && cve_flipper == 1) {
                                p_em[1] = 0xFE;
                            } else {
                                cve_flipper++;
                            }
                        }
                    }

                    emlGetMem(response, blockNo, 1);

                    if (g_dbglevel >= DBG_EXTENDED)  {
                        Dbprintf("[MFEMUL_WORK - ISO14443A_CMD_READBLOCK] Data Block[%d]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", blockNo,
                                 response[0], response[1], response[2], response[3],  response[4],  response[5],  response[6],
                                 response[7], response[8], response[9], response[10], response[11], response[12], response[13],
                                 response[14], response[15]);
                    }

                    // Access permission management:
                    //
                    // Sector Trailer:
                    // - KEY A access
                    // - KEY B access
                    // - AC bits access
                    //
                    // Data block:
                    // - Data access

                    // If permission is not allowed, data is cleared (00) in emulator memory.
                    // ex: a0a1a2a3a4a561e789c1b0b1b2b3b4b5 => 00000000000061e789c1b0b1b2b3b4b5


                    // Check if selected Block is a Sector Trailer
                    if (IsSectorTrailer(blockNo)) {

                        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_KEYA_READ) == false) {
                            memset(response, 0x00, 6); // keyA can never be read
                            if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsSectorTrailer] keyA can never be read - block %d (0x%02x)", blockNo, blockNo);
                        }
                        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_KEYB_READ) == false) {
                            memset(response + 10, 0x00, 6); // keyB cannot be read
                            if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsSectorTrailer] keyB cannot be read - block %d (0x%02x)", blockNo, blockNo);
                        }
                        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_AC_READ) == false) {
                            memset(response + 6, 0x00, 4); // AC bits cannot be read
                            if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsAccessAllowed] AC bits cannot be read - block %d (0x%02x)", blockNo, blockNo);
                        }
                    } else {
                        if (IsAccessAllowed(blockNo, cardAUTHKEY, AC_DATA_READ) == false) {
                            memset(response, 0x00, 16); // datablock cannot be read
                            if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK - IsAccessAllowed] Data block %d (0x%02x) cannot be read", blockNo, blockNo);
                        }
                    }
                    AddCrc14A(response, 16);
                    mf_crypto1_encrypt(pcs, response, MAX_MIFARE_FRAME_SIZE, response_par);
                    EmSendCmdPar(response, MAX_MIFARE_FRAME_SIZE, response_par);
                    FpgaDisableTracing();

                    if (g_dbglevel >= DBG_EXTENDED) {
                        Dbprintf("[MFEMUL_WORK - EmSendCmdPar] Data Block[%d]: %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x", blockNo,
                                 response[0], response[1], response[2], response[3],  response[4],  response[5],  response[6],
                                 response[7], response[8], response[9], response[10], response[11], response[12], response[13],
                                 response[14], response[15]);
                    }
                    numReads++;

                    if (exitAfterNReads > 0 && numReads == exitAfterNReads) {
                        Dbprintf("[MFEMUL_WORK] %d reads done, exiting", numReads);
                        finished = true;
                    }
                    break;

                } // End receivedCmd_dec[0] == ISO14443A_CMD_READBLOCK

                // case MFEMUL_WORK => CMD WRITEBLOCK
                if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_WRITEBLOCK) {
                    blockNo = receivedCmd_dec[1];
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0xA0 write block %d (%02x)", blockNo, blockNo);
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                    FpgaDisableTracing();

                    cardWRBL = blockNo;
                    cardSTATE = MFEMUL_WRITEBL2;
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_WRITEBL2");
                    break;
                }

                // case MFEMUL_WORK => CMD INC/DEC/REST
                if (receivedCmd_len == 4 && (receivedCmd_dec[0] == MIFARE_CMD_INC || receivedCmd_dec[0] == MIFARE_CMD_DEC || receivedCmd_dec[0] == MIFARE_CMD_RESTORE)) {
                    blockNo = receivedCmd_dec[1];
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x inc(0xC1)/dec(0xC0)/restore(0xC2) block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                    if (emlCheckValBl(blockNo) == false) {
                        if (g_dbglevel >= DBG_ERROR) Dbprintf("[MFEMUL_WORK] Reader tried to operate on block, but emlCheckValBl failed, nacking");
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        FpgaDisableTracing();
                        break;
                    }
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                    FpgaDisableTracing();
                    cardWRBL = blockNo;

                    // INC
                    if (receivedCmd_dec[0] == MIFARE_CMD_INC) {
                        cardSTATE = MFEMUL_INTREG_INC;
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_INC");
                    }

                    // DEC
                    if (receivedCmd_dec[0] == MIFARE_CMD_DEC) {
                        cardSTATE = MFEMUL_INTREG_DEC;
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_DEC");
                    }

                    // REST
                    if (receivedCmd_dec[0] == MIFARE_CMD_RESTORE) {
                        cardSTATE = MFEMUL_INTREG_REST;
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_INTREG_REST");
                    }
                    break;

                } // End case MFEMUL_WORK => CMD INC/DEC/REST


                // case MFEMUL_WORK => CMD TRANSFER
                if (receivedCmd_len == 4 && receivedCmd_dec[0] == MIFARE_CMD_TRANSFER) {
                    blockNo = receivedCmd_dec[1];
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] RECV 0x%02x transfer block %d (%02x)", receivedCmd_dec[0], blockNo, blockNo);
                    emlSetValBl(cardINTREG, cardINTBLOCK, receivedCmd_dec[1]);
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK));
                    FpgaDisableTracing();
                    break;
                }

                // case MFEMUL_WORK => CMD HALT
                if (receivedCmd_len > 1 && receivedCmd_dec[0] == ISO14443A_CMD_HALT && receivedCmd_dec[1] == 0x00) {
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    LED_B_OFF();
                    LED_C_OFF();
                    cardSTATE = MFEMUL_HALTED;
                    cardAUTHKEY = AUTHKEYNONE;
                    if (g_dbglevel >= DBG_EXTENDED) {
                        Dbprintf("[MFEMUL_WORK] cardSTATE = MFEMUL_HALTED");
                    }
                    break;
                }

                // case MFEMUL_WORK => CMD RATS
                if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_RATS && (receivedCmd_dec[1] & 0xF0) <= 0x80 && (receivedCmd_dec[1] & 0x0F) <= 0x0e) {
                    if (rats && rats_len) {
                        if (encrypted_data) {
                            memcpy(response, rats, rats_len);
                            mf_crypto1_encrypt(pcs, response, rats_len, response_par);
                            EmSendCmdPar(response, rats_len, response_par);
                        } else {
                            EmSendCmd(rats, rats_len);
                        }
                        FpgaDisableTracing();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV RATS => ACK");
                    } else {
                        EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV RATS => NACK");
                    }
                    break;
                }

                // case MFEMUL_WORK => ISO14443A_CMD_NXP_DESELECT
                if (receivedCmd_len == 3 && receivedCmd_dec[0] == ISO14443A_CMD_NXP_DESELECT) {
                    if (rats && rats_len) {
                        // response back NXP_DESELECT
                        if (encrypted_data) {
                            memcpy(response, receivedCmd_dec, receivedCmd_len);
                            mf_crypto1_encrypt(pcs, response, receivedCmd_len, response_par);
                            EmSendCmdPar(response, receivedCmd_len, response_par);
                        } else
                            EmSendCmd(receivedCmd_dec, receivedCmd_len);

                        FpgaDisableTracing();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV NXP DESELECT => ACK");
                    } else {
                        EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (g_dbglevel >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV NXP DESELECT => NACK");
                    }
                    break;
                }

                // case MFEMUL_WORK => command not allowed
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("Received command not allowed, nacking");
                EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                FpgaDisableTracing();
                break;
            }

            // AUTH1
            case MFEMUL_AUTH1: {
                if (g_dbglevel >= DBG_EXTENDED)
                    Dbprintf("[MFEMUL_AUTH1] Enter case");

                if (receivedCmd_len != 8) {
                    cardSTATE_TO_IDLE();
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    if (g_dbglevel >= DBG_EXTENDED)
                        Dbprintf("MFEMUL_AUTH1: receivedCmd_len != 8 (%d) => cardSTATE_TO_IDLE())", receivedCmd_len);
                    break;
                }

                nr = bytes_to_num(receivedCmd, 4);
                ar = bytes_to_num(&receivedCmd[4], 4);

                // --- crypto
                crypto1_word(pcs, nr, 1);
                cardRr = ar ^ crypto1_word(pcs, 0, 0);

                // test if auth KO
                if (cardRr != prng_successor(nonce, 64)) {
                    // Collect AR/NR per keytype & sector
                    if (running_nested_auth_attack) {
                        ar_nr_resp[0].nr = nr;
                        ar_nr_resp[0].ar = ar;
                        ar_nr_resp[0].state = NESTED;
                        finished = true;
                    }
                    if ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) {

                        for (uint8_t i = 0; i < ATTACK_KEY_COUNT; i++) {
                            if (ar_nr_resp[i].state == EMPTY ||
                                    (
                                        (ar_nr_resp[i].state != EMPTY) &&
                                        (cardAUTHSC == ar_nr_resp[i].sector) &&
                                        (cardAUTHKEY == ar_nr_resp[i].keytype)
                                    )
                               ) {
                                // if first auth for sector, or matches sector and keytype of previous auth
                                if (ar_nr_resp[i].state != SECOND) {
                                    // if we haven't already collected 2 nonces for this sector
                                    if (ar_nr_resp[i].state == EMPTY) {
                                        // first nonce collect
                                        ar_nr_resp[i].cuid = cuid;
                                        ar_nr_resp[i].sector = cardAUTHSC;
                                        ar_nr_resp[i].keytype = cardAUTHKEY;
                                        ar_nr_resp[i].nonce = nonce;
                                        ar_nr_resp[i].nr = nr;
                                        ar_nr_resp[i].ar = ar;
                                        ar_nr_resp[i].state = FIRST;
                                    } else { // second nonce collect
                                        // make sure we have different nonces for moebius attack
                                        if (ar_nr_resp[i].nonce != nonce) {
                                            ar_nr_resp[i].nonce2 = nonce;
                                            ar_nr_resp[i].nr2 = nr;
                                            ar_nr_resp[i].ar2 = ar;
                                            ar_nr_resp[i].state = SECOND;
                                            finished = true;
                                        }
                                    }
                                }
                                // we found right spot for this nonce stop looking
                                break;
                            }
                        }
                    }
                    if (g_dbglevel >= DBG_EXTENDED) {
                        Dbprintf("[MFEMUL_AUTH1] AUTH FAILED for sector %d with key %c. [nr=%08x  cardRr=%08x] [nt=%08x succ=%08x]"
                                 , cardAUTHSC
                                 , (cardAUTHKEY == 0) ? 'A' : 'B'
                                 , nr
                                 , cardRr
                                 , nonce // nt
                                 , prng_successor(nonce, 64)
                                );
                    }
                    cardAUTHKEY = AUTHKEYNONE; // not authenticated
                    cardSTATE_TO_IDLE();
                    // Really tags not respond NACK on invalid authentication
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    break;
                }

                ans = prng_successor(nonce, 96);
                num_to_bytes(ans, 4, response);
                mf_crypto1_encrypt(pcs, response, 4, response_par);
                EmSendCmdPar(response, 4, response_par);
                FpgaDisableTracing();

                if (g_dbglevel >= DBG_EXTENDED) {
                    Dbprintf("[MFEMUL_AUTH1] AUTH COMPLETED for sector %d with key %c. time=%d",
                             cardAUTHSC,
                             cardAUTHKEY == 0 ? 'A' : 'B',
                             GetTickCountDelta(authTimer)
                            );
                }
                LED_C_ON();
                cardSTATE = MFEMUL_WORK;
                if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_AUTH1] cardSTATE = MFEMUL_WORK");
                break;
            }

            // WRITE BL2
            case MFEMUL_WRITEBL2: {
                if (receivedCmd_len == MAX_MIFARE_FRAME_SIZE) {
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, receivedCmd_dec);
                    if (CheckCrc14A(receivedCmd_dec, receivedCmd_len)) {
                        if (IsSectorTrailer(cardWRBL)) {
                            emlGetMem(response, cardWRBL, 1);
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_KEYA_WRITE)) {
                                memcpy(receivedCmd_dec, response, 6); // don't change KeyA
                            }
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_KEYB_WRITE)) {
                                memcpy(receivedCmd_dec + 10, response + 10, 6); // don't change KeyA
                            }
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_AC_WRITE)) {
                                memcpy(receivedCmd_dec + 6, response + 6, 4); // don't change AC bits
                            }
                        } else {
                            if (!IsAccessAllowed(cardWRBL, cardAUTHKEY, AC_DATA_WRITE)) {
                                memcpy(receivedCmd_dec, response, 16); // don't change anything
                            }
                        }
                        emlSetMem_xt(receivedCmd_dec, cardWRBL, 1, 16);
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_ACK)); // always ACK?
                        FpgaDisableTracing();

                        cardSTATE = MFEMUL_WORK;
                        if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WRITEBL2] cardSTATE = MFEMUL_WORK");
                        break;
                    }
                }
                cardSTATE_TO_IDLE();
                if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_WRITEBL2] cardSTATE = MFEMUL_IDLE");
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                break;
            }

            // INC
            case MFEMUL_INTREG_INC: {
                if (receivedCmd_len == 6) {
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, (uint8_t *)&ans);
                    if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL) != PM3_SUCCESS) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        FpgaDisableTracing();

                        cardSTATE_TO_IDLE();
                        break;
                    }
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    cardINTREG = cardINTREG + ans;

                    cardSTATE = MFEMUL_WORK;
                    if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_INTREG_INC] cardSTATE = MFEMUL_WORK");
                    break;
                }
            }

            // DEC
            case MFEMUL_INTREG_DEC: {
                if (receivedCmd_len == 6) {  //  Data is encrypted
                    // Decrypted cmd
                    mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, (uint8_t *)&ans);
                    if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL) != PM3_SUCCESS) {
                        EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                        FpgaDisableTracing();

                        cardSTATE_TO_IDLE();
                        break;
                    }
                }
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                cardINTREG = cardINTREG - ans;
                cardSTATE = MFEMUL_WORK;
                if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_INTREG_DEC] cardSTATE = MFEMUL_WORK");
                break;
            }

            // REST
            case MFEMUL_INTREG_REST: {
                mf_crypto1_decryptEx(pcs, receivedCmd, receivedCmd_len, (uint8_t *)&ans);
                if (emlGetValBl(&cardINTREG, &cardINTBLOCK, cardWRBL) != PM3_SUCCESS) {
                    EmSend4bit(mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA));
                    FpgaDisableTracing();

                    cardSTATE_TO_IDLE();
                    break;
                }
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                cardSTATE = MFEMUL_WORK;
                if (g_dbglevel >= DBG_EXTENDED) Dbprintf("[MFEMUL_INTREG_REST] cardSTATE = MFEMUL_WORK");
                break;
            }

        }  // End Switch Loop

        button_pushed = BUTTON_PRESS();

    }  // End While Loop

    FpgaDisableTracing();

    uint8_t index = 0;
    if (running_nested_auth_attack) {
        if ((nonce_state)ar_nr_resp[0].state == NESTED) {
            running_nested_auth_attack = false;
            if (g_dbglevel >= DBG_INFO) {
                Dbprintf("Collected nested AR/NR which can be used to extract sector %d " _YELLOW_("%s")
                         , ar_nr_resp[0].sector
                         , (ar_nr_resp[0].keytype == AUTHKEYA) ? "key A" : "key B"
                        );
                Dbprintf("../tools/mfc/card_reader/mfkey32nested %08x %08x %08x %08x %08x",
                         ar_nr_resp[0].cuid,  //UID
                         ar_nr_resp[0].nonce, //NT
                         ar_nr_resp[0].nonce2,//NT_ENC
                         ar_nr_resp[0].nr,    //NR1
                         ar_nr_resp[0].ar     //AR1
                        );
            }
        }
    } else {
        // NR AR ATTACK
        if ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) {
            for (uint8_t i = 0; i < ATTACK_KEY_COUNT; i++) {
                if ((nonce_state)ar_nr_resp[i].state == SECOND) {
                    index = i;
                    if (g_dbglevel >= DBG_INFO) {
                        Dbprintf("Collected two pairs of AR/NR which can be used to extract sector %d " _YELLOW_("%s")
                                 , ar_nr_resp[i].sector
                                 , (ar_nr_resp[i].keytype == AUTHKEYA) ? "key A" : "key B"
                                );
                        Dbprintf("../tools/mfc/card_reader/mfkey32v2 %08x %08x %08x %08x %08x %08x %08x",
                                 ar_nr_resp[i].cuid,  //UID
                                 ar_nr_resp[i].nonce, //NT
                                 ar_nr_resp[i].nr,    //NR1
                                 ar_nr_resp[i].ar,    //AR1
                                 ar_nr_resp[i].nonce2,//NT2
                                 ar_nr_resp[i].nr2,   //NR2
                                 ar_nr_resp[i].ar2    //AR2
                                );
                    }
                }
            }
        }
    }
    if (g_dbglevel >= DBG_ERROR) {
        Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", get_tracing(), BigBuf_get_traceLen());
    }

    if ((flags & FLAG_INTERACTIVE) == FLAG_INTERACTIVE) {  // Interactive mode flag, means we need to send ACK
        //Send the collected ar_nr in the response
        reply_ng(CMD_HF_MIFARE_SIMULATE, button_pushed ? PM3_EOPABORTED : PM3_SUCCESS, (uint8_t *)&ar_nr_resp[index], sizeof(nonces_t));
    }

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    set_tracing(false);
    BigBuf_free_keep_EM();
}
