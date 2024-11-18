//-----------------------------------------------------------------------------
// Copyright (C) n-hutton - Sept 2024
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
// EVM contact to contactless bridge attack
//-----------------------------------------------------------------------------

// Verbose Mode:
// DBG_NONE          0
// DBG_ERROR         1
// DBG_INFO          2
// DBG_DEBUG         3
// DBG_EXTENDED      4

//  /!\ Printing Debug message is disrupting emulation,
//  Only use with caution during debugging

#include "emvsim.h"

#include <inttypes.h>

#include "BigBuf.h"
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
#include "i2c.h"
#include "i2c_direct.h"

#pragma GCC diagnostic ignored "-Wunused-variable"
#pragma GCC diagnostic ignored "-Wunused-but-set-variable"
#pragma GCC diagnostic ignored "-Wunused-function"

static uint8_t filenotfound[] = {0x02, 0x6a, 0x82, 0x93, 0x2f};

// query and response that inserts PDOL so as to continue process...
static uint8_t fci_query[] = {0x02, 0x00, 0xa4, 0x04, 0x00, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x00, 0x56, 0x3f};
static uint8_t fci_template[] = {0x02, 0x6f, 0x5e, 0x84, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0xa5, 0x53, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x38, 0x18, 0x9f, 0x66, 0x04, 0x9f, 0x02, 0x06, 0x9f, 0x03, 0x06, 0x9f, 0x1a, 0x02, 0x95, 0x05, 0x5f, 0x2a, 0x02, 0x9a, 0x03, 0x9c, 0x01, 0x9f, 0x37, 0x04, 0x5f, 0x2d, 0x02, 0x65, 0x6e, 0x9f, 0x11, 0x01, 0x01, 0x9f, 0x12, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0xbf, 0x0c, 0x13, 0x9f, 0x5a, 0x05, 0x31, 0x08, 0x26, 0x08, 0x26, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0xd8, 0x15};

static uint8_t pay1_response[] = { 0x6F, 0x1E, 0x84, 0x0E, 0x31, 0x50, 0x41, 0x59 };
static uint8_t pay2_response[] = { 0x03, 0x6f, 0x3e, 0x84, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x2c, 0xbf, 0x0c, 0x29, 0x61, 0x27, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10, 0x50, 0x0a, 0x56, 0x69, 0x73, 0x61, 0x20, 0x44, 0x65, 0x62, 0x69, 0x74, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x01, 0x00, 0x00, 0x00, 0x00, 0xbf, 0x63, 0x04, 0xdf, 0x20, 0x01, 0x80, 0x90, 0x00, 0x07, 0x9d};

static bool MifareSimInit(uint16_t flags, uint8_t *datain, uint16_t atqa, uint8_t sak, tag_response_info_t **responses, uint32_t *cuid, uint8_t *uid_len, uint8_t **rats, uint8_t *rats_len) {

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

    // Get UID, SAK, ATQA from EMUL
    if ((flags & FLAG_UID_IN_EMUL) == FLAG_UID_IN_EMUL) {
        uint8_t block0[16];
        emlGet(block0, 0, 16);

        // If uid size defined, copy only uid from EMUL to use, backward compatibility for 'hf_colin.c', 'hf_mattyrun.c'
        if ((flags & (FLAG_4B_UID_IN_DATA | FLAG_7B_UID_IN_DATA | FLAG_10B_UID_IN_DATA)) != 0) {
            memcpy(datain, block0, 10);  // load 10bytes from EMUL to the datain pointer. to be used below.
        } else {
            // Check for 4 bytes uid: bcc corrected and single size uid bits in ATQA
            if ((block0[0] ^ block0[1] ^ block0[2] ^ block0[3]) == block0[4] && (block0[6] & 0xc0) == 0) {
                flags |= FLAG_4B_UID_IN_DATA;
                memcpy(datain, block0, 4);
                rSAK[0] = block0[5];
                memcpy(rATQA, &block0[6], sizeof(rATQA));
            }
                // Check for 7 bytes UID: double size uid bits in ATQA
            else if ((block0[8] & 0xc0) == 0x40) {
                flags |= FLAG_7B_UID_IN_DATA;
                memcpy(datain, block0, 7);
                rSAK[0] = block0[7];
                memcpy(rATQA, &block0[8], sizeof(rATQA));
            } else {
                Dbprintf("ERROR: " _RED_("Invalid dump. UID/SAK/ATQA not found"));
                return false;
            }
        }

    }

    // Tune tag type, if defined directly
    // Otherwise use defined by default or extracted from EMUL
    if ((flags & FLAG_MF_MINI) == FLAG_MF_MINI) {
        memcpy(rATQA, rATQA_Mini, sizeof(rATQA));
        rSAK[0] = rSAK_Mini;
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare Mini ATQA/SAK");
    } else if ((flags & FLAG_MF_1K) == FLAG_MF_1K) {
        memcpy(rATQA, rATQA_1k, sizeof(rATQA));
        rSAK[0] = rSAK_1k;
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare 1K ATQA/SAK (!!!!)");
    } else if ((flags & FLAG_MF_2K) == FLAG_MF_2K) {
        memcpy(rATQA, rATQA_2k, sizeof(rATQA));
        rSAK[0] = rSAK_2k;
        *rats = rRATS;
        *rats_len = sizeof(rRATS);
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare 2K ATQA/SAK with RATS support");
    } else if ((flags & FLAG_MF_4K) == FLAG_MF_4K) {
        memcpy(rATQA, rATQA_4k, sizeof(rATQA));
        rSAK[0] = rSAK_4k;
        if (999 > DBG_NONE) Dbprintf("Enforcing Mifare 4K ATQA/SAK");
    }

    // Prepare UID arrays
    if ((flags & FLAG_4B_UID_IN_DATA) == FLAG_4B_UID_IN_DATA) { // get UID from datain
        memcpy(rUIDBCC1, datain, 4);
        *uid_len = 4;
        if (999 >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - FLAG_4B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_4B_UID_IN_DATA, flags, rUIDBCC1);

        // save CUID
        *cuid = bytes_to_num(rUIDBCC1, 4);
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        if (999 > DBG_NONE) {
            Dbprintf("4B UID: %02x%02x%02x%02x", rUIDBCC1[0], rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3]);
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x00; // single size uid

    } else if ((flags & FLAG_7B_UID_IN_DATA) == FLAG_7B_UID_IN_DATA) {
        memcpy(&rUIDBCC1[1], datain, 3);
        memcpy(rUIDBCC2, datain + 3, 4);
        *uid_len = 7;
        if (999 >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - FLAG_7B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_7B_UID_IN_DATA, flags, rUIDBCC1);

        // save CUID
        *cuid = bytes_to_num(rUIDBCC2, 4);
        // CascadeTag, CT
        rUIDBCC1[0] = MIFARE_SELECT_CT;
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        if (999 > DBG_NONE) {
            Dbprintf("7B UID: %02x %02x %02x %02x %02x %02x %02x",
                     rUIDBCC1[1], rUIDBCC1[2], rUIDBCC1[3], rUIDBCC2[0], rUIDBCC2[1], rUIDBCC2[2], rUIDBCC2[3]);
        }

        // Correct uid size bits in ATQA
        rATQA[0] = (rATQA[0] & 0x3f) | 0x40; // double size uid

    } else if ((flags & FLAG_10B_UID_IN_DATA) == FLAG_10B_UID_IN_DATA) {
        memcpy(&rUIDBCC1[1], datain,   3);
        memcpy(&rUIDBCC2[1], datain + 3, 3);
        memcpy(rUIDBCC3,    datain + 6, 4);
        *uid_len = 10;
        if (999 >= DBG_EXTENDED)
            Dbprintf("MifareSimInit - FLAG_10B_UID_IN_DATA => Get UID from datain: %02X - Flag: %02X - UIDBCC1: %02X", FLAG_10B_UID_IN_DATA, flags, rUIDBCC1);

        // save CUID
        *cuid = bytes_to_num(rUIDBCC3, 4);
        // CascadeTag, CT
        rUIDBCC1[0] = MIFARE_SELECT_CT;
        rUIDBCC2[0] = MIFARE_SELECT_CT;
        // BCC
        rUIDBCC1[4] = rUIDBCC1[0] ^ rUIDBCC1[1] ^ rUIDBCC1[2] ^ rUIDBCC1[3];
        rUIDBCC2[4] = rUIDBCC2[0] ^ rUIDBCC2[1] ^ rUIDBCC2[2] ^ rUIDBCC2[3];
        rUIDBCC3[4] = rUIDBCC3[0] ^ rUIDBCC3[1] ^ rUIDBCC3[2] ^ rUIDBCC3[3];

        if (999 > DBG_NONE) {
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
    if (flags & FLAG_FORCED_ATQA) {
        rATQA[0] = atqa >> 8;
        rATQA[1] = atqa & 0xff;
    }
    if (flags & FLAG_FORCED_SAK) {
        rSAK[0] = sak;
    }

    if (999 > DBG_NONE) {
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
*xxxxxxxxxxxxxxxxxx.
*
*@param flags :
*@param exitAfterNReads, exit simulation after n blocks have been read, 0 is infinite ...
* (unless reader attack mode enabled then it runs util it gets enough nonces to recover all keys attmpted)
*/
void EMVsim(uint16_t flags, uint8_t exitAfterNReads, uint8_t *datain, uint16_t atqa, uint8_t sak) {

    tag_response_info_t *responses;
    uint8_t cardSTATE = MFEMUL_NOFIELD;
    uint8_t uid_len = 0; // 4, 7, 10
    uint32_t cuid = 0, authTimer = 0;
    uint32_t nr, ar;
    //uint8_t blockNo;
    //bool encrypted_data;

    uint8_t cardWRBL = 0;
    uint8_t cardAUTHSC = 0;
    uint8_t cardAUTHKEY = AUTHKEYNONE;  // no authentication
    uint32_t cardRr = 0;
    uint32_t ans = 0;
    uint32_t cardINTREG = 0;
    uint8_t cardINTBLOCK = 0;

    struct Crypto1State mpcs = {0, 0};
    struct Crypto1State *pcs;
    pcs = &mpcs;

    //uint32_t numReads = 0; //Counts numer of times reader reads a block
    uint8_t receivedCmd[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_copy[MAX_FRAME_SIZE] = {0x00};
    uint8_t receivedCmd_dec[MAX_FRAME_SIZE] = {0x00};
    //uint8_t convenient_buffer[64] = {0x00};
    uint8_t receivedCmd_par[MAX_MIFARE_PARITY_SIZE] = {0x00};
    uint8_t responseToReader[MAX_FRAME_SIZE] = {0x00};
    uint16_t responseToReader_len;
    uint16_t receivedCmd_len;
    uint16_t receivedCmd_len_copy = 0;

    if (receivedCmd_len_copy) {
        Dbprintf("receivedCmd_len_copy: %d", receivedCmd_len_copy);
    }

    //volatile uint8_t response[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t response[MAX_MIFARE_FRAME_SIZE] = {0x00};
    uint8_t response_par[MAX_MIFARE_PARITY_SIZE] = {0x00};

    uint8_t *rats = NULL;
    uint8_t rats_len = 0;


    // if fct is called with NULL we need to assign some memory since this pointer is passaed around
    uint8_t datain_tmp[10] = {0};
    if (datain == NULL) {
        datain = datain_tmp;
    }

    //Here, we collect UID,sector,keytype,NT,AR,NR,NT2,AR2,NR2
    // This will be used in the reader-only attack.

    //allow collecting up to 7 sets of nonces to allow recovery of up to 7 keys
#define ATTACK_KEY_COUNT 7 // keep same as define in cmdhfmf.c -> readerAttack() (Cannot be more than 7)
    nonces_t ar_nr_resp[ATTACK_KEY_COUNT * 2]; // *2 for 2 separate attack types (nml, moebius) 36 * 7 * 2 bytes = 504 bytes
    memset(ar_nr_resp, 0x00, sizeof(ar_nr_resp));

    uint8_t ar_nr_collected[ATTACK_KEY_COUNT * 2]; // *2 for 2nd attack type (moebius)
    memset(ar_nr_collected, 0x00, sizeof(ar_nr_collected));
    uint8_t nonce1_count = 0;
    uint8_t nonce2_count = 0;
    uint8_t moebius_n_count = 0;
    bool gettingMoebius = false;
    uint8_t mM = 0; //moebius_modifier for collection storage

    // Authenticate response - nonce
    //uint8_t rAUTH_NT[4] = {0, 0, 0, 1};
    //uint8_t rAUTH_NT_keystream[4];
    uint32_t nonce = 0;

    const tUart14a *uart = GetUart14a();

    // free eventually allocated BigBuf memory but keep Emulator Memory
    BigBuf_free_keep_EM();

    Dbprintf("Sim init...");

    if (MifareSimInit(flags, datain, atqa, sak, &responses, &cuid, &uid_len, &rats, &rats_len) == false) {
        BigBuf_free_keep_EM();
        return;
    }

    Dbprintf("Sim finish...");

    // We need to listen to the high-frequency, peak-detected path.
    iso14443a_setup(FPGA_HF_ISO14443A_TAGSIM_LISTEN);

    Dbprintf("Sim finish...");

    // clear trace
    clear_trace();
    set_tracing(true);
    LED_D_ON();
    ResetSspClk();

    uint8_t *p_em = BigBuf_get_EM_addr();
    //uint8_t cve_flipper = 0;

    int counter = 0;
    bool finished = false;
    bool button_pushed = BUTTON_PRESS();

    // nathan

    Dbprintf("Loop ending!");

    while ((button_pushed == false) && (finished == false)) {

        WDT_HIT();

        if (counter == 3000) {
            if (data_available()) {
                Dbprintf("----------- " _GREEN_("BREAKING") " ----------");
                break;
            }
            counter = 0;
        } else {
            counter++;
        }

        FpgaEnableTracing();
        // Now, get data from the FPGA
        int res = EmGetCmd(receivedCmd, sizeof(receivedCmd), &receivedCmd_len, receivedCmd_par);
        bool was_three = false;

        if (receivedCmd[0] == 3) {
            was_three = true;
        }

        if (was_three && receivedCmd[0] != 3) {
            Dbprintf("We have found our segv here 000");
        }

        // print the commmand we got and its length

        //if(receivedCmd_len > 1) {
        //    Dbprintf("Received command: %d bytes", receivedCmd_len);
        //    //Dbhexdump(receivedCmd_len, receivedCmd, false);
        //}

        //Dbprintf("Received command: %d bytes", receivedCmd_len); // this breaks the emulator
        //Dbhexdump(receivedCmd_len, receivedCmd, false);

        //int res = EmGetCmd(receivedCmd, &receivedCmd_len, receivedCmd_par); // nathan old - seems like bugfix.

        if (res == 2) { //Field is off!
            //FpgaDisableTracing();
            if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {
                p_em[1] = 0x21;
                //cve_flipper = 0;
            }
            LEDsoff();
            if (cardSTATE != MFEMUL_NOFIELD) {
                Dbprintf("cardSTATE = MFEMUL_NOFIELD");
                break;
            }
            cardSTATE = MFEMUL_NOFIELD;
            continue;
        } else if (res == 1) { // button pressed
            FpgaDisableTracing();
            button_pushed = true;
            if (999 >= DBG_EXTENDED)
                Dbprintf("Button pressed");
            break;
        }

        if (was_three && receivedCmd[0] != 3) {
            Dbprintf("We have found our segv here 001");
        }

        // WUPA in HALTED state or REQA or WUPA in any other state
        if (receivedCmd_len == 1 && ((receivedCmd[0] == ISO14443A_CMD_REQA && cardSTATE != MFEMUL_HALTED) || receivedCmd[0] == ISO14443A_CMD_WUPA)) {
            //selTimer = GetTickCount();
            if (999 >= DBG_EXTENDED) {
                //Dbprintf("EmSendPrecompiledCmd(&responses[ATQA]);");
            }
            EmSendPrecompiledCmd(&responses[ATQA]);

            FpgaDisableTracing();

            if (was_three && receivedCmd[0] != 3) {
                Dbprintf("We have found our segv here 002");
            }

            /*
            // init crypto block
            crypto1_deinit(pcs);
            cardAUTHKEY = AUTHKEYNONE;
            nonce = prng_successor(selTimer, 32);
            // prepare NT for nested authentication
            num_to_bytes(nonce, 4, rAUTH_NT);
            num_to_bytes(cuid ^ nonce, 4, rAUTH_NT_keystream); */ // hutton removed dead code

            LED_B_OFF();
            LED_C_OFF();
            cardSTATE = MFEMUL_SELECT;

            /*if ((flags & FLAG_CVE21_0430) == FLAG_CVE21_0430) {
                p_em[1] = 0x21;
                cve_flipper = 0;
            } */
            continue;
        }

        if (was_three && receivedCmd[0] != 3) {
            Dbprintf("We have found our segv here 003");
        }

        switch (cardSTATE) {
            case MFEMUL_NOFIELD: {
                if (999 >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_NOFIELD");

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 102");
                }
                break;
            }
            case MFEMUL_HALTED: {
                if (999 >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_HALTED");

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 102");
                }
                break;
            }
            case MFEMUL_IDLE: {
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                if (999 >= DBG_EXTENDED)
                    Dbprintf("MFEMUL_IDLE");

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 102");
                }
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

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 004");
                }

                // Dbprintf("MFEMUL_SELECT 001"); // hutton disable comment
                int uid_index = -1;
                // Extract cascade level
                if (receivedCmd_len >= 2) {
                    switch (receivedCmd[0]) {
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT:
                            // Dbprintf("MFEMUL_SELECT 002"); // hutton disable comment
                            uid_index = UIDBCC1;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_2:
                            // Dbprintf("MFEMUL_SELECT 003"); // hutton disable comment
                            uid_index = UIDBCC2;
                            break;
                        case ISO14443A_CMD_ANTICOLL_OR_SELECT_3:
                            Dbprintf("MFEMUL_SELECT 004");
                            uid_index = UIDBCC3;
                            break;
                    }
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 005");
                }

                if (uid_index < 0) {
                    LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                    cardSTATE_TO_IDLE();
                    // Dbprintf("incorrect cascade level received 001"); // hutton disable comment
                    //if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Incorrect cascade level received"); // nathan print
                    break;
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 006");
                }

                // Incoming SELECT ALL for any cascade level
                if (receivedCmd_len == 2 && receivedCmd[1] == 0x20) {
                    // Dbprintf("incoming select all 001"); // hutton disable comment
                    EmSendPrecompiledCmd(&responses[uid_index]);
                    FpgaDisableTracing();

                    //if (999 >= DBG_EXTENDED) Dbprintf("SELECT ALL - EmSendPrecompiledCmd(%02x)", &responses[uid_index]); // nathan print
                    break;
                }

                // Incoming SELECT CLx for any cascade level
                if (receivedCmd_len == 9 && receivedCmd[1] == 0x70) {
                    // Dbprintf("incoming select clx 001"); // hutton disable comment
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, 4) == 0) {
                        bool cl_finished = (uid_len == 4  && uid_index == UIDBCC1) ||
                                           (uid_len == 7  && uid_index == UIDBCC2) ||
                                           (uid_len == 10 && uid_index == UIDBCC3);
                        //Dbprintf("send sak command 001"); // hutton disable comment
                        EmSendPrecompiledCmd(&responses[cl_finished ? SAK : SAKuid]);
                        FpgaDisableTracing();

                        //if (999 >= DBG_EXTENDED) Dbprintf("SELECT CLx %02x%02x%02x%02x received", receivedCmd[2], receivedCmd[3], receivedCmd[4], receivedCmd[5]); // nathan print
                        if (cl_finished) {
                            LED_B_ON();
                            cardSTATE = MFEMUL_WORK;
                            // Dbprintf("MFEMUL_WORK state 001"); // hutton disable comment
                            //if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_WORK"); // nathan print
                        }
                    } else {
                        // IDLE, not our UID
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }
                    break;
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 007");
                }

                // Incoming anti-collision frame
                // receivedCmd[1] indicates number of byte and bit collision, supports only for bit collision is zero
                if (receivedCmd_len >= 3 && receivedCmd_len <= 6 && (receivedCmd[1] & 0x0f) == 0) {
                    // we can process only full-byte frame anti-collision procedure
                    if (memcmp(&receivedCmd[2], responses[uid_index].response, receivedCmd_len - 2) == 0) {
                        // response missing part of UID via relative array index
                        EmSendPrecompiledCmd(&responses[uid_index + receivedCmd_len - 2]);
                        FpgaDisableTracing();

                        if (999 >= DBG_EXTENDED) Dbprintf("SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                        Dbprintf("001 SELECT ANTICOLLISION - EmSendPrecompiledCmd(%02x)", &responses[uid_index]);
                    } else {
                        // IDLE, not our UID or split-byte frame anti-collision (not supports)
                        LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                        Dbprintf("001 [MFEMUL_SELECT] cardSTATE = MFEMUL_IDLE");
                    }

                    if (was_three && receivedCmd[0] != 3) {
                        Dbprintf("We have found our segv here 008");
                    }

                    break;
                }

                // Unknown selection procedure
                LogTrace(uart->output, uart->len, uart->startTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->endTime * 16 - DELAY_AIR2ARM_AS_TAG, uart->parity, true);
                cardSTATE_TO_IDLE();

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 009");
                }

                if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_SELECT] Unknown selection procedure");
                Dbprintf("001 [MFEMUL_SELECT] Unknown selection procedure");
                break;
            }

                // WORK
            case MFEMUL_WORK: {

                // Dbprintf("MFEMUL_WORK 001"); // hutton disable comment
                if (999 >= DBG_EXTENDED) {
                    // Dbprintf("[MFEMUL_WORK] Enter in case");
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 102");
                }

                if (receivedCmd_len == 0) {
                    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] NO CMD received");
                    Dbprintf("001 [MFEMUL_WORK] NO CMD received");
                    break;
                }
                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 101");
                }

                memcpy(receivedCmd_dec, receivedCmd, receivedCmd_len);

                if (was_three && receivedCmd[0] != 3) {
                    // print length copied
                    Dbprintf("The length of receivedCmd_dec is %d", receivedCmd_len);
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 00a");
                }

                // all commands must have a valid CRC
                if (!CheckCrc14A(receivedCmd_dec, receivedCmd_len)) {
                    //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    //FpgaDisableTracing();

                    if (999 >= DBG_EXTENDED) Dbprintf("[MFEMUL_WORK] All commands must have a valid CRC %02X (%d)", receivedCmd_dec, receivedCmd_len);
                    break;
                }

                // rule 13 of 7.5.3. in ISO 14443-4. chaining shall be continued
                // BUT... ACK --> NACK
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_ACK) {
                    Dbprintf("[MFEMUL_WORK] ACK --> NACK !!");
                    //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                    EmSend4bit(CARD_NACK_NA);
                    FpgaDisableTracing();
                    break;
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 00b");
                }

                // rule 12 of 7.5.3. in ISO 14443-4. R(NAK) --> R(ACK)
                if (receivedCmd_len == 1 && receivedCmd_dec[0] == CARD_NACK_NA) {
                    Dbprintf("[MFEMUL_WORK] NACK --> NACK !!");
                    //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_ACK) : CARD_ACK);
                    EmSend4bit(CARD_ACK);
                    FpgaDisableTracing();
                    break;
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 00c");
                }

                // case MFEMUL_WORK => CMD RATS
                if (receivedCmd_len == 4 && receivedCmd_dec[0] == ISO14443A_CMD_RATS && receivedCmd_dec[1] == 0x80) {
                    if (rats && rats_len) {
                        EmSendCmd(rats, rats_len);
                        FpgaDisableTracing();
                    } else {
                        Dbprintf("Rats and rats len is: %d, %d", rats[0], rats_len);
                        //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                        EmSend4bit(CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV RATS => NACK");
                    }
                    break;
                }

                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 00d");
                }

                // case MFEMUL_WORK => ISO14443A_CMD_NXP_DESELECT
                if (receivedCmd_len == 3 && receivedCmd_dec[0] == ISO14443A_CMD_NXP_DESELECT) {
                    if (rats && rats_len) {
                        EmSendCmd(receivedCmd_dec, receivedCmd_len);

                        FpgaDisableTracing();
                        if (999 >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV NXP DESELECT => ACK");
                    } else {
                        //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                        EmSend4bit(CARD_NACK_NA);
                        FpgaDisableTracing();
                        cardSTATE_TO_IDLE();
                        if (999 >= DBG_EXTENDED)
                            Dbprintf("[MFEMUL_WORK] RCV NXP DESELECT => NACK");
                    }
                    break;
                }
                if (was_three && receivedCmd[0] != 3) {
                    Dbprintf("We have found our segv here 00e");
                }

                // case MFEMUL_WORK => command not allowed nathan nathan
                Dbprintf("Received command not allowed nathanxx");
                if (999 >= DBG_EXTENDED) {
                    // The WTX we want to send out...
                    //static uint8_t extend_resp[] = {0xf2, 0x01, 0x91, 0x40};
                    //static uint8_t extend_resp[] = {0xf2, 0x02, 0x0a, 0x72};
                    //static uint8_t extend_resp[] = {0xf2, 0x03, 0x83, 0x63};
                    //static uint8_t extend_resp[] = {0xf2, 0x04, 0x3c, 0x17};
                    //static uint8_t extend_resp[] = {0xf2, 0x05, 0x50, 0x6b};
                    //static uint8_t extend_resp[] = {0xf2, 0x06, 0x2e, 0x34};
                    //static uint8_t extend_resp[] = {0xf2, 0x07, 0xa7, 0x25};
                    //static uint8_t extend_resp[] = {0xf2, 0x08, 0x50, 0xdd}; // This works
                    //static uint8_t extend_resp[] = {0xf2, 0x09, 0xd9, 0xcc};
                    //static uint8_t extend_resp[] = {0xf2, 0x0a, 0x42, 0xfe};
                    //static uint8_t extend_resp[] = {0xf2, 0x0b, 0xcb, 0xef};
                    //static uint8_t extend_resp[] = {0xf2, 0x0c, 0x74, 0x9b};
                    //static uint8_t extend_resp[] = {0xf2, 0x0d, 0xfd, 0x8a};
                    static uint8_t extend_resp[] = {0xf2, 0x0e, 0x66, 0xb8};

                    // nathan print me
                    Dbprintf("\nrecvd from reader:");
                    Dbhexdump(receivedCmd_len, receivedCmd, false);
                    Dbprintf("");

                    // lets handle some obvious stuff here!
                    if (receivedCmd[6] == 'O' && receivedCmd[7] == 'S' && receivedCmd[8] == 'E') {
                        Dbprintf("We saw OSE... ignore it!");
                        //Full: 02  6a  82  93  2f
                        EmSendCmd(filenotfound, 5);
                        continue;
                    }

                    // rather than asing for more time, lets just send the response with the PDOL there too
                    //  there are two of this for some reason?? Ach, this one is not at the card read level, that is why.
                    if (memcmp(&fci_query[0], receivedCmd, sizeof(fci_query)) == 0 && false) {
                        Dbprintf("***** returning fast FCI response...!");
                        //uint8_t modified_response[] = { 0x03, 0x77, 0x0e, 0x82, 0x02, 0x39, 0x80, 0x94, 0x08, 0x18, 0x01, 0x02, 0x01, 0x20, 0x01, 0x04, 0x00, 0x90, 0x00, 0x03, 0xec };
                        //uint8_t modified_response[] = { 0x03, 0x77, 0x0e, 0x82, 0x02, 0x39, 0x80, 0x94, 0x08, 0x18, 0x01, 0x02, 0x01, 0x20, 0x01, 0x04, 0x00, 0x90, 0x00, 0x03, 0xec };
                        EmSendCmd(&fci_template[0], sizeof(fci_template));

                        //for (int i = 0; i < sizeof(fci_template); i++) {
                        //    Dbprintf("%02x ", fci_template[i]);
                        //}

                        continue;
                    }

                    //if (memcmp(&pay1_query[0], receivedCmd, sizeof(pay1_query)) == 0 && false) {
                    //    Dbprintf("We see we made a pay1 query to the card... lets return a pay2 response!");
                    //    EmSendCmd(&pay2_response[0], sizeof(pay2_response));
                    //    continue;
                    //}

                    // We want to modify corrupted request
                    if ((receivedCmd_len > 5 && receivedCmd[0] != 0x03 && receivedCmd[0] != 0x02 && receivedCmd[1] == 0 && receivedCmd[4] == 0) || (receivedCmd[2] == 0xa8)) {
                        Dbprintf("We saw corrupted request... modifying it into a generate ac transaction !!!!");
                        receivedCmd[0] = 0x03;
                        receivedCmd[1] = 0x80;
                        receivedCmd[2] = 0xae;
                        receivedCmd[3] = 0x80;
                        receivedCmd[4] = 0x00;
                        receivedCmd[5] = 0x1d;

                        for (int i = 0; i < 29; i++) {
                            receivedCmd[6 + i] = receivedCmd[12 + i];
                        }

                        // clear final byte just in case
                        receivedCmd[35] = 0;

                        receivedCmd_len = 35 + 3; // Core command is 35, then there is control code and hte crc

                        Dbprintf("\nthe command has now become:");
                        Dbhexdump(receivedCmd_len, receivedCmd, false);
                    }

                    // Seems unlikely
                    if (receivedCmd_len >= 9 && receivedCmd[6] == '1' && receivedCmd[7] == 'P' && receivedCmd[8] == 'A') {
                        Dbprintf("We saw 1PA... !!!!");
                    }

                    if (was_three && receivedCmd[0] != 3) {
                        Dbprintf("We have found our segv here 00f");
                    }

                    // Request more time for 2PAY and respond with a modified 1PAY request
                    if (receivedCmd_len >= 9 && receivedCmd[6] == '2' && receivedCmd[7] == 'P' && receivedCmd[8] == 'A') {
                        Dbprintf("We saw 2PA... switching it to 1PAY !!!!");
                        receivedCmd[6] = '1';

                        if (was_three) {
                            Dbprintf("It used to be three...");
                        }

                        /*
                        //static uint8_t modified_to_say_2pay[]  = { 0x03, 0x6F, 0x1A, 0x84, 0x0E, 0x32, 0x50, 0x41, 0x59, 0x2E, 0x53, 0x59, 0x53, 0x2E, 0x44, 0x44, 0x46, 0x30, 0x31, 0xA5, 0x08, 0x88, 0x01, 0x01, 0x5F, 0x2D, 0x02, 0x65, 0x6E, 0x90, 0x00, 0x7B, 0x7D};
                        static uint8_t original_card_response[] =
                                { 0x03, 0x6f, 0x2e, 0x84, 0x0e, 0x32, 0x50, 0x41, 0x59, 0x2e, 0x53, 0x59, 0x53, 0x2e, 0x44, 0x44, 0x46, 0x30, 0x31, 0xa5, 0x1c, 0xbf, 0x0c, 0x19, 0x61, 0x17, 0x4f, 0x07, 0xa0, 0x00, 0x00, 0x00, 0x04, 0x10, 0x10, 0x87, 0x01, 0x01, 0x9f, 0x0a, 0x08, 0x00, 0x01, 0x05, 0x02, 0x00, 0x00, 0x00, 0x00, 0x90, 0x00, 0x33, 0x4e};
                        EmSendCmd(original_card_response, sizeof(original_card_response));
                        continue;
                         */

                        //EmSendCmd(extend_resp, 4);

                        //// copy the command and its length
                        //receivedCmd[6] = '1';
                        //memcpy(receivedCmd_copy, receivedCmd, receivedCmd_len);
                        //receivedCmd_len_copy = receivedCmd_len;
                    }

                    static uint8_t rnd_resp[] = {0xb2, 0x67, 0xc7};
                    if (memcmp(receivedCmd, rnd_resp, sizeof(rnd_resp)) == 0) {
                        Dbprintf("We saw bad response... !");
                        continue;
                    }

                    // We have received the response from a WTX command! Process the cached command at this point.
                    if (memcmp(receivedCmd, extend_resp, sizeof(extend_resp)) == 0) {
                        //Dbprintf("We saw wtx response... !");
                        //waiting_wtx_response = false;
                        // Now process pending command!

                        // Special case: if we are about to do a generate AC, we also need to
                        // make a request for pdol...
                        if (receivedCmd_copy[1] == 0x80 && receivedCmd_copy[2] == 0xae) {
                            Dbprintf("We are about to do a generate AC... we need to request PDOL first...");
                            uint8_t pdol_request[] = { 0x80, 0xa8, 0x00, 0x00, 0x02, 0x83, 0x00 };

                            CmdSmartRaw(0xff, &(pdol_request[0]), sizeof(pdol_request), (&responseToReader[0]), &responseToReader_len);
                        }

                        // This is minus 3 because we don't include the first byte (prepend), plus we don't want to send the
                        // last two bytes (CRC) to the card
                        CmdSmartRaw(receivedCmd_copy[0], &(receivedCmd_copy[1]), receivedCmd_len_copy-3, (&responseToReader[0]), &responseToReader_len);
                        EmSendCmd(responseToReader, responseToReader_len);

                        Dbprintf("Sent delayed command to card...");
                        //EmSendCmd(thirdResponse, sizeof(thirdResponse));
                        continue;
                    }

                    // Send a request for more time, and cache the command we want to process
                    EmSendCmd(extend_resp, 4);

                    // copy the command and its length (minus 1???)
                    Dbprintf("Caching command for later processing... its length is %d", receivedCmd_len);
                    memcpy(receivedCmd_copy, receivedCmd, receivedCmd_len);
                    receivedCmd_len_copy = receivedCmd_len;
                }

                //EmSend4bit(encrypted_data ? mf_crypto1_encrypt4bit(pcs, CARD_NACK_NA) : CARD_NACK_NA);
                //FpgaDisableTracing();

                //Dbprintf("die here.");
                //BigBuf_free_keep_EM();
                //return;
                continue;
            }
        }  // End Switch Loop

        button_pushed = BUTTON_PRESS();
    }  // End While Loop

    Dbprintf("Loop beginning!");

    FpgaDisableTracing();

    if (999 >= DBG_ERROR) {
        Dbprintf("Emulator stopped. Tracing: %d  trace length: %d ", get_tracing(), BigBuf_get_traceLen());
    }

    //if ((flags & FLAG_INTERACTIVE) == FLAG_INTERACTIVE) {  // Interactive mode flag, means we need to send ACK
    //    //Send the collected ar_nr in the response
    //    reply_mix(CMD_ACK, CMD_HF_MIFARE_SIMULATE, button_pushed, 0, &ar_nr_resp, sizeof(ar_nr_resp));
    //}

    FpgaWriteConfWord(FPGA_MAJOR_MODE_OFF);
    LEDsoff();
    set_tracing(false);
    BigBuf_free_keep_EM();
}
