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
// High frequency MIFARE commands
//-----------------------------------------------------------------------------

#include "cmdhfmf.h"
#include <ctype.h>

#include "bruteforce.h"
#include "cmdparser.h"             // command_t
#include "commonutil.h"            // ARRAYLEN
#include "comms.h"                 // clearCommandBuffer
#include "fileutils.h"
#include "cmdtrace.h"
#include "mifare/mifaredefault.h"  // mifare default key array
#include "cliparser.h"             // argtable
#include "hardnested_bf_core.h"    // SetSIMDInstr
#include "mifare/mad.h"
#include "nfc/ndef.h"
#include "protocols.h"
#include "util_posix.h"            // msclock
#include "cmdhfmfhard.h"
#include "crapto1/crapto1.h"       // prng_successor
#include "cmdhf14a.h"              // exchange APDU
#include "crypto/libpcrypto.h"
#include "wiegand_formats.h"
#include "wiegand_formatutils.h"
#include "cmdhw.h"                 // set_fpga_mode
#include "loclass/cipherutils.h"   // BitstreamOut_t
#include "proxendian.h"
#include "preferences.h"
#include "mifare/gen4.h"
#include "generator.h"              // keygens.
#include "fpga.h"
#include "mifare/mifarehost.h"
#include "crypto/originality.h"

static int CmdHelp(const char *Cmd);

/*
static int usage_hf14_keybrute(void) {
    PrintAndLogEx(NORMAL, "J_Run's 2nd phase of multiple sector nested authentication key recovery");
    PrintAndLogEx(NORMAL, "You have a known 4 last bytes of a key recovered with mf_nonce_brute tool.");
    PrintAndLogEx(NORMAL, "First 2 bytes of key will be bruteforced");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(NORMAL, " ---[ This attack is obsolete,  try hardnested instead ]---");
    PrintAndLogEx(NORMAL, "Options:");
    PrintAndLogEx(NORMAL, "      h               this help");
    PrintAndLogEx(NORMAL, "      <block number>  target block number");
    PrintAndLogEx(NORMAL, "      <A|B>           target key type");
    PrintAndLogEx(NORMAL, "      <key>           candidate key from mf_nonce_brute tool");
    PrintAndLogEx(NORMAL, "Examples:");
    PrintAndLogEx(NORMAL, _YELLOW_("           hf mf keybrute --blk 1 -k 000011223344"));
    return 0;
}
*/

int mfc_ev1_print_signature(uint8_t *uid, uint8_t uidlen, uint8_t *signature, int signature_len) {
    int index = originality_check_verify(uid, uidlen, signature, signature_len, PK_MFC);
    PrintAndLogEx(NORMAL, "");
    return originality_check_print(signature, signature_len, index);
}

static int mf_read_uid(uint8_t *uid, int *uidlen, int *nxptype) {
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        DropField();
        return PM3_ERFTRANS;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    if (nxptype) {
        uint64_t select_status = resp.oldarg[0];
        *nxptype = detect_nxp_card(card.sak, ((card.atqa[1] << 8) + card.atqa[0]), select_status);
    }

    memcpy(uid, card.uid, card.uidlen * sizeof(uint8_t));
    *uidlen = card.uidlen;
    return PM3_SUCCESS;
}

static char *GenerateFilename(const char *prefix, const char *suffix) {
    if (! IfPm3Iso14443a()) {
        return NULL;
    }
    uint8_t uid[10] = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
    int uidlen = 0;
    char *fptr = calloc(sizeof(char) * (strlen(prefix) + strlen(suffix)) + sizeof(uid) * 2 + 1,  sizeof(uint8_t));

    int res = mf_read_uid(uid, &uidlen, NULL);
    if (res != PM3_SUCCESS || !uidlen) {
        PrintAndLogEx(WARNING, "No tag found.");
        free(fptr);
        return NULL;
    }

    strcpy(fptr, prefix);
    FillFileNameByUID(fptr, uid, suffix, uidlen);
    return fptr;
}

// allocates `items` table entries, storing pointer to `*src`
// Each entry stores two keys (A and B), initialized to six-byte value 0xFFFFFFFFFFFF
// Each entry also stores whether the key was "found", defaults to false (0)
static int initSectorTable(sector_t **src, size_t items) {


    // typedef struct {
    //     uint64_t Key[2];
    //     uint8_t foundKey[2];
    // } sector_t;

    // This allocates based on the size of a single item
    (*src) = calloc(items, sizeof(sector_t));
    if (*src == NULL) {
        return PM3_EMALLOC;
    }

    // empty e_sector
    for (size_t i = 0; i < items; i++) {
        for (uint8_t j = 0; j < 2; j++) {
            (*src)[i].Key[j] = 0xffffffffffff;
            // (*src)[i].foundKey[j] = 0; // calloc zero's these already
        }
    }
    return PM3_SUCCESS;
}

static void decode_print_st(uint16_t blockno, uint8_t *data) {
    if (mfIsSectorTrailer(blockno)) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "-------------------------- " _CYAN_("Sector trailer decoder") " --------------------------");
        PrintAndLogEx(INFO, "key A........ " _GREEN_("%s"), sprint_hex_inrow(data, 6));
        PrintAndLogEx(INFO, "acr.......... " _GREEN_("%s"), sprint_hex_inrow(data + 6, 3));
        PrintAndLogEx(INFO, "user / gpb... " _GREEN_("%02x"), data[9]);
        PrintAndLogEx(INFO, "key B........ " _GREEN_("%s"), sprint_hex_inrow(data + 10, 6));
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, "  # | access rights");
        PrintAndLogEx(INFO, "----+-----------------------------------------------------------------------");

        if (mfValidateAccessConditions(&data[6]) == false) {
            PrintAndLogEx(WARNING, _RED_("Invalid Access Conditions"));
        }


        int bln = mfFirstBlockOfSector(mfSectorNum(blockno));
        int blinc = (mfNumBlocksPerSector(mfSectorNum(blockno)) > 4) ? 5 : 1;
        for (int i = 0; i < 4; i++) {
            PrintAndLogEx(INFO, "%3d%c| " _YELLOW_("%s"), bln, ((blinc > 1) && (i < 3) ? '+' : ' '), mfGetAccessConditionsDesc(i, &data[6]));
            bln += blinc;

            if (i == 3) {
                uint8_t cond = mf_get_accesscondition(i, &data[6]);
                if (cond == 0 || cond == 1 || cond == 2) {
                    PrintAndLogEx(INFO, "");
                    PrintAndLogEx(INFO, "OBS! Key B is readable, it SHALL NOT be able to authenticate on original MFC");
                }
            }
        }


        PrintAndLogEx(INFO, "----------------------------------------------------------------------------");
        PrintAndLogEx(NORMAL, "");
    }
}

static uint8_t NumOfSectors(char card) {
    switch (card) {
        case '0' :
            return MIFARE_MINI_MAXSECTOR;
        case '1' :
            return MIFARE_1K_MAXSECTOR;
        case '2' :
            return MIFARE_2K_MAXSECTOR;
        case '4' :
            return MIFARE_4K_MAXSECTOR;
        default  :
            return 0;
    }
}

static char GetFormatFromSector(uint8_t sectors) {
    switch (sectors) {
        case MIFARE_MINI_MAXSECTOR:
            return '0';
        case MIFARE_1K_MAXSECTOR:
            return '1';
        case MIFARE_2K_MAXSECTOR:
            return '2';
        case MIFARE_4K_MAXSECTOR:
            return '4';
        default  :
            return ' ';
    }
}

bool mfc_value(const uint8_t *d, int32_t *val) {
    // values
    int32_t a = (int32_t)MemLeToUint4byte(d);
    uint32_t a_inv = MemLeToUint4byte(d + 4);
    uint32_t b = MemLeToUint4byte(d + 8);

    int val_checks = (
                         (a == b) && (a == ~a_inv) &&
                         (d[12] == (~d[13] & 0xFF)) &&
                         (d[14] == (~d[15] & 0xFF))
                     );

    if (val) {
        *val = a;
    }
    return val_checks;
}

void mf_print_block_one(uint8_t blockno, uint8_t *d, bool verbose) {

    if (blockno == 0) {
        char ascii[24] = {0};
        ascii_to_buffer((uint8_t *)ascii, d, MFBLOCK_SIZE, sizeof(ascii) - 1, 1);
        PrintAndLogEx(INFO, "%3d | " _RED_("%s") "| " _RED_("%s"),
                      blockno,
                      sprint_hex(d, MFBLOCK_SIZE),
                      ascii
                     );
    } else if (mfIsSectorTrailer(blockno)) {

        char keya[26] = {0};
        hex_to_buffer((uint8_t *)keya, d, MIFARE_KEY_SIZE, sizeof(keya) - 1, 0, 1, true);

        char acl[20] = {0};
        hex_to_buffer((uint8_t *)acl, d + MIFARE_KEY_SIZE, 3, sizeof(acl) - 1, 0, 1, true);

        char keyb[26] = {0};
        hex_to_buffer((uint8_t *)keyb, d + 10, MIFARE_KEY_SIZE, sizeof(keyb) - 1, 0, 1, true);

        char ascii[24] = {0};
        ascii_to_buffer((uint8_t *)ascii, d, MFBLOCK_SIZE, sizeof(ascii) - 1, 1);

        PrintAndLogEx(INFO, "%3d | " _YELLOW_("%s") _MAGENTA_("%s") "%02X " _YELLOW_("%s") "| " _YELLOW_("%s"),
                      blockno,
                      keya,
                      acl,
                      d[9],
                      keyb,
                      ascii
                     );

    } else {
        int32_t value = 0;
        if (verbose && mfc_value(d, &value)) {
            PrintAndLogEx(INFO, "%3d | " _CYAN_("%s") " %"PRIi32, blockno, sprint_hex_ascii(d, MFBLOCK_SIZE), value);
        } else {
            PrintAndLogEx(INFO, "%3d | %s ", blockno, sprint_hex_ascii(d, MFBLOCK_SIZE));
        }
    }
}

static void mf_print_block(uint8_t blockno, uint8_t *d, bool verbose) {
    uint8_t sectorno = mfSectorNum(blockno);

    char secstr[6] = "     ";
    if (mfFirstBlockOfSector(sectorno) == blockno) {
        sprintf(secstr, " %3d ", sectorno);
    }

    if (blockno == 0) {
        char ascii[24] = {0};
        ascii_to_buffer((uint8_t *)ascii, d, MFBLOCK_SIZE, sizeof(ascii) - 1, 1);
        PrintAndLogEx(INFO, "%s| %3d | " _RED_("%s") "| " _RED_("%s"),
                      secstr,
                      blockno,
                      sprint_hex(d, MFBLOCK_SIZE),
                      ascii
                     );

    } else if (mfIsSectorTrailer(blockno)) {

        char keya[26] = {0};
        hex_to_buffer((uint8_t *)keya, d, MIFARE_KEY_SIZE, sizeof(keya) - 1, 0, 1, true);

        char acl[20] = {0};
        hex_to_buffer((uint8_t *)acl, d + MIFARE_KEY_SIZE, 3, sizeof(acl) - 1, 0, 1, true);

        char keyb[26] = {0};
        hex_to_buffer((uint8_t *)keyb, d + 10, MIFARE_KEY_SIZE, sizeof(keyb) - 1, 0, 1, true);

        char ascii[24] = {0};
        ascii_to_buffer((uint8_t *)ascii, d, MFBLOCK_SIZE, sizeof(ascii) - 1, 1);

        if (blockno >= MIFARE_1K_MAXBLOCK) {
            PrintAndLogEx(INFO, 
                _BACK_BLUE_("%s| %3d | " _YELLOW_("%s")) 
                _BACK_BLUE_(_MAGENTA_("%s")) 
                _BACK_BLUE_("%02X ") 
                _BACK_BLUE_(_YELLOW_("%s"))
                _BACK_BLUE_("| " _YELLOW_("%s"))
                ,
                    secstr,
                    blockno,
                    keya,
                    acl,
                    d[9],
                    keyb,
                    ascii
                );
        } else {
            PrintAndLogEx(INFO, "%s| %3d | " _YELLOW_("%s") _MAGENTA_("%s") "%02X " _YELLOW_("%s") "| " _YELLOW_("%s"),
                    secstr,
                    blockno,
                    keya,
                    acl,
                    d[9],
                    keyb,
                    ascii
                );
        }
    } else {

        int32_t value = 0;
        if (verbose && mfc_value(d, &value)) {
            PrintAndLogEx(INFO, "%s| %3d | " _CYAN_("%s") " %"PRIi32, secstr, blockno, sprint_hex_ascii(d, MFBLOCK_SIZE), value);
        }

        if (blockno >= MIFARE_1K_MAXBLOCK) {
            // MFC Ev1 signature blocks.
            PrintAndLogEx(INFO, _BACK_BLUE_("%s| %3d | %s"), secstr, blockno, sprint_hex_ascii(d, MFBLOCK_SIZE));
        } else  {
            PrintAndLogEx(INFO, "%s| %3d | %s", secstr, blockno, sprint_hex_ascii(d, MFBLOCK_SIZE));
        }
    }
}

static void mf_print_blocks(uint16_t n, uint8_t *d, bool verbose) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "-----+-----+-------------------------------------------------+-----------------");
    PrintAndLogEx(INFO, " sec | blk | data                                            | ascii");
    PrintAndLogEx(INFO, "-----+-----+-------------------------------------------------+-----------------");
    for (uint16_t i = 0; i < n; i++) {
        mf_print_block(i, d + (i * MFBLOCK_SIZE), verbose);
    }
    PrintAndLogEx(INFO, "-----+-----+-------------------------------------------------+-----------------");
    if (verbose) {
        PrintAndLogEx(HINT, _CYAN_("cyan") " = value block with decoded value");
        PrintAndLogEx(HINT, _CYAN_("background blue") " = MFC Ev1 signature blocks");
    }

    // MAD detection
    if (HasMADKey(d)) {
        PrintAndLogEx(HINT, "MAD key detected. Try " _YELLOW_("`hf mf mad`") " for more details");
    }
    PrintAndLogEx(NORMAL, "");
}

// assumes n is in number of blocks 0..255
static int mf_print_keys(uint16_t n, uint8_t *d) {
    uint8_t sectors = 0;
    switch (n) {
        case MIFARE_MINI_MAXBLOCK:
            sectors = MIFARE_MINI_MAXSECTOR;
            break;
        case MIFARE_2K_MAXBLOCK:
            sectors = MIFARE_2K_MAXSECTOR;
            break;
        case MIFARE_4K_MAXBLOCK:
            sectors = MIFARE_4K_MAXSECTOR;
            break;
        case MIFARE_1K_MAXBLOCK:
            sectors = MIFARE_1K_MAXSECTOR;
            break;
        default:
            sectors = MIFARE_1K_MAXSECTOR;
            n = MIFARE_1K_MAXBLOCK;
            break;
    }

    sector_t *e_sector = calloc(sectors, sizeof(sector_t));
    if (e_sector == NULL) {
        return PM3_EMALLOC;
    }

    for (uint16_t i = 0; i < n; i++) {
        if (mfIsSectorTrailer(i) == false) {
            continue;
        }
        // zero based index...
        uint8_t lookup = mfSectorNum(i);
        uint8_t sec = MIN(sectors - 1, lookup);
        e_sector[sec].foundKey[0] = 1;
        e_sector[sec].Key[0] = bytes_to_num(d + (i * MFBLOCK_SIZE), MIFARE_KEY_SIZE);
        e_sector[sec].foundKey[1] = 1;
        e_sector[sec].Key[1] = bytes_to_num(d + (i * MFBLOCK_SIZE) + 10, MIFARE_KEY_SIZE);
    }
    printKeyTable(sectors, e_sector);
    free(e_sector);
    return PM3_SUCCESS;
}

// MFC dump ,  extract and save the keys to key file
// assumes n is in number of blocks 0..255
static int mf_save_keys_from_arr(uint16_t n, uint8_t *d) {
    uint8_t sectors = 0;
    switch (n) {
        case MIFARE_MINI_MAXBLOCK:
            sectors = MIFARE_MINI_MAXSECTOR;
            break;
        case MIFARE_2K_MAXBLOCK:
            sectors = MIFARE_2K_MAXSECTOR;
            break;
        case MIFARE_4K_MAXBLOCK:
            sectors = MIFARE_4K_MAXSECTOR;
            break;
        case MIFARE_1K_MAXBLOCK:
        default:
            sectors = MIFARE_1K_MAXSECTOR;
            break;
    }

    uint16_t keysize = 2 * MIFARE_KEY_SIZE * sectors;

    uint8_t *keys = calloc(keysize, sizeof(uint8_t));
    if (keys == NULL) {
        return PM3_EMALLOC;
    }

    uint8_t sector = 0;
    for (uint16_t i = 0; i < n; i++) {
        if (mfIsSectorTrailer(i)) {
            // key A offset in ST block
            memcpy(keys + (MIFARE_KEY_SIZE * sector), d + (i * MFBLOCK_SIZE), MIFARE_KEY_SIZE);

            // key B offset in ST block
            memcpy(keys + (MIFARE_KEY_SIZE * sectors) + (MIFARE_KEY_SIZE * sector), d + (i * MFBLOCK_SIZE) + 10, MIFARE_KEY_SIZE);

            sector++;
        }
    }

    char fn[FILE_PATH_SIZE] = {0};
    snprintf(fn, sizeof(fn), "hf-mf-%s-key", sprint_hex_inrow(d, 4));
    saveFileEx(fn, ".bin", keys, keysize, spDump);
    free(keys);
    return PM3_SUCCESS;
}

/*
static void mf_print_values(uint16_t n, uint8_t *d) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Looking for value blocks...");
    PrintAndLogEx(NORMAL, "");
    uint8_t cnt = 0;
    int32_t value = 0;
    for (uint16_t i = 0; i < n; i++) {

        if (mfc_value(d + (i * MFBLOCK_SIZE), &value))  {
            PrintAndLogEx(INFO, "%03d | " _YELLOW_("%" PRIi32) " " _YELLOW_("0x%" PRIX32), i, value, value);
            ++cnt;
        }
    }

    if (cnt) {
        PrintAndLogEx(INFO, "Found %u value blocks in file", cnt);
        PrintAndLogEx(NORMAL, "");
    }
}
*/

void mf_print_sector_hdr(uint8_t sector) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | sector " _GREEN_("%02d") " / " _GREEN_("0x%02X") "                                | ascii", sector, sector);
    PrintAndLogEx(INFO, "----+-------------------------------------------------+-----------------");
}


// assumes n is in number of blocks 0..255
static void mf_analyse_acl(uint16_t n, uint8_t *d) {

    for (uint16_t b = 3; b < n; b++) {
        if (mfIsSectorTrailer(b) == false) {
            continue;
        }

        uint8_t block[MFBLOCK_SIZE] = {0x00};
        memcpy(block, d + (b * MFBLOCK_SIZE), MFBLOCK_SIZE);

        // ensure access right isn't messed up.
        if (mfValidateAccessConditions(&block[6]) == false) {
            PrintAndLogEx(WARNING, "Invalid Access Conditions on sector " _YELLOW_("%u"), mfSectorNum(b));
        }

        // Warn if ACL is strict read-only
        uint8_t bar = mfNumBlocksPerSector(mfSectorNum(b));
        for (uint8_t foo = 0; foo < bar; foo++) {
            if (mfReadOnlyAccessConditions(foo, &block[6])) {
                PrintAndLogEx(WARNING, _YELLOW_("s%u / b%u") " - Strict ReadOnly Access Conditions detected", mfSectorNum(b), b - bar + 1 + foo);
            }
        }
    }
}

/*
 Sector trailer sanity checks.
 Warn if ACL is strict read-only,  or invalid ACL.
*/
static int mf_analyse_st_block(uint8_t blockno, uint8_t *block, bool force) {

    if (mfIsSectorTrailer(blockno) == false) {
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, "Sector trailer (ST) write detected");

    // ensure access right isn't messed up.
    if (mfValidateAccessConditions(&block[6]) == false) {
        PrintAndLogEx(WARNING, "Invalid Access Conditions detected, replacing with default values");
        memcpy(block + 6, "\xFF\x07\x80\x69", 4);
    }

    bool ro_detected = false;
    uint8_t bar = mfNumBlocksPerSector(mfSectorNum(blockno));
    for (uint8_t foo = 0; foo < bar; foo++) {
        if (mfReadOnlyAccessConditions(foo, &block[6])) {
            PrintAndLogEx(WARNING, "Strict ReadOnly Access Conditions on block " _YELLOW_("%u") " detected", blockno - bar + 1 + foo);
            ro_detected = true;
        }
    }
    if (ro_detected) {
        if (force) {
            PrintAndLogEx(WARNING, " --force override, continuing...");
        } else {
            PrintAndLogEx(INFO, "Exiting, please run `" _YELLOW_("hf mf acl -d %s") "` to understand", sprint_hex_inrow(&block[6], 3));
            PrintAndLogEx(INFO, "Use `" _YELLOW_("--force") "` to override and write this data");
            return PM3_EINVARG;
        }
    } else {
        PrintAndLogEx(SUCCESS, "ST checks ( " _GREEN_("ok") " )");
    }

    return PM3_SUCCESS;
}

/* Reads data from tag
 * @param card: (output) card info
 * @param carddata: (output) card data
 * @param numSectors: size of the card
 * @param keyFileName: filename containing keys or NULL.
*/
static int mfc_read_tag(iso14a_card_select_t *card, uint8_t *carddata, uint8_t numSectors, char *keyfn) {

    // Select card to get UID/UIDLEN/ATQA/SAK information
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }

    uint64_t select_status = resp.oldarg[0];
    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return PM3_ESOFT;
    }

    // store card info
    memcpy(card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    char *fptr = NULL;
    if (keyfn == NULL || keyfn[0] == '\0') {
        fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr == NULL)
            return PM3_ESOFT;

        keyfn = fptr ;
    }

    PrintAndLogEx(INFO, "Using... %s", keyfn);

    size_t alen = 0, blen = 0;
    uint8_t *keyA, *keyB;
    if (loadFileBinaryKey(keyfn, "", (void **)&keyA, (void **)&keyB, &alen, &blen) != PM3_SUCCESS) {
        free(fptr);
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Reading sector access bits...");
    PrintAndLogEx(INFO, "." NOLF);

    uint8_t rights[40][4] = {0};

    mf_readblock_t payload;
    uint8_t current_key;
    for (uint8_t sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        current_key = MF_KEY_A;
        for (uint8_t tries = 0; tries < MIFARE_SECTOR_RETRY; tries++) {
            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);

            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                free(fptr);
                free(keyA);
                free(keyB);
                return PM3_EOPABORTED;
            }

            payload.blockno = mfFirstBlockOfSector(sectorNo) + mfNumBlocksPerSector(sectorNo) - 1;
            payload.keytype = current_key;

            memcpy(payload.key, (current_key == MF_KEY_A) ? keyA + (sectorNo * MIFARE_KEY_SIZE) : keyB + (sectorNo * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);

            clearCommandBuffer();
            SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));

            if (WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500)) {

                uint8_t *data = resp.data.asBytes;
                if (resp.status == PM3_SUCCESS) {
                    rights[sectorNo][0] = ((data[7] & 0x10) >> 2) | ((data[8] & 0x1) << 1) | ((data[8] & 0x10) >> 4); // C1C2C3 for data area 0
                    rights[sectorNo][1] = ((data[7] & 0x20) >> 3) | ((data[8] & 0x2) << 0) | ((data[8] & 0x20) >> 5); // C1C2C3 for data area 1
                    rights[sectorNo][2] = ((data[7] & 0x40) >> 4) | ((data[8] & 0x4) >> 1) | ((data[8] & 0x40) >> 6); // C1C2C3 for data area 2
                    rights[sectorNo][3] = ((data[7] & 0x80) >> 5) | ((data[8] & 0x8) >> 2) | ((data[8] & 0x80) >> 7); // C1C2C3 for sector trailer
                    break;
                } else if (tries == (MIFARE_SECTOR_RETRY / 2)) { // after half unsuccessful tries, give key B a go
                    PrintAndLogEx(WARNING, "\nTrying with " _YELLOW_("key B") " instead...");
                    current_key = MF_KEY_B;
                    PrintAndLogEx(INFO, "." NOLF);
                } else if (tries == (MIFARE_SECTOR_RETRY - 1)) { // on last try set defaults
                    PrintAndLogEx(FAILED, "\nFailed to read access rights for sector %2d  ( fallback to default )", sectorNo);
                    rights[sectorNo][0] = rights[sectorNo][1] = rights[sectorNo][2] = 0x00;
                    rights[sectorNo][3] = 0x01;
                }
            } else {
                PrintAndLogEx(FAILED, "\nTimeout reading access rights for sector... %2d  ( fallback to default )", sectorNo);
                rights[sectorNo][0] = rights[sectorNo][1] = rights[sectorNo][2] = 0x00;
                rights[sectorNo][3] = 0x01;
            }
        }
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "Finished reading sector access bits");
    PrintAndLogEx(INFO, "Dumping all blocks from card...");

    for (uint8_t sectorNo = 0; sectorNo < numSectors; sectorNo++) {
        for (uint8_t blockNo = 0; blockNo < mfNumBlocksPerSector(sectorNo); blockNo++) {
            bool received = false;
            current_key = MF_KEY_A;
            uint8_t data_area = (sectorNo < 32) ? blockNo : blockNo / 5;
            if (rights[sectorNo][data_area] == 0x07) {                                     // no key would work
                PrintAndLogEx(WARNING, "Access rights prevent reading sector... " _YELLOW_("%2d") " block... " _YELLOW_("%3d") " ( skip )", sectorNo, blockNo);
                continue;
            }

            for (uint8_t tries = 0; tries < MIFARE_SECTOR_RETRY; tries++) {

                if (mfIsSectorTrailerBasedOnBlocks(sectorNo, blockNo)) {

                    // sector trailer. At least the Access Conditions can always be read with key A.
                    payload.blockno = mfFirstBlockOfSector(sectorNo) + blockNo;
                    payload.keytype = current_key;
                    memcpy(payload.key, (current_key == MF_KEY_A) ? keyA + (sectorNo * MIFARE_KEY_SIZE) : keyB + (sectorNo * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);

                    clearCommandBuffer();
                    SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));
                    received = WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500);
                } else {
                    // data block. Check if it can be read with key A or key B
                    if ((rights[sectorNo][data_area] == 0x03) || (rights[sectorNo][data_area] == 0x05)) {
                        // only key B would work
                        payload.blockno = mfFirstBlockOfSector(sectorNo) + blockNo;
                        payload.keytype = MF_KEY_B;
                        memcpy(payload.key, keyB + (sectorNo * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);

                        clearCommandBuffer();
                        SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));
                        received = WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500);
                    } else {
                        // key A would work
                        payload.blockno = mfFirstBlockOfSector(sectorNo) + blockNo;
                        payload.keytype = current_key;
                        memcpy(payload.key, (current_key == MF_KEY_A) ? keyA + (sectorNo * MIFARE_KEY_SIZE) : keyB + (sectorNo * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);

                        clearCommandBuffer();
                        SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));
                        received = WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500);
                    }
                }

                if (received) {
                    if (resp.status == PM3_SUCCESS) {
                        // break the re-try loop
                        break;
                    }
                    if ((current_key == MF_KEY_A) && (tries == (MIFARE_SECTOR_RETRY / 2))) {
                        // Half the tries failed with key A. Swap for key B
                        current_key = MF_KEY_B;

                        // clear out keyA since it failed.
                        memset(keyA + (sectorNo * MIFARE_KEY_SIZE), 0x00, MIFARE_KEY_SIZE);
                    }
                }
            }

            if (received) {

                if (resp.status == PM3_SUCCESS) {

                    uint8_t *data  = resp.data.asBytes;

                    if (mfIsSectorTrailerBasedOnBlocks(sectorNo, blockNo)) {
                        // sector trailer. Fill in the keys.
                        memcpy(data, keyA + (sectorNo * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
                        memcpy(data + 10, keyB + (sectorNo * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
                    }

                    memcpy(carddata + (MFBLOCK_SIZE * (mfFirstBlockOfSector(sectorNo) + blockNo)), data, MFBLOCK_SIZE);
                    PrintAndLogEx(INPLACE, "Sector... " _YELLOW_("%2d") " block..." _YELLOW_("%2d") " ( " _GREEN_("ok") " )", sectorNo, blockNo);
                } else {
                    PrintAndLogEx(FAILED, "\nSector... %2d Block... %2d ( " _RED_("fail") " )", sectorNo, blockNo);
                }
            } else {
                PrintAndLogEx(WARNING, "Timeout reading sector... %2d  block... %2d", sectorNo, blockNo);
            }
        }
    }

    free(fptr);
    free(keyA);
    free(keyB);
    PrintAndLogEx(SUCCESS, "\nSucceeded in dumping all blocks");
    return PM3_SUCCESS ;
}

static int mf_load_keys(uint8_t **pkeyBlock, uint32_t *pkeycnt, uint8_t *userkey, int userkeylen, const char *filename, int fnlen, bool load_default) {
    // Handle Keys
    *pkeycnt = 0;
    *pkeyBlock = NULL;
    uint8_t *p;
    // Handle user supplied key
    // (it considers *pkeycnt and *pkeyBlock as possibly non-null so logic can be easily reordered)
    if (userkeylen >= MIFARE_KEY_SIZE) {
        int numKeys = userkeylen / MIFARE_KEY_SIZE;
        p = realloc(*pkeyBlock, numKeys * MIFARE_KEY_SIZE);
        if (!p) {
            PrintAndLogEx(FAILED, "cannot allocate memory for Keys");
            free(*pkeyBlock);
            return PM3_EMALLOC;
        }
        *pkeyBlock = p;

        memcpy(*pkeyBlock, userkey, numKeys * MIFARE_KEY_SIZE);

        for (int i = 0; i < numKeys; i++) {
            PrintAndLogEx(DEBUG, _YELLOW_("%2d") " - %s", i, sprint_hex(*pkeyBlock + i * MIFARE_KEY_SIZE, MIFARE_KEY_SIZE));
        }
        *pkeycnt += numKeys;
        PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%2d") " user keys", numKeys);
    }

    if (load_default) {
        // Handle default keys
        p = realloc(*pkeyBlock, (*pkeycnt + ARRAYLEN(g_mifare_default_keys)) * MIFARE_KEY_SIZE);
        if (!p) {
            PrintAndLogEx(FAILED, "cannot allocate memory for Keys");
            free(*pkeyBlock);
            return PM3_EMALLOC;
        }
        *pkeyBlock = p;
        // Copy default keys to list
        for (int i = 0; i < ARRAYLEN(g_mifare_default_keys); i++) {
            num_to_bytes(g_mifare_default_keys[i], MIFARE_KEY_SIZE, (uint8_t *)(*pkeyBlock + (*pkeycnt + i) * MIFARE_KEY_SIZE));
            PrintAndLogEx(DEBUG, _YELLOW_("%2d") " - %s", *pkeycnt + i, sprint_hex(*pkeyBlock + (*pkeycnt + i) * MIFARE_KEY_SIZE, MIFARE_KEY_SIZE));
        }
        *pkeycnt += ARRAYLEN(g_mifare_default_keys);
        PrintAndLogEx(SUCCESS, "loaded " _GREEN_("%zu") " hardcoded keys", ARRAYLEN(g_mifare_default_keys));
    }

    // Handle user supplied dictionary file
    if (fnlen > 0) {
        uint32_t loaded_numKeys = 0;
        uint8_t *keyBlock_tmp = NULL;
        int res = loadFileDICTIONARY_safe(filename, (void **) &keyBlock_tmp, MIFARE_KEY_SIZE, &loaded_numKeys);
        if (res != PM3_SUCCESS || loaded_numKeys == 0 || keyBlock_tmp == NULL) {
            PrintAndLogEx(FAILED, "An error occurred while loading the dictionary!");
            free(keyBlock_tmp);
            free(*pkeyBlock);
            return PM3_EFILE;
        } else {
            p = realloc(*pkeyBlock, (*pkeycnt + loaded_numKeys) * MIFARE_KEY_SIZE);
            if (!p) {
                PrintAndLogEx(FAILED, "cannot allocate memory for Keys");
                free(keyBlock_tmp);
                free(*pkeyBlock);
                return PM3_EMALLOC;
            }
            *pkeyBlock = p;
            memcpy(*pkeyBlock + *pkeycnt * MIFARE_KEY_SIZE, keyBlock_tmp, loaded_numKeys * MIFARE_KEY_SIZE);
            *pkeycnt += loaded_numKeys;
            free(keyBlock_tmp);
        }
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfAcl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf acl",
                  "Print decoded MIFARE access rights (ACL), \n"
                  "  A = key A\n"
                  "  B = key B\n"
                  "  AB = both key A and B\n"
                  "  ACCESS = access bytes inside sector trailer block\n"
                  "  Increment, decrement, transfer, restore is for value blocks",
                  "hf mf acl\n"
                  "hf mf acl -d FF0780\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "ACL bytes specified as 3 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int acllen = 0;
    uint8_t acl[3] = {0};
    CLIGetHexWithReturn(ctx, 1, acl, &acllen);

    CLIParserFree(ctx);

    PrintAndLogEx(NORMAL, "");

    // look up common default ACL bytes and print a fingerprint line about it.
    if (memcmp(acl, "\xFF\x07\x80", 3) == 0) {
        PrintAndLogEx(INFO, "ACL... " _GREEN_("%s") " (transport configuration)", sprint_hex(acl, sizeof(acl)));
    }
    if (mfValidateAccessConditions(acl) == false) {
        PrintAndLogEx(ERR, _RED_("Invalid Access Conditions, NEVER write these on a card!"));
    }
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "  # | Access rights");
    PrintAndLogEx(INFO, "----+-----------------------------------------------------------------");
    for (int i = 0; i < 4; i++) {
        PrintAndLogEx(INFO, "%3d | " _YELLOW_("%s"), i, mfGetAccessConditionsDesc(i, acl));
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHF14AMfDarkside(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf darkside",
                  "Darkside attack",
                  "hf mf darkside\n"
                  "hf mf darkside --blk 16\n"
                  "hf mf darkside --blk 16 -b\n");

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "blk", "<dec> ", "Target block"),
        arg_lit0("b", NULL, "Target key B instead of default key A"),
        arg_int0("c", NULL, "<dec>", "Target key type is key A + offset"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t blockno = arg_get_u32_def(ctx, 1, 0) & 0xFF;
    uint8_t key_type = MF_KEY_A;

    if (arg_get_lit(ctx, 2)) {
        PrintAndLogEx(INFO, "Targeting key B");
        key_type = MF_KEY_B;
    }

    uint8_t prev_keytype = key_type;
    key_type = arg_get_int_def(ctx, 3, key_type);
    if (arg_get_lit(ctx, 2) && (key_type != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single target key type");
        return PM3_EINVARG;
    }
    // mf_dark_side expects the full command byte 0x6x
    key_type += MIFARE_AUTH_KEYA;

    CLIParserFree(ctx);

    uint64_t key = 0;
    uint64_t t1 = msclock();
    int ret = mf_dark_side(blockno, key_type, &key);
    t1 = msclock() - t1;

    if (ret != PM3_SUCCESS) return ret;

    PrintAndLogEx(SUCCESS, "found valid key: " _GREEN_("%012" PRIx64), key);
    PrintAndLogEx(SUCCESS, "time in darkside " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}

static int CmdHF14AMfWrBl(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf wrbl",
                  "Write MIFARE Classic block with 16 hex bytes of data\n"
                  " \n"
                  "Sector 0 / Block 0 - Manufacturer block\n"
                  "When writing to block 0 you must use a VALID block 0 data (UID, BCC, SAK, ATQA)\n"
                  "Writing an invalid block 0 means rendering your Magic GEN2 card undetectable. \n"
                  "Look in the magic_cards_notes.md file for help to resolve it.\n"
                  " \n"
                  "`--force` param is used to override warnings like bad ACL and BLOCK 0 writes.\n"
                  "          if not specified, it will exit if detected",
                  "hf mf wrbl --blk 1 -d 000102030405060708090a0b0c0d0e0f\n"
                  "hf mf wrbl --blk 1 -k A0A1A2A3A4A5 -d 000102030405060708090a0b0c0d0e0f\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_lit0("a", NULL, "input key type is key A (def)"),
        arg_lit0("b", NULL, "input key type is key B"),
        arg_int0("c", NULL, "<dec>", "input key type is key A + offset"),
        arg_lit0(NULL, "force", "override warnings"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_str0("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int b = arg_get_int_def(ctx, 1, 1);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 2) && arg_get_lit(ctx, 3)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 3)) {
        keytype = MF_KEY_B;
    }
    uint8_t prev_keytype = keytype;
    keytype = arg_get_int_def(ctx, 4, keytype);
    if ((arg_get_lit(ctx, 2) || arg_get_lit(ctx, 3)) && (keytype != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    }
    bool force = arg_get_lit(ctx, 5);

    int keylen = 0;
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CLIGetHexWithReturn(ctx, 6, key, &keylen);

    uint8_t block[MFBLOCK_SIZE] = {0x00};
    int blen = 0;
    CLIGetHexWithReturn(ctx, 7, block, &blen);
    CLIParserFree(ctx);

    if (keylen && keylen != 6) {
        PrintAndLogEx(WARNING, "Key must be 12 hex digits. Got %d", keylen);
        return PM3_EINVARG;
    }

    if (blen != MFBLOCK_SIZE) {
        PrintAndLogEx(WARNING, "block data must include 16 HEX bytes. Got %i", blen);
        return PM3_EINVARG;
    }

    if (b > 255) {
        return PM3_EINVARG;
    }

    // BLOCK 0 detection
    if (b == 0 && force == false) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "Targeting Sector 0 / Block 0 - Manufacturer block");
        PrintAndLogEx(INFO, "Read the helptext for details before writing to this block");
        PrintAndLogEx(INFO, "You must use param `" _YELLOW_("--force") "` to write to this block");
        PrintAndLogEx(NORMAL, "");
        return PM3_EINVARG;
    }

    uint8_t blockno = (uint8_t)b;

    if (mf_analyse_st_block(blockno, block, force) != PM3_SUCCESS) {
        return PM3_EINVARG;
    }

    if (keytype < 2) {
        PrintAndLogEx(INFO, "Writing block no %d, key type:%c - %s", blockno, (keytype == MF_KEY_B) ? 'B' : 'A', sprint_hex_inrow(key, sizeof(key)));
    } else {
        PrintAndLogEx(INFO, "Writing block no %d, key type:%02x - %s", blockno, MIFARE_AUTH_KEYA + keytype, sprint_hex_inrow(key, sizeof(key)));
    }

    PrintAndLogEx(INFO, "data: %s", sprint_hex(block, sizeof(block)));

    uint8_t data[26];
    memcpy(data, key, sizeof(key));
    memcpy(data + 10, block, sizeof(block));
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_WRITEBL, blockno, keytype, 0, data, sizeof(data));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(FAILED, "command execution time out");
        return PM3_ETIMEOUT;
    }

    int status  = resp.oldarg[0];
    if (status > 0) {
        PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
        PrintAndLogEx(HINT, "try `" _YELLOW_("hf mf rdbl") "` to verify");
    } else if (status == PM3_ETEAROFF) {
        return status;
    } else {
        PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
        // suggest the opposite keytype than what was used.
        PrintAndLogEx(HINT, "Maybe access rights? Try specify keytype `" _YELLOW_("hf mf wrbl -%c ...") "` instead", (keytype == MF_KEY_A) ? 'b' : 'a');
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfRdBl(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf rdbl",
                  "Read MIFARE Classic block",
                  "hf mf rdbl --blk 0\n"
                  "hf mf rdbl --blk 0 -k A0A1A2A3A4A5\n"
                  "hf mf rdbl --blk 3 -v   -> get block 3, decode sector trailer\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_lit0("a", NULL, "input key type is key A (def)"),
        arg_lit0("b", NULL, "input key type is key B"),
        arg_int0("c", NULL, "<dec>", "input key type is key A + offset"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int b = arg_get_int_def(ctx, 1, 0);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 2) && arg_get_lit(ctx, 3)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 3)) {
        keytype = MF_KEY_B;
    }
    keytype = arg_get_int_def(ctx, 4, keytype);
    uint8_t prev_keytype = keytype;
    keytype = arg_get_int_def(ctx, 4, keytype);
    if ((arg_get_lit(ctx, 2) || arg_get_lit(ctx, 3)) && (keytype != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    }

    int keylen = 0;
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CLIGetHexWithReturn(ctx, 5, key, &keylen);
    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (keylen && keylen != 6) {
        PrintAndLogEx(WARNING, "Key must be 12 hex digits. Got %d", keylen);
        return PM3_EINVARG;
    }

    if (b > 255) {
        return PM3_EINVARG;
    }
    uint8_t blockno = (uint8_t)b;

    uint8_t data[16] = {0};
    int res =  mf_read_block(blockno, keytype, key, data);
    if (res == PM3_SUCCESS) {

        uint8_t sector = mfSectorNum(blockno);
        mf_print_sector_hdr(sector);
        mf_print_block_one(blockno, data, verbose);
        if (verbose) {
            decode_print_st(blockno, data);
        }
    }
    PrintAndLogEx(NORMAL, "");
    return res;
}

static int CmdHF14AMfRdSc(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf rdsc",
                  "Read MIFARE Classic sector",
                  "hf mf rdsc -s 0\n"
                  "hf mf rdsc -s 0 -k A0A1A2A3A4A5\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", NULL, "input key specified is A key (def)"),
        arg_lit0("b", NULL, "input key specified is B key"),
        arg_int0("c", NULL, "<dec>", "input key type is key A + offset"),
        arg_str0("k", "key", "<hex>", "key specified as 6 hex bytes"),
        arg_int1("s", "sec", "<dec>", "sector number"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 1) && arg_get_lit(ctx, 2)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 2)) {
        keytype = MF_KEY_B;
    }
    uint8_t prev_keytype = keytype;
    keytype = arg_get_int_def(ctx, 3, keytype);
    if ((arg_get_lit(ctx, 1) || arg_get_lit(ctx, 2)) && (keytype != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    }

    int keylen = 0;
    uint8_t key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CLIGetHexWithReturn(ctx, 4, key, &keylen);

    int s = arg_get_int_def(ctx, 5, 0);
    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    if (keylen && keylen != 6) {
        PrintAndLogEx(WARNING, "Key must be 12 hex digits. Got %d", keylen);
        return PM3_EINVARG;
    }

    if (s >= MIFARE_4K_MAXSECTOR) {
        PrintAndLogEx(WARNING, "Sector number must be less than 40");
        return PM3_EINVARG;
    }

    uint8_t sector = (uint8_t)s;
    uint16_t sc_size = mfNumBlocksPerSector(sector) * MFBLOCK_SIZE;

    uint8_t *data = calloc(sc_size, sizeof(uint8_t));
    if (data == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        return PM3_EMALLOC;
    }

    int res =  mf_read_sector(sector, keytype, key, data);
    if (res == PM3_SUCCESS) {

        uint8_t blocks = mfNumBlocksPerSector(sector);
        uint8_t start = mfFirstBlockOfSector(sector);

        mf_print_sector_hdr(sector);
        for (int i = 0; i < blocks; i++) {
            mf_print_block_one(start + i, data + (i * MFBLOCK_SIZE), verbose);
        }

        if (verbose) {
            decode_print_st(start + blocks - 1, data + ((blocks - 1) * MFBLOCK_SIZE));
        }
    }
    free(data);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int FastDumpWithEcFill(uint8_t numsectors) {

    uint8_t dbg_curr = DBG_NONE;
    if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    /*
    if (setDeviceDebugLevel(DBG_NONE, false) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }
    */

    mfc_eload_t payload;
    payload.sectorcnt = numsectors;
    payload.keytype = MF_KEY_A;

    // ecfill key A
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EML_LOAD, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    bool res = WaitForResponseTimeout(CMD_HF_MIFARE_EML_LOAD, &resp, 2500);
    if (res == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "fast dump reported back failure w KEY A,  swapping to KEY B");

        // ecfill key B
        payload.keytype = MF_KEY_B;

        clearCommandBuffer();
        SendCommandNG(CMD_HF_MIFARE_EML_LOAD, (uint8_t *)&payload, sizeof(payload));
        res = WaitForResponseTimeout(CMD_HF_MIFARE_EML_LOAD, &resp, 2500);
        if (res == false) {
            PrintAndLogEx(WARNING, "command execution time out");
            setDeviceDebugLevel(dbg_curr, false);
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "fast dump reported back failure w KEY B");
            PrintAndLogEx(FAILED, "Dump file is " _RED_("PARTIAL") " complete");
        }
    }

    if (setDeviceDebugLevel(dbg_curr, false) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    return PM3_SUCCESS;
}

static int CmdHF14AMfDump(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf dump",
                  "Dump MIFARE Classic tag to file (bin/json)\n"
                  "If no <name> given, UID will be used as filename",
                  "hf mf dump --mini                        --> MIFARE Mini\n"
                  "hf mf dump --1k                          --> MIFARE Classic 1k\n"
                  "hf mf dump --2k                          --> MIFARE 2k\n"
                  "hf mf dump --4k                          --> MIFARE 4k\n"
                  "hf mf dump --keys hf-mf-066C8B78-key.bin --> MIFARE 1k with keys from specified file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_str0("k", "keys", "<fn>", "filename of keys"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "ns", "no save to file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int datafnlen = 0;
    char dataFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)dataFilename, FILE_PATH_SIZE, &datafnlen);

    int keyfnlen = 0;
    char keyFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)keyFilename, FILE_PATH_SIZE, &keyfnlen);

    bool m0 = arg_get_lit(ctx, 3);
    bool m1 = arg_get_lit(ctx, 4);
    bool m2 = arg_get_lit(ctx, 5);
    bool m4 = arg_get_lit(ctx, 6);
    bool nosave = arg_get_lit(ctx, 7);
    bool verbose = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    uint64_t t1 = msclock();

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t numSectors = MIFARE_1K_MAXSECTOR;
    uint16_t bytes = MIFARE_1K_MAX_BYTES;
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;

    if (m0) {
        numSectors = MIFARE_MINI_MAXSECTOR;
        bytes = MIFARE_MINI_MAX_BYTES;
        block_cnt = MIFARE_MINI_MAXBLOCK;
    } else if (m1) {
        numSectors = MIFARE_1K_MAXSECTOR;
        bytes = MIFARE_1K_MAX_BYTES;
        block_cnt = MIFARE_1K_MAXBLOCK;
    } else if (m2) {
        numSectors = MIFARE_2K_MAXSECTOR;
        bytes = MIFARE_2K_MAX_BYTES;
        block_cnt = MIFARE_2K_MAXBLOCK;
    } else if (m4) {
        numSectors = MIFARE_4K_MAXSECTOR;
        bytes = MIFARE_4K_MAX_BYTES;
        block_cnt = MIFARE_4K_MAXBLOCK;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    // read card
    iso14a_card_select_t card ;
    uint8_t *mem = calloc(MIFARE_4K_MAX_BYTES, sizeof(uint8_t));
    if (mem == NULL) {
        PrintAndLogEx(ERR, "failed to allocate memory");
        return PM3_EMALLOC;
    }
    int res = mfc_read_tag(&card, mem, numSectors, keyFilename);
    if (res != PM3_SUCCESS) {
        free(mem);
        return res;
    }

    PrintAndLogEx(SUCCESS, "time: %" PRIu64 " seconds\n", (msclock() - t1) / 1000);

    mf_print_blocks(block_cnt, mem, verbose);

    if (verbose) {
        mf_print_keys(block_cnt, mem);
        mf_analyse_acl(block_cnt, mem);
    }

    // Skip saving card data to file
    if (nosave) {
        PrintAndLogEx(INFO, "Called with no save option");
        free(mem);
        return PM3_SUCCESS;
    }

    // Save to file
    if (strlen(dataFilename) < 1) {
        char *fptr = GenerateFilename("hf-mf-", "-dump");
        if (fptr == NULL) {
            free(mem);
            return PM3_ESOFT;
        }

        strcpy(dataFilename, fptr);
        free(fptr);
    }

    pm3_save_mf_dump(dataFilename, mem, bytes, jsfCardMemory);
    free(mem);
    return PM3_SUCCESS;
}

static int CmdHF14AMfRestore(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf restore",
                  "Restore MIFARE Classic dump file to tag.\n"
                  "\n"
                  "The key file and dump file will program the card sector trailers.\n"
                  "By default we authenticate to card with key 0xFFFFFFFFFFFF.\n"
                  "If access rights in dump file is all zeros,  it will be replaced with default values\n"
                  "\n"
                  "`--uid` param is used for filename templates `hf-mf-<uid>-dump.bin` and `hf-mf-<uid>-key.bin.\n"
                  "          if not specified, it will read the card uid instead.\n"
                  " `--ka` param you can indicate that the key file should be used for authentication instead.\n"
                  "          if so we also try both B/A keys\n"
                  "`--force` param is used to override warnings and allow bad ACL block writes.\n"
                  "          if not specified, it will skip blocks with bad ACL.\n",
                  "hf mf restore\n"
                  "hf mf restore --1k --uid 04010203\n"
                  "hf mf restore --1k --uid 04010203 -k hf-mf-AABBCCDD-key.bin\n"
                  "hf mf restore --4k"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_str0("u", "uid",  "<hex>", "uid, (4|7|10 hex bytes)"),
        arg_str0("f", "file", "<fn>", "specify a filename for dump file"),
        arg_str0("k", "kfn",  "<fn>", "key filename"),
        arg_lit0(NULL, "ka",  "use specified keyfile to authenticate"),
        arg_lit0(NULL, "force", "override warnings"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m4 = arg_get_lit(ctx, 4);

    int uidlen = 0;
    char uid[20] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)uid, sizeof(uid), &uidlen);

    int datafnlen = 0;
    char datafilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)datafilename, FILE_PATH_SIZE, &datafnlen);

    int keyfnlen = 0;
    char keyfilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 7), (uint8_t *)keyfilename, FILE_PATH_SIZE, &keyfnlen);

    bool use_keyfile_for_auth = arg_get_lit(ctx, 8);
    bool force = arg_get_lit(ctx, 9);

    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t sectors = MIFARE_1K_MAXSECTOR;

    if (m0) {
        sectors = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        sectors = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        sectors = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        sectors = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    // if user specified UID,  use it in file templates
    if (uidlen) {

        if (keyfnlen == 0) {
            snprintf(keyfilename, FILE_PATH_SIZE, "hf-mf-%s-key.bin", uid);
            keyfnlen = strlen(keyfilename);
        }

        if (datafnlen == 0) {
            snprintf(datafilename, FILE_PATH_SIZE, "hf-mf-%s-dump.bin", uid);
            datafnlen = strlen(datafilename);
        }
    }

    // try reading card uid and create filename
    if (keyfnlen == 0) {
        char *fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr == NULL)
            return PM3_ESOFT;

        strncpy(keyfilename, fptr, sizeof(keyfilename) - 1);
        free(fptr);
    }

    //
    size_t alen = 0, blen = 0;
    uint8_t *keyA, *keyB;
    if (loadFileBinaryKey(keyfilename, "", (void **)&keyA, (void **)&keyB, &alen, &blen) != PM3_SUCCESS) {
        return PM3_ESOFT;
    }

    PrintAndLogEx(INFO, "Using key file `" _YELLOW_("%s") "`", keyfilename);

    // try reading card uid and create filename
    if (datafnlen == 0) {
        char *fptr = GenerateFilename("hf-mf-", "-dump.bin");
        if (fptr == NULL) {
            if (keyA) {
                free(keyA);
            }
            if (keyB) {
                free(keyB);
            }
            return PM3_ESOFT;
        }
        strcpy(datafilename, fptr);
        free(fptr);
    }

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(datafilename, (void **)&dump, &bytes_read, (MFBLOCK_SIZE * MIFARE_4K_MAXBLOCK));
    if (res != PM3_SUCCESS) {
        free(keyA);
        free(keyB);
        return res;
    }

    // default authentication key
    uint8_t default_key[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, " blk | data                                            | status");
    PrintAndLogEx(INFO, "-----+-------------------------------------------------+----------------");

    // main loop for restoring.
    // a bit more complicated than needed
    // this is because of two things.
    // 1. we are setting keys from a key file or using the existing ones in the dump
    // 2. we need to authenticate against a card which might not have default keys.
    uint8_t *ref_dump = dump;
    for (uint8_t s = 0; s < sectors; s++) {
        for (uint8_t b = 0; b < mfNumBlocksPerSector(s); b++) {

            uint8_t bldata[MFBLOCK_SIZE] = {0x00};
            memcpy(bldata, dump, MFBLOCK_SIZE);

            bool skip = false;
            // if sector trailer
            if (mfIsSectorTrailerBasedOnBlocks(s, b)) {
                // keep the current keys on the card
                if (use_keyfile_for_auth == false) {
                    // replace KEY A
                    memcpy(bldata, keyA + (s * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);

                    // replace KEY B
                    memcpy(bldata + 10, keyB + (s * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
                }

                // ensure access right isn't messed up.
                if (mfValidateAccessConditions(&bldata[6]) == false) {
                    PrintAndLogEx(WARNING, "Invalid Access Conditions on sector %i, replacing with default values", s);
                    memcpy(bldata + 6, "\xFF\x07\x80\x69", 4);
                }

                // Warn if ACL is strict read-only
                for (uint8_t foo = 0; foo < mfNumBlocksPerSector(s); foo++) {
                    if (mfReadOnlyAccessConditions(foo, &bldata[6])) {
                        PrintAndLogEx(WARNING, "Strict ReadOnly Access Conditions on block " _YELLOW_("%u") " detected", foo);

                        // if --force isn't used, skip writing this block
                        if (force == false) {
                            PrintAndLogEx(INFO, "Skipping,  use `" _YELLOW_("--force") "` to override and write this data");
                            skip = true;
                        }
                    }
                }
            }

            if (bytes_read) {
                dump += MFBLOCK_SIZE;
                bytes_read -= MFBLOCK_SIZE;
            }
            if (skip) {
                continue;
            }

            uint8_t wdata[26];
            memcpy(wdata + 10, bldata, sizeof(bldata));

            for (int8_t kt = MF_KEY_B; kt > -1; kt--) {
                if (use_keyfile_for_auth) {

                    if (kt == MF_KEY_A) {
                        memcpy(wdata, keyA + (s * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
                    } else {
                        memcpy(wdata, keyB + (s * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
                    }

                } else {
                    // use default key to authenticate for the write command
                    memcpy(wdata, default_key, MIFARE_KEY_SIZE);
                }

                uint16_t blockno = (mfFirstBlockOfSector(s) + b);

                clearCommandBuffer();
                SendCommandMIX(CMD_HF_MIFARE_WRITEBL, blockno, kt, 0, wdata, sizeof(wdata));
                PacketResponseNG resp;
                if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
                    PrintAndLogEx(WARNING, "command execution time out");
                    continue;
                }

                int isOK  = resp.oldarg[0] & 0xff;
                if (isOK == 1) {
                    // if success,  skip to next block
                    PrintAndLogEx(INFO, " %3d | %s| ( " _GREEN_("ok") " )", blockno, sprint_hex(bldata, sizeof(bldata)));
                    break;
                }
                // write somehow failed.  Lets determine why.
                if (isOK == PM3_ETEAROFF) {
                    PrintAndLogEx(INFO, "Tear off triggered. Recommendation is not to use tear-off with restore command");
                    goto out;
                }

                PrintAndLogEx(INFO, " %3d | %s| ( " _RED_("fail") " ) key " _YELLOW_("%c"),
                              blockno,
                              sprint_hex(bldata, sizeof(bldata)),
                              (kt == MF_KEY_A) ? 'A' : 'B'
                             );
            } // end loop key types
        } // end loop B
    } // end loop S

out:
    free(ref_dump);
    free(keyA);
    free(keyB);
    PrintAndLogEx(INFO, "-----+-------------------------------------------------+----------------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(HINT, "try `" _YELLOW_("hf mf dump --ns") "` to verify");
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHF14AMfNested(const char *Cmd) { //TODO: single mode broken? can't find keys...
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf nested",
                  "Execute Nested attack against MIFARE Classic card for key recovery",
                  "hf mf nested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta           --> Use block 0 Key A to find block 4 Key A (single sector key recovery)\n"
                  "hf mf nested --mini --blk 0 -a -k FFFFFFFFFFFF                  --> Key recovery against MIFARE Mini\n"
                  "hf mf nested --1k --blk 0 -a -k FFFFFFFFFFFF                    --> Key recovery against MIFARE Classic 1k\n"
                  "hf mf nested --2k --blk 0 -a -k FFFFFFFFFFFF                    --> Key recovery against MIFARE 2k\n"
                  "hf mf nested --4k --blk 0 -a -k FFFFFFFFFFFF                    --> Key recovery against MIFARE 4k");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Key specified as 12 hex symbols"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_int0(NULL, "blk", "<dec>", "Input block number"),
        arg_lit0("a", NULL, "Input key specified is A key (default)"),
        arg_lit0("b", NULL, "Input key specified is B key"),
        arg_int0("c", NULL, "<dec>", "input key type is key A + offset"),
        arg_int0(NULL, "tblk", "<dec>", "Target block number"),
        arg_lit0(NULL, "ta", "Target A key (default)"),
        arg_lit0(NULL, "tb", "Target B key"),
        arg_int0(NULL, "tc", "<dec>", "Nested input key type is key A + offset (you must specify a single block as well!)"),
        arg_lit0(NULL, "emu", "Fill simulator keys from found keys"),
        arg_lit0(NULL, "dump", "Dump found keys to file"),
        arg_lit0(NULL, "mem", "Use dictionary from flashmemory"),
        arg_lit0("i", NULL, "Ignore static encrypted nonces"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);

    uint8_t blockNo = arg_get_u32_def(ctx, 6, 0);

    uint8_t keyType = MF_KEY_A;

    if (arg_get_lit(ctx, 7) && arg_get_lit(ctx, 8)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 8)) {
        keyType = MF_KEY_B;
    }
    uint8_t prev_keytype = keyType;
    keyType = arg_get_int_def(ctx, 9, keyType);
    if ((arg_get_lit(ctx, 7) || arg_get_lit(ctx, 8)) && (keyType != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    }

    int trgBlockNo = arg_get_int_def(ctx, 10, -1);

    uint8_t trgKeyType = MF_KEY_A;

    if (arg_get_lit(ctx, 11) && arg_get_lit(ctx, 12)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single target key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 12)) {
        trgKeyType = MF_KEY_B;
    }
    uint8_t prev_trgkeytype = trgKeyType;
    trgKeyType = arg_get_int_def(ctx, 13, trgKeyType);
    if ((arg_get_lit(ctx, 11) || arg_get_lit(ctx, 12)) && (trgKeyType != prev_trgkeytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single target key type");
        return PM3_EINVARG;
    }
    bool transferToEml = arg_get_lit(ctx, 14);
    bool createDumpFile = arg_get_lit(ctx, 15);
    bool singleSector = trgBlockNo > -1;
    bool use_flashmemory = arg_get_lit(ctx, 16);
    bool ignore_static_encrypted = arg_get_lit(ctx, 17);

    CLIParserFree(ctx);

    //validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    }

    uint8_t SectorsCnt = 1;
    if (m0) {
        SectorsCnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        SectorsCnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        SectorsCnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        SectorsCnt = MIFARE_4K_MAXSECTOR;
    }

    if (singleSector) {
        uint8_t MinSectorsCnt = 0;
        // find a MIFARE type that can accommodate the provided block number
        uint8_t s = MAX(mfSectorNum(trgBlockNo), mfSectorNum(blockNo));
        if (s < MIFARE_MINI_MAXSECTOR) {
            MinSectorsCnt = MIFARE_MINI_MAXSECTOR;
        } else if (s < MIFARE_1K_MAXSECTOR) {
            MinSectorsCnt = MIFARE_1K_MAXSECTOR;
        } else if (s < MIFARE_2K_MAXSECTOR) {
            MinSectorsCnt = MIFARE_2K_MAXSECTOR;
        } else if (s < MIFARE_4K_MAXSECTOR) {
            MinSectorsCnt = MIFARE_4K_MAXSECTOR;
        } else {
            PrintAndLogEx(WARNING, "Provided block out of possible MIFARE Type memory map");
            return PM3_EINVARG;
        }
        if (SectorsCnt == 1) {
            SectorsCnt = MinSectorsCnt;
        } else if (SectorsCnt < MinSectorsCnt) {
            PrintAndLogEx(WARNING, "Provided block out of provided MIFARE Type memory map");
            return PM3_EINVARG;
        }
    }
    if (SectorsCnt == 1) {
        SectorsCnt = MIFARE_1K_MAXSECTOR;
    }

    if (keylen != 6) {
        PrintAndLogEx(WARNING, "Input key must include 12 HEX symbols");
        return PM3_EINVARG;
    }

    sector_t *e_sector = NULL;
    uint8_t keyBlock[(ARRAYLEN(g_mifare_default_keys) + 1) * 6];
    uint64_t key64 = 0;

    // check if tag doesn't have static nonce
    if (detect_classic_static_nonce() == NONCE_STATIC) {
        PrintAndLogEx(WARNING, "Static nonce detected. Quitting...");
        PrintAndLogEx(INFO, "\t Try use " _YELLOW_("`hf mf staticnested`"));
        return PM3_EOPABORTED;
    }

    // check if we can authenticate to sector
    if (mf_check_keys(blockNo, keyType, true, 1, key, &key64) != PM3_SUCCESS) {
        if (keyType < 2) {
            PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%c", blockNo, keyType ? 'B' : 'A');
        } else {
            PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%02x", blockNo, MIFARE_AUTH_KEYA + keyType);
        }
        return PM3_EOPABORTED;
    }

    if (singleSector) {
        int16_t isOK = mf_nested(blockNo, keyType, key, trgBlockNo, trgKeyType, keyBlock, !ignore_static_encrypted);
        switch (isOK) {
            case PM3_ETIMEOUT:
                PrintAndLogEx(ERR, "command execution time out\n");
                break;
            case PM3_EOPABORTED:
                PrintAndLogEx(WARNING, "Button pressed. Aborted\n");
                break;
            case PM3_EFAILED:
                PrintAndLogEx(FAILED, "Tag isn't vulnerable to Nested Attack (PRNG is not predictable).\n");
                break;
            case PM3_ESOFT:
                PrintAndLogEx(FAILED, "No valid key found");
                break;
            case PM3_ESTATIC_NONCE:
                PrintAndLogEx(ERR, "Error: Static encrypted nonce detected. Aborted\n");
                break;
            case PM3_SUCCESS:
                key64 = bytes_to_num(keyBlock, 6);

                // transfer key to the emulator
                if (transferToEml) {
                    uint8_t sectortrailer;

                    if (trgBlockNo < 32 * 4) {  // 4 block sector
                        sectortrailer = trgBlockNo | 0x03;
                    } else {                    // 16 block sector
                        sectortrailer = trgBlockNo | 0x0f;
                    }
                    mf_eml_get_mem(keyBlock, sectortrailer, 1);

                    if (trgKeyType == MF_KEY_A)
                        num_to_bytes(key64, 6, keyBlock);
                    else
                        num_to_bytes(key64, 6, &keyBlock[10]);

                    mf_elm_set_mem(keyBlock, sectortrailer, 1);
                    PrintAndLogEx(SUCCESS, "Key transferred to emulator memory.");
                }
                return PM3_SUCCESS;
            default :
                PrintAndLogEx(ERR, "Unknown error\n");
        }
        return PM3_SUCCESS;

    } else { // ------------------------------------  multiple sectors working
        uint64_t t1 = msclock();

        e_sector = calloc(SectorsCnt, sizeof(sector_t));
        if (e_sector == NULL) return PM3_EMALLOC;

        // add our known key
        e_sector[mfSectorNum(blockNo)].foundKey[keyType] = 1;
        e_sector[mfSectorNum(blockNo)].Key[keyType] = key64;

        //test current key and additional standard keys first
        // add parameter key
        memcpy(keyBlock + (ARRAYLEN(g_mifare_default_keys) * 6), key, 6);

        for (int cnt = 0; cnt < ARRAYLEN(g_mifare_default_keys); cnt++) {
            num_to_bytes(g_mifare_default_keys[cnt], 6, (uint8_t *)(keyBlock + cnt * 6));
        }

        PrintAndLogEx(SUCCESS, "Testing known keys. Sector count "_YELLOW_("%d"), SectorsCnt);
        int res = mf_check_keys_fast(SectorsCnt, true, true, 1, ARRAYLEN(g_mifare_default_keys) + 1, keyBlock, e_sector, use_flashmemory, false);
        if (res == PM3_SUCCESS) {
            PrintAndLogEx(SUCCESS, "Fast check found all keys");
            goto jumptoend;
        }

        uint64_t t2 = msclock() - t1;
        PrintAndLogEx(SUCCESS, "Time to check " _YELLOW_("%zu") " known keys: %.0f seconds\n", ARRAYLEN(g_mifare_default_keys), (float)t2 / 1000.0);
        PrintAndLogEx(SUCCESS, "enter nested key recovery");

        // nested sectors
        bool calibrate = !ignore_static_encrypted;

        for (trgKeyType = MF_KEY_A; trgKeyType <= MF_KEY_B; ++trgKeyType) {
            for (uint8_t sectorNo = 0; sectorNo < SectorsCnt; ++sectorNo) {
                for (int i = 0; i < MIFARE_SECTOR_RETRY; i++) {

                    if (e_sector[sectorNo].foundKey[trgKeyType]) continue;

                    int16_t isOK = mf_nested(blockNo, keyType, key, mfFirstBlockOfSector(sectorNo), trgKeyType, keyBlock, calibrate);
                    switch (isOK) {
                        case PM3_ETIMEOUT:
                            PrintAndLogEx(ERR, "command execution time out\n");
                            break;
                        case PM3_EOPABORTED:
                            PrintAndLogEx(WARNING, "button pressed. Aborted\n");
                            break;
                        case PM3_EFAILED :
                            PrintAndLogEx(FAILED, "Tag isn't vulnerable to Nested Attack (PRNG is not predictable)\n");
                            break;
                        case PM3_ESOFT:
                            //key not found
                            calibrate = false;
                            continue;
                        case PM3_ESTATIC_NONCE:
                            PrintAndLogEx(ERR, "Error: Static encrypted nonce detected. Aborted\n");
                            break;
                        case PM3_SUCCESS:
                            calibrate = false;
                            e_sector[sectorNo].foundKey[trgKeyType] = 1;
                            e_sector[sectorNo].Key[trgKeyType] = bytes_to_num(keyBlock, 6);

                            mf_check_keys_fast(SectorsCnt, true, true, 2, 1, keyBlock, e_sector, false, false);
                            continue;
                        default :
                            PrintAndLogEx(ERR, "Unknown error\n");
                    }
                    free(e_sector);
                    return PM3_ESOFT;
                }
            }
        }

        t1 = msclock() - t1;
        PrintAndLogEx(SUCCESS, "time in nested " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);


        // 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
        PrintAndLogEx(INFO, "trying to read key B...");
        for (int i = 0; i < SectorsCnt; i++) {
            // KEY A but not KEY B
            if (e_sector[i].foundKey[0] && !e_sector[i].foundKey[1]) {

                uint8_t sectrail = (mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1);

                PrintAndLogEx(SUCCESS, "reading block %d", sectrail);

                mf_readblock_t payload;
                payload.blockno = sectrail;
                payload.keytype = MF_KEY_A;

                num_to_bytes(e_sector[i].Key[0], 6, payload.key); // KEY A

                clearCommandBuffer();
                SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));

                PacketResponseNG resp;
                if (!WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500)) continue;

                if (resp.status != PM3_SUCCESS) continue;

                uint8_t *data = resp.data.asBytes;
                key64 = bytes_to_num(data + 10, 6);
                if (key64) {
                    PrintAndLogEx(SUCCESS, "data: %s", sprint_hex(data + 10, 6));
                    e_sector[i].foundKey[1] = true;
                    e_sector[i].Key[1] = key64;
                }
            }
        }

jumptoend:

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));

        //print them
        printKeyTable(SectorsCnt, e_sector);

        // transfer them to the emulator
        if (transferToEml) {
            // fast push mode
            g_conn.block_after_ACK = true;
            for (int i = 0; i < SectorsCnt; i++) {
                mf_eml_get_mem(keyBlock, mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1, 1);

                if (e_sector[i].foundKey[0])
                    num_to_bytes(e_sector[i].Key[0], 6, keyBlock);

                if (e_sector[i].foundKey[1])
                    num_to_bytes(e_sector[i].Key[1], 6, &keyBlock[10]);

                if (i == SectorsCnt - 1) {
                    // Disable fast mode on last packet
                    g_conn.block_after_ACK = false;
                }
                mf_elm_set_mem(keyBlock, mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1, 1);
            }
            PrintAndLogEx(SUCCESS, "keys transferred to emulator memory.");
        }

        // Create dump file
        if (createDumpFile) {
            char *fptr = GenerateFilename("hf-mf-", "-key.bin");
            if (createMfcKeyDump(fptr, SectorsCnt, e_sector) != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Failed to save keys to file");
                free(e_sector);
                free(fptr);
                return PM3_EFILE;
            }
            free(fptr);
        }
        free(e_sector);
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfNestedStatic(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf staticnested",
                  "Execute static nested attack against MIFARE Classic card with static nonce for key recovery.\n"
                  "Supply a known key from one block to recover all keys",
                  "hf mf staticnested --mini --blk 0 -a -k FFFFFFFFFFFF\n"
                  "hf mf staticnested --1k --blk 0 -a -k FFFFFFFFFFFF\n"
                  "hf mf staticnested --2k --blk 0 -a -k FFFFFFFFFFFF\n"
                  "hf mf staticnested --4k --blk 0 -a -k FFFFFFFFFFFF\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "Known key (12 hex symbols)"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_int0(NULL, "blk", "<dec>", "Input block number"),
        arg_lit0("a", NULL, "Input key specified is keyA (def)"),
        arg_lit0("b", NULL, "Input key specified is keyB"),
        arg_lit0("e", "emukeys", "Fill simulator keys from found keys"),
        arg_lit0(NULL, "dumpkeys", "Dump found keys to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);

    uint8_t blockNo = arg_get_u32_def(ctx, 6, 0);

    uint8_t keyType = MF_KEY_A;

    if (arg_get_lit(ctx, 7) && arg_get_lit(ctx, 8)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 8)) {
        keyType = MF_KEY_B;
    }

    bool transferToEml = arg_get_lit(ctx, 9);
    bool createDumpFile = arg_get_lit(ctx, 10);
    CLIParserFree(ctx);

    //validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    }

    uint8_t SectorsCnt = 1;
    if (m0) {
        SectorsCnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        SectorsCnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        SectorsCnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        SectorsCnt = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    if (keylen != 6) {
        PrintAndLogEx(WARNING, "Input key must include 12 HEX symbols");
        return PM3_EINVARG;
    }

    sector_t *e_sector = NULL;

    uint8_t trgKeyType = MF_KEY_A;

    uint8_t keyBlock[(ARRAYLEN(g_mifare_default_keys) + 1) * 6];
    uint64_t key64 = 0;

    // check if tag have static nonce
    if (detect_classic_static_nonce() != NONCE_STATIC) {
        PrintAndLogEx(WARNING, "Normal nonce detected, or failed read of card. Quitting...");
        PrintAndLogEx(INFO, "\t Try use " _YELLOW_("`hf mf nested`"));
        return PM3_EOPABORTED;
    }

    // check if we can authenticate to sector
    if (mf_check_keys(blockNo, keyType, true, 1, key, &key64) != PM3_SUCCESS) {
        if (keyType < 2) {
            PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%c", blockNo, keyType ? 'B' : 'A');
        } else {
            PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%02x", blockNo, MIFARE_AUTH_KEYA + keyType);
        }
        return PM3_EOPABORTED;
    }

    if (IfPm3Flash()) {
        PrintAndLogEx(INFO, "RDV4 with flashmemory supported detected.");
    }

    uint64_t t1 = msclock();

    e_sector = calloc(SectorsCnt, sizeof(sector_t));
    if (e_sector == NULL)
        return PM3_EMALLOC;

    // add our known key
    e_sector[mfSectorNum(blockNo)].foundKey[keyType] = 1;
    e_sector[mfSectorNum(blockNo)].Key[keyType] = key64;

    //test current key and additional standard keys first
    // add parameter key
    memcpy(keyBlock + (ARRAYLEN(g_mifare_default_keys) * 6), key, 6);

    for (int cnt = 0; cnt < ARRAYLEN(g_mifare_default_keys); cnt++) {
        num_to_bytes(g_mifare_default_keys[cnt], 6, (uint8_t *)(keyBlock + cnt * 6));
    }

    PrintAndLogEx(SUCCESS, "Testing known keys. Sector count "_YELLOW_("%d"), SectorsCnt);
    int res = mf_check_keys_fast(SectorsCnt, true, true, 1, ARRAYLEN(g_mifare_default_keys) + 1, keyBlock, e_sector, false, false);
    if (res == PM3_SUCCESS) {
        // all keys found
        PrintAndLogEx(SUCCESS, "Fast check found all keys");
        goto jumptoend;
    }

    uint64_t t2 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "Time to check "_YELLOW_("%zu") " known keys: %.0f seconds\n", ARRAYLEN(g_mifare_default_keys), (float)t2 / 1000.0);
    PrintAndLogEx(SUCCESS, "enter static nested key recovery");

    // nested sectors
    for (trgKeyType = MF_KEY_A; trgKeyType <= MF_KEY_B; ++trgKeyType) {
        for (uint8_t sectorNo = 0; sectorNo < SectorsCnt; ++sectorNo) {

            for (int i = 0; i < 1; i++) {

                if (e_sector[sectorNo].foundKey[trgKeyType]) continue;

                int16_t isOK = mf_static_nested(blockNo, keyType, key, mfFirstBlockOfSector(sectorNo), trgKeyType, keyBlock);
                switch (isOK) {
                    case PM3_ETIMEOUT :
                        PrintAndLogEx(ERR, "command execution time out");
                        break;
                    case PM3_EOPABORTED :
                        PrintAndLogEx(WARNING, "aborted via keyboard.");
                        break;
                    case PM3_ESOFT :
                        continue;
                    case PM3_SUCCESS :
                        e_sector[sectorNo].foundKey[trgKeyType] = 1;
                        e_sector[sectorNo].Key[trgKeyType] = bytes_to_num(keyBlock, 6);

                        // mfCheckKeys_fast(SectorsCnt, true, true, 2, 1, keyBlock, e_sector, false, false);
                        continue;
                    default :
                        PrintAndLogEx(ERR, "unknown error.\n");
                }
                free(e_sector);
                return PM3_ESOFT;
            }
        }
    }

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "time in static nested " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);


    // 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
    PrintAndLogEx(INFO, "trying to read key B...");
    for (int i = 0; i < SectorsCnt; i++) {
        // KEY A but not KEY B
        if (e_sector[i].foundKey[0] && !e_sector[i].foundKey[1]) {

            uint8_t sectrail = (mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1);

            PrintAndLogEx(SUCCESS, "reading block %d", sectrail);

            mf_readblock_t payload;
            payload.blockno = sectrail;
            payload.keytype = MF_KEY_A;

            num_to_bytes(e_sector[i].Key[0], 6, payload.key); // KEY A

            clearCommandBuffer();
            SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500) == false) {
                continue;
            }

            if (resp.status != PM3_SUCCESS) continue;

            uint8_t *data = resp.data.asBytes;
            key64 = bytes_to_num(data + 10, 6);
            if (key64) {
                PrintAndLogEx(SUCCESS, "data: %s", sprint_hex(data + 10, 6));
                e_sector[i].foundKey[1] = true;
                e_sector[i].Key[1] = key64;
            }
        }
    }

jumptoend:

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));

    //print them
    printKeyTable(SectorsCnt, e_sector);

    // transfer them to the emulator
    if (transferToEml) {
        // fast push mode
        g_conn.block_after_ACK = true;
        for (int i = 0; i < SectorsCnt; i++) {
            mf_eml_get_mem(keyBlock, mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1, 1);

            if (e_sector[i].foundKey[0])
                num_to_bytes(e_sector[i].Key[0], 6, keyBlock);

            if (e_sector[i].foundKey[1])
                num_to_bytes(e_sector[i].Key[1], 6, &keyBlock[10]);

            if (i == SectorsCnt - 1) {
                // Disable fast mode on last packet
                g_conn.block_after_ACK = false;
            }
            mf_elm_set_mem(keyBlock, mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1, 1);
        }
        PrintAndLogEx(SUCCESS, "keys transferred to emulator memory.");
    }

    // Create dump file
    if (createDumpFile) {
        char *fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (createMfcKeyDump(fptr, SectorsCnt, e_sector) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to save keys to file");
            free(e_sector);
            free(fptr);
            return PM3_EFILE;
        }
        free(fptr);
    }
    free(e_sector);

    return PM3_SUCCESS;
}

static int CmdHF14AMfNestedHard(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf hardnested",
                  "Nested attack for hardened MIFARE Classic cards.\n"
                  "if card is EV1, command can detect and use known key see example below\n"
                  " \n"
                  "`--i<X>`  set type of SIMD instructions. Without this flag programs autodetect it.\n"
                  " or \n"
                  "    hf mf hardnested -r --tk [known target key]\n"
                  "Add the known target key to check if it is present in the remaining key space\n"
                  "    hf mf hardnested --blk 0 -a -k A0A1A2A3A4A5 --tblk 4 --ta --tk FFFFFFFFFFFF\n"
                  ,
                  "hf mf hardnested --tblk 4 --ta     --> works for MFC EV1\n"
                  "hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta\n"
                  "hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta -w\n"
                  "hf mf hardnested --blk 0 -a -k FFFFFFFFFFFF --tblk 4 --ta -f nonces.bin -w -s\n"
                  "hf mf hardnested -r\n"
                  "hf mf hardnested -r --tk a0a1a2a3a4a5\n"
                  "hf mf hardnested -t --tk a0a1a2a3a4a5\n"
                  "hf mf hardnested --blk 0 -a -k a0a1a2a3a4a5 --tblk 4 --ta --tk FFFFFFFFFFFF\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k",  "key",   "<hex>", "Key, 12 hex bytes"),      // 1
        arg_int0(NULL, "blk",   "<dec>", "Input block number"),     // 2
        arg_lit0("a",   NULL,            "Input key A (def)"),      // 3
        arg_lit0("b",   NULL,            "Input key B"),
        arg_int0(NULL, "tblk",  "<dec>", "Target block number"),
        arg_lit0(NULL, "ta",             "Target key A"),
        arg_lit0(NULL, "tb",             "Target key B"),
        arg_str0(NULL, "tk",    "<hex>", "Target key, 12 hex bytes"), // 8
        arg_str0("u",  "uid",   "<hex>", "R/W `hf-mf-<UID>-nonces.bin` instead of default name"),
        arg_str0("f",  "file",  "<fn>",  "R/W <name> instead of default name"),
        arg_lit0("r",  "read",           "Read `hf-mf-<UID>-nonces.bin` if tag present, otherwise `nonces.bin`, and start attack"),
        arg_lit0("s",  "slow",           "Slower acquisition (required by some non standard cards)"),
        arg_lit0("t",  "tests",          "Run tests"),
        arg_lit0("w",  "wr",             "Acquire nonces and UID, and write them to file `hf-mf-<UID>-nonces.bin`"),

        arg_lit0(NULL, "in", "None (use CPU regular instruction set)"),
#if defined(COMPILER_HAS_SIMD_X86)
        arg_lit0(NULL, "im", "MMX"),
        arg_lit0(NULL, "is", "SSE2"),
        arg_lit0(NULL, "ia", "AVX"),
        arg_lit0(NULL, "i2", "AVX2"),
#endif
#if defined(COMPILER_HAS_SIMD_AVX512)
        arg_lit0(NULL, "i5", "AVX512"),
#endif
#if defined(COMPILER_HAS_SIMD_NEON)
        arg_lit0(NULL, "ie", "NEON"),
#endif
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);

    uint8_t blockno = arg_get_u32_def(ctx, 2, 0);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 3) && arg_get_lit(ctx, 4)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 4)) {
        keytype = MF_KEY_B;
    }

    uint8_t trg_blockno = arg_get_u32_def(ctx, 5, 0);

    uint8_t trg_keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 6) && arg_get_lit(ctx, 7)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single target key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 7)) {
        trg_keytype = MF_KEY_B;
    }

    int trg_keylen = 0;
    uint8_t trg_key[6] = {0};
    CLIGetHexWithReturn(ctx, 8, trg_key, &trg_keylen);

    int uidlen = 0;
    char uid[14] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 9), (uint8_t *)uid, sizeof(uid), &uidlen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 10), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool nonce_file_read = arg_get_lit(ctx, 11);
    bool slow = arg_get_lit(ctx, 12);
    bool tests = arg_get_lit(ctx, 13);
    bool nonce_file_write = arg_get_lit(ctx, 14);

    bool in = arg_get_lit(ctx, 15);
#if defined(COMPILER_HAS_SIMD_X86)
    bool im = arg_get_lit(ctx, 16);
    bool is = arg_get_lit(ctx, 17);
    bool ia = arg_get_lit(ctx, 18);
    bool i2 = arg_get_lit(ctx, 19);
#endif
#if defined(COMPILER_HAS_SIMD_AVX512)
    bool i5 = arg_get_lit(ctx, 20);
#endif
#if defined(COMPILER_HAS_SIMD_NEON)
    bool ie = arg_get_lit(ctx, 16);
#endif
    CLIParserFree(ctx);

    // set SIM instructions
    SetSIMDInstr(SIMD_AUTO);

#if defined(COMPILER_HAS_SIMD_AVX512)
    if (i5)
        SetSIMDInstr(SIMD_AVX512);
#endif

#if defined(COMPILER_HAS_SIMD_X86)
    if (i2)
        SetSIMDInstr(SIMD_AVX2);
    if (ia)
        SetSIMDInstr(SIMD_AVX);
    if (is)
        SetSIMDInstr(SIMD_SSE2);
    if (im)
        SetSIMDInstr(SIMD_MMX);
#endif

#if defined(COMPILER_HAS_SIMD_NEON)
    if (ie)
        SetSIMDInstr(SIMD_NEON);
#endif

    if (in)
        SetSIMDInstr(SIMD_NONE);


    bool known_target_key = (trg_keylen);

    if (nonce_file_read) {
        char *fptr = GenerateFilename("hf-mf-", "-nonces.bin");
        if (fptr == NULL)
            strncpy(filename, "nonces.bin", FILE_PATH_SIZE - 1);
        else
            strncpy(filename, fptr, FILE_PATH_SIZE - 1);
        free(fptr);
    }

    if (nonce_file_write) {
        char *fptr = GenerateFilename("hf-mf-", "-nonces.bin");
        if (fptr == NULL) {
            return PM3_EFILE;
        }
        strncpy(filename, fptr, FILE_PATH_SIZE - 1);
        free(fptr);
    }

    if (uidlen) {
        snprintf(filename, FILE_PATH_SIZE, "hf-mf-%s-nonces.bin", uid);
    }

    if (g_session.pm3_present && !tests) {
        // detect MFC EV1 Signature
        if (detect_mfc_ev1_signature() && keylen == 0) {
            PrintAndLogEx(INFO, "MIFARE Classic EV1 card detected");
            blockno = 69;
            keytype = MF_KEY_B;
            memcpy(key, g_mifare_signature_key_b, sizeof(g_mifare_signature_key_b));
        }

        if (known_target_key == false && nonce_file_read == false) {
            // check if tag doesn't have static nonce
            if (detect_classic_static_nonce() == NONCE_STATIC) {
                PrintAndLogEx(WARNING, "Static nonce detected. Quitting...");
                PrintAndLogEx(HINT, "\tTry use `" _YELLOW_("hf mf staticnested") "`");
                return PM3_EOPABORTED;
            }

            uint64_t key64 = 0;
            // check if we can authenticate to sector
            if (mf_check_keys(blockno, keytype, true, 1, key, &key64) != PM3_SUCCESS) {
                if (keytype < 2) {
                    PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%c", blockno, keytype ? 'B' : 'A');
                } else {
                    PrintAndLogEx(WARNING, "Wrong key. Can't authenticate to block:%3d key type:%02x", blockno, MIFARE_AUTH_KEYA + keytype);
                }
                return PM3_EWRONGANSWER;
            }
        }
    }

    PrintAndLogEx(INFO, "Target block no " _YELLOW_("%3d") ", target key type: " _YELLOW_("%c") ", known target key: " _YELLOW_("%02x%02x%02x%02x%02x%02x%s"),
                  trg_blockno,
                  (trg_keytype == MF_KEY_B) ? 'B' : 'A',
                  trg_key[0], trg_key[1], trg_key[2], trg_key[3], trg_key[4], trg_key[5],
                  known_target_key ? "" : " (not set)"
                 );
    PrintAndLogEx(INFO, "File action: " _YELLOW_("%s") ", Slow: " _YELLOW_("%s") ", Tests: " _YELLOW_("%d"),
                  nonce_file_write ? "write" : nonce_file_read ? "read" : "none",
                  slow ? "Yes" : "No",
                  tests);

    uint64_t foundkey = 0;
    int16_t isOK = mfnestedhard(blockno, keytype, key, trg_blockno, trg_keytype, known_target_key ? trg_key : NULL, nonce_file_read, nonce_file_write, slow, tests, &foundkey, filename);
    switch (isOK) {
        case PM3_ETIMEOUT :
            PrintAndLogEx(ERR, "Error: No response from Proxmark3\n");
            break;
        case PM3_EOPABORTED:
            PrintAndLogEx(WARNING, "Button pressed. Aborted\n");
            break;
        case PM3_ESTATIC_NONCE:
            PrintAndLogEx(ERR, "Error: Static encrypted nonce detected. Aborted\n");
            break;
        case PM3_EFAILED: {
            PrintAndLogEx(FAILED, "\nFailed to recover a key...");
            break;
        }
        default :
            break;
    }

    if ((tests == 0) && IfPm3Iso14443a()) {
        DropField();
    }
    return isOK;
}

static int CmdHF14AMfAutoPWN(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf autopwn",
                  "This command automates the key recovery process on MIFARE Classic cards.\n"
                  "It uses the fchk, chk, darkside, nested, hardnested and staticnested to recover keys.\n"
                  "If all keys are found, it try dumping card content both to file and emulator memory.\n"
                  "\n"
                  "default file name template is `hf-mf-<uid>-<dump|key>.`\n"
                  "using suffix the template becomes `hf-mf-<uid>-<dump|key>-<suffix>.` \n",
                  "hf mf autopwn\n"
                  "hf mf autopwn -s 0 -a -k FFFFFFFFFFFF     --> target MFC 1K card, Sector 0 with known key A 'FFFFFFFFFFFF'\n"
                  "hf mf autopwn --1k -f mfc_default_keys    --> target MFC 1K card, default dictionary\n"
                  "hf mf autopwn --1k -s 0 -a -k FFFFFFFFFFFF -f mfc_default_keys  --> combo of the two above samples\n"
                  "hf mf autopwn --1k -s 0 -a -k FFFFFFFFFFFF -k a0a1a2a3a4a5      --> multiple user supplied keys"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("k", "key",    "<hex>",  "Known key, 12 hex bytes"),
        arg_int0("s",  "sector", "<dec>",  "Input sector number"),
        arg_lit0("a",   NULL,              "Input key A (def)"),
        arg_lit0("b",   NULL,              "Input key B"),
        arg_str0("f",  "file",    "<fn>",  "filename of dictionary"),
        arg_str0(NULL, "suffix",  "<txt>", "Add this suffix to generated files"),
        arg_lit0(NULL, "slow",             "Slower acquisition (required by some non standard cards)"),
        arg_lit0("l",  "legacy",           "legacy mode (use the slow `hf mf chk`)"),
        arg_lit0("v",  "verbose",          "verbose output"),

        arg_lit0(NULL, "ns", "No save to file"),

        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (default)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),

        arg_lit0(NULL, "in", "None (use CPU regular instruction set)"),
#if defined(COMPILER_HAS_SIMD_X86)
        arg_lit0(NULL, "im", "MMX"),
        arg_lit0(NULL, "is", "SSE2"),
        arg_lit0(NULL, "ia", "AVX"),
        arg_lit0(NULL, "i2", "AVX2"),
#endif
#if defined(COMPILER_HAS_SIMD_AVX512)
        arg_lit0(NULL, "i5", "AVX512"),
#endif
#if defined(COMPILER_HAS_SIMD_NEON)
        arg_lit0(NULL, "ie", "NEON"),
#endif
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int in_keys_len = 0;
    uint8_t in_keys[100 * MIFARE_KEY_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 1, in_keys, &in_keys_len);

    uint8_t sectorno = arg_get_u32_def(ctx, 2, 0);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 3) && arg_get_lit(ctx, 4)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 4)) {
        keytype = MF_KEY_B;
    }

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int outfnlen = 0;
    char outfilename[127] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)outfilename, 127, &outfnlen);


    bool slow = arg_get_lit(ctx, 7);
    bool legacy_mfchk = arg_get_lit(ctx, 8);
    bool verbose = arg_get_lit(ctx, 9);

    bool no_save = arg_get_lit(ctx, 10);

    bool m0 = arg_get_lit(ctx, 11);
    bool m1 = arg_get_lit(ctx, 12);
    bool m2 = arg_get_lit(ctx, 13);
    bool m4 = arg_get_lit(ctx, 14);

    bool in = arg_get_lit(ctx, 15);
#if defined(COMPILER_HAS_SIMD_X86)
    bool im = arg_get_lit(ctx, 16);
    bool is = arg_get_lit(ctx, 17);
    bool ia = arg_get_lit(ctx, 18);
    bool i2 = arg_get_lit(ctx, 19);
#endif
#if defined(COMPILER_HAS_SIMD_AVX512)
    bool i5 = arg_get_lit(ctx, 20);
#endif
#if defined(COMPILER_HAS_SIMD_NEON)
    bool ie = arg_get_lit(ctx, 16);
#endif

    CLIParserFree(ctx);

    //validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t sector_cnt = MIFARE_1K_MAXSECTOR;
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;

    if (m0) {
        sector_cnt = MIFARE_MINI_MAXSECTOR;
        block_cnt = MIFARE_MINI_MAXBLOCK;
    } else if (m1) {
        sector_cnt = MIFARE_1K_MAXSECTOR;
        block_cnt = MIFARE_1K_MAXBLOCK;
    } else if (m2) {
        sector_cnt = MIFARE_2K_MAXSECTOR;
        block_cnt = MIFARE_2K_MAXBLOCK;
    } else if (m4) {
        sector_cnt = MIFARE_4K_MAXSECTOR;
        block_cnt = MIFARE_4K_MAXBLOCK;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }


    // set SIM instructions
    SetSIMDInstr(SIMD_AUTO);

#if defined(COMPILER_HAS_SIMD_AVX512)
    if (i5)
        SetSIMDInstr(SIMD_AVX512);
#endif

#if defined(COMPILER_HAS_SIMD_X86)
    if (i2)
        SetSIMDInstr(SIMD_AVX2);
    if (ia)
        SetSIMDInstr(SIMD_AVX);
    if (is)
        SetSIMDInstr(SIMD_SSE2);
    if (im)
        SetSIMDInstr(SIMD_MMX);
#endif

#if defined(COMPILER_HAS_SIMD_NEON)
    if (ie)
        SetSIMDInstr(SIMD_NEON);
#endif

    if (in) {
        SetSIMDInstr(SIMD_NONE);
    }

    // Nested and Hardnested parameter
    uint64_t key64 = 0;
    bool calibrate = true;

    // Attack key storage variables
    uint8_t *keyBlock = NULL;
    uint32_t key_cnt = 0;
    uint8_t tmp_key[MIFARE_KEY_SIZE] = {0};

    // Nested and Hardnested returned status
    uint64_t foundkey = 0;
    int current_sector_i = 0, current_key_type_i = 0;

    // Dumping and transfere to simulater memory
    uint8_t block[MFBLOCK_SIZE] = {0x00};
    int bytes;

    // Settings
    int prng_type = PM3_EUNDEF;
    int isOK = 0;
    // ------------------------------

    uint64_t tagT = GetHF14AMfU_Type();
    if (tagT != MFU_TT_UL_ERROR) {
        PrintAndLogEx(ERR, "Detected a MIFARE Ultralight/C/NTAG Compatible card.");
        PrintAndLogEx(ERR, "This command targets " _YELLOW_("MIFARE Classic"));
        return PM3_ESOFT;
    }

    // Select card to get UID/UIDLEN/ATQA/SAK information
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }

    uint64_t select_status = resp.oldarg[0];
    if (select_status == 0) {
        // iso14443a card select failed
        PrintAndLogEx(FAILED, "No tag detected or other tag communication error");
        PrintAndLogEx(HINT, "Hint: Try some distance or position of the card");
        return PM3_ECARDEXCHANGE;
    }

    // store card info
    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    bool known_key = (in_keys_len > 5);
    uint8_t key[MIFARE_KEY_SIZE] = {0};
    if (known_key) {
        memcpy(key, in_keys, sizeof(key));
    }

    // Add KDF keys...
    uint16_t key1_offset = in_keys_len;
    uint64_t key1 = 0;

    // iceman: todo, need to add all generated keys
    mfc_algo_mizip_one(card.uid, 0, MF_KEY_A, &key1);
    num_to_bytes(key1, MIFARE_KEY_SIZE, in_keys + key1_offset + (0 * MIFARE_KEY_SIZE));

    mfc_algo_di_one(card.uid, 0, MF_KEY_A, &key1);
    num_to_bytes(key1, MIFARE_KEY_SIZE, in_keys + key1_offset + (1 * MIFARE_KEY_SIZE));

    mfc_algo_sky_one(card.uid, 15, MF_KEY_A, &key1);
    num_to_bytes(key1, MIFARE_KEY_SIZE, in_keys + key1_offset + (2 * MIFARE_KEY_SIZE));

    // one key
    mfc_algo_saflok_one(card.uid, 0, MF_KEY_A, &key1);
    num_to_bytes(key1, MIFARE_KEY_SIZE, in_keys + key1_offset + (3 * MIFARE_KEY_SIZE));

    mfc_algo_touch_one(card.uid, 0, MF_KEY_A, &key1);
    num_to_bytes(key1, MIFARE_KEY_SIZE, in_keys + key1_offset + (4 * MIFARE_KEY_SIZE));

    in_keys_len += (MIFARE_KEY_SIZE * 5);

    // detect MFC EV1 Signature
    bool is_ev1 = detect_mfc_ev1_signature();
    if (is_ev1) {
        // hidden sectors on MFC EV1
        sector_cnt += 2;

        // bandaid fix
        block_cnt += 8;
    }

    // create/initialize key storage structure
    sector_t *e_sector = NULL;
    size_t e_sector_cnt = (sector_cnt > sectorno) ? sector_cnt : sectorno + 1;
    if (initSectorTable(&e_sector, e_sector_cnt) != PM3_SUCCESS) {
        return PM3_EMALLOC;
    }

    if (is_ev1) {
        PrintAndLogEx(INFO, "MIFARE Classic EV1 card detected");

        // use found key if not supplied
        if (known_key == false) {
            known_key = true;
            sectorno = 17;
            keytype = MF_KEY_B;
            memcpy(key, g_mifare_signature_key_b, sizeof(g_mifare_signature_key_b));
        }
    }

    // read uid to generate a filename for the key file
    char suffix[FILE_PATH_SIZE];
    if (outfnlen) {
        snprintf(suffix, sizeof(suffix) - strlen(outfilename), "-key-%s.bin", outfilename);
    } else {
        snprintf(suffix, sizeof(suffix), "-key.bin");
    }
    char *fptr = GenerateFilename("hf-mf-", suffix);

    // check if tag doesn't have static nonce
    int has_staticnonce = detect_classic_static_nonce();

    // card prng type (weak=1 / hard=0 / select/card comm error = negative value)
    if (has_staticnonce == NONCE_NORMAL)  {
        prng_type = detect_classic_prng();
        if (prng_type < 0) {
            PrintAndLogEx(FAILED, "\nNo tag detected or other tag communication error (%i)", prng_type);
            free(e_sector);
            free(fptr);
            return PM3_ESOFT;
        }
    }

    // print parameters
    if (verbose) {
        PrintAndLogEx(INFO, "======================= " _YELLOW_("SETTINGS") " =======================");
        PrintAndLogEx(INFO, " card sectors .. " _YELLOW_("%d"), sector_cnt);
        PrintAndLogEx(INFO, " key supplied .. " _YELLOW_("%s"), known_key ? "True" : "False");
        PrintAndLogEx(INFO, " known sector .. " _YELLOW_("%d"), sectorno);
        PrintAndLogEx(INFO, " keytype ....... " _YELLOW_("%c"), (keytype == MF_KEY_B) ? 'B' : 'A');
        PrintAndLogEx(INFO, " known key ..... " _YELLOW_("%s"), sprint_hex_inrow(key, sizeof(key)));

        if (has_staticnonce == NONCE_STATIC)
            PrintAndLogEx(INFO, " card PRNG ..... " _YELLOW_("STATIC"));
        else if (has_staticnonce == NONCE_NORMAL)
            PrintAndLogEx(INFO, " card PRNG ..... " _YELLOW_("%s"), prng_type ? "WEAK" : "HARD");
        else
            PrintAndLogEx(INFO, " card PRNG ..... " _YELLOW_("Could not determine PRNG,") " " _RED_("read failed."));

        PrintAndLogEx(INFO, " dictionary .... " _YELLOW_("%s"), strlen(filename) ? filename : "NONE");
        PrintAndLogEx(INFO, " legacy mode ... " _YELLOW_("%s"), legacy_mfchk ? "True" : "False");

        PrintAndLogEx(INFO, "========================================================================");
    }

    // check the user supplied key
    if (known_key == false) {
        PrintAndLogEx(WARNING, "no known key was supplied, key recovery might fail");
    }

    // Start the timer
    uint64_t t1 = msclock();

    int ret = mf_load_keys(&keyBlock, &key_cnt, in_keys, in_keys_len, filename, fnlen, true);
    if (ret != PM3_SUCCESS) {
        free(e_sector);
        return ret;
    }

    int32_t res = PM3_SUCCESS;

    // Use the dictionary to find sector keys on the card
    if (verbose) PrintAndLogEx(INFO, "======================= " _YELLOW_("START DICTIONARY ATTACK") " =======================");

    if (legacy_mfchk) {
        PrintAndLogEx(INFO, "." NOLF);
        // Check all the sectors
        for (int i = 0; i < sector_cnt; i++) {
            for (int j = MF_KEY_A; j <= MF_KEY_B; j++) {
                // Check if the key is known
                if (e_sector[i].foundKey[j] == 0) {
                    for (uint32_t k = 0; k < key_cnt; k++) {
                        PrintAndLogEx(NORMAL, "." NOLF);
                        fflush(stdout);

                        if (mf_check_keys(mfFirstBlockOfSector(i), j, true, 1, (keyBlock + (MIFARE_KEY_SIZE * k)), &key64) == PM3_SUCCESS) {
                            e_sector[i].Key[j] = bytes_to_num((keyBlock + (MIFARE_KEY_SIZE * k)), MIFARE_KEY_SIZE);
                            e_sector[i].foundKey[j] = 'D';
                            break;
                        }
                    }
                }
            }
        }
        PrintAndLogEx(NORMAL, "");
    } else {

        uint32_t chunksize = key_cnt > (PM3_CMD_DATA_SIZE / MIFARE_KEY_SIZE) ? (PM3_CMD_DATA_SIZE / MIFARE_KEY_SIZE) : key_cnt;
        bool firstChunk = true, lastChunk = false;

        for (uint8_t strategy = 1; strategy < 3; strategy++) {
            PrintAndLogEx(INFO, "running strategy %u", strategy);
            // main keychunk loop
            for (uint32_t i = 0; i < key_cnt; i += chunksize) {

                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                    i = key_cnt;
                    strategy = 3;
                    break; // Exit the loop
                }
                uint32_t size = ((key_cnt - i)  > chunksize) ? chunksize : key_cnt - i;
                // last chunk?
                if (size == key_cnt - i) {
                    lastChunk = true;
                }

                res = mf_check_keys_fast(sector_cnt, firstChunk, lastChunk, strategy, size, keyBlock + (i * MIFARE_KEY_SIZE), e_sector, false, verbose);
                if (firstChunk) {
                    firstChunk = false;
                }
                // all keys,  aborted
                if (res == PM3_SUCCESS) {
                    i = key_cnt;
                    strategy = 3;
                    break; // Exit the loop
                }
            } // end chunks of keys
            firstChunk = true;
            lastChunk = false;
        } // end strategy
    }

    // Analyse the dictionary attack
    uint8_t num_found_keys = 0;
    for (int i = 0; i < sector_cnt; i++) {
        for (int j = MF_KEY_A; j <= MF_KEY_B; j++) {
            if (e_sector[i].foundKey[j] != 1) {
                continue;
            }

            ++num_found_keys;

            e_sector[i].foundKey[j] = 'D';
            num_to_bytes(e_sector[i].Key[j], MIFARE_KEY_SIZE, tmp_key);

            // Store valid credentials for the nested / hardnested attack if none exist
            if (known_key == false) {
                num_to_bytes(e_sector[i].Key[j], MIFARE_KEY_SIZE, key);
                known_key = true;
                sectorno = i;
                keytype = j;
                PrintAndLogEx(SUCCESS, "target sector %3u key type %c -- found valid key [ " _GREEN_("%s") " ] (used for nested / hardnested attack)",
                              i,
                              (j == MF_KEY_B) ? 'B' : 'A',
                              sprint_hex_inrow(tmp_key, sizeof(tmp_key))
                             );
            } else {
                PrintAndLogEx(SUCCESS, "target sector %3u key type %c -- found valid key [ " _GREEN_("%s") " ]",
                              i,
                              (j == MF_KEY_B) ? 'B' : 'A',
                              sprint_hex_inrow(tmp_key, sizeof(tmp_key))
                             );
            }
        }
    }

    if (num_found_keys == sector_cnt * 2) {
        goto all_found;
    }

    // Check if at least one sector key was found
    if (known_key == false) {

        // Check if the darkside attack can be used
        if (prng_type && has_staticnonce != NONCE_STATIC) {
            if (verbose) {
                PrintAndLogEx(INFO, "======================= " _YELLOW_("START DARKSIDE ATTACK") " =======================");
            }

            PrintAndLogEx(NORMAL, "");

            isOK = mf_dark_side(mfFirstBlockOfSector(sectorno), MIFARE_AUTH_KEYA + keytype, &key64);

            if (isOK != PM3_SUCCESS)
                goto noValidKeyFound;

            PrintAndLogEx(SUCCESS, "Found valid key [ " _GREEN_("%012" PRIx64) " ]\n", key64);

            // Store the keys
            num_to_bytes(key64, MIFARE_KEY_SIZE, key);
            e_sector[sectorno].Key[keytype] = key64;
            e_sector[sectorno].foundKey[keytype] = 'S';
            PrintAndLogEx(SUCCESS, "target sector %3u key type %c -- found valid key [ " _GREEN_("%012" PRIx64) " ] (used for nested / hardnested attack)",
                          sectorno,
                          (keytype == MF_KEY_B) ? 'B' : 'A',
                          key64
                         );
        } else {

noValidKeyFound:
            PrintAndLogEx(FAILED, "No usable key was found!");
            free(keyBlock);
            free(e_sector);
            free(fptr);
            return PM3_ESOFT;
        }
    }

    free(keyBlock);
    // Clear the needed variables
    num_to_bytes(0, MIFARE_KEY_SIZE, tmp_key);
    bool nested_failed = false;

    // Iterate over each sector and key(A/B)
    for (current_sector_i = 0; current_sector_i < sector_cnt; current_sector_i++) {

        for (current_key_type_i = MF_KEY_A; current_key_type_i <= MF_KEY_B; current_key_type_i++) {

            // If the key is already known, just skip it
            if (e_sector[current_sector_i].foundKey[current_key_type_i] == 0) {

                if (has_staticnonce == NONCE_STATIC)
                    goto tryStaticnested;

                // Try the found keys are reused
                if (bytes_to_num(tmp_key, MIFARE_KEY_SIZE) != 0) {
                    // <!> The fast check --> mfCheckKeys_fast(sector_cnt, true, true, 2, 1, tmp_key, e_sector, false, verbose);
                    // <!> Returns false keys, so we just stick to the slower mfchk.
                    for (int i = 0; i < sector_cnt; i++) {
                        for (int j = MF_KEY_A; j <= MF_KEY_B; j++) {
                            // Check if the sector key is already broken
                            if (e_sector[i].foundKey[j])
                                continue;

                            // Check if the key works
                            if (mf_check_keys(mfFirstBlockOfSector(i), j, true, 1, tmp_key, &key64) == PM3_SUCCESS) {
                                e_sector[i].Key[j] = bytes_to_num(tmp_key, MIFARE_KEY_SIZE);
                                e_sector[i].foundKey[j] = 'R';
                                PrintAndLogEx(SUCCESS, "target sector %3u key type %c -- found valid key [ " _GREEN_("%s") " ]",
                                              i,
                                              (j == MF_KEY_B) ? 'B' : 'A',
                                              sprint_hex_inrow(tmp_key, sizeof(tmp_key))
                                             );
                            }
                        }
                    }
                }
                // Clear the last found key
                num_to_bytes(0, MIFARE_KEY_SIZE, tmp_key);

                if (current_key_type_i == MF_KEY_B) {
                    if (e_sector[current_sector_i].foundKey[0] && !e_sector[current_sector_i].foundKey[1]) {
                        if (verbose) {
                            PrintAndLogEx(INFO, "======================= " _YELLOW_("START READ B KEY ATTACK") " =======================");
                            PrintAndLogEx(INFO, "reading B key of sector %3d with key type %c",
                                          current_sector_i,
                                          (current_key_type_i == MF_KEY_B) ? 'B' : 'A');
                        }
                        uint8_t sectrail = (mfFirstBlockOfSector(current_sector_i) + mfNumBlocksPerSector(current_sector_i) - 1);

                        mf_readblock_t payload;
                        payload.blockno = sectrail;
                        payload.keytype = MF_KEY_A;

                        num_to_bytes(e_sector[current_sector_i].Key[0], MIFARE_KEY_SIZE, payload.key); // KEY A

                        clearCommandBuffer();
                        SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));

                        if (WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500) == false) goto skipReadBKey;

                        if (resp.status != PM3_SUCCESS) goto skipReadBKey;

                        uint8_t *data = resp.data.asBytes;
                        key64 = bytes_to_num(data + 10, MIFARE_KEY_SIZE);
                        if (key64) {
                            e_sector[current_sector_i].foundKey[current_key_type_i] = 'A';
                            e_sector[current_sector_i].Key[current_key_type_i] = key64;
                            num_to_bytes(key64, MIFARE_KEY_SIZE, tmp_key);
                            PrintAndLogEx(SUCCESS, "target sector %3u key type %c -- found valid key [ " _GREEN_("%s") " ]",
                                          current_sector_i,
                                          (current_key_type_i == MF_KEY_B) ? 'B' : 'A',
                                          sprint_hex_inrow(tmp_key, sizeof(tmp_key))
                                         );
                        } else {
                            if (verbose) {
                                PrintAndLogEx(WARNING, "unknown  B  key: sector: %3d key type: %c",
                                              current_sector_i,
                                              (current_key_type_i == MF_KEY_B) ? 'B' : 'A'
                                             );
                                PrintAndLogEx(INFO, " -- reading the B key was not possible, maybe due to access rights?");

                            }

                        }
                    }
                }

                // Use the nested / hardnested attack
skipReadBKey:
                if (e_sector[current_sector_i].foundKey[current_key_type_i] == 0) {

                    if (has_staticnonce == NONCE_STATIC)
                        goto tryStaticnested;

                    if (prng_type && (nested_failed == false)) {
                        uint8_t retries = 0;
                        if (verbose) {
                            PrintAndLogEx(INFO, "======================= " _YELLOW_("START NESTED ATTACK") " =======================");
                            PrintAndLogEx(INFO, "sector no %3d, target key type %c",
                                          current_sector_i,
                                          (current_key_type_i == MF_KEY_B) ? 'B' : 'A');
                        }
tryNested:
                        isOK = mf_nested(mfFirstBlockOfSector(sectorno), keytype, key, mfFirstBlockOfSector(current_sector_i), current_key_type_i, tmp_key, calibrate);

                        switch (isOK) {
                            case PM3_ETIMEOUT: {
                                PrintAndLogEx(ERR, "\nError: No response from Proxmark3.");
                                free(e_sector);
                                free(fptr);
                                return isOK;
                            }
                            case PM3_EOPABORTED: {
                                PrintAndLogEx(WARNING, "\nButton pressed. Aborted.");
                                free(e_sector);
                                free(fptr);
                                return isOK;
                            }
                            case PM3_EFAILED: {
                                PrintAndLogEx(FAILED, "Tag isn't vulnerable to Nested Attack (PRNG is probably not predictable).");
                                PrintAndLogEx(FAILED, "Nested attack failed --> try hardnested");
                                goto tryHardnested;
                            }
                            case PM3_ESOFT: {
                                // key not found
                                calibrate = false;
                                // this can happen on some old cards, it's worth trying some more before switching to slower hardnested
                                if (retries++ < MIFARE_SECTOR_RETRY) {
                                    PrintAndLogEx(FAILED, "Nested attack failed, trying again (%i/%i)", retries, MIFARE_SECTOR_RETRY);
                                    goto tryNested;
                                } else {
                                    PrintAndLogEx(FAILED, "Nested attack failed, moving to hardnested");
                                    nested_failed = true;
                                    goto tryHardnested;
                                }
                                break;
                            }
                            case PM3_ESTATIC_NONCE: {
                                PrintAndLogEx(ERR, "Error: Static encrypted nonce detected. Aborted\n");

                                e_sector[current_sector_i].Key[current_key_type_i] = 0xffffffffffff;
                                e_sector[current_sector_i].foundKey[current_key_type_i] = false;
                                // Show the results to the user
                                PrintAndLogEx(NORMAL, "");
                                PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));
                                printKeyTable(sector_cnt, e_sector);
                                PrintAndLogEx(NORMAL, "");
                                free(e_sector);
                                free(fptr);
                                return isOK;
                            }
                            case PM3_SUCCESS: {
                                calibrate = false;
                                e_sector[current_sector_i].Key[current_key_type_i] = bytes_to_num(tmp_key, MIFARE_KEY_SIZE);
                                e_sector[current_sector_i].foundKey[current_key_type_i] = 'N';
                                break;
                            }
                            default: {
                                PrintAndLogEx(ERR, "unknown Error.\n");
                                free(e_sector);
                                free(fptr);
                                return isOK;
                            }
                        }

                    } else {
tryHardnested: // If the nested attack fails then we try the hardnested attack
                        if (verbose) {
                            PrintAndLogEx(INFO, "======================= " _YELLOW_("START HARDNESTED ATTACK") " =======================");
                            PrintAndLogEx(INFO, "sector no %3d, target key type %c, Slow %s",
                                          current_sector_i,
                                          (current_key_type_i == MF_KEY_B) ? 'B' : 'A',
                                          slow ? "Yes" : "No");
                        }

                        foundkey = 0;
                        isOK = mfnestedhard(mfFirstBlockOfSector(sectorno), keytype, key, mfFirstBlockOfSector(current_sector_i), current_key_type_i, NULL, false, false, slow, 0, &foundkey, NULL);
                        DropField();
                        if (isOK != PM3_SUCCESS) {
                            switch (isOK) {
                                case PM3_ETIMEOUT: {
                                    PrintAndLogEx(ERR, "\nError: No response from Proxmark3");
                                    break;
                                }
                                case PM3_EOPABORTED: {
                                    PrintAndLogEx(NORMAL, "\nButton pressed, user aborted");
                                    break;
                                }
                                case PM3_ESTATIC_NONCE: {
                                    PrintAndLogEx(ERR, "\nError: Static encrypted nonce detected. Aborted\n");

                                    e_sector[current_sector_i].Key[current_key_type_i] = 0xffffffffffff;
                                    e_sector[current_sector_i].foundKey[current_key_type_i] = false;

                                    // Show the results to the user
                                    PrintAndLogEx(NORMAL, "");
                                    PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));
                                    printKeyTable(sector_cnt, e_sector);
                                    PrintAndLogEx(NORMAL, "");
                                    break;
                                }
                                case PM3_EFAILED: {
                                    PrintAndLogEx(FAILED, "\nFailed to recover a key...");
                                    continue;
                                }
                                default: {
                                    break;
                                }
                            }
                            free(e_sector);
                            free(fptr);
                            return PM3_ESOFT;
                        }

                        // Copy the found key to the tmp_key variale (for the following print statement, and the mfCheckKeys above)
                        num_to_bytes(foundkey, MIFARE_KEY_SIZE, tmp_key);
                        e_sector[current_sector_i].Key[current_key_type_i] = foundkey;
                        e_sector[current_sector_i].foundKey[current_key_type_i] = 'H';
                    }

                    if (has_staticnonce == NONCE_STATIC) {
tryStaticnested:
                        if (verbose) {
                            PrintAndLogEx(INFO, "======================= " _YELLOW_("START STATIC NESTED ATTACK") " =======================");
                            PrintAndLogEx(INFO, "sector no %3d, target key type %c",
                                          current_sector_i,
                                          (current_key_type_i == MF_KEY_B) ? 'B' : 'A');
                        }

                        isOK = mf_static_nested(mfFirstBlockOfSector(sectorno), keytype, key, mfFirstBlockOfSector(current_sector_i), current_key_type_i, tmp_key);
                        DropField();
                        switch (isOK) {
                            case PM3_ETIMEOUT: {
                                PrintAndLogEx(ERR, "\nError: No response from Proxmark3");
                                free(e_sector);
                                free(fptr);
                                return isOK;
                            }
                            case PM3_EOPABORTED: {
                                PrintAndLogEx(WARNING, "\nButton pressed, user aborted");
                                free(e_sector);
                                free(fptr);
                                return isOK;
                            }
                            case PM3_SUCCESS: {
                                e_sector[current_sector_i].Key[current_key_type_i] = bytes_to_num(tmp_key, MIFARE_KEY_SIZE);
                                e_sector[current_sector_i].foundKey[current_key_type_i] = 'C';
                                break;
                            }
                            default: {
                                break;
                            }
                        }
                    }

                    // Check if the key was found
                    if (e_sector[current_sector_i].foundKey[current_key_type_i]) {
                        PrintAndLogEx(SUCCESS, "target sector %3u key type %c -- found valid key [ " _GREEN_("%s") " ]",
                                      current_sector_i,
                                      (current_key_type_i == MF_KEY_B) ? 'B' : 'A',
                                      sprint_hex_inrow(tmp_key, sizeof(tmp_key))
                                     );
                    }
                }
            }
        }
    }

all_found:

    // Show the results to the user
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));

    printKeyTable(sector_cnt, e_sector);

    if (no_save == false) {

        // Dump the keys
        PrintAndLogEx(NORMAL, "");
        if (createMfcKeyDump(fptr, sector_cnt, e_sector) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to save keys to file");
        }
    }

    // clear emulator mem
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EML_MEMCLR, NULL, 0);

    PrintAndLogEx(INFO, "transferring keys to simulator memory " NOLF);

    bool transfer_status = true;
    for (current_sector_i = 0; current_sector_i < sector_cnt; current_sector_i++) {
        mf_eml_get_mem(block, current_sector_i, 1);
        if (e_sector[current_sector_i].foundKey[0])
            num_to_bytes(e_sector[current_sector_i].Key[0], MIFARE_KEY_SIZE, block);
        if (e_sector[current_sector_i].foundKey[1])
            num_to_bytes(e_sector[current_sector_i].Key[1], MIFARE_KEY_SIZE, block + 10);

        transfer_status |= mf_elm_set_mem(block, mfFirstBlockOfSector(current_sector_i) + mfNumBlocksPerSector(current_sector_i) - 1, 1);
    }
    PrintAndLogEx(NORMAL, "( %s )", (transfer_status) ? _GREEN_("ok") : _RED_("fail"));

    PrintAndLogEx(INFO, "dumping card content to emulator memory (Cmd Error: 04 can occur)");

    // use ecfill trick
    FastDumpWithEcFill(sector_cnt);

    if (no_save) {
        PrintAndLogEx(INFO, "Called with no save option");
        PrintAndLogEx(NORMAL, "");
        goto out;
    }

    bytes = block_cnt * MFBLOCK_SIZE;
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(ERR, "Fail, cannot allocate memory");
        free(e_sector);
        free(fptr);
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading card content from emulator memory");
    if (GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false) == false) {
        PrintAndLogEx(ERR, "Fail, transfer from device time-out");
        free(e_sector);
        free(dump);
        free(fptr);
        return PM3_ETIMEOUT;
    }

    free(fptr);

    if (outfnlen) {
        snprintf(suffix, sizeof(suffix), "-dump-%s", outfilename);
    } else {
        snprintf(suffix, sizeof(suffix), "-dump");
    }
    fptr = GenerateFilename("hf-mf-", suffix);
    if (fptr == NULL) {
        free(dump);
        free(e_sector);
        free(fptr);
        return PM3_ESOFT;
    }

    strncpy(filename, fptr, sizeof(filename) - 1);
    free(fptr);

    pm3_save_mf_dump(filename, dump, bytes, jsfCardMemory);
    free(dump);

out:
    // Generate and show statistics
    t1 = msclock() - t1;
    PrintAndLogEx(INFO, "autopwn execution time: " _YELLOW_("%.0f") " seconds", (float)t1 / 1000.0);

    free(e_sector);
    return PM3_SUCCESS;
}

static int CmdHF14AMfChk_fast(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf fchk",
                  "This is a improved checkkeys method speedwise. It checks MIFARE Classic tags sector keys against a dictionary file with keys",
                  "hf mf fchk --mini -k FFFFFFFFFFFF              --> Key recovery against MIFARE Mini\n"
                  "hf mf fchk --1k -k FFFFFFFFFFFF                --> Key recovery against MIFARE Classic 1k\n"
                  "hf mf fchk --2k -k FFFFFFFFFFFF                --> Key recovery against MIFARE 2k\n"
                  "hf mf fchk --4k -k FFFFFFFFFFFF                --> Key recovery against MIFARE 4k\n"
                  "hf mf fchk --1k -f mfc_default_keys.dic        --> Target 1K using default dictionary file\n"
                  "hf mf fchk --1k --emu                          --> Target 1K, write keys to emulator memory\n"
                  "hf mf fchk --1k --dump                         --> Target 1K, write keys to file\n"
                  "hf mf fchk --1k --mem                          --> Target 1K, use dictionary from flash memory");

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("k", "key", "<hex>", "Key specified as 12 hex symbols"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (default)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "emu", "Fill simulator keys from found keys"),
        arg_lit0(NULL, "dump", "Dump found keys to binary file"),
        arg_lit0(NULL, "mem", "Use dictionary from flashmemory"),
        arg_str0("f", "file", "<fn>", "filename of dictionary"),
        arg_int0(NULL, "blk", "<dec>", "block number (single block recovery mode)"),
        arg_lit0("a", NULL, "single block recovery key A"),
        arg_lit0("b", NULL, "single block recovery key B"),
        arg_lit0(NULL, "no-default", "Skip check default keys"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keylen = 0;
    uint8_t key[100 * MIFARE_KEY_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);

    bool transferToEml = arg_get_lit(ctx, 6);
    bool createDumpFile = arg_get_lit(ctx, 7);
    bool use_flashmemory = arg_get_lit(ctx, 8);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 9), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    int blockn = arg_get_int_def(ctx, 10, -1);
    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 11) && arg_get_lit(ctx, 12)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 12)) {
        keytype = MF_KEY_B;
    }
    bool load_default = ! arg_get_lit(ctx, 13);

    CLIParserFree(ctx);

    //validations

    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t sectorsCnt = MIFARE_1K_MAXSECTOR;
    if (m0) {
        sectorsCnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        sectorsCnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        sectorsCnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        sectorsCnt = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    uint8_t *keyBlock = NULL;
    uint32_t keycnt = 0;
    int ret = mf_load_keys(&keyBlock, &keycnt, key, keylen, filename, fnlen, load_default);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    // create/initialize key storage structure
    sector_t *e_sector = NULL;
    if (initSectorTable(&e_sector, sectorsCnt) != PM3_SUCCESS) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    uint32_t chunksize = keycnt > (PM3_CMD_DATA_SIZE / MIFARE_KEY_SIZE) ? (PM3_CMD_DATA_SIZE / MIFARE_KEY_SIZE) : keycnt;
    bool firstChunk = true, lastChunk = false;

    int i = 0;

    // time
    uint64_t t1 = msclock();

    uint16_t singleSectorParams = 0;
    if (blockn != -1) {
        singleSectorParams = (blockn & 0xFF) | keytype << 8 | 1 << 15;
    }
    if (use_flashmemory) {
        PrintAndLogEx(SUCCESS, "Using dictionary in flash memory");
        mf_check_keys_fast_ex(sectorsCnt, true, true, 1, 0, keyBlock, e_sector, use_flashmemory, false, false, singleSectorParams);
    } else {

        // strategies. 1= deep first on sector 0 AB,  2= width first on all sectors
        for (uint8_t strategy = 1; strategy < 3; strategy++) {
            PrintAndLogEx(INFO, "Running strategy %u", strategy);

            // main keychunk loop
            for (i = 0; i < keycnt; i += chunksize) {

                if (kbd_enter_pressed()) {
                    PrintAndLogEx(NORMAL, "");
                    PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                    // field is still ON if not on last chunk
                    clearCommandBuffer();
                    SendCommandNG(CMD_FPGA_MAJOR_MODE_OFF, NULL, 0);
                    // TODO: we're missing these cleanups on arm side, not sure if it's important...
                    // set_tracing(false);
                    // BigBuf_free();
                    // BigBuf_Clear_ext(false);
                    goto out;
                }
                PrintAndLogEx(INPLACE, "Testing %5i/%5i %02.1f%%", i, keycnt, (float)i * 100 / keycnt);
                uint32_t size = ((keycnt - i)  > chunksize) ? chunksize : keycnt - i;

                // last chunk?
                if (size == keycnt - i)
                    lastChunk = true;

                int res = mf_check_keys_fast_ex(sectorsCnt, firstChunk, lastChunk, strategy, size, keyBlock + (i * MIFARE_KEY_SIZE), e_sector, false, false, true, singleSectorParams);
                if (firstChunk)
                    firstChunk = false;

                // all keys,  aborted
                if (res == PM3_SUCCESS || res == 2) {
                    PrintAndLogEx(NORMAL, "");
                    goto out;
                }
            } // end chunks of keys
            PrintAndLogEx(INPLACE, "Testing %5i/%5i 100.00%%", keycnt, keycnt);
            PrintAndLogEx(NORMAL, "");
            firstChunk = true;
            lastChunk = false;
            if (blockn != -1) break;
        } // end strategy
    }
out:
    t1 = msclock() - t1;
    PrintAndLogEx(INFO, "Time in checkkeys (fast) " _YELLOW_("%.1fs") "\n", (float)(t1 / 1000.0));

    if (blockn != -1) {
        goto out2;
    }

    // check..
    uint8_t found_keys = 0;
    for (i = 0; i < sectorsCnt; ++i) {

        if (e_sector[i].foundKey[0])
            found_keys++;

        if (e_sector[i].foundKey[1])
            found_keys++;
    }

    if (found_keys == 0) {
        PrintAndLogEx(WARNING, "No keys found");
    } else {

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));

        printKeyTable(sectorsCnt, e_sector);

        if (use_flashmemory && found_keys == (sectorsCnt << 1)) {
            PrintAndLogEx(SUCCESS, "Card dumped as well. run " _YELLOW_("`%s %c`"),
                          "hf mf esave",
                          GetFormatFromSector(sectorsCnt)
                         );
        }

        if (transferToEml) {
            // fast push mode
            g_conn.block_after_ACK = true;
            uint8_t block[MFBLOCK_SIZE] = {0x00};
            for (i = 0; i < sectorsCnt; ++i) {
                uint8_t b = mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1;
                mf_eml_get_mem(block, b, 1);

                if (e_sector[i].foundKey[0])
                    num_to_bytes(e_sector[i].Key[0], MIFARE_KEY_SIZE, block);

                if (e_sector[i].foundKey[1])
                    num_to_bytes(e_sector[i].Key[1], MIFARE_KEY_SIZE, block + 10);

                if (i == sectorsCnt - 1) {
                    // Disable fast mode on last packet
                    g_conn.block_after_ACK = false;
                }
                mf_elm_set_mem(block, b, 1);
            }
            PrintAndLogEx(SUCCESS, "Found keys have been transferred to the emulator memory");

            if (found_keys == (sectorsCnt << 1)) {
                FastDumpWithEcFill(sectorsCnt);
            }
        }

        if (createDumpFile) {

            char *fptr = GenerateFilename("hf-mf-", "-key.bin");
            if (createMfcKeyDump(fptr, sectorsCnt, e_sector) != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Failed to save keys to file");
            }
            free(fptr);
        }
    }
out2:
    free(keyBlock);
    free(e_sector);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHF14AMfSmartBrute(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf brute",
                  "This is a smart bruteforce, exploiting common patterns, bugs and bad designs in key generators.",
                  "hf mf brute --mini           --> Key recovery against MIFARE Mini\n"
                  "hf mf brute --1k               --> Key recovery against MIFARE Classic 1k\n"
                  "hf mf brute --2k                --> Key recovery against MIFARE 2k\n"
                  "hf mf brute --4k                --> Key recovery against MIFARE 4k\n"
                  "hf mf brute --1k --emu                          --> Target 1K, write keys to emulator memory\n"
                  "hf mf brute --1k --dump                         --> Target 1K, write keys to file\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (default)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "emu", "Fill simulator keys from found keys"),
        arg_lit0(NULL, "dump", "Dump found keys to binary file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);


    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);

    bool transferToEml = arg_get_lit(ctx, 6);
    bool createDumpFile = arg_get_lit(ctx, 7);

    CLIParserFree(ctx);

    //validations

    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t sectorsCnt = MIFARE_1K_MAXSECTOR;
    if (m0) {
        sectorsCnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        sectorsCnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        sectorsCnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        sectorsCnt = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    uint32_t chunksize = 100 > (PM3_CMD_DATA_SIZE / MIFARE_KEY_SIZE) ? (PM3_CMD_DATA_SIZE / MIFARE_KEY_SIZE) : 100;
    uint8_t *keyBlock = calloc(MIFARE_KEY_SIZE, chunksize);

    if (keyBlock == NULL)
        return PM3_EMALLOC;

    // create/initialize key storage structure
    sector_t *e_sector = NULL;
    if (initSectorTable(&e_sector, sectorsCnt) != PM3_SUCCESS) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    // initialize bruteforce engine
    generator_context_t bctx;
    bf_generator_init(&bctx, BF_MODE_SMART, BF_KEY_SIZE_48);

    int i = 0, ret;
    int smart_mode_stage = -1;
    uint64_t generator_key;

    // time
    uint64_t t0 = msclock();
    uint64_t t1 = msclock();
    uint64_t keys_checked = 0;
    uint64_t total_keys_checked = 0;

    uint32_t keycnt = 0;
    bool firstChunk = true, lastChunk = false;

    while (!lastChunk) {
        keycnt = 0;

        // generate block of keys from generator
        memset(keyBlock, 0, MIFARE_KEY_SIZE * chunksize);

        for (i = 0; i < chunksize; i++) {

            ret = bf_generate(&bctx);

            if (ret == BF_GENERATOR_ERROR) {
                PrintAndLogEx(ERR, "Internal bruteforce generator error");
                free(keyBlock);
                free(e_sector);
                return PM3_EFAILED;

            } else if (ret == BF_GENERATOR_END) {

                lastChunk = true;
                break;

            } else if (ret == BF_GENERATOR_NEXT) {

                generator_key = bf_get_key48(&bctx);
                num_to_bytes(generator_key, MIFARE_KEY_SIZE, keyBlock + (i * MIFARE_KEY_SIZE));
                keycnt++;

                if (smart_mode_stage != bctx.smart_mode_stage) {

                    smart_mode_stage = bctx.smart_mode_stage;
                    PrintAndLogEx(INFO, "Running bruteforce stage %d", smart_mode_stage);

                    if (keys_checked) {

                        PrintAndLogEx(INFO, "Current cracking speed (keys/s): %lu",
                                      keys_checked / ((msclock() - t1) / 1000)
                                     );

                        t1 = msclock();
                        keys_checked = 0;
                    }
                }
            }
        }

        int strategy = 2; // width first on all sectors
        ret = mf_check_keys_fast(sectorsCnt, firstChunk, lastChunk, strategy, keycnt, keyBlock, e_sector, false, false);

        keys_checked += keycnt;
        total_keys_checked += keycnt;

        if (firstChunk)
            firstChunk = false;

        if (ret == PM3_SUCCESS || ret == 2)
            goto out;

    }

out:
    PrintAndLogEx(INFO, "Time in brute mode: " _YELLOW_("%.1fs") "\n", (float)((msclock() - t0) / 1000.0));
    PrintAndLogEx(INFO, "Total keys checked: " _YELLOW_("%lu") "\n", total_keys_checked);
    // check..
    uint8_t found_keys = 0;
    for (i = 0; i < sectorsCnt; ++i) {

        if (e_sector[i].foundKey[0]) {
            found_keys++;
        }

        if (e_sector[i].foundKey[1]) {
            found_keys++;
        }
    }

    if (found_keys == 0) {
        PrintAndLogEx(WARNING, "No keys found");
    } else {

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));

        printKeyTable(sectorsCnt, e_sector);

        if (transferToEml) {
            // fast push mode
            g_conn.block_after_ACK = true;
            uint8_t block[MFBLOCK_SIZE] = {0x00};
            for (i = 0; i < sectorsCnt; ++i) {
                uint8_t b = mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1;
                mf_eml_get_mem(block, b, 1);

                if (e_sector[i].foundKey[0])
                    num_to_bytes(e_sector[i].Key[0], MIFARE_KEY_SIZE, block);

                if (e_sector[i].foundKey[1])
                    num_to_bytes(e_sector[i].Key[1], MIFARE_KEY_SIZE, block + 10);

                if (i == sectorsCnt - 1) {
                    // Disable fast mode on last packet
                    g_conn.block_after_ACK = false;
                }
                mf_elm_set_mem(block, b, 1);
            }
            PrintAndLogEx(SUCCESS, "Found keys have been transferred to the emulator memory");

            if (found_keys == (sectorsCnt << 1)) {
                FastDumpWithEcFill(sectorsCnt);
            }
        }

        if (createDumpFile) {

            char *fptr = GenerateFilename("hf-mf-", "-key.bin");
            if (createMfcKeyDump(fptr, sectorsCnt, e_sector) != PM3_SUCCESS) {
                PrintAndLogEx(ERR, "Failed to save keys to file");
            }
            free(fptr);

        }
    }

    free(keyBlock);
    free(e_sector);
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHF14AMfChk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf chk",
                  "Check keys on MIFARE Classic card",
                  "hf mf chk --mini -k FFFFFFFFFFFF              --> Check all sectors, all keys against MIFARE Mini\n"
                  "hf mf chk --1k -k FFFFFFFFFFFF                --> Check all sectors, all keys against MIFARE Classic 1k\n"
                  "hf mf chk --2k -k FFFFFFFFFFFF                --> Check all sectors, all keys against MIFARE 2k\n"
                  "hf mf chk --4k -k FFFFFFFFFFFF                --> Check all sectors, all keys against MIFARE 4k\n"
                  "hf mf chk --1k --emu                          --> Check all sectors, all keys, 1K, and write to emulator memory\n"
                  "hf mf chk --1k --dump                         --> Check all sectors, all keys, 1K, and write to file\n"
                  "hf mf chk -a --tblk 0 -f mfc_default_keys.dic --> Check dictionary against block 0, key A");

    void *argtable[] = {
        arg_param_begin,
        arg_strx0("k", "key", "<hex>", "Key specified as 12 hex symbols"),
        arg_int0(NULL, "tblk", "<dec>", "Target block number"),
        arg_lit0("a", NULL, "Target Key A"),
        arg_lit0("b", NULL, "Target Key B"),
        arg_lit0("*", "all", "Target both key A & B (default)"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (default)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "emu", "Fill simulator keys from found keys"),
        arg_lit0(NULL, "dump", "Dump found keys to binary file"),
        arg_str0("f", "file", "<fn>", "Filename of dictionary"),
        arg_lit0(NULL, "no-default", "Skip check default keys"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keylen = 0;
    uint8_t key[100 * MIFARE_KEY_SIZE] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);

    int blockNo = arg_get_int_def(ctx, 2, -1);

    uint8_t keyType = 2;

    if ((arg_get_lit(ctx, 3) && arg_get_lit(ctx, 4)) || arg_get_lit(ctx, 5)) {
        keyType = 2;
    } else if (arg_get_lit(ctx, 3)) {
        keyType = MF_KEY_A;
    } else if (arg_get_lit(ctx, 4)) {
        keyType = MF_KEY_B;
    }

    bool m0 = arg_get_lit(ctx, 6);
    bool m1 = arg_get_lit(ctx, 7);
    bool m2 = arg_get_lit(ctx, 8);
    bool m4 = arg_get_lit(ctx, 9);

    bool transferToEml = arg_get_lit(ctx, 10);
    bool createDumpFile = arg_get_lit(ctx, 11);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 12), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool load_default = ! arg_get_lit(ctx, 13);

    CLIParserFree(ctx);

    bool singleSector = (blockNo > -1);
    if (singleSector == false) {
        // start from first trailer block
        blockNo = 3;
    }

    //validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    }

    size_t sectors_cnt = 1;
    if (m0) {
        sectors_cnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        sectors_cnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        sectors_cnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        sectors_cnt = MIFARE_4K_MAXSECTOR;
    }

    if (singleSector) {

        // find a MIFARE type that can accommodate the provided block number
        size_t min_sectors_cnt = 0;
        uint8_t s =  mfSectorNum(blockNo);

        if (s < MIFARE_MINI_MAXSECTOR) {
            min_sectors_cnt = MIFARE_MINI_MAXSECTOR;
        } else if (s < MIFARE_1K_MAXSECTOR) {
            min_sectors_cnt = MIFARE_1K_MAXSECTOR;
        } else if (s < MIFARE_2K_MAXSECTOR) {
            min_sectors_cnt = MIFARE_2K_MAXSECTOR;
        } else if (s < MIFARE_4K_MAXSECTOR) {
            min_sectors_cnt = MIFARE_4K_MAXSECTOR;
        } else {
            PrintAndLogEx(WARNING, "Provided block out of possible MIFARE Type memory map");
            return PM3_EINVARG;
        }

        if (sectors_cnt == 1) {
            sectors_cnt = min_sectors_cnt;
        } else if (sectors_cnt < min_sectors_cnt) {
            PrintAndLogEx(WARNING, "Provided block out of provided MIFARE Type memory map");
            return PM3_EINVARG;
        }
    }

    if (sectors_cnt == 1) {
        sectors_cnt = MIFARE_1K_MAXSECTOR;
    }

    uint8_t *keyBlock = NULL;
    uint32_t keycnt = 0;
    int ret = mf_load_keys(&keyBlock, &keycnt, key, keylen, filename, fnlen, load_default);
    if (ret != PM3_SUCCESS) {
        return ret;
    }

    uint64_t key64 = 0;

    // create/initialize key storage structure
    sector_t *e_sector = NULL;
    if (initSectorTable(&e_sector, sectors_cnt) != PM3_SUCCESS) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    uint8_t trgKeyType = MF_KEY_A;
    uint16_t max_keys = keycnt > KEYS_IN_BLOCK ? KEYS_IN_BLOCK : keycnt;

    PrintAndLogEx(INFO, "Start check for keys...");
    PrintAndLogEx(INFO, "." NOLF);

    // fast push mode
    g_conn.block_after_ACK = true;

    // clear trace log by first check keys call only
    bool clearLog = true;

    // time
    uint64_t t1 = msclock();

    // check keys.
    for (trgKeyType = (keyType == 2) ? 0 : keyType; trgKeyType < 2; (keyType == 2) ? (++trgKeyType) : (trgKeyType = 2)) {

        // loop sectors but block is used as to keep track of from which blocks to test
        int b = blockNo;
        for (int i = mfSectorNum(b); i < sectors_cnt; ++i) {

            // skip already found keys.
            if (e_sector[i].foundKey[trgKeyType]) continue;

            for (uint32_t c = 0; c < keycnt; c += max_keys) {

                PrintAndLogEx(NORMAL, "." NOLF);
                fflush(stdout);

                if (kbd_enter_pressed()) {
                    PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                    goto out;
                }

                uint32_t size = keycnt - c > max_keys ? max_keys : keycnt - c;

                if (mf_check_keys(b, trgKeyType, clearLog, size, &keyBlock[MIFARE_KEY_SIZE * c], &key64) == PM3_SUCCESS) {
                    e_sector[i].Key[trgKeyType] = key64;
                    e_sector[i].foundKey[trgKeyType] = true;
                    clearLog = false;
                    break;
                }
                clearLog = false;
            }
            if (singleSector)
                break;

            b < 127 ? (b += 4) : (b += 16);
        }
    }
    t1 = msclock() - t1;
    PrintAndLogEx(INFO, "\ntime in checkkeys " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);

    // 20160116 If Sector A is found, but not Sector B,  try just reading it of the tag?
    if (keyType != MF_KEY_B) {
        PrintAndLogEx(INFO, "testing to read key B...");

        // loop sectors but block is used as to keep track of from which blocks to test
        int b = blockNo;
        for (int i = mfSectorNum(b); i < sectors_cnt; i++) {

            // KEY A but not KEY B
            if (e_sector[i].foundKey[0] && !e_sector[i].foundKey[1]) {

                uint8_t sectrail = mfSectorTrailerOfSector(i);
                PrintAndLogEx(INFO, "Sector: %u, First block: %u, Last block: %u, Num of blocks: %u", i, mfFirstBlockOfSector(i), sectrail, mfNumBlocksPerSector(i));
                PrintAndLogEx(INFO, "Reading sector trailer");

                mf_readblock_t payload;
                payload.blockno = sectrail;
                payload.keytype = MF_KEY_A;

                // Use key A
                num_to_bytes(e_sector[i].Key[0], MIFARE_KEY_SIZE, payload.key);

                clearCommandBuffer();
                SendCommandNG(CMD_HF_MIFARE_READBL, (uint8_t *)&payload, sizeof(mf_readblock_t));

                PacketResponseNG resp;
                if (!WaitForResponseTimeout(CMD_HF_MIFARE_READBL, &resp, 1500)) continue;

                if (resp.status != PM3_SUCCESS) continue;

                uint8_t *data = resp.data.asBytes;
                key64 = bytes_to_num(data + 10, MIFARE_KEY_SIZE);
                if (key64) {
                    PrintAndLogEx(NORMAL, "Data:%s", sprint_hex(data + 10, MIFARE_KEY_SIZE));
                    e_sector[i].foundKey[1] = 1;
                    e_sector[i].Key[1] = key64;
                }
            }
            if (singleSector)
                break;
            b < 127 ? (b += 4) : (b += 16);
        }
    }

out:
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, _GREEN_("found keys:"));

    //print keys
//    if (singleSector)
//        printKeyTableEx(1, e_sector, mfSectorNum(blockNo));
//    else
    printKeyTable(sectors_cnt, e_sector);

    if (transferToEml) {
        // fast push mode
        g_conn.block_after_ACK = true;
        uint8_t block[MFBLOCK_SIZE] = {0x00};
        for (int i = 0; i < sectors_cnt; ++i) {
            uint8_t blockno = mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1;
            mf_eml_get_mem(block, blockno, 1);

            if (e_sector[i].foundKey[0])
                num_to_bytes(e_sector[i].Key[0], MIFARE_KEY_SIZE, block);

            if (e_sector[i].foundKey[1])
                num_to_bytes(e_sector[i].Key[1], MIFARE_KEY_SIZE, block + 10);

            if (i == sectors_cnt - 1) {
                // Disable fast mode on last packet
                g_conn.block_after_ACK = false;
            }
            mf_elm_set_mem(block, blockno, 1);
        }
        PrintAndLogEx(SUCCESS, "Found keys have been transferred to the emulator memory");
    }

    if (createDumpFile) {
        char *fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (createMfcKeyDump(fptr, sectors_cnt, e_sector) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "Failed to save keys to file");
        }
        free(fptr);
    }

    free(keyBlock);
    free(e_sector);

    // Disable fast mode and send a dummy command to make it effective
    g_conn.block_after_ACK = false;
    SendCommandNG(CMD_PING, NULL, 0);
    if (!WaitForResponseTimeout(CMD_PING, NULL, 1000)) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

void showSectorTable(sector_t *k_sector, size_t k_sectors_cnt) {
    if (k_sector != NULL) {
        printKeyTable(k_sectors_cnt, k_sector);
        free(k_sector);
    }
}

void readerAttack(sector_t *k_sector, size_t k_sectors_cnt, nonces_t data, bool setEmulatorMem, bool verbose) {

    // init if needed
    if (k_sector == NULL) {
        if (initSectorTable(&k_sector, k_sectors_cnt) != PM3_SUCCESS) {
            return;
        }
    }

    uint64_t key = 0;
    bool found = false;
    if ((nonce_state)data.state == SECOND) {
        found = mfkey32_moebius(&data, &key);
    } else if ((nonce_state)data.state == NESTED) {
        found = mfkey32_nested(&data, &key);
    }
    if (found) {
        uint8_t sector = data.sector;
        uint8_t keytype = data.keytype;

        PrintAndLogEx(INFO, "Reader is trying authenticate with: Key %s, sector %02d: [%012" PRIx64 "]"
                      , (keytype == MF_KEY_B) ? "B" : "A"
                      , sector
                      , key
                     );

        k_sector[sector].Key[keytype] = key;
        k_sector[sector].foundKey[keytype] = true;

        //set emulator memory for keys
        if (setEmulatorMem) {
            uint8_t memBlock[16];
            mf_eml_get_mem(memBlock, (sector * 4) + 3, 1);
            if ((memBlock[6] == 0) && (memBlock[7] == 0) && (memBlock[8] == 0)) {
                // ACL not yet set?
                memBlock[6] = 0xFF;
                memBlock[7] = 0x07;
                memBlock[8] = 0x80;
            }
            num_to_bytes(k_sector[sector].Key[keytype], 6, memBlock + ((keytype == MF_KEY_B) ? 10 : 0));
            //iceman,  guessing this will not work so well for 4K tags.
            PrintAndLogEx(INFO, "Setting Emulator Memory Block %02d: [%s]"
                          , (sector * 4) + 3
                          , sprint_hex(memBlock, sizeof(memBlock))
                         );
            mf_elm_set_mem(memBlock, (sector * 4) + 3, 1);
        }
    }

    free(k_sector);
}

static int CmdHF14AMfSim(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf sim",
                  "Simulate MIFARE Classic family type based upon\n"
                  "ISO/IEC 14443 type A tag with 4,7 or 10 byte UID\n"
                  "from emulator memory.  See `hf mf eload` first.\n"
                  "The UID from emulator memory will be used if not specified.",
                  "hf mf sim --mini                    --> MIFARE Mini\n"
                  "hf mf sim --1k                      --> MIFARE Classic 1k (default)\n"
                  "hf mf sim --1k -u 0a0a0a0a          --> MIFARE Classic 1k with 4b UID\n"
                  "hf mf sim --1k -u 11223344556677    --> MIFARE Classic 1k with 7b UID\n"
                  "hf mf sim --1k -u 11223344 -i -x    --> Perform reader attack in interactive mode\n"
                  "hf mf sim --2k                      --> MIFARE 2k\n"
                  "hf mf sim --4k                      --> MIFARE 4k"
                  "hf mf sim --1k -x -e                --> Keep simulation running and populate with found reader keys\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "<4|7|10> hex bytes UID"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_str0(NULL, "atqa", "<hex>", "Provide explicit ATQA (2 bytes)"),
        arg_str0(NULL, "sak", "<hex>", "Provide explicit SAK (1 bytes)"),
        arg_int0("n", "num", "<dec> ", "Automatically exit simulation after <numreads> blocks have been read by reader. 0 = infinite"),
        arg_lit0("i", "interactive", "Console will not be returned until simulation finishes or is aborted"),
        arg_lit0("x", NULL, "Performs the 'reader attack', nr/ar attack against a reader."),
        arg_lit0("y", NULL, "Performs the nested 'reader attack'. This requires preloading nt & nt_enc in emulator memory. Implies -x."),
        arg_lit0("e", "emukeys", "Fill simulator keys from found keys. Requires -x or -y. Implies -i. Simulation will restart automatically."),
        // If access bits show that key B is Readable, any subsequent memory access should be refused.
        arg_lit0(NULL, "allowkeyb", "Allow key B even if readable"),
        arg_lit0("v", "verbose", "Verbose output"),
        arg_lit0(NULL, "cve", "Trigger CVE 2021_0430"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint16_t flags = 0;

    int uidlen = 0;
    uint8_t uid[10] = {0};
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);

    if (uidlen > 0) {
        FLAG_SET_UID_IN_DATA(flags, uidlen);
        if (IS_FLAG_UID_IN_EMUL(flags)) {
            PrintAndLogEx(WARNING, "Invalid parameter for UID");
            CLIParserFree(ctx);
            return PM3_EINVARG;
        }
    }

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);

    int atqalen = 0;
    uint8_t atqa[2] = {0};
    CLIGetHexWithReturn(ctx, 6, atqa, &atqalen);

    int saklen = 0;
    uint8_t sak[1] = {0};
    CLIGetHexWithReturn(ctx, 7, sak, &saklen);

    uint8_t exitAfterNReads = arg_get_u32_def(ctx, 8, 0);

    if (arg_get_lit(ctx, 9)) {
        flags |= FLAG_INTERACTIVE;
    }

    if (arg_get_lit(ctx, 10)) {
        flags |= FLAG_NR_AR_ATTACK;
    }

    if (arg_get_lit(ctx, 11)) {
        flags |= FLAG_NESTED_AUTH_ATTACK;
    }

    bool setEmulatorMem = arg_get_lit(ctx, 12);

    if (arg_get_lit(ctx, 13)) {
        flags |= FLAG_MF_USE_READ_KEYB;
    }

    bool verbose = arg_get_lit(ctx, 14);

    if (arg_get_lit(ctx, 15)) {
        flags |= FLAG_CVE21_0430;
    }
    CLIParserFree(ctx);

    //Validations
    if (atqalen > 0) {
        if (atqalen != 2) {
            PrintAndLogEx(WARNING, "Wrong ATQA length");
            return PM3_EINVARG;
        }
        flags |= FLAG_ATQA_IN_DATA;
    }

    if (saklen > 0) {
        if (saklen != 1) {
            PrintAndLogEx(WARNING, "Wrong SAK length");
            return PM3_EINVARG;
        }
        flags |= FLAG_SAK_IN_DATA;
    }

    size_t k_sectors_cnt = MIFARE_4K_MAXSECTOR;
    char csize[13] = { 0 };

    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    }

    if (m0) {
        FLAG_SET_MF_SIZE(flags, MIFARE_MINI_MAX_BYTES);
        snprintf(csize, sizeof(csize), "MINI");
        k_sectors_cnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        FLAG_SET_MF_SIZE(flags, MIFARE_1K_MAX_BYTES);
        snprintf(csize, sizeof(csize), "1K");
        k_sectors_cnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        FLAG_SET_MF_SIZE(flags, MIFARE_2K_MAX_BYTES);
        snprintf(csize, sizeof(csize), "2K with RATS");
        k_sectors_cnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        FLAG_SET_MF_SIZE(flags, MIFARE_4K_MAX_BYTES);
        snprintf(csize, sizeof(csize), "4K");
        k_sectors_cnt = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    if ((flags & FLAG_NESTED_AUTH_ATTACK) == FLAG_NESTED_AUTH_ATTACK) {
        if ((flags & FLAG_NR_AR_ATTACK) != FLAG_NR_AR_ATTACK) {
            PrintAndLogEx(INFO, "Note: option -y implies -x");
            flags |= FLAG_NR_AR_ATTACK;
        }
    }

    if (setEmulatorMem) {
        if ((flags & FLAG_INTERACTIVE) != FLAG_INTERACTIVE) {
            PrintAndLogEx(INFO, "Note: option -e implies -i");
            flags |= FLAG_INTERACTIVE;
        }
        if ((flags & FLAG_NR_AR_ATTACK) != FLAG_NR_AR_ATTACK) {
            PrintAndLogEx(WARNING, "Option -e requires -x or -y");
            return PM3_EINVARG;
        }
    }

    PrintAndLogEx(INFO, _YELLOW_("MIFARE %s") " | %i bytes UID  " _YELLOW_("%s") ""
                  , csize
                  , uidlen
                  , (uidlen == 0) ? "n/a" : sprint_hex(uid, uidlen)
                 );

    PrintAndLogEx(INFO, "Options [ numreads: %d, flags: 0x%04x ]"
                  , exitAfterNReads
                  , flags);

    struct {
        uint16_t flags;
        uint8_t exitAfter;
        uint8_t uid[10];
        uint16_t atqa;
        uint8_t sak;
    } PACKED payload;

    payload.flags = flags;
    payload.exitAfter = exitAfterNReads;
    memcpy(payload.uid, uid, uidlen);
    payload.atqa = (atqa[1] << 8) | atqa[0];
    payload.sak = sak[0];

    clearCommandBuffer();

    if (flags & FLAG_INTERACTIVE) {
        PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or a key to abort simulation");
    } else {
        PrintAndLogEx(INFO, "Press " _GREEN_("pm3 button") " or send another cmd to abort simulation");
    }
    bool cont;
    do {
        cont = false;
        SendCommandNG(CMD_HF_MIFARE_SIMULATE, (uint8_t *)&payload, sizeof(payload));
        if (flags & FLAG_INTERACTIVE) {
            PacketResponseNG resp;
            sector_t *k_sector = NULL;

            bool keypress = kbd_enter_pressed();
            while (keypress == false) {

                if (WaitForResponseTimeout(CMD_HF_MIFARE_SIMULATE, &resp, 1500) == 0) {
                    keypress = kbd_enter_pressed();
                    continue;
                }

                if (resp.status != PM3_SUCCESS)
                    break;

                if ((flags & FLAG_NR_AR_ATTACK) != FLAG_NR_AR_ATTACK)
                    break;

                const nonces_t *data = (nonces_t *)resp.data.asBytes;
                readerAttack(k_sector, k_sectors_cnt, data[0], setEmulatorMem, verbose);
                if (setEmulatorMem) {
                    cont = true;
                }
                break;
            }
            if (keypress) {
                if ((flags & FLAG_NR_AR_ATTACK) == FLAG_NR_AR_ATTACK) {
                    // inform device to break the sim loop since client has exited
                    PrintAndLogEx(INFO, "Key pressed, please wait a few seconds for the pm3 to stop...");
                    SendCommandNG(CMD_BREAK_LOOP, NULL, 0);
                }
            }
        }

    } while (cont);
    return PM3_SUCCESS;
}

/*
static int CmdHF14AMfKeyBrute(const char *Cmd) {

    uint8_t blockNo = 0, keytype = MF_KEY_A;
    uint8_t key[6] = {0, 0, 0, 0, 0, 0};
    uint64_t foundkey = 0;

    char cmdp = tolower(param_getchar(Cmd, 0));
    if (cmdp == 'h') return usage_hf14_keybrute();

    // block number
    blockNo = param_get8(Cmd, 0);

    // keytype
    cmdp = tolower(param_getchar(Cmd, 1));
    if (cmdp == 'b') keytype = MF_KEY_B;

    // key
    int keylen = 0;
    if (param_gethex_ex(Cmd, 2, key, &keylen) && (keylen != 12)) {
        return usage_hf14_keybrute();
    }

    uint64_t t1 = msclock();

    if (mfKeyBrute(blockNo, keytype, key, &foundkey))
        PrintAndLogEx(SUCCESS, "found valid key: %012" PRIx64 " \n", foundkey);
    else
        PrintAndLogEx(FAILED, "key not found");

    t1 = msclock() - t1;
    PrintAndLogEx(SUCCESS, "\ntime in keybrute " _YELLOW_("%.0f") " seconds\n", (float)t1 / 1000.0);
    return PM3_SUCCESS;
}
*/

void printKeyTable(size_t sectorscnt, sector_t *e_sector) {
    printKeyTableEx(sectorscnt, e_sector, 0);
}

void printKeyTableEx(size_t sectorscnt, sector_t *e_sector, uint8_t start_sector) {
    char strA[26 + 1] = {0};
    char strB[26 + 1] = {0};
    char resA[20 + 1] = {0};
    char resB[20 + 1] = {0};

    uint64_t ndef_key = 0xD3F7D3F7D3F7;
    bool has_ndef_key = false;
    bool extended_legend = false;

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "-----+-----+--------------+---+--------------+----");
    PrintAndLogEx(SUCCESS, " Sec | Blk | key A        |res| key B        |res");
    PrintAndLogEx(SUCCESS, "-----+-----+--------------+---+--------------+----");

    for (size_t i = 0; i < sectorscnt; i++) {

        if ((e_sector[i].foundKey[0] > 1) || (e_sector[i].foundKey[1] > 1)) {
            extended_legend = true;
        }

        if (e_sector[i].Key[0] == ndef_key || e_sector[i].Key[1] == ndef_key) {
            has_ndef_key = true;
        }

        if (e_sector[i].foundKey[0]) {
            snprintf(strA, sizeof(strA), _GREEN_("%012" PRIX64), e_sector[i].Key[0]);
            if (extended_legend) {
                snprintf(resA, sizeof(resA), _BRIGHT_GREEN_("%c"), e_sector[i].foundKey[0]);
            } else {
                snprintf(resA, sizeof(resA), _BRIGHT_GREEN_("%d"), e_sector[i].foundKey[0]);
            }
        } else {
            snprintf(strA, sizeof(strA), _RED_("%s"), "------------");
            snprintf(resA, sizeof(resA), _RED_("0"));
        }

        if (e_sector[i].foundKey[1]) {
            snprintf(strB, sizeof(strB), _GREEN_("%012" PRIX64), e_sector[i].Key[1]);
            if (extended_legend) {
                snprintf(resB, sizeof(resB), _BRIGHT_GREEN_("%c"), e_sector[i].foundKey[1]);
            } else {
                snprintf(resB, sizeof(resB), _BRIGHT_GREEN_("%d"), e_sector[i].foundKey[1]);
            }
        } else {
            snprintf(strB, sizeof(strB), _RED_("%s"), "------------");
            snprintf(resB, sizeof(resB), _RED_("0"));
        }

        // keep track if we use start_sector or i
        // show one sector or all.
        uint8_t s = start_sector;
        if (start_sector == 0) {
            s = i;
        }

        char extra[24] = {0x00};
        if (sectorscnt == 18 && i > 15) {
            strcat(extra, "( " _MAGENTA_("*") " )");
        }

        PrintAndLogEx(SUCCESS, " " _YELLOW_("%03d") " | %03d | %s | %s | %s | %s %s"
                      , s
                      , mfSectorTrailerOfSector(s)
                      , strA, resA
                      , strB, resB
                      , extra
                     );
    }

    PrintAndLogEx(SUCCESS, "-----+-----+--------------+---+--------------+----");

    if (extended_legend) {
        PrintAndLogEx(INFO, "( "
                      _YELLOW_("D") ":Dictionary / "
                      _YELLOW_("S") ":darkSide / "
                      _YELLOW_("U") ":User / "
                      _YELLOW_("R") ":Reused / "
                      _YELLOW_("N") ":Nested / "
                      _YELLOW_("H") ":Hardnested / "
                      _YELLOW_("C") ":statiCnested / "
                      _YELLOW_("A") ":keyA "
                      " )"
                     );
        if (sectorscnt == 18) {
            PrintAndLogEx(INFO, "( " _MAGENTA_("*") " ) These sectors used for signature. Lays outside of user memory");
        }

    } else {
        PrintAndLogEx(SUCCESS, "( " _RED_("0") ":Failed / " _GREEN_("1") ":Success )");
    }

    // MAD detection
    if (e_sector[MF_MAD1_SECTOR].foundKey[0] && e_sector[MF_MAD1_SECTOR].Key[0] == 0xA0A1A2A3A4A5) {
        PrintAndLogEx(HINT, "MAD key detected. Try " _YELLOW_("`hf mf mad`") " for more details");
    }
    // NDEF detection
    if (has_ndef_key) {
        PrintAndLogEx(HINT, "NDEF key detected. Try " _YELLOW_("`hf mf ndefread`") " for more details");
    }
    PrintAndLogEx(NORMAL, "");
}


// EMULATOR COMMANDS
static int CmdHF14AMfEGetBlk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf egetblk",
                  "Get emulator memory block",
                  "hf mf egetblk --blk 0      -> get block 0 (manufacturer)\n"
                  "hf mf egetblk --blk 3 -v   -> get block 3, decode sector trailer\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b",  "blk", "<dec>", "block number"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int b = arg_get_int_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (b > 255) {
        return PM3_EINVARG;
    }
    uint8_t blockno = (uint8_t)b;

    uint8_t data[16] = {0x00};
    if (mf_eml_get_mem(data, blockno, 1) == PM3_SUCCESS) {

        uint8_t sector = mfSectorNum(blockno);
        mf_print_sector_hdr(sector);
        mf_print_block_one(blockno, data, verbose);
    }
    if (verbose) {
        decode_print_st(blockno, data);
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfEGetSc(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf egetsc",
                  "Get emulator memory sector",
                  "hf mf egetsc -s 0"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("s",  "sec", "<dec>", "sector number"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int s = arg_get_int_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    if (s >= MIFARE_4K_MAXSECTOR) {
        PrintAndLogEx(WARNING, "Sector number must be less than 40");
        return PM3_EINVARG;
    }

    uint8_t sector = (uint8_t)s;
    mf_print_sector_hdr(sector);

    uint8_t blocks = mfNumBlocksPerSector(sector);
    uint8_t start = mfFirstBlockOfSector(sector);

    uint8_t data[16] = {0};
    for (int i = 0; i < blocks; i++) {
        int res = mf_eml_get_mem(data, start + i, 1);
        if (res == PM3_SUCCESS) {
            mf_print_block_one(start + i, data, verbose);
        }
    }
    if (verbose) {
        decode_print_st(start + blocks - 1, data);
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfEClear(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf eclr",
                  "It set card emulator memory to empty data blocks and key A/B FFFFFFFFFFFF",
                  "hf mf eclr"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_EML_MEMCLR, NULL, 0);
    return PM3_SUCCESS;
}

static int CmdHF14AMfESet(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf esetblk",
                  "Set emulator memory block",
                  "hf mf esetblk --blk 1 -d 000102030405060708090a0b0c0d0e0f"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "blk", "<dec>", "block number"),
        arg_str0("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int b = arg_get_int_def(ctx, 1, 0);

    uint8_t data[16] = {0x00};
    int datalen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), data, sizeof(data), &datalen);
    CLIParserFree(ctx);
    if (res) {
        PrintAndLogEx(FAILED, "Error parsing bytes");
        return PM3_EINVARG;
    }

    if (b > 255) {
        return PM3_EINVARG;
    }

    if (datalen != sizeof(data)) {
        PrintAndLogEx(WARNING, "block data must include 16 HEX bytes. Got %i", datalen);
        return PM3_EINVARG;
    }

    //  1 - blocks count
    return mf_elm_set_mem(data, b, 1);
}

int CmdHF14AMfELoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf eload",
                  "Load emulator memory with data from (bin/eml/json) dump file",
                  "hf mf eload -f hf-mf-01020304.bin\n"
                  "hf mf eload --4k -f hf-mf-01020304.eml\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "ul", "MIFARE Ultralight family"),
        arg_lit0("m", "mem",  "use RDV4 spiffs"),
        arg_int0("q", "qty", "<dec>", "manually set number of blocks (overrides)"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);
    bool mu = arg_get_lit(ctx, 6);

    bool use_spiffs = arg_get_lit(ctx, 7);
    int numblks = arg_get_int_def(ctx, 8, -1);
    bool verbose = arg_get_lit(ctx, 9);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4 + mu) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4 + mu) == 0) {
        m1 = true;
    }

    uint8_t block_width = 16;
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    uint8_t hdr_len = 0;

    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
    } else if (mu) {
        block_cnt = MFU_MAX_BLOCKS;
        block_width = MFU_BLOCK_SIZE;
        hdr_len = MFU_DUMP_PREFIX_LENGTH;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Upload " _YELLOW_("%u") " blocks " _YELLOW_("%u") " bytes", block_cnt, block_cnt * block_width);

    if (numblks > 0) {
        block_cnt = MIN(numblks, block_cnt);
        PrintAndLogEx(INFO, "overriding number of blocks, will use " _YELLOW_("%u") " blocks " _YELLOW_("%u") " bytes", block_cnt, block_cnt * block_width);
    }

    // ICEMAN:  bug.  if device has been using ICLASS commands,
    // the device needs to load the HF fpga image. It takes 1.5 second.
    set_fpga_mode(FPGA_BITSTREAM_HF);

    // use RDV4 spiffs
    if (use_spiffs && IfPm3Flash() == false) {
        PrintAndLogEx(WARNING, "Device not compiled to support spiffs");
        return PM3_EINVARG;
    }

    if (use_spiffs) {

        if (fnlen > 32) {
            PrintAndLogEx(WARNING, "filename too long for spiffs, expected 32, got %u", fnlen);
            return PM3_EINVARG;
        }

        clearCommandBuffer();
        SendCommandNG(CMD_SPIFFS_ELOAD, (uint8_t *)filename, fnlen);
        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_SPIFFS_ELOAD, &resp, 2000) == false) {
            PrintAndLogEx(WARNING, "timeout while waiting for reply.");
            return PM3_ETIMEOUT;
        }

        if (resp.status != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Loading file from spiffs to emulator memory failed");
            return PM3_EFLASH;
        }

        PrintAndLogEx(SUCCESS, "File transfered from spiffs to device emulator memory");
        return PM3_SUCCESS;
    }

    uint8_t *data = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&data, &bytes_read, (block_width * block_cnt + hdr_len));
    if (res != PM3_SUCCESS) {
        return res;
    }

    // 64 or 256 blocks.
    if ((bytes_read % block_width) != 0) {
        PrintAndLogEx(FAILED, "File content error. Size doesn't match blockwidth ");
        free(data);
        return PM3_ESOFT;
    }

    // convert plain or old mfu format to new format
    if (block_width == MFU_BLOCK_SIZE) {
        res = convert_mfu_dump_format(&data, &bytes_read, true);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Failed convert on load to new Ultralight/NTAG format");
            free(data);
            return res;
        }

        if (verbose) {
            mfu_dump_t *mfu_dump = (mfu_dump_t *)data;
            mfu_print_dump(mfu_dump, mfu_dump->pages + 1, 0, false);
        }

        // update expected blocks to match converted data.
        block_cnt = bytes_read / MFU_BLOCK_SIZE;
        PrintAndLogEx(INFO, "MIFARE Ultralight override, will use %d blocks ( %u bytes )", block_cnt, block_cnt * block_width);
    }

    PrintAndLogEx(INFO, "Uploading to emulator memory");
    PrintAndLogEx(INFO, "." NOLF);

    // fast push mode
    g_conn.block_after_ACK = true;

    size_t offset = 0;
    int cnt = 0;

    // 12 is the size of the struct the fct mf_eml_set_mem_xt uses to transfer to device
    uint16_t max_avail_blocks = ((PM3_CMD_DATA_SIZE - 12) / block_width) * block_width;

    while (bytes_read && cnt < block_cnt) {
        if (bytes_read == block_width) {
            // Disable fast mode on last packet
            g_conn.block_after_ACK = false;
        }

        uint16_t chunk_size = MIN(max_avail_blocks, bytes_read);
        uint16_t blocks_to_send = chunk_size / block_width;

        if (mf_eml_set_mem_xt(data + offset, cnt, blocks_to_send, block_width) != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Can't set emulator mem at block: %3d", cnt);
            free(data);
            return PM3_ESOFT;
        }
        cnt += blocks_to_send;
        offset += chunk_size;
        bytes_read -= chunk_size;
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    free(data);
    PrintAndLogEx(NORMAL, "");

    if (block_width == MFU_BLOCK_SIZE) {
        PrintAndLogEx(HINT, "You are ready to simulate. See " _YELLOW_("`hf mfu sim -h`"));
        // MFU / NTAG
        if ((cnt != block_cnt)) {
            PrintAndLogEx(WARNING, "Warning, Ultralight/Ntag file content, Loaded %d blocks of expected %d blocks into emulator memory", cnt, block_cnt);
            return PM3_SUCCESS;
        }
    } else {
        PrintAndLogEx(HINT, "You are ready to simulate. See " _YELLOW_("`hf mf sim -h`"));
        // MFC
        if ((cnt != block_cnt)) {
            PrintAndLogEx(WARNING, "Error, file content, Only loaded %d blocks, must be %d blocks into emulator memory", cnt, block_cnt);
            return PM3_SUCCESS;
        }
        PrintAndLogEx(INFO, "Done!");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfESave(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf esave",
                  "Save emulator memory to file (bin/json) ",
                  "hf mf esave\n"
                  "hf mf esave --4k\n"
                  "hf mf esave --4k -f hf-mf-01020304.eml"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;

    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
    }

    int bytes = block_cnt * MFBLOCK_SIZE;

    // reserv memory
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }
    memset(dump, 0, bytes);

    PrintAndLogEx(INFO, "downloading %u bytes from emulator memory", bytes);
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    // user supplied filename?
    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(fptr, sizeof(filename), "hf-mf-");
        FillFileNameByUID(fptr, dump, "-dump", 4);
    }

    pm3_save_mf_dump(filename, dump, bytes, jsfCardMemory);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfEView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf eview",
                  "It displays emulator memory",
                  "hf mf eview\n"
                  "hf mf eview --4k"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "sk", "Save extracted keys to binary file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m4 = arg_get_lit(ctx, 4);
    bool verbose = arg_get_lit(ctx, 5);
    bool save_keys = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;

    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    int bytes = block_cnt * MFBLOCK_SIZE;

    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(INFO, "downloading emulator memory");
    if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
        PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
        free(dump);
        return PM3_ETIMEOUT;
    }

    mf_print_blocks(block_cnt, dump, verbose);

    if (verbose) {
        mf_print_keys(block_cnt, dump);
    }

    if (save_keys) {
        mf_save_keys_from_arr(block_cnt, dump);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfECFill(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ecfill",
                  "Dump card and transfer the data to emulator memory.\n"
                  "Keys must be in the emulator memory",
                  "hf mf ecfill          --> use key type A\n"
                  "hf mf ecfill --4k -b  --> target 4K card with key type B"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", NULL, "input key type is key A(def)"),
        arg_lit0("b", NULL, "input key type is key B"),
        arg_int0("c", NULL, "<dec>", "input key type is key A + offset"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes, only for option -c"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 1) && arg_get_lit(ctx, 2)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 2)) {
        keytype = MF_KEY_B;
    }
    uint8_t prev_keytype = keytype;
    keytype = arg_get_int_def(ctx, 3, keytype);
    if ((arg_get_lit(ctx, 1) || arg_get_lit(ctx, 2)) && (keytype != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    }
    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 4, key, &keylen);
    if ((keytype > MF_KEY_B) && (keylen != 6)) {
        PrintAndLogEx(WARNING, "Missing key");
        return PM3_EINVARG;
    }
    if ((keytype <= MF_KEY_B) && (keylen > 0)) {
        PrintAndLogEx(WARNING, "Ignoring provided key");
    }

    bool m0 = arg_get_lit(ctx, 5);
    bool m1 = arg_get_lit(ctx, 6);
    bool m2 = arg_get_lit(ctx, 7);
    bool m4 = arg_get_lit(ctx, 8);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t sectors_cnt = MIFARE_1K_MAXSECTOR;

    if (m0) {
        sectors_cnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        sectors_cnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        sectors_cnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        sectors_cnt = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    mfc_eload_t payload = {
        .sectorcnt = sectors_cnt,
        .keytype = keytype
    };
    memcpy(payload.key, key, sizeof(payload.key));

    clearCommandBuffer();
    uint64_t t1 = msclock();
    SendCommandNG(CMD_HF_MIFARE_EML_LOAD, (uint8_t *)&payload, sizeof(payload));

    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_EML_LOAD, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }
    t1 = msclock() - t1;

    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Fill ( " _GREEN_("ok") " ) in " _YELLOW_("%" PRIu64) " ms", t1);
    else
        PrintAndLogEx(FAILED, "Fill ( " _RED_("fail") " )");

    return resp.status;
}

static int CmdHF14AMfEKeyPrn(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ekeyprn",
                  "Download and print the keys from emulator memory",
                  "hf mf ekeyprn --1k --> print MFC 1K keyset\n"
                  "hf mf ekeyprn -w   --> write keys to binary file"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("w", "write", "write keys to binary file `hf-mf-<UID>-key.bin`"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool create_dumpfile = arg_get_lit(ctx, 1);
    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    size_t sectors_cnt = MIFARE_1K_MAXSECTOR;

    if (m0) {
        sectors_cnt = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        sectors_cnt = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        sectors_cnt = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        sectors_cnt = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    // create/initialize key storage structure
    sector_t *e_sector = NULL;
    if (initSectorTable(&e_sector, sectors_cnt) != PM3_SUCCESS) {
        return PM3_EMALLOC;
    }

    // read UID from EMUL
    uint8_t data[16];
    if (mf_eml_get_mem(data, 0, 1) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "error get block 0");
        free(e_sector);
        return PM3_ESOFT;
    }

    // assuming 4byte UID.
    uint8_t uid[4];
    memcpy(uid, data, sizeof(uid));

    // download keys from EMUL
    for (int i = 0; i < sectors_cnt; i++) {

        if (mf_eml_get_mem(data, mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1, 1) != PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "error get block %d", mfFirstBlockOfSector(i) + mfNumBlocksPerSector(i) - 1);
            e_sector[i].foundKey[0] = false;
            e_sector[i].foundKey[1] = false;
        } else {
            e_sector[i].foundKey[0] = true;
            e_sector[i].Key[0] = bytes_to_num(data, 6);
            e_sector[i].foundKey[1] = true;
            e_sector[i].Key[1] = bytes_to_num(data + 10, 6);
        }
    }

    // print keys
    printKeyTable(sectors_cnt, e_sector);

    // dump the keys
    if (create_dumpfile) {

        char filename[FILE_PATH_SIZE] = {0};
        char *fptr = filename;
        fptr += snprintf(fptr, sizeof(filename), "hf-mf-");
        FillFileNameByUID(fptr + strlen(fptr), uid, "-key", sizeof(uid));
        createMfcKeyDump(filename, sectors_cnt, e_sector);
    }

    free(e_sector);
    return PM3_SUCCESS;
}

// CHINESE MAGIC COMMANDS
static int CmdHF14AMfCSetUID(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf csetuid",
                  "Set UID, ATQA, and SAK for magic gen1a card",
                  "hf mf csetuid -u 01020304\n"
                  "hf mf csetuid -w -u 01020304 --atqa 0004 --sak 08"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("w", "wipe", "wipes card with backdoor cmd`"),
        arg_str0("u", "uid",  "<hex>", "UID, 4/7 hex bytes"),
        arg_str0("a", "atqa", "<hex>", "ATQA, 2 hex bytes"),
        arg_str0("s", "sak",  "<hex>", "SAK, 1 hex byte"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t wipe_card = arg_get_lit(ctx, 1);

    int uidlen = 0;
    uint8_t uid[7] = {0x00};
    CLIGetHexWithReturn(ctx, 2, uid, &uidlen);

    int alen = 0;
    uint8_t atqa[2] = {0x00};
    CLIGetHexWithReturn(ctx, 3, atqa, &alen);

    int slen = 0;
    uint8_t sak[1] = {0x00};
    CLIGetHexWithReturn(ctx, 4, sak, &slen);
    uint8_t gdm = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // sanity checks
    if (uidlen != 4 && uidlen != 7) {
        PrintAndLogEx(FAILED, "UID must be 4 or 7 hex bytes. Got %d", uidlen);
        return PM3_EINVARG;
    }
    if (alen && alen != 2) {
        PrintAndLogEx(FAILED, "ATQA must be 2 hex bytes. Got %d", alen);
        return PM3_EINVARG;
    }
    if (slen && slen != 1) {
        PrintAndLogEx(FAILED, "SAK must be 1 hex byte. Got %d", slen);
        return PM3_EINVARG;
    }

    uint8_t old_uid[7] = {0};
    uint8_t verify_uid[7] = {0};

    int res = mf_chinese_set_uid(
                  uid,
                  uidlen,
                  (alen) ? atqa : NULL,
                  (slen) ? sak : NULL,
                  old_uid,
                  verify_uid,
                  wipe_card,
                  gdm
              );

    if (res) {
        PrintAndLogEx(ERR, "Can't set UID. error %d", res);
        return PM3_ESOFT;
    }

    res = memcmp(uid, verify_uid, uidlen);

    PrintAndLogEx(SUCCESS, "Old UID... %s", sprint_hex(old_uid, uidlen));
    PrintAndLogEx(SUCCESS, "New UID... %s ( %s )",
                  sprint_hex(verify_uid, uidlen),
                  (res == 0) ? _GREEN_("verified") : _RED_("fail")
                 );
    return PM3_SUCCESS;
}

static int CmdHF14AMfCWipe(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf cwipe",
                  "Wipe gen1 magic chinese card.\n"
                  "Set UID / ATQA / SAK / Data / Keys / Access to default values",
                  "hf mf cwipe\n"
                  "hf mf cwipe -u 09080706 -a 0004 -s 18 --> set UID, ATQA and SAK and wipe card");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid",  "<hex>", "UID, 4 hex bytes"),
        arg_str0("a", "atqa", "<hex>", "ATQA, 2 hex bytes"),
        arg_str0("s", "sak",  "<hex>", "SAK, 1 hex byte"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);

    int uidlen = 0;
    uint8_t uid[8] = {0x00};
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);

    int alen = 0;
    uint8_t atqa[2] = {0x00};
    CLIGetHexWithReturn(ctx, 2, atqa, &alen);

    int slen = 0;
    uint8_t sak[1] = {0x00};
    CLIGetHexWithReturn(ctx, 3, sak, &slen);
    uint8_t gdm = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (uidlen && uidlen != 4) {
        PrintAndLogEx(ERR, "UID length must be 4 bytes, got %d", uidlen);
        return PM3_EINVARG;
    }
    if (alen && alen != 2) {
        PrintAndLogEx(ERR, "ATQA length must be 2 bytes, got %d", alen);
        return PM3_EINVARG;
    }
    if (slen && slen != 1) {
        PrintAndLogEx(ERR, "SAK length must be 1 byte, got %d", slen);
        return PM3_EINVARG;
    }

    int res = mf_chinese_wipe((uidlen) ? uid : NULL, (alen) ? atqa : NULL, (slen) ? sak : NULL, gdm);
    if (res) {
        PrintAndLogEx(ERR, "Can't wipe card. error %d", res);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Card wiped successfully");
    return PM3_SUCCESS;
}

static int CmdHF14AMfCSetBlk(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf csetblk",
                  "Set block data on a magic gen1a card",
                  "hf mf csetblk --blk 1 -d 000102030405060708090a0b0c0d0e0f"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "blk", "<dec>", "block number"),
        arg_str0("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_lit0("w", "wipe", "wipes card with backdoor cmd before writing"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int b = arg_get_int_def(ctx, 1, -1);

    uint8_t data[MFBLOCK_SIZE] = {0x00};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 2, data, &datalen);

    uint8_t wipe_card = arg_get_lit(ctx, 3);
    uint8_t gdm = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (b < 0 ||  b >= MIFARE_1K_MAXBLOCK) {
        PrintAndLogEx(FAILED, "target block number out-of-range, got %i", b);
        return PM3_EINVARG;
    }

    if (datalen != MFBLOCK_SIZE) {
        PrintAndLogEx(FAILED, "expected 16 bytes data, got %i", datalen);
        return PM3_EINVARG;
    }

    uint8_t params = MAGIC_SINGLE;
    if (gdm) {
        params |= MAGIC_GDM_ALT_WUPC;
    } else {
        params |= MAGIC_WUPC;
    }

    if (wipe_card) {
        params |= MAGIC_WIPE;
    }

    PrintAndLogEx(INFO, "Writing block number:%2d data:%s", b, sprint_hex_inrow(data, sizeof(data)));

    int res = mf_chinese_set_block(b, data, NULL, params);
    if (res) {
        PrintAndLogEx(ERR, "Can't write block. error=%d", res);
        return PM3_ESOFT;
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfCLoad(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf cload",
                  "Load magic gen1a card with data from (bin/eml/json) dump file\n"
                  "or from emulator memory.",
                  "hf mf cload --emu\n"
                  "hf mf cload -f hf-mf-01020304.eml\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k",   "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "1k+",  "MIFARE Classic Ev1 1k / S50"),
        arg_lit0(NULL, "2k",   "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k",   "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "emu",  "from emulator memory"),
        arg_lit0(NULL, "gdm",  "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m1ev1 = arg_get_lit(ctx, 4);
    bool m2 = arg_get_lit(ctx, 5);
    bool m4 = arg_get_lit(ctx, 6);
    bool fill_from_emulator = arg_get_lit(ctx, 7);
    bool gdm = arg_get_lit(ctx, 8);

    CLIParserFree(ctx);

    if ((m0 + m1 + m2 + m4 + m1ev1) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4 + m1ev1) == 0) {
        m1 = true;
    }

    char s[8];
    memset(s, 0, sizeof(s));
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
        strncpy(s, "Mini", 5);
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
        strncpy(s, "1K", 3);
    } else if (m1ev1) {
        block_cnt = MIFARE_1K_EV1_MAXBLOCK;
        strncpy(s, "1K Ev1", 7);
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
        strncpy(s, "2K", 3);
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
        strncpy(s, "4K", 3);
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    if (m1ev1) {
        PrintAndLogEx(INFO, "Normally only a GDM / UMC card will handle the extra sectors");
    }

    if (fill_from_emulator) {

        PrintAndLogEx(INFO, "Start upload from emulator memory");
        PrintAndLogEx(INFO, "." NOLF);

        for (int b = 0; b < block_cnt; b++) {
            int flags = 0;
            uint8_t buf8[MFBLOCK_SIZE] = {0x00};

            // read from emul memory
            if (mf_eml_get_mem(buf8, b, 1)) {
                PrintAndLogEx(WARNING, "Can't read from emul block: %d", b);
                return PM3_ESOFT;
            }

            // switch on field and send magic sequence
            if (b == 0) {
                flags = MAGIC_INIT | (gdm ? MAGIC_GDM_ALT_WUPC : MAGIC_WUPC);
            }

            // just write
            if (b == 1) {
                flags = 0;
            }

            // Done. Magic Halt and switch off field.
            if (b == (block_cnt - 1)) {
                flags = MAGIC_HALT + MAGIC_OFF;
            }

            // write to card
            if (mf_chinese_set_block(b, buf8, NULL, flags)) {
                PrintAndLogEx(WARNING, "Can't set magic card block: %d", b);
                return PM3_ESOFT;
            }
            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }
        PrintAndLogEx(NORMAL, "");
        return PM3_SUCCESS;
    }

    // reserve memory
    uint8_t *data = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&data, &bytes_read, (MFBLOCK_SIZE * block_cnt));
    if (res != PM3_SUCCESS) {
        return res;
    }

    if (bytes_read != (block_cnt * MFBLOCK_SIZE)) {
        PrintAndLogEx(ERR, "File content error. Read %zu bytes", bytes_read);
        free(data);
        return PM3_EFILE;
    }

    PrintAndLogEx(INFO, "Copying to magic gen1a card");
    PrintAndLogEx(INFO, "." NOLF);

    int blockno = 0;
    int flags = 0;
    while (bytes_read) {

        // switch on field and send magic sequence
        if (blockno == 0) {
            flags = MAGIC_INIT | (gdm ? MAGIC_GDM_ALT_WUPC : MAGIC_WUPC);
        }

        // write
        if (blockno == 1) {
            flags = 0;
        }

        // switch off field
        if (blockno == (block_cnt - 1)) {
            flags = MAGIC_HALT + MAGIC_OFF;
        }

        if (mf_chinese_set_block(blockno, data + (MFBLOCK_SIZE * blockno), NULL, flags)) {
            PrintAndLogEx(WARNING, "Can't set magic card block: %d", blockno);
            PrintAndLogEx(HINT, "Verify that it is a GDM and not USCUID derivative");
            free(data);
            return PM3_ESOFT;
        }

        bytes_read -= MFBLOCK_SIZE;

        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);

        blockno++;

        if (blockno >= block_cnt) break;
    }
    PrintAndLogEx(NORMAL, "\n");

    free(data);

    // confirm number written blocks. Must be 20, 64 or 256 blocks
    if (blockno != block_cnt) {
        PrintAndLogEx(ERR, "File content error. There must be %d blocks", block_cnt);
        return PM3_EFILE;
    }

    PrintAndLogEx(SUCCESS, "Card loaded " _YELLOW_("%d") " blocks from file", block_cnt);
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

static int CmdHF14AMfCGetBlk(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf cgetblk",
                  "Get block data from magic Chinese card.\n"
                  "Only works with magic gen1a cards",
                  "hf mf cgetblk --blk 0      --> get block 0 (manufacturer)\n"
                  "hf mf cgetblk --blk 3 -v   --> get block 3, decode sector trailer\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b",  "blk", "<dec>", "block number"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int b = arg_get_int_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);
    bool gdm = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (b > 255) {
        return PM3_EINVARG;
    }

    uint8_t blockno = (uint8_t)b;
    uint8_t data[16] = {0};
    int res = mf_chinese_get_block(blockno, data, MAGIC_SINGLE | (gdm ? MAGIC_GDM_ALT_WUPC : MAGIC_WUPC));
    if (res) {
        PrintAndLogEx(ERR, "Can't read block. error=%d", res);
        return PM3_ESOFT;
    }

    uint8_t sector = mfSectorNum(blockno);
    mf_print_sector_hdr(sector);
    mf_print_block_one(blockno, data, verbose);

    if (verbose) {
        decode_print_st(blockno, data);
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfCGetSc(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf cgetsc",
                  "Get sector data from magic Chinese card.\n"
                  "Only works with magic gen1a cards",
                  "hf mf cgetsc -s 0"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("s",  "sec", "<dec>", "sector number"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int s = arg_get_int_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);
    bool gdm = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    if (s >= MIFARE_4K_MAXSECTOR) {
        PrintAndLogEx(WARNING, "Sector number must be less than 40");
        return PM3_EINVARG;
    }

    uint8_t sector = (uint8_t)s;
    mf_print_sector_hdr(sector);

    uint8_t blocks = 4;
    uint8_t start = sector * 4;
    if (sector >= 32) {
        blocks = 16;
        start = 128 + (sector - 32) * 16;
    }

    int flags = MAGIC_INIT + (gdm ? MAGIC_GDM_ALT_WUPC : MAGIC_WUPC);
    uint8_t data[16] = {0};
    for (int i = 0; i < blocks; i++) {
        if (i == 1) flags = 0;
        if (i == blocks - 1) flags = MAGIC_HALT + MAGIC_OFF;

        int res = mf_chinese_get_block(start + i, data, flags);
        if (res) {
            PrintAndLogEx(ERR, "Can't read block. %d error=%d", start + i, res);
            return PM3_ESOFT;
        }
        mf_print_block_one(start + i, data, verbose);
    }
    if (verbose) {
        decode_print_st(start + blocks - 1, data);
    } else {
        PrintAndLogEx(NORMAL, "");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfCSave(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf csave",
                  "Save magic gen1a card memory to file (bin/json)"
                  "or into emulator memory",
                  "hf mf csave\n"
                  "hf mf csave --4k"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0(NULL, "emu", "to emulator memory"),
        arg_lit0(NULL, "gdm", "to emulator memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);
    bool fill_emulator = arg_get_lit(ctx, 6);
    bool gdm = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    char s[6];
    memset(s, 0, sizeof(s));
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
        strncpy(s, "Mini", 5);
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
        strncpy(s, "1K", 3);
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
        strncpy(s, "2K", 3);
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
        strncpy(s, "4K", 3);
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    PrintAndLogEx(SUCCESS, "Dumping magic Gen1a MIFARE Classic " _GREEN_("%s") " card memory", s);
    PrintAndLogEx(INFO, "." NOLF);

    // Select card to get UID/UIDLEN information
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];
    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return PM3_SUCCESS;
    }

    // store card info
    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    // reserve memory
    uint16_t bytes = block_cnt * MFBLOCK_SIZE;
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    // switch on field and send magic sequence
    uint8_t flags = MAGIC_INIT + (gdm ? MAGIC_GDM_ALT_WUPC : MAGIC_WUPC);
    for (uint16_t i = 0; i < block_cnt; i++) {

        // read
        if (i == 1) {
            flags = 0;
        }
        // switch off field
        if (i == block_cnt - 1) {
            flags = MAGIC_HALT + MAGIC_OFF;
        }

        if (mf_chinese_get_block(i, dump + (i * MFBLOCK_SIZE), flags)) {
            PrintAndLogEx(WARNING, "Can't get magic card block: %d", i);
            PrintAndLogEx(HINT, "Verify your card size, and try again or try another tag position");
            free(dump);
            return PM3_ESOFT;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }
    PrintAndLogEx(NORMAL, "");

    if (fill_emulator) {
        PrintAndLogEx(INFO, "uploading to emulator memory");
        PrintAndLogEx(INFO, "." NOLF);
        // fast push mode
        g_conn.block_after_ACK = true;
        for (int i = 0; i < block_cnt; i += 5) {
            if (i == block_cnt - 1) {
                // Disable fast mode on last packet
                g_conn.block_after_ACK = false;
            }
            if (mf_elm_set_mem(dump + (i * MFBLOCK_SIZE), i, 5) != PM3_SUCCESS) {
                PrintAndLogEx(WARNING, "Can't set emul block: " _YELLOW_("%d"), i);
            }
            if (i % 64 == 0) {
                PrintAndLogEx(NORMAL, "");
                PrintAndLogEx(INFO, "" NOLF) ;
            }
            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", bytes);
    }

    // user supplied filename?
    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(fptr, sizeof(filename), "hf-mf-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }

    pm3_save_mf_dump(filename, dump, bytes, jsfCardMemory);
    free(dump);
    return PM3_SUCCESS;
}

static int CmdHF14AMfCView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf cview",
                  "View `magic gen1a` card memory",
                  "hf mf cview\n"
                  "hf mf cview --4k"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m4 = arg_get_lit(ctx, 4);
    bool verbose = arg_get_lit(ctx, 5);
    bool gdm = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    char s[6];
    memset(s, 0, sizeof(s));
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
        strncpy(s, "Mini", 5);
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
        strncpy(s, "1K", 3);
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
        strncpy(s, "2K", 3);
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
        strncpy(s, "4K", 3);
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }
    PrintAndLogEx(SUCCESS, "View magic Gen1a MIFARE Classic " _GREEN_("%s"), s);
    PrintAndLogEx(INFO, "." NOLF);

    // Select card to get UID/UIDLEN information
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return PM3_ERFTRANS;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    // reserve memory
    uint16_t bytes = block_cnt * MFBLOCK_SIZE;
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    // switch on field and send magic sequence
    uint8_t flags = MAGIC_INIT + (gdm ? MAGIC_GDM_ALT_WUPC : MAGIC_WUPC);
    for (uint16_t i = 0; i < block_cnt; i++) {
        // read
        if (i == 1) {
            flags = 0;
        }
        // switch off field
        if (i == block_cnt - 1) {
            flags = MAGIC_HALT + MAGIC_OFF;
        }

        if (mf_chinese_get_block(i, dump + (i * MFBLOCK_SIZE), flags)) {
            PrintAndLogEx(WARNING, "Can't get magic card block: " _YELLOW_("%u"), i);
            PrintAndLogEx(HINT, "Verify your card size, and try again or try another tag position");
            free(dump);
            return PM3_ESOFT;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
    }

    PrintAndLogEx(NORMAL, "");
    mf_print_blocks(block_cnt, dump, verbose);

    if (verbose) {
        mf_print_keys(block_cnt, dump);
    }

    free(dump);
    return PM3_SUCCESS;
}

//needs nt, ar, at, Data to decrypt
static int CmdHf14AMfDecryptBytes(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf decrypt",
                  "Decrypt Crypto-1 encrypted bytes given some known state of crypto. See tracelog to gather needed values",
                  "hf mf decrypt --nt b830049b --ar 9248314a --at 9280e203 -d 41e586f9\n"
                  " -> 41e586f9 becomes 3003999a\n"
                  " -> which annotates 30 03 [99 9a] read block 3 [crc]"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1(NULL, "nt",  "<hex>", "tag nonce"),
        arg_str1(NULL, "ar",  "<hex>", "ar_enc, encrypted reader response"),
        arg_str1(NULL, "at",  "<hex>", "at_enc, encrypted tag response"),
        arg_str1("d", "data", "<hex>", "encrypted data, taken directly after at_enc and forward"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint32_t nt = 0;
    int res = arg_get_u32_hexstr_def(ctx, 1, 0, &nt);
    if (res != 1) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "check `nt` parameter");
        return PM3_EINVARG;
    }

    uint32_t ar_enc = 0;
    res = arg_get_u32_hexstr_def(ctx, 2, 0, &ar_enc);
    if (res != 1) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "check `ar` parameter");
        return PM3_EINVARG;
    }

    uint32_t at_enc = 0;
    res = arg_get_u32_hexstr_def(ctx, 3, 0, &at_enc);
    if (res != 1) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "check `at` parameter");
        return PM3_EINVARG;
    }

    int datalen = 0;
    uint8_t data[512] = {0x00};
    CLIGetHexWithReturn(ctx, 4, data, &datalen);
    CLIParserFree(ctx);

    PrintAndLogEx(INFO, "nt....... %08X", nt);
    PrintAndLogEx(INFO, "ar enc... %08X", ar_enc);
    PrintAndLogEx(INFO, "at enc... %08X", at_enc);

    return try_decrypt_word(nt, ar_enc, at_enc, data, datalen);
}

static int CmdHf14AMfSetMod(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf setmod",
                  "Sets the load modulation strength of a MIFARE Classic EV1 card",
                  "hf mf setmod -k ffffffffffff -0"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("0", NULL, "normal modulation"),
        arg_lit0("1", NULL, "strong modulation (def)"),
        arg_str0("k", "key", "<hex>", "key A, Sector 0,  6 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    CLIParserFree(ctx);

    if (m0 + m1 > 1) {
        PrintAndLogEx(WARNING, "please select one modulation");
        return PM3_EINVARG;
    }

    uint8_t data[7] = {0};
    memcpy(data + 1, key, 6);

    if (m1) {
        data[0] = 1;
    } else {
        data[0] = 0;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_SETMOD, data, sizeof(data));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_SETMOD, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS)
        PrintAndLogEx(SUCCESS, "Change ( " _GREEN_("ok") " )");
    else
        PrintAndLogEx(FAILED, "Change ( " _RED_("fail") " )");

    return resp.status;
}

// MIFARE NACK bug detection
static int CmdHf14AMfNack(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf nack",
                  "Test a MIFARE Classic based card for the NACK bug",
                  "hf mf nack"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output`"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (verbose)
        PrintAndLogEx(INFO, "Started testing card for NACK bug. Press Enter to abort");

    detect_classic_nackbug(verbose);
    return PM3_SUCCESS;
}

/*
static int CmdHF14AMfice(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ice",
                  "Collect MIFARE Classic nonces to file",
                  "hf mf ice\n"
                  "hf mf ice -f nonces.bin");

    void *argtable[] = {
        arg_param_begin,
        arg_str0("f", "file", "<fn>", "filename of nonce dump"),
        arg_u64_0(NULL, "limit", "<dec>", "nonces to be collected"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    uint32_t limit = arg_get_u32_def(ctx, 2, 50000);

    CLIParserFree(ctx);

    // Validations
    char *fptr;

    if (filename[0] == '\0') {
        fptr = GenerateFilename("hf-mf-", "-nonces.bin");
        if (fptr == NULL)
            return PM3_EFILE;
        strncpy(filename, fptr, sizeof(filename) - 1);
        free(fptr);
    }

    uint8_t blockNo = 0;
    uint8_t keyType = MF_KEY_A;
    uint8_t trgBlockNo = 0;
    uint8_t trgKeyType = MF_KEY_B;
    bool slow = false;
    bool initialize = true;
    bool acquisition_completed = false;
    uint32_t total_num_nonces = 0;
    PacketResponseNG resp;

    uint32_t part_limit = 3000;

    PrintAndLogEx(NORMAL, "Collecting "_YELLOW_("%u")" nonces \n", limit);

    FILE *fnonces = NULL;
    if ((fnonces = fopen(filename, "wb")) == NULL) {
        PrintAndLogEx(WARNING, "Could not create file " _YELLOW_("%s"), filename);
        return PM3_EFILE;
    }

    clearCommandBuffer();

    uint64_t t1 = msclock();

    do {
        if (kbd_enter_pressed()) {
            PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
            break;
        }

        uint32_t flags = 0;
        flags |= initialize ? 0x0001 : 0;
        flags |= slow ? 0x0002 : 0;
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_MIFARE_ACQ_NONCES, blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, flags, NULL, 0);

        if (!WaitForResponseTimeout(CMD_ACK, &resp, 3000)) goto out;
        if (resp.oldarg[0])  goto out;

        uint32_t items = resp.oldarg[2];
        fwrite(resp.data.asBytes, 1, items * 4, fnonces);
        fflush(fnonces);

        total_num_nonces += items;
        if (total_num_nonces > part_limit) {
            PrintAndLogEx(INFO, "Total nonces %u\n", total_num_nonces);
            part_limit += 3000;
        }

        acquisition_completed = (total_num_nonces > limit);

        initialize = false;

    } while (!acquisition_completed);

out:
    PrintAndLogEx(SUCCESS, "time: %" PRIu64 " seconds\n", (msclock() - t1) / 1000);

    if (fnonces) {
        fflush(fnonces);
        fclose(fnonces);
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_MIFARE_ACQ_NONCES, blockNo + keyType * 0x100, trgBlockNo + trgKeyType * 0x100, 4, NULL, 0);
    return PM3_SUCCESS;
}
*/

static int CmdHF14AMfAuth4(const char *Cmd) {
    uint8_t keyn[20] = {0};
    int keynlen = 0;
    uint8_t key[16] = {0};
    int keylen = 0;

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf auth4",
                  "Executes AES authentication command in ISO14443-4",
                  "hf mf auth4 -n 4000 -k 000102030405060708090a0b0c0d0e0f -> executes authentication\n"
                  "hf mf auth4 -n 9003 -k FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF -> executes authentication\n");

    void *argtable[] = {
        arg_param_begin,
        arg_str1("n", NULL, "<hex>", "key num, 2 hex bytes"),
        arg_str1("k", "key", "<hex>", "key, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIGetHexWithReturn(ctx, 1, keyn, &keynlen);
    CLIGetHexWithReturn(ctx, 2, key, &keylen);
    CLIParserFree(ctx);

    if (keynlen != 2) {
        PrintAndLogEx(ERR, "Key number must be 2 bytes. Got... %d", keynlen);
        return PM3_ESOFT;
    }

    if (keylen != 16) {
        PrintAndLogEx(ERR, "Key must be 16 bytes. Got... %d", keylen);
        return PM3_ESOFT;
    }

    return MifareAuth4(NULL, keyn, key, true, false, true, true, false);
}

// https://www.nxp.com/docs/en/application-note/AN10787.pdf
static int CmdHF14AMfMAD(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf mad",
                  "Checks and prints MIFARE Application Directory (MAD)",
                  "hf mf mad -> shows MAD if exists\n"
                  "hf mf mad --aid e103 -k ffffffffffff -b -> shows NDEF data if exists. read card with custom key and key B\n"
                  "hf mf mad --dch -k ffffffffffff -> decode CardHolder information\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v",  "verbose",  "verbose output"),
        arg_str0(NULL, "aid",      "<hex>", "print all sectors with specified aid"),
        arg_str0("k",  "key",      "<hex>", "key for printing sectors"),
        arg_lit0("b",  "keyb",     "use key B for access printing sectors (by default: key A)"),
        arg_lit0(NULL, "be",       "(optional, BigEndian)"),
        arg_lit0(NULL, "dch",      "decode Card Holder information"),
        arg_str0("f",  "file",     "<fn>", "load dump file and decode MAD"),
        arg_lit0(NULL, "force",    "force decode (skip key check)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);
    uint8_t aid[2] = {0};
    int aidlen = 0;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t userkey[6] = {0};
    int keylen = 0;
    CLIGetHexWithReturn(ctx, 3, userkey, &keylen);
    bool keyB = arg_get_lit(ctx, 4);
    bool swapmad = arg_get_lit(ctx, 5);
    bool decodeholder = arg_get_lit(ctx, 6);
    bool force = arg_get_lit(ctx, 8);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 7), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    CLIParserFree(ctx);

    if (fnlen > 0) {

        // read dump file
        uint8_t *dump = NULL;
        size_t bytes_read = 0;
        int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, MIFARE_4K_MAX_BYTES);
        if (res != PM3_SUCCESS) {
            return res;
        }

        uint16_t block_cnt = MIN(MIFARE_1K_MAXBLOCK, (bytes_read / MFBLOCK_SIZE));
        if (bytes_read == MIFARE_MINI_MAX_BYTES)
            block_cnt = MIFARE_MINI_MAXBLOCK;
        else if (bytes_read == MIFARE_1K_EV1_MAX_BYTES)
            block_cnt = MIFARE_1K_EV1_MAXBLOCK;
        else if (bytes_read == MIFARE_2K_MAX_BYTES)
            block_cnt = MIFARE_2K_MAXBLOCK;
        else if (bytes_read == MIFARE_4K_MAX_BYTES)
            block_cnt = MIFARE_4K_MAXBLOCK;

        if (verbose) {
            PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, block_cnt, block_cnt);
        }

        // MAD detection
        if ((HasMADKey(dump) == false) && (force == false)) {
            PrintAndLogEx(FAILED, "No MAD key was detected in the dump file");
            free(dump);
            return PM3_ESOFT;
        }

        MADPrintHeader();
        bool haveMAD2 = false;
        MAD1DecodeAndPrint(dump, swapmad, verbose, &haveMAD2);

        int sector = DetectHID(dump, 0x484d);
        if (sector > -1) {

            // decode it
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, _CYAN_("HID PACS detected"));

            uint8_t pacs_sector[MFBLOCK_SIZE * 3] = {0};
            memcpy(pacs_sector, dump + (sector * 4 * 16), sizeof(pacs_sector));

            if (pacs_sector[16] == 0x02) {

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

                PrintAndLogEx(INFO, "Wiegand decode");
                decode_wiegand(top, mid, bot, 0);
            }
        }

        sector = DetectHID(dump, 0x4910);
        if (sector > -1) {
            // decode it
            PrintAndLogEx(INFO, "");
            PrintAndLogEx(INFO, _CYAN_("VIGIK PACS detected"));
        }

        if (haveMAD2) {
            MAD2DecodeAndPrint(dump + (MIFARE_1K_MAXBLOCK * MF_MAD2_SECTOR), swapmad, verbose);
        }

        if (aidlen == 2 || decodeholder) {
            uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
            size_t madlen = 0;
            if (MADDecode(dump, dump + (0x10 * MIFARE_1K_MAXBLOCK), mad, &madlen, swapmad)) {
                PrintAndLogEx(ERR, "can't decode MAD");
                free(dump);
                return PM3_ESOFT;
            }

            uint16_t aaid = 0x0004;
            if (aidlen == 2) {
                aaid = (aid[0] << 8) + aid[1];
            }

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------- " _CYAN_("Card Holder Info 0x%04x") " --------", aaid);

            MADCardHolderInfoDecode(dump, bytes_read, verbose);
        }
        free(dump);
        return PM3_SUCCESS;
    }

    if (g_session.pm3_present == false)
        return PM3_ENOTTY;


    uint8_t sector0[MFBLOCK_SIZE * 4] = {0};
    uint8_t sector10[MFBLOCK_SIZE * 4] = {0};

    bool got_first = true;
    if (mf_read_sector(MF_MAD1_SECTOR, MF_KEY_A, (uint8_t *)g_mifare_mad_key, sector0) != PM3_SUCCESS) {
        PrintAndLogEx(WARNING, "error, read sector 0. card doesn't have MAD or doesn't have MAD on default keys");
        got_first = false;
    } else {
        PrintAndLogEx(INFO, "Authentication ( " _GREEN_("ok") " )");
    }

    // User supplied key
    if (got_first == false && keylen == 6) {
        PrintAndLogEx(INFO, "Trying user specified key...");
        if (mf_read_sector(MF_MAD1_SECTOR, MF_KEY_A, userkey, sector0) != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "error, read sector 0. card doesn't have MAD or the custom key is wrong");
        } else {
            PrintAndLogEx(INFO, "Authentication ( " _GREEN_("ok") " )");
            got_first = true;
        }
    }

    // Both default and user supplied key failed
    if (got_first == false) {
        return PM3_ESOFT;
    }

    got_first = true;
    if (mf_read_sector(MF_MAD2_SECTOR, MF_KEY_A, (uint8_t *)g_mifare_mad_key, sector10) != PM3_SUCCESS) {
        if (verbose) {
            PrintAndLogEx(ERR, "error, read sector 0x10. card doesn't have MAD 2 or doesn't have MAD 2 on default keys");
        }
        got_first = false;
    } else {
        PrintAndLogEx(INFO, "Authentication ( " _GREEN_("ok") " )");
    }

    // User supplied key
    if (got_first == false && keylen == 6) {
        PrintAndLogEx(INFO, "Trying user specified key...");
        if (mf_read_sector(MF_MAD2_SECTOR, MF_KEY_A, userkey, sector10) != PM3_SUCCESS) {
            if (verbose) {
                PrintAndLogEx(ERR, "error, read sector 10. card doesn't have MAD 2 or the custom key is wrong");
            }
        } else {
            PrintAndLogEx(INFO, "Authentication ( " _GREEN_("ok") " )");
        }
    }

    MADPrintHeader();

    bool haveMAD2 = false;
    MAD1DecodeAndPrint(sector0, swapmad, verbose, &haveMAD2);

    if (haveMAD2) {
        MAD2DecodeAndPrint(sector10, swapmad, verbose);
    }

    if (aidlen == 2 || decodeholder) {
        uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
        size_t madlen = 0;
        if (MADDecode(sector0, sector10, mad, &madlen, swapmad)) {
            PrintAndLogEx(ERR, "can't decode MAD");
            return PM3_ESOFT;
        }

        // copy default NDEF key
        uint8_t akey[6] = {0};
        memcpy(akey, g_mifare_ndef_key, 6);

        // user specified key
        if (keylen == 6) {
            memcpy(akey, userkey, sizeof(akey));
        }

        uint16_t aaid = 0x0004;
        if (aidlen == 2) {

            aaid = (aid[0] << 8) + aid[1];

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------------- " _CYAN_("AID 0x%04x") " ---------------", aaid);

            for (int i = 0; i < madlen; i++) {
                if (aaid == mad[i]) {
                    uint8_t vsector[MFBLOCK_SIZE * 4] = {0};
                    if (mf_read_sector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector)) {
                        PrintAndLogEx(NORMAL, "");
                        PrintAndLogEx(ERR, "error, read sector %d", i + 1);
                        return PM3_ESOFT;
                    }

                    for (int j = 0; j < (verbose ? 4 : 3); j ++)
                        PrintAndLogEx(NORMAL, " [%03d] %s", (i + 1) * 4 + j, sprint_hex(&vsector[j * MFBLOCK_SIZE], MFBLOCK_SIZE));
                }
            }
        }

        if (decodeholder) {

            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "-------- " _CYAN_("Card Holder Info 0x%04x") " --------", aaid);

            uint8_t data[MIFARE_4K_MAX_BYTES] = {0};
            int datalen = 0;

            for (int i = 0; i < madlen; i++) {
                if (aaid == mad[i]) {

                    uint8_t vsector[MFBLOCK_SIZE * 4] = {0};
                    if (mf_read_sector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, akey, vsector)) {
                        PrintAndLogEx(NORMAL, "");
                        PrintAndLogEx(ERR, "error, read sector %d", i + 1);
                        return PM3_ESOFT;
                    }

                    // skip ST block hence only 3 blocks copy
                    memcpy(&data[datalen], vsector, MFBLOCK_SIZE * 3);
                    datalen += MFBLOCK_SIZE * 3;
                }
            }

            if (!datalen) {
                PrintAndLogEx(WARNING, "no Card Holder Info data");
                return PM3_SUCCESS;
            }
            MADCardHolderInfoDecode(data, datalen, verbose);
        }
    }

    if (verbose) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v1 sector raw") " -------------");
        for (int i = 0; i < 4; i ++) {
            PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex(&sector0[i * MFBLOCK_SIZE], MFBLOCK_SIZE));
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "------------ " _CYAN_("MAD v2 sector raw") " -------------");
        for (int i = 0; i < 4; i ++) {
            PrintAndLogEx(INFO, "[%d] %s", i, sprint_hex(&sector10[i * MFBLOCK_SIZE], MFBLOCK_SIZE));
        }
    }

    return PM3_SUCCESS;
}

int CmdHFMFNDEFRead(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ndefread",
                  "Prints NFC Data Exchange Format (NDEF)",
                  "hf mf ndefread -> shows NDEF parsed data\n"
                  "hf mf ndefread -vv -> shows NDEF parsed and raw data\n"
                  "hf mf ndefread --aid e103 -k ffffffffffff -b -> shows NDEF data with custom AID, key and with key B\n"
                  "hf mf ndefread -f myfilename -> save raw NDEF to file"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_litn("v",  "verbose",  0, 2, "Verbose output"),
        arg_str0(NULL, "aid",      "<aid>", "replace default aid for NDEF"),
        arg_str0("k",  "key",      "<key>", "replace default key for NDEF"),
        arg_lit0("b",  "keyb",     "use key B for access sectors (by default: key A)"),
        arg_str0("f", "file", "<fn>", "save raw NDEF to file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool verbose = arg_get_lit(ctx, 1);
    bool verbose2 = arg_get_lit(ctx, 1) > 1;
    uint8_t aid[2] = {0};

    int aidlen;
    CLIGetHexWithReturn(ctx, 2, aid, &aidlen);
    uint8_t key[6] = {0};

    int keylen;
    CLIGetHexWithReturn(ctx, 3, key, &keylen);
    bool keyB = arg_get_lit(ctx, 4);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 5), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    uint16_t ndef_aid = NDEF_MFC_AID;
    if (aidlen == 2) {
        ndef_aid = (aid[0] << 8) + aid[1];
    }

    uint8_t ndefkey[6] = {0};
    memcpy(ndefkey, g_mifare_ndef_key, 6);
    if (keylen == 6) {
        memcpy(ndefkey, key, 6);
    }

    uint8_t sector0[MFBLOCK_SIZE * 4] = {0};
    uint8_t sector10[MFBLOCK_SIZE * 4] = {0};
    uint8_t data[4096] = {0};
    int datalen = 0;

    if (verbose) {
        PrintAndLogEx(INFO, "reading MAD v1 sector");
    }

    if (mf_read_sector(MF_MAD1_SECTOR, MF_KEY_A, g_mifare_mad_key, sector0)) {
        PrintAndLogEx(ERR, "error, read sector 0. card doesn't have MAD or doesn't have MAD on default keys");
        PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mf ndefread -k `") " with your custom key");
        return PM3_ESOFT;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "reading MAD v2 sector");
    }

    if (mf_read_sector(MF_MAD2_SECTOR, MF_KEY_A, g_mifare_mad_key, sector10)) {
        if (verbose) {
            PrintAndLogEx(ERR, "error, read sector 0x10. card doesn't have MAD 2 or doesn't have MAD 2 on default keys");
            PrintAndLogEx(INFO, "Skipping MAD 2");
        }
    }

    bool haveMAD2 = false;
    int res = MADCheck(sector0, sector10, verbose, &haveMAD2);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "MAD error %d", res);
        return res;
    }

    uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
    size_t madlen = 0;
    res = MADDecode(sector0, sector10, mad, &madlen, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return res;
    }

    PrintAndLogEx(INFO, "reading data from tag");
    for (int i = 0; i < madlen; i++) {
        if (ndef_aid == mad[i]) {
            uint8_t vsector[MFBLOCK_SIZE * 4] = {0};
            if (mf_read_sector(i + 1, keyB ? MF_KEY_B : MF_KEY_A, ndefkey, vsector)) {
                PrintAndLogEx(ERR, "error, reading sector %d ", i + 1);
                return PM3_ESOFT;
            }

            memcpy(&data[datalen], vsector, MFBLOCK_SIZE * 3);
            datalen += MFBLOCK_SIZE * 3;

            PrintAndLogEx(INPLACE, "%d", i);
        }
    }
    PrintAndLogEx(NORMAL, "");

    if (datalen == 0) {
        PrintAndLogEx(WARNING, "no NDEF data");
        return PM3_SUCCESS;
    }

    if (verbose2) {
        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(INFO, "--- " _CYAN_("MFC NDEF raw") " ----------------");
        print_buffer(data, datalen, 1);
    }

    res = NDEFDecodeAndPrint(data, datalen, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(INFO, "Trying to parse NDEF records w/o NDEF header");
        res = NDEFRecordsDecodeAndPrint(data, datalen, verbose);
    }

    // if given a filename, save it
    if (fnlen) {
        // get total NDEF length before save. If fails, we save it all
        size_t n = 0;
        if (NDEFGetTotalLength(data, datalen, &n) != PM3_SUCCESS) {
            n = datalen;
        }

        pm3_save_dump(filename, data, n, jsfNDEF);
    }

    if (verbose == false) {
        PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mf ndefread -v`") " for more details");
    } else {
        if (verbose2 == false) {
            PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mf ndefread -vv`") " for more details");
        }
    }
    return PM3_SUCCESS;
}

// https://www.nxp.com/docs/en/application-note/AN1305.pdf
int CmdHFMFNDEFFormat(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ndefformat",
                  "format MIFARE Classic Tag as a NFC tag with Data Exchange Format (NDEF)\n"
                  "If no <name> given, UID will be used as filename. \n"
                  "It will try default keys and MAD keys to detect if tag is already formatted in order to write.\n"
                  "\n"
                  "If not, it will try finding a key file based on your UID.  ie, if you ran autopwn before",
                  "hf mf ndefformat\n"
                  // "hf mf ndefformat --mini                        --> MIFARE Mini\n"
                  "hf mf ndefformat --1k                          --> MIFARE Classic 1k\n"
                  // "hf mf ndefformat --2k                          --> MIFARE 2k\n"
                  // "hf mf ndefformat --4k                          --> MIFARE 4k\n"
                  "hf mf ndefformat --keys hf-mf-01020304-key.bin --> MIFARE 1k with keys from specified file\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "keys", "<fn>", "filename of keys"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keyfnlen = 0;
    char keyFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)keyFilename, FILE_PATH_SIZE, &keyfnlen);

    bool m0 = arg_get_lit(ctx, 2);
    bool m1 = arg_get_lit(ctx, 3);
    bool m2 = arg_get_lit(ctx, 4);
    bool m4 = arg_get_lit(ctx, 5);

    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t numSectors = MIFARE_1K_MAXSECTOR;

    if (m0) {
        numSectors = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        numSectors = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        numSectors = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        numSectors = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }


    if (g_session.pm3_present == false)
        return PM3_ENOTTY;

    // Select card to get UID/UIDLEN/ATQA/SAK information
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }

    uint64_t select_status = resp.oldarg[0];
    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return PM3_SUCCESS;
    }

    DropField();


    // init keys to default key
    uint8_t keyA[MIFARE_4K_MAXSECTOR][MIFARE_KEY_SIZE];
    uint8_t keyB[MIFARE_4K_MAXSECTOR][MIFARE_KEY_SIZE];

    for (uint8_t i = 0; i < MIFARE_4K_MAXSECTOR; i++) {
        memcpy(keyA[i], g_mifare_default_key, sizeof(g_mifare_default_key));
        memcpy(keyB[i], g_mifare_default_key, sizeof(g_mifare_default_key));
    }

    // test if MAD key is used
    uint64_t key64 = 0;

    // check if we can authenticate to sector
    if (mf_check_keys(0, MF_KEY_A, true, 1, (uint8_t *)g_mifare_mad_key, &key64) == PM3_SUCCESS) {

        // if used,  assume KEY A is MAD/NDEF set.
        memcpy(keyA[0], g_mifare_mad_key, sizeof(g_mifare_mad_key));
        memcpy(keyB[0], g_mifare_mad_key_b, sizeof(g_mifare_mad_key_b));
        for (uint8_t i = 1; i < MIFARE_4K_MAXSECTOR; i++) {
            memcpy(keyA[i], g_mifare_ndef_key, sizeof(g_mifare_ndef_key));
        }
    }

    // Do we have a keyfile based from UID?
    if (keyfnlen == 0) {
        char *fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr) {
            strncpy(keyFilename, fptr, sizeof(keyFilename) - 1);
        }
        free(fptr);
        DropField();
    }

    // load key file if exist
    if (strlen(keyFilename)) {
        //
        size_t alen = 0, blen = 0;
        uint8_t *tmpA, *tmpB;
        if (loadFileBinaryKey(keyFilename, "", (void **)&tmpA, (void **)&tmpB, &alen, &blen) != PM3_SUCCESS) {
            goto skipfile;
        }

        PrintAndLogEx(INFO, "Using `" _YELLOW_("%s") "`", keyFilename);

        for (int i = 0; i < numSectors; i++) {
            memcpy(keyA[i], tmpA + (i * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
            memcpy(keyB[i], tmpB + (i * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
        }
        free(tmpA);
        free(tmpB);
    }

skipfile:
    ;

    uint8_t firstblocks[8][16] = {
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x14, 0x01, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 },
        { 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1, 0x03, 0xE1 },
        { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A },
        { 0x03, 0x00, 0xFE, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 },
        { 0xD3, 0xF7, 0xD3, 0xF7, 0xD3, 0xF7, 0x7F, 0x07, 0x88, 0x40, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF },
    };

    // main loop
    for (int i = 0; i < numSectors; i++) {
        for (int j = 0; j < mfNumBlocksPerSector(j); j++) {

            uint8_t b = (mfFirstBlockOfSector(i) + j);
            uint8_t block[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

            switch (b) {
                case 0:
                    continue;
                case 1:
                case 2:
                case 3:
                case 4:
                case 5:
                case 6:
                case 7:
                    memcpy(block, firstblocks[b], MFBLOCK_SIZE);
                    break;
                default: {
                    if (mfIsSectorTrailerBasedOnBlocks(i, j)) {
                        // ST NDEF
                        memcpy(block, firstblocks[7], MFBLOCK_SIZE);
                    }
                    break;
                }
            }

            // write to card,  try B key first
            if (mf_write_block(b, MF_KEY_B, keyB[i], block) != PM3_SUCCESS) {
                // try A key,
                if (mf_write_block(b, MF_KEY_A, keyA[i], block) != PM3_SUCCESS) {
                    return PM3_EFAILED;
                }
            }
            PrintAndLogEx(INPLACE, "Formatting block %u", b);
        }
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

int CmdHFMFNDEFWrite(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ndefwrite",
                  "Write raw NDEF hex bytes to tag. This commands assumes tag already been NFC/NDEF formatted.\n",
                  "hf mf ndefwrite -d 0300FE      -> write empty record to tag\n"
                  "hf mf ndefwrite -f myfilename\n"
                  "hf mf ndefwrite -d 033fd1023a53709101195405656e2d55534963656d616e2054776974746572206c696e6b5101195502747769747465722e636f6d2f686572726d616e6e31303031\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", NULL, "<hex>", "raw NDEF hex bytes"),
        arg_str0("f", "file", "<fn>", "write raw NDEF file to tag"),
        arg_lit0("p", NULL, "fix NDEF record headers / terminator block if missing"),
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t raw[4096] = {0};
    int rawlen;
    CLIGetHexWithReturn(ctx, 1, raw, &rawlen);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 2), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool fix_msg = arg_get_lit(ctx, 3);

    bool m0 = arg_get_lit(ctx, 4);
    bool m1 = arg_get_lit(ctx, 5);
    bool m2 = arg_get_lit(ctx, 6);
    bool m4 = arg_get_lit(ctx, 7);
    bool verbose = arg_get_lit(ctx, 8);

    CLIParserFree(ctx);

    // validations
    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    uint8_t numSectors = MIFARE_1K_MAXSECTOR;

    if (m0) {
        numSectors = MIFARE_MINI_MAXSECTOR;
    } else if (m1) {
        numSectors = MIFARE_1K_MAXSECTOR;
    } else if (m2) {
        numSectors = MIFARE_2K_MAXSECTOR;
    } else if (m4) {
        numSectors = MIFARE_4K_MAXSECTOR;
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Number of sectors selected: %u", numSectors);
    }

    if (g_session.pm3_present == false) {
        PrintAndLogEx(FAILED, "No Proxmark3 device present");
        return PM3_ENOTTY;
    }

    if ((rawlen && fnlen) || (rawlen == 0 && fnlen == 0)) {
        PrintAndLogEx(WARNING, "Please specify either raw hex or filename");
        return PM3_EINVARG;
    }

    // test if MAD key is used
    uint64_t key64 = 0;

    // check if we can authenticate to sector
    int res = mf_check_keys(0, MF_KEY_A, true, 1, (uint8_t *)g_mifare_mad_key, &key64);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "Sector 0 failed to authenticate with MAD default key");
        PrintAndLogEx(HINT, "Verify that the tag NDEF formatted");
        return res;
    }

    // NDEF for MIFARE CLASSIC has different memory size available.

    int32_t bytes = rawlen;

    // read dump file
    if (fnlen) {
        uint8_t *dump = NULL;
        size_t bytes_read = 0;
        res = pm3_load_dump(filename, (void **)&dump, &bytes_read, sizeof(raw));
        if (res != PM3_SUCCESS) {
            return res;
        }
        memcpy(raw, dump, bytes_read);
        bytes = bytes_read;
        free(dump);
    }

    // Has raw bytes ndef message header?bytes
    switch (raw[0]) {
        case 0x00:
        case 0x01:
        case 0x02:
        case 0x03:
        case 0xFD:
        case 0xFE:
            break;
        default: {
            if (fix_msg == false) {
                PrintAndLogEx(WARNING, "raw NDEF message doesn't have a proper header,  continuing...");
            } else {
                if (bytes + 2 > sizeof(raw)) {
                    PrintAndLogEx(WARNING, "no room for header, exiting...");
                    return PM3_EMALLOC;
                }
                uint8_t tmp_raw[4096];
                memcpy(tmp_raw, raw, sizeof(tmp_raw));
                raw[0] = 0x03;
                raw[1] = bytes;
                memcpy(raw + 2, tmp_raw, sizeof(raw) - 2);
                bytes += 2;
                PrintAndLogEx(SUCCESS, "Added generic message header (0x03)");
            }
        }
    }

    // Has raw bytes ndef a terminator block?
    if (raw[bytes - 1] != 0xFE) {
        if (fix_msg == false) {
            PrintAndLogEx(WARNING, "raw NDEF message doesn't have a terminator block,  continuing...");
        } else {

            if (bytes + 1 > sizeof(raw)) {
                PrintAndLogEx(WARNING, "no room for terminator block, exiting...");
                return PM3_EMALLOC;
            }
            raw[bytes] = 0xFE;
            bytes++;
            PrintAndLogEx(SUCCESS, "Added terminator block (0xFE)");
        }
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Num of Bytes... %u", bytes);
        print_buffer(raw, bytes, 0);
    }

    // read MAD Sector 0, block1,2
    uint8_t sector0[MFBLOCK_SIZE * 4] = {0};
    if (mf_read_sector(MF_MAD1_SECTOR, MF_KEY_A, g_mifare_mad_key, sector0)) {
        PrintAndLogEx(ERR, "error, reading sector 0. Card doesn't have MAD or doesn't have MAD on default keys");
        PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mf ndefread -k `") " with your custom key");
        return PM3_ESOFT;
    }

    // read MAD Sector 10, block1,2
    uint8_t sector10[MFBLOCK_SIZE * 4] = {0};
    if (m4) {
        if (mf_read_sector(MF_MAD2_SECTOR, MF_KEY_A, g_mifare_mad_key, sector10)) {
            PrintAndLogEx(ERR, "error, reading sector 10. Card doesn't have MAD or doesn't have MAD on default keys");
            PrintAndLogEx(HINT, "Try " _YELLOW_("`hf mf ndefread -k `") " with your custom key");
            return PM3_ESOFT;
        }
    }

    // decode MAD v1
    uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
    size_t madlen = 0;
    res = MADDecode(sector0, sector10, mad, &madlen, false);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "can't decode MAD");
        return res;
    }

    // how much memory do I have available ?
    // Skip sector 0 since its used for MAD
    uint8_t freemem[MIFARE_4K_MAXSECTOR] = {0};
    uint16_t sum = 0;
    uint8_t block_no = 0;
    for (uint8_t i = 1; i < (madlen & 0xFF); i++) {

        freemem[i] = (mad[i] == NDEF_MFC_AID);

        if (freemem[i]) {

            if (block_no == 0) {
                block_no = mfFirstBlockOfSector(i);
            }

            if (verbose) {
                PrintAndLogEx(INFO, "Sector %u is NDEF formatted", i);
            }
            sum += (MFBLOCK_SIZE * 3);
        }
    }

    if (verbose) {
        PrintAndLogEx(INFO, "Total avail ndef mem... %u", sum);
        PrintAndLogEx(INFO, "First block............ %u", block_no);
    }

    if (sum < bytes) {
        PrintAndLogEx(WARNING, "Raw NDEF message is larger than available NDEF formatted memory");
        return PM3_EINVARG;
    }

    // main loop - write blocks
    uint8_t *ptr_raw = raw;
    while (bytes > 0) {

        uint8_t block[MFBLOCK_SIZE] = { 0x00 };

        if (bytes < MFBLOCK_SIZE) {
            memcpy(block, ptr_raw, bytes);
        } else {
            memcpy(block, ptr_raw, MFBLOCK_SIZE);
            ptr_raw += MFBLOCK_SIZE;
        }

        // write to card,  try B key first
        if (mf_write_block(block_no,  MF_KEY_B, g_mifare_default_key, block) != PM3_SUCCESS) {

            // try A key,

            if (mf_write_block(block_no, MF_KEY_A, g_mifare_ndef_key, block) != PM3_SUCCESS) {
                return PM3_EFAILED;
            }
        }

        PrintAndLogEx(INPLACE, "%u", block_no);

        // find next available block
        block_no++;

        if (mfIsSectorTrailer(block_no)) {
            block_no++;
            // skip sectors which isn't ndef formatted
            while (freemem[mfSectorNum(block_no)] == 0) {
                block_no++;
            }
        }

        bytes -= MFBLOCK_SIZE;
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHFMFPersonalize(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf personalize",
                  "Personalize the UID of a MIFARE Classic EV1 card. This is only possible \n"
                  "if it is a 7Byte UID card and if it is not already personalized.",
                  "hf mf personalize --f0                    -> double size UID\n"
                  "hf mf personalize --f1                    -> double size UID, optional usage of selection process shortcut\n"
                  "hf mf personalize --f2                    -> single size random ID\n"
                  "hf mf personalize --f3                    -> single size NUID\n"
                  "hf mf personalize -b -k B0B1B2B3B4B5 --f3 -> use key B = 0xB0B1B2B3B4B5"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("a", NULL, "use key A to authenticate sector 0 (def)"),
        arg_lit0("b", NULL, "use key B to authenticate sector 0"),
        arg_str0("k",  "key", "<hex>", "key (def FFFFFFFFFFFF)"),
        arg_lit0(NULL, "f0", "UIDFO, double size UID"),
        arg_lit0(NULL, "f1", "UIDF1, double size UID, optional usage of selection process shortcut"),
        arg_lit0(NULL, "f2", "UIDF2, single size random ID"),
        arg_lit0(NULL, "f3", "UIDF3, single size NUID"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    bool use_a = arg_get_lit(ctx, 1);
    bool use_b = arg_get_lit(ctx, 2);

    if (use_a + use_b > 1) {
        PrintAndLogEx(ERR, "error, use only one key type");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    uint8_t keytype = 0;
    if (use_b) {
        keytype = 1;
    }

    uint8_t key[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
    int key_len;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 3), key, 6, &key_len);
    if (res || (!res && key_len && key_len != 6)) {
        PrintAndLogEx(ERR, "ERROR: not a valid key. Key must be 12 hex digits");
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool f0 = arg_get_lit(ctx, 4);
    bool f1 = arg_get_lit(ctx, 5);
    bool f2 = arg_get_lit(ctx, 6);
    bool f3 = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    uint8_t tmp = f0 + f1 + f2 + f3;
    if (tmp > 1) {
        PrintAndLogEx(WARNING, "select only one key type");
        return PM3_EINVARG;
    }
    if (tmp == 0) {
        PrintAndLogEx(WARNING, "select one key type");
        return PM3_EINVARG;
    }

    uint8_t pers_option = MIFARE_EV1_UIDF3;
    if (f0) {
        pers_option = MIFARE_EV1_UIDF0;
    } else if (f1) {
        pers_option = MIFARE_EV1_UIDF1;
    } else if (f2) {
        pers_option = MIFARE_EV1_UIDF2;
    }

    CLIParserFree(ctx);

    struct {
        uint8_t keytype;
        uint8_t pers_option;
        uint8_t key[6];
    } PACKED payload;
    payload.keytype = keytype;
    payload.pers_option = pers_option;
    memcpy(payload.key, key, sizeof(payload.key));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_PERSONALIZE_UID, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_PERSONALIZE_UID, &resp, 2500) == false) {
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Personalization ( %s )", _GREEN_("ok"));
    } else {
        PrintAndLogEx(FAILED, "Personalization ( %s )",  _RED_("fail"));
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfList(const char *Cmd) {
    return CmdTraceListAlias(Cmd, "hf mf", "mf -c");
}

static int CmdHf14AGen3UID(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gen3uid",
                  "Set UID for magic Gen3 card _without_ changes to manufacturer block 0",
                  "hf mf gen3uid --uid 01020304       --> set 4 byte uid\n"
                  "hf mf gen3uid --uid 01020304050607 --> set 7 byte uid"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("u", "uid", "<hex>", "UID 4/7 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t uid[7] = {0};
    int uidlen = 0;
    CLIGetHexWithReturn(ctx, 1, uid, &uidlen);
    CLIParserFree(ctx);

    // sanity checks
    if (uidlen != 4 && uidlen != 7) {
        PrintAndLogEx(FAILED, "UID must be 4 or 7 hex bytes. Got %d", uidlen);
        return PM3_EINVARG;
    }

    uint8_t old_uid[10] = {0};

    int res = mf_chinese_gen_3_uid(uid, uidlen, old_uid);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't set UID");
        PrintAndLogEx(HINT, "Are you sure your card is a Gen3 ?");
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Old UID... %s", sprint_hex(old_uid, uidlen));
    PrintAndLogEx(SUCCESS, "New UID... %s", sprint_hex(uid, uidlen));
    return PM3_SUCCESS;
}

static int CmdHf14AGen3Block(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gen3blk",
                  "Overwrite full manufacturer block for magic Gen3 card\n"
                  " - You can specify part of manufacturer block as\n"
                  "   4/7-bytes for UID change only\n"
                  "\n"
                  "NOTE: BCC and ATQA will be calculated automatically\n"
                  "SAK will be automatically set to default values if not specified"
                  ,
                  "hf mf gen3blk                      --> print current data\n"
                  "hf mf gen3blk -d 01020304          --> set 4 byte uid\n"
                  "hf mf gen3blk -d 01020304050607    --> set 7 byte uid \n"
                  "hf mf gen3blk -d 01020304FFFFFFFF0102030405060708"

                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("d", "data", "<hex>", "manufacturer block data up to 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    uint8_t data[MFBLOCK_SIZE] = {0x00};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 1, data, &datalen);
    CLIParserFree(ctx);

    uint8_t new_block[MFBLOCK_SIZE] = {0x00};
    int res = mf_chinese_gen_3_block(data, datalen, new_block);
    if (res) {
        PrintAndLogEx(ERR, "Can't change manufacturer block data. error %d", res);
        return PM3_ESOFT;
    }

    PrintAndLogEx(SUCCESS, "Current block... %s", sprint_hex_inrow(new_block, sizeof(new_block)));
    return PM3_SUCCESS;
}

static int CmdHf14AGen3Freeze(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gen3freeze",
                  "Perma lock further UID changes. No more UID changes available after operation completed\n"
                  "\nNote: operation is " _RED_("! irreversible !"),

                  "hf mf gen3freeze -y"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit1("y", "yes", "confirm UID lock operation"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    bool confirm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);
    if (confirm == false) {
        PrintAndLogEx(INFO, "please confirm that you want to perma lock the card");
        return PM3_SUCCESS;
    }

    int res = mf_chinese_gen_3_freeze();
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Can't lock UID changes. error %d", res);
    } else {
        PrintAndLogEx(SUCCESS, "MFC Gen3 UID card is now perma-locked");
    }
    return res;
}

#define FURUI_MAX_TRACES    8
static int mfc_furui_recovery(uint8_t items, uint8_t tracedata[FURUI_MAX_TRACES][18]) {
    // recover key from collected traces
    // outer loop
    for (uint8_t i = 0; i < items; i++) {

        // first
        nonces_t data;
        data.cuid = bytes_to_num(tracedata[i], 4);
        data.nonce = bytes_to_num(tracedata[i] + 6, 4);
        data.nr = bytes_to_num(tracedata[i] + 10, 4);
        data.ar = bytes_to_num(tracedata[i] + 14, 4);
        data.at = 0;

        // inner loop
        for (uint8_t j = i + 1; j < items; j++) {

            uint8_t *p = tracedata[j];
            PrintAndLogEx(INFO, "%u... %s", i, sprint_hex_inrow(p, 18));

            // since data stored as block number but its the same key for all blocks in one sector
            // we compare with sector number here
            uint8_t s = mfSectorNum(tracedata[i][4]);
            if (mfSectorNum(p[4]) == s) {

                data.nonce2 = bytes_to_num(p + 6, 4);
                data.nr2 = bytes_to_num(p + 10, 4);
                data.ar2 = bytes_to_num(p + 14, 4);
                data.sector = s;
                data.keytype = tracedata[i][5];
                data.state = FIRST;

                uint64_t key64 = -1;
                if (mfkey32_moebius(&data, &key64)) {
                    PrintAndLogEx(SUCCESS, "UID: %s Sector %02x key %c [ "_GREEN_("%012" PRIX64) " ]",
                                  sprint_hex_inrow(tracedata[i], 4),
                                  data.sector,
                                  (data.keytype == 0x60) ? 'A' : 'B',
                                  key64
                                 );
                    break;
                }
            }
        }
    }
    return PM3_SUCCESS;
}

static int mfc_supercard_gen2_recovery(uint8_t items, uint8_t tracedata[FURUI_MAX_TRACES][18]) {
    for (uint8_t i = 0; i < items; i++) {
        uint8_t *tmp = tracedata[i];

        // first
        uint16_t NT0 = (tmp[6] << 8) | tmp[7];

        nonces_t data;
        data.cuid = bytes_to_num(tmp, 4);
        data.nonce = prng_successor(NT0, 31);
        data.nr = bytes_to_num(tmp + 8, 4);
        data.ar = bytes_to_num(tmp + 12, 4);
        data.at = 0;

        // second
        for (uint8_t j = i + 1; j < items; j++) {
            uint8_t *p = tracedata[j];

            // since data stored as block number but its the same key for all blocks in one sector
            // we compare with sector number here
            uint8_t s = mfSectorNum(tmp[5]);
            if (mfSectorNum(p[5]) == s) {

                NT0 = (p[6] << 8) | p[7];

                data.nonce2 = prng_successor(NT0, 31);
                data.nr2 = bytes_to_num(p + 8, 4);
                data.ar2 = bytes_to_num(p + 12, 4);
                data.sector = s;
                data.keytype = tmp[4];
                data.state = FIRST;

                uint64_t key64 = -1;
                if (mfkey32_moebius(&data, &key64)) {
                    PrintAndLogEx(SUCCESS, "UID: %s Sector %02x key %c [ "_GREEN_("%012" PRIX64) " ]",
                                  sprint_hex_inrow(tmp, 4),
                                  data.sector,
                                  (data.keytype == 0x60) ? 'A' : 'B',
                                  key64
                                 );
                    break;
                }
            }
        }
    }
    return PM3_SUCCESS;
}

static int CmdHf14AMfSuperCard(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf supercard",
                  "Extract info from a `super card`",
                  "hf mf supercard              -> recover key\n"
                  "hf mf supercard -r           -> reset card\n"
                  "hf mf supercard -u 11223344  -> change UID\n");

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("r", "reset", "Reset card"),
        arg_str0("u", "uid", "<hex>", "New UID (4 hex bytes)"),
        arg_lit0(NULL, "furui", "Furui detection card"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool reset_card = arg_get_lit(ctx, 1);
    uint8_t uid[4];
    int uidlen = 0;
    int res = CLIParamHexToBuf(arg_get_str(ctx, 2), uid, sizeof(uid), &uidlen);
    bool is_furui = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    // sanity checks
    if (res || (!res && uidlen && uidlen != sizeof(uid))) {
        PrintAndLogEx(ERR, "UID must include 4 hex bytes");
        return PM3_EINVARG;
    }

    uint8_t tracedata[FURUI_MAX_TRACES][18];

    // Super card FURUI
    if (is_furui) {

        // no reset on super card FURUI
        if (uidlen || reset_card) {
            PrintAndLogEx(FAILED, "Not supported on this card");
            return PM3_SUCCESS;
        }

        // read 8 traces
        uint8_t i;
        for (i = 0; i < FURUI_MAX_TRACES; i++) {

            uint8_t data[] = {0xAA, 0xA8, 0x00, i};
            uint32_t flags = ISO14A_CONNECT | ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_RATS;
            clearCommandBuffer();
            SendCommandMIX(CMD_HF_ISO14443A_READER, flags, sizeof(data), 0, data, sizeof(data));
            if (WaitForResponseTimeout(CMD_ACK, NULL, 1500) == false) {
                break;
            }

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
                break;
            }

            uint16_t len = resp.oldarg[0] & 0xFFFF;
            if (len != 20) {
                break; // Not trace data
            }

            PrintAndLogEx(DEBUG, ">>> %s", sprint_hex_inrow(resp.data.asBytes, len));
            memcpy(&tracedata[i], resp.data.asBytes, len - 2);
        }

        return mfc_furui_recovery(i, tracedata);
    }

#define SUPER_MAX_TRACES    7

    // read 7 traces from super card generation 1,2
    uint8_t i = 0;
    for (i = 0; i < SUPER_MAX_TRACES; i++) {

        uint8_t data[] = {0x30, i};
        uint32_t flags = ISO14A_CONNECT | ISO14A_RAW | ISO14A_APPEND_CRC | ISO14A_NO_RATS;
        clearCommandBuffer();
        SendCommandMIX(CMD_HF_ISO14443A_READER, flags, sizeof(data), 0, data, sizeof(data));
        if (WaitForResponseTimeout(CMD_ACK, NULL, 1500) == false) {
            break;
        }

        PacketResponseNG resp;
        if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
            break;
        }

        uint16_t len = resp.oldarg[0] & 0xFFFF;
        if (len != 18) {
            break; // Not trace data
        }

        PrintAndLogEx(DEBUG, ">>> %s", sprint_hex_inrow(resp.data.asBytes, len));
        memcpy(&tracedata[i], resp.data.asBytes, len - 2);
    }

    // Super card generation 2
    if (i == SUPER_MAX_TRACES) {

        // no reset on super card generation 2.
        if (uidlen || reset_card) {
            PrintAndLogEx(FAILED, "Not supported on this card");
            return PM3_SUCCESS;
        }

        // recover key from collected traces
        return mfc_supercard_gen2_recovery(i, tracedata);
    }

    // Super card generation 1

    // Commands:
    // a0 - set UID
    // b0 - read traces
    // c0 - clear card
    bool activate_field = true;
    bool keep_field_on = true;

    // change UID on a super card generation 1
    if (uidlen) {
        keep_field_on = false;
        uint8_t response[6];
        int resplen = 0;

        // --------------- CHANGE UID ----------------
        uint8_t aCHANGE[] = {0x00, 0xa6, 0xa0, 0x00, 0x05, 0xff, 0xff, 0xff, 0xff, 0x00};
        memcpy(aCHANGE + 5, uid, uidlen);
        res = ExchangeAPDU14a(
                  aCHANGE, sizeof(aCHANGE),
                  activate_field,
                  keep_field_on,
                  response, sizeof(response),
                  &resplen
              );

        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Super card UID change [ " _RED_("fail") " ]");
            DropField();
            return res;
        }

        PrintAndLogEx(SUCCESS, "Super card UID change ( " _GREEN_("ok") " )");
        return PM3_SUCCESS;
    }

    // reset a super card generation 1
    if (reset_card) {
        keep_field_on = false;
        uint8_t response[6];
        int resplen = 0;

        // --------------- RESET CARD ----------------
        uint8_t aRESET[] = {0x00, 0xa6, 0xc0, 0x00};
        res = ExchangeAPDU14a(
                  aRESET, sizeof(aRESET),
                  activate_field,
                  keep_field_on,
                  response, sizeof(response),
                  &resplen
              );

        if (res != PM3_SUCCESS) {
            PrintAndLogEx(FAILED, "Super card reset [ " _RED_("fail") " ]");
            DropField();
            return res;
        }
        PrintAndLogEx(SUCCESS, "Super card reset ( " _GREEN_("ok") " )");
        return PM3_SUCCESS;
    }

    uint8_t responseA[22];
    uint8_t responseB[22];
    int respAlen = 0;
    int respBlen = 0;

    // --------------- First ----------------
    uint8_t aFIRST[] = {0x00, 0xa6, 0xb0, 0x00, 0x10};
    res = ExchangeAPDU14a(aFIRST, sizeof(aFIRST), activate_field, keep_field_on, responseA, sizeof(responseA), &respAlen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    // --------------- Second ----------------
    activate_field = false;
    keep_field_on = false;

    uint8_t aSECOND[] = {0x00, 0xa6, 0xb0, 0x01, 0x10};
    res = ExchangeAPDU14a(aSECOND, sizeof(aSECOND), activate_field, keep_field_on, responseB, sizeof(responseB), &respBlen);
    if (res != PM3_SUCCESS) {
        DropField();
        return res;
    }

    uint8_t outA[16] = {0};
    uint8_t outB[16] = {0};

    uint8_t key[] = {0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88};
    for (i = 0; i < 16; i += 8) {
        des_decrypt(outA + i, responseA + i, key);
        des_decrypt(outB + i, responseB + i, key);
    }

    PrintAndLogEx(DEBUG, " in : %s", sprint_hex_inrow(responseA, respAlen));
    PrintAndLogEx(DEBUG, "out : %s", sprint_hex_inrow(outA, sizeof(outA)));
    PrintAndLogEx(DEBUG, " in : %s", sprint_hex_inrow(responseB, respAlen));
    PrintAndLogEx(DEBUG, "out : %s", sprint_hex_inrow(outB, sizeof(outB)));

    if (memcmp(outA, "\x01\x01\x01\x01\x01\x01\x01\x01", 8) == 0) {
        PrintAndLogEx(INFO, "No trace recorded");
        return PM3_SUCCESS;
    }

    // second trace?
    if (memcmp(outB, "\x01\x01\x01\x01\x01\x01\x01\x01", 8) == 0) {
        PrintAndLogEx(INFO, "Only one trace recorded");
        return PM3_SUCCESS;
    }

    nonces_t data;

    // first
    uint16_t NT0 = (outA[6] << 8) | outA[7];
    data.cuid = bytes_to_num(outA, 4);
    data.nonce = prng_successor(NT0, 31);
    data.nr = bytes_to_num(outA + 8, 4);
    data.ar = bytes_to_num(outA + 12, 4);
    data.at = 0;

    // second
    NT0 = (outB[6] << 8) | outB[7];
    data.nonce2 = prng_successor(NT0, 31);
    data.nr2 = bytes_to_num(outB + 8, 4);
    data.ar2 = bytes_to_num(outB + 12, 4);
    data.sector = mfSectorNum(outA[5]);
    data.keytype = outA[4];
    data.state = FIRST;

    PrintAndLogEx(DEBUG, "A Sector %02x", data.sector);
    PrintAndLogEx(DEBUG, "A NT  %08x", data.nonce);
    PrintAndLogEx(DEBUG, "A NR  %08x", data.nr);
    PrintAndLogEx(DEBUG, "A AR  %08x", data.ar);
    PrintAndLogEx(DEBUG, "");
    PrintAndLogEx(DEBUG, "B NT  %08x", data.nonce2);
    PrintAndLogEx(DEBUG, "B NR  %08x", data.nr2);
    PrintAndLogEx(DEBUG, "B AR  %08x", data.ar2);

    uint64_t key64 = -1;
    if (mfkey32_moebius(&data, &key64)) {
        PrintAndLogEx(SUCCESS, "UID: %s Sector %02x key %c [ " _GREEN_("%012" PRIX64) " ]",
                      sprint_hex_inrow(outA, 4),
                      data.sector,
                      (data.keytype == 0x60) ? 'A' : 'B',
                      key64
                     );
    } else {
        PrintAndLogEx(FAILED, "failed to recover any key");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfWipe(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf wipe",
                  "Wipe card to zeros and default keys/acc. This command takes a key file to wipe card\n"
                  "Will use UID from card to generate keyfile name if not specified.\n"
                  "New A/B keys.....  FF FF FF FF FF FF\n"
                  "New acc rights...  FF 07 80\n"
                  "New GPB..........  69",
                  "hf mf wipe                --> reads card uid to generate file name\n"
                  "hf mf wipe --gen2         --> force write to S0, B0 manufacture block\n"
                  "hf mf wipe -f mykey.bin   --> use mykey.bin\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("f",  "file", "<fn>", "key filename"),
        arg_lit0(NULL, "gen2", "force write to Sector 0, block 0  (GEN2)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keyfnlen = 0;
    char keyFilename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)keyFilename, FILE_PATH_SIZE, &keyfnlen);

    bool gen2 = arg_get_lit(ctx, 2);
    CLIParserFree(ctx);

    char *fptr;
    if (keyfnlen == 0) {
        fptr = GenerateFilename("hf-mf-", "-key.bin");
        if (fptr == NULL) {
            return PM3_ESOFT;
        }
        strncpy(keyFilename, fptr, sizeof(keyFilename) - 1);
        free(fptr);
    }

    uint8_t *keys;
    size_t keyslen = 0;
    if (loadFile_safeEx(keyFilename, ".bin", (void **)&keys, (size_t *)&keyslen, false) != PM3_SUCCESS) {
        PrintAndLogEx(FAILED, "failed to load key file");
        return PM3_ESOFT;
    }

    uint8_t keyA[MIFARE_4K_MAXSECTOR * MIFARE_KEY_SIZE];
    uint8_t keyB[MIFARE_4K_MAXSECTOR * MIFARE_KEY_SIZE];
    uint8_t num_sectors = 0;

    uint8_t mf[MFBLOCK_SIZE];
    switch (keyslen) {
        case (MIFARE_MINI_MAX_KEY_SIZE): {
            PrintAndLogEx(INFO, "Loaded keys matching MIFARE Classic Mini 320b");
            memcpy(keyA, keys, (MIFARE_MINI_MAXSECTOR * MIFARE_KEY_SIZE));
            memcpy(keyB, keys + (MIFARE_MINI_MAXSECTOR * MIFARE_KEY_SIZE), (MIFARE_MINI_MAXSECTOR * MIFARE_KEY_SIZE));
            num_sectors = NumOfSectors('0');
            memcpy(mf, "\x11\x22\x33\x44\x44\x09\x04\x00\x62\x63\x64\x65\x66\x67\x68\x69", MFBLOCK_SIZE);
            break;
        }
        case (MIFARE_1K_EV1_MAX_KEY_SIZE): {
            PrintAndLogEx(INFO, "Loaded keys matching MIFARE Classic 1K Ev1");
            memcpy(keyA, keys, (MIFARE_1K_EV1_MAXSECTOR * MIFARE_KEY_SIZE));
            memcpy(keyB, keys + (MIFARE_1K_EV1_MAXSECTOR * MIFARE_KEY_SIZE), (MIFARE_1K_EV1_MAXSECTOR * MIFARE_KEY_SIZE));
            num_sectors = NumOfSectors('1');
            memcpy(mf, "\x11\x22\x33\x44\x44\x08\x04\x00\x62\x63\x64\x65\x66\x67\x68\x69", MFBLOCK_SIZE);
            break;
        }
        case (MIFARE_1K_MAX_KEY_SIZE): {
            PrintAndLogEx(INFO, "Loaded keys matching MIFARE Classic 1K");
            memcpy(keyA, keys, (MIFARE_1K_MAXSECTOR * MIFARE_KEY_SIZE));
            memcpy(keyB, keys + (MIFARE_1K_MAXSECTOR * MIFARE_KEY_SIZE), (MIFARE_1K_MAXSECTOR * MIFARE_KEY_SIZE));
            num_sectors = NumOfSectors('1');

            memcpy(mf, "\x11\x22\x33\x44\x44\x08\x04\x00\x62\x63\x64\x65\x66\x67\x68\x69", MFBLOCK_SIZE);
            break;
        }
        case (MIFARE_4K_MAX_KEY_SIZE): {
            PrintAndLogEx(INFO, "Loaded keys matching MIFARE Classic 4K");
            memcpy(keyA, keys, (MIFARE_4K_MAXSECTOR * MIFARE_KEY_SIZE));
            memcpy(keyB, keys + (MIFARE_4K_MAXSECTOR * MIFARE_KEY_SIZE), (MIFARE_4K_MAXSECTOR * MIFARE_KEY_SIZE));
            num_sectors = NumOfSectors('4');
            memcpy(mf, "\x11\x22\x33\x44\x44\x18\x02\x00\x62\x63\x64\x65\x66\x67\x68\x69", MFBLOCK_SIZE);
            break;
        }
        default: {
            PrintAndLogEx(INFO, "wrong key file size.  got %zu", keyslen);
            goto out;
        }
    }

    if (gen2)
        PrintAndLogEx(INFO, "Forcing overwrite of sector 0 / block 0 ");
    else
        PrintAndLogEx(INFO, "Skipping sector 0 / block 0");

    PrintAndLogEx(NORMAL, "");

    uint8_t zeros[MFBLOCK_SIZE] = {0};
    memset(zeros, 0x00, sizeof(zeros));
    uint8_t st[MFBLOCK_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0x07, 0x80, 0x69, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};

    PrintAndLogEx(INFO, " blk | ");
    PrintAndLogEx(INFO, "-----+------------------------------------------------------------");
    // time to wipe card
    for (uint8_t s = 0; s < num_sectors; s++) {

        for (uint8_t b = 0; b < mfNumBlocksPerSector(s); b++) {

            if (kbd_enter_pressed()) {
                PrintAndLogEx(WARNING, "\naborted via keyboard!\n");
                goto out;
            }

            // Skip write to manufacture block if not enforced
            if (s == 0 && b == 0 && gen2 == false) {
                continue;
            }

            uint8_t data[26];
            memset(data, 0, sizeof(data));
            if (mfIsSectorTrailerBasedOnBlocks(s, b)) {
                memcpy(data + 10, st, sizeof(st));
            } else {
                memcpy(data + 10, zeros, sizeof(zeros));
            }

            // add correct manufacture block if UID Gen2
            if (s == 0 && b == 0 && gen2) {
                memcpy(data + 10, mf, sizeof(mf));
            }

            // try both A/B keys, start with B key first
            for (int8_t kt = MF_KEY_B; kt > -1; kt--) {

                if (kt == MF_KEY_A)
                    memcpy(data, keyA + (s * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);
                else
                    memcpy(data, keyB + (s * MIFARE_KEY_SIZE), MIFARE_KEY_SIZE);

                PrintAndLogEx(INFO, " %3d | %s" NOLF, mfFirstBlockOfSector(s) + b, sprint_hex(data + 10, MFBLOCK_SIZE));
                clearCommandBuffer();
                SendCommandMIX(CMD_HF_MIFARE_WRITEBL, mfFirstBlockOfSector(s) + b, kt, 0, data, sizeof(data));
                PacketResponseNG resp;
                if (WaitForResponseTimeout(CMD_ACK, &resp, 1500)) {
                    int8_t isOK = resp.oldarg[0];
                    if (isOK == 1) {
                        PrintAndLogEx(NORMAL, "- key %c ( " _GREEN_("ok") " )", (kt == MF_KEY_A) ? 'A' : 'B');
                        break;
                    } else {
                        PrintAndLogEx(NORMAL, "- key %c ( " _RED_("fail") " )", (kt == MF_KEY_A) ? 'A' : 'B');
                    }
                } else {
                    PrintAndLogEx(WARNING, "command execution time out");
                }
            }
        }
    }

    PrintAndLogEx(INFO, "-----+------------------------------------------------------------");
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "Done!");
out:
    free(keys);
    return PM3_SUCCESS;
}

static int CmdHF14AMfView(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf view",
                  "Print a MIFARE Classic dump file (bin/eml/json)",
                  "hf mf view -f hf-mf-01020304-dump.bin"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_lit0(NULL, "sk", "Save extracted keys to binary file"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);
    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 1), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);
    bool verbose = arg_get_lit(ctx, 2);
    bool save_keys = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // read dump file
    uint8_t *dump = NULL;
    size_t bytes_read = 0;
    int res = pm3_load_dump(filename, (void **)&dump, &bytes_read, MIFARE_4K_MAX_BYTES);
    if (res != PM3_SUCCESS) {
        return res;
    }

    uint16_t block_cnt = MIN(MIFARE_1K_MAXBLOCK, (bytes_read / MFBLOCK_SIZE));
    if (bytes_read == MIFARE_MINI_MAX_BYTES)
        block_cnt = MIFARE_MINI_MAXBLOCK;
    else if (bytes_read == MIFARE_1K_EV1_MAX_BYTES)
            block_cnt = MIFARE_1K_EV1_MAXBLOCK;
    else if (bytes_read == MIFARE_2K_MAX_BYTES)
        block_cnt = MIFARE_2K_MAXBLOCK;
    else if (bytes_read == MIFARE_4K_MAX_BYTES)
        block_cnt = MIFARE_4K_MAXBLOCK;

    if (verbose) {
        PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, block_cnt, block_cnt);
    }

    mf_print_blocks(block_cnt, dump, verbose);

    if (verbose) {
        mf_print_keys(block_cnt, dump);
        mf_analyse_acl(block_cnt, dump);
    }

    if (save_keys) {
        mf_save_keys_from_arr(block_cnt, dump);
    }

    int sector = DetectHID(dump, 0x4910);
    if (sector > -1) {
        // decode it
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, _CYAN_("VIGIK PACS detected"));

        // decode MAD v1
        uint16_t mad[7 + 8 + 8 + 8 + 8] = {0};
        size_t madlen = 0;
        res = MADDecode(dump, NULL, mad, &madlen, false);
        if (res != PM3_SUCCESS) {
            PrintAndLogEx(ERR, "can't decode MAD");
            return res;
        }

        typedef union UDATA {
            uint8_t *bytes;
            mfc_vigik_t *vigik;
        } UDATA;
        // allocate memory
        UDATA d;
        d.bytes = calloc(bytes_read, sizeof(uint8_t));
        if (d.bytes == NULL) {
            return PM3_EMALLOC;
        }
        uint16_t dlen = 0;

        // vigik struture sector 0
        uint8_t *pdump = dump;

        memcpy(d.bytes + dlen, pdump, MFBLOCK_SIZE * 3);
        dlen += MFBLOCK_SIZE * 3;
        pdump += (MFBLOCK_SIZE * 4);  // skip sectortrailer

        // extract memory from MAD sectors
        for (int i = 0; i <= madlen; i++) {
            if (0x4910 == mad[i] || 0x4916 == mad[i]) {
                memcpy(d.bytes + dlen, pdump, MFBLOCK_SIZE * 3);
                dlen += MFBLOCK_SIZE * 3;
            }

            pdump += (MFBLOCK_SIZE * 4);  // skip sectortrailer
        }

//          convert_mfc_2_arr(pdump, bytes_read, d, &dlen);
        vigik_annotate(d.vigik);
        free(d.bytes);
    }

    free(dump);
    return PM3_SUCCESS;
}

static int parse_gtu_cfg(uint8_t *d, size_t n) {

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "---------- " _CYAN_("GTU Gen4 Configuration") " -------------------------------------");
    if (n != 30 && n != 32) {
        PrintAndLogEx(INFO, "%s", sprint_hex_inrow(d, n));
        PrintAndLogEx(INFO, "%zu bytes", n);
        PrintAndLogEx(WARNING, "Unknown config format");
        return PM3_SUCCESS;
    }

    PrintAndLogEx(INFO, _YELLOW_("%s"), sprint_hex_inrow(d, n));
    PrintAndLogEx(INFO, "%zu bytes", n);
    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_("Config 1 - UID & modes"));
    PrintAndLogEx(INFO, "%s", sprint_hex_inrow(d, 8));
    PrintAndLogEx(INFO, "%02X.............. " NOLF, d[0]);
    bool is_ul_enabled = (d[0] == 1);
    switch (d[0]) {
        case 0x00:
            PrintAndLogEx(NORMAL, "MIFARE Classic mode");
            break;
        case 0x01:
            PrintAndLogEx(NORMAL, "MIFARE Ultralight/NTAG mode");
            break;
        default:
            PrintAndLogEx(NORMAL, _RED_("unknown"));
            break;
    }

    PrintAndLogEx(INFO, "..%02X............ UID " NOLF, d[1]);

    switch (d[1]) {
        case 0x00:
            PrintAndLogEx(NORMAL, _GREEN_("4") " byte");
            break;
        case 0x01:
            PrintAndLogEx(NORMAL, _GREEN_("7") " byte");
            break;
        case 0x02:
            PrintAndLogEx(NORMAL, _GREEN_("10") " byte");
            break;
        default:
            PrintAndLogEx(NORMAL, _RED_("unknown"));
            break;
    }

    PrintAndLogEx(INFO, "...." _YELLOW_("%s") ".... " _YELLOW_("Password"), sprint_hex_inrow(&d[2], 4));
    PrintAndLogEx(INFO, "............%02X.. GTU mode " NOLF, d[6]);
    switch (d[6]) {
        case 0x00:
            PrintAndLogEx(NORMAL, _GREEN_("pre-write") " - shadow data can be written");
            break;
        case 0x01:
            PrintAndLogEx(NORMAL, _GREEN_("restore mode"));
            break;
        case 0x02:
            PrintAndLogEx(NORMAL, "disabled");
            break;
        case 0x03:
            PrintAndLogEx(NORMAL, "disabled, high speed R/W mode for Ultralight ?");
            break;
        default:
            PrintAndLogEx(NORMAL, _RED_("unknown"));
            break;
    }

    uint8_t atslen = d[7];
    if (atslen == 0) {
        PrintAndLogEx(INFO, "..............%02X ATS length %u bytes ( %s )", d[7], atslen, _YELLOW_("zero"));
    } else if (atslen <= 16) {
        PrintAndLogEx(INFO, "..............%02X ATS length %u bytes ( %s )", d[7], atslen, _GREEN_("ok"));
    } else {
        PrintAndLogEx(INFO, "..............%02X ATS length %u bytes ( %s )", d[7], atslen, _RED_("fail"));
        atslen = 0;
    }

    PrintAndLogEx(INFO, "");

    // ATS seems to have 16 bytes reserved
    PrintAndLogEx(INFO, _CYAN_("Config 2 - ATS"));
    PrintAndLogEx(INFO, "%s", sprint_hex_inrow(d + 8, 16));
    if ((atslen > 0) && (atslen <= 16)) {
        PrintAndLogEx(INFO, "%s.............. ATS ( %d bytes )", sprint_hex_inrow(&d[8], d[7]), d[7]);
        PrintAndLogEx(INFO, "..................%s Reserved for ATS", sprint_hex_inrow(d + 8 + d[7], 16 - d[7]));
    } else {
        PrintAndLogEx(INFO, "%s.............. %u Reserved for ATS", sprint_hex_inrow(&d[8], 16), 16);
    }

    PrintAndLogEx(INFO, "");
    PrintAndLogEx(INFO, _CYAN_("Config 3 - Limits"));
    PrintAndLogEx(INFO, "%s", sprint_hex_inrow(d + 24, (n - 24)));
    PrintAndLogEx(INFO, "%02X%02X............ ATQA", d[24], d[25]);
    PrintAndLogEx(INFO, "....%02X.......... SAK", d[26]);
    PrintAndLogEx(INFO, "......%02X........ " NOLF, d[27]);
    switch (d[27]) {
        case 0x00:
            PrintAndLogEx(NORMAL, "%s", (is_ul_enabled) ? _GREEN_("Ultralight EV1")  : "Ultralight Ev1");
            break;
        case 0x01:
            PrintAndLogEx(NORMAL, "%s", (is_ul_enabled) ? _GREEN_("NTAG")  : "NTAG");
            break;
        case 0x02:
            PrintAndLogEx(NORMAL, "%s", (is_ul_enabled) ? _GREEN_("Ultralight C")  : "Ultralight C");
            break;
        case 0x03:
            PrintAndLogEx(NORMAL, "%s", (is_ul_enabled) ? _GREEN_("Ultralight")  : "Ultralight");
            break;
        default:
            PrintAndLogEx(NORMAL, _RED_("unknown"));
            break;
    }

    PrintAndLogEx(INFO, "........%02X...... Max R/W sectors", d[28]);
    PrintAndLogEx(INFO, "..........%02X.... " NOLF, d[29]);
    switch (d[29]) {
        case 0x00:
            PrintAndLogEx(NORMAL, _GREEN_("CUID enabled"));
            break;
        case 0x01:
            PrintAndLogEx(NORMAL, "CUID disabled");
            break;
        case 0x02:
            PrintAndLogEx(NORMAL, "Default value. Same behaviour as 00?");
            break;
        default:
            PrintAndLogEx(NORMAL, _RED_("unknown"));
            break;
    }
    PrintAndLogEx(INFO, "............%s unknown", sprint_hex_inrow(d + 30, n - 30));
    PrintAndLogEx(INFO, "");
    return PM3_SUCCESS;
}

// info about Gen4 GTU card
static int CmdHF14AGen4Info(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ginfo",
                  "Read info about magic gen4 GTU card.",
                  "hf mf ginfo                  --> get info with default password 00000000\n"
                  "hf mf ginfo --pwd 01020304   --> get info with password\n"
                  "hf mf ginfo -d 00000000000002090978009102BDAC19131011121314151604001800FF0002FD -v --> decode config block"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0("v", "verbose", "verbose output"),
        arg_str0("p", "pwd", "<hex>", "password 4 bytes"),
        arg_str0("d", "data", "<hex>", "config bytes 32 bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, true);
    bool verbose = arg_get_lit(ctx, 1);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 2, pwd, &pwd_len);

    int dlen = 0;
    uint8_t data[32] = {0};
    CLIGetHexWithReturn(ctx, 3, data, &dlen);
    CLIParserFree(ctx);

    if (pwd_len != 0 && pwd_len != 4) {
        PrintAndLogEx(FAILED, "Password must be 4 bytes length, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    uint8_t resp[40] = {0};
    size_t resplen = 0;
    int res = 0;

    if (dlen == 0) {
        if (IfPm3Iso14443a()) {
            res = mfG4GetConfig(pwd, resp, &resplen, verbose);
            if (res != PM3_SUCCESS || resplen == 0) {
                if (res == PM3_ETIMEOUT)
                    PrintAndLogEx(ERR, "No card in the field or card command timeout.");
                else
                    PrintAndLogEx(ERR, "Error get config. Maybe not a Gen4 card?. error=%d rlen=%zu", res, resplen);
                return PM3_ESOFT;
            }
        } else {
            PrintAndLogEx(ERR, "Offline mode, please provide data");
            return PM3_ESOFT;
        }
    } else if (dlen != 32) {
        PrintAndLogEx(FAILED, "Data must be 32 bytes length, got " _YELLOW_("%u"), dlen);
        return PM3_EINVARG;
    } else {
        memcpy(resp, data, dlen);
        resplen = 32;
    }

    parse_gtu_cfg(resp, resplen);
    if (! IfPm3Iso14443a()) {
        return PM3_SUCCESS;
    }

    uint8_t uid_len = resp[1];

    res = mfG4GetFactoryTest(pwd, resp, &resplen, false);
    if (res == PM3_SUCCESS && resplen > 2) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, _CYAN_("Factory test"));
        if (verbose) {
            PrintAndLogEx(INFO, "Raw......... %s", sprint_hex_inrow(resp, resplen));
        }

        if (memcmp(resp + resplen - 2, "\x66\x66", 2) == 0) {
            PrintAndLogEx(INFO, "Card type... Generic");

        } else if (memcmp(resp + resplen - 2, "\x02\xAA", 2) == 0) {
            PrintAndLogEx(INFO, "Card type... " _RED_("Limited functionality"));

        } else if (memcmp(resp + resplen - 2, "\x03\xA0", 2) == 0) {
            PrintAndLogEx(INFO, "Card type... Old card version");

        } else if (memcmp(resp + resplen - 2, "\x06\xA0", 2) == 0) {
            PrintAndLogEx(INFO, "Card type... " _GREEN_("New card version"));

        } else {
            PrintAndLogEx(INFO, "Card type... " _RED_("unknown %02X%02X"), resp[resplen - 2], resp[resplen - 1]);
        }
    }

    // read block 0
    res = mfG4GetBlock(pwd, 0, resp, MAGIC_INIT | MAGIC_OFF);
    if (res == PM3_SUCCESS) {
        PrintAndLogEx(INFO, "");
        PrintAndLogEx(INFO, _CYAN_("Block 0 test"));
        PrintAndLogEx(INFO, "Block 0..... %s", sprint_hex_inrow(resp, 16));

        switch (uid_len) {
            case 0x00:
                PrintAndLogEx(INFO, "UID [4]..... %s", sprint_hex_inrow(resp, 4));
                break;
            case 0x01:
                PrintAndLogEx(INFO, "UID [7]..... %s", sprint_hex_inrow(resp, 7));
                break;
            case 0x02:
                PrintAndLogEx(INFO, "UID [10..... %s", sprint_hex_inrow(resp, 10));
                break;
            default:
                break;
        }
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

// Read block from Gen4 GTU card
static int CmdHF14AGen4GetBlk(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf ggetblk",
                  "Get block data from magic gen4 GTU card.",
                  "hf mf ggetblk --blk 0      --> get block 0 (manufacturer)\n"
                  "hf mf ggetblk --blk 3 -v   --> get block 3, decode sector trailer\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b",  "blk", "<dec>", "block number"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_str0("p", "pwd", "<hex>", "password 4bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);
    int b = arg_get_int_def(ctx, 1, 0);
    bool verbose = arg_get_lit(ctx, 2);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 3, pwd, &pwd_len);
    CLIParserFree(ctx);

    //validate args
    if (b > MIFARE_4K_MAXBLOCK) {
        return PM3_EINVARG;
    }

    if (pwd_len != 4 && pwd_len != 0) {
        PrintAndLogEx(FAILED, "Must specify 4 bytes, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    uint8_t blockno = (uint8_t)b;
    uint8_t data[16] = {0};

    PrintAndLogEx(NORMAL, "Block: %x", blockno) ;

    int res = mfG4GetBlock(pwd, blockno, data, MAGIC_INIT | MAGIC_OFF);
    if (res) {
        PrintAndLogEx(ERR, "Can't read block. error=%d", res);
        return PM3_ESOFT;
    }

    uint8_t sector = mfSectorNum(blockno);
    mf_print_sector_hdr(sector);
    mf_print_block_one(blockno, data, verbose);

    if (verbose) {
        decode_print_st(blockno, data);
    } else {
        PrintAndLogEx(NORMAL, "");
    }

    return PM3_SUCCESS;
}

// Load dump to Gen4 GTU card
static int CmdHF14AGen4Load(const char *cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gload",
                  "Load magic gen4 gtu card with data from (bin/eml/json) dump file\n"
                  "or from emulator memory.",
                  "hf mf gload --emu\n"
                  "hf mf gload -f hf-mf-01020304.eml\n"
                  "hf mf gload -p AABBCCDD --4k -v -f hf-mf-01020304-dump.bin\n"
                  "\n"
                  "Card must be configured beforehand with `script run hf_mf_ultimatecard`.\n"
                  "Blocks are 16 bytes long."
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_str0("p", "pwd", "<hex>", "password 4bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0(NULL, "emu", "from emulator memory"),
        arg_int0(NULL, "start", "<dec>", "index of block to start writing (default 0)"),
        arg_int0(NULL, "end", "<dec>", "index of block to end writing (default last block)"),
        arg_param_end
    };

    CLIExecWithReturn(ctx, cmd, argtable, false);
    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m4 = arg_get_lit(ctx, 4);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 5, pwd, &pwd_len);

    bool verbose = arg_get_lit(ctx, 6);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 7), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool fill_from_emulator = arg_get_lit(ctx, 8);

    int start = arg_get_int_def(ctx, 9, 0);
    int end = arg_get_int_def(ctx, 10, -1);

    CLIParserFree(ctx);

    // validations
    if (pwd_len != 4 && pwd_len != 0) {
        PrintAndLogEx(FAILED, "Must specify 4 bytes, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    char s[6];
    memset(s, 0, sizeof(s));
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
        strncpy(s, "Mini", 5);
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
        strncpy(s, "1K", 3);
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
        strncpy(s, "2K", 3);
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
        strncpy(s, "4K", 3);
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    if (fill_from_emulator && (fnlen != 0)) {
        PrintAndLogEx(WARNING, "Please specify file or emulator memory, but not both");
        return PM3_EINVARG;
    }

    if (!fill_from_emulator && (fnlen == 0)) {
        PrintAndLogEx(WARNING, "Please specify file or emulator memory");
        return PM3_EINVARG;
    }

    if (end == -1) {
        end = block_cnt - 1;
    }

    if (start < 0 || end < 0) {
        PrintAndLogEx(WARNING, "start and end must be positive integers");
        return PM3_EINVARG ;
    }

    if (start > end) {
        PrintAndLogEx(WARNING, "start cannot be more than end");
        return PM3_EINVARG ;
    }

    if (start >= block_cnt) {
        PrintAndLogEx(WARNING, "Last block for Mifare %s is %d. Start is too high.", s, block_cnt - 1) ;
        return PM3_EINVARG ;
    }

    if (end >= block_cnt) {
        PrintAndLogEx(WARNING, "Last block for Mifare %s is %d. End is too high.", s, block_cnt - 1) ;
        return PM3_EINVARG ;
    }

    uint8_t *data = NULL;
    size_t bytes_read = 0;

    if (fill_from_emulator) {
        data = calloc(block_cnt * MFBLOCK_SIZE, sizeof(uint8_t));
        if (data == NULL) {
            PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
            return PM3_EMALLOC;
        }

        PrintAndLogEx(INFO, "downloading emulator memory");
        if (GetFromDevice(BIG_BUF_EML, data, block_cnt * MFBLOCK_SIZE, 0, NULL, 0, NULL, 2500, false) == false) {
            PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
            free(data);
            return PM3_ETIMEOUT;
        }

    } else {
        // read from file
        int res = pm3_load_dump(filename, (void **)&data, &bytes_read, (MFBLOCK_SIZE * MIFARE_4K_MAXBLOCK));
        if (res != PM3_SUCCESS) {
            return res;
        }

        // check file size corresponds to card size.
        if (bytes_read != (block_cnt * MFBLOCK_SIZE))  {
            PrintAndLogEx(ERR, "File content error. Read %zu bytes, expected %i", bytes_read, block_cnt * MFBLOCK_SIZE);
            if (data != NULL) free(data);
            return PM3_EFILE;
        }
    }

    if (verbose) {
        if (fnlen != 0) {
            PrintAndLogEx(INFO, "File: " _YELLOW_("%s"), filename);
            PrintAndLogEx(INFO, "File size %zu bytes, file blocks %d (0x%x)", bytes_read, block_cnt, block_cnt);
        } else {
            PrintAndLogEx(INFO, "Read %d blocks from emulator memory", block_cnt);
        }
    }

    PrintAndLogEx(INFO, "Copying to magic gen4 GTU MIFARE Classic " _GREEN_("%s"), s);
    PrintAndLogEx(INFO, "Starting block: %d. Ending block: %d.", start, end);

    // copy to card
    for (uint16_t blockno = start; blockno <= end; blockno++) {

        // 4k writes can be long, so we split status each 64 block boundary.
        if (blockno % 64 == 0 || blockno == start) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "" NOLF) ;
        }
        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);

        // write block
        uint8_t flags = 0 ;
        if (blockno == start) flags |= MAGIC_INIT ;
        if (blockno == end)   flags |= MAGIC_OFF ;

        int res = mfG4SetBlock(pwd, blockno, data + (blockno * MFBLOCK_SIZE), flags);
        if (res !=  PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Can't set magic card block: %d. error=%d", blockno, res);
            PrintAndLogEx(HINT, "Verify your card size, and try again or try another tag position");
            free(data);
            return PM3_ESOFT;
        }
    }
    PrintAndLogEx(NORMAL, "\n");

    if (data != NULL) free(data);

    PrintAndLogEx(SUCCESS, "Card loaded " _YELLOW_("%d") " blocks from %s", end - start + 1,
                  (fill_from_emulator ? "emulator memory" : "file"));
    PrintAndLogEx(INFO, "Done!");
    return PM3_SUCCESS;
}

// Write block to Gen4 GTU card
static int CmdHF14AGen4SetBlk(const char *cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gsetblk",
                  "Set block data on a magic gen4 GTU card",
                  "hf mf gsetblk --blk 1 -d 000102030405060708090a0b0c0d0e0f"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1("b", "blk", "<dec>", "block number"),
        arg_str0("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_str0("p", "pwd", "<hex>", "password 4bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, cmd, argtable, false);

    int b = arg_get_int_def(ctx, 1, -1);

    uint8_t data[MFBLOCK_SIZE] = {0x00};
    int datalen = 0;
    CLIGetHexWithReturn(ctx, 2, data, &datalen);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 3, pwd, &pwd_len);

    CLIParserFree(ctx);

    // validations
    if (pwd_len != 4 && pwd_len != 0) {
        PrintAndLogEx(FAILED, "Must specify 4 bytes, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    CLIParserFree(ctx);

    if (b < 0 ||  b >= MIFARE_4K_MAXBLOCK) {
        PrintAndLogEx(FAILED, "target block number out-of-range, got %i", b);
        return PM3_EINVARG;
    }

    if (datalen != MFBLOCK_SIZE) {
        PrintAndLogEx(FAILED, "expected 16 bytes data, got %i", datalen);
        return PM3_EINVARG;
    }

    // write block
    PrintAndLogEx(INFO, "Writing block number:%2d data:%s", b, sprint_hex_inrow(data, sizeof(data)));

    uint8_t blockno = (uint8_t)b;
    int res = mfG4SetBlock(pwd, blockno, data, MAGIC_INIT | MAGIC_OFF);
    if (res) {
        PrintAndLogEx(ERR, "Can't write block. error=%d", res);
        return PM3_ESOFT;
    }

    return PM3_SUCCESS;
}

static int CmdHF14AGen4View(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gview",
                  "View `magic gen4 gtu` card memory",
                  "hf mf gview\n"
                  "hf mf gview --4k"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_str0("p", "pwd", "<hex>", "password 4bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m4 = arg_get_lit(ctx, 4);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 5, pwd, &pwd_len);

    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    // validations
    if (pwd_len != 4 && pwd_len != 0) {
        PrintAndLogEx(FAILED, "Must specify 4 bytes, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    char s[6];
    memset(s, 0, sizeof(s));
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
        strncpy(s, "Mini", 5);
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
        strncpy(s, "1K", 3);
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
        strncpy(s, "2K", 3);
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
        strncpy(s, "4K", 3);
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }
    PrintAndLogEx(SUCCESS, "View magic gen4 GTU MIFARE Classic " _GREEN_("%s"), s);

    // reserve memory
    uint16_t bytes = block_cnt * MFBLOCK_SIZE;
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    for (uint16_t i = 0; i < block_cnt; i++) {

        uint8_t flags = 0 ;
        if (i == 0)            flags |= MAGIC_INIT ;
        if (i + 1 == block_cnt)  flags |= MAGIC_OFF ;

        int res = mfG4GetBlock(pwd, i, dump + (i * MFBLOCK_SIZE), flags);
        if (res !=  PM3_SUCCESS) {
            PrintAndLogEx(WARNING, "Can't get magic card block: %u. error=%d", i, res);
            PrintAndLogEx(HINT, "Verify your card size, and try again or try another tag position");
            free(dump);
            return PM3_ESOFT;
        }

        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
        // 4k READs can be long, so we split status each 64 blocks.
        if (i % 64 == 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "" NOLF) ;
        }
    }

    PrintAndLogEx(NORMAL, "");
    mf_print_blocks(block_cnt, dump, verbose);

    if (verbose) {
        mf_print_keys(block_cnt, dump);
    }

    free(dump);
    return PM3_SUCCESS;
}

// save contents of Gent4 GTU card to file / emulator
static int CmdHF14AGen4Save(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gsave",
                  "Save `magic gen4 gtu` card memory to file (bin/json)"
                  "or into emulator memory",
                  "hf mf gsave\n"
                  "hf mf gsave --4k\n"
                  "hf mf gsave -p DEADBEEF -f hf-mf-01020304.json"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_lit0(NULL, "mini", "MIFARE Classic Mini / S20"),
        arg_lit0(NULL, "1k", "MIFARE Classic 1k / S50 (def)"),
        arg_lit0(NULL, "2k", "MIFARE Classic/Plus 2k"),
        arg_lit0(NULL, "4k", "MIFARE Classic 4k / S70"),
        arg_str0("p", "pwd", "<hex>", "password 4 bytes"),
        arg_str0("f", "file", "<fn>", "Specify a filename for dump file"),
        arg_lit0(NULL, "emu", "to emulator memory"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool m0 = arg_get_lit(ctx, 1);
    bool m1 = arg_get_lit(ctx, 2);
    bool m2 = arg_get_lit(ctx, 3);
    bool m4 = arg_get_lit(ctx, 4);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 5, pwd, &pwd_len);

    int fnlen = 0;
    char filename[FILE_PATH_SIZE];
    CLIParamStrToBuf(arg_get_str(ctx, 6), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    bool fill_emulator = arg_get_lit(ctx, 7);
    CLIParserFree(ctx);

    // ICEMAN:  bug.  if device has been using ICLASS commands,
    // the device needs to load the HF fpga image. It takes 1.5 second.
    set_fpga_mode(FPGA_BITSTREAM_HF);

    // validations
    if (pwd_len != 4 && pwd_len != 0) {
        PrintAndLogEx(FAILED, "Must specify 4 bytes, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    if ((m0 + m1 + m2 + m4) > 1) {
        PrintAndLogEx(WARNING, "Only specify one MIFARE Type");
        return PM3_EINVARG;
    } else if ((m0 + m1 + m2 + m4) == 0) {
        m1 = true;
    }

    char s[6];
    memset(s, 0, sizeof(s));
    uint16_t block_cnt = MIFARE_1K_MAXBLOCK;
    if (m0) {
        block_cnt = MIFARE_MINI_MAXBLOCK;
        strncpy(s, "Mini", 5);
    } else if (m1) {
        block_cnt = MIFARE_1K_MAXBLOCK;
        strncpy(s, "1K", 3);
    } else if (m2) {
        block_cnt = MIFARE_2K_MAXBLOCK;
        strncpy(s, "2K", 3);
    } else if (m4) {
        block_cnt = MIFARE_4K_MAXBLOCK;
        strncpy(s, "4K", 3);
    } else {
        PrintAndLogEx(WARNING, "Please specify a MIFARE Type");
        return PM3_EINVARG;
    }

    // Select card to get UID/UIDLEN information
    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return PM3_ETIMEOUT;
    }

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];
    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return PM3_SUCCESS;
    }

    // store card info
    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    // reserve memory
    uint16_t bytes = block_cnt * MFBLOCK_SIZE;
    uint8_t *dump = calloc(bytes, sizeof(uint8_t));
    if (dump == NULL) {
        PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
        return PM3_EMALLOC;
    }

    PrintAndLogEx(SUCCESS, "Dumping magic gen4 GTU MIFARE Classic " _GREEN_("%s") " card memory", s);
    PrintAndLogEx(INFO, "." NOLF);

    for (uint16_t i = 0; i < block_cnt; i++) {
        uint8_t flags = 0 ;
        if (i == 0) {
            flags |= MAGIC_INIT;
        }
        if (i + 1 == block_cnt) {
            flags |= MAGIC_OFF;
        }

        int res = mfG4GetBlock(pwd, i, dump + (i * MFBLOCK_SIZE), flags);
        if (res !=  PM3_SUCCESS) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(WARNING, "Can't get magic card block: %u. error=%d", i, res);
            PrintAndLogEx(HINT, "Verify your card size, and try again or try another tag position");
            free(dump);
            return PM3_ESOFT;
        }


        PrintAndLogEx(NORMAL, "." NOLF);
        fflush(stdout);
        // 4k READs can be long, so we split status each 64 blocks.
        if (i % 64 == 0 && i != 0) {
            PrintAndLogEx(NORMAL, "");
            PrintAndLogEx(INFO, "" NOLF) ;
        }
    }

    PrintAndLogEx(NORMAL, "");

    if (fill_emulator) {
        PrintAndLogEx(INFO, "uploading to emulator memory");
        PrintAndLogEx(INFO, "." NOLF);
        // fast push mode
        g_conn.block_after_ACK = true;

        size_t offset = 0;
        int cnt = 0;
        uint16_t bytes_left = bytes ;

        // 12 is the size of the struct the fct mf_eml_set_mem_xt uses to transfer to device
        uint16_t max_avail_blocks = ((PM3_CMD_DATA_SIZE - 12) / MFBLOCK_SIZE) * MFBLOCK_SIZE;

        while (bytes_left > 0 && cnt < block_cnt) {
            if (bytes_left == MFBLOCK_SIZE) {
                // Disable fast mode on last packet
                g_conn.block_after_ACK = false;
            }

            uint16_t chunk_size = MIN(max_avail_blocks, bytes_left);
            uint16_t blocks_to_send = chunk_size / MFBLOCK_SIZE;

            if (mf_eml_set_mem_xt(dump + offset, cnt, blocks_to_send, MFBLOCK_SIZE) != PM3_SUCCESS) {
                PrintAndLogEx(FAILED, "Can't set emulator mem at block: %3d", cnt);
                free(dump);
                return PM3_ESOFT;
            }

            cnt += blocks_to_send;
            offset += chunk_size;
            bytes_left -= chunk_size;
            PrintAndLogEx(NORMAL, "." NOLF);
            fflush(stdout);
        }

        PrintAndLogEx(NORMAL, "");
        PrintAndLogEx(SUCCESS, "uploaded " _YELLOW_("%d") " bytes to emulator memory", bytes);
    }

    // user supplied filename?
    if (fnlen < 1) {
        char *fptr = filename;
        fptr += snprintf(fptr, sizeof(filename), "hf-mf-");
        FillFileNameByUID(fptr, card.uid, "-dump", card.uidlen);
    }

    pm3_save_mf_dump(filename, dump, bytes, jsfCardMemory);
    free(dump);
    return PM3_SUCCESS;
}

// change Gent4 GTU card access password
static int CmdHF14AGen4ChangePwd(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gchpwd",
                  "Change access password for Gen4 GTU card. WARNING! If you dont KNOW the password - you CAN'T access it!!!",
                  "hf mf gchpwd --pwd 00000000 --newpwd 01020304"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("p", "pwd", "<hex>", "password 4 bytes"),
        arg_str0("n", "newpwd", "<hex>", "new password 4 bytes"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int pwd_len = 0;
    uint8_t pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 1, pwd, &pwd_len);

    int new_pwd_len = 0;
    uint8_t new_pwd[4] = {0};
    CLIGetHexWithReturn(ctx, 2, new_pwd, &new_pwd_len);

    bool verbose = arg_get_lit(ctx, 3);

    CLIParserFree(ctx);

    if (pwd_len != 4) {
        PrintAndLogEx(FAILED, "Old password must be 4 bytes long, got " _YELLOW_("%u"), pwd_len);
        return PM3_EINVARG;
    }

    if (new_pwd_len != 4) {
        PrintAndLogEx(FAILED, "New password must be 4 bytes long, got " _YELLOW_("%u"), new_pwd_len);
        return PM3_EINVARG;
    }

    int res = mfG4ChangePassword(pwd, new_pwd, verbose);
    if (res != PM3_SUCCESS) {
        PrintAndLogEx(ERR, "Change password error");
        return res;
    }

    PrintAndLogEx(SUCCESS, "Change password ( " _GREEN_("ok") " )");
    return PM3_SUCCESS;
}

static void parse_gdm_cfg(const uint8_t *d) {
    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(SUCCESS, "------------------- " _CYAN_("GDM Gen4 Configuration") " -----------------------------------------");
    PrintAndLogEx(SUCCESS,  _YELLOW_("%s"), sprint_hex_inrow(d, MFBLOCK_SIZE));
    PrintAndLogEx(SUCCESS,  _YELLOW_("%02X%02X") "............................ %s %s"
                  , d[0]
                  , d[1]
                  , (d[0] == 0x85 && d[1] == 0x00) ? "Magic wakeup disabled" : _GREEN_("Magic wakeup enabled")
                  , (d[0] == 0x85 && d[1] == 0x00) ? "" : ((d[0] == 0x7A && d[1] == 0xFF) ? _GREEN_("with GDM cfg block access") : _RED_(", no GDM cfg block access"))
                 );
    PrintAndLogEx(SUCCESS, "...." _YELLOW_("%02X") ".......................... Magic wakeup style " _YELLOW_("%s"), d[2], ((d[2] == 0x85) ? "GDM 20(7)/23" : "Gen1a 40(7)/43"));
    PrintAndLogEx(SUCCESS, "......" _YELLOW_("%02X%02X%02X") ".................... unknown", d[3], d[4], d[5]);
    PrintAndLogEx(SUCCESS, "............" _YELLOW_("%02X") ".................. %s", d[6], (d[6] == 0x5A) ? "Key B use blocked when readable by ACL" : "Key B use allowed when readable by ACL");
    PrintAndLogEx(SUCCESS, ".............." _YELLOW_("%02X") "................ %s", d[7], (d[7] == 0x5A) ? _GREEN_("CUID enabled") : "CUID Disabled");
    PrintAndLogEx(SUCCESS, "................" _YELLOW_("%02X") ".............. n/a", d[8]);

    const char *pers;
    switch (d[9]) {
        case 0x5A:
            pers = _YELLOW_("Unfused");
            break;
        case 0xC3:
            pers = _CYAN_("UIDFO, double size UID");
            break;
        case 0xA5:
            pers = _CYAN_("UIDF1, double size UID, optional usage of selection process shortcut");
            break;
        case 0x87:
            pers = _GREEN_("UIDF2, single size random ID");
            break;
        case 0x69:
            pers = _GREEN_("UIDF3, single size NUID");
            break;
        default:
            pers = "4B UID from Block 0";
            break;
    }
    PrintAndLogEx(SUCCESS, ".................." _YELLOW_("%02X") "............ MFC EV1 perso. " _YELLOW_("%s"), d[9], pers);
    PrintAndLogEx(SUCCESS, "...................." _YELLOW_("%02X") ".......... %s", d[10], (d[10] == 0x5A) ? _GREEN_("Shadow mode enabled") : "Shadow mode disabled");
    PrintAndLogEx(SUCCESS, "......................" _YELLOW_("%02X") "........ %s", d[11], (d[11] == 0x5A) ? _GREEN_("Magic auth enabled") : "Magic auth disabled");
    PrintAndLogEx(SUCCESS, "........................" _YELLOW_("%02X") "...... %s", d[12], (d[12] == 0x5A) ? _GREEN_("Static encrypted nonce enabled") : "Static encrypted nonce disabled");
    PrintAndLogEx(SUCCESS, ".........................." _YELLOW_("%02X") ".... %s", d[13], (d[13] == 0x5A) ? _GREEN_("MFC EV1 signature enabled") : "MFC EV1 signature disabled");
    PrintAndLogEx(SUCCESS, "............................" _YELLOW_("%02X") ".. n/a", d[14]);
    PrintAndLogEx(SUCCESS, ".............................." _YELLOW_("%02X") " SAK", d[15]);
    PrintAndLogEx(NORMAL, "");
}

static int CmdHF14AGen4_GDM_ParseCfg(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gdmparsecfg",
                  "Parse configuration data on a magic gen4 GDM card",
                  "hf mf gdmparsecfg -d 850000000000000000005A5A00000008"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t block[MFBLOCK_SIZE] = {0x00};
    int blen = 0;
    CLIGetHexWithReturn(ctx, 1, block, &blen);
    CLIParserFree(ctx);

    if (blen != MFBLOCK_SIZE) {
        PrintAndLogEx(WARNING, "expected %u HEX bytes. got %i", MFBLOCK_SIZE, blen);
        return PM3_EINVARG;
    }

    parse_gdm_cfg(block);

    return PM3_SUCCESS;
}

static int CmdHF14AGen4_GDM_Cfg(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gdmcfg",
                  "Get configuration data from magic gen4 GDM card.",
                  "hf mf gdmcfg\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "key 6 bytes (only for regular wakeup)"),
        arg_lit0(NULL, "gen1a", "use gen1a (40/43) magic wakeup"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);
    bool gen1a = arg_get_lit(ctx, 2);
    bool gdm = arg_get_lit(ctx, 3);
    CLIParserFree(ctx);

    // validate args
    if (keylen != 6 && keylen != 0) {
        PrintAndLogEx(FAILED, "Must specify 6 bytes, got " _YELLOW_("%u"), keylen);
        return PM3_EINVARG;
    }

    if (gen1a && gdm) {
        PrintAndLogEx(FAILED, "Can only specify a single magic wakeup command");
        return PM3_EINVARG;
    }

    if ((gen1a || gdm) && keylen != 0) {
        PrintAndLogEx(FAILED, "Cannot use a key in combination with a magic wakeup");
        return PM3_EINVARG;
    }

    mf_readblock_ex_t payload = {
        .read_cmd = MIFARE_MAGIC_GDM_READ_CFG,
        .block_no = 0,
    };
    memcpy(payload.key, key, sizeof(payload.key));

    if (gen1a) {
        payload.wakeup = MF_WAKE_GEN1A;
        payload.auth_cmd = 0;
    } else if (gdm) {
        payload.wakeup = MF_WAKE_GDM_ALT;
        payload.auth_cmd = 0;
    } else {
        payload.wakeup = MF_WAKE_WUPA;
        payload.auth_cmd = MIFARE_MAGIC_GDM_AUTH_KEY;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_READBL_EX, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_READBL_EX, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS && resp.length == MFBLOCK_SIZE) {
        parse_gdm_cfg(resp.data.asBytes);

        PrintAndLogEx(NORMAL, "");
    }

    return resp.status;
}

static int CmdHF14AGen4_GDM_SetCfg(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gdmsetcfg",
                  "Set configuration data on a magic gen4 GDM card",
                  "hf mf gdmsetcfg -d 850000000000000000005A5A00000008"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str1("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_str0("k", "key", "<hex>", "key 6 bytes (only for regular wakeup)"),
        arg_lit0(NULL, "gen1a", "use gen1a (40/43) magic wakeup"),
        arg_lit0(NULL, "gdm", "use gdm alt (20/23) magic wakeup"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t block[MFBLOCK_SIZE] = {0x00};
    int blen = 0;
    CLIGetHexWithReturn(ctx, 1, block, &blen);
    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 2, key, &keylen);
    bool gen1a = arg_get_lit(ctx, 3);
    bool gdm = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (blen != MFBLOCK_SIZE) {
        PrintAndLogEx(WARNING, "expected %u HEX bytes. got %i", MFBLOCK_SIZE, blen);
        return PM3_EINVARG;
    }

    if (keylen != 6 && keylen != 0) {
        PrintAndLogEx(FAILED, "Must specify 6 bytes, got " _YELLOW_("%u"), keylen);
        return PM3_EINVARG;
    }

    if (gen1a && gdm) {
        PrintAndLogEx(FAILED, "Can only specify a single magic wakeup command");
        return PM3_EINVARG;
    }

    if ((gen1a || gdm) && keylen != 0) {
        PrintAndLogEx(FAILED, "Cannot use a key in combination with a magic wakeup");
        return PM3_EINVARG;
    }

    mf_writeblock_ex_t payload = {
        .write_cmd = MIFARE_MAGIC_GDM_WRITE_CFG,
        .block_no = 0,
    };
    memcpy(payload.block_data, block, sizeof(payload.block_data));
    memcpy(payload.key, key, sizeof(payload.key));

    if (gen1a) {
        payload.wakeup = MF_WAKE_GEN1A;
        payload.auth_cmd = 0;
    } else if (gdm) {
        payload.wakeup = MF_WAKE_GDM_ALT;
        payload.auth_cmd = 0;
    } else {
        payload.wakeup = MF_WAKE_WUPA;
        payload.auth_cmd = MIFARE_MAGIC_GDM_AUTH_KEY;
    }

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_WRITEBL_EX, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_WRITEBL_EX, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
        PrintAndLogEx(HINT, "try `" _YELLOW_("hf mf gdmcfg") "` to verify");
    } else {
        PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AGen4_GDM_SetBlk(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf gdmsetblk",
                  "Set block data on a magic gen4 GDM card\n"
                  "`--force` param is used to override warnings like bad ACL writes.\n"
                  "          if not specified, it will exit if detected",
                  "hf mf gdmsetblk --blk 1 -d 000102030405060708090a0b0c0d0e0f"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_int1(NULL, "blk", "<dec>", "block number"),
        arg_str0("d", "data", "<hex>", "bytes to write, 16 hex bytes"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_lit0(NULL, "force", "override warnings"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int b = arg_get_int_def(ctx, 1, 1);

    uint8_t block[MFBLOCK_SIZE] = {0x00};
    int blen = 0;
    CLIGetHexWithReturn(ctx, 2, block, &blen);

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 3, key, &keylen);

    bool force = arg_get_lit(ctx, 4);
    CLIParserFree(ctx);

    if (blen != MFBLOCK_SIZE) {
        PrintAndLogEx(WARNING, "expected %u HEX bytes. got %i", MFBLOCK_SIZE, blen);
        return PM3_EINVARG;
    }

    if (b < 0 ||  b >= MIFARE_4K_MAXBLOCK) {
        PrintAndLogEx(FAILED, "target block number out-of-range, got %i", b);
        return PM3_EINVARG;
    }

    if (keylen != 6 && keylen != 0) {
        PrintAndLogEx(FAILED, "Must specify 6 bytes, got " _YELLOW_("%u"), keylen);
        return PM3_EINVARG;
    }

    uint8_t blockno = (uint8_t)b;

    if (mf_analyse_st_block(blockno, block, force) != PM3_SUCCESS) {
        return PM3_EINVARG;
    }

    PrintAndLogEx(INFO, "Writing block no %d, key %s", blockno, sprint_hex_inrow(key, sizeof(key)));
    PrintAndLogEx(INFO, "data: %s", sprint_hex(block, sizeof(block)));

    struct p {
        uint8_t blockno;
        uint8_t key[6];
        uint8_t data[MFBLOCK_SIZE]; // data to be written
    } PACKED payload;

    payload.blockno = blockno;
    memcpy(payload.key, key, sizeof(payload.key));
    memcpy(payload.data, block, sizeof(payload.data));

    clearCommandBuffer();
    SendCommandNG(CMD_HF_MIFARE_G4_GDM_WRBL, (uint8_t *)&payload, sizeof(payload));
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_HF_MIFARE_G4_GDM_WRBL, &resp, 1500) == false) {
        PrintAndLogEx(WARNING, "command execution time out");
        return PM3_ETIMEOUT;
    }

    if (resp.status == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Write ( " _GREEN_("ok") " )");
        PrintAndLogEx(HINT, "try `" _YELLOW_("hf mf rdbl") "` to verify");
    } else if (resp.status == PM3_ETEAROFF) {
        PrintAndLogEx(INFO, "Tear off triggered");
        return resp.status;
    } else {
        PrintAndLogEx(FAILED, "Write ( " _RED_("fail") " )");
    }
    return PM3_SUCCESS;
}

static int CmdHF14AMfValue(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf value",
                  "MIFARE Classic value data commands\n",
                  "hf mf value --blk 16 -k FFFFFFFFFFFF --set 1000\n"
                  "hf mf value --blk 16 -k FFFFFFFFFFFF --inc 10\n"
                  "hf mf value --blk 16 -k FFFFFFFFFFFF -b --dec 10\n"
                  "hf mf value --blk 16 -k FFFFFFFFFFFF -b --get\n"
                  "hf mf value --blk 16 -k FFFFFFFFFFFF --res --transfer 30 --tk FFFFFFFFFFFF --> transfer block 16 value to block 30 (even if block can't be incremented by ACL)\n"
                  "hf mf value --get -d 87D612007829EDFF87D6120011EE11EE\n"
                 );
    void *argtable[] = {
        arg_param_begin,
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_lit0("a", NULL, "input key type is key A (def)"),
        arg_lit0("b", NULL, "input key type is key B"),
        arg_u64_0(NULL, "inc", "<dec>", "Increment value by X (0 - 2147483647)"),
        arg_u64_0(NULL, "dec", "<dec>", "Decrement value by X (0 - 2147483647)"),
        arg_u64_0(NULL, "set", "<dec>", "Set value to X (-2147483647 - 2147483647)"),
        arg_u64_0(NULL, "transfer", "<dec>", "Transfer value to other block (after inc/dec/restore)"),
        arg_str0(NULL, "tkey", "<hex>", "transfer key, 6 hex bytes (if transfer is preformed to other sector)"),
        arg_lit0(NULL, "ta", "transfer key type is key A (def)"),
        arg_lit0(NULL, "tb", "transfer key type is key B"),
        arg_lit0(NULL, "get", "Get value from block"),
        arg_lit0(NULL, "res", "Restore (copy value to card buffer, should be used with --transfer)"),
        arg_int0(NULL, "blk", "<dec>", "block number"),
        arg_str0("d", "data", "<hex>", "block data to extract values from (16 hex bytes)"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t blockno = (uint8_t)arg_get_int_def(ctx, 13, 1);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 2) && arg_get_lit(ctx, 3)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 3)) {
        keytype = MF_KEY_B;
    }

    uint8_t transferkeytype = MF_KEY_A;
    if (arg_get_lit(ctx, 9) && arg_get_lit(ctx, 10)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single transfer key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 10)) {
        transferkeytype = MF_KEY_B;
    }

    int keylen = 0;
    uint8_t key[6] = {0};
    CLIGetHexWithReturn(ctx, 1, key, &keylen);

    int transferkeylen = 0;
    uint8_t transferkey[6] = {0};
    CLIGetHexWithReturn(ctx, 8, transferkey, &transferkeylen);

    /*
        Value    /Value   Value    BLK /BLK BLK /BLK
        00000000 FFFFFFFF 00000000 10  EF   10  EF
        BLK is used to reference where the backup come from, I suspect it's just the current block for the actual value ?
        increment and decrement are an unsigned value
        set value is a signed value

        We are getting signed and/or bigger values to allow a default to be set meaning users did not supply that option.
    */
    int64_t incval = (int64_t)arg_get_u64_def(ctx, 4, -1); // Inc by -1 is invalid, so not set.
    int64_t decval = (int64_t)arg_get_u64_def(ctx, 5, -1); // Dec by -1 is invalid, so not set.
    int64_t setval = (int64_t)arg_get_u64_def(ctx, 6, 0x7FFFFFFFFFFFFFFF);  // out of bounds (for int32) so not set
    int64_t trnval = (int64_t)arg_get_u64_def(ctx, 7, -1);  // block to transfer to
    bool getval = arg_get_lit(ctx, 11);
    bool resval = arg_get_lit(ctx, 12);
    int dlen = 0;
    uint8_t data[16] = {0};
    CLIGetHexWithReturn(ctx, 14, data, &dlen);
    CLIParserFree(ctx);

    // sanity checks


    // Action:  0 Increment, 1 - Decrement, 2 - Restore, 3 - Set, 4 - Get, 5 - Decode from data
    // iceman:  TODO - should be enum
    uint8_t action = 4;
    uint32_t value = 0;

    // Need to check we only have 1 of inc/dec/set and get the value from the selected option
    int optionsprovided = 0;

    if (incval != -1) {
        optionsprovided++;
        action = 0;
        if ((incval <= 0) || (incval > 2147483647)) {
            PrintAndLogEx(WARNING, "increment value must be between 1 and 2147483647. Got %lli", incval);
            return PM3_EINVARG;
        } else
            value = (uint32_t)incval;
    }

    if (decval != -1) {
        optionsprovided++;
        action = 1;
        if ((decval <= 0) || (decval > 2147483647)) {
            PrintAndLogEx(WARNING, "decrement value must be between 1 and 2147483647. Got %lli", decval);
            return PM3_EINVARG;
        } else
            value = (uint32_t)decval;
    }

    if (setval != 0x7FFFFFFFFFFFFFFF) {
        optionsprovided++;
        action = 3;
        if ((setval < -2147483647) || (setval > 2147483647)) {
            PrintAndLogEx(WARNING, "set value must be between -2147483647 and 2147483647. Got %lli", setval);
            return PM3_EINVARG;
        } else
            value = (uint32_t)setval;
    }

    if (resval) {
        if (trnval == -1) {
            PrintAndLogEx(WARNING, "You can't use restore without using transfer");
            return PM3_EINVARG;
        }

        optionsprovided++;
        action = 2;
    }

    if (dlen != 0)  {
        optionsprovided++;
        action = 5;
        if (dlen != 16) {
            PrintAndLogEx(WARNING, "date length must be 16 hex bytes long, got %d", dlen);
            return PM3_EINVARG;
        }
    }

    if (optionsprovided > 1) {
        PrintAndLogEx(WARNING, "must have one and only one of --inc, --dec, --set or --data");
        return PM3_EINVARG;
    }

    if (trnval != -1 && action > 2) {
        PrintAndLogEx(WARNING, "You can't use transfer without using --inc, --dec or --res");
        return PM3_EINVARG;
    }

    if (trnval != -1 && transferkeylen == 0 && mfSectorNum(trnval) != mfSectorNum(blockno)) {
        PrintAndLogEx(WARNING, "Transfer is preformed to other sector, but no key for new sector provided");
        return PM3_EINVARG;
    }

    // don't want to write value data and break something
    if ((blockno == 0) ||
            (mfIsSectorTrailer(blockno)) ||
            (trnval == 0) ||
            (trnval != -1 && mfIsSectorTrailer(trnval))) {
        PrintAndLogEx(WARNING, "invalid block number, should be a data block");
        return PM3_EINVARG;
    }

    if (action < 4) {

        uint8_t isok = true;
        if (g_session.pm3_present == false)
            return PM3_ENOTTY;

        // 0 Increment, 1 - Decrement, 2 - Restore, 3 - Set, 4 - Get, 5 - Decode from data
        if (action <= 2) {

            uint8_t block[MFBLOCK_SIZE] = {0x00};
            memcpy(block, (uint8_t *)&value, 4);

            uint8_t cmddata[34];
            memcpy(cmddata, key, sizeof(key));
            // Key == 6 data went to 10, so lets offset 9 for inc/dec

            if (action == 0) {
                PrintAndLogEx(INFO, "Value incremented by : %d", (int32_t)value);
            }
            if (action == 1) {
                PrintAndLogEx(INFO, "Value decremented by : %d", (int32_t)value);
            }

            // 00 if increment, 01 if decrement, 02 if restore
            cmddata[9] = action;

            if (trnval != -1) {

                // transfer to block
                cmddata[10] = trnval;

                memcpy(cmddata + 27, transferkey, sizeof(transferkey));
                if (mfSectorNum(trnval) != mfSectorNum(blockno)) {
                    cmddata[33] = 1; // should send nested auth
                }
                PrintAndLogEx(INFO, "Transfer block no %u to block %" PRId64, blockno, trnval);

            } else {
                cmddata[10] = 0;
                if (keytype < 2) {
                    PrintAndLogEx(INFO, "Writing block no %u, key type:%c - %s", blockno, (keytype == MF_KEY_B) ? 'B' : 'A', sprint_hex_inrow(key, sizeof(key)));
                } else {
                    PrintAndLogEx(INFO, "Writing block no %u, key type:%02x - %s", blockno, MIFARE_AUTH_KEYA + keytype, sprint_hex_inrow(key, sizeof(key)));
                }
            }

            memcpy(cmddata + 11, block, sizeof(block));

            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFARE_VALUE, blockno, keytype, transferkeytype, cmddata, sizeof(cmddata));

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
                PrintAndLogEx(FAILED, "command execution time out");
                return PM3_ETIMEOUT;
            }
            isok = resp.oldarg[0] & 0xff;
        } else { // set value
            // To set a value block (or setup) we can use the normal mifare classic write block
            // So build the command options can call CMD_HF_MIFARE_WRITEBL
            PrintAndLogEx(INFO, "set value to : %d", (int32_t)value);

            uint8_t writedata[26] = {0x00};
            int32_t invertvalue = value ^ 0xFFFFFFFF;
            memcpy(writedata, key, sizeof(key));
            memcpy(writedata + 10, (uint8_t *)&value, 4);
            memcpy(writedata + 14, (uint8_t *)&invertvalue, 4);
            memcpy(writedata + 18, (uint8_t *)&value, 4);
            writedata[22] = blockno;
            writedata[23] = (blockno ^ 0xFF);
            writedata[24] = blockno;
            writedata[25] = (blockno ^ 0xFF);

            clearCommandBuffer();
            SendCommandMIX(CMD_HF_MIFARE_WRITEBL, blockno, keytype, 0, writedata, sizeof(writedata));

            PacketResponseNG resp;
            if (WaitForResponseTimeout(CMD_ACK, &resp, 1500) == false) {
                PrintAndLogEx(FAILED, "command execution time out");
                return PM3_ETIMEOUT;
            }

            isok = resp.oldarg[0] & 0xff;
        }

        if (isok) {
            PrintAndLogEx(SUCCESS, "Update ... : " _GREEN_("success"));
            getval = true;
            // all ok so set flag to read current value
        } else {
            PrintAndLogEx(FAILED, "Update ... : " _RED_("failed"));
        }
    }

    // If all went well getval will be true, so read the current value and display
    if (getval) {
        int32_t readvalue;
        int res = -1;

        if (action == 5) {
            res = PM3_SUCCESS;
            // already have data from command line
        } else {
            if (trnval == -1) {
                res = mf_read_block(blockno, keytype, key, data);
            } else {
                if (mfSectorNum(trnval) != mfSectorNum(blockno))
                    res = mf_read_block(trnval, transferkeytype, transferkey, data);
                else
                    res = mf_read_block(trnval, keytype, key, data);
            }
        }

        if (res == PM3_SUCCESS) {
            if (mfc_value(data, &readvalue))  {
                PrintAndLogEx(SUCCESS, "Dec ...... : " _YELLOW_("%" PRIi32), readvalue);
                PrintAndLogEx(SUCCESS, "Hex ...... : " _YELLOW_("0x%" PRIX32), readvalue);
            } else {
                PrintAndLogEx(FAILED, "No value block detected");
            }
        } else {
            PrintAndLogEx(FAILED, "failed to read value block");
        }
    }

    return PM3_SUCCESS;
}

static int CmdHFMFHidEncode(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf encodehid",
                  "Encode binary wiegand to card\n"
                  "Use either --bin or --wiegand/--fc/--cn",
                  "hf mf encodehid --bin 10001111100000001010100011            -> FC 31 CN 337 (H10301)\n"
                  "hf mf encodehid -w H10301 --fc 31 --cn 337\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0(NULL, "bin", "<bin>", "Binary string i.e 0001001001"),
        arg_u64_0(NULL, "fc", "<dec>", "facility code"),
        arg_u64_0(NULL, "cn", "<dec>", "card number"),
        arg_str0("w",   "wiegand", "<format>", "see " _YELLOW_("`wiegand list`") " for available formats"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    uint8_t bin[121] = {0};
    int bin_len = sizeof(bin) - 1; // CLIGetStrWithReturn does not guarantee string to be null-terminated
    CLIGetStrWithReturn(ctx, 1, bin, &bin_len);

    wiegand_card_t card;
    memset(&card, 0, sizeof(wiegand_card_t));
    card.FacilityCode = arg_get_u32_def(ctx, 2, 0);
    card.CardNumber = arg_get_u32_def(ctx, 3, 0);

    char format[16] = {0};
    int format_len = 0;
    CLIParamStrToBuf(arg_get_str(ctx, 4), (uint8_t *)format, sizeof(format), &format_len);

    bool verbose = arg_get_lit(ctx, 5);
    CLIParserFree(ctx);

    // santity checks
    if (bin_len > 120) {
        PrintAndLogEx(ERR, "Binary wiegand string must be less than 120 bits");
        return PM3_EINVARG;
    }

    if (bin_len == 0 && card.FacilityCode == 0 && card.CardNumber == 0) {
        PrintAndLogEx(ERR, "Must provide either --cn/--fc or --bin");
        return PM3_EINVARG;
    }

    uint8_t blocks[] = {
        0x1B, 0x01, 0x4D, 0x48, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0x78, 0x77, 0x88, 0xC1, 0x89, 0xEC, 0xA9, 0x7F, 0x8C, 0x2A,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x48, 0x49, 0x44, 0x20, 0x49, 0x53, 0x78, 0x77, 0x88, 0xAA, 0x20, 0x47, 0x52, 0x45, 0x41, 0x54,
    };

    if (bin_len) {
        char mfcbin[121] = {0};
        mfcbin[0] = '1';
        memcpy(mfcbin + 1, bin, bin_len);

        size_t hexlen = 0;
        uint8_t hex[15] = {0};
        binstr_2_bytes(hex, &hexlen, mfcbin);

        memcpy(blocks + (MFBLOCK_SIZE * 4) + 1 + (15 - hexlen), hex, hexlen);
    } else {
        wiegand_message_t packed;
        memset(&packed, 0, sizeof(wiegand_message_t));

        int format_idx = HIDFindCardFormat(format);
        if (format_idx == -1) {
            PrintAndLogEx(WARNING, "Unknown format: " _YELLOW_("%s"), format);
            return PM3_EINVARG;
        }

        if (HIDPack(format_idx, &card, &packed, false) == false) {
            PrintAndLogEx(WARNING, "The card data could not be encoded in the selected format.");
            return PM3_ESOFT;
        }

        // iceman: only for formats w length smaller than 37.
        // Needs a check.

        // increase length to allow setting bit just above real data
        packed.Length++;
        // Set sentinel bit
        set_bit_by_position(&packed, true, 0);

#ifdef HOST_LITTLE_ENDIAN
        packed.Mid = BSWAP_32(packed.Mid);
        packed.Bot = BSWAP_32(packed.Bot);
#endif

        memcpy(blocks + (MFBLOCK_SIZE * 4) + 8, &packed.Mid, sizeof(packed.Mid));
        memcpy(blocks + (MFBLOCK_SIZE * 4) + 12, &packed.Bot, sizeof(packed.Bot));
    }

    uint8_t empty[MIFARE_KEY_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    bool res = true;
    for (uint8_t i = 0; i < (sizeof(blocks) / MFBLOCK_SIZE); i++) {

        if (verbose) {
            PrintAndLogEx(INFO, "Writing %u - %s", (i + 1), sprint_hex_inrow(blocks + (i * MFBLOCK_SIZE), MFBLOCK_SIZE));
        }

        if (mf_write_block((i + 1), MF_KEY_A, empty, blocks + (i * MFBLOCK_SIZE)) == PM3_EFAILED) {
            if (mf_write_block((i + 1), MF_KEY_B, empty, blocks + (i * MFBLOCK_SIZE)) == PM3_EFAILED) {
                PrintAndLogEx(WARNING, "failed writing block %d using default empty key", (i + 1));
                res = false;
                break;
            }
        }
    }
    if (res == false) {
        PrintAndLogEx(WARNING, "Make sure card is wiped before running this command");
    }
    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHF14AMfInfo(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf info",
                  "Information and check vulnerabilities in a MIFARE Classic card\n"
                  "Some cards in order to extract information you need to specify key\n"
                  "and/or specific keys in the command line",
                  "hf mf info\n"
                  "hf mf info -k FFFFFFFFFFFF -n -v\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "blk", "<dec>", "block number"),
        arg_lit0("a", NULL, "input key type is key A (def)"),
        arg_lit0("b", NULL, "input key type is key B"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_lit0("n", "nack", "do nack test"),
        arg_lit0("v", "verbose", "verbose output"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int blockn = arg_get_int_def(ctx, 1, 0);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 2) && arg_get_lit(ctx, 3)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 3)) {
        keytype = MF_KEY_B;
    }

    int keylen = 0;
    uint8_t key[100 * MIFARE_KEY_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CLIGetHexWithReturn(ctx, 4, key, &keylen);

    bool do_nack_test = arg_get_lit(ctx, 5);
    bool verbose = arg_get_lit(ctx, 6);
    CLIParserFree(ctx);

    uint8_t dbg_curr = DBG_NONE;
    if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    if (keylen != 0 && keylen != MIFARE_KEY_SIZE) {
        PrintAndLogEx(ERR, "Key length must be %u bytes", MIFARE_KEY_SIZE);
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return 0;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return select_status;
    }

    if (select_status == 3) {
        PrintAndLogEx(INFO, "Card doesn't support standard iso14443-3 anticollision");

        if (verbose) {
            PrintAndLogEx(SUCCESS, "ATQA: %02X %02X", card.atqa[1], card.atqa[0]);
        }
        return select_status;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("ISO14443-a Information") " ---------------------");
    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02X %02X"), card.atqa[1], card.atqa[0]);
    PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02X [%" PRIu64 "]"), card.sak, resp.oldarg[0]);

    if (setDeviceDebugLevel(verbose ? MAX(dbg_curr, DBG_INFO) : DBG_NONE, false) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    uint8_t signature[32] = {0};
    int res = read_mfc_ev1_signature(signature);
    if (res == PM3_SUCCESS) {
        mfc_ev1_print_signature(card.uid, card.uidlen, signature, sizeof(signature));
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Keys Information"));

    uint8_t fkey[MIFARE_KEY_SIZE] = {0};
    uint8_t fKeyType = 0xFF;

    uint64_t tmpkey = 0;
    mfc_algo_saflok_one(card.uid, 0, MF_KEY_A, &tmpkey);
    num_to_bytes(tmpkey, MIFARE_KEY_SIZE, key + MIFARE_KEY_SIZE);

    int sectorsCnt = 2;
    uint8_t *keyBlock = NULL;
    uint32_t keycnt = 0;
    res = mf_load_keys(&keyBlock, &keycnt, key, MIFARE_KEY_SIZE * 2, NULL, 0, true);
    if (res != PM3_SUCCESS) {
        return res;
    }

    // create/initialize key storage structure
    sector_t *e_sector = NULL;
    if (initSectorTable(&e_sector, sectorsCnt) != PM3_SUCCESS) {
        free(keyBlock);
        return PM3_EMALLOC;
    }

    uint8_t blockdata[MFBLOCK_SIZE] = {0};
    res = mf_check_keys_fast(sectorsCnt, true, true, 1, keycnt, keyBlock, e_sector, false, verbose);
    if (res == PM3_SUCCESS || res == PM3_EPARTIAL) {

        if (e_sector[0].foundKey[MF_KEY_A]) {
            PrintAndLogEx(SUCCESS, "Sector 0 key A... " _GREEN_("%012" PRIX64), e_sector[0].Key[MF_KEY_A]);

            num_to_bytes(e_sector[0].Key[MF_KEY_A], MIFARE_KEY_SIZE, fkey);
            if (mf_read_block(0, MF_KEY_A, key, blockdata) == PM3_SUCCESS) {
                fKeyType = MF_KEY_A;
            }
        }

        if (e_sector[0].foundKey[MF_KEY_B]) {
            PrintAndLogEx(SUCCESS, "Sector 0 key B... " _GREEN_("%012" PRIX64), e_sector[0].Key[MF_KEY_B]);

            if (fKeyType == 0xFF) {
                num_to_bytes(e_sector[0].Key[MF_KEY_B], MIFARE_KEY_SIZE, fkey);
                if (mf_read_block(0, MF_KEY_B, key, blockdata) == PM3_SUCCESS) {
                    fKeyType = MF_KEY_B;
                }
            }
        }

        if (e_sector[1].foundKey[MF_KEY_A]) {
            PrintAndLogEx(SUCCESS, "Sector 1 key A... " _GREEN_("%012" PRIX64), e_sector[1].Key[MF_KEY_A]);
        }
    }

    uint8_t k08s[6] = {0xA3, 0x96, 0xEF, 0xA4, 0xE2, 0x4F};
    uint8_t k08[6] = {0xA3, 0x16, 0x67, 0xA8, 0xCE, 0xC1};
    uint8_t k32[6] = {0x51, 0x8B, 0x33, 0x54, 0xE7, 0x60};
    if (mf_read_block(0, 4, k08s, blockdata) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Backdoor key..... " _YELLOW_("%s"), sprint_hex_inrow(k08s, sizeof(k08s)));
        fKeyType = MF_KEY_BD;
        memcpy(fkey, k08s, sizeof(fkey));

    } else if (mf_read_block(0, 4, k08, blockdata) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Backdoor key..... " _YELLOW_("%s"), sprint_hex_inrow(k08, sizeof(k08)));
        fKeyType = MF_KEY_BD;
        memcpy(fkey, k08, sizeof(fkey));
    } else if (mf_read_block(0, 4, k32, blockdata) == PM3_SUCCESS) {
        PrintAndLogEx(SUCCESS, "Backdoor key..... " _YELLOW_("%s"), sprint_hex_inrow(k32, sizeof(k32)));
        fKeyType = MF_KEY_BD;
        memcpy(fkey, k32, sizeof(fkey));
    }

    if (fKeyType != 0xFF) {
        PrintAndLogEx(SUCCESS, "Block 0.... %s | " NOLF, sprint_hex_inrow(blockdata, MFBLOCK_SIZE));
        PrintAndLogEx(NORMAL, "%s", sprint_ascii(blockdata + 8, 8));
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Fingerprint"));

    if (fKeyType != 0xFF) {
        // cards with known backdoor
        if (card.sak != 0x20  && memcmp(blockdata + 8, "\x62\x63\x64\x65\x66\x67\x68\x69", 8) == 0) {
            // backdoor might be present, or just a clone reusing Fudan MF data...
            PrintAndLogEx(SUCCESS, "Fudan based card");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08s, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x08\x04\x00", 3) == 0
                   && (blockdata[8] == 0x03 || blockdata[8] == 0x04) && blockdata[15] == 0x90) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF08S");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08s, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x00\x03\x00\x10", 4) == 0
                   && blockdata[15] == 0x90) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF08S-7B");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x08\x04\x00", 3) == 0
                   && blockdata[15] == 0x98) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF08S **98");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x08\x04\x00", 3) == 0
                   && (blockdata[8] >= 0x01 && blockdata[8] <= 0x03) && blockdata[15] == 0x1D) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF08");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x00\x01\x00\x10", 4) == 0
                   && blockdata[15] == 0x1D) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF08-7B");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k32, sizeof(fkey)) == 0
                   && card.sak == 0x18 && memcmp(blockdata + 5, "\x18\x02\x00\x46\x44\x53\x37\x30\x56\x30\x31", 11) == 0) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF32");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x20 && memcmp(blockdata + 8, "\x62\x63\x64\x65\x66\x67\x68\x69", 8) == 0) {
            PrintAndLogEx(SUCCESS, "Fudan FM11RF32 (SAK=20)");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x28 && (
                       (memcmp(blockdata + 5, "\x28\x04\x00\x90\x10\x15\x01\x00\x00\x00\x00", 11) == 0) ||
                       (memcmp(blockdata + 5, "\x28\x04\x00\x90\x11\x15\x01\x00\x00\x00\x00", 11) == 0))) {
            // Note: it also has ATS =
            // 10 78 80 90 02 20 90 00 00 00 00 00 + UID + CRC
            PrintAndLogEx(SUCCESS, "Fudan FM1208-10");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x28 && memcmp(blockdata + 5, "\x28\x04\x00\x90\x53\xB7\x0C\x00\x00\x00\x00", 11) == 0) {
            // Note: it also has ATS =
            // 10 78 80 B0 02 20 90 00 00 00 00 00 + UID + CRC
            PrintAndLogEx(SUCCESS, "Fudan FM1216-137");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x88 && memcmp(blockdata + 5, "\x88\x04\x00\x43", 4) == 0) {
            PrintAndLogEx(SUCCESS, "Infineon SLE66R35");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x88\x04\x00\x44", 4) == 0) {
            PrintAndLogEx(SUCCESS, "NXP MF1ICS5003");
        } else if (fKeyType == MF_KEY_BD && memcmp(fkey, k08, sizeof(fkey)) == 0
                   && card.sak == 0x08 && memcmp(blockdata + 5, "\x88\x04\x00\x45", 4) == 0) {
            PrintAndLogEx(SUCCESS, "NXP MF1ICS5004");
        } else if (fKeyType == MF_KEY_BD) {
            PrintAndLogEx(SUCCESS, _RED_("Unknown card with backdoor, please report details!"));
        } else
            // other cards
            if (card.sak == 0x08 && memcmp(blockdata + 5, "\x88\x04\x00\x46", 4) == 0) {
                PrintAndLogEx(SUCCESS, "NXP MF1ICS5005");
            } else if (card.sak == 0x08 && memcmp(blockdata + 5, "\x88\x04\x00\x47", 4) == 0) {
                PrintAndLogEx(SUCCESS, "NXP MF1ICS5006");
            } else if (card.sak == 0x09 && memcmp(blockdata + 5, "\x89\x04\x00\x47", 4) == 0) {
                PrintAndLogEx(SUCCESS, "NXP MF1ICS2006");
            } else if (card.sak == 0x08 && memcmp(blockdata + 5, "\x88\x04\x00\x48", 4) == 0) {
                PrintAndLogEx(SUCCESS, "NXP MF1ICS5007");
            } else if (card.sak == 0x08 && memcmp(blockdata + 5, "\x88\x04\x00\xc0", 4) == 0) {
                PrintAndLogEx(SUCCESS, "NXP MF1ICS5035");
            } else {
                PrintAndLogEx(SUCCESS, "unknown");
            }

        if (e_sector[1].foundKey[MF_KEY_A] && (e_sector[1].Key[MF_KEY_A] == 0x2A2C13CC242A)) {
            PrintAndLogEx(SUCCESS, "dormakaba Saflok detected");
        }

    } else {
        PrintAndLogEx(INFO, "<n/a>");
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("Magic Tag Information"));
    if (detect_mf_magic(true, MF_KEY_B, e_sector[0].Key[MF_KEY_B]) == MAGIC_FLAG_NONE) {
        if (detect_mf_magic(true, MF_KEY_A, e_sector[0].Key[MF_KEY_A]) == MAGIC_FLAG_NONE) {
            PrintAndLogEx(INFO, "<n/a>");
        }
    }

    free(keyBlock);
    free(e_sector);

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("PRNG Information"));

    res = detect_classic_static_nonce();
    if (res == NONCE_STATIC) {
        PrintAndLogEx(SUCCESS, "Static nonce......... " _YELLOW_("yes"));
    }


    if (res == NONCE_NORMAL) {
        // not static
        res = detect_classic_prng();
        if (res == 1) {
            PrintAndLogEx(SUCCESS, "Prng....... " _GREEN_("weak"));
        } else if (res == 0) {
            PrintAndLogEx(SUCCESS, "Prng....... " _YELLOW_("hard"));
        } else {
            PrintAndLogEx(FAILED, "Prng........ " _RED_("fail"));
        }

        // detect static encrypted nonce
        if (keylen == MIFARE_KEY_SIZE) {
            res = detect_classic_static_encrypted_nonce(blockn, keytype, key);
            if (res == NONCE_STATIC) {
                PrintAndLogEx(SUCCESS, "Static nonce... " _YELLOW_("yes"));
                fKeyType = 0xFF; // dont detect twice
            } else if (res == NONCE_SUPERSTATIC) {
                PrintAndLogEx(SUCCESS, "Static nonce... " _YELLOW_("yes, even when nested"));
                fKeyType = 0xFF; // dont detect twice
            } else if (res == NONCE_STATIC_ENC) {
                PrintAndLogEx(SUCCESS, "Static enc nonce... " _RED_("yes"));
                fKeyType = 0xFF; // dont detect twice
            }
        }

        if (fKeyType != 0xFF) {
            res = detect_classic_static_encrypted_nonce(0, fKeyType, fkey);
            if (res == NONCE_STATIC) {
                PrintAndLogEx(SUCCESS, "Static nonce... " _YELLOW_("yes"));
            } else if (res == NONCE_SUPERSTATIC) {
                PrintAndLogEx(SUCCESS, "Static nonce... " _YELLOW_("yes, even when nested"));
            } else if (res == NONCE_STATIC_ENC) {
                PrintAndLogEx(SUCCESS, "Static enc nonce... " _RED_("yes"));
            }
        }

        if (do_nack_test) {
            detect_classic_nackbug(verbose);
        }
    }

    if (setDeviceDebugLevel(dbg_curr, false) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static int CmdHF14AMfISEN(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "hf mf isen",
                  "Information about Static Encrypted Nonce properties in a MIFARE Classic card",
                  "hf mf isen\n"
                  "Default behavior:\n"
                  "auth(blk)-auth(blk2)-auth(blk2)-...\n"
                  "Default behavior when wrong key2:\n"
                  "auth(blk)-auth(blk2) auth(blk)-auth(blk2) ...\n"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_int0(NULL, "blk", "<dec>", "block number"),
        arg_lit0("a", NULL, "input key type is key A (def)"),
        arg_lit0("b", NULL, "input key type is key B"),
        arg_int0("c", NULL, "<dec>", "input key type is key A + offset"),
        arg_str0("k", "key", "<hex>", "key, 6 hex bytes"),
        arg_int0(NULL, "blk2", "<dec>", "nested block number (default=same)"),
        arg_lit0(NULL, "a2", "nested input key type is key A (default=same)"),
        arg_lit0(NULL, "b2", "nested input key type is key B (default=same)"),
        arg_int0(NULL, "c2", "<dec>", "nested input key type is key A + offset"),
        arg_str0(NULL, "key2", "<hex>", "nested key, 6 hex bytes (default=same)"),
        arg_int0("n", NULL, "<dec>", "number of nonces (default=2)"),
        arg_lit0(NULL, "reset", "reset between attempts, even if auth was successful"),
        arg_lit0(NULL, "hardreset", "hard reset (RF off/on) between attempts, even if auth was successful"),
        arg_lit0(NULL, "addread", "auth(blk)-read(blk)-auth(blk2)"),
        arg_lit0(NULL, "addauth", "auth(blk)-auth(blk)-auth(blk2)"),
        arg_lit0(NULL, "incblk2", "auth(blk)-auth(blk2)-auth(blk2+4)-..."),
        arg_lit0(NULL, "corruptnrar", "corrupt {nR}{aR}, but with correct parity"),
        arg_lit0(NULL, "corruptnrarparity", "correct {nR}{aR}, but with corrupted parity"),
        arg_rem("", ""),
        arg_rem("FM11RF08S specific options:", "Incompatible with above options, except -k; output in JSON"),
        arg_lit0(NULL, "collect_fm11rf08s", "collect all nT/{nT}/par_err."),
        arg_lit0(NULL, "collect_fm11rf08s_with_data", "collect all nT/{nT}/par_err and data blocks."),
        arg_lit0(NULL, "collect_fm11rf08s_without_backdoor", "collect all nT/{nT}/par_err without backdoor. Requires first auth keytype and block"),
        arg_str0("f", "file", "<fn>", "Specify a filename for collected data"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);

    int blockn = arg_get_int_def(ctx, 1, 0);

    uint8_t keytype = MF_KEY_A;
    if (arg_get_lit(ctx, 2) && arg_get_lit(ctx, 3)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 3)) {
        keytype = MF_KEY_B;
    }
    uint8_t prev_keytype = keytype;
    keytype = arg_get_int_def(ctx, 4, keytype);
    if ((arg_get_lit(ctx, 2) || arg_get_lit(ctx, 3)) && (keytype != prev_keytype)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single input key type");
        return PM3_EINVARG;
    }

    int keylen = 0;
    uint8_t key[MIFARE_KEY_SIZE] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
    CLIGetHexWithReturn(ctx, 5, key, &keylen);

    int blockn_nested = arg_get_int_def(ctx, 6, blockn);

    uint8_t keytype_nested = keytype;
    if (arg_get_lit(ctx, 7) && arg_get_lit(ctx, 8)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single nested input key type");
        return PM3_EINVARG;
    } else if (arg_get_lit(ctx, 7)) {
        keytype_nested = MF_KEY_A;
    } else if (arg_get_lit(ctx, 8)) {
        keytype_nested = MF_KEY_B;
    }
    uint8_t prev_keytype_nested = keytype_nested;
    keytype_nested = arg_get_int_def(ctx, 9, keytype_nested);
    if ((arg_get_lit(ctx, 7) || arg_get_lit(ctx, 8)) && (keytype_nested != prev_keytype_nested)) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single nested input key type");
        return PM3_EINVARG;
    }

    int keylen_nested = 0;
    uint8_t key_nested[MIFARE_KEY_SIZE];
    memcpy(key_nested, key, MIFARE_KEY_SIZE);
    CLIGetHexWithReturn(ctx, 10, key_nested, &keylen_nested);

    int nr_nested = arg_get_int_def(ctx, 11, 2);

    bool reset = arg_get_lit(ctx, 12);
    bool hardreset = arg_get_lit(ctx, 13);
    if (reset && hardreset) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Choose one single type of reset");
        return PM3_EINVARG;
    }
    bool addread = arg_get_lit(ctx, 14);
    bool addauth = arg_get_lit(ctx, 15);
    bool incblk2 = arg_get_lit(ctx, 16);
    bool corruptnrar = arg_get_lit(ctx, 17);
    bool corruptnrarparity = arg_get_lit(ctx, 18);
    bool collect_fm11rf08s = arg_get_lit(ctx, 21);
    bool collect_fm11rf08s_with_data = arg_get_lit(ctx, 22);
    if (collect_fm11rf08s_with_data) {
        collect_fm11rf08s = 1;
    }
    bool collect_fm11rf08s_without_backdoor = arg_get_lit(ctx, 23);
    if (collect_fm11rf08s_without_backdoor) {
        collect_fm11rf08s = 1;
    }
    if (collect_fm11rf08s_with_data && collect_fm11rf08s_without_backdoor) {
        CLIParserFree(ctx);
        PrintAndLogEx(WARNING, "Don't mix with_data and without_backdoor options");
        return PM3_EINVARG;
    }
    int fnlen = 0;
    char filename[FILE_PATH_SIZE] = {0};
    CLIParamStrToBuf(arg_get_str(ctx, 24), (uint8_t *)filename, FILE_PATH_SIZE, &fnlen);

    CLIParserFree(ctx);

    uint8_t dbg_curr = DBG_NONE;
    if (getDeviceDebugLevel(&dbg_curr) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    if (keylen != 0 && keylen != MIFARE_KEY_SIZE) {
        PrintAndLogEx(ERR, "Key length must be %u bytes", MIFARE_KEY_SIZE);
        return PM3_EINVARG;
    }

    if (keylen_nested != 0 && keylen_nested != MIFARE_KEY_SIZE) {
        PrintAndLogEx(ERR, "Key length must be %u bytes", MIFARE_KEY_SIZE);
        return PM3_EINVARG;
    }

    clearCommandBuffer();
    SendCommandMIX(CMD_HF_ISO14443A_READER, ISO14A_CONNECT, 0, 0, NULL, 0);
    PacketResponseNG resp;
    if (WaitForResponseTimeout(CMD_ACK, &resp, 2500) == false) {
        PrintAndLogEx(DEBUG, "iso14443a card select timeout");
        return 0;
    }

    iso14a_card_select_t card;
    memcpy(&card, (iso14a_card_select_t *)resp.data.asBytes, sizeof(iso14a_card_select_t));

    /*
        0: couldn't read
        1: OK, with ATS
        2: OK, no ATS
        3: proprietary Anticollision
    */
    uint64_t select_status = resp.oldarg[0];

    if (select_status == 0) {
        PrintAndLogEx(DEBUG, "iso14443a card select failed");
        return select_status;
    }

    if (select_status == 3) {
        PrintAndLogEx(INFO, "Card doesn't support standard iso14443-3 anticollision");
    }

    if (collect_fm11rf08s) {
        uint64_t t1 = msclock();
        uint32_t flags = collect_fm11rf08s_with_data | (collect_fm11rf08s_without_backdoor << 1);
        SendCommandMIX(CMD_HF_MIFARE_ACQ_STATIC_ENCRYPTED_NONCES, flags, blockn, keytype, key, sizeof(key));
        if (WaitForResponseTimeout(CMD_ACK, &resp, 2500)) {
            if (resp.oldarg[0] != PM3_SUCCESS) {
                return NONCE_FAIL;
            }
        } else {
            PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
            return PM3_ETIMEOUT;
        }
        uint8_t num_sectors = MIFARE_1K_MAXSECTOR + 1;
        iso14a_fm11rf08s_nonces_with_data_t nonces_dump = {0};
        for (uint8_t sec = 0; sec < num_sectors; sec++) {
            // reconstruct full nt
            uint32_t nt;
            nt = bytes_to_num(resp.data.asBytes + ((sec * 2) * 8), 2);
            nt = nt << 16 | prng_successor(nt, 16);
            num_to_bytes(nt, 4, nonces_dump.nt[sec][0]);
            nt = bytes_to_num(resp.data.asBytes + (((sec * 2) + 1) * 8), 2);
            nt = nt << 16 | prng_successor(nt, 16);
            num_to_bytes(nt, 4, nonces_dump.nt[sec][1]);
        }
        for (uint8_t sec = 0; sec < num_sectors; sec++) {
            memcpy(nonces_dump.nt_enc[sec][0], resp.data.asBytes + ((sec * 2) * 8) + 4, 4);
            memcpy(nonces_dump.nt_enc[sec][1], resp.data.asBytes + (((sec * 2) + 1) * 8) + 4, 4);
        }
        for (uint8_t sec = 0; sec < num_sectors; sec++) {
            nonces_dump.par_err[sec][0] = resp.data.asBytes[((sec * 2) * 8) + 2];
            nonces_dump.par_err[sec][1] = resp.data.asBytes[(((sec * 2) + 1) * 8) + 2];
        }
        if (collect_fm11rf08s_with_data) {
            int bytes = MIFARE_1K_MAXBLOCK * MFBLOCK_SIZE;

            uint8_t *dump = calloc(bytes, sizeof(uint8_t));
            if (dump == NULL) {
                PrintAndLogEx(WARNING, "Fail, cannot allocate memory");
                return PM3_EFAILED;
            }
            if (!GetFromDevice(BIG_BUF_EML, dump, bytes, 0, NULL, 0, NULL, 2500, false)) {
                PrintAndLogEx(WARNING, "Fail, transfer from device time-out");
                free(dump);
                return PM3_ETIMEOUT;
            }
            for (uint8_t blk = 0; blk < MIFARE_1K_MAXBLOCK; blk++) {
                memcpy(nonces_dump.blocks[blk], dump + blk * MFBLOCK_SIZE, MFBLOCK_SIZE);
            }
            free(dump);
        }
        t1 = msclock() - t1;
        PrintAndLogEx(SUCCESS, "time: " _YELLOW_("%" PRIu64) " ms", t1);

        if (fnlen == 0) {
            snprintf(filename, sizeof(filename), "hf-mf-%s-nonces%s", sprint_hex_inrow(card.uid, card.uidlen), collect_fm11rf08s_with_data ? "_with_data" : "");
        }
        if (pm3_save_fm11rf08s_nonces(filename, &nonces_dump, collect_fm11rf08s_with_data) != PM3_SUCCESS) {
            return PM3_EFAILED;
        }
        return PM3_SUCCESS;
    }

    PrintAndLogEx(NORMAL, "");
    PrintAndLogEx(INFO, "--- " _CYAN_("ISO14443-a Information") " ---------------------");
    PrintAndLogEx(SUCCESS, " UID: " _GREEN_("%s"), sprint_hex(card.uid, card.uidlen));
    PrintAndLogEx(SUCCESS, "ATQA: " _GREEN_("%02X %02X"), card.atqa[1], card.atqa[0]);
    PrintAndLogEx(SUCCESS, " SAK: " _GREEN_("%02X [%" PRIu64 "]"), card.sak, resp.oldarg[0]);

//    if (setDeviceDebugLevel(DBG_DEBUG, false) != PM3_SUCCESS) {
    if (setDeviceDebugLevel(DBG_EXTENDED, false) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    int res = detect_classic_static_encrypted_nonce_ex(blockn, keytype, key, blockn_nested, keytype_nested, key_nested, nr_nested, reset, hardreset, addread, addauth, incblk2, corruptnrar, corruptnrarparity, true);
    if (res == NONCE_STATIC) {
        PrintAndLogEx(SUCCESS, "Static nonce......... " _YELLOW_("yes"));
    } else if (res == NONCE_SUPERSTATIC) {
        PrintAndLogEx(SUCCESS, "Static nonce......... " _YELLOW_("yes, even when nested"));
    } else if (res == NONCE_STATIC_ENC) {
        PrintAndLogEx(SUCCESS, "Static enc nonce..... " _RED_("yes"));
    }
    if (setDeviceDebugLevel(dbg_curr, false) != PM3_SUCCESS) {
        return PM3_EFAILED;
    }

    PrintAndLogEx(NORMAL, "");
    return PM3_SUCCESS;
}

static command_t CommandTable[] = {
    {"help",        CmdHelp,                AlwaysAvailable, "This help"},
    {"list",        CmdHF14AMfList,         AlwaysAvailable, "List MIFARE history"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("recovery") " -----------------------"},
    {"info",        CmdHF14AMfInfo,         IfPm3Iso14443a,  "mfc card Info"},
    {"isen",        CmdHF14AMfISEN,         IfPm3Iso14443a,  "mfc card Info Static Encrypted Nonces"},
    {"darkside",    CmdHF14AMfDarkside,     IfPm3Iso14443a,  "Darkside attack"},
    {"nested",      CmdHF14AMfNested,       IfPm3Iso14443a,  "Nested attack"},
    {"hardnested",  CmdHF14AMfNestedHard,   AlwaysAvailable, "Nested attack for hardened MIFARE Classic cards"},
    {"staticnested", CmdHF14AMfNestedStatic, IfPm3Iso14443a, "Nested attack against static nonce MIFARE Classic cards"},
    {"brute",       CmdHF14AMfSmartBrute,   IfPm3Iso14443a,  "Smart bruteforce to exploit weak key generators"},
    {"autopwn",     CmdHF14AMfAutoPWN,      IfPm3Iso14443a,  "Automatic key recovery tool for MIFARE Classic"},
//    {"keybrute",    CmdHF14AMfKeyBrute,     IfPm3Iso14443a,  "J_Run's 2nd phase of multiple sector nested authentication key recovery"},
    {"nack",        CmdHf14AMfNack,         IfPm3Iso14443a,  "Test for MIFARE NACK bug"},
    {"chk",         CmdHF14AMfChk,          IfPm3Iso14443a,  "Check keys"},
    {"fchk",        CmdHF14AMfChk_fast,     IfPm3Iso14443a,  "Check keys fast, targets all keys on card"},
    {"decrypt",     CmdHf14AMfDecryptBytes, AlwaysAvailable, "Decrypt Crypto1 data from sniff or trace"},
    {"supercard",   CmdHf14AMfSuperCard,    IfPm3Iso14443a,  "Extract info from a `super card`"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("operations") " -----------------------"},
    {"auth4",       CmdHF14AMfAuth4,        IfPm3Iso14443a,  "ISO14443-4 AES authentication"},
    {"acl",         CmdHF14AMfAcl,          AlwaysAvailable, "Decode and print MIFARE Classic access rights bytes"},
    {"dump",        CmdHF14AMfDump,         IfPm3Iso14443a,  "Dump MIFARE Classic tag to binary file"},
    {"mad",         CmdHF14AMfMAD,          AlwaysAvailable, "Checks and prints MAD"},
    {"personalize", CmdHFMFPersonalize,     IfPm3Iso14443a,  "Personalize UID (MIFARE Classic EV1 only)"},
    {"rdbl",        CmdHF14AMfRdBl,         IfPm3Iso14443a,  "Read MIFARE Classic block"},
    {"rdsc",        CmdHF14AMfRdSc,         IfPm3Iso14443a,  "Read MIFARE Classic sector"},
    {"restore",     CmdHF14AMfRestore,      IfPm3Iso14443a,  "Restore MIFARE Classic binary file to tag"},
    {"setmod",      CmdHf14AMfSetMod,       IfPm3Iso14443a,  "Set MIFARE Classic EV1 load modulation strength"},
    {"value",       CmdHF14AMfValue,        AlwaysAvailable, "Value blocks"},
    {"view",        CmdHF14AMfView,         AlwaysAvailable, "Display content from tag dump file"},
    {"wipe",        CmdHF14AMfWipe,         IfPm3Iso14443a,  "Wipe card to zeros and default keys/acc"},
    {"wrbl",        CmdHF14AMfWrBl,         IfPm3Iso14443a,  "Write MIFARE Classic block"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("simulation") " -----------------------"},
    {"sim",         CmdHF14AMfSim,          IfPm3Iso14443a,  "Simulate MIFARE card"},
    {"ecfill",      CmdHF14AMfECFill,       IfPm3Iso14443a,  "Fill emulator memory with help of keys from emulator"},
    {"eclr",        CmdHF14AMfEClear,       IfPm3Iso14443a,  "Clear emulator memory"},
    {"egetblk",     CmdHF14AMfEGetBlk,      IfPm3Iso14443a,  "Get emulator memory block"},
    {"egetsc",      CmdHF14AMfEGetSc,       IfPm3Iso14443a,  "Get emulator memory sector"},
    {"ekeyprn",     CmdHF14AMfEKeyPrn,      IfPm3Iso14443a,  "Print keys from emulator memory"},
    {"eload",       CmdHF14AMfELoad,        IfPm3Iso14443a,  "Upload file into emulator memory"},
    {"esave",       CmdHF14AMfESave,        IfPm3Iso14443a,  "Save emulator memory to file"},
    {"esetblk",     CmdHF14AMfESet,         IfPm3Iso14443a,  "Set emulator memory block"},
    {"eview",       CmdHF14AMfEView,        IfPm3Iso14443a,  "View emulator memory"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("magic gen1") " -----------------------"},
    {"cgetblk",     CmdHF14AMfCGetBlk,      IfPm3Iso14443a,  "Read block from card"},
    {"cgetsc",      CmdHF14AMfCGetSc,       IfPm3Iso14443a,  "Read sector from card"},
    {"cload",       CmdHF14AMfCLoad,        IfPm3Iso14443a,  "Load dump to card"},
    {"csave",       CmdHF14AMfCSave,        IfPm3Iso14443a,  "Save dump from card into file or emulator"},
    {"csetblk",     CmdHF14AMfCSetBlk,      IfPm3Iso14443a,  "Write block to card"},
    {"csetuid",     CmdHF14AMfCSetUID,      IfPm3Iso14443a,  "Set UID on card"},
    {"cview",       CmdHF14AMfCView,        IfPm3Iso14443a,  "View card"},
    {"cwipe",       CmdHF14AMfCWipe,        IfPm3Iso14443a,  "Wipe card to default UID/Sectors/Keys"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("magic gen3") " -----------------------"},
    {"gen3uid",     CmdHf14AGen3UID,        IfPm3Iso14443a,  "Set UID without changing manufacturer block"},
    {"gen3blk",     CmdHf14AGen3Block,      IfPm3Iso14443a,  "Overwrite manufacturer block"},
    {"gen3freeze",  CmdHf14AGen3Freeze,     IfPm3Iso14443a,  "Perma lock UID changes. irreversible"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "-------------------- " _CYAN_("magic gen4 GTU") " --------------------------"},
    {"ginfo",       CmdHF14AGen4Info,       AlwaysAvailable,  "Info about configuration of the card"},
    {"ggetblk",     CmdHF14AGen4GetBlk,     IfPm3Iso14443a,  "Read block from card"},
    {"gload",       CmdHF14AGen4Load,       IfPm3Iso14443a,  "Load dump to card"},
    {"gsave",       CmdHF14AGen4Save,       IfPm3Iso14443a,  "Save dump from card into file or emulator"},
    {"gsetblk",     CmdHF14AGen4SetBlk,     IfPm3Iso14443a,  "Write block to card"},
    {"gview",       CmdHF14AGen4View,       IfPm3Iso14443a,  "View card"},
    {"gchpwd",      CmdHF14AGen4ChangePwd,  IfPm3Iso14443a,  "Change card access password. Warning!"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "-------------------- " _CYAN_("magic gen4 GDM") " --------------------------"},
    {"gdmcfg",      CmdHF14AGen4_GDM_Cfg,   IfPm3Iso14443a,  "Read config block from card"},
    {"gdmsetcfg",   CmdHF14AGen4_GDM_SetCfg, IfPm3Iso14443a, "Write config block to card"},
    {"gdmparsecfg",   CmdHF14AGen4_GDM_ParseCfg, AlwaysAvailable, "Parse config block to card"},
    {"gdmsetblk",   CmdHF14AGen4_GDM_SetBlk, IfPm3Iso14443a, "Write block to card"},
    {"-----------", CmdHelp,                IfPm3Iso14443a,  "----------------------- " _CYAN_("ndef") " -----------------------"},
//    {"ice",         CmdHF14AMfice,          IfPm3Iso14443a,  "collect MIFARE Classic nonces to file"},
    {"ndefformat",  CmdHFMFNDEFFormat,      IfPm3Iso14443a,  "Format MIFARE Classic Tag as NFC Tag"},
    {"ndefread",    CmdHFMFNDEFRead,        IfPm3Iso14443a,  "Read and print NDEF records from card"},
    {"ndefwrite",   CmdHFMFNDEFWrite,       IfPm3Iso14443a,  "Write NDEF records to card"},
    {"encodehid",   CmdHFMFHidEncode,       IfPm3Iso14443a,  "Encode a HID Credential / NDEF record to card"},
    {NULL, NULL, NULL, NULL}

};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdHFMF(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}
