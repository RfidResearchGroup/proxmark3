//-----------------------------------------------------------------------------
// Iceman, 2019
//
// This code is licensed to you under the terms of the GNU GPL, version 2 or,
// at your option, any later version. See the LICENSE.txt file for the text of
// the license.
//-----------------------------------------------------------------------------
// Low frequency GALLAGHER tag commands
// ASK/MAN, RF/32, 96 bits long (unknown cs) (0x00088060)
// sample Q5 ,  ASK RF/32, STT,  96 bits  (3blocks)   ( 0x9000F006)
//-----------------------------------------------------------------------------
#include "cmdlfgallagher.h"
#include <string.h>        // memcpy
#include <ctype.h>         // tolower
#include <stdio.h>
#include "commonutil.h"    // ARRAYLEN
#include "common.h"
#include "cmdparser.h"     // command_t
#include "comms.h"
#include "ui.h"
#include "cmddata.h"
#include "cmdlf.h"
#include "lfdemod.h"       // preamble test
#include "protocols.h"     // t55xx defines
#include "cmdlft55xx.h"    // clone..
#include "crc.h"           // CRC8/Cardx
#include "cmdlfem4x05.h"   //
#include "cliparser.h"

static int CmdHelp(const char *Cmd);

static void scramble(uint8_t *arr, uint8_t len) {
    const uint8_t lut[] = {
        0xa3, 0xb0, 0x80, 0xc6, 0xb2, 0xf4, 0x5c, 0x6c, 0x81, 0xf1, 0xbb, 0xeb, 0x55, 0x67, 0x3c, 0x05,
        0x1a, 0x0e, 0x61, 0xf6, 0x22, 0xce, 0xaa, 0x8f, 0xbd, 0x3b, 0x1f, 0x5e, 0x44, 0x04, 0x51, 0x2e,
        0x4d, 0x9a, 0x84, 0xea, 0xf8, 0x66, 0x74, 0x29, 0x7f, 0x70, 0xd8, 0x31, 0x7a, 0x6d, 0xa4, 0x00,
        0x82, 0xb9, 0x5f, 0xb4, 0x16, 0xab, 0xff, 0xc2, 0x39, 0xdc, 0x19, 0x65, 0x57, 0x7c, 0x20, 0xfa,
        0x5a, 0x49, 0x13, 0xd0, 0xfb, 0xa8, 0x91, 0x73, 0xb1, 0x33, 0x18, 0xbe, 0x21, 0x72, 0x48, 0xb6,
        0xdb, 0xa0, 0x5d, 0xcc, 0xe6, 0x17, 0x27, 0xe5, 0xd4, 0x53, 0x42, 0xf3, 0xdd, 0x7b, 0x24, 0xac,
        0x2b, 0x58, 0x1e, 0xa7, 0xe7, 0x86, 0x40, 0xd3, 0x98, 0x97, 0x71, 0xcb, 0x3a, 0x0f, 0x01, 0x9b,
        0x6e, 0x1b, 0xfc, 0x34, 0xa6, 0xda, 0x07, 0x0c, 0xae, 0x37, 0xca, 0x54, 0xfd, 0x26, 0xfe, 0x0a,
        0x45, 0xa2, 0x2a, 0xc4, 0x12, 0x0d, 0xf5, 0x4f, 0x69, 0xe0, 0x8a, 0x77, 0x60, 0x3f, 0x99, 0x95,
        0xd2, 0x38, 0x36, 0x62, 0xb7, 0x32, 0x7e, 0x79, 0xc0, 0x46, 0x93, 0x2f, 0xa5, 0xba, 0x5b, 0xaf,
        0x52, 0x1d, 0xc3, 0x75, 0xcf, 0xd6, 0x4c, 0x83, 0xe8, 0x3d, 0x30, 0x4e, 0xbc, 0x08, 0x2d, 0x09,
        0x06, 0xd9, 0x25, 0x9e, 0x89, 0xf2, 0x96, 0x88, 0xc1, 0x8c, 0x94, 0x0b, 0x28, 0xf0, 0x47, 0x63,
        0xd5, 0xb3, 0x68, 0x56, 0x9c, 0xf9, 0x6f, 0x41, 0x50, 0x85, 0x8b, 0x9d, 0x59, 0xbf, 0x9f, 0xe2,
        0x8e, 0x6a, 0x11, 0x23, 0xa1, 0xcd, 0xb5, 0x7d, 0xc7, 0xa9, 0xc8, 0xef, 0xdf, 0x02, 0xb8, 0x03,
        0x6b, 0x35, 0x3e, 0x2c, 0x76, 0xc9, 0xde, 0x1c, 0x4b, 0xd1, 0xed, 0x14, 0xc5, 0xad, 0xe9, 0x64,
        0x4a, 0xec, 0x8d, 0xf7, 0x10, 0x43, 0x78, 0x15, 0x87, 0xe4, 0xd7, 0x92, 0xe1, 0xee, 0xe3, 0x90
    };

    for (int i = 0; i < len;  i++) {
        arr[i] = lut[arr[i]];
    }
}

static void descramble(uint8_t *arr, uint8_t len) {
    const uint8_t lut[] = {
        0x2f, 0x6e, 0xdd, 0xdf, 0x1d, 0x0f, 0xb0, 0x76, 0xad, 0xaf, 0x7f, 0xbb, 0x77, 0x85, 0x11, 0x6d,
        0xf4, 0xd2, 0x84, 0x42, 0xeb, 0xf7, 0x34, 0x55, 0x4a, 0x3a, 0x10, 0x71, 0xe7, 0xa1, 0x62, 0x1a,
        0x3e, 0x4c, 0x14, 0xd3, 0x5e, 0xb2, 0x7d, 0x56, 0xbc, 0x27, 0x82, 0x60, 0xe3, 0xae, 0x1f, 0x9b,
        0xaa, 0x2b, 0x95, 0x49, 0x73, 0xe1, 0x92, 0x79, 0x91, 0x38, 0x6c, 0x19, 0x0e, 0xa9, 0xe2, 0x8d,
        0x66, 0xc7, 0x5a, 0xf5, 0x1c, 0x80, 0x99, 0xbe, 0x4e, 0x41, 0xf0, 0xe8, 0xa6, 0x20, 0xab, 0x87,
        0xc8, 0x1e, 0xa0, 0x59, 0x7b, 0x0c, 0xc3, 0x3c, 0x61, 0xcc, 0x40, 0x9e, 0x06, 0x52, 0x1b, 0x32,
        0x8c, 0x12, 0x93, 0xbf, 0xef, 0x3b, 0x25, 0x0d, 0xc2, 0x88, 0xd1, 0xe0, 0x07, 0x2d, 0x70, 0xc6,
        0x29, 0x6a, 0x4d, 0x47, 0x26, 0xa3, 0xe4, 0x8b, 0xf6, 0x97, 0x2c, 0x5d, 0x3d, 0xd7, 0x96, 0x28,
        0x02, 0x08, 0x30, 0xa7, 0x22, 0xc9, 0x65, 0xf8, 0xb7, 0xb4, 0x8a, 0xca, 0xb9, 0xf2, 0xd0, 0x17,
        0xff, 0x46, 0xfb, 0x9a, 0xba, 0x8f, 0xb6, 0x69, 0x68, 0x8e, 0x21, 0x6f, 0xc4, 0xcb, 0xb3, 0xce,
        0x51, 0xd4, 0x81, 0x00, 0x2e, 0x9c, 0x74, 0x63, 0x45, 0xd9, 0x16, 0x35, 0x5f, 0xed, 0x78, 0x9f,
        0x01, 0x48, 0x04, 0xc1, 0x33, 0xd6, 0x4f, 0x94, 0xde, 0x31, 0x9d, 0x0a, 0xac, 0x18, 0x4b, 0xcd,
        0x98, 0xb8, 0x37, 0xa2, 0x83, 0xec, 0x03, 0xd8, 0xda, 0xe5, 0x7a, 0x6b, 0x53, 0xd5, 0x15, 0xa4,
        0x43, 0xe9, 0x90, 0x67, 0x58, 0xc0, 0xa5, 0xfa, 0x2a, 0xb1, 0x75, 0x50, 0x39, 0x5c, 0xe6, 0xdc,
        0x89, 0xfc, 0xcf, 0xfe, 0xf9, 0x57, 0x54, 0x64, 0xa8, 0xee, 0x23, 0x0b, 0xf1, 0xea, 0xfd, 0xdb,
        0xbd, 0x09, 0xb5, 0x5b, 0x05, 0x86, 0x13, 0xf3, 0x24, 0xc5, 0x3f, 0x44, 0x72, 0x7c, 0x7e, 0x36
    };

    for (int i = 0; i < len;  i++) {
        arr[i] = lut[arr[i]];
    }
}

//see ASK/MAN Demod for what args are accepted
int demodGallagher(bool verbose) {
    (void) verbose; // unused so far
    bool st = true;
    if (ASKDemod_ext(32, 0, 100, 0, false, false, false, 1, &st) != PM3_SUCCESS) {
        PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: ASKDemod failed");
        return PM3_ESOFT;
    }

    size_t size = g_DemodBufferLen;
    int ans = detectGallagher(g_DemodBuffer, &size);
    if (ans < 0) {
        if (ans == -1)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: too few bits found");
        else if (ans == -2)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: preamble not found");
        else if (ans == -3)
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: Size not correct: %zu", size);
        else
            PrintAndLogEx(DEBUG, "DEBUG: Error - GALLAGHER: ans: %d", ans);

        return PM3_ESOFT;
    }
    setDemodBuff(g_DemodBuffer, 96, ans);
    setClockGrid(g_DemodClock, g_DemodStartIdx + (ans * g_DemodClock));

    // got a good demod
    uint32_t raw1 = bytebits_to_byte(g_DemodBuffer, 32);
    uint32_t raw2 = bytebits_to_byte(g_DemodBuffer + 32, 32);
    uint32_t raw3 = bytebits_to_byte(g_DemodBuffer + 64, 32);

    // bytes
    uint8_t arr[8] = {0};
    for (int i = 0, pos = 0; i < ARRAYLEN(arr); i++) {
        pos = 16 + (9 * i);
        arr[i] = bytebits_to_byte(g_DemodBuffer + pos, 8);
    }

    // crc
    uint8_t crc = bytebits_to_byte(g_DemodBuffer + 16 + (9 * 8), 8);
    uint8_t calc_crc =  CRC8Cardx(arr, ARRAYLEN(arr));

    descramble(arr, ARRAYLEN(arr));

    // 4bit region code
    uint8_t rc = (arr[3] & 0x1E) >> 1;

    // 16bit FC
    uint16_t fc = (arr[5] & 0x0F) << 12 | arr[1] << 4 | ((arr[7] >> 4) & 0x0F);

    // 24bit CN
    uint32_t cn = arr[0] << 16 | (arr[4] & 0x1F) << 11 | arr[2] << 3 | (arr[3] & 0xE0) >> 5;

    // 4bit issue level
    uint8_t il = arr[7] & 0x0F;

    PrintAndLogEx(SUCCESS, "GALLAGHER - Region: " _GREEN_("%u") " FC: " _GREEN_("%u") " CN: " _GREEN_("%u") " Issue Level: " _GREEN_("%u"), rc, fc, cn, il);
    PrintAndLogEx(SUCCESS, "   Displayed: " _GREEN_("%C%u"), rc + 'A', fc);
    PrintAndLogEx(SUCCESS, "   Raw: %08X%08X%08X", raw1, raw2, raw3);
    PrintAndLogEx(SUCCESS, "   CRC: %02X - %02X (%s)", crc, calc_crc, (crc == calc_crc) ? "ok" : "fail");
    return PM3_SUCCESS;
}

static int CmdGallagherDemod(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gallagher demod",
                  "Try to find GALLAGHER preamble, if found decode / descramble data",
                  "lf gallagher demod"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    CLIParserFree(ctx);
    return demodGallagher(true);
}

static int CmdGallagherReader(const char *Cmd) {
    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gallagher reader",
                  "read a GALLAGHER tag",
                  "lf gallagher reader -@   -> continuous reader mode"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_lit0("@", NULL, "optional - continuous reader mode"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, true);
    bool cm = arg_get_lit(ctx, 1);
    CLIParserFree(ctx);

    if (cm) {
        PrintAndLogEx(INFO, "Press " _GREEN_("<Enter>") " to exit");
    }

    do {
        lf_read(false, 4096 * 2 + 20);
        demodGallagher(!cm);
    } while (cm && !kbd_enter_pressed());
    return PM3_SUCCESS;
}

static bool isValidGallagherParams(int8_t rc, int32_t fc, int32_t cn, int8_t il) {
    bool isValid = true;

    // if one is set, all must be set
    if (rc < 0 || fc < 0 || cn < 0 || il < 0) {
        PrintAndLogEx(FAILED, "If rc/fc/cn/il is specified, all must be set");
        isValid = false;
    }
    // validate input
    if (rc > 0x0f) {
        PrintAndLogEx(FAILED, "Region code must be less than 16 (4 bits)");
        isValid = false;
    }
    if (fc > 0xffff) {
        PrintAndLogEx(FAILED, "Facility code must be less than 65536 (2 bytes)");
        isValid = false;
    }
    if (cn > 0xffffff) {
        PrintAndLogEx(FAILED, "Card number must be less than 16777216 (3 bytes)");
        isValid = false;
    }
    if (il > 0x0f) {
        PrintAndLogEx(FAILED, "Issue level must be less than 16 (4 bits)");
        isValid = false;
    }
    return isValid;
}

static void setBitsInBlocks(uint32_t *blocks, uint8_t *pos, uint32_t data, uint8_t data_len) {
    for (int i = data_len - 1; i >= 0; i--) {
        uint8_t blk = *pos / 32;
        uint8_t bitPos = 31 - *pos % 32; // fill from left
        uint8_t bit = (data >> i) & 1;
        blocks[blk] |= bit << bitPos;
        (*pos)++;
    }
}

static void createBlocks(uint32_t *blocks, uint8_t rc, uint16_t fc, uint32_t cn, uint8_t il) {
    // put data into the correct places (Gallagher obfuscation)
    uint8_t arr[8] = {0};
    arr[0] = (cn & 0xffffff) >> 16;
    arr[1] = (fc & 0xfff) >> 4;
    arr[2] = (cn & 0x7ff) >> 3;
    arr[3] = (cn & 0x7) << 5 | (rc & 0xf) << 1;
    arr[4] = (cn & 0xffff) >> 11;
    arr[5] = (fc & 0xffff) >> 12;
    arr[6] = 0;
    arr[7] = (fc & 0xf) << 4 | (il & 0xf);

    // more obfuscation
    scramble(arr, ARRAYLEN(arr));

    blocks[0] = blocks[1] = blocks[2] = 0;
    uint8_t pos = 0;

    // magic prefix
    setBitsInBlocks(blocks, &pos, 0x7fea, 16);

    for (int i = 0; i < ARRAYLEN(arr); i++) {
        // data byte
        setBitsInBlocks(blocks, &pos, arr[i], 8);

        // every byte is followed by a bit which is the inverse of the last bit
        setBitsInBlocks(blocks, &pos, !(arr[i] & 0x1), 1);
    }

    // checksum
    uint8_t crc = CRC8Cardx(arr, ARRAYLEN(arr));
    setBitsInBlocks(blocks, &pos, crc, 8);
}

static int CmdGallagherClone(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gallagher clone",
                  "clone a GALLAGHER tag to a T55x7, Q5/T5555 or EM4305/4469 tag.",
                  "lf gallagher clone --raw 0FFD5461A9DA1346B2D1AC32\n"
                  "lf gallagher clone --q5 --raw 0FFD5461A9DA1346B2D1AC32 -> encode for Q5/T5555 tag\n"
                  "lf gallagher clone --em --raw 0FFD5461A9DA1346B2D1AC32 -> encode for EM4305/4469\n"
                  "lf gallagher clone --rc 0 --fc 9876 --cn 1234 --il 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes max"),
        arg_lit0(NULL, "q5", "optional - specify writing to Q5/T5555 tag"),
        arg_lit0(NULL, "em", "optional - specify writing to EM4305/4469 tag"),
        arg_int0(NULL, "rc", "<decimal>", "Region code. 4 bits max"),
        arg_int0(NULL, "fc", "<decimal>", "Facility code. 2 bytes max"),
        arg_int0(NULL, "cn", "<decimal>", "Card number. 3 bytes max"),
        arg_int0(NULL, "il", "<decimal>", "Issue level. 4 bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof raw, &raw_len);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    bool q5 = arg_get_lit(ctx, 2);
    bool em = arg_get_lit(ctx, 3);
    int16_t region_code = arg_get_int_def(ctx, 4, -1);
    int32_t facility_code = arg_get_int_def(ctx, 5, -1);
    int32_t card_number = arg_get_int_def(ctx, 6, -1);
    int32_t issue_level = arg_get_int_def(ctx, 7, -1);
    CLIParserFree(ctx);

    bool use_raw = raw_len > 0;

    if (q5 && em) {
        PrintAndLogEx(FAILED, "Can't specify both Q5 and EM4305 at the same time");
        return PM3_EINVARG;
    }

    if (region_code == -1 && facility_code == -1 && card_number == -1 && issue_level == -1) {
        if (!use_raw) {
            PrintAndLogEx(FAILED, "Must specify either raw data to clone, or rc/fc/cn/il");
            return PM3_EINVARG;
        }
    } else {
        // --raw and --rc/fc/cn/il are mutually exclusive
        if (use_raw) {
            PrintAndLogEx(FAILED, "Can't specify both raw and rc/fc/cn/il at the same time");
            return PM3_EINVARG;
        }
        if (!isValidGallagherParams(region_code, facility_code, card_number, issue_level)) {
            return PM3_EINVARG;
        }
    }

    uint32_t blocks[4];
    if (use_raw) {
        for (uint8_t i = 1; i < ARRAYLEN(blocks); i++) {
            blocks[i] = bytes_to_num(raw + ((i - 1) * 4), sizeof(uint32_t));
        }
    } else {
        // fill blocks 1 to 3 with Gallagher data
        createBlocks(blocks + 1, region_code, facility_code, card_number, issue_level);
    }

    //Pac - compat mode, NRZ, data rate 40, 3 data blocks
    blocks[0] = T55x7_MODULATION_MANCHESTER | T55x7_BITRATE_RF_32 | 3 << T55x7_MAXBLOCK_SHIFT;
    char cardtype[16] = {"T55x7"};
    // Q5
    if (q5) {
        blocks[0] = T5555_FIXED | T5555_MODULATION_MANCHESTER | T5555_SET_BITRATE(32) | 3 << T5555_MAXBLOCK_SHIFT;
        snprintf(cardtype, sizeof(cardtype), "Q5/T5555");
    }

    // EM4305
    if (em) {
        blocks[0] = EM4305_GALLAGHER_CONFIG_BLOCK;
        snprintf(cardtype, sizeof(cardtype), "EM4305/4469");
    }

    PrintAndLogEx(INFO, "Preparing to clone Gallagher to " _YELLOW_("%s") " from %s.",
                  cardtype, use_raw ? "raw hex" : "specified data");
    print_blocks(blocks,  ARRAYLEN(blocks));

    if (em) {
        res = em4x05_clone_tag(blocks, ARRAYLEN(blocks), 0, false);
    } else {
        res = clone_t55xx_tag(blocks, ARRAYLEN(blocks));
    }
    PrintAndLogEx(SUCCESS, "Done");
    PrintAndLogEx(HINT, "Hint: try " _YELLOW_("`lf gallagher reader`") " to verify");
    return res;
}

static int CmdGallagherSim(const char *Cmd) {

    CLIParserContext *ctx;
    CLIParserInit(&ctx, "lf gallagher sim",
                  "Enables simulation of GALLAGHER card with specified card number.\n"
                  "Simulation runs until the button is pressed or another USB command is issued.\n",
                  "lf gallagher sim --raw 0FFD5461A9DA1346B2D1AC32\n"
                  "lf gallagher sim --rc 0 --fc 9876 --cn 1234 --il 1"
                 );

    void *argtable[] = {
        arg_param_begin,
        arg_str0("r", "raw", "<hex>", "raw hex data. 12 bytes max"),
        arg_int0(NULL, "rc", "<decimal>", "Region code. 4 bits max"),
        arg_int0(NULL, "fc", "<decimal>", "Facility code. 2 bytes max"),
        arg_int0(NULL, "cn", "<decimal>", "Card number. 3 bytes max"),
        arg_int0(NULL, "il", "<decimal>", "Issue level. 4 bits max"),
        arg_param_end
    };
    CLIExecWithReturn(ctx, Cmd, argtable, false);

    int raw_len = 0;
    // skip first block,  3*4 = 12 bytes left
    uint8_t raw[12] = {0};
    CLIGetHexWithReturn(ctx, 1, raw, &raw_len);
    int res = CLIParamHexToBuf(arg_get_str(ctx, 1), raw, sizeof raw, &raw_len);
    if (res) {
        CLIParserFree(ctx);
        return PM3_EINVARG;
    }

    int16_t region_code = arg_get_int_def(ctx, 2, -1);
    int32_t facility_code = arg_get_int_def(ctx, 3, -1);
    int32_t card_number = arg_get_int_def(ctx, 4, -1);
    int32_t issue_level = arg_get_int_def(ctx, 5, -1);
    CLIParserFree(ctx);

    bool use_raw = raw_len > 0;

    if (region_code == -1 && facility_code == -1 && card_number == -1 && issue_level == -1) {
        if (!use_raw) {
            PrintAndLogEx(FAILED, "Must specify either raw data to clone, or rc/fc/cn/il");
            return PM3_EINVARG;
        }
    } else {
        // --raw and --rc/fc/cn/il are mutually exclusive
        if (use_raw) {
            PrintAndLogEx(FAILED, "Can't specify both raw and rc/fc/cn/il at the same time");
            return PM3_EINVARG;
        }
        if (!isValidGallagherParams(region_code, facility_code, card_number, issue_level)) {
            return PM3_EINVARG;
        }
    }

    if (!use_raw) {
        // generate Gallagher data
        uint32_t blocks[3];
        createBlocks(blocks, region_code, facility_code, card_number, issue_level);

        // convert to the normal 'raw' format
        for (int i = 0; i < ARRAYLEN(blocks); i++) {
            raw[(4 * i) + 0] = (blocks[i] >> 24) & 0xff;
            raw[(4 * i) + 1] = (blocks[i] >> 16) & 0xff;
            raw[(4 * i) + 2] = (blocks[i] >> 8) & 0xff;
            raw[(4 * i) + 3] = (blocks[i]) & 0xff;
        }
    }

    // ASK/MAN sim.
    PrintAndLogEx(SUCCESS, "Simulating Gallagher - raw " _YELLOW_("%s"), sprint_hex_inrow(raw, sizeof(raw)));

    uint8_t bs[sizeof(raw) * 8];
    bytes_to_bytebits(raw, sizeof(raw), bs);

    lf_asksim_t *payload = calloc(1, sizeof(lf_asksim_t) + sizeof(bs));
    payload->encoding = 1;
    payload->invert = 0;
    payload->separator = 0;
    payload->clock = 32;
    memcpy(payload->data, bs, sizeof(bs));

    clearCommandBuffer();
    SendCommandNG(CMD_LF_ASK_SIMULATE, (uint8_t *)payload,  sizeof(lf_asksim_t) + sizeof(bs));
    free(payload);

    return lfsim_wait_check(CMD_LF_ASK_SIMULATE);
}

static command_t CommandTable[] = {
    {"help",   CmdHelp,            AlwaysAvailable, "This help"},
    {"demod",  CmdGallagherDemod,  AlwaysAvailable, "demodulate an GALLAGHER tag from the GraphBuffer"},
    {"reader", CmdGallagherReader, IfPm3Lf,         "attempt to read and extract tag data"},
    {"clone",  CmdGallagherClone,  IfPm3Lf,         "clone GALLAGHER tag to T55x7"},
    {"sim",    CmdGallagherSim,    IfPm3Lf,         "simulate GALLAGHER tag"},
    {NULL, NULL, NULL, NULL}
};

static int CmdHelp(const char *Cmd) {
    (void)Cmd; // Cmd is not used so far
    CmdsHelp(CommandTable);
    return PM3_SUCCESS;
}

int CmdLFGallagher(const char *Cmd) {
    clearCommandBuffer();
    return CmdsParse(CommandTable, Cmd);
}

// find Gallagher preamble in already demoded data
int detectGallagher(uint8_t *dest, size_t *size) {
    if (*size < 96) return -1; //make sure buffer has data
    size_t startIdx = 0;
    uint8_t preamble[] = { 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 1, 0, 1, 0 };
    if (!preambleSearch(dest, preamble, sizeof(preamble), size, &startIdx))
        return -2; //preamble not found

    if (*size != 96) return -3; //wrong demoded size
    //return start position
    return (int)startIdx;
}
